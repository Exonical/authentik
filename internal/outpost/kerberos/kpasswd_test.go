package kerberos

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/kpasswd"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"

	"goauthentik.io/internal/outpost/ak"
	api "goauthentik.io/packages/client-go"
)

func TestParseKpasswdRequest(t *testing.T) {
	apReq := []byte{0x01, 0x02}
	priv := []byte{0x03, 0x04}
	packet := make([]byte, 6+len(apReq)+len(priv))
	binary.BigEndian.PutUint16(packet[:2], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[2:4], kpasswdVersion)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(apReq)))
	copy(packet[6:], apReq)
	copy(packet[6+len(apReq):], priv)

	// The AP-REQ bytes must be valid for the parser to expose its routing data.
	// Replace the payload with a real ASN.1 request after exercising framing.
	request := protocol.APReq{PVNO: 5, MsgType: 14, Ticket: protocol.Ticket{Realm: "EXAMPLE.TEST"}}
	der, err := asn1.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(packet[:2], uint16(6+len(der)+len(priv)))
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(der)))
	packet = append(packet[:6], append(der, priv...)...)
	parsed, err := parseKpasswdRequest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.apReq.Ticket.Realm != "EXAMPLE.TEST" {
		t.Fatalf("realm = %q", parsed.apReq.Ticket.Realm)
	}
	if len(parsed.privDER) != len(priv) {
		t.Fatalf("priv length = %d, want %d", len(parsed.privDER), len(priv))
	}
}

func TestParseKpasswdRequestRejectsInvalidFraming(t *testing.T) {
	tests := [][]byte{
		nil,
		{0, 6, 0, 1, 0, 0},
		{0, 6, 0, 1, 0, 1},
	}
	for _, data := range tests {
		if _, err := parseKpasswdRequest(data); err == nil {
			t.Fatalf("parseKpasswdRequest(%x) succeeded", data)
		}
	}
}

func TestBuildKpasswdReply(t *testing.T) {
	key := make([]byte, 32)
	state := &ap.VerifiedAPReq{
		Client:            principal.Principal{Realm: "EXAMPLE.TEST", Components: []string{"alice"}},
		SessionKey:        protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key},
		AuthenticatorTime: time.Now().UTC(),
		Cusec:             42,
		SeqNumber:         uint32Pointer(7),
	}
	reply, err := buildKpasswdReply(state, 2, "failed", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) < 6 || int(binary.BigEndian.Uint16(reply[:2])) != len(reply) {
		t.Fatalf("invalid reply framing")
	}
	if binary.BigEndian.Uint16(reply[2:4]) != kpasswdVersion {
		t.Fatalf("version = %d", binary.BigEndian.Uint16(reply[2:4]))
	}
	apLength := int(binary.BigEndian.Uint16(reply[4:6]))
	if apLength == 0 || 6+apLength >= len(reply) {
		t.Fatalf("invalid AP-REP length %d", apLength)
	}
}

func TestStoreChangepwRecord(t *testing.T) {
	store := testStore(t, nil)
	name := principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvInstance,
		Components: []string{"kadmin", "changepw"},
	}
	record, ok, err := store.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || record.KVNO != 1 {
		t.Fatalf("record = %#v, ok = %v", record, ok)
	}
	if len(record.Keys) != len(store.allowed) {
		t.Fatalf("keys = %d, want %d", len(record.Keys), len(store.allowed))
	}
}

func TestKpasswdClientChangesPasswordThroughServer(t *testing.T) {
	const (
		realm    = "EXAMPLE.TEST"
		username = "alice"
		oldPass  = "old-password"
		newPass  = "new-password"
	)
	etype, err := crypto.NewRegistry().Get(18)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := etype.StringToKey([]byte(oldPass), []byte(realm+username), nil)
	if err != nil {
		t.Fatal(err)
	}
	var receivedUsername, receivedPassword string
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/outposts/kerberos/1/user_key/":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"username":                 username,
				"enabled":                  true,
				"principal":                username,
				"kvno":                     1,
				"salt":                     realm + username,
				"max_ticket_lifetime":      nil,
				"max_renew_lifetime":       nil,
				"requires_password_change": false,
				"flags":                    []string{},
				"pac_user_id":              2001,
				"pac_primary_group_id":     2001,
				"pac_group_ids":            []int32{},
				"pac_name":                 username,
				"pac_upn":                  username + "@" + realm,
				"password_expiration":      nil,
				"keys": map[string]string{
					"18": base64.StdEncoding.EncodeToString(userKey),
				},
			})
		case "/api/v3/outposts/kerberos/1/set_password/":
			var request struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			receivedUsername, receivedPassword = request.Username, request.Password
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Logf("unexpected API request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(apiServer.Close)
	parsed, err := url.Parse(apiServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := api.NewConfiguration()
	cfg.Host = parsed.Host
	cfg.Scheme = parsed.Scheme
	cfg.Servers = api.ServerConfigurations{{URL: "/api/v3"}}
	server := &KerberosServer{ac: &ak.APIController{Client: api.NewAPIClient(cfg)}}
	store := testStore(t, nil)
	store.realm = realm
	store.server = server
	store.providerID = 1
	instance := &ProviderInstance{
		Config: *api.NewKerberosOutpostConfig(1, "test", realm, 3600, 3600, "test"),
		Store:  store,
	}
	instance.Config.SetKpasswdEnabled(true)
	instance.Config.SetUdpEnabled(true)
	instance.Config.SetTcpEnabled(true)
	instance.KDC = &kdc.Server{
		Realm:            realm,
		DB:               store,
		ClockSkew:        5 * time.Minute,
		MaxTicketLife:    10 * time.Hour,
		MaxRenewableLife: 24 * time.Hour,
		Policy: &kdc.Policy{
			AllowForwardable: true,
			AllowRenewable:   true,
			AllowProxiable:   true,
		},
	}
	server.providers = map[int32]*ProviderInstance{1: instance}
	kerberosClient := &client.Client{
		Exchange: func(_ context.Context, _ string, payload []byte) ([]byte, error) {
			if len(payload) > 0 && payload[0] != 0x6a && payload[0] != 0x6c {
				return server.handleKpasswd(payload, true)
			}
			return instance.KDC.HandleMessage(payload), nil
		},
	}
	passwordClient := &kpasswd.Client{Kerberos: kerberosClient}
	if err := passwordClient.ChangePassword(
		context.Background(),
		principal.Principal{
			Realm: realm, NameType: principal.NTEnterprise, Components: []string{username},
		},
		oldPass, newPass,
	); err != nil {
		t.Fatal(err)
	}
	if receivedUsername != username || receivedPassword != newPass {
		t.Fatalf("API received %q/%q", receivedUsername, receivedPassword)
	}
}

func TestPasswordPolicyError(t *testing.T) {
	var responseBody = `{"messages":["Password is too short.","Use a longer password."]}`
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(responseBody))
	}))
	t.Cleanup(apiServer.Close)
	parsed, err := url.Parse(apiServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := api.NewConfiguration()
	cfg.Host = parsed.Host
	cfg.Scheme = parsed.Scheme
	cfg.Servers = api.ServerConfigurations{{URL: "/api/v3"}}
	response, err := api.NewAPIClient(cfg).OutpostsAPI.
		OutpostsKerberosSetPasswordCreate(context.Background(), 1).
		KerberosSetPasswordRequest(*api.NewKerberosSetPasswordRequest("alice", "short")).
		Execute()
	message, ok := passwordPolicyError(response, err)
	if !ok {
		t.Fatalf("passwordPolicyError(%v) did not recognize policy response", err)
	}
	if message != "Password is too short.\nUse a longer password." {
		t.Fatalf("message = %q", message)
	}

	apiServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"invalid request"}`))
	})
	response, err = api.NewAPIClient(cfg).OutpostsAPI.
		OutpostsKerberosSetPasswordCreate(context.Background(), 1).
		KerberosSetPasswordRequest(*api.NewKerberosSetPasswordRequest("alice", "short")).
		Execute()
	if _, ok := passwordPolicyError(response, err); ok {
		t.Fatal("malformed policy response was recognized")
	}
}

func uint32Pointer(value uint32) *uint32 {
	return &value
}
