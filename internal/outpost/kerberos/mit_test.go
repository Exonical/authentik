package kerberos

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"

	"goauthentik.io/internal/outpost/ak"
	api "goauthentik.io/packages/client-go"
)

const (
	mitRealm    = "MITKDC.TEST"
	mitUser     = "alice"
	mitPassword = "alice-password"
	mitService  = "host/service.test"
)

type mitHarness struct {
	config     string
	cache      string
	keytabPath string
}

func startMITKDC(t *testing.T, forceTCP bool) *mitHarness {
	t.Helper()
	for _, tool := range []string{"kinit", "kvno", "klist"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed, skipping MIT interop test", tool)
		}
	}
	registry := crypto.NewRegistry()
	etype, err := registry.Get(18)
	if err != nil {
		t.Fatal(err)
	}
	// Same string-to-key behavior as the Python provider (RFC 3962).
	userKey, err := etype.StringToKey([]byte(mitPassword), []byte(mitRealm+mitUser), nil)
	if err != nil {
		t.Fatal(err)
	}
	serviceKey := make([]byte, 32)
	for i := range serviceKey {
		serviceKey[i] = byte(i + 1)
	}

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("username") != mitUser {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"username": mitUser,
			"kvno":     1,
			"salt":     mitRealm + mitUser,
			"keys": map[string]string{
				"18": base64.StdEncoding.EncodeToString(userKey),
			},
		})
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

	store := &providerStore{
		realm:      mitRealm,
		masterKey:  []byte("provider master key"),
		allowed:    map[int32]bool{18: true},
		services:   make(map[string]kdb.PrincipalRecord),
		cache:      make(map[string]cachedUserKey),
		server:     &KerberosServer{ac: &ak.APIController{Client: api.NewAPIClient(cfg)}},
		providerID: 1,
	}
	serviceRecord, err := store.serviceRecord(mitService, 1, map[string]interface{}{
		"18": base64.StdEncoding.EncodeToString(serviceKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.services[principalKey(serviceRecord.Name)] = serviceRecord

	server := &kdc.Server{
		Realm:            mitRealm,
		DB:               store,
		ClockSkew:        5 * time.Minute,
		MaxTicketLife:    10 * time.Hour,
		MaxRenewableLife: 24 * time.Hour,
	}
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		udpConn.Close()
		t.Fatal(err)
	}
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	tcpPort := tcpListener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx, udpConn, tcpListener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	dir := t.TempDir()
	extra := ""
	if forceTCP {
		extra = "    udp_preference_limit = 1\n"
	}
	configText := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    permitted_enctypes = aes256-cts-hmac-sha1-96
%s
[realms]
    %s = {
        kdc = 127.0.0.1:%d
        kdc = tcp/127.0.0.1:%d
        admin_server = 127.0.0.1:%d
    }
`, mitRealm, extra, mitRealm, udpPort, tcpPort, tcpPort)
	configPath := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}

	servicePrincipal, err := principal.Parse(mitService + "@" + mitRealm)
	if err != nil {
		t.Fatal(err)
	}
	kt := &keytab.Keytab{Entries: []keytab.Entry{{
		Principal: *servicePrincipal,
		Timestamp: time.Now().Unix(),
		KVNO:      1,
		Enctype:   18,
		Key:       serviceKey,
	}}}
	keytabPath := filepath.Join(dir, "service.keytab")
	keytabFile, err := os.OpenFile(keytabPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := keytab.Write(keytabFile, kt); err != nil {
		t.Fatal(err)
	}
	if err := keytabFile.Close(); err != nil {
		t.Fatal(err)
	}

	return &mitHarness{
		config:     configPath,
		cache:      filepath.Join(dir, "ccache"),
		keytabPath: keytabPath,
	}
}

func (h *mitHarness) run(t *testing.T, input, command string, args ...string) string {
	t.Helper()
	cmd := exec.Command(command, args...)
	env := make([]string, 0, len(os.Environ())+3)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "KRB5_CONFIG=") ||
			strings.HasPrefix(value, "KRB5CCNAME=") ||
			strings.HasPrefix(value, "KRB5_KTNAME=") {
			continue
		}
		env = append(env, value)
	}
	cmd.Env = append(env,
		"KRB5_CONFIG="+h.config,
		"KRB5CCNAME=FILE:"+h.cache,
		"KRB5_KTNAME=FILE:"+h.keytabPath,
	)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", command, args, err, output)
	}
	return string(output)
}

func runMITFlow(t *testing.T, forceTCP bool) {
	h := startMITKDC(t, forceTCP)
	h.run(t, mitPassword+"\n", "kinit", mitUser)
	klist := h.run(t, "", "klist")
	t.Logf("klist after kinit:\n%s", klist)
	if !strings.Contains(klist, "krbtgt/"+mitRealm+"@"+mitRealm) {
		t.Fatalf("klist does not show TGT:\n%s", klist)
	}
	kvno := h.run(t, "", "kvno", mitService)
	t.Logf("kvno output:\n%s", kvno)
	if !strings.Contains(kvno, "kvno = 1") {
		t.Fatalf("unexpected kvno output:\n%s", kvno)
	}
	full := h.run(t, "", "klist", "-e")
	t.Logf("klist -e output:\n%s", full)
	if !strings.Contains(full, mitService+"@"+mitRealm) {
		t.Fatalf("klist -e does not show service ticket:\n%s", full)
	}
}

func TestMITInteropUDP(t *testing.T) {
	runMITFlow(t, false)
}

func TestMITInteropTCP(t *testing.T) {
	runMITFlow(t, true)
}
