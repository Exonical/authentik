package kerberos

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func newS4UTestServer(
	t *testing.T, policy delegationPolicy,
) (*kdc.Server, *client.Client, principal.Principal, principal.Principal, principal.Principal) {
	return newS4UTestServerWithAccessCheck(t, policy, func(string, string) bool { return true })
}

func newS4UTestServerWithAccessCheck(
	t *testing.T,
	policy delegationPolicy,
	accessCheck func(username, spn string) bool,
) (*kdc.Server, *client.Client, principal.Principal, principal.Principal, principal.Principal) {
	t.Helper()
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v3/outposts/kerberos/1/access_check/" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access": map[string]interface{}{
					"passing": accessCheck(
						r.URL.Query().Get("username"),
						r.URL.Query().Get("spn"),
					),
					"messages":     []string{},
					"log_messages": []string{},
				},
			})
			return
		}
		if r.URL.Query().Get("username") != "alice" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"username":             "alice",
			"principal":            "alice",
			"kvno":                 1,
			"salt":                 testRealm + "alice",
			"pac_user_id":          2001,
			"pac_primary_group_id": 2001,
			"pac_group_ids":        []int32{},
			"pac_name":             "alice",
			"pac_upn":              "alice@" + testRealm,
			"password_expiration":  nil,
			"keys": map[string]string{
				"18": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
			},
		})
	}))
	service := principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	}
	target := principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvHst,
		Components: []string{"HTTP", "backend.test"},
	}
	user := principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	etype, err := crypto.NewRegistry().Get(18)
	if err != nil {
		t.Fatal(err)
	}
	serviceKey, err := etype.StringToKey(
		[]byte("service-password"),
		[]byte(testRealm+"hostservice.test"),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name string
		key  []byte
	}{
		{name: "host/service.test", key: serviceKey},
		{name: "HTTP/backend.test", key: bytes.Repeat([]byte{2}, 32)},
	} {
		record, err := store.serviceRecord(item.name, 1, map[string]interface{}{
			"18": base64.StdEncoding.EncodeToString(item.key),
		})
		if err != nil {
			t.Fatal(err)
		}
		store.services[principalKey(record.Name)] = record
	}
	store.delegations["host/service.test"] = policy

	now := time.Now().UTC().Truncate(time.Second)
	server := &kdc.Server{
		Realm:     testRealm,
		DB:        store,
		Now:       func() time.Time { return now },
		ClockSkew: 5 * time.Minute,
		Policy: &kdc.Policy{
			AllowForwardable: true,
			AllowRenewable:   true,
			AllowProxiable:   true,
		},
		CheckAllowedToDelegate: store.checkAllowedToDelegate,
	}
	kclient := &client.Client{
		Now: func() time.Time { return now },
		Exchange: func(_ context.Context, _ string, payload []byte) ([]byte, error) {
			return server.HandleMessage(payload), nil
		},
	}
	return server, kclient, service, target, user
}

func TestS4UDelegationPolicy(t *testing.T) {
	t.Run("allowed delegation", func(t *testing.T) {
		target := principal.Principal{
			Realm: testRealm, NameType: principal.NTSrvHst,
			Components: []string{"HTTP", "backend.test"},
		}
		_, kclient, service, _, user := newS4UTestServer(t, delegationPolicy{
			ok:      true,
			targets: []principal.Principal{target},
		})
		tgt, err := kclient.ASExchange(context.Background(), service, "service-password")
		if err != nil {
			t.Fatalf("service AS exchange: %v", err)
		}
		self, err := kclient.S4U2Self(context.Background(), tgt, user)
		if err != nil {
			t.Fatalf("S4U2Self: %v", err)
		}
		if self.Client.String() != user.String() {
			t.Fatalf("S4U2Self client = %s, want %s", self.Client, user)
		}
		if self.Flags&types.TicketForwardable == 0 {
			t.Fatalf("S4U2Self ticket is not forwardable: %#x", self.Flags)
		}
		proxy, err := kclient.S4U2Proxy(context.Background(), tgt, self, target)
		if err != nil {
			t.Fatalf("S4U2Proxy: %v", err)
		}
		if proxy.Client.String() != user.String() {
			t.Fatalf("S4U2Proxy client = %s, want %s", proxy.Client, user)
		}
		if proxy.Server.String() != target.String() {
			t.Fatalf("S4U2Proxy server = %s, want %s", proxy.Server, target)
		}
	})

	t.Run("delegation disabled", func(t *testing.T) {
		target := principal.Principal{
			Realm: testRealm, NameType: principal.NTSrvHst,
			Components: []string{"HTTP", "backend.test"},
		}
		_, kclient, service, _, user := newS4UTestServer(t, delegationPolicy{
			ok: false,
		})
		tgt, err := kclient.ASExchange(context.Background(), service, "service-password")
		if err != nil {
			t.Fatalf("service AS exchange: %v", err)
		}
		self, err := kclient.S4U2Self(context.Background(), tgt, user)
		if err != nil {
			t.Fatalf("S4U2Self: %v", err)
		}
		if self.Flags&types.TicketForwardable != 0 {
			t.Fatalf("S4U2Self ticket is forwardable: %#x", self.Flags)
		}
		if _, err := kclient.S4U2Proxy(context.Background(), tgt, self, target); err == nil {
			t.Fatal("S4U2Proxy succeeded with delegation disabled")
		}
	})

	t.Run("target not allowed", func(t *testing.T) {
		target := principal.Principal{
			Realm: testRealm, NameType: principal.NTSrvHst,
			Components: []string{"HTTP", "backend.test"},
		}
		_, kclient, service, _, user := newS4UTestServer(t, delegationPolicy{ok: true})
		tgt, err := kclient.ASExchange(context.Background(), service, "service-password")
		if err != nil {
			t.Fatalf("service AS exchange: %v", err)
		}
		self, err := kclient.S4U2Self(context.Background(), tgt, user)
		if err != nil {
			t.Fatalf("S4U2Self: %v", err)
		}
		if self.Flags&types.TicketForwardable == 0 {
			t.Fatalf("S4U2Self ticket is not forwardable: %#x", self.Flags)
		}
		if _, err := kclient.S4U2Proxy(context.Background(), tgt, self, target); err == nil {
			t.Fatal("S4U2Proxy succeeded for a target outside the delegation list")
		}
	})
}

func TestS4UProxyImpersonatedUserPolicy(t *testing.T) {
	var checkedUsername, checkedSPN string
	_, kclient, service, target, user := newS4UTestServerWithAccessCheck(
		t,
		delegationPolicy{
			ok: true,
			targets: []principal.Principal{{
				Realm: testRealm, NameType: principal.NTSrvHst,
				Components: []string{"HTTP", "backend.test"},
			}},
		},
		func(username, spn string) bool {
			checkedUsername, checkedSPN = username, spn
			return false
		},
	)
	tgt, err := kclient.ASExchange(context.Background(), service, "service-password")
	if err != nil {
		t.Fatalf("service AS exchange: %v", err)
	}
	self, err := kclient.S4U2Self(context.Background(), tgt, user)
	if err != nil {
		t.Fatalf("S4U2Self: %v", err)
	}
	if _, err := kclient.S4U2Proxy(context.Background(), tgt, self, target); err == nil {
		t.Fatal("S4U2Proxy succeeded despite impersonated-user policy denial")
	}
	if checkedUsername != "alice" || checkedSPN != "HTTP/backend.test" {
		t.Fatalf("access check = username %q, spn %q", checkedUsername, checkedSPN)
	}
}
