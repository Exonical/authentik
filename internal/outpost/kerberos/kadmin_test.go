package kerberos

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestKadminBackendPrincipalMapping(t *testing.T) {
	store := testStore(t, nil)
	instance := &ProviderInstance{Store: store}
	backend := &kadminBackend{instance: instance}

	user, err := principal.Parse("alice@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.service(*user); err == nil {
		t.Fatal("user principal unexpectedly accepted as service")
	}
	service, err := principal.Parse("host/web@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := backend.service(*service); err != nil || got != "host/web" {
		t.Fatalf("service mapping = %q, err=%v", got, err)
	}
	for _, operation := range []func() error{
		func() error { return backend.SetKeys(*service, nil, false) },
		func() error { return backend.PurgeKeys(*service, 1) },
		func() error { return backend.RenamePrincipal(*service, *service) },
		func() error { return backend.AddAlias("host/web", "host/other") },
	} {
		if err := operation(); err != errKadminUnsupported {
			t.Fatalf("unsupported operation error = %v", err)
		}
	}
}

func TestKadminPasswordQuality(t *testing.T) {
	module := kadminPasswordQuality{}
	user, err := principal.Parse("alice@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	service, err := principal.Parse("host/web@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"", "alice"} {
		if err := module.Check(password, "", *user); err == nil {
			t.Fatalf("user password %q was accepted", password)
		}
	}
	for _, password := range []string{"", "host"} {
		if err := module.Check(password, "", *service); err != nil {
			t.Fatalf("service password %q was rejected: %v", password, err)
		}
	}
}

func TestKadminBackendRandomizeReturnsFreshKeys(t *testing.T) {
	first := base64.StdEncoding.EncodeToString(make([]byte, 32))
	second := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/outposts/kerberos/1/service_principal_rotate/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"spn":"host/web","kvno":2,"keys":{"18":"` + second +
			`"},"ok_to_auth_as_delegate":false,"allowed_delegation_targets":[],"required_auth_indicators":[],"ticket_flags":[]}`))
	}))
	service, err := store.serviceRecord("host/web", 1, map[string]interface{}{"18": first})
	if err != nil {
		t.Fatal(err)
	}
	store.services[principalKey(service.Name)] = service
	instance := &ProviderInstance{Store: store}
	backend := &kadminBackend{instance: instance}
	name, err := principal.Parse("host/web@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := backend.RandomizeKeys(*name)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || string(keys[0].Key) != "01234567890123456789012345678901" {
		t.Fatalf("randomized keys = %#v", keys)
	}
}

func TestParseKadminACLAddsLocalRealm(t *testing.T) {
	acl, err := parseKadminACL([]string{"admin *"}, testRealm)
	if err != nil {
		t.Fatal(err)
	}
	client, err := principal.Parse("admin@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	target, err := principal.Parse("host/web@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	if !acl.Check(*client, "get", *target) {
		t.Fatal("realm-less local ACL entry did not authorize client")
	}
}
