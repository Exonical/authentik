package kerberos

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"

	"goauthentik.io/internal/outpost/ak"
	api "goauthentik.io/packages/client-go"
)

const testRealm = "EXAMPLE.TEST"

func testStore(t *testing.T, handler http.Handler) *providerStore {
	t.Helper()
	store := &providerStore{
		realm:       testRealm,
		masterKey:   []byte("provider master key"),
		allowed:     map[int32]bool{18: true, 20: true},
		services:    make(map[string]kdb.PrincipalRecord),
		delegations: make(map[string]delegationPolicy),
		cache:       make(map[string]cachedUserKey),
		providerID:  1,
	}
	if handler != nil {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		parsed, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		cfg := api.NewConfiguration()
		cfg.Host = parsed.Host
		cfg.Scheme = parsed.Scheme
		store.server = &KerberosServer{ac: &ak.APIController{Client: api.NewAPIClient(cfg)}}
	}
	return store
}

func TestStoreDelegationPolicyMapping(t *testing.T) {
	store := testStore(t, nil)
	target := principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvHst,
		Components: []string{"HTTP", "backend.test"},
	}
	store.delegations["host/service.test"] = delegationPolicy{
		ok:      true,
		targets: []principal.Principal{target},
	}

	service := principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	}
	ok, targets := store.delegationPolicy(service)
	if !ok || len(targets) != 1 || targets[0].String() != target.String() {
		t.Fatalf("delegationPolicy(%v) = %v, %v", service, ok, targets)
	}

	for _, unknown := range []principal.Principal{
		{Realm: testRealm, Components: []string{"host"}},
		{Realm: "OTHER.TEST", Components: []string{"host", "service.test"}},
		{Realm: testRealm, Components: []string{"host", "missing.test"}},
	} {
		ok, targets = store.delegationPolicy(unknown)
		if ok || targets != nil {
			t.Fatalf("delegationPolicy(%v) = %v, %v; want false, nil", unknown, ok, targets)
		}
	}

	store.delegations["host/no-delegate.test"] = delegationPolicy{targets: []principal.Principal{target}}
	ok, targets = store.delegationPolicy(principal.Principal{
		Realm: testRealm, Components: []string{"host", "no-delegate.test"},
	})
	if ok || len(targets) != 1 || targets[0].String() != target.String() {
		t.Fatalf("delegationPolicy with delegation disabled = %v, %v", ok, targets)
	}
}

func TestStoreKrbtgtDerivationMatchesPythonFixture(t *testing.T) {
	store := testStore(t, nil)
	name := principal.Principal{
		Realm:      testRealm,
		NameType:   principal.NTSrvInstance,
		Components: []string{"krbtgt", testRealm},
	}
	record, ok, err := store.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("krbtgt lookup failed")
	}
	if record.KVNO != 1 {
		t.Fatalf("krbtgt KVNO = %d, want 1", record.KVNO)
	}
	// Fixture from the Python-side HKDF-SHA256(master, salt=nil, info="krbtgt-18").
	want := "0e32342dfea8a54cb5067e24bff22a04b1ce3ec2c71bae56d54fb106029e27a2"
	if got := hex.EncodeToString(record.Keys[18].Key); got != want {
		t.Fatalf("krbtgt aes256 key = %s, want %s", got, want)
	}
	if len(record.Keys[20].Key) != 32 {
		t.Fatalf("krbtgt aes256-sha384 key length = %d", len(record.Keys[20].Key))
	}
}

func TestStoreServiceLookup(t *testing.T) {
	store := testStore(t, nil)
	record, err := store.serviceRecord("host/service.test", 3, map[string]interface{}{
		"18": base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.services[principalKey(record.Name)] = record
	name := principal.Principal{
		Realm:      testRealm,
		NameType:   principal.NTSrvHst,
		Components: []string{"host", "service.test"},
	}
	got, ok, err := store.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("service lookup failed")
	}
	if got.KVNO != 3 || got.Keys[18].KVNO != 3 {
		t.Fatalf("service KVNO = %d/%d, want 3", got.KVNO, got.Keys[18].KVNO)
	}
	if _, ok, err := store.Lookup(principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvHst, Components: []string{"host", "other.test"},
	}); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("unknown service lookup succeeded")
	}
}

func TestStoreUserLookupCacheAndUnknown(t *testing.T) {
	requests := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("username") != "alice" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"username": "alice",
			"kvno":     2,
			"salt":     testRealm + "alice",
			"keys": map[string]string{
				"18": base64.StdEncoding.EncodeToString(make([]byte, 32)),
			},
		})
	})
	store := testStore(t, handler)
	name := principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}
	record, ok, err := store.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("user lookup failed")
	}
	if record.KVNO != 2 || record.Keys[18].Salt != testRealm+"alice" {
		t.Fatalf("unexpected user record: %+v", record)
	}
	if _, ok, err := store.Lookup(name); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("cached user lookup failed")
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 (cache hit expected)", requests)
	}
	store.cacheMu.Lock()
	entry := store.cache["alice"]
	entry.expires = time.Now().Add(-time.Second)
	store.cache["alice"] = entry
	store.cacheMu.Unlock()
	if _, ok, err := store.Lookup(name); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("expired-cache user lookup failed")
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2 (TTL expiry expected)", requests)
	}
	if _, ok, err := store.Lookup(principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"bob"},
	}); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("unknown user lookup succeeded")
	}
	if _, ok, err := store.Lookup(principal.Principal{
		Realm: "OTHER.TEST", NameType: principal.NTPrincipal, Components: []string{"alice"},
	}); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("wrong-realm lookup succeeded")
	}
}

func TestStoreUserLookupPropagatesAPIFailure(t *testing.T) {
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	_, ok, err := store.Lookup(principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"},
	})
	if err == nil {
		t.Fatal("expected API failure")
	}
	if ok {
		t.Fatal("API failure reported as a found principal")
	}
}
