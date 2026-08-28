package kerberos

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestStoreAuthorizeAllowAndCache(t *testing.T) {
	requests := 0
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("username") != "alice" || r.URL.Query().Get("spn") != "host/service.test" {
			t.Errorf("unexpected access check query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access": map[string]interface{}{"passing": true, "messages": []string{}, "log_messages": []string{}},
		})
	}))
	client := principal.Principal{Realm: testRealm, Components: []string{"alice"}}
	service := principal.Principal{Realm: testRealm, Components: []string{"host", "service.test"}}
	if err := store.Authorize(client, service, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Authorize(client, service, false); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
}

func TestStoreAuthorizePolicyDenialAndCacheSeparation(t *testing.T) {
	requests := 0
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		allowed := r.URL.Query().Get("username") == "alice" &&
			r.URL.Query().Get("spn") != "host/denied.test"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access": map[string]interface{}{"passing": allowed, "messages": []string{}, "log_messages": []string{}},
		})
	}))
	alice := principal.Principal{Realm: testRealm, Components: []string{"alice"}}
	allowed := principal.Principal{Realm: testRealm, Components: []string{"host", "allowed.test"}}
	denied := principal.Principal{Realm: testRealm, Components: []string{"host", "denied.test"}}
	if err := store.Authorize(alice, allowed, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Authorize(alice, denied, false); err == nil ||
		!strings.Contains(err.Error(), "policy denied") {
		t.Fatalf("denied authorization error = %v", err)
	}
	if err := store.Authorize(alice, denied, false); err == nil {
		t.Fatal("cached denied authorization succeeded")
	}
	bob := principal.Principal{Realm: testRealm, Components: []string{"bob"}}
	if err := store.Authorize(bob, allowed, false); err == nil {
		t.Fatal("bob authorization unexpectedly succeeded")
	}
	if requests != 3 {
		t.Fatalf("requests = %d, want 3 for distinct cache keys", requests)
	}
}

func TestStoreAuthorizeClientSPNAndBypasses(t *testing.T) {
	requests := 0
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("client_spn") != "" &&
			(r.URL.Query().Get("client_spn") != "svc/worker" ||
				r.URL.Query().Get("username") != "" ||
				r.URL.Query().Get("spn") != "host/service.test") {
			t.Errorf("unexpected client-SPN access check query: %s", r.URL.RawQuery)
		}
		if r.URL.Query().Get("client_spn") == "" &&
			(r.URL.Query().Get("username") != "alice" || r.URL.Query().Get("spn") != "") {
			t.Errorf("unexpected access check query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access": map[string]interface{}{"passing": true, "messages": []string{}, "log_messages": []string{}},
		})
	}))
	if err := store.Authorize(
		principal.Principal{Realm: testRealm, Components: []string{"svc", "worker"}},
		principal.Principal{Realm: testRealm, Components: []string{"host", "service.test"}},
		false,
	); err != nil {
		t.Fatal(err)
	}
	for _, client := range []principal.Principal{
		{Realm: testRealm, Components: []string{"krbtgt", testRealm}},
		{Realm: testRealm, Components: []string{"kadmin", "changepw"}},
	} {
		if err := store.Authorize(
			client,
			principal.Principal{Realm: testRealm, Components: []string{"host", "service.test"}},
			false,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Authorize(
		principal.Principal{Realm: "OTHER.TEST", Components: []string{"alice"}},
		principal.Principal{Realm: testRealm, Components: []string{"host", "service.test"}},
		false,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Authorize(
		principal.Principal{Realm: testRealm, Components: []string{"alice"}},
		principal.Principal{Realm: testRealm, Components: []string{"krbtgt", testRealm}},
		false,
	); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want client-SPN and app-only checks", requests)
	}
}

func TestStoreAuthorizeClientSPNCacheKeySeparation(t *testing.T) {
	requests := 0
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		allowed := r.URL.Query().Get("username") == "alice" ||
			r.URL.Query().Get("client_spn") == "svc/worker"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access": map[string]interface{}{"passing": allowed, "messages": []string{}, "log_messages": []string{}},
		})
	}))
	service := principal.Principal{Realm: testRealm, Components: []string{"host", "service.test"}}
	if err := store.Authorize(
		principal.Principal{Realm: testRealm, Components: []string{"alice"}}, service, false,
	); err != nil {
		t.Fatal(err)
	}
	client := principal.Principal{Realm: testRealm, Components: []string{"svc", "worker"}}
	if err := store.Authorize(client, service, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Authorize(client, service, false); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2 distinct subject checks with client cache reuse", requests)
	}
}

func TestStoreAuthorizeAPIFailureDenies(t *testing.T) {
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "backend unavailable", http.StatusInternalServerError)
	}))
	err := store.Authorize(
		principal.Principal{Realm: testRealm, Components: []string{"alice"}},
		principal.Principal{Realm: testRealm, Components: []string{"host", "service.test"}},
		false,
	)
	if err == nil || !strings.Contains(err.Error(), "access check failed") {
		t.Fatalf("Authorize error = %v", err)
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
			"username":  "alice",
			"principal": "alice",
			"kvno":      2,
			"salt":      testRealm + "alice",
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

func TestStoreUserAliasLookupAndCanonicalCache(t *testing.T) {
	requests := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("username") != "alice@example.com" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"username":  "alice",
			"principal": "alice",
			"kvno":      1,
			"salt":      testRealm + "alice",
			"keys": map[string]string{
				"18": base64.StdEncoding.EncodeToString(make([]byte, 32)),
			},
		})
	})
	store := testStore(t, handler)
	alias := principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice@example.com"},
	}
	canonical := principal.Principal{
		Realm: testRealm, NameType: principal.NTPrincipal, Components: []string{"alice"},
	}

	resolved, ok, err := store.ResolveAlias(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || resolved.String() != canonical.String() {
		t.Fatalf("ResolveAlias(%v) = %v, %v; want %v, true", alias, resolved, ok, canonical)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	if _, ok, err := store.Lookup(alias); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("alias lookup unexpectedly returned a canonical record")
	}
	if _, ok, err := store.Lookup(canonical); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("canonical lookup failed")
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 after cache reuse", requests)
	}
	if _, ok, err := store.ResolveAlias(canonical); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("canonical principal resolved as an alias")
	}
}

func TestStoreAliasLookupGuards(t *testing.T) {
	store := testStore(t, nil)
	for _, name := range []principal.Principal{
		{Realm: "OTHER.TEST", Components: []string{"alice@example.com"}},
		{Realm: testRealm, Components: []string{"alice", "extra"}},
		{Realm: testRealm, Components: nil},
	} {
		if _, ok, err := store.ResolveAlias(name); err != nil {
			t.Fatal(err)
		} else if ok {
			t.Fatalf("ResolveAlias(%v) unexpectedly succeeded", name)
		}
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
