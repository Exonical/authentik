package kerberos

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"

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

func TestStoreUserRecordPasswordExpiration(t *testing.T) {
	expiration := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"username": "alice",
			"enabled": true,
			"principal": "alice",
			"kvno": 1,
			"salt": "EXAMPLE.TESTalice",
			"keys": {"18": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
			"max_ticket_lifetime": null,
			"max_renew_lifetime": null,
			"requires_password_change": false,
			"flags": [],
			"pac_user_id": 0,
			"pac_primary_group_id": 0,
			"pac_group_ids": [],
			"pac_name": "Alice",
			"pac_upn": "alice@example.test",
			"password_expiration": "2030-01-02T03:04:05Z"
		}`))
	}))
	record, found, err := store.userRecord(principal.Principal{
		Realm: testRealm, Components: []string{"alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("user record was not found")
	}
	if !record.PasswordExpiration.Equal(expiration) {
		t.Fatalf("password expiration = %v, want %v", record.PasswordExpiration, expiration)
	}
}

func TestStoreUserRecordAccountStateAndLifetimes(t *testing.T) {
	expiration := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	enabled := false
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{
			"username": "alice",
			"enabled": %t,
			"principal": "alice",
			"kvno": 1,
			"salt": "EXAMPLE.TESTalice",
			"keys": {"18": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
			"max_ticket_lifetime": 3600,
			"max_renew_lifetime": 7200,
			"requires_password_change": true,
			"flags": [],
			"pac_user_id": 0,
			"pac_primary_group_id": 0,
			"pac_group_ids": [],
			"pac_name": "Alice",
			"pac_upn": "alice@example.test",
			"password_expiration": "2030-01-02T03:04:05Z"
		}`, enabled)))
	}))
	record, found, err := store.userRecord(principal.Principal{
		Realm: testRealm, Components: []string{"alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("user record was not found")
	}
	if record.Flags&kdb.DisallowAllTickets == 0 {
		t.Fatalf("user flags = %#x, missing DisallowAllTickets", record.Flags)
	}
	if record.Flags&kdb.RequiresPWChange == 0 {
		t.Fatalf("user flags = %#x, missing RequiresPWChange", record.Flags)
	}
	if record.MaxLife != time.Hour {
		t.Fatalf("max ticket lifetime = %v, want 1h", record.MaxLife)
	}
	if record.MaxRenew != 2*time.Hour {
		t.Fatalf("max renew lifetime = %v, want 2h", record.MaxRenew)
	}
	if !record.PasswordExpiration.Equal(expiration) {
		t.Fatalf("password expiration = %v, want %v", record.PasswordExpiration, expiration)
	}

	enabled = true
	store.cache = make(map[string]cachedUserKey)
	record, found, err = store.userRecord(principal.Principal{
		Realm: testRealm, Components: []string{"alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("enabled user record was not found")
	}
	if record.Flags&kdb.DisallowAllTickets != 0 {
		t.Fatalf("enabled user flags = %#x, unexpectedly includes DisallowAllTickets", record.Flags)
	}
}

func TestStoreUserRecordRequiresPasswordChangeFalse(t *testing.T) {
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"username": "alice",
			"enabled": true,
			"principal": "alice",
			"kvno": 1,
			"salt": "EXAMPLE.TESTalice",
			"keys": {"18": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
			"max_ticket_lifetime": null,
			"max_renew_lifetime": null,
			"requires_password_change": false,
			"flags": [],
			"pac_user_id": 0,
			"pac_primary_group_id": 0,
			"pac_group_ids": [],
			"pac_name": "Alice",
			"pac_upn": "alice@example.test",
			"password_expiration": null
		}`))
	}))
	record, found, err := store.userRecord(principal.Principal{
		Realm: testRealm, Components: []string{"alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("user record was not found")
	}
	if record.Flags&kdb.RequiresPWChange != 0 {
		t.Fatalf("user flags = %#x, unexpectedly includes RequiresPWChange", record.Flags)
	}
}

func TestStoreChangePasswordRecordAllowsExpiredUsers(t *testing.T) {
	store := testStore(t, nil)
	record, found, err := store.changepwRecord(principal.Principal{
		Realm: testRealm, NameType: principal.NTSrvInstance,
		Components: []string{"kadmin", "changepw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("changepw record was not found")
	}
	if record.Flags&kdb.PWChangeService == 0 {
		t.Fatalf("changepw flags = %#x, missing PWChangeService", record.Flags)
	}
}

func TestAnonymousPrincipalAuthorization(t *testing.T) {
	anonymous := principal.Principal{
		Realm:      "WELLKNOWN:ANONYMOUS",
		NameType:   principal.NTWellKnown,
		Components: []string{"WELLKNOWN", "ANONYMOUS"},
	}
	if !isAnonymousPrincipal(anonymous) {
		t.Fatal("anonymous principal was not detected")
	}
	if isAnonymousPrincipal(principal.Principal{
		NameType:   principal.NTWellKnown,
		Components: []string{"WELLKNOWN", "OTHER"},
	}) {
		t.Fatal("non-anonymous well-known principal was detected")
	}
	for _, enabled := range []bool{false, true} {
		store := testStore(t, nil)
		store.anonymousPKINITEnabled = enabled
		err := store.Authorize(anonymous, principal.Principal{Realm: testRealm}, true)
		if enabled && err != nil {
			t.Fatalf("enabled anonymous authorization failed: %v", err)
		}
		if !enabled && (err == nil || !strings.Contains(err.Error(), "anonymous PKINIT is disabled")) {
			t.Fatalf("disabled anonymous authorization error = %v", err)
		}
	}
}

func TestStoreValidateOTPDoesNotCache(t *testing.T) {
	requests := 0
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("username") != "alice" || r.URL.Query().Get("value") != "123456" {
			t.Errorf("unexpected OTP query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": true})
	}))
	store.otpEnabled = true
	user := principal.Principal{Realm: testRealm, Components: []string{"alice"}}
	if err := store.validateOTP(user, "123456"); err != nil {
		t.Fatalf("first OTP validation failed: %v", err)
	}
	if err := store.validateOTP(user, "123456"); err != nil {
		t.Fatalf("second OTP validation failed: %v", err)
	}
	if requests != 2 {
		t.Fatalf("OTP validation requests = %d, want 2", requests)
	}
	if err := store.validateOTP(
		principal.Principal{Realm: testRealm, Components: []string{"krbtgt", testRealm}},
		"123456",
	); err == nil {
		t.Fatal("special principal OTP validation unexpectedly succeeded")
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

func TestServiceRecordAuthIndicators(t *testing.T) {
	store := &providerStore{
		realm:   testRealm,
		allowed: map[int32]bool{18: true},
	}
	key := make([]byte, 32)
	record, err := store.serviceRecordWithIndicators(
		"host/service.test",
		1,
		map[string]interface{}{
			"18": base64.StdEncoding.EncodeToString(key),
		},
		[]string{"pkinit", "hardware"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := record.Strings["require_auth"]; got != "pkinit hardware" {
		t.Fatalf("require_auth = %q, want %q", got, "pkinit hardware")
	}
	withoutIndicators, err := store.serviceRecordWithIndicators(
		"host/other.test",
		1,
		map[string]interface{}{
			"18": base64.StdEncoding.EncodeToString(key),
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutIndicators.Strings) != 0 {
		t.Fatalf("auth indicators unexpectedly set: %#v", withoutIndicators.Strings)
	}
}

func TestApplyTicketFlags(t *testing.T) {
	record := kdb.PrincipalRecord{Flags: kdb.DisallowAllTickets | kdb.PWChangeService}
	applyTicketFlags(&record, []string{
		"requires_preauth",
		"requires_hwauth",
		"disallow_postdated",
		"disallow_forwardable",
		"disallow_proxiable",
		"disallow_renewable",
		"disallow_tgt_based",
		"disallow_server",
		"unknown",
	})
	want := kdb.DisallowAllTickets | kdb.PWChangeService |
		kdb.RequiresPreAuth | kdb.RequiresHWAuth |
		kdb.DisallowPostdated | kdb.DisallowForwardable |
		kdb.DisallowProxiable | kdb.DisallowRenewable |
		kdb.DisallowTGTBased | kdb.DisallowServer
	if record.Flags != want {
		t.Fatalf("record flags = %#x, want %#x", record.Flags, want)
	}
}

func TestServiceRecordTicketFlags(t *testing.T) {
	store := &providerStore{
		realm:   testRealm,
		allowed: map[int32]bool{18: true},
	}
	record, err := store.serviceRecordWithIndicators(
		"host/service.test",
		1,
		map[string]interface{}{
			"18": base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
		nil,
		[]string{"disallow_server"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.Flags&kdb.DisallowServer == 0 {
		t.Fatalf("service flags = %#x, missing DisallowServer", record.Flags)
	}
}

func TestTrustRecordLookupAndDirection(t *testing.T) {
	store := testStore(t, nil)
	key := make([]byte, 32)
	values := map[string]interface{}{
		"18": base64.StdEncoding.EncodeToString(key),
	}
	outgoing, err := store.trustRecord("krbtgt/REMOTE.TEST", testRealm, 3, values)
	if err != nil {
		t.Fatal(err)
	}
	incoming, err := store.trustRecord("krbtgt/"+testRealm, "REMOTE.TEST", 4, values)
	if err != nil {
		t.Fatal(err)
	}
	store.trusts = map[string]kdb.PrincipalRecord{
		principalKey(outgoing.Name): outgoing,
		principalKey(incoming.Name): incoming,
	}

	for _, test := range []struct {
		name principal.Principal
		kvno uint32
	}{
		{outgoing.Name, 3},
		{incoming.Name, 4},
	} {
		record, found, err := store.Lookup(test.name)
		if err != nil {
			t.Fatal(err)
		}
		if !found || record.KVNO != test.kvno || record.Keys[18].KVNO != test.kvno {
			t.Fatalf("Lookup(%v) = %#v, %t; want KVNO %d", test.name, record, found, test.kvno)
		}
	}
	if _, found, err := store.Lookup(principal.Principal{
		Realm: "REMOTE.TEST", Components: []string{"alice"},
	}); err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatal("remote user lookup succeeded")
	}
}

func TestTrustCapathsOrientation(t *testing.T) {
	server := &kdc.Server{}
	setCapaths(server, testRealm, "REMOTE.TEST", []string{"INTERMEDIATE.TEST"})
	if got := server.Capaths[testRealm]["REMOTE.TEST"]; len(got) != 1 ||
		got[0] != "INTERMEDIATE.TEST" {
		t.Fatalf("Capaths = %#v, want client-to-server path", server.Capaths)
	}
	if _, ok := server.Capaths["REMOTE.TEST"]; ok {
		t.Fatalf("Capaths unexpectedly reversed: %#v", server.Capaths)
	}
}

func TestCrossRealmProviderStores(t *testing.T) {
	const remoteRealm = "REMOTE.TEST"
	trustKey := make([]byte, 32)
	serviceKey := make([]byte, 32)
	etype, err := crypto.NewRegistry().Get(18)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := etype.StringToKey(
		[]byte("alice-password"), []byte(testRealm+"alice"), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("username") != "alice" {
			http.Error(w, "unknown user", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"username":                 "alice",
			"enabled":                  true,
			"principal":                "alice",
			"kvno":                     1,
			"salt":                     testRealm + "alice",
			"max_ticket_lifetime":      nil,
			"max_renew_lifetime":       nil,
			"requires_password_change": false,
			"flags":                    []string{},
			"password_expiration":      nil,
			"pac_user_id":              0,
			"pac_primary_group_id":     0,
			"pac_group_ids":            []int32{},
			"pac_name":                 "alice",
			"pac_upn":                  "alice@" + testRealm,
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
	controller := &ak.APIController{Client: api.NewAPIClient(cfg)}

	storeA := &providerStore{
		realm:       testRealm,
		allowed:     map[int32]bool{18: true},
		services:    make(map[string]kdb.PrincipalRecord),
		trusts:      make(map[string]kdb.PrincipalRecord),
		delegations: make(map[string]delegationPolicy),
		cache:       make(map[string]cachedUserKey),
		server:      &KerberosServer{ac: controller},
	}
	storeB := &providerStore{
		realm:       remoteRealm,
		allowed:     map[int32]bool{18: true},
		services:    make(map[string]kdb.PrincipalRecord),
		trusts:      make(map[string]kdb.PrincipalRecord),
		delegations: make(map[string]delegationPolicy),
		cache:       make(map[string]cachedUserKey),
		server:      &KerberosServer{ac: controller},
	}
	values := map[string]interface{}{
		"18": base64.StdEncoding.EncodeToString(trustKey),
	}
	outgoing, err := storeA.trustRecord("krbtgt/"+remoteRealm, testRealm, 1, values)
	if err != nil {
		t.Fatal(err)
	}
	incoming, err := storeB.trustRecord("krbtgt/"+remoteRealm, testRealm, 1, values)
	if err != nil {
		t.Fatal(err)
	}
	storeA.trusts[principalKey(outgoing.Name)] = outgoing
	storeB.trusts[principalKey(incoming.Name)] = incoming
	service, err := storeB.serviceRecord(
		"host/backend",
		1,
		map[string]interface{}{"18": base64.StdEncoding.EncodeToString(serviceKey)},
	)
	if err != nil {
		t.Fatal(err)
	}
	storeB.services[principalKey(service.Name)] = service

	serverA := &kdc.Server{
		Realm:     testRealm,
		DB:        storeA,
		Authorize: func(principal.Principal, principal.Principal, bool) error { return nil },
	}
	serverB := &kdc.Server{
		Realm:     remoteRealm,
		DB:        storeB,
		Authorize: func(principal.Principal, principal.Principal, bool) error { return nil },
	}
	kclient := &client.Client{
		Exchange: func(_ context.Context, realm string, payload []byte) ([]byte, error) {
			switch realm {
			case testRealm:
				return serverA.HandleMessage(payload), nil
			case remoteRealm:
				return serverB.HandleMessage(payload), nil
			default:
				return nil, errors.New("unexpected realm")
			}
		},
	}
	user, err := principal.Parse("alice@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := kclient.ASExchange(context.Background(), *user, "alice-password")
	if err != nil {
		t.Fatalf("AS exchange: %v", err)
	}
	target, err := principal.Parse("host/backend@" + remoteRealm)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := kclient.TGSExchange(context.Background(), tgt, *target)
	if err != nil {
		t.Fatalf("cross-realm TGS exchange: %v", err)
	}
	if credentials.Server.String() != target.String() {
		t.Fatalf("service credentials = %#v, want %v", credentials, target)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(credentials.Ticket, &ticket); err != nil {
		t.Fatalf("decode service ticket: %v", err)
	}
	key := service.Keys[credentials.Key.KeyType]
	etype, err = crypto.NewRegistry().Get(key.Enctype)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := etype.Decrypt(key.Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("decrypt service ticket: %v", err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plaintext, &part); err != nil {
		t.Fatalf("decode service ticket part: %v", err)
	}
	if part.CRealm != testRealm || len(part.CName.NameString) != 1 ||
		part.CName.NameString[0] != "alice" {
		t.Fatalf("foreign client = %s/%#v", part.CRealm, part.CName)
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
			"username":                 "alice",
			"enabled":                  true,
			"principal":                "alice",
			"kvno":                     2,
			"salt":                     testRealm + "alice",
			"max_ticket_lifetime":      nil,
			"max_renew_lifetime":       nil,
			"requires_password_change": false,
			"flags":                    []string{},
			"pac_user_id":              2001,
			"pac_primary_group_id":     2001,
			"pac_group_ids":            []int32{},
			"pac_name":                 "alice",
			"pac_upn":                  "alice@" + testRealm,
			"password_expiration":      nil,
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
			"username":                 "alice",
			"enabled":                  true,
			"principal":                "alice",
			"kvno":                     1,
			"salt":                     testRealm + "alice",
			"max_ticket_lifetime":      nil,
			"max_renew_lifetime":       nil,
			"requires_password_change": false,
			"flags":                    []string{},
			"pac_user_id":              2001,
			"pac_primary_group_id":     2001,
			"pac_group_ids":            []int32{},
			"pac_name":                 "alice",
			"pac_upn":                  "alice@" + testRealm,
			"password_expiration":      nil,
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
