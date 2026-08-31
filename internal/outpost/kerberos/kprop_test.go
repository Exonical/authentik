package kerberos

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/principal"
	api "goauthentik.io/packages/client-go"
)

func TestKpropTargetAddress(t *testing.T) {
	tests := []struct {
		target, host, address string
		ok                    bool
	}{
		{target: "replica.example", host: "replica.example", address: "replica.example:754", ok: true},
		{target: "replica.example:875", host: "replica.example", address: "replica.example:875", ok: true},
		{target: "", ok: false},
		{target: "replica.example:bad:port", ok: false},
	}
	for _, test := range tests {
		host, address, err := kpropTargetAddress(test.target)
		if test.ok {
			if err != nil || host != test.host || address != test.address {
				t.Fatalf("kpropTargetAddress(%q) = %q, %q, %v", test.target, host, address, err)
			}
		} else if err == nil {
			t.Fatalf("kpropTargetAddress(%q) unexpectedly succeeded", test.target)
		}
	}
}

func TestKpropSnapshotContainsExpectedPrincipals(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	store := testStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pagination":{"count":1,"current":1,"next":0,"previous":0,"total_pages":1,"start_index":1,"end_index":1},"results":[{
			"username":"alice","enabled":true,"principal":"alice","kvno":1,
			"salt":"EXAMPLE.TESTalice","keys":{"18":"` + key + `"},
			"max_ticket_lifetime":null,"max_renew_lifetime":null,
			"requires_password_change":false,"pac_user_id":0,"pac_primary_group_id":0,
			"pac_group_ids":[],"pac_name":"Alice","pac_upn":"alice@example.test",
			"password_expiration":null,"flags":[]
		}],"autocomplete":{}}`))
	}))
	store.trusts = make(map[string]kdb.PrincipalRecord)
	service, err := store.serviceRecord("host/web", 1, map[string]interface{}{"18": key})
	if err != nil {
		t.Fatal(err)
	}
	store.services[principalKey(service.Name)] = service
	instance := &ProviderInstance{Store: store, Config: *api.NewKerberosOutpostConfig(
		1, "provider", testRealm, 3600, 7200, "provider",
	)}
	instance.Config.SetKpropMasterPassword("master-password")
	dump, err := instance.snapshotDump(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := mitdump.ParseWithMasterPassword(dump, "master-password")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"krbtgt/" + testRealm, "kadmin/changepw", "host/web", "alice"} {
		parsed, parseErr := principal.Parse(name + "@" + testRealm)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if _, found, lookupErr := loaded.Lookup(*parsed); lookupErr != nil || !found {
			t.Fatalf("dump missing %s: found=%v err=%v", name, found, lookupErr)
		}
	}
}
