package kerberos

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/iprop"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/principal"
	log "github.com/sirupsen/logrus"
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

func TestIpropReplicaAuthorizationAndModifierComparison(t *testing.T) {
	store := &providerStore{
		realm:                testRealm,
		ipropAllowedReplicas: []string{"host/replica.example.test", "host/other@OTHER.TEST"},
	}
	allowed, err := principal.Parse("host/replica.example.test@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	if !store.authorizeIpropReplica(*allowed) {
		t.Fatal("replica without realm was not authorized")
	}
	denied, err := principal.Parse("host/nope.example.test@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	if store.authorizeIpropReplica(*denied) {
		t.Fatal("unconfigured replica was authorized")
	}
	left := kdb.PrincipalRecord{
		Name: *allowed,
		TLData: []kdb.TLData{
			{Type: 2, Data: []byte("old")},
			{Type: 8, Data: []byte("same")},
		},
	}
	right := kdb.PrincipalRecord{
		Name: allowedCopy(*allowed),
		TLData: []kdb.TLData{
			{Type: 2, Data: []byte("old")},
			{Type: 8, Data: []byte("same")},
		},
	}
	right.TLData[0].Data = []byte("new")
	if !equalIpropRecord(left, right) {
		t.Fatal("modifier TLData changed the iprop record")
	}
}

func TestIpropMasterKeyMatchesKpropDump(t *testing.T) {
	const password = "master-password"
	store := &providerStore{
		realm:     testRealm,
		masterKey: []byte("provider master key"),
		allowed:   map[int32]bool{18: true},
		server:    &KerberosServer{providers: map[int32]*ProviderInstance{}},
	}
	instance := &ProviderInstance{
		Config: *api.NewKerberosOutpostConfig(1, "provider", testRealm, 3600, 7200, "provider"),
		Store:  store,
	}
	instance.Config.SetIpropEnabled(true)
	instance.Config.SetIpropSpn("kiprop/kdc.example.test")
	instance.Config.SetKpropMasterPassword(password)
	instance.Config.SetIpropUlogSize(100)
	store.ipropSPN = "kiprop/kdc.example.test@" + testRealm

	if err := instance.configureIprop(); err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	want, err := etype.StringToKey([]byte(password), []byte(testRealm+"KM"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if instance.Iprop.MasterEnctype != crypto.EnctypeAES256SHA1 {
		t.Fatalf("iprop master enctype = %d, want %d",
			instance.Iprop.MasterEnctype, crypto.EnctypeAES256SHA1)
	}
	if string(instance.Iprop.MasterKey) != string(want) {
		t.Fatalf("iprop master key does not match kprop dump derivation")
	}
	instance.Config.SetKpropMasterPassword("")
	if err := instance.configureIprop(); err != nil {
		t.Fatal(err)
	}
	if instance.Iprop.MasterEnctype != 0 || len(instance.Iprop.MasterKey) != 0 {
		t.Fatalf("empty kprop password configured iprop master key: enctype=%d key=%x",
			instance.Iprop.MasterEnctype, instance.Iprop.MasterKey)
	}
}

func TestIpropRPCClientIncrementalUpdatesAndAuthorization(t *testing.T) {
	harness := startMITKDC(t, false)
	const (
		replicaSPN      = "host/replica"
		replicaPassword = "replica-password"
		deniedSPN       = "host/denied"
		deniedPassword  = "denied-password"
		ipropSPN        = "kiprop/kdc.example.test"
	)
	harness.server.Authorize = func(principal.Principal, principal.Principal, bool) error {
		return nil
	}
	harness.server.MaxDatagramReplySize = 65536
	harness.server.DisablePreauth = true
	addIpropClientService(t, harness.store, replicaSPN, replicaPassword)
	addIpropClientService(t, harness.store, deniedSPN, deniedPassword)
	replicaName, err := principal.Parse(replicaSPN + "@" + mitRealm)
	if err != nil {
		t.Fatal(err)
	}
	replicaRecord, found, err := harness.store.Lookup(*replicaName)
	if err != nil || !found {
		t.Fatalf("lookup replica principal: found=%v err=%v", found, err)
	}
	replicaEtype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	expectedReplicaKey, err := replicaEtype.StringToKey(
		[]byte(replicaPassword), []byte(mitRealm+"hostreplica"), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(replicaRecord.Keys[18].Key) != string(expectedReplicaKey) {
		t.Fatal("replica key does not match its string-to-key derivation")
	}
	harness.store.ipropSPN = ipropSPN + "@" + mitRealm
	harness.store.ipropAllowedReplicas = []string{replicaSPN}
	harness.instance.Config.SetIpropEnabled(true)
	harness.instance.Config.SetIpropSpn(ipropSPN)
	harness.instance.Config.SetIpropAllowedReplicas([]string{replicaSPN})
	harness.instance.Config.SetIpropUlogSize(100)
	harness.instance.Config.SetKpropMasterPassword("master-password")
	harness.instance.Config.SetKpropInterval(300)
	harness.instance.log = log.New().WithField("test", "iprop")
	if err := harness.instance.configureIprop(); err != nil {
		t.Fatal(err)
	}
	if err := harness.instance.syncIprop(context.Background()); err != nil {
		t.Fatal(err)
	}
	harness.instance.Iprop.ErrorLog = nil

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverDone := make(chan error, 1)
	go func() { serverDone <- harness.instance.Iprop.Serve(listener) }()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Error("iprop server did not stop")
		}
	})

	kclient := newMITKerberosClient(t, harness)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	replicaCredentials := ipropCredentials(t, kclient, replicaSPN, replicaPassword, ipropSPN)
	replica, err := iprop.Dial(ctx, listener.Addr().String(), replicaCredentials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replica.Close() })
	initial, err := replica.GetUpdates(ctx, iprop.Last{})
	if err != nil {
		t.Fatal(err)
	}
	if initial.Ret != iprop.UpdateNil {
		t.Fatalf("initial iprop status = %v, want UpdateNil", initial.Ret)
	}

	harness.stateMu.Lock()
	*harness.userMaxLife = 123
	harness.stateMu.Unlock()
	harness.store.invalidateUserKey(mitUser)
	before, err := harness.instance.snapshotRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before[mitUser+"@"+mitRealm].MaxLife != 123*time.Second {
		t.Fatalf("changed snapshot max life = %s, want 2m3s",
			before[mitUser+"@"+mitRealm].MaxLife)
	}
	if err := harness.instance.syncIprop(ctx); err != nil {
		t.Fatal(err)
	}
	changedName, err := principal.Parse(mitUser + "@" + mitRealm)
	if err != nil {
		t.Fatal(err)
	}
	changedRecord, changedOK, err := harness.instance.IpropDatabase.Lookup(*changedName)
	if err != nil || !changedOK {
		t.Fatalf("lookup changed mirror record: found=%v err=%v", changedOK, err)
	}
	lastSno, _ := harness.instance.IpropDatabase.UpdateLog.Last()
	if changedRecord.MaxLife != 123*time.Second || lastSno == 0 {
		t.Fatalf("changed mirror record = %#v, serial = %d", changedRecord, lastSno)
	}
	update, err := replica.GetUpdates(ctx, initial.LastEntry)
	if err != nil {
		t.Fatal(err)
	}
	if update.Ret != iprop.UpdateOK {
		t.Fatalf("incremental iprop status = %v, want UpdateOK", update.Ret)
	}
	changedFound := false
	for _, value := range update.Updates {
		if value.PrincipalName == mitUser+"@"+mitRealm {
			changedFound = true
			break
		}
	}
	if !changedFound {
		t.Fatalf("incremental iprop update missing changed principal: %#v", update.Updates)
	}

	deniedCredentials := ipropCredentials(t, kclient, deniedSPN, deniedPassword, ipropSPN)
	denied, err := iprop.Dial(ctx, listener.Addr().String(), deniedCredentials)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	deniedResult, err := denied.GetUpdates(ctx, iprop.Last{})
	if err != nil {
		t.Fatal(err)
	}
	if deniedResult.Ret != iprop.UpdatePermDenied {
		t.Fatalf("unauthorized iprop status = %v, want UpdatePermDenied", deniedResult.Ret)
	}
}

func addIpropClientService(
	t *testing.T, store *providerStore, spn, password string,
) {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	name, err := principal.Parse(spn + "@" + mitRealm)
	if err != nil {
		t.Fatal(err)
	}
	key, err := etype.StringToKey(
		[]byte(password), []byte(mitRealm+strings.Join(name.Components, "")), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.serviceRecord(spn, 1, map[string]interface{}{
		"18": base64.StdEncoding.EncodeToString(key),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.servicesMu.Lock()
	store.services[principalKey(record.Name)] = record
	store.servicesMu.Unlock()
}

func newMITKerberosClient(t *testing.T, harness *mitHarness) *client.Client {
	t.Helper()
	data, err := os.ReadFile(harness.config)
	if err != nil {
		t.Fatal(err)
	}
	var kdcAddress string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "kdc = 127.0.0.1:") {
			kdcAddress = strings.TrimSpace(strings.TrimPrefix(line, "kdc = "))
			break
		}
	}
	if kdcAddress == "" {
		t.Fatal("MIT harness config contains no KDC address")
	}
	return &client.Client{Config: &config.Config{
		DefaultRealm:       mitRealm,
		Realms:             map[string][]string{mitRealm: {kdcAddress}},
		UDPPreferenceLimit: 65536,
	}}
}

func ipropCredentials(
	t *testing.T, kclient *client.Client, clientSPN, password, serviceSPN string,
) *client.Credentials {
	t.Helper()
	clientPrincipal, err := principal.Parse(clientSPN + "@" + mitRealm)
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := kclient.ASExchange(context.Background(), *clientPrincipal, password)
	if err != nil {
		t.Fatalf("AS exchange for %s: %v", clientSPN, err)
	}
	servicePrincipal, err := principal.Parse(serviceSPN + "@" + mitRealm)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := kclient.TGSExchange(context.Background(), tgt, *servicePrincipal)
	if err != nil {
		t.Fatalf("TGS exchange for %s: %v", serviceSPN, err)
	}
	return credentials
}

func allowedCopy(value principal.Principal) principal.Principal {
	value.Components = append([]string(nil), value.Components...)
	return value
}
