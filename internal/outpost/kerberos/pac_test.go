package kerberos

import (
	"context"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"

	api "goauthentik.io/packages/client-go"
)

func TestPACInServiceTicket(t *testing.T) {
	h := startMITKDCWithIdentityPolicy(t, false, false, true, mitUser, mitUser,
		func(string, string, string) bool { return true })
	realmSID, err := pac.ParseSID("S-1-5-21-1-2-3")
	if err != nil {
		t.Fatal(err)
	}
	h.store.pacEnabled = true
	h.store.realmSID = &realmSID
	h.server.EnablePAC = true
	h.server.GeneratePACIdentity = h.store.generatePACIdentity
	etype, err := crypto.NewRegistry().Get(18)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := etype.StringToKey([]byte(mitPassword), []byte(mitRealm+mitUser), nil)
	if err != nil {
		t.Fatal(err)
	}
	userRecord := kdb.PrincipalRecord{Name: principal.Principal{
		Realm: mitRealm, Components: []string{mitUser},
	}, Keys: map[int32]kdb.Key{
		18: {Enctype: 18, KVNO: 1, Key: userKey},
	}, KVNO: 1}
	h.store.cache[mitUser] = cachedUserKey{
		record: userRecord,
		identity: api.NewKerberosUserKeyOutpost(
			mitUser, true, mitUser+"@"+mitRealm, 1, mitRealm+mitUser, nil,
			api.NullableInt32{}, api.NullableInt32{},
			false,
			2001, 2001, []int32{4001, 5678}, "Alice Example", "alice@example.test",
			api.NullableTime{}, nil,
		),
		found: true, expires: time.Now().Add(time.Hour),
	}
	goClient := &client.Client{
		Exchange: func(_ context.Context, _ string, payload []byte) ([]byte, error) {
			return h.server.HandleMessage(payload), nil
		},
	}
	user, err := principal.Parse(mitUser + "@" + mitRealm)
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := goClient.ASExchange(context.Background(), *user, mitPassword)
	if err != nil {
		t.Fatal(err)
	}
	service, err := principal.Parse(mitService + "@" + mitRealm)
	if err != nil {
		t.Fatal(err)
	}
	serviceCredentials, err := goClient.TGSExchange(context.Background(), tgt, *service)
	if err != nil {
		t.Fatal(err)
	}
	p := parseServicePAC(t, h.store, serviceCredentials.Ticket)
	logonData, ok := p.Buffer(pac.LogonInfoBuffer)
	if !ok {
		t.Fatal("service ticket PAC has no logon-info buffer")
	}
	logon, err := pac.ParseLogonInfo(logonData)
	if err != nil {
		t.Fatal(err)
	}
	if logon.UserID != 2001 || logon.PrimaryGroupID != 2001 {
		t.Fatalf("unexpected PAC IDs: user=%d primary=%d", logon.UserID, logon.PrimaryGroupID)
	}
	if len(logon.GroupIDs) != 2 || logon.GroupIDs[0].RelativeID != 4001 ||
		logon.GroupIDs[1].RelativeID != 5678 {
		t.Fatalf("unexpected PAC groups: %#v", logon.GroupIDs)
	}
	for _, group := range logon.GroupIDs {
		if group.Attributes != 7 {
			t.Fatalf("unexpected PAC group attributes: %d", group.Attributes)
		}
	}
	if logon.LogonDomainName != "MITKDC" || logon.LogonDomainID.String() != realmSID.String() {
		t.Fatalf("unexpected PAC domain: %s %s", logon.LogonDomainName, logon.LogonDomainID)
	}
	h.server.EnablePAC = false
	h.server.GeneratePACIdentity = nil
	tgtNoPAC, err := goClient.ASExchange(context.Background(), *user, mitPassword)
	if err != nil {
		t.Fatal(err)
	}
	withoutPAC, err := goClient.TGSExchange(context.Background(), tgtNoPAC, *service)
	if err != nil {
		t.Fatal(err)
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(withoutPAC.Ticket, &ticket); err != nil {
		t.Fatal(err)
	}
	etype, err = crypto.NewRegistry().Get(ticket.EncPart.EType)
	if err != nil {
		t.Fatal(err)
	}
	record := h.store.services[principalKey(*service)]
	plain, err := etype.Decrypt(record.Keys[ticket.EncPart.EType].Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	if _, err := pac.FromAuthorizationData(part.AuthorizationData); err == nil {
		t.Fatal("PAC-disabled service ticket unexpectedly contained a PAC")
	}
}

func parseServicePAC(t *testing.T, store *providerStore, encoded []byte) *pac.PAC {
	t.Helper()
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(encoded, &ticket); err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(ticket.EncPart.EType)
	if err != nil {
		t.Fatal(err)
	}
	servicePrincipal := principal.Principal{
		Realm:      ticket.Realm,
		NameType:   principal.NameType(ticket.SName.NameType),
		Components: ticket.SName.NameString,
	}
	record, ok := store.services[principalKey(servicePrincipal)]
	if !ok {
		t.Fatalf("missing service key for %s", servicePrincipal)
	}
	plain, err := etype.Decrypt(record.Keys[ticket.EncPart.EType].Key, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var part protocol.EncTicketPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	p, err := pac.FromAuthorizationData(part.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPACIdentity(t *testing.T) {
	realmSID, err := pac.ParseSID("S-1-5-21-1-2-3")
	if err != nil {
		t.Fatal(err)
	}
	store := &providerStore{realm: "EXAMPLE.TEST", realmSID: &realmSID}
	response := api.NewKerberosUserKeyOutpost(
		"alice", true, "alice@EXAMPLE.TEST", 1, "EXAMPLE.TESTalice", nil,
		api.NullableInt32{}, api.NullableInt32{},
		false,
		2007, 2007, []int32{4001, 5678}, "Alice Example", "alice@example.test",
		api.NullableTime{}, nil,
	)
	identity := store.pacIdentity(response)
	if identity == nil || identity.LogonInfo == nil {
		t.Fatal("PAC identity was not generated")
	}
	info := identity.LogonInfo
	if info.EffectiveName != "alice" || info.FullName != "Alice Example" {
		t.Fatalf("unexpected PAC names: %#v", info)
	}
	if info.UserID != 2007 || info.PrimaryGroupID != 2007 {
		t.Fatalf("unexpected PAC RIDs: user=%d primary=%d", info.UserID, info.PrimaryGroupID)
	}
	if len(info.GroupIDs) != 2 || info.GroupIDs[0].RelativeID != 4001 ||
		info.GroupIDs[1].RelativeID != 5678 {
		t.Fatalf("unexpected PAC groups: %#v", info.GroupIDs)
	}
	for _, group := range info.GroupIDs {
		if group.Attributes != 7 {
			t.Fatalf("unexpected PAC group attributes: %d", group.Attributes)
		}
	}
	if got := info.LogonDomainID.String(); got != "S-1-5-21-1-2-3" {
		t.Fatalf("unexpected PAC domain SID: %s", got)
	}
	if got := identity.SID.String(); got != "S-1-5-21-1-2-3-2007" {
		t.Fatalf("unexpected PAC user SID: %s", got)
	}
	if info.LogonDomainName != "EXAMPLE" || info.LogonServer != "authentik" ||
		identity.DNSDomainName != "example.test" || identity.UPN != "alice@example.test" {
		t.Fatalf("unexpected PAC domain fields: %#v %#v", info, identity)
	}
}

func TestPACIdentityDisabledAndMissingData(t *testing.T) {
	realmSID, err := pac.ParseSID("S-1-5-21-1-2-3")
	if err != nil {
		t.Fatal(err)
	}
	store := &providerStore{realmSID: &realmSID}
	if got := store.pacIdentity(nil); got != nil {
		t.Fatalf("nil PAC payload produced identity: %#v", got)
	}
	if got, err := (&providerStore{}).generatePACIdentity(
		principal.Principal{Realm: "EXAMPLE.TEST", Components: []string{"alice"}},
		principal.Principal{},
	); err != nil || got != nil {
		t.Fatalf("PAC-disabled callback returned %v, %v", got, err)
	}
}
