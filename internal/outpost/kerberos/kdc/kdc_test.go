package kdc

import (
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func testProvider(t *testing.T) (*Provider, crypto.EType, []byte, []byte) {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := etype.StringToKey([]byte("correct horse battery staple"), []byte("REALMalice"), nil)
	if err != nil {
		t.Fatal(err)
	}
	serviceKey, err := etype.StringToKey([]byte("service secret"), []byte("REALMHTTP"), nil)
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{
		Realm:              "REALM",
		MasterKey:          []byte("provider master key"),
		AllowedEnctypes:    []int32{crypto.EnctypeAES256SHA1},
		MaxTicketLifetime:  30 * time.Minute,
		MaxRenewalLifetime: time.Hour,
		Now:                func() time.Time { return time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) },
		User: func(username string) (*UserKey, error) {
			if username != "alice" {
				return nil, nil
			}
			return &UserKey{
				Username: username, Salt: "REALMalice", KVNO: 3,
				Keys: map[int32]Key{crypto.EnctypeAES256SHA1: {EType: crypto.EnctypeAES256SHA1, Value: userKey, KVNO: 3}},
			}, nil
		},
		Services: map[string]ServicePrincipal{
			"http/host@REALM": {
				SPN: "http/host", KVNO: 5,
				Keys: map[int32]Key{crypto.EnctypeAES256SHA1: {EType: crypto.EnctypeAES256SHA1, Value: serviceKey, KVNO: 5}},
			},
		},
	}
	return provider, etype, userKey, serviceKey
}

func makeASReq(t *testing.T, etype crypto.EType, key []byte, withPA bool) []byte {
	t.Helper()
	req := protocol.ASReq{
		PVNO: ProtocolVersion, MsgType: MsgASReq,
		ReqBody: protocol.KDCReqBody{
			CName: &protocol.PrincipalName{NameType: 1, NameString: []string{"alice"}},
			Realm: "REALM", SName: ptrPrincipal(protocol.PrincipalName{NameType: 2, NameString: []string{"krbtgt", "REALM"}}),
			Till: kerberosTime(time.Date(2026, 1, 1, 12, 30, 0, 0, time.UTC)), Nonce: 1234,
			EType: []int32{etype.ID()},
		},
	}
	if withPA {
		plain, err := asn1.Marshal(PAEncTsEnc{PA: kerberosTime(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))})
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := etype.Encrypt(key, usagePAEncTimestamp, plain)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := asn1.Marshal(protocol.EncryptedData{EType: etype.ID(), Cipher: cipher})
		if err != nil {
			t.Fatal(err)
		}
		req.PAData = protocol.MethodData{{PADataType: PAEncTimestamp, PADataValue: encoded}}
	}
	data, err := asn1.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestASPreauthAndTGSRoundTrip(t *testing.T) {
	provider, etype, userKey, serviceKey := testProvider(t)
	response, err := HandleASReq(makeASReq(t, etype, userKey, true), provider)
	if err != nil {
		t.Fatal(err)
	}
	var asrep protocol.ASRep
	if err := asn1.Unmarshal(response, &asrep); err != nil {
		t.Fatal(err)
	}
	if asrep.CRealm != "REALM" || asrep.CName.NameString[0] != "alice" {
		t.Fatalf("unexpected AS-REP principal: %#v", asrep.CName)
	}
	partCipher, err := etype.Decrypt(userKey, usageASRep, asrep.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var asPart protocol.EncASRepPart
	if err := asn1.Unmarshal(partCipher, &asPart); err != nil {
		t.Fatal(err)
	}
	if asPart.Key.KeyType != etype.ID() || asPart.EndTime.Time.Sub(provider.now()) != 30*time.Minute {
		t.Fatalf("unexpected AS-REP part: %#v", asPart)
	}
	body := protocol.KDCReqBody{
		KDCOptions: types.KDCForwardable, Realm: "REALM",
		CName: &asrep.CName,
		SName: ptrPrincipal(protocol.PrincipalName{NameType: 3, NameString: []string{"http", "host"}}),
		Till:  kerberosTime(provider.now().Add(time.Hour)), RTime: ptrTime(provider.now().Add(2 * time.Hour)),
		Nonce: 4321, EType: []int32{etype.ID()},
	}
	unknownBody := body
	unknownBody.SName = ptrPrincipal(protocol.PrincipalName{NameType: 3, NameString: []string{"unknown", "host"}})
	unknownResponse, err := HandleTGSReq(makeTGSReq(t, asrep.Ticket, asPart.Key.KeyValue, unknownBody), provider)
	if err != nil {
		t.Fatal(err)
	}
	var unknownError protocol.KRBError
	if err := asn1.Unmarshal(unknownResponse, &unknownError); err != nil {
		t.Fatal(err)
	}
	if unknownError.ErrorCode != KDCErrSPrincipalUnknown {
		t.Fatalf("unknown service error = %d, want %d", unknownError.ErrorCode, KDCErrSPrincipalUnknown)
	}
	tgsData := makeTGSReq(t, asrep.Ticket, asPart.Key.KeyValue, body)
	tgsResponse, err := HandleTGSReq(tgsData, provider)
	if err != nil {
		t.Fatal(err)
	}
	var tgsrep protocol.TGSRep
	if err := asn1.Unmarshal(tgsResponse, &tgsrep); err != nil {
		t.Fatal(err)
	}
	tgsPartCipher, err := etype.Decrypt(asPart.Key.KeyValue, usageTGSRep, tgsrep.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var tgsPart protocol.EncTGSRepPart
	if err := asn1.Unmarshal(tgsPartCipher, &tgsPart); err != nil {
		t.Fatal(err)
	}
	if tgsPart.SName.NameString[0] != "http" || tgsPart.Key.KeyType != etype.ID() {
		t.Fatalf("unexpected TGS-REP part: %#v", tgsPart)
	}
	serviceTicketCipher, err := etype.Decrypt(serviceKey, usageTicket, tgsrep.Ticket.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var servicePart protocol.EncTicketPart
	if err := asn1.Unmarshal(serviceTicketCipher, &servicePart); err != nil {
		t.Fatal(err)
	}
	if servicePart.CName.NameString[0] != "alice" || servicePart.CRealm != "REALM" {
		t.Fatalf("unexpected service ticket: %#v", servicePart)
	}
}

func makeTGSReq(t *testing.T, ticket protocol.Ticket, sessionKey []byte, body protocol.KDCReqBody) []byte {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(ticket.EncPart.EType)
	if err != nil {
		t.Fatal(err)
	}
	checksumInput, err := asn1.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := etype.Checksum(sessionKey, usageTGSChecksum, checksumInput)
	if err != nil {
		t.Fatal(err)
	}
	authPlain, err := asn1.Marshal(protocol.Authenticator{
		AuthenticatorVNO: ProtocolVersion, CRealm: body.Realm, CName: *body.CName,
		Checksum: &protocol.Checksum{ChecksumType: crypto.ChecksumHMACSHA196AES256, Checksum: checksum},
		Ctime:    kerberosTime(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatal(err)
	}
	authCipher, err := etype.Encrypt(sessionKey, usageAuthenticator, authPlain)
	if err != nil {
		t.Fatal(err)
	}
	apreqData, err := asn1.Marshal(protocol.APReq{
		PVNO: ProtocolVersion, MsgType: protocolTagAPReq(), Ticket: ticket,
		Authenticator: protocol.EncryptedData{EType: etype.ID(), Cipher: authCipher},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := asn1.Marshal(protocol.TGSReq{
		PVNO: ProtocolVersion, MsgType: MsgTGSReq,
		PAData:  protocol.MethodData{{PADataType: PATGSReq, PADataValue: apreqData}},
		ReqBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestASReqErrors(t *testing.T) {
	provider, etype, userKey, _ := testProvider(t)
	for name, request := range map[string][]byte{
		"preauth required": makeASReq(t, etype, userKey, false),
		"unknown client":   makeASReqUnknown(t, etype),
	} {
		response, err := HandleASReq(request, provider)
		if err != nil {
			t.Fatal(err)
		}
		var krbError protocol.KRBError
		if err := asn1.Unmarshal(response, &krbError); err != nil {
			t.Fatal(err)
		}
		want := int32(KDCErrPreauthRequired)
		if name == "unknown client" {
			want = KDCErrCPrincipalUnknown
		}
		if krbError.ErrorCode != want {
			t.Errorf("%s error code = %d, want %d", name, krbError.ErrorCode, want)
		}
		if name == "preauth required" {
			var info protocol.ETypeInfo2
			if err := asn1.Unmarshal(krbError.EData, &info); err != nil {
				t.Fatal(err)
			}
			if len(info) != 1 || info[0].EType != etype.ID() || info[0].Salt == nil || *info[0].Salt != "REALMalice" {
				t.Fatalf("unexpected PA-ETYPE-INFO2: %#v", info)
			}
		}
	}
}

func TestASReqInvalidPreauthAndUnsupportedEnctype(t *testing.T) {
	provider, etype, userKey, _ := testProvider(t)
	request := makeASReq(t, etype, make([]byte, etype.KeySize()), true)
	response, err := HandleASReq(request, provider)
	if err != nil {
		t.Fatal(err)
	}
	var krbError protocol.KRBError
	if err := asn1.Unmarshal(response, &krbError); err != nil {
		t.Fatal(err)
	}
	if krbError.ErrorCode != KDCErrPreauthFailed {
		t.Fatalf("invalid preauth error = %d, want %d", krbError.ErrorCode, KDCErrPreauthFailed)
	}
	request = makeASReq(t, etype, userKey, false)
	var asreq protocol.ASReq
	if err := asn1.Unmarshal(request, &asreq); err != nil {
		t.Fatal(err)
	}
	asreq.ReqBody.EType = []int32{999}
	request, err = asn1.Marshal(asreq)
	if err != nil {
		t.Fatal(err)
	}
	response, err = HandleASReq(request, provider)
	if err != nil {
		t.Fatal(err)
	}
	if err := asn1.Unmarshal(response, &krbError); err != nil {
		t.Fatal(err)
	}
	if krbError.ErrorCode != KDCErrETypeNoSupp {
		t.Fatalf("unsupported enctype error = %d, want %d", krbError.ErrorCode, KDCErrETypeNoSupp)
	}
}

func TestDeriveKRBtgtKey(t *testing.T) {
	first, err := DeriveKRBtgtKey([]byte("provider master key"), crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveKRBtgtKey([]byte("provider master key"), crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || string(first) != string(second) {
		t.Fatalf("derived key is not deterministic or has wrong length: %x", first)
	}
}

func makeASReqUnknown(t *testing.T, etype crypto.EType) []byte {
	data := makeASReq(t, etype, nil, false)
	var req protocol.ASReq
	if err := asn1.Unmarshal(data, &req); err != nil {
		t.Fatal(err)
	}
	req.ReqBody.CName.NameString[0] = "unknown"
	data, err := asn1.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func ptrPrincipal(value protocol.PrincipalName) *protocol.PrincipalName { return &value }
func ptrTime(value time.Time) *types.KerberosTime {
	result := kerberosTime(value)
	return &result
}
