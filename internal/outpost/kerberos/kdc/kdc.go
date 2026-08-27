package kdc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
	"golang.org/x/crypto/hkdf"
)

const (
	ProtocolVersion = 5
	MsgASReq        = 10
	MsgASRep        = 11
	MsgTGSReq       = 12
	MsgTGSRep       = 13
	MsgKRBError     = 30

	PAEncTimestamp = 2
	PATGSReq       = 1
	PAETypeInfo2   = 19

	KDCErrNameExp            int32 = 1
	KDCErrServiceUnavailable int32 = 29
	KDCErrCPrincipalUnknown  int32 = 6
	KDCErrSPrincipalUnknown  int32 = 7
	KDCErrPreauthFailed      int32 = 24
	KDCErrPreauthRequired    int32 = 25
	KDCErrETypeNoSupp        int32 = 14
	KDCErrTktExpired         int32 = 32
	KRBAPErrBadIntegrity     int32 = 31
	KRBAPErrSkew             int32 = 37
)

const (
	usagePAEncTimestamp = 1
	usageTicket         = 2
	usageASRep          = 3
	usageAuthenticator  = 7
	usageTGSRep         = 8
	usageTGSChecksum    = 6
)

type Key struct {
	EType int32
	Value []byte
	KVNO  uint32
}

type UserKey struct {
	Username string
	Salt     string
	KVNO     uint32
	Keys     map[int32]Key
}

type ServicePrincipal struct {
	SPN  string
	KVNO uint32
	Keys map[int32]Key
}

type Provider struct {
	Realm              string
	MasterKey          []byte
	AllowedEnctypes    []int32
	MaxTicketLifetime  time.Duration
	MaxRenewalLifetime time.Duration
	Services           map[string]ServicePrincipal
	User               func(string) (*UserKey, error)
	Now                func() time.Time
	Random             io.Reader
}

type PAEncTsEnc struct {
	PA   doKerberosTime `krb5:"tag:0"`
	USec *int32         `krb5:"tag:1,optional"`
}

type doKerberosTime = types.KerberosTime

func (p *Provider) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

func (p *Provider) randomReader() io.Reader {
	if p.Random != nil {
		return p.Random
	}
	return rand.Reader
}

func HandleASReq(data []byte, provider *Provider) ([]byte, error) {
	var req protocol.ASReq
	if err := asn1.Unmarshal(data, &req); err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, nil, nil, providerRealm(provider), nil)
	}
	if req.PVNO != ProtocolVersion || req.MsgType != MsgASReq {
		return marshalError(provider, KDCErrServiceUnavailable, nil, nil, providerRealm(provider), nil)
	}
	if req.ReqBody.CName == nil || len(req.ReqBody.CName.NameString) == 0 {
		return marshalError(provider, KDCErrCPrincipalUnknown, nil, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	username := req.ReqBody.CName.NameString[0]
	if provider == nil || provider.User == nil {
		return marshalError(provider, KDCErrServiceUnavailable, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	user, err := provider.User(username)
	if err != nil || user == nil {
		return marshalError(provider, KDCErrCPrincipalUnknown, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	etype, key, err := chooseKey(provider, req.ReqBody.EType, user.Keys)
	if err != nil {
		return marshalError(provider, KDCErrETypeNoSupp, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	pa := findPA(req.PAData, PAEncTimestamp)
	if pa == nil {
		info, marshalErr := asn1.Marshal(buildETypeInfo(provider, user))
		if marshalErr != nil {
			return marshalError(provider, KDCErrServiceUnavailable, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
		}
		return marshalError(provider, KDCErrPreauthRequired, req.ReqBody.CName, info, req.ReqBody.Realm, req.ReqBody.SName)
	}
	var encrypted protocol.EncryptedData
	if err := asn1.Unmarshal(pa.PADataValue, &encrypted); err != nil {
		return marshalError(provider, KDCErrPreauthFailed, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	etypeImpl, err := crypto.NewRegistry().Get(encrypted.EType)
	if err != nil || encrypted.EType != etype {
		return marshalError(provider, KDCErrPreauthFailed, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	plain, err := etypeImpl.Decrypt(key.Value, usagePAEncTimestamp, encrypted.Cipher)
	if err != nil {
		return marshalError(provider, KDCErrPreauthFailed, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	var timestamp PAEncTsEnc
	if err := asn1.Unmarshal(plain, &timestamp); err != nil || !withinSkew(timestamp.PA.Time, provider.now()) {
		return marshalError(provider, KDCErrPreauthFailed, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	session, err := randomBytes(provider.randomReader(), etypeImpl.KeySize())
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	start, end, renew := ticketTimes(provider, req.ReqBody.Till, req.ReqBody.RTime)
	cname := *req.ReqBody.CName
	tgtName := principalName("krbtgt", providerRealm(provider))
	ticketPart := protocol.EncTicketPart{
		Flags:  types.TicketInitial | types.TicketPreAuthent | types.TicketForwardable,
		Key:    protocol.EncryptionKey{KeyType: etype, KeyValue: session},
		CRealm: providerRealm(provider), CName: cname,
		Transited: protocol.TransitedEncoding{TrType: 0},
		AuthTime:  kerberosTime(provider.now()), StartTime: &start, EndTime: end,
		RenewTill: renew,
	}
	ticketDER, err := asn1.Marshal(ticketPart)
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	tgtKey, err := deriveKRBtgt(provider.MasterKey, etypeImpl)
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	tgtCipher, err := etypeImpl.Encrypt(tgtKey, usageTicket, ticketDER)
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	tgt := protocol.Ticket{
		TktVNO: ProtocolVersion, Realm: providerRealm(provider), SName: tgtName,
		EncPart: protocol.EncryptedData{EType: etype, KVNO: uint32Ptr(1), Cipher: tgtCipher},
	}
	repPart := protocol.EncASRepPart{
		Key:   protocol.EncryptionKey{KeyType: etype, KeyValue: session},
		Nonce: req.ReqBody.Nonce, Flags: ticketPart.Flags,
		AuthTime: ticketPart.AuthTime, StartTime: &start, EndTime: end,
		RenewTill: renew, SRealm: providerRealm(provider), SName: tgtName,
	}
	repDER, err := asn1.Marshal(repPart)
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	repCipher, err := etypeImpl.Encrypt(key.Value, usageASRep, repDER)
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	response, err := asn1.Marshal(protocol.ASRep{
		PVNO: ProtocolVersion, MsgType: MsgASRep, CRealm: providerRealm(provider),
		CName: cname, Ticket: tgt,
		EncPart: protocol.EncryptedData{EType: etype, KVNO: uint32Ptr(user.KVNO), Cipher: repCipher},
	})
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	return response, nil
}

func HandleTGSReq(data []byte, provider *Provider) ([]byte, error) {
	var req protocol.TGSReq
	if err := asn1.Unmarshal(data, &req); err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, nil, nil, providerRealm(provider), nil)
	}
	if req.PVNO != ProtocolVersion || req.MsgType != MsgTGSReq {
		return marshalError(provider, KDCErrServiceUnavailable, nil, nil, providerRealm(provider), nil)
	}
	pa := findPA(req.PAData, PATGSReq)
	if pa == nil {
		return marshalError(provider, KDCErrPreauthRequired, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	var apreq protocol.APReq
	if err := asn1.Unmarshal(pa.PADataValue, &apreq); err != nil {
		return marshalError(provider, KDCErrPreauthFailed, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	if apreq.PVNO != ProtocolVersion || apreq.MsgType != protocolTagAPReq() ||
		apreq.Ticket.Realm != providerRealm(provider) ||
		apreq.Ticket.SName.NameString == nil ||
		!samePrincipal(apreq.Ticket.SName, principalName("krbtgt", providerRealm(provider))) {
		return marshalError(provider, KDCErrPreauthFailed, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	ticketEType, err := crypto.NewRegistry().Get(apreq.Ticket.EncPart.EType)
	if err != nil {
		return marshalError(provider, KDCErrETypeNoSupp, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	tgtKey, err := deriveKRBtgt(provider.MasterKey, ticketEType)
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	ticketDER, err := ticketEType.Decrypt(tgtKey, usageTicket, apreq.Ticket.EncPart.Cipher)
	if err != nil {
		return marshalError(provider, KDCErrPreauthFailed, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	var ticketPart protocol.EncTicketPart
	if err := asn1.Unmarshal(ticketDER, &ticketPart); err != nil {
		return marshalError(provider, KDCErrPreauthFailed, req.ReqBody.CName, nil, req.ReqBody.Realm, req.ReqBody.SName)
	}
	if ticketPart.CRealm != providerRealm(provider) {
		return marshalError(provider, KDCErrPreauthFailed, &ticketPart.CName, nil, ticketPart.CRealm, req.ReqBody.SName)
	}
	if !ticketValid(ticketPart, provider.now()) {
		return marshalError(provider, KDCErrTktExpired, &ticketPart.CName, nil, ticketPart.CRealm, req.ReqBody.SName)
	}
	sessionEType, err := crypto.NewRegistry().Get(ticketPart.Key.KeyType)
	if err != nil {
		return marshalError(provider, KDCErrETypeNoSupp, &ticketPart.CName, nil, ticketPart.CRealm, req.ReqBody.SName)
	}
	if apreq.Authenticator.EType != sessionEType.ID() {
		return marshalError(provider, KDCErrPreauthFailed, &ticketPart.CName, nil, ticketPart.CRealm, req.ReqBody.SName)
	}
	authDER, err := sessionEType.Decrypt(ticketPart.Key.KeyValue, usageAuthenticator, apreq.Authenticator.Cipher)
	if err != nil {
		return marshalError(provider, KDCErrPreauthFailed, &ticketPart.CName, nil, ticketPart.CRealm, req.ReqBody.SName)
	}
	var auth protocol.Authenticator
	if err := asn1.Unmarshal(authDER, &auth); err != nil || !samePrincipal(auth.CName, ticketPart.CName) || auth.CRealm != ticketPart.CRealm || !withinSkew(auth.Ctime.Time, provider.now()) {
		return marshalError(provider, KDCErrPreauthFailed, &ticketPart.CName, nil, ticketPart.CRealm, req.ReqBody.SName)
	}
	if auth.Checksum == nil || auth.Checksum.ChecksumType == 0 || sessionEType.VerifyChecksum(ticketPart.Key.KeyValue, usageTGSChecksum, mustMarshal(req.ReqBody), auth.Checksum.Checksum) != nil {
		return marshalError(provider, KDCErrPreauthFailed, &ticketPart.CName, nil, ticketPart.CRealm, req.ReqBody.SName)
	}
	if req.ReqBody.SName == nil {
		return marshalError(provider, KDCErrSPrincipalUnknown, &ticketPart.CName, nil, ticketPart.CRealm, nil)
	}
	if req.ReqBody.Realm != "" && req.ReqBody.Realm != providerRealm(provider) {
		return marshalError(provider, KDCErrSPrincipalUnknown, &ticketPart.CName, nil, providerRealm(provider), req.ReqBody.SName)
	}
	service := principalDisplay(*req.ReqBody.SName, req.ReqBody.Realm)
	sp, ok := provider.Services[service]
	if !ok {
		sp, ok = provider.Services[principalDisplay(*req.ReqBody.SName, providerRealm(provider))]
	}
	if !ok {
		return marshalError(provider, KDCErrSPrincipalUnknown, &ticketPart.CName, nil, providerRealm(provider), req.ReqBody.SName)
	}
	etype, serviceKey, err := chooseKey(provider, req.ReqBody.EType, sp.Keys)
	if err != nil {
		return marshalError(provider, KDCErrETypeNoSupp, &ticketPart.CName, nil, providerRealm(provider), req.ReqBody.SName)
	}
	serviceEType, err := crypto.NewRegistry().Get(etype)
	if err != nil {
		return marshalError(provider, KDCErrETypeNoSupp, &ticketPart.CName, nil, providerRealm(provider), req.ReqBody.SName)
	}
	start, end, renew := ticketTimes(provider, req.ReqBody.Till, req.ReqBody.RTime)
	serviceSession, err := randomBytes(provider.randomReader(), serviceEType.KeySize())
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, &ticketPart.CName, nil, providerRealm(provider), req.ReqBody.SName)
	}
	servicePart := protocol.EncTicketPart{
		Flags: ticketPart.Flags, Key: protocol.EncryptionKey{KeyType: serviceEType.ID(), KeyValue: serviceSession},
		CRealm: ticketPart.CRealm, CName: ticketPart.CName, Transited: ticketPart.Transited,
		AuthTime: ticketPart.AuthTime, StartTime: &start, EndTime: end, RenewTill: renew,
	}
	serviceTicketDER, err := asn1.Marshal(servicePart)
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, &ticketPart.CName, nil, providerRealm(provider), req.ReqBody.SName)
	}
	serviceCipher, err := serviceEType.Encrypt(serviceKey.Value, usageTicket, serviceTicketDER)
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, &ticketPart.CName, nil, providerRealm(provider), req.ReqBody.SName)
	}
	serviceTicket := protocol.Ticket{
		TktVNO: ProtocolVersion, Realm: providerRealm(provider), SName: *req.ReqBody.SName,
		EncPart: protocol.EncryptedData{EType: etype, KVNO: uint32Ptr(sp.KVNO), Cipher: serviceCipher},
	}
	repPart := protocol.EncTGSRepPart{
		Key: servicePart.Key, Nonce: req.ReqBody.Nonce, Flags: servicePart.Flags,
		AuthTime: servicePart.AuthTime, StartTime: &start, EndTime: end, RenewTill: renew,
		SRealm: providerRealm(provider), SName: *req.ReqBody.SName,
	}
	repDER, err := asn1.Marshal(repPart)
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, &ticketPart.CName, nil, providerRealm(provider), req.ReqBody.SName)
	}
	repCipher, err := sessionEType.Encrypt(ticketPart.Key.KeyValue, usageTGSRep, repDER)
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, &ticketPart.CName, nil, providerRealm(provider), req.ReqBody.SName)
	}
	response, err := asn1.Marshal(protocol.TGSRep{
		PVNO: ProtocolVersion, MsgType: MsgTGSRep, CRealm: ticketPart.CRealm,
		CName: ticketPart.CName, Ticket: serviceTicket,
		EncPart: protocol.EncryptedData{EType: sessionEType.ID(), Cipher: repCipher},
	})
	if err != nil {
		return marshalError(provider, KDCErrServiceUnavailable, &ticketPart.CName, nil, providerRealm(provider), req.ReqBody.SName)
	}
	return response, nil
}

func Handle(data []byte, provider *Provider) ([]byte, error) {
	if len(data) == 0 {
		return marshalError(provider, KDCErrServiceUnavailable, nil, nil, providerRealm(provider), nil)
	}
	switch int32(data[0] & 0x1f) {
	case protocolTagASReq():
		return HandleASReq(data, provider)
	case protocolTagTGSReq():
		return HandleTGSReq(data, provider)
	default:
		return marshalError(provider, KDCErrServiceUnavailable, nil, nil, providerRealm(provider), nil)
	}
}

func RequestRealm(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("empty kerberos request")
	}
	switch int32(data[0] & 0x1f) {
	case protocolTagASReq():
		var request protocol.ASReq
		if err := asn1.Unmarshal(data, &request); err != nil {
			return "", err
		}
		return request.ReqBody.Realm, nil
	case protocolTagTGSReq():
		var request protocol.TGSReq
		if err := asn1.Unmarshal(data, &request); err != nil {
			return "", err
		}
		return request.ReqBody.Realm, nil
	default:
		return "", fmt.Errorf("unsupported kerberos request")
	}
}

func providerRealm(p *Provider) string {
	if p == nil {
		return ""
	}
	return p.Realm
}

func marshalError(provider *Provider, code int32, cname *protocol.PrincipalName, eData []byte, realm string, sname *protocol.PrincipalName) ([]byte, error) {
	if realm == "" {
		realm = providerRealm(provider)
	}
	if sname == nil {
		name := principalName("krbtgt", realm)
		sname = &name
	}
	now := time.Now().UTC()
	if provider != nil {
		now = provider.now()
	}
	errorValue := protocol.KRBError{
		PVNO: ProtocolVersion, MsgType: MsgKRBError, STime: kerberosTime(now),
		Susec: int32(now.Nanosecond() / 1000), ErrorCode: code, Realm: realm,
		SName: *sname, CName: cname, EData: eData,
	}
	if cname != nil {
		crealm := realm
		errorValue.CRealm = &crealm
	}
	return asn1.Marshal(errorValue)
}

func buildETypeInfo(p *Provider, user *UserKey) protocol.ETypeInfo2 {
	out := make(protocol.ETypeInfo2, 0, len(p.AllowedEnctypes))
	for _, enctype := range p.AllowedEnctypes {
		if _, ok := user.Keys[enctype]; !ok {
			continue
		}
		salt := user.Salt
		out = append(out, protocol.ETypeInfo2Entry{EType: enctype, Salt: &salt})
	}
	return out
}

func chooseKey(p *Provider, requested []int32, keys map[int32]Key) (int32, Key, error) {
	allowed := map[int32]bool{}
	for _, value := range p.AllowedEnctypes {
		allowed[value] = true
	}
	choices := make([]int32, 0)
	for _, value := range requested {
		if allowed[value] {
			if _, ok := keys[value]; ok {
				choices = append(choices, value)
			}
		}
	}
	sort.Slice(choices, func(i, j int) bool { return enctypeStrength(choices[i]) > enctypeStrength(choices[j]) })
	if len(choices) == 0 {
		return 0, Key{}, fmt.Errorf("no mutually supported enctype")
	}
	return choices[0], keys[choices[0]], nil
}

func enctypeStrength(value int32) int {
	switch value {
	case crypto.EnctypeAES256SHA384:
		return 40
	case crypto.EnctypeAES128SHA256:
		return 30
	case crypto.EnctypeAES256SHA1:
		return 20
	default:
		return 10
	}
}

func deriveKRBtgt(master []byte, etype crypto.EType) ([]byte, error) {
	info := []byte(fmt.Sprintf("krbtgt-%d", etype.ID()))
	out := make([]byte, etype.KeySize())
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, info), out); err != nil {
		return nil, err
	}
	return out, nil
}

func DeriveKRBtgtKey(master []byte, enctype int32) ([]byte, error) {
	etype, err := crypto.NewRegistry().Get(enctype)
	if err != nil {
		return nil, err
	}
	return deriveKRBtgt(master, etype)
}

func randomBytes(reader io.Reader, size int) ([]byte, error) {
	out := make([]byte, size)
	_, err := io.ReadFull(reader, out)
	return out, err
}

func findPA(data protocol.MethodData, kind int32) *protocol.PAData {
	for i := range data {
		if data[i].PADataType == kind {
			return &data[i]
		}
	}
	return nil
}

func kerberosTime(t time.Time) types.KerberosTime {
	return types.KerberosTime{Time: t.UTC().Truncate(time.Second), Present: true}
}

func withinSkew(value, now time.Time) bool {
	return !value.IsZero() && value.After(now.Add(-5*time.Minute)) && value.Before(now.Add(5*time.Minute))
}

func ticketTimes(p *Provider, till types.KerberosTime, rtime *types.KerberosTime) (types.KerberosTime, types.KerberosTime, *types.KerberosTime) {
	now := p.now()
	max := p.MaxTicketLifetime
	if max <= 0 {
		max = 10 * time.Hour
	}
	end := now.Add(max)
	if till.Present && till.Time.After(now) && till.Time.Before(end) {
		end = till.Time
	}
	start := kerberosTime(now)
	endTime := kerberosTime(end)
	var renew *types.KerberosTime
	if p.MaxRenewalLifetime > 0 {
		renewEnd := now.Add(p.MaxRenewalLifetime)
		if rtime != nil && rtime.Present && rtime.Time.After(now) && rtime.Time.Before(renewEnd) {
			renewEnd = rtime.Time
		}
		if renewEnd.Before(end) {
			renewEnd = end
		}
		value := kerberosTime(renewEnd)
		renew = &value
	}
	return start, endTime, renew
}

func ticketValid(ticket protocol.EncTicketPart, now time.Time) bool {
	if ticket.StartTime != nil && now.Before(ticket.StartTime.Time.Add(-5*time.Minute)) {
		return false
	}
	return now.Before(ticket.EndTime.Time.Add(5 * time.Minute))
}

func principalName(parts ...string) protocol.PrincipalName {
	return protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: parts}
}

func usernamePrincipal(name *protocol.PrincipalName) string {
	if name == nil || len(name.NameString) == 0 {
		return ""
	}
	return strings.Join(name.NameString, "/")
}

func principalDisplay(name protocol.PrincipalName, realm string) string {
	return strings.Join(name.NameString, "/") + "@" + realm
}

func samePrincipal(a, b protocol.PrincipalName) bool {
	if a.NameType != b.NameType || len(a.NameString) != len(b.NameString) {
		return false
	}
	for i := range a.NameString {
		if a.NameString[i] != b.NameString[i] {
			return false
		}
	}
	return true
}

func protocolTagAPReq() int32  { return protocol.TagAPReq }
func protocolTagASReq() int32  { return protocol.TagASReq }
func protocolTagTGSReq() int32 { return protocol.TagTGSReq }

func uint32Ptr(value uint32) *uint32 { return &value }

func mustMarshal(value any) []byte {
	data, _ := asn1.Marshal(value)
	return data
}

func DecodeKeyValues(values map[string]interface{}) (map[int32]Key, error) {
	out := make(map[int32]Key, len(values))
	for rawType, rawValue := range values {
		var encoded string
		switch value := rawValue.(type) {
		case string:
			encoded = value
		default:
			return nil, fmt.Errorf("key %s is not a string", rawType)
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode key %s: %w", rawType, err)
		}
		var enctype int32
		if _, err := fmt.Sscan(rawType, &enctype); err != nil {
			return nil, fmt.Errorf("parse enctype %s: %w", rawType, err)
		}
		out[enctype] = Key{EType: enctype, Value: data}
	}
	return out, nil
}
