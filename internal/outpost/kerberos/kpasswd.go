package kerberos

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/transport"
	"github.com/Exonical/go-kerberos/krb5/types"

	api "goauthentik.io/packages/client-go"
)

const (
	kpasswdVersion   = 1
	kpasswdPrivUsage = 13
	kpasswdResultLen = 2
)

type kpasswdRequest struct {
	apReqDER []byte
	privDER  []byte
	apReq    protocol.APReq
}

func parseKpasswdRequest(data []byte) (kpasswdRequest, error) {
	if len(data) < 6 {
		return kpasswdRequest{}, errors.New("kpasswd request: truncated header")
	}
	if int(binary.BigEndian.Uint16(data[:2])) != len(data) {
		return kpasswdRequest{}, errors.New("kpasswd request: inconsistent length")
	}
	if binary.BigEndian.Uint16(data[2:4]) != kpasswdVersion {
		return kpasswdRequest{}, errors.New("kpasswd request: unsupported version")
	}
	apLength := int(binary.BigEndian.Uint16(data[4:6]))
	if apLength == 0 || apLength > len(data)-6 {
		return kpasswdRequest{}, errors.New("kpasswd request: invalid AP-REQ length")
	}
	apReqDER := append([]byte(nil), data[6:6+apLength]...)
	var apReq protocol.APReq
	if err := asn1.Unmarshal(apReqDER, &apReq); err != nil {
		return kpasswdRequest{}, fmt.Errorf("kpasswd request: decode AP-REQ: %w", err)
	}
	if len(data) == 6+apLength {
		return kpasswdRequest{}, errors.New("kpasswd request: missing KRB-PRIV")
	}
	return kpasswdRequest{
		apReqDER: apReqDER,
		privDER:  append([]byte(nil), data[6+apLength:]...),
		apReq:    apReq,
	}, nil
}

func (rs *KerberosServer) serveKpasswdUDP(conn net.PacketConn) error {
	buffer := make([]byte, 64*1024)
	for {
		size, address, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		response, err := rs.handleKpasswd(buffer[:size], true)
		if err != nil {
			rs.log.WithError(err).Warn("failed to handle kpasswd request")
			continue
		}
		if _, err := conn.WriteTo(response, address); err != nil {
			return err
		}
	}
}

func (rs *KerberosServer) serveKpasswdTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			for {
				request, err := transport.ReadTCPFrame(conn, transport.DefaultMaxFrameSize)
				if err != nil {
					return
				}
				response, err := rs.handleKpasswd(request, false)
				if err != nil {
					rs.log.WithError(err).Warn("failed to handle kpasswd request")
					return
				}
				if err := transport.WriteTCPFrame(conn, response); err != nil {
					return
				}
			}
		}()
	}
}

func (rs *KerberosServer) handleKpasswd(data []byte, udp bool) ([]byte, error) {
	request, err := parseKpasswdRequest(data)
	if err != nil {
		return kpasswdError("", "", krberrors.KDCErrPreauthFailed), nil
	}
	realm := request.apReq.Ticket.Realm
	rs.mu.Lock()
	var provider *ProviderInstance
	for _, candidate := range rs.providers {
		if candidate.Config.RealmName == realm {
			provider = candidate
			break
		}
	}
	rs.mu.Unlock()
	if provider == nil {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrPreauthFailed), nil
	}
	if !provider.Config.GetKpasswdEnabled() {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrPreauthFailed), nil
	}
	if udp && !provider.Config.GetUdpEnabled() {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrPreauthFailed), nil
	}
	if !udp && !provider.Config.GetTcpEnabled() {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrPreauthFailed), nil
	}
	record, ok, err := provider.Store.changepwRecord(principal.Principal{
		Realm: realm, NameType: principal.NTSrvInstance,
		Components: []string{"kadmin", "changepw"},
	})
	if err != nil {
		return nil, err
	}
	if !ok {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrEtypeNosp), nil
	}
	kt := &keytab.Keytab{}
	for enctype, value := range record.Keys {
		kt.Entries = append(kt.Entries, keytab.Entry{
			Principal: record.Name,
			Timestamp: time.Now().Unix(),
			KVNO:      uint32(value.KVNO),
			Enctype:   enctype,
			Key:       append([]byte(nil), value.Key...),
		})
	}
	now := time.Now().UTC()
	verified, err := ap.VerifyAPReq(kt, request.apReqDER, now, 5*time.Minute)
	if err != nil {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrPreauthFailed), nil
	}
	if verified.Client.Realm != realm || len(verified.Client.Components) != 1 {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrPreauthFailed), nil
	}
	key := verified.SubKey
	if key == nil {
		key = &verified.SessionKey
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, err
	}
	var priv protocol.KRBPriv
	if err := asn1.Unmarshal(request.privDER, &priv); err != nil {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrPreauthFailed), nil
	}
	if priv.PVNO != 5 || priv.MsgType != 21 || priv.EncPart.EType != key.KeyType {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrPreauthFailed), nil
	}
	plaintext, err := etype.Decrypt(key.KeyValue, kpasswdPrivUsage, priv.EncPart.Cipher)
	if err != nil {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrPreauthFailed), nil
	}
	var part protocol.EncKRBPrivPart
	if err := asn1.Unmarshal(plaintext, &part); err != nil || len(part.UserData) == 0 {
		return kpasswdError("kadmin/changepw", realm, krberrors.KDCErrPreauthFailed), nil
	}
	username := verified.Client.Components[0]
	password := append([]byte(nil), part.UserData...)
	requestBody := api.NewKerberosSetPasswordRequest(username, string(password))
	clear(password)
	response, err := rs.ac.Client.OutpostsAPI.
		OutpostsKerberosSetPasswordCreate(context.Background(), provider.Store.providerID).
		KerberosSetPasswordRequest(*requestBody).Execute()
	if err != nil {
		if message, ok := passwordPolicyError(response, err); ok {
			return buildKpasswdReply(verified, 4, message, now)
		}
		return buildKpasswdReply(verified, 2, "password change failed", now)
	}
	provider.Store.invalidateUserKey(username)
	return buildKpasswdReply(verified, 0, "", now)
}

func passwordPolicyError(response *http.Response, err error) (string, bool) {
	if response == nil || response.StatusCode != http.StatusBadRequest {
		return "", false
	}
	var openAPIError *api.GenericOpenAPIError
	if !errors.As(err, &openAPIError) {
		return "", false
	}
	var payload struct {
		Messages []string `json:"messages"`
	}
	if json.Unmarshal(openAPIError.Body(), &payload) != nil || len(payload.Messages) == 0 {
		return "", false
	}
	return strings.Join(payload.Messages, "\n"), true
}

func buildKpasswdReply(state *ap.VerifiedAPReq, code uint16, message string, now time.Time) ([]byte, error) {
	apRep, err := ap.BuildAPRep(state)
	if err != nil {
		return nil, err
	}
	key := state.SubKey
	if key == nil {
		key = &state.SessionKey
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, err
	}
	userData := make([]byte, kpasswdResultLen+len(message))
	binary.BigEndian.PutUint16(userData[:kpasswdResultLen], code)
	copy(userData[kpasswdResultLen:], message)
	usec := int32(now.Nanosecond() / 1000)
	part := protocol.EncKRBPrivPart{
		UserData:  userData,
		Timestamp: &types.KerberosTime{Time: now.UTC(), Present: true},
		Usec:      &usec,
		SeqNumber: state.SeqNumber,
		SAddress:  protocol.HostAddress{},
	}
	plain, err := asn1.Marshal(part)
	if err != nil {
		return nil, err
	}
	ciphertext, err := etype.Encrypt(key.KeyValue, kpasswdPrivUsage, plain)
	if err != nil {
		return nil, err
	}
	priv, err := asn1.Marshal(protocol.KRBPriv{
		PVNO: 5, MsgType: 21,
		EncPart: protocol.EncryptedData{EType: key.KeyType, Cipher: ciphertext},
	})
	if err != nil {
		return nil, err
	}
	response := make([]byte, 6+len(apRep)+len(priv))
	binary.BigEndian.PutUint16(response[:2], uint16(len(response)))
	binary.BigEndian.PutUint16(response[2:4], kpasswdVersion)
	binary.BigEndian.PutUint16(response[4:6], uint16(len(apRep)))
	copy(response[6:], apRep)
	copy(response[6+len(apRep):], priv)
	return response, nil
}

func kpasswdError(service, realm string, code krberrors.ErrorCode) []byte {
	components := strings.Split(service, "/")
	now := time.Now().UTC()
	data, _ := asn1.Marshal(protocol.KRBError{
		PVNO: 5, MsgType: 30,
		STime:     types.KerberosTime{Time: now, Present: true},
		Susec:     int32(now.Nanosecond() / 1000),
		ErrorCode: int32(code),
		Realm:     realm,
		SName: protocol.PrincipalName{
			NameType:   int32(principal.NTSrvInstance),
			NameString: components,
		},
	})
	return data
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
