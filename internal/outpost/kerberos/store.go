package kerberos

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/principal"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"

	api "goauthentik.io/packages/client-go"
)

func (s *providerStore) Lookup(name principal.Principal) (kdb.PrincipalRecord, bool, error) {
	if s == nil || name.Realm != s.realm || len(name.Components) == 0 {
		return kdb.PrincipalRecord{}, false, nil
	}
	if len(name.Components) == 2 && name.Components[0] == "krbtgt" && name.Components[1] == s.realm {
		return s.krbtgtRecord(name)
	}
	if len(name.Components) == 2 && name.Components[0] == "kadmin" && name.Components[1] == "changepw" {
		return s.changepwRecord(name)
	}
	if len(name.Components) > 1 {
		record, ok := s.services[principalKey(name)]
		return record, ok, nil
	}
	return s.userRecord(name)
}

// Authorize enforces authentik policy bindings for user ticket requests.
func (s *providerStore) Authorize(
	client, service principal.Principal, asExchange bool,
) error {
	if s == nil {
		return nil
	}
	if isAnonymousPrincipal(client) {
		if !s.anonymousPKINITEnabled {
			return fmt.Errorf("anonymous PKINIT is disabled")
		}
		return nil
	}
	if client.Realm != s.realm || len(client.Components) == 0 {
		return nil
	}
	subject := client.Components[0]
	clientSPN := ""
	if len(client.Components) > 1 {
		if (len(client.Components) == 2 && client.Components[0] == "krbtgt") ||
			(len(client.Components) == 2 && client.Components[0] == "kadmin" &&
				client.Components[1] == "changepw") {
			return nil
		}
		clientSPN = strings.Join(client.Components, "/")
		subject = clientSPN
	}
	spn := ""
	if service.Realm == s.realm && len(service.Components) > 1 &&
		!(len(service.Components) == 2 && service.Components[0] == "krbtgt") &&
		!(len(service.Components) == 2 && service.Components[0] == "kadmin" &&
			service.Components[1] == "changepw") {
		spn = strings.Join(service.Components, "/")
	}
	key := "username\x00" + subject + "\x00" + spn
	if clientSPN != "" {
		key = "client_spn\x00" + subject + "\x00" + spn
	}
	now := time.Now()
	s.accessCacheMu.Lock()
	if cached, ok := s.accessCache[key]; ok && now.Before(cached.expires) {
		s.accessCacheMu.Unlock()
		if cached.allowed {
			return nil
		}
		return fmt.Errorf("authentik policy denied access")
	}
	s.accessCacheMu.Unlock()

	if s.server == nil || s.server.ac == nil || s.server.ac.Client == nil {
		log.WithField("username", subject).
			WithField("spn", spn).Warn("Kerberos policy access check failed")
		return fmt.Errorf("authentik policy access check failed")
	}
	request := s.server.ac.Client.OutpostsAPI.
		OutpostsKerberosAccessCheck(context.Background(), s.providerID)
	if clientSPN != "" {
		request = request.ClientSpn(clientSPN)
	} else {
		request = request.Username(subject)
	}
	if spn != "" {
		request = request.Spn(spn)
	}
	response, _, err := request.Execute()
	if err != nil || response == nil {
		logger := log.WithField("username", subject).WithField("spn", spn)
		if err != nil {
			logger = logger.WithError(err)
		}
		logger.Warn("Kerberos policy access check failed")
		return fmt.Errorf("authentik policy access check failed")
	}
	access := response.GetAccess()
	allowed := access.GetPassing()
	s.accessCacheMu.Lock()
	if s.accessCache == nil {
		s.accessCache = make(map[string]cachedAccessCheck)
	}
	s.accessCache[key] = cachedAccessCheck{allowed: allowed, expires: now.Add(accessCheckCacheTTL)}
	s.accessCacheMu.Unlock()
	if !allowed {
		log.WithField("username", subject).
			WithField("spn", spn).Info("Kerberos policy denied access")
		return fmt.Errorf("authentik policy denied access")
	}
	return nil
}

func isAnonymousPrincipal(p principal.Principal) bool {
	return p.NameType == principal.NTWellKnown &&
		len(p.Components) == 2 &&
		p.Components[0] == "WELLKNOWN" &&
		p.Components[1] == "ANONYMOUS"
}

// krbtgtRecord synthesizes the krbtgt/<realm> principal. Its KVNO is
// hardcoded to 1 because the keys derive deterministically from the
// provider master key (accepted limitation).
func (s *providerStore) krbtgtRecord(name principal.Principal) (kdb.PrincipalRecord, bool, error) {
	return s.syntheticRecord(name, "krbtgt")
}

func (s *providerStore) changepwRecord(name principal.Principal) (kdb.PrincipalRecord, bool, error) {
	return s.syntheticRecord(name, "kadmin-changepw")
}

func (s *providerStore) syntheticRecord(
	name principal.Principal, keyPrefix string,
) (kdb.PrincipalRecord, bool, error) {
	keys := make(map[int32]kdb.Key)
	for enctype := range s.allowed {
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			return kdb.PrincipalRecord{}, false, fmt.Errorf("get enctype %d: %w", enctype, err)
		}
		key, err := deriveSyntheticKey(s.masterKey, etype, keyPrefix)
		if err != nil {
			return kdb.PrincipalRecord{}, false, fmt.Errorf("derive %s enctype %d: %w", keyPrefix, enctype, err)
		}
		keys[enctype] = kdb.Key{
			Enctype: enctype,
			KVNO:    1,
			Key:     key,
			Salt:    name.Realm + strings.Join(name.Components, ""),
		}
	}
	return kdb.PrincipalRecord{Name: name, Keys: keys, KVNO: 1}, len(keys) > 0, nil
}

func (s *providerStore) invalidateUserKey(username string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	for key, cached := range s.cache {
		if key == username ||
			(len(cached.record.Name.Components) == 1 && cached.record.Name.Components[0] == username) {
			delete(s.cache, key)
		}
	}
}

func (s *providerStore) userRecord(name principal.Principal) (kdb.PrincipalRecord, bool, error) {
	username := name.Components[0]
	now := time.Now()
	s.cacheMu.Lock()
	if cached, ok := s.cache[username]; ok && now.Before(cached.expires) {
		s.cacheMu.Unlock()
		if !cached.found {
			return kdb.PrincipalRecord{}, false, nil
		}
		isCanonical := len(cached.record.Name.Components) == 1 &&
			cached.record.Name.Components[0] == username
		return cached.record, isCanonical && len(cached.record.Keys) > 0, nil
	}
	s.cacheMu.Unlock()

	response, httpResponse, err := s.server.ac.Client.OutpostsAPI.
		OutpostsKerberosUserKeyRetrieve(context.Background(), s.providerID).
		Username(username).Execute()
	if err != nil {
		if httpResponse != nil && httpResponse.StatusCode == http.StatusNotFound {
			s.cacheMu.Lock()
			s.cache[username] = cachedUserKey{expires: now.Add(userKeyCacheTTL)}
			s.cacheMu.Unlock()
			return kdb.PrincipalRecord{}, false, nil
		}
		return kdb.PrincipalRecord{}, false, fmt.Errorf("retrieve user key for %q: %w", username, err)
	}
	canonicalUsername := response.GetPrincipal()
	if canonicalUsername == "" {
		return kdb.PrincipalRecord{}, false, fmt.Errorf(
			"retrieve user key for %q: response has no canonical principal", username,
		)
	}
	keys, err := decodeKeyValues(response.Keys, s.allowed, uint32(response.Kvno), response.Salt)
	if err != nil {
		return kdb.PrincipalRecord{}, false, fmt.Errorf("decode user key for %q: %w", username, err)
	}
	record := kdb.PrincipalRecord{
		Name: principal.Principal{
			Realm: name.Realm, NameType: principal.NTPrincipal, Components: []string{canonicalUsername},
		},
		Keys: keys,
		KVNO: uint32(response.Kvno),
	}
	cached := cachedUserKey{
		record: record, identity: response, found: true, expires: now.Add(userKeyCacheTTL),
	}
	s.cacheMu.Lock()
	s.cache[username] = cached
	if canonicalUsername != username {
		s.cache[canonicalUsername] = cached
	}
	s.cacheMu.Unlock()
	return record, canonicalUsername == username && len(keys) > 0, nil
}

func (s *providerStore) generatePACIdentity(
	client, _ principal.Principal,
) (*kdc.PACIdentity, error) {
	if s == nil || !s.pacEnabled || s.realmSID == nil || len(client.Components) != 1 {
		return nil, nil
	}
	_, found, err := s.userRecord(client)
	if err != nil || !found {
		return nil, nil
	}
	s.cacheMu.Lock()
	cached, ok := s.cache[client.Components[0]]
	s.cacheMu.Unlock()
	if !ok || cached.identity == nil {
		return nil, nil
	}
	return s.pacIdentity(cached.identity), nil
}

func (s *providerStore) pacIdentity(response *api.KerberosUserKeyOutpost) *kdc.PACIdentity {
	if s == nil || s.realmSID == nil || response == nil {
		return nil
	}
	userID := uint32(response.GetPacUserId())
	domainSID := *s.realmSID
	userSID := domainSID
	userSID.SubAuthorities = append(
		append([]uint32(nil), domainSID.SubAuthorities...), userID,
	)
	groupIDs := make([]pac.GroupMembership, 0, len(response.GetPacGroupIds()))
	for _, groupID := range response.GetPacGroupIds() {
		groupIDs = append(groupIDs, pac.GroupMembership{RelativeID: uint32(groupID), Attributes: 7})
	}
	realmLabel := strings.Split(s.realm, ".")[0]
	return &kdc.PACIdentity{
		LogonInfo: &pac.LogonInfo{
			EffectiveName:      response.GetUsername(),
			FullName:           response.GetPacName(),
			UserID:             userID,
			PrimaryGroupID:     uint32(response.GetPacPrimaryGroupId()),
			GroupIDs:           groupIDs,
			LogonDomainName:    strings.ToUpper(realmLabel),
			LogonDomainID:      &domainSID,
			LogonServer:        "authentik",
			UserAccountControl: 0x200,
		},
		UPN:           response.GetPacUpn(),
		DNSDomainName: strings.ToLower(s.realm),
		SAMName:       response.GetUsername(),
		SID:           userSID,
		Flags:         pac.UPNDNSInfoHasSAMNameAndSID,
	}
}

func (s *providerStore) ResolveAlias(
	name principal.Principal,
) (principal.Principal, bool, error) {
	if s == nil || name.Realm != s.realm || len(name.Components) != 1 {
		return principal.Principal{}, false, nil
	}
	record, _, err := s.userRecord(name)
	if err != nil || len(record.Name.Components) != 1 {
		return principal.Principal{}, false, err
	}
	if record.Name.Components[0] == name.Components[0] {
		return principal.Principal{}, false, nil
	}
	return principal.Principal{
		Realm:      s.realm,
		NameType:   principal.NTPrincipal,
		Components: []string{record.Name.Components[0]},
	}, true, nil
}

func (s *providerStore) serviceRecord(spn string, kvno int32, values map[string]interface{}) (kdb.PrincipalRecord, error) {
	return s.serviceRecordWithIndicators(spn, kvno, values, nil)
}

func (s *providerStore) serviceRecordWithIndicators(
	spn string, kvno int32, values map[string]interface{}, requiredIndicators []string,
) (kdb.PrincipalRecord, error) {
	name, err := principal.Parse(spn + "@" + s.realm)
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	keys, err := decodeKeyValues(values, s.allowed, uint32(kvno), name.Realm+strings.Join(name.Components, ""))
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	record := kdb.PrincipalRecord{Name: *name, Keys: keys, KVNO: uint32(kvno)}
	if len(requiredIndicators) > 0 {
		record.Strings = map[string]string{
			"require_auth": strings.Join(requiredIndicators, " "),
		}
	}
	return record, nil
}

func decodeKeyValues(
	values map[string]interface{}, allowed map[int32]bool, kvno uint32, salt string,
) (map[int32]kdb.Key, error) {
	out := make(map[int32]kdb.Key, len(values))
	for rawType, rawValue := range values {
		enctype, err := parseEnctype(rawType)
		if err != nil {
			return nil, err
		}
		if !allowed[enctype] {
			continue
		}
		encoded, ok := rawValue.(string)
		if !ok {
			return nil, fmt.Errorf("key %s is not a string", rawType)
		}
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode key %s: %w", rawType, err)
		}
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			return nil, err
		}
		if len(value) != etype.KeySize() {
			return nil, fmt.Errorf("key %s has invalid length %d", rawType, len(value))
		}
		out[enctype] = kdb.Key{Enctype: enctype, KVNO: kvno, Key: value, Salt: salt}
	}
	return out, nil
}

func parseEnctype(value string) (int32, error) {
	var enctype int32
	if _, err := fmt.Sscan(value, &enctype); err != nil {
		return 0, fmt.Errorf("parse enctype %s: %w", value, err)
	}
	return enctype, nil
}

func principalKey(name principal.Principal) string {
	return name.Realm + "\x00" + strings.Join(name.Components, "\x00")
}

func deriveKRBtgtKey(master []byte, etype crypto.EType) ([]byte, error) {
	return deriveSyntheticKey(master, etype, "krbtgt")
}

func deriveSyntheticKey(master []byte, etype crypto.EType, prefix string) ([]byte, error) {
	info := []byte(fmt.Sprintf("%s-%d", prefix, etype.ID()))
	out := make([]byte, etype.KeySize())
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, info), out); err != nil {
		return nil, err
	}
	return out, nil
}

var _ kdb.Store = (*providerStore)(nil)
var _ kdb.AliasResolver = (*providerStore)(nil)
