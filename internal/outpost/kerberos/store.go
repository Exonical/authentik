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
	"github.com/Exonical/go-kerberos/krb5/principal"
	"golang.org/x/crypto/hkdf"
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
	delete(s.cache, username)
}

func (s *providerStore) userRecord(name principal.Principal) (kdb.PrincipalRecord, bool, error) {
	username := name.Components[0]
	now := time.Now()
	s.cacheMu.Lock()
	if cached, ok := s.cache[username]; ok && now.Before(cached.expires) {
		s.cacheMu.Unlock()
		return cached.record, true, nil
	}
	s.cacheMu.Unlock()

	response, httpResponse, err := s.server.ac.Client.OutpostsAPI.
		OutpostsKerberosUserKeyRetrieve(context.Background(), s.providerID).
		Username(username).Execute()
	if err != nil {
		if httpResponse != nil && httpResponse.StatusCode == http.StatusNotFound {
			return kdb.PrincipalRecord{}, false, nil
		}
		return kdb.PrincipalRecord{}, false, fmt.Errorf("retrieve user key for %q: %w", username, err)
	}
	keys, err := decodeKeyValues(response.Keys, s.allowed, uint32(response.Kvno), response.Salt)
	if err != nil {
		return kdb.PrincipalRecord{}, false, fmt.Errorf("decode user key for %q: %w", username, err)
	}
	record := kdb.PrincipalRecord{
		Name: principal.Principal{
			Realm: name.Realm, NameType: principal.NTPrincipal, Components: []string{response.Username},
		},
		Keys: keys,
		KVNO: uint32(response.Kvno),
	}
	s.cacheMu.Lock()
	s.cache[username] = cachedUserKey{record: record, expires: now.Add(userKeyCacheTTL)}
	s.cacheMu.Unlock()
	return record, len(keys) > 0, nil
}

func (s *providerStore) serviceRecord(spn string, kvno int32, values map[string]interface{}) (kdb.PrincipalRecord, error) {
	name, err := principal.Parse(spn + "@" + s.realm)
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	keys, err := decodeKeyValues(values, s.allowed, uint32(kvno), name.Realm+strings.Join(name.Components, ""))
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	return kdb.PrincipalRecord{Name: *name, Keys: keys, KVNO: uint32(kvno)}, nil
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
