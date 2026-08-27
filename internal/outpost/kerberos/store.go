package kerberos

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"golang.org/x/crypto/hkdf"
)

func (s *providerStore) Lookup(name principal.Principal) (kdb.PrincipalRecord, bool) {
	if s == nil || name.Realm != s.realm || len(name.Components) == 0 {
		return kdb.PrincipalRecord{}, false
	}
	if len(name.Components) == 2 && name.Components[0] == "krbtgt" && name.Components[1] == s.realm {
		return s.krbtgtRecord(name)
	}
	if len(name.Components) > 1 {
		record, ok := s.services[principalKey(name)]
		return record, ok
	}
	return s.userRecord(name)
}

// krbtgtRecord synthesizes the krbtgt/<realm> principal. Its KVNO is
// hardcoded to 1 because the keys derive deterministically from the
// provider master key (accepted limitation).
func (s *providerStore) krbtgtRecord(name principal.Principal) (kdb.PrincipalRecord, bool) {
	keys := make(map[int32]kdb.Key)
	for enctype := range s.allowed {
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			continue
		}
		key, err := deriveKRBtgtKey(s.masterKey, etype)
		if err != nil {
			continue
		}
		keys[enctype] = kdb.Key{Enctype: enctype, KVNO: 1, Key: key}
	}
	return kdb.PrincipalRecord{
		Name: name, Salt: name.Realm + strings.Join(name.Components, ""), Keys: keys, KVNO: 1,
	}, len(keys) > 0
}

func (s *providerStore) userRecord(name principal.Principal) (kdb.PrincipalRecord, bool) {
	username := name.Components[0]
	now := time.Now()
	s.cacheMu.Lock()
	if cached, ok := s.cache[username]; ok && now.Before(cached.expires) {
		s.cacheMu.Unlock()
		return cached.record, true
	}
	s.cacheMu.Unlock()

	response, _, err := s.server.ac.Client.OutpostsAPI.
		OutpostsKerberosUserKeyRetrieve(context.Background(), s.providerID).
		Username(username).Execute()
	if err != nil {
		return kdb.PrincipalRecord{}, false
	}
	keys, err := decodeKeyValues(response.Keys, s.allowed, uint32(response.Kvno))
	if err != nil {
		return kdb.PrincipalRecord{}, false
	}
	record := kdb.PrincipalRecord{
		Name: principal.Principal{
			Realm: name.Realm, NameType: principal.NTPrincipal, Components: []string{response.Username},
		},
		Salt: response.Salt,
		Keys: keys,
		KVNO: uint32(response.Kvno),
	}
	s.cacheMu.Lock()
	s.cache[username] = cachedUserKey{record: record, expires: now.Add(userKeyCacheTTL)}
	s.cacheMu.Unlock()
	return record, len(keys) > 0
}

func (s *providerStore) serviceRecord(spn string, kvno int32, values map[string]interface{}) (kdb.PrincipalRecord, error) {
	name, err := principal.Parse(spn + "@" + s.realm)
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	keys, err := decodeKeyValues(values, s.allowed, uint32(kvno))
	if err != nil {
		return kdb.PrincipalRecord{}, err
	}
	return kdb.PrincipalRecord{Name: *name, Keys: keys, KVNO: uint32(kvno)}, nil
}

func decodeKeyValues(values map[string]interface{}, allowed map[int32]bool, kvno uint32) (map[int32]kdb.Key, error) {
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
		out[enctype] = kdb.Key{Enctype: enctype, KVNO: kvno, Key: value}
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
	info := []byte(fmt.Sprintf("krbtgt-%d", etype.ID()))
	out := make([]byte, etype.KeySize())
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, info), out); err != nil {
		return nil, err
	}
	return out, nil
}

var _ kdb.Store = (*providerStore)(nil)
