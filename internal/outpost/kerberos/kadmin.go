package kerberos

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"

	"goauthentik.io/internal/outpost/ak"
	api "goauthentik.io/packages/client-go"
)

var errKadminUnsupported = errors.New("kadmin operation is unsupported by authentik")

type kadminBackend struct {
	instance *ProviderInstance
}

func (b *kadminBackend) Lookup(name principal.Principal) (kdb.PrincipalRecord, bool, error) {
	return b.instance.Store.Lookup(name)
}

func (b *kadminBackend) GetRealm() string {
	return b.instance.Store.realm
}

func (b *kadminBackend) ListPrincipals() []string {
	instance := b.instance
	names := make([]string, 0, len(instance.Store.services)+len(instance.Store.trusts)+2)
	add := func(name principal.Principal) {
		if formatted, err := name.Format(); err == nil {
			names = append(names, formatted)
		}
	}
	add(principal.Principal{
		Realm: instance.Store.realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", instance.Store.realm},
	})
	add(principal.Principal{
		Realm: instance.Store.realm, NameType: principal.NTSrvInstance,
		Components: []string{"kadmin", "changepw"},
	})
	add(principal.Principal{
		Realm: instance.Store.realm, NameType: principal.NTSrvInstance,
		Components: []string{"kadmin", "admin"},
	})
	for _, record := range instance.Store.services {
		add(record.Name)
	}
	for _, record := range instance.Store.trusts {
		add(record.Name)
	}
	users, err := ak.Paginator(
		instance.Store.server.ac.Client.OutpostsAPI.OutpostsKerberosUserKeysList(
			context.Background(), instance.Store.providerID,
		),
		ak.PaginatorOptions{PageSize: 100, Logger: instance.log},
	)
	if err == nil {
		for _, user := range users {
			record, recordErr := instance.Store.userRecordFromResponse(
				principal.Principal{Realm: instance.Store.realm}, &user,
			)
			if recordErr == nil {
				add(record.Name)
			}
		}
	}
	sort.Strings(names)
	return names
}

func (b *kadminBackend) service(name principal.Principal) (string, bool, error) {
	if name.Realm != b.instance.Store.realm || len(name.Components) < 2 {
		return "", false, fmt.Errorf("%w: only service principals in the local realm are supported", errKadminUnsupported)
	}
	if strings.EqualFold(name.Components[0], "krbtgt") ||
		(strings.EqualFold(name.Components[0], "kadmin") &&
			strings.EqualFold(name.Components[1], "changepw")) {
		return "", false, fmt.Errorf("%w: synthetic principals cannot be modified", errKadminUnsupported)
	}
	formatted, err := name.Format()
	if err != nil {
		return "", false, err
	}
	return strings.TrimSuffix(formatted, "@"+name.Realm), true, nil
}

func (b *kadminBackend) user(name principal.Principal) (string, error) {
	if name.Realm != b.instance.Store.realm || len(name.Components) != 1 {
		return "", fmt.Errorf("%w: only local user principals are supported", errKadminUnsupported)
	}
	return name.Components[0], nil
}

func (b *kadminBackend) serviceRequest(spn string) *api.KerberosServicePrincipalAdminRequest {
	return api.NewKerberosServicePrincipalAdminRequest(spn)
}

func duplicateOrError(response *http.Response, err error) error {
	if response != nil && response.StatusCode == http.StatusConflict {
		return kdb.ErrPrincipalExists
	}
	return err
}

func (b *kadminBackend) CreatePrincipalWithOptions(
	name, _ string, _ *kdb.PolicyRecord,
) error {
	parsed, err := principal.Parse(name)
	if err != nil {
		return err
	}
	spn, _, err := b.service(*parsed)
	if err != nil {
		return err
	}
	_, response, err := b.instance.Store.server.ac.Client.OutpostsAPI.
		OutpostsKerberosServicePrincipalCreate(context.Background(), b.instance.Store.providerID).
		KerberosServicePrincipalAdminRequest(*b.serviceRequest(spn)).Execute()
	return duplicateOrError(response, err)
}

func (b *kadminBackend) CreatePrincipalWithKeySaltsAndOptions(
	name, password string, _ []kdb.KeySaltTuple, policy *kdb.PolicyRecord,
) error {
	return b.CreatePrincipalWithOptions(name, password, policy)
}

func (b *kadminBackend) DeletePrincipal(name principal.Principal) error {
	spn, _, err := b.service(name)
	if err != nil {
		return err
	}
	response, err := b.instance.Store.server.ac.Client.OutpostsAPI.
		OutpostsKerberosServicePrincipalDelete(context.Background(), b.instance.Store.providerID).
		KerberosServicePrincipalAdminRequest(*b.serviceRequest(spn)).Execute()
	if response != nil && response.StatusCode == http.StatusNotFound {
		return kdb.ErrPrincipalNotFound
	}
	return err
}

func (b *kadminBackend) UpdatePrincipal(record kdb.PrincipalRecord) error {
	spn, _, err := b.service(record.Name)
	if err != nil {
		return err
	}
	flags := make([]api.TicketFlagsEnum, 0, 8)
	flagBits := []struct {
		name string
		bit  uint32
	}{
		{"requires_preauth", kdb.RequiresPreAuth},
		{"requires_hwauth", kdb.RequiresHWAuth},
		{"disallow_postdated", kdb.DisallowPostdated},
		{"disallow_forwardable", kdb.DisallowForwardable},
		{"disallow_proxiable", kdb.DisallowProxiable},
		{"disallow_renewable", kdb.DisallowRenewable},
		{"disallow_tgt_based", kdb.DisallowTGTBased},
		{"disallow_server", kdb.DisallowServer},
	}
	for _, flag := range flagBits {
		if record.Flags&flag.bit != 0 {
			flags = append(flags, api.TicketFlagsEnum(flag.name))
		}
	}
	request := api.NewKerberosServicePrincipalUpdateRequest(spn, flags)
	_, _, err = b.instance.Store.server.ac.Client.OutpostsAPI.
		OutpostsKerberosServicePrincipalUpdate(context.Background(), b.instance.Store.providerID).
		KerberosServicePrincipalUpdateRequest(*request).Execute()
	return err
}

func (b *kadminBackend) ChangePasswordWithPolicyAndKeepOld(
	name principal.Principal, password string, _ time.Time, _ *kdb.PolicyRecord, keepOld, _ bool,
) error {
	if keepOld {
		return fmt.Errorf("%w: password history is not supported", errKadminUnsupported)
	}
	username, err := b.user(name)
	if err != nil {
		return err
	}
	request := api.NewKerberosSetPasswordRequest(username, password)
	response, err := b.instance.Store.server.ac.Client.OutpostsAPI.
		OutpostsKerberosSetPasswordCreate(context.Background(), b.instance.Store.providerID).
		KerberosSetPasswordRequest(*request).Execute()
	if message, ok := passwordPolicyError(response, err); ok {
		return &kadm5.PasswordQualityError{
			Code:    kadm5.PassQualityGeneric,
			Message: message,
		}
	}
	return err
}

func (b *kadminBackend) RandomizeKeys(name principal.Principal) ([]kdb.Key, error) {
	return b.RandomizeKeysWithKeySalts(name, false, nil)
}

func (b *kadminBackend) RandomizeKeysWithKeySalts(
	name principal.Principal, keepOld bool, tuples []kdb.KeySaltTuple,
) ([]kdb.Key, error) {
	if keepOld {
		return nil, fmt.Errorf("%w: retaining old keys is unsupported", errKadminUnsupported)
	}
	spn, _, err := b.service(name)
	if err != nil {
		return nil, err
	}
	for _, tuple := range tuples {
		if !b.instance.Store.allowed[tuple.Enctype] {
			return nil, kdb.ErrBadKeySalts
		}
	}
	response, _, err := b.instance.Store.server.ac.Client.OutpostsAPI.
		OutpostsKerberosServicePrincipalRotate(context.Background(), b.instance.Store.providerID).
		KerberosServicePrincipalAdminRequest(*b.serviceRequest(spn)).Execute()
	if err != nil {
		return nil, err
	}
	record, err := b.instance.Store.serviceRecordWithIndicators(
		response.Spn, response.Kvno, response.Keys,
		response.GetRequiredAuthIndicators(), response.GetTicketFlags(),
	)
	if err != nil {
		return nil, err
	}
	keys := make([]kdb.Key, 0, len(record.Keys))
	for _, key := range record.Keys {
		keys = append(keys, key)
	}
	return keys, nil
}

func (*kadminBackend) SetKeys(principal.Principal, []kdb.Key, bool) error {
	return errKadminUnsupported
}
func (*kadminBackend) PurgeKeys(principal.Principal, int32) error { return errKadminUnsupported }
func (*kadminBackend) RenamePrincipal(principal.Principal, principal.Principal) error {
	return errKadminUnsupported
}
func (*kadminBackend) AddAlias(string, string) error { return errKadminUnsupported }
func (*kadminBackend) GetPolicy(string) (kdb.PolicyRecord, error) {
	return kdb.PolicyRecord{}, errKadminUnsupported
}
func (*kadminBackend) CreatePolicy(kdb.PolicyRecord) error { return errKadminUnsupported }
func (*kadminBackend) UpdatePolicy(kdb.PolicyRecord) error { return errKadminUnsupported }
func (*kadminBackend) DeletePolicy(string) error           { return errKadminUnsupported }
func (*kadminBackend) ListPolicies() []string              { return []string{} }
func (*kadminBackend) GetStrings(principal.Principal) (map[string]string, error) {
	return nil, errKadminUnsupported
}
func (*kadminBackend) SetString(principal.Principal, string, *string) error {
	return errKadminUnsupported
}
func (*kadminBackend) CheckPasswordPolicy(principal.Principal, string, time.Time, *kdb.PolicyRecord, bool) error {
	return nil
}

func (instance *ProviderInstance) kadminKeytab() (*keytab.Keytab, error) {
	record, _, err := instance.Store.syntheticRecord(
		principal.Principal{
			Realm: instance.Store.realm, NameType: principal.NTSrvInstance,
			Components: []string{"kadmin", "admin"},
		},
		"kadmin-admin",
	)
	if err != nil {
		return nil, err
	}
	kt := &keytab.Keytab{}
	for enctype, value := range record.Keys {
		if err := kt.AddEntry(keytab.Entry{
			Principal: record.Name,
			KVNO:      uint32(value.KVNO),
			Enctype:   enctype,
			Key:       append([]byte(nil), value.Key...),
		}); err != nil {
			return nil, err
		}
	}
	return kt, nil
}
