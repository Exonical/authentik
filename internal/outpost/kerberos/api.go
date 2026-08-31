package kerberos

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/otp"
	"github.com/Exonical/go-kerberos/krb5/pac"
	"github.com/Exonical/go-kerberos/krb5/principal"
	log "github.com/sirupsen/logrus"

	"goauthentik.io/internal/outpost/ak"
	api "goauthentik.io/packages/client-go"
)

const userKeyCacheTTL = time.Minute
const accessCheckCacheTTL = time.Minute

func (rs *KerberosServer) getCurrentProvider(pk int32) *ProviderInstance {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.providers[pk]
}

func (rs *KerberosServer) Refresh() error {
	apiProviders, err := ak.Paginator(
		rs.ac.Client.OutpostsAPI.OutpostsKerberosList(context.Background()),
		ak.PaginatorOptions{PageSize: 100, Logger: rs.log},
	)
	if err != nil {
		return err
	}
	if len(apiProviders) == 0 {
		return errors.New("no kerberos provider defined")
	}

	providers := make(map[int32]*ProviderInstance, len(apiProviders))
	var kadminServer *kadm5.Server
	for _, provider := range apiProviders {
		masterKey, err := base64.StdEncoding.DecodeString(provider.GetMasterKey())
		if err != nil {
			return fmt.Errorf("decode provider %d master key: %w", provider.Pk, err)
		}
		defaultTicketLife, err := parseDuration(provider.GetDefaultTicketLifetime())
		if err != nil {
			return fmt.Errorf("parse provider %d default ticket lifetime: %w", provider.Pk, err)
		}
		defaultRenewableLife, err := parseDuration(provider.GetDefaultTicketRenewLifetime())
		if err != nil {
			return fmt.Errorf("parse provider %d default ticket renew lifetime: %w", provider.Pk, err)
		}
		pkinitCertificate, pkinitSigner, pkinitClientCAs, err := rs.pkinitConfig(provider)
		if err != nil {
			return fmt.Errorf("load provider %d PKINIT configuration: %w", provider.Pk, err)
		}
		kkdcpCertificate := rs.kkdcpConfig(provider)
		var realmSID *pac.SID
		if provider.GetRealmSid() != "" {
			parsedSID, sidErr := pac.ParseSID(provider.GetRealmSid())
			if sidErr != nil {
				rs.log.WithField("provider", provider.Name).
					WithError(sidErr).Warn("Ignoring invalid PAC realm SID")
			} else {
				realmSID = &parsedSID
			}
		}
		store := &providerStore{
			realm:                  provider.RealmName,
			masterKey:              masterKey,
			allowed:                make(map[int32]bool, len(provider.AllowedEnctypes)),
			services:               make(map[string]kdb.PrincipalRecord),
			trusts:                 make(map[string]kdb.PrincipalRecord),
			delegations:            make(map[string]delegationPolicy),
			cache:                  make(map[string]cachedUserKey),
			accessCache:            make(map[string]cachedAccessCheck),
			server:                 rs,
			providerID:             provider.Pk,
			anonymousPKINITEnabled: provider.GetAnonymousPkinitEnabled(),
			pacEnabled:             provider.GetPacEnabled(),
			realmSID:               realmSID,
			otpEnabled:             provider.GetOtpEnabled(),
		}
		for _, enctype := range provider.AllowedEnctypes {
			store.allowed[int32(enctype)] = true
		}
		instance := &ProviderInstance{
			Config: provider,
			Store:  store,
			KDC: &kdc.Server{
				Realm:                       provider.RealmName,
				DB:                          store,
				ClockSkew:                   5 * time.Minute,
				MaxTicketLife:               time.Duration(provider.MaximumTicketLifetime) * time.Second,
				MaxRenewableLife:            time.Duration(provider.MaximumTicketRenewLifetime) * time.Second,
				DefaultTicketLife:           defaultTicketLife,
				DefaultRenewableLife:        defaultRenewableLife,
				DisablePreauth:              !provider.GetRequirePreauthentication(),
				EnableSPAKE:                 provider.GetSpakeEnabled(),
				PKINITRequireFreshness:      provider.GetPkinitRequireFreshness(),
				PKINITIndicators:            provider.GetPkinitIndicators(),
				SPAKEPreauthIndicators:      provider.GetSpakeIndicators(),
				EncryptedChallengeIndicator: provider.GetEncryptedChallengeIndicator(),
				OTPIndicators:               provider.GetOtpIndicators(),
				Policy: &kdc.Policy{
					AllowForwardable: provider.GetForwardable(),
					AllowRenewable:   provider.GetRenewable(),
					AllowProxiable:   provider.GetProxiable(),
				},
				CheckAllowedToDelegate: store.checkAllowedToDelegate,
				Authorize:              store.Authorize,
				PKINITCertificate:      pkinitCertificate,
				PKINITSigner:           pkinitSigner,
				PKINITClientCAs:        pkinitClientCAs,
				EnablePAC:              provider.GetPacEnabled() && realmSID != nil,
			},
			KKDCPCertificate: kkdcpCertificate,
			log:              log.WithField("logger", "authentik.outpost.kerberos").WithField("provider", provider.Name),
		}
		if provider.GetKdcAuditEnabled() {
			instance.KDC.AuditModules = []kdc.AuditModule{
				kdc.NewFuncAuditModule("authentik", instance.auditCallback),
			}
			instance.KDC.AuditErrorLog = func(err error) {
				instance.log.WithError(err).Warn("KDC audit module failed")
			}
		}
		if provider.GetOtpEnabled() {
			instance.KDC.OTPValidator = store.validateOTP
			instance.KDC.OTPTokenInfo = func(principal.Principal) []otp.TokenInfo {
				length, format := int32(6), otp.FormatDecimal
				return []otp.TokenInfo{{Length: &length, Format: &format}}
			}
		}
		if provider.GetPacEnabled() && realmSID != nil {
			instance.KDC.GeneratePACIdentity = store.generatePACIdentity
		}
		services, err := ak.Paginator(
			rs.ac.Client.OutpostsAPI.OutpostsKerberosServicePrincipalsList(context.Background(), provider.Pk),
			ak.PaginatorOptions{PageSize: 100, Logger: instance.log},
		)
		if err != nil {
			return err
		}
		for _, service := range services {
			record, err := store.serviceRecordWithIndicators(
				service.Spn,
				service.Kvno,
				service.Keys,
				service.GetRequiredAuthIndicators(),
				service.GetTicketFlags(),
			)
			if err != nil {
				return fmt.Errorf("decode service principal %s: %w", service.Spn, err)
			}
			store.services[principalKey(record.Name)] = record
			targets := make([]principal.Principal, 0, len(service.AllowedDelegationTargets))
			for _, target := range service.AllowedDelegationTargets {
				parsed, parseErr := principal.Parse(target + "@" + provider.RealmName)
				if parseErr != nil {
					instance.log.WithField("spn", service.Spn).
						WithField("target", target).
						Warn("Skipping malformed Kerberos delegation target")
					continue
				}
				targets = append(targets, *parsed)
			}
			store.delegations[service.Spn] = delegationPolicy{
				ok:      service.GetOkToAuthAsDelegate(),
				targets: targets,
			}
		}
		trusts, err := ak.Paginator(
			rs.ac.Client.OutpostsAPI.OutpostsKerberosRealmTrustsList(
				context.Background(), provider.Pk,
			),
			ak.PaginatorOptions{PageSize: 100, Logger: instance.log},
		)
		if err != nil {
			return err
		}
		for _, trust := range trusts {
			outgoing, err := store.trustRecord(
				"krbtgt/"+trust.GetRemoteRealm(),
				provider.RealmName,
				trust.GetOutgoingKvno(),
				trust.GetOutgoingKeys(),
			)
			if err != nil {
				return fmt.Errorf(
					"decode outgoing realm trust %s: %w", trust.GetRemoteRealm(), err,
				)
			}
			incoming, err := store.trustRecord(
				"krbtgt/"+provider.RealmName,
				trust.GetRemoteRealm(),
				trust.GetIncomingKvno(),
				trust.GetIncomingKeys(),
			)
			if err != nil {
				return fmt.Errorf(
					"decode incoming realm trust %s: %w", trust.GetRemoteRealm(), err,
				)
			}
			store.trusts[principalKey(outgoing.Name)] = outgoing
			store.trusts[principalKey(incoming.Name)] = incoming
			setCapaths(
				instance.KDC,
				provider.RealmName,
				trust.GetRemoteRealm(),
				trust.GetCapaths(),
			)
		}
		if provider.GetKadminEnabled() && kadminServer == nil {
			serviceKeytab, keytabErr := instance.kadminKeytab()
			if keytabErr != nil {
				return fmt.Errorf("build provider %d kadmin keytab: %w", provider.Pk, keytabErr)
			}
			kadminServer = kadm5.NewServer(&kadminBackend{instance: instance}, serviceKeytab)
			kadminServer.PasswordQualityModules = []kadm5.PasswordQualityModule{}
			if len(provider.GetKadminAcl()) > 0 {
				acl, aclErr := parseKadminACL(provider.GetKadminAcl(), provider.RealmName)
				if aclErr != nil {
					return fmt.Errorf("parse provider %d kadmin ACL: %w", provider.Pk, aclErr)
				}
				kadminServer.ACL = acl.Func()
			}
			kadminServer.ErrorLog = func(err error) {
				instance.log.WithError(err).Warn("kadmin server error")
			}
		} else if provider.GetKadminEnabled() {
			rs.log.WithField("provider", provider.Pk).Warn(
				"kadmin is single-realm; ignoring additional enabled provider",
			)
		}
		if old := rs.getCurrentProvider(provider.Pk); old != nil {
			store.cache = old.Store.cache
			store.accessCache = old.Store.accessCache
		}
		providers[provider.Pk] = instance
	}
	rs.mu.Lock()
	oldProviders := rs.providers
	rs.providers = providers
	rs.kadminServer = kadminServer
	rs.mu.Unlock()
	for _, provider := range oldProviders {
		provider.stopKprop()
		provider.stopAudit()
	}
	for _, provider := range providers {
		rs.startKprop(provider)
		rs.startAudit(provider)
	}
	rs.log.Info("Update kerberos providers")
	return nil
}

func parseKadminACL(lines []string, realm string) (*kadm5.ACL, error) {
	aclLines := make([]string, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] != "*" && !strings.Contains(fields[0], "@") {
			fields[0] += "@" + realm
			line = strings.Join(fields, " ")
		}
		aclLines = append(aclLines, line)
	}
	return kadm5.ParseACL(strings.NewReader(strings.Join(aclLines, "\n")))
}

func setCapaths(server *kdc.Server, clientRealm, serverRealm string, intermediates []string) {
	if server.Capaths == nil {
		server.Capaths = make(map[string]map[string][]string)
	}
	if server.Capaths[clientRealm] == nil {
		server.Capaths[clientRealm] = make(map[string][]string)
	}
	server.Capaths[clientRealm][serverRealm] = append([]string(nil), intermediates...)
}

func (rs *KerberosServer) kkdcpConfig(provider api.KerberosOutpostConfig) *tls.Certificate {
	if !provider.GetKkdcpEnabled() {
		return nil
	}
	certificateUUID := provider.GetKkdcpCertificate()
	if certificateUUID == "" {
		rs.log.WithField("provider", provider.Name).
			Warn("KKDCP is enabled but no TLS certificate is configured")
		return nil
	}
	if rs.cs == nil {
		rs.log.WithField("provider", provider.Name).
			Warn("KKDCP is enabled but the certificate store is not initialized")
		return nil
	}
	if err := rs.cs.AddKeypair(certificateUUID); err != nil {
		rs.log.WithField("provider", provider.Name).
			WithError(err).Warn("Failed to fetch KKDCP TLS certificate")
		return nil
	}
	certificate := rs.cs.Get(certificateUUID)
	if certificate == nil {
		rs.log.WithField("provider", provider.Name).
			Warn("KKDCP TLS certificate was not found")
	}
	return certificate
}

func (rs *KerberosServer) pkinitConfig(
	provider api.KerberosOutpostConfig,
) (*x509.Certificate, crypto.Signer, *x509.CertPool, error) {
	certificateUUID := provider.GetPkinitCertificate()
	clientCAUUID := provider.GetPkinitClientCa()
	if certificateUUID == "" && clientCAUUID == "" {
		return nil, nil, nil, nil
	}
	if certificateUUID == "" || clientCAUUID == "" {
		logger := rs.log
		if logger == nil {
			logger = log.WithField("logger", "authentik.outpost.kerberos")
		}
		logger.WithField("provider", provider.Name).Warn(
			"PKINIT requires both a KDC certificate and client CA certificate",
		)
		return nil, nil, nil, nil
	}
	if rs.cs == nil {
		return nil, nil, nil, errors.New("certificate store is not initialized")
	}
	if err := rs.cs.AddKeypair(certificateUUID); err != nil {
		return nil, nil, nil, fmt.Errorf("fetch KDC certificate: %w", err)
	}
	kdcCertificate := rs.cs.Get(certificateUUID)
	if kdcCertificate == nil {
		return nil, nil, nil, errors.New("KDC certificate was not found")
	}
	leaf := kdcCertificate.Leaf
	if leaf == nil {
		if len(kdcCertificate.Certificate) == 0 {
			return nil, nil, nil, errors.New("KDC certificate has no certificate data")
		}
		var err error
		leaf, err = x509.ParseCertificate(kdcCertificate.Certificate[0])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse KDC certificate: %w", err)
		}
	}
	signer, ok := kdcCertificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, nil, errors.New("KDC certificate has no crypto.Signer private key")
	}
	if err := rs.cs.FetchCertificateOnly(clientCAUUID); err != nil {
		return nil, nil, nil, fmt.Errorf("fetch PKINIT client CA: %w", err)
	}
	clientCA := rs.cs.Get(clientCAUUID)
	if clientCA == nil {
		return nil, nil, nil, errors.New("PKINIT client CA was not found")
	}
	roots := x509.NewCertPool()
	if len(clientCA.Certificate) == 0 {
		return nil, nil, nil, errors.New("PKINIT client CA has no certificate data")
	}
	for _, certificateDER := range clientCA.Certificate {
		certificate, err := x509.ParseCertificate(certificateDER)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse PKINIT client CA certificate: %w", err)
		}
		roots.AddCert(certificate)
	}
	return leaf, signer, roots, nil
}

type ProviderInstance struct {
	Config           api.KerberosOutpostConfig
	Store            *providerStore
	KDC              *kdc.Server
	KKDCPCertificate *tls.Certificate
	log              *log.Entry
	kpropCancel      context.CancelFunc
	kpropDone        chan struct{}
	auditCancel      context.CancelFunc
	auditDone        chan struct{}
	auditEvents      chan auditRecord
}

type cachedUserKey struct {
	record   kdb.PrincipalRecord
	identity *api.KerberosUserKeyOutpost
	found    bool
	expires  time.Time
}

type cachedAccessCheck struct {
	allowed bool
	expires time.Time
}

type providerStore struct {
	realm                  string
	masterKey              []byte
	allowed                map[int32]bool
	services               map[string]kdb.PrincipalRecord
	servicesMu             sync.RWMutex
	trusts                 map[string]kdb.PrincipalRecord
	delegations            map[string]delegationPolicy
	cache                  map[string]cachedUserKey
	cacheMu                sync.Mutex
	accessCache            map[string]cachedAccessCheck
	accessCacheMu          sync.Mutex
	server                 *KerberosServer
	providerID             int32
	anonymousPKINITEnabled bool
	pacEnabled             bool
	realmSID               *pac.SID
	otpEnabled             bool
}

func (s *providerStore) allowedEnctypes() []int32 {
	enctypes := make([]int32, 0, len(s.allowed))
	for enctype := range s.allowed {
		enctypes = append(enctypes, enctype)
	}
	sort.Slice(enctypes, func(i, j int) bool {
		return enctypes[i] < enctypes[j]
	})
	return enctypes
}

type delegationPolicy struct {
	ok      bool
	targets []principal.Principal
}

func (s *providerStore) delegationPolicy(service principal.Principal) (bool, []principal.Principal) {
	if s == nil || service.Realm != s.realm || len(service.Components) < 2 {
		return false, nil
	}
	policy, ok := s.delegations[strings.Join(service.Components, "/")]
	if !ok {
		return false, nil
	}
	return policy.ok, policy.targets
}

func (s *providerStore) checkAllowedToDelegate(
	impersonated *principal.Principal,
	service principal.Principal,
	target *principal.Principal,
) error {
	allowed, targets := s.delegationPolicy(service)
	if impersonated == nil && target == nil {
		if !allowed {
			return fmt.Errorf("Kerberos service principal %s is not allowed to authenticate as delegate", service)
		}
		return nil
	}
	if impersonated == nil || target == nil || !allowed {
		return fmt.Errorf("Kerberos service principal %s is not allowed to delegate", service)
	}
	targetAllowed := false
	for _, candidate := range targets {
		if candidate.String() == target.String() {
			targetAllowed = true
			break
		}
	}
	if !targetAllowed {
		return fmt.Errorf(
			"Kerberos service principal %s is not allowed to delegate to %s",
			service,
			target,
		)
	}
	return s.Authorize(*impersonated, *target, false)
}

func parseDuration(expression string) (time.Duration, error) {
	if expression == "" {
		return 0, nil
	}
	values := make(map[string]float64)
	for _, pair := range strings.Split(expression, ";") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return 0, fmt.Errorf("invalid duration component %q", pair)
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		switch key {
		case "microseconds", "milliseconds", "seconds", "minutes", "hours", "days", "weeks":
		default:
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid %s value: %w", key, err)
		}
		values[key] = value
	}
	if len(values) == 0 {
		return 0, errors.New("no valid duration components")
	}
	var duration float64
	duration += values["microseconds"] * float64(time.Microsecond)
	duration += values["milliseconds"] * float64(time.Millisecond)
	duration += values["seconds"] * float64(time.Second)
	duration += values["minutes"] * float64(time.Minute)
	duration += values["hours"] * float64(time.Hour)
	duration += values["days"] * float64(24*time.Hour)
	duration += values["weeks"] * float64(7*24*time.Hour)
	return time.Duration(duration), nil
}
