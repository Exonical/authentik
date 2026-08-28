package kerberos

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/principal"
	log "github.com/sirupsen/logrus"

	"goauthentik.io/internal/outpost/ak"
	api "goauthentik.io/packages/client-go"
)

const userKeyCacheTTL = time.Minute

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
		store := &providerStore{
			realm:       provider.RealmName,
			masterKey:   masterKey,
			allowed:     make(map[int32]bool, len(provider.AllowedEnctypes)),
			services:    make(map[string]kdb.PrincipalRecord),
			delegations: make(map[string]delegationPolicy),
			cache:       make(map[string]cachedUserKey),
			server:      rs,
			providerID:  provider.Pk,
		}
		for _, enctype := range provider.AllowedEnctypes {
			store.allowed[int32(enctype)] = true
		}
		instance := &ProviderInstance{
			Config: provider,
			Store:  store,
			KDC: &kdc.Server{
				Realm:                provider.RealmName,
				DB:                   store,
				ClockSkew:            5 * time.Minute,
				MaxTicketLife:        time.Duration(provider.MaximumTicketLifetime) * time.Second,
				MaxRenewableLife:     time.Duration(provider.MaximumTicketRenewLifetime) * time.Second,
				DefaultTicketLife:    defaultTicketLife,
				DefaultRenewableLife: defaultRenewableLife,
				DisablePreauth:       !provider.GetRequirePreauthentication(),
				Policy: &kdc.Policy{
					AllowForwardable: provider.GetForwardable(),
					AllowRenewable:   provider.GetRenewable(),
					AllowProxiable:   provider.GetProxiable(),
				},
				DelegationPolicy: func(service principal.Principal) (bool, []principal.Principal) {
					return store.delegationPolicy(service)
				},
				PKINITCertificate: pkinitCertificate,
				PKINITSigner:      pkinitSigner,
				PKINITClientCAs:   pkinitClientCAs,
			},
			log: log.WithField("logger", "authentik.outpost.kerberos").WithField("provider", provider.Name),
		}
		services, err := ak.Paginator(
			rs.ac.Client.OutpostsAPI.OutpostsKerberosServicePrincipalsList(context.Background(), provider.Pk),
			ak.PaginatorOptions{PageSize: 100, Logger: instance.log},
		)
		if err != nil {
			return err
		}
		for _, service := range services {
			record, err := store.serviceRecord(service.Spn, service.Kvno, service.Keys)
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
		if old := rs.getCurrentProvider(provider.Pk); old != nil {
			store.cache = old.Store.cache
		}
		providers[provider.Pk] = instance
	}
	rs.mu.Lock()
	rs.providers = providers
	rs.mu.Unlock()
	rs.log.Info("Update kerberos providers")
	return nil
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
	Config api.KerberosOutpostConfig
	Store  *providerStore
	KDC    *kdc.Server
	log    *log.Entry
}

type cachedUserKey struct {
	record  kdb.PrincipalRecord
	expires time.Time
}

type providerStore struct {
	realm       string
	masterKey   []byte
	allowed     map[int32]bool
	services    map[string]kdb.PrincipalRecord
	delegations map[string]delegationPolicy
	cache       map[string]cachedUserKey
	cacheMu     sync.Mutex
	server      *KerberosServer
	providerID  int32
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
