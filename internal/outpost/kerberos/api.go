package kerberos

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"goauthentik.io/internal/outpost/ak"
	"goauthentik.io/internal/outpost/kerberos/kdc"
	api "goauthentik.io/packages/client-go"
)

const userKeyCacheTTL = time.Minute

type cachedUserKey struct {
	key     *kdc.UserKey
	expires time.Time
}

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
		allowed := make([]int32, len(provider.AllowedEnctypes))
		for i, enctype := range provider.AllowedEnctypes {
			allowed[i] = int32(enctype)
		}
		instance := &ProviderInstance{
			Config:   provider,
			Services: make(map[string]kdc.ServicePrincipal),
			cache:    make(map[string]cachedUserKey),
			log:      log.WithField("logger", "authentik.outpost.kerberos").WithField("provider", provider.Name),
			server:   rs,
		}
		services, err := ak.Paginator(
			rs.ac.Client.OutpostsAPI.OutpostsKerberosServicePrincipalsList(context.Background(), provider.Pk),
			ak.PaginatorOptions{PageSize: 100, Logger: instance.log},
		)
		if err != nil {
			return err
		}
		for _, service := range services {
			keys, err := kdc.DecodeKeyValues(service.Keys)
			if err != nil {
				return fmt.Errorf("decode service principal %s: %w", service.Spn, err)
			}
			instance.Services[service.Spn+"@"+provider.RealmName] = kdc.ServicePrincipal{
				SPN: service.Spn, KVNO: uint32(service.Kvno), Keys: keys,
			}
		}
		instance.Provider = &kdc.Provider{
			Realm:              provider.RealmName,
			MasterKey:          masterKey,
			AllowedEnctypes:    allowed,
			MaxTicketLifetime:  time.Duration(provider.MaximumTicketLifetime) * time.Second,
			MaxRenewalLifetime: time.Duration(provider.MaximumTicketRenewLifetime) * time.Second,
			Services:           instance.Services,
			User:               instance.user,
		}
		if old := rs.getCurrentProvider(provider.Pk); old != nil {
			instance.cache = old.cache
		}
		providers[provider.Pk] = instance
	}
	rs.mu.Lock()
	rs.providers = providers
	rs.mu.Unlock()
	rs.log.Info("Update kerberos providers")
	return nil
}

func (pi *ProviderInstance) user(username string) (*kdc.UserKey, error) {
	pi.cacheMu.Lock()
	if cached, ok := pi.cache[username]; ok && time.Now().Before(cached.expires) {
		pi.cacheMu.Unlock()
		return cached.key, nil
	}
	pi.cacheMu.Unlock()

	response, _, err := pi.server.ac.Client.OutpostsAPI.
		OutpostsKerberosUserKeyRetrieve(context.Background(), pi.Config.Pk).
		Username(username).Execute()
	if err != nil {
		return nil, err
	}
	keys, err := kdc.DecodeKeyValues(response.Keys)
	if err != nil {
		return nil, err
	}
	key := &kdc.UserKey{Username: response.Username, Salt: response.Salt, KVNO: uint32(response.Kvno), Keys: keys}
	pi.cacheMu.Lock()
	pi.cache[username] = cachedUserKey{key: key, expires: time.Now().Add(userKeyCacheTTL)}
	pi.cacheMu.Unlock()
	return key, nil
}

type ProviderInstance struct {
	Config   api.KerberosOutpostConfig
	Provider *kdc.Provider
	Services map[string]kdc.ServicePrincipal

	cacheMu sync.Mutex
	cache   map[string]cachedUserKey
	log     *log.Entry
	server  *KerberosServer
}
