package kerberos

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/iprop"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/kprop"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"

	"goauthentik.io/internal/outpost/ak"
)

func (rs *KerberosServer) startKprop(instance *ProviderInstance) {
	if !instance.kpropConfigured() && !instance.ipropConfigured() {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	instance.kpropCancel = cancel
	instance.kpropDone = make(chan struct{})
	go func() {
		defer close(instance.kpropDone)
		if instance.kpropConfigured() {
			instance.pushKprop(ctx)
		}
		if err := instance.syncIprop(ctx); err != nil {
			instance.log.WithError(err).Warn("Failed to synchronize iprop database")
		}
		ticker := time.NewTicker(time.Duration(instance.Config.GetKpropInterval()) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if instance.kpropConfigured() {
					instance.pushKprop(ctx)
				}
				if err := instance.syncIprop(ctx); err != nil {
					instance.log.WithError(err).Warn("Failed to synchronize iprop database")
				}
			}
		}
	}()
}

func (instance *ProviderInstance) stopKprop() {
	if instance == nil || instance.kpropCancel == nil {
		return
	}
	instance.kpropCancel()
	<-instance.kpropDone
	instance.kpropCancel = nil
	instance.kpropDone = nil
}

func (instance *ProviderInstance) kpropConfigured() bool {
	targets := instance.kpropTargets()
	return instance.Config.GetKpropEnabled() &&
		len(targets) > 0 &&
		instance.Config.GetKpropClientSpn() != "" &&
		instance.Config.GetKpropMasterPassword() != "" &&
		instance.Config.GetKpropInterval() > 0
}

func (instance *ProviderInstance) ipropConfigured() bool {
	return instance.Config.GetIpropEnabled() && instance.Iprop != nil &&
		instance.Config.GetKpropInterval() > 0
}

func (instance *ProviderInstance) kpropTargets() []string {
	targets := make([]string, 0, len(instance.Config.GetKpropTargets()))
	for _, target := range instance.Config.GetKpropTargets() {
		if strings.TrimSpace(target) != "" {
			targets = append(targets, target)
		}
	}
	return targets
}

func (instance *ProviderInstance) pushKprop(ctx context.Context) {
	dump, err := instance.snapshotDump(ctx)
	if err != nil {
		instance.log.WithError(err).Warn("Failed to build MIT replica dump")
		return
	}
	for _, target := range instance.kpropTargets() {
		if err := instance.pushKpropTarget(ctx, target, dump); err != nil {
			instance.log.WithField("target", target).WithError(err).
				Warn("Failed to push MIT replica dump")
		}
	}
}

func (instance *ProviderInstance) snapshotDump(ctx context.Context) ([]byte, error) {
	records, err := instance.snapshotRecords(ctx)
	if err != nil {
		return nil, err
	}
	db := kdb.NewDatabase(instance.Store.realm)
	for _, record := range records {
		if len(record.Keys) == 0 {
			continue
		}
		if err := db.ApplyPrincipal(record, false); err != nil {
			return nil, err
		}
	}
	dump, err := mitdump.DumpWithMasterPassword(db, instance.Config.GetKpropMasterPassword())
	if err != nil {
		return nil, fmt.Errorf("serialize MIT dump: %w", err)
	}
	return dump, nil
}

func (instance *ProviderInstance) snapshotRecords(
	ctx context.Context,
) (map[string]kdb.PrincipalRecord, error) {
	records := make(map[string]kdb.PrincipalRecord)
	add := func(record kdb.PrincipalRecord) {
		if len(record.Keys) > 0 {
			records[record.Name.String()] = record
		}
	}
	localTGT, found, err := instance.Store.krbtgtRecord(principal.Principal{
		Realm: instance.Store.realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", instance.Store.realm},
	})
	if err != nil {
		return nil, fmt.Errorf("build local krbtgt: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("build local krbtgt: no keys")
	}
	add(localTGT)
	changepw, found, err := instance.Store.changepwRecord(principal.Principal{
		Realm: instance.Store.realm, NameType: principal.NTSrvInstance,
		Components: []string{"kadmin", "changepw"},
	})
	if err != nil {
		return nil, fmt.Errorf("build changepw: %w", err)
	}
	if found {
		add(changepw)
	}
	instance.Store.servicesMu.RLock()
	services := make([]kdb.PrincipalRecord, 0, len(instance.Store.services))
	for _, record := range instance.Store.services {
		services = append(services, record)
	}
	instance.Store.servicesMu.RUnlock()
	for _, record := range services {
		add(record)
	}
	if instance.Store.ipropSPN != "" {
		name, parseErr := principal.Parse(instance.Store.ipropSPN)
		if parseErr != nil {
			return nil, fmt.Errorf("parse iprop SPN: %w", parseErr)
		}
		record, found, lookupErr := instance.Store.syntheticRecord(*name, "kiprop")
		if lookupErr != nil {
			return nil, lookupErr
		}
		if found {
			add(record)
		}
	}
	for _, record := range instance.Store.trusts {
		add(record)
	}
	users, err := ak.Paginator(
		instance.Store.server.ac.Client.OutpostsAPI.OutpostsKerberosUserKeysList(
			ctx, instance.Store.providerID,
		),
		ak.PaginatorOptions{PageSize: 100, Logger: instance.log},
	)
	if err != nil {
		return nil, fmt.Errorf("list user keys: %w", err)
	}
	for _, user := range users {
		record, err := instance.Store.userRecordFromResponse(
			principal.Principal{
				Realm: instance.Store.realm, NameType: principal.NTPrincipal,
				Components: []string{user.GetPrincipal()},
			},
			&user,
		)
		if err != nil {
			return nil, fmt.Errorf("build user %q: %w", user.GetUsername(), err)
		}
		add(record)
	}
	return records, nil
}

func (instance *ProviderInstance) syncIprop(ctx context.Context) error {
	if !instance.ipropConfigured() {
		return nil
	}
	records, err := instance.snapshotRecords(ctx)
	if err != nil {
		return err
	}
	instance.ipropMirrorMu.Lock()
	defer instance.ipropMirrorMu.Unlock()
	mirror := instance.IpropDatabase
	if mirror == nil {
		return fmt.Errorf("iprop mirror is not initialized")
	}
	existing := mirror.ListPrincipals()
	initial := len(existing) == 0
	for name, record := range records {
		parsed, parseErr := principal.Parse(name)
		if parseErr != nil {
			return parseErr
		}
		current, found, lookupErr := mirror.Lookup(*parsed)
		if lookupErr != nil {
			return lookupErr
		}
		if found && equalIpropRecord(current, record) {
			continue
		}
		if !found {
			if err := mirror.ImportPrincipal(record); err != nil {
				return err
			}
			if initial {
				continue
			}
		}
		if err := mirror.UpdatePrincipal(record); err != nil {
			return err
		}
	}
	for _, name := range existing {
		if _, found := records[name]; found {
			continue
		}
		parsed, parseErr := principal.Parse(name)
		if parseErr != nil {
			return parseErr
		}
		if err := mirror.DeletePrincipal(*parsed); err != nil &&
			err != kdb.ErrPrincipalNotFound {
			return err
		}
	}
	return nil
}

func equalIpropRecord(left, right kdb.PrincipalRecord) bool {
	left.TLData = withoutModifierTLData(left.TLData)
	right.TLData = withoutModifierTLData(right.TLData)
	return reflect.DeepEqual(left, right)
}

func withoutModifierTLData(values []kdb.TLData) []kdb.TLData {
	filtered := make([]kdb.TLData, 0, len(values))
	for _, value := range values {
		if value.Type != 2 {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func (instance *ProviderInstance) configureIprop() error {
	mirror := kdb.NewDatabase(instance.Store.realm)
	mirror.ConfigureUpdateLog(int(instance.Config.GetIpropUlogSize()))
	if old := instance.Store.server.getCurrentProvider(instance.Store.providerID); old != nil &&
		old.IpropDatabase != nil {
		mirror = old.IpropDatabase
		if old.Config.GetIpropUlogSize() != instance.Config.GetIpropUlogSize() {
			mirror.ConfigureUpdateLog(int(instance.Config.GetIpropUlogSize()))
		}
	}
	name, err := parseIpropSPN(instance.Config.GetIpropSpn(), instance.Store.realm)
	if err != nil {
		return err
	}
	record, found, err := instance.Store.syntheticRecord(*name, "kiprop")
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("iprop SPN has no usable keys")
	}
	serviceKeytab := &keytab.Keytab{}
	for enctype, value := range record.Keys {
		if err := serviceKeytab.AddEntry(keytab.Entry{
			Principal: record.Name,
			KVNO:      uint32(value.KVNO),
			Enctype:   enctype,
			Key:       append([]byte(nil), value.Key...),
		}); err != nil {
			return err
		}
	}
	server := iprop.NewServer(mirror, serviceKeytab)
	server.MasterEnctype = instance.Store.masterEnctype()
	server.MasterKey = append([]byte(nil), instance.Store.masterKey...)
	server.Authorize = instance.Store.authorizeIpropReplica
	server.ErrorLog = func(err error) {
		instance.log.WithError(err).Warn("iprop server error")
	}
	instance.IpropDatabase = mirror
	instance.IpropKeytab = serviceKeytab
	instance.Iprop = server
	return nil
}

func (instance *ProviderInstance) pushKpropTarget(
	ctx context.Context, target string, dump []byte,
) error {
	host, address, err := kpropTargetAddress(target)
	if err != nil {
		return err
	}
	tgt, err := instance.kpropTGT(ctx)
	if err != nil {
		return fmt.Errorf("obtain kprop client TGT: %w", err)
	}
	creds, err := kprop.ServiceCredentials(
		ctx, instance.kpropClient(), tgt, host, instance.Store.realm,
	)
	if err != nil {
		return fmt.Errorf("obtain kprop service credentials: %w", err)
	}
	if err := kprop.DialAndSend(ctx, address, creds, bytes.NewReader(dump),
		uint64(len(dump))); err != nil {
		return fmt.Errorf("send kprop dump: %w", err)
	}
	return nil
}

func kpropTargetAddress(target string) (string, string, error) {
	if target == "" {
		return "", "", fmt.Errorf("kprop target is empty")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = strconv.Itoa(754)
		if strings.Contains(target, ":") {
			return "", "", fmt.Errorf("invalid kprop target %q: %w", target, err)
		}
	}
	if host == "" {
		return "", "", fmt.Errorf("kprop target %q has empty host", target)
	}
	if port == "" {
		port = strconv.Itoa(754)
	}
	return host, net.JoinHostPort(host, port), nil
}

func (instance *ProviderInstance) kpropClient() *client.Client {
	return &client.Client{
		Config: &config.Config{
			DefaultRealm:       instance.Store.realm,
			DefaultTKTEnctypes: instance.Store.allowedEnctypes(),
			Forwardable:        true,
		},
		Exchange: func(_ context.Context, _ string, payload []byte) ([]byte, error) {
			return instance.KDC.HandleMessage(payload), nil
		},
	}
}

func (instance *ProviderInstance) kpropTGT(ctx context.Context) (*client.Credentials, error) {
	name, err := principal.Parse(instance.Config.GetKpropClientSpn() + "@" + instance.Store.realm)
	if err != nil {
		return nil, fmt.Errorf("parse kprop client SPN: %w", err)
	}
	record, found, err := instance.Store.Lookup(*name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("kprop client SPN %q was not found", name)
	}
	var selected kdb.Key
	for enctype, key := range record.Keys {
		if selected.Key == nil || enctype > selected.Enctype {
			selected = key
		}
	}
	if len(selected.Key) == 0 {
		return nil, fmt.Errorf("kprop client SPN %q has no keys", name)
	}
	etype, err := crypto.NewRegistry().Get(selected.Enctype)
	if err != nil {
		return nil, err
	}
	kerberos := instance.kpropClient()
	request, err := kerberos.BuildASRequest(*name, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	request.ReqBody.EType = []int32{selected.Enctype}
	timestamp, err := preauth.BuildEncryptedTimestamp(etype, selected.Key, time.Now().UTC(), 0)
	if err != nil {
		return nil, err
	}
	request.PAData = []protocol.PAData{timestamp}
	payload, err := asn1.Marshal(request)
	if err != nil {
		return nil, err
	}
	response, err := kerberos.Exchange(ctx, instance.Store.realm, payload)
	if err != nil {
		return nil, err
	}
	return kerberos.DecodeASResponse(
		response, *name, request.ReqBody.Nonce, selected.Enctype, selected.Key, time.Now().UTC(),
	)
}
