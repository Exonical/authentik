package kerberos

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/kprop"
	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"

	"goauthentik.io/internal/outpost/ak"
)

func (rs *KerberosServer) startKprop(instance *ProviderInstance) {
	if !instance.kpropConfigured() {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	instance.kpropCancel = cancel
	instance.kpropDone = make(chan struct{})
	go func() {
		defer close(instance.kpropDone)
		instance.pushKprop(ctx)
		ticker := time.NewTicker(time.Duration(instance.Config.GetKpropInterval()) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				instance.pushKprop(ctx)
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
	db := kdb.NewDatabase(instance.Store.realm)
	add := func(record kdb.PrincipalRecord) error {
		if len(record.Keys) == 0 {
			return nil
		}
		return db.ApplyPrincipal(record, false)
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
	if err := add(localTGT); err != nil {
		return nil, err
	}
	changepw, found, err := instance.Store.changepwRecord(principal.Principal{
		Realm: instance.Store.realm, NameType: principal.NTSrvInstance,
		Components: []string{"kadmin", "changepw"},
	})
	if err != nil {
		return nil, fmt.Errorf("build changepw: %w", err)
	}
	if found {
		if err := add(changepw); err != nil {
			return nil, err
		}
	}
	for _, record := range instance.Store.services {
		if err := add(record); err != nil {
			return nil, fmt.Errorf("add service principal: %w", err)
		}
	}
	for _, record := range instance.Store.trusts {
		if err := add(record); err != nil {
			return nil, fmt.Errorf("add realm trust: %w", err)
		}
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
		if err := add(record); err != nil {
			return nil, fmt.Errorf("add user %q: %w", user.GetUsername(), err)
		}
	}
	dump, err := mitdump.DumpWithMasterPassword(db, instance.Config.GetKpropMasterPassword())
	if err != nil {
		return nil, fmt.Errorf("serialize MIT dump: %w", err)
	}
	return dump, nil
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
