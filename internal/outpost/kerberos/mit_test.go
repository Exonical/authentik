package kerberos

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/kkdcp"
	"github.com/Exonical/go-kerberos/krb5/principal"

	"goauthentik.io/internal/outpost/ak"
	api "goauthentik.io/packages/client-go"
)

const (
	mitRealm = "MITKDC.TEST"
	mitUser  = "alice"
	mitAlias = "alice@example.com"
	// MIT principal syntax uses a backslash to keep the email address in one
	// component instead of interpreting its @ as the realm separator.
	mitAliasArg = `alice\@example.com`
	mitPassword = "alice-password"
	mitService  = "host/service.test"
)

type mitHarness struct {
	config          string
	cache           string
	keytabPath      string
	trace           string
	passwordChanged chan string
	store           *providerStore
	server          *kdc.Server
}

func startMITKDC(t *testing.T, forceTCP bool) *mitHarness {
	return startMITKDCWithDelegation(t, forceTCP, false, true)
}

func startMITKDCWithKpasswd(t *testing.T, forceTCP, withKpasswd bool) *mitHarness {
	return startMITKDCWithDelegation(t, forceTCP, withKpasswd, true)
}

func startMITKDCWithDelegation(
	t *testing.T, forceTCP, withKpasswd, allowProxy bool,
) *mitHarness {
	return startMITKDCWithIdentity(
		t, forceTCP, withKpasswd, allowProxy, mitUser, mitUser,
	)
}

func startMITKDCWithAlias(t *testing.T) *mitHarness {
	return startMITKDCWithIdentity(t, false, false, true, mitAlias, mitUser)
}

func startMITKDCWithIdentity(
	t *testing.T,
	forceTCP, withKpasswd, allowProxy bool,
	apiUsername, canonicalUsername string,
) *mitHarness {
	return startMITKDCWithIdentityPolicy(
		t, forceTCP, withKpasswd, allowProxy, apiUsername, canonicalUsername,
		func(string, string, string) bool { return true },
	)
}

func startMITKDCWithIdentityPolicy(
	t *testing.T,
	forceTCP, withKpasswd, allowProxy bool,
	apiUsername, canonicalUsername string,
	accessCheck func(username, clientSPN, spn string) bool,
) *mitHarness {
	return startMITKDCWithIdentityPolicyOptions(
		t, forceTCP, withKpasswd, allowProxy, apiUsername, canonicalUsername,
		accessCheck, false, false,
	)
}

func startMITKDCWithIdentityPolicyOptions(
	t *testing.T,
	forceTCP, withKpasswd, allowProxy bool,
	apiUsername, canonicalUsername string,
	accessCheck func(username, clientSPN, spn string) bool,
	spake, freshness bool,
) *mitHarness {
	t.Helper()
	tools := []string{"kinit", "kvno", "klist"}
	if withKpasswd {
		tools = append(tools, "kpasswd")
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed, skipping MIT interop test", tool)
		}
	}
	registry := crypto.NewRegistry()
	etype, err := registry.Get(18)
	if err != nil {
		t.Fatal(err)
	}
	// Same string-to-key behavior as the Python provider (RFC 3962).
	userKey, err := etype.StringToKey(
		[]byte(mitPassword), []byte(mitRealm+canonicalUsername), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var passwordChanged chan string
	if withKpasswd {
		passwordChanged = make(chan string, 1)
	}
	serviceKey := make([]byte, 32)
	for i := range serviceKey {
		serviceKey[i] = byte(i + 1)
	}

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if withKpasswd && r.URL.Path == "/api/v3/outposts/kerberos/1/set_password/" {
			var request struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			userKey, err = etype.StringToKey(
				[]byte(request.Password), []byte(mitRealm+canonicalUsername), nil,
			)
			if err != nil {
				http.Error(w, "bad password", http.StatusBadRequest)
				return
			}
			passwordChanged <- request.Password
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/api/v3/outposts/kerberos/1/access_check/" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access": map[string]interface{}{
					"passing": accessCheck(
						r.URL.Query().Get("username"),
						r.URL.Query().Get("client_spn"),
						r.URL.Query().Get("spn"),
					),
					"messages":     []string{},
					"log_messages": []string{},
				},
			})
			return
		}
		if r.URL.Query().Get("username") != apiUsername &&
			r.URL.Query().Get("username") != canonicalUsername {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"username":             canonicalUsername,
			"principal":            canonicalUsername,
			"kvno":                 1,
			"salt":                 mitRealm + canonicalUsername,
			"pac_user_id":          2001,
			"pac_primary_group_id": 2001,
			"pac_group_ids":        []int32{},
			"pac_name":             canonicalUsername,
			"pac_upn":              canonicalUsername + "@" + mitRealm,
			"keys": map[string]string{
				"18": base64.StdEncoding.EncodeToString(userKey),
			},
		})
	}))
	t.Cleanup(apiServer.Close)
	parsed, err := url.Parse(apiServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := api.NewConfiguration()
	cfg.Host = parsed.Host
	cfg.Scheme = parsed.Scheme
	cfg.Servers = api.ServerConfigurations{{URL: "/api/v3"}}

	outpost := &KerberosServer{ac: &ak.APIController{Client: api.NewAPIClient(cfg)}}
	store := &providerStore{
		realm:       mitRealm,
		masterKey:   []byte("provider master key"),
		allowed:     map[int32]bool{18: true},
		services:    make(map[string]kdb.PrincipalRecord),
		delegations: make(map[string]delegationPolicy),
		cache:       make(map[string]cachedUserKey),
		server:      outpost,
		providerID:  1,
	}
	serviceRecord, err := store.serviceRecord(mitService, 1, map[string]interface{}{
		"18": base64.StdEncoding.EncodeToString(serviceKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.services[principalKey(serviceRecord.Name)] = serviceRecord
	backendKey := make([]byte, 32)
	for i := range backendKey {
		backendKey[i] = byte(33 + i)
	}
	backendRecord, err := store.serviceRecord("HTTP/backend.test", 1, map[string]interface{}{
		"18": base64.StdEncoding.EncodeToString(backendKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.services[principalKey(backendRecord.Name)] = backendRecord
	backend, err := principal.Parse("HTTP/backend.test@" + mitRealm)
	if err != nil {
		t.Fatal(err)
	}
	if allowProxy {
		store.delegations[mitService] = delegationPolicy{
			ok:      true,
			targets: []principal.Principal{*backend},
		}
	} else {
		store.delegations[mitService] = delegationPolicy{ok: true}
	}

	server := &kdc.Server{
		Realm:            mitRealm,
		DB:               store,
		ClockSkew:        5 * time.Minute,
		MaxTicketLife:    10 * time.Hour,
		MaxRenewableLife: 24 * time.Hour,
		Policy: &kdc.Policy{
			AllowForwardable: true,
			AllowRenewable:   true,
			AllowProxiable:   true,
		},
		CheckAllowedToDelegate: store.checkAllowedToDelegate,
		Authorize:              store.Authorize,
		EnableSPAKE:            spake,
		PKINITRequireFreshness: freshness,
	}
	instance := &ProviderInstance{
		Config: *api.NewKerberosOutpostConfig(1, "test", mitRealm, 3600, 3600, "test"),
		Store:  store,
		KDC:    server,
	}
	instance.Config.SetKpasswdEnabled(withKpasswd)
	instance.Config.SetUdpEnabled(true)
	instance.Config.SetTcpEnabled(true)
	outpost.providers = map[int32]*ProviderInstance{1: instance}
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		udpConn.Close()
		t.Fatal(err)
	}
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	tcpPort := tcpListener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		err := server.ListenAndServe(ctx, udpConn, tcpListener)
		done <- err
	}()
	var kpasswdUDP net.PacketConn
	var kpasswdTCP net.Listener
	if withKpasswd {
		kpasswdUDP, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		kpasswdTCP, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			_ = kpasswdUDP.Close()
			t.Fatal(err)
		}
		go func() { _ = outpost.serveKpasswdUDP(kpasswdUDP) }()
		go func() { _ = outpost.serveKpasswdTCP(kpasswdTCP) }()
	}
	t.Cleanup(func() {
		cancel()
		if kpasswdUDP != nil {
			_ = kpasswdUDP.Close()
		}
		if kpasswdTCP != nil {
			_ = kpasswdTCP.Close()
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	dir := t.TempDir()
	extra := ""
	if forceTCP {
		extra = "    udp_preference_limit = 1\n"
	}
	kpasswdPort := 0
	if withKpasswd {
		kpasswdPort = kpasswdTCP.Addr().(*net.TCPAddr).Port
	}
	configText := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    permitted_enctypes = aes256-cts-hmac-sha1-96
%s
[realms]
    %s = {
        kdc = 127.0.0.1:%d
        kdc = tcp/127.0.0.1:%d
        admin_server = 127.0.0.1:%d
        kpasswd_server = 127.0.0.1:%d
    }
`, mitRealm, extra, mitRealm, udpPort, tcpPort, tcpPort, kpasswdPort)
	configPath := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}

	servicePrincipal, err := principal.Parse(mitService + "@" + mitRealm)
	if err != nil {
		t.Fatal(err)
	}
	kt := &keytab.Keytab{Entries: []keytab.Entry{{
		Principal: *servicePrincipal,
		Timestamp: time.Now().Unix(),
		KVNO:      1,
		Enctype:   18,
		Key:       serviceKey,
	}}}
	keytabPath := filepath.Join(dir, "service.keytab")
	keytabFile, err := os.OpenFile(keytabPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := keytab.Write(keytabFile, kt); err != nil {
		t.Fatal(err)
	}
	if err := keytabFile.Close(); err != nil {
		t.Fatal(err)
	}

	return &mitHarness{
		config:          configPath,
		cache:           filepath.Join(dir, "ccache"),
		keytabPath:      keytabPath,
		trace:           filepath.Join(dir, "trace"),
		passwordChanged: passwordChanged,
		store:           store,
		server:          server,
	}
}

func (h *mitHarness) run(t *testing.T, input, command string, args ...string) string {
	return h.runWithCache(t, h.cache, input, command, args...)
}

func (h *mitHarness) runWithCache(t *testing.T, cache, input, command string, args ...string) string {
	t.Helper()
	output, err := h.runResult(cache, input, command, args...)
	if err != nil {
		trace := ""
		if h.trace != "" {
			if data, traceErr := os.ReadFile(h.trace); traceErr == nil {
				trace = "\nKRB5_TRACE:\n" + string(data)
			}
		}
		t.Fatalf("%s %v failed: %v\n%s%s", command, args, err, output, trace)
	}
	return output
}

func (h *mitHarness) runResult(cache, input, command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	env := make([]string, 0, len(os.Environ())+3)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "KRB5_CONFIG=") ||
			strings.HasPrefix(value, "KRB5CCNAME=") ||
			strings.HasPrefix(value, "KRB5_KTNAME=") {
			continue
		}
		env = append(env, value)
	}
	cmd.Env = append(env,
		"KRB5_CONFIG="+h.config,
		"KRB5CCNAME=FILE:"+cache,
		"KRB5_KTNAME=FILE:"+h.keytabPath,
	)
	if h.trace != "" {
		cmd.Env = append(cmd.Env, "KRB5_TRACE="+h.trace)
	}
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runMITFlow(t *testing.T, forceTCP bool) {
	h := startMITKDC(t, forceTCP)
	h.run(t, mitPassword+"\n", "kinit", mitUser)
	klist := h.run(t, "", "klist")
	t.Logf("klist after kinit:\n%s", klist)
	if !strings.Contains(klist, "krbtgt/"+mitRealm+"@"+mitRealm) {
		t.Fatalf("klist does not show TGT:\n%s", klist)
	}
	kvno := h.run(t, "", "kvno", mitService)
	t.Logf("kvno output:\n%s", kvno)
	if !strings.Contains(kvno, "kvno = 1") {
		t.Fatalf("unexpected kvno output:\n%s", kvno)
	}
	full := h.run(t, "", "klist", "-e")
	t.Logf("klist -e output:\n%s", full)
	if !strings.Contains(full, mitService+"@"+mitRealm) {
		t.Fatalf("klist -e does not show service ticket:\n%s", full)
	}
}

func TestMITInteropUDP(t *testing.T) {
	runMITFlow(t, false)
}

func TestMITInteropTCP(t *testing.T) {
	runMITFlow(t, true)
}

func TestMITInteropSPAKE(t *testing.T) {
	h := startMITKDCWithIdentityPolicyOptions(
		t, false, false, true, mitUser, mitUser,
		func(string, string, string) bool { return true },
		true, false,
	)
	h.run(t, mitPassword+"\n", "kinit", mitUser)
	trace, err := os.ReadFile(h.trace)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(string(trace)), "spake") {
		t.Fatalf("MIT trace did not show SPAKE preauthentication:\n%s", trace)
	}
}

func TestMITInteropKpasswd(t *testing.T) {
	const newPassword = "alice-new-password"
	h := startMITKDCWithKpasswd(t, false, true)
	h.run(t, mitPassword+"\n", "kinit", mitUser)
	h.run(t, mitPassword+"\n"+newPassword+"\n"+newPassword+"\n", "kpasswd", mitUser)
	select {
	case password := <-h.passwordChanged:
		if password != newPassword {
			t.Fatalf("password change = %q, want %q", password, newPassword)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for password API call")
	}
	h.run(t, newPassword+"\n", "kinit", mitUser)
	if output := h.run(t, "", "klist"); !strings.Contains(
		output, "krbtgt/"+mitRealm+"@"+mitRealm,
	) {
		t.Fatalf("klist does not show TGT after password change:\n%s", output)
	}
}

func TestMITInteropPolicies(t *testing.T) {
	h := startMITKDC(t, false)
	h.run(t, mitPassword+"\n", "kinit", "-p", "-r", "2h", mitUser)
	flags := h.run(t, "", "klist", "-f")
	t.Logf("klist flags after policy-enabled kinit:\n%s", flags)
	foundFlags := false
	for _, line := range strings.Split(flags, "\n") {
		if strings.Contains(line, "Flags:") {
			foundFlags = true
			if !strings.Contains(line, "P") {
				t.Fatalf("klist does not show proxiable ticket flag:\n%s", flags)
			}
		}
	}
	if !foundFlags {
		t.Fatalf("klist does not show ticket flags:\n%s", flags)
	}
	if !strings.Contains(strings.ToLower(flags), "renew until") {
		t.Fatalf("klist does not show renewable ticket lifetime:\n%s", flags)
	}
}

func TestMITInteropAuthorization(t *testing.T) {
	denied := startMITKDCWithIdentityPolicy(
		t, false, false, true, mitUser, mitUser,
		func(string, string, string) bool { return false },
	)
	if output, err := denied.runResult(denied.cache, mitPassword+"\n", "kinit", mitUser); err == nil {
		t.Fatalf("kinit unexpectedly succeeded despite application policy denial:\n%s", output)
	} else {
		t.Logf("kinit application policy denial:\n%s", output)
		if !strings.Contains(strings.ToLower(output), "policy") {
			t.Fatalf("kinit denial did not report a policy error:\n%s", output)
		}
	}

	h := startMITKDCWithIdentityPolicy(
		t, false, false, true, mitUser, mitUser,
		func(username, clientSPN, spn string) bool {
			return username == mitUser && spn != mitService
		},
	)
	h.run(t, mitPassword+"\n", "kinit", mitUser)
	if output, err := h.runResult(h.cache, "", "kvno", mitService); err == nil {
		t.Fatalf("kvno unexpectedly succeeded despite service policy denial:\n%s", output)
	} else {
		t.Logf("kvno service policy denial:\n%s", output)
		if !strings.Contains(strings.ToLower(output), "policy") {
			t.Fatalf("kvno denial did not report a policy error:\n%s", output)
		}
	}
	allowed := h.run(t, "", "kvno", "HTTP/backend.test")
	t.Logf("kvno allowed service output:\n%s", allowed)
	if !strings.Contains(allowed, "HTTP/backend.test@"+mitRealm) ||
		!strings.Contains(allowed, "kvno = 1") {
		t.Fatalf("allowed kvno output unexpected:\n%s", allowed)
	}
}

func TestMITInteropServiceAccountAuthorization(t *testing.T) {
	denied := startMITKDCWithIdentityPolicy(
		t, false, false, true, mitUser, mitUser,
		func(username, clientSPN, spn string) bool {
			return clientSPN == "" && username == mitUser && spn == ""
		},
	)
	if output, err := denied.runResult(
		denied.cache, "", "kinit", "-f", "-kt", denied.keytabPath, mitService,
	); err == nil {
		t.Fatalf("service principal kinit unexpectedly succeeded despite linked policy denial:\n%s", output)
	} else {
		t.Logf("service principal kinit policy denial:\n%s", output)
		if !strings.Contains(strings.ToLower(output), "policy") {
			t.Fatalf("service principal kinit denial did not report a policy error:\n%s", output)
		}
	}

	unlinked := startMITKDC(t, false)
	unlinked.run(t, "", "kinit", "-f", "-kt", unlinked.keytabPath, mitService)
}

func TestMITInteropS4U(t *testing.T) {
	h := startMITKDC(t, false)
	kinit := h.run(t, "", "kinit", "-f", "-kt", h.keytabPath, mitService)
	t.Logf("kinit service output:\n%s", kinit)
	klist := h.run(t, "", "klist")
	t.Logf("klist after service kinit:\n%s", klist)
	if !strings.Contains(klist, "krbtgt/"+mitRealm+"@"+mitRealm) {
		t.Fatalf("klist does not show service TGT:\n%s", klist)
	}
	self := h.run(t, "", "kvno", "-U", mitUser, mitService)
	t.Logf("kvno S4U2Self output:\n%s", self)
	if !strings.Contains(self, mitService+"@"+mitRealm) ||
		!strings.Contains(self, "kvno = 1") {
		t.Fatalf("kvno S4U2Self output unexpected:\n%s", self)
	}
	proxy := h.run(t, "", "kvno", "-U", mitUser, "-P", "HTTP/backend.test")
	t.Logf("kvno S4U2Proxy output:\n%s", proxy)
	if !strings.Contains(proxy, "HTTP/backend.test@"+mitRealm) ||
		!strings.Contains(proxy, "kvno = 1") {
		t.Fatalf("kvno S4U2Proxy output unexpected:\n%s", proxy)
	}

	denied := startMITKDCWithDelegation(t, false, false, false)
	denied.run(t, "", "kinit", "-f", "-kt", denied.keytabPath, mitService)
	denied.run(t, "", "kvno", "-U", mitUser, mitService)
	if output, err := denied.runResult(
		denied.cache, "", "kvno", "-U", mitUser, "-P", "HTTP/backend.test",
	); err == nil {
		t.Fatalf("kvno S4U2Proxy unexpectedly succeeded without allowed target:\n%s", output)
	} else {
		t.Logf("kvno denied S4U2Proxy output:\n%s", output)
		if !strings.Contains(strings.ToLower(output), "can't fulfill requested option") {
			t.Fatalf("kvno S4U2Proxy did not report the expected option error:\n%s", output)
		}
	}

	deniedUser := startMITKDCWithIdentityPolicy(
		t, false, false, true, mitUser, mitUser,
		func(username, clientSPN, spn string) bool {
			return username != mitUser || spn != "HTTP/backend.test"
		},
	)
	deniedUser.run(t, "", "kinit", "-f", "-kt", deniedUser.keytabPath, mitService)
	deniedUser.run(t, "", "kvno", "-U", mitUser, mitService)
	if output, err := deniedUser.runResult(
		deniedUser.cache, "", "kvno", "-U", mitUser, "-P", "HTTP/backend.test",
	); err == nil {
		t.Fatalf("kvno S4U2Proxy unexpectedly succeeded despite impersonated-user policy denial:\n%s", output)
	} else {
		t.Logf("kvno impersonated-user policy denial:\n%s", output)
		if !strings.Contains(strings.ToLower(output), "can't fulfill requested option") {
			t.Fatalf("kvno impersonated-user denial did not report the expected option error:\n%s", output)
		}
	}
}

func TestMITInteropPrincipalAliasCanonicalization(t *testing.T) {
	h := startMITKDCWithAlias(t)
	if output, err := h.runResult(h.cache, mitPassword+"\n", "kinit", mitAliasArg); err == nil {
		t.Fatalf("kinit with alias unexpectedly succeeded:\n%s", output)
	} else {
		t.Logf("kinit without canonicalization output:\n%s", output)
		if !strings.Contains(strings.ToLower(output), "client") ||
			!strings.Contains(strings.ToLower(output), "not found") {
			t.Fatalf("kinit alias failure did not report an unknown client:\n%s", output)
		}
	}

	h.run(t, mitPassword+"\n", "kinit", "-C", mitAliasArg)
	klist := h.run(t, "", "klist")
	t.Logf("klist after canonicalized alias kinit:\n%s", klist)
	if !strings.Contains(klist, "Default principal: "+mitUser+"@"+mitRealm) {
		t.Fatalf("klist does not show canonical default principal:\n%s", klist)
	}
	if strings.Contains(klist, "Default principal: "+mitAlias+"@"+mitRealm) {
		t.Fatalf("klist retained alias default principal:\n%s", klist)
	}
}

func TestMITInteropPKINIT(t *testing.T) {
	runMITPKINIT(t, false, false)
}

func TestMITInteropPKINITFreshness(t *testing.T) {
	runMITPKINIT(t, true, false)
}

func TestMITInteropAnonymousPKINIT(t *testing.T) {
	h := runMITPKINIT(t, false, true)
	h.run(t, "", "kinit", "-n")
	klist := h.run(t, "", "klist")
	if !strings.Contains(klist, "Default principal: WELLKNOWN/ANONYMOUS@") {
		t.Fatalf("anonymous klist did not show the well-known principal:\n%s", klist)
	}
	disabled := runMITPKINITWithAnonymousEnabled(t, false, true, false)
	disabledCache := filepath.Join(filepath.Dir(disabled.cache), "anonymous-disabled")
	if output, err := disabled.runResult(disabledCache, "", "kinit", "-n"); err == nil {
		t.Fatalf("anonymous PKINIT unexpectedly succeeded while disabled:\n%s", output)
	} else if !strings.Contains(strings.ToLower(output), "policy") &&
		!strings.Contains(strings.ToLower(output), "generic") {
		t.Fatalf("anonymous PKINIT failure did not report a policy error:\n%s", output)
	}
}

func TestMITInteropKKDCP(t *testing.T) {
	for _, tool := range []string{"kinit", "klist"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed, skipping MIT KKDCP interop test", tool)
		}
	}
	h := startMITKDCWithIdentityPolicy(t, false, false, true, mitUser, mitUser,
		func(string, string, string) bool { return true })
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KKDCP test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}),
	)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(caCertificate)
	handler := &kkdcp.Handler{
		Backend: func(_ context.Context, message []byte) ([]byte, error) {
			return h.server.HandleMessage(message), nil
		},
		RequireTargetURL: "/KdcProxy",
	}
	proxy := httptest.NewUnstartedServer(handler)
	proxy.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	proxy.StartTLS()
	t.Cleanup(proxy.Close)
	caPath := filepath.Join(filepath.Dir(h.config), "kkdcp-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	configText := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
    dns_lookup_realm = false
    http_anchors = FILE:%s
    permitted_enctypes = aes256-cts-hmac-sha1-96
[realms]
    %s = {
        kdc = https://localhost:%s/KdcProxy
    }
`, mitRealm, caPath, mitRealm, parsed.Port())
	if err := os.WriteFile(h.config, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.runResult(h.cache, mitPassword+"\n", "kinit", mitUser); err != nil {
		trace, traceErr := os.ReadFile(h.trace)
		if traceErr != nil || !strings.Contains(string(trace), "k5tls") {
			t.Fatalf("MIT KKDCP kinit failed without an identifiable proxy transport limitation: %v\n%s", err, trace)
		}
		parsedPrincipal, err := principal.Parse(mitUser + "@" + mitRealm)
		if err != nil {
			t.Fatal(err)
		}
		kkdcpClient := &kkdcp.Client{RootCAs: roots, Timeout: 5 * time.Second}
		goClient := &client.Client{
			Exchange: func(ctx context.Context, realm string, payload []byte) ([]byte, error) {
				return kkdcpClient.Exchange(ctx, "https://localhost:"+parsed.Port()+"/KdcProxy", realm, payload)
			},
		}
		credentials, err := goClient.ASExchange(context.Background(), *parsedPrincipal, mitPassword)
		if err != nil {
			t.Fatalf("go-kerberos KKDCP fallback failed: %v", err)
		}
		if credentials == nil || len(credentials.Ticket) == 0 {
			t.Fatal("go-kerberos KKDCP fallback returned no ticket")
		}
		t.Log("MIT k5tls unavailable; verified KKDCP with go-kerberos client")
		return
	}
	klist := h.run(t, "", "klist")
	if !strings.Contains(klist, "krbtgt/"+mitRealm+"@"+mitRealm) {
		t.Fatalf("KKDCP klist did not show a TGT:\n%s", klist)
	}
}

func runMITPKINIT(t *testing.T, requireFreshness, anonymous bool) *mitHarness {
	return runMITPKINITWithAnonymousEnabled(t, requireFreshness, anonymous, anonymous)
}

func runMITPKINITWithAnonymousEnabled(
	t *testing.T, requireFreshness, anonymous, anonymousEnabled bool,
) *mitHarness {
	for _, tool := range []string{"kinit", "klist"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed, skipping MIT PKINIT interop test", tool)
		}
	}
	pluginPaths := []string{
		"/usr/lib/krb5/plugins/preauth/pkinit.so",
		"/usr/lib64/krb5/plugins/preauth/pkinit.so",
		"/usr/lib/*/krb5/plugins/preauth/pkinit.so",
	}
	hasPKINITPlugin := false
	for _, path := range pluginPaths {
		matches, _ := filepath.Glob(path)
		if len(matches) > 0 {
			hasPKINITPlugin = true
			break
		}
	}
	if !hasPKINITPlugin {
		t.Skip("MIT PKINIT plugin not installed, skipping MIT PKINIT interop test")
	}
	dir := t.TempDir()
	ca, kdcCertificate, kdcKey, clientCertificate, clientKey := makeMITPKINITCertificates(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	registry := crypto.NewRegistry()
	etype, err := registry.Get(18)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := etype.StringToKey([]byte(mitPassword), []byte(mitRealm+mitUser), nil)
	if err != nil {
		t.Fatal(err)
	}
	krbtgtKey := make([]byte, 32)
	for i := range krbtgtKey {
		krbtgtKey[i] = byte(i + 1)
	}
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("username") != mitUser {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"username":  mitUser,
			"principal": mitUser,
			"kvno":      1,
			"salt":      mitRealm + mitUser,
			"keys": map[string]string{
				"18": base64.StdEncoding.EncodeToString(userKey),
			},
			"pac_user_id": 2001, "pac_primary_group_id": 2001,
			"pac_group_ids": []int32{}, "pac_name": mitUser,
			"pac_upn": mitUser + "@" + mitRealm,
		})
	}))
	t.Cleanup(apiServer.Close)
	parsed, err := url.Parse(apiServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := api.NewConfiguration()
	cfg.Host = parsed.Host
	cfg.Scheme = parsed.Scheme
	cfg.Servers = api.ServerConfigurations{{URL: "/api/v3"}}
	store := &providerStore{
		realm:                  mitRealm,
		allowed:                map[int32]bool{18: true},
		services:               make(map[string]kdb.PrincipalRecord),
		cache:                  make(map[string]cachedUserKey),
		server:                 &KerberosServer{ac: &ak.APIController{Client: api.NewAPIClient(cfg)}},
		providerID:             1,
		anonymousPKINITEnabled: anonymousEnabled,
	}
	krbtgtRecord, err := store.serviceRecord("krbtgt/"+mitRealm, 1, map[string]interface{}{
		"18": base64.StdEncoding.EncodeToString(krbtgtKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.services[principalKey(krbtgtRecord.Name)] = krbtgtRecord

	server := &kdc.Server{
		Realm:                  mitRealm,
		DB:                     store,
		ClockSkew:              5 * time.Minute,
		MaxTicketLife:          10 * time.Hour,
		MaxRenewableLife:       24 * time.Hour,
		PKINITCertificate:      kdcCertificate,
		PKINITSigner:           kdcKey,
		PKINITClientCAs:        roots,
		PKINITRequireFreshness: requireFreshness,
	}
	if anonymous {
		server.Authorize = store.Authorize
	}
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		udpConn.Close()
		t.Fatal(err)
	}
	udpPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	tcpPort := tcpListener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx, udpConn, tcpListener) }()
	t.Cleanup(func() {
		cancel()
		_ = udpConn.Close()
		_ = tcpListener.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	caPath := filepath.Join(dir, "ca.pem")
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client.key")
	writePEM := func(path, kind string, data []byte) {
		t.Helper()
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := pem.Encode(file, &pem.Block{Type: kind, Bytes: data}); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	writePEM(caPath, "CERTIFICATE", ca.Raw)
	writePEM(clientCertPath, "CERTIFICATE", clientCertificate.Raw)
	clientKeyDER := x509.MarshalPKCS1PrivateKey(clientKey)
	writePEM(clientKeyPath, "RSA PRIVATE KEY", clientKeyDER)
	configPath := filepath.Join(dir, "krb5.conf")
	configText := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    pkinit_anchors = FILE:%s
    pkinit_identities = FILE:%s,%s
    permitted_enctypes = aes256-cts-hmac-sha1-96
[realms]
    %s = {
        kdc = 127.0.0.1:%d
        kdc = tcp/127.0.0.1:%d
        pkinit_anchors = FILE:%s
        pkinit_identities = FILE:%s,%s
        admin_server = 127.0.0.1:%d
    }
`, mitRealm, caPath, clientCertPath, clientKeyPath, mitRealm, udpPort, tcpPort, caPath, clientCertPath, clientKeyPath, tcpPort)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &mitHarness{
		config: configPath,
		cache:  filepath.Join(dir, "ccache"),
		trace:  filepath.Join(dir, "trace"),
		store:  store,
	}
	if anonymous {
		return h
	}
	out := h.run(t, "", "kinit", "-X", "X509_user_identity=FILE:"+clientCertPath+","+clientKeyPath, mitUser)
	t.Logf("kinit PKINIT output:\n%s", out)
	klist := h.run(t, "", "klist")
	t.Logf("klist after PKINIT kinit:\n%s", klist)
	if !strings.Contains(klist, "krbtgt/"+mitRealm+"@"+mitRealm) {
		t.Fatalf("klist does not show PKINIT TGT:\n%s", klist)
	}
	return h
}

func makeMITPKINITCertificates(
	t *testing.T,
) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "PKINIT CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	makeCertificate := func(component string, kdc bool) (*x509.Certificate, *rsa.PrivateKey) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		components := []string{component}
		nameType := int64(1)
		eku := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4}
		if kdc {
			components = append(components, mitRealm)
			nameType = 2
			eku = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5}
		}
		nameParts := make([][]byte, 0, len(components))
		for _, value := range components {
			nameParts = append(nameParts, mitPKINITGeneralString(value))
		}
		principalDER := mitPKINITSequence(
			mitPKINITExplicit(0, mitPKINITGeneralString(mitRealm)),
			mitPKINITExplicit(1, mitPKINITSequence(
				mitPKINITExplicit(0, mitPKINITInteger(nameType)),
				mitPKINITExplicit(1, mitPKINITSequence(nameParts...)),
			)),
		)
		otherName := mitPKINITContext(0, append(
			mitPKINTOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}),
			mitPKINITContext(0, principalDER)...,
		))
		template := &x509.Certificate{
			SerialNumber:       big.NewInt(101),
			Subject:            pkix.Name{CommonName: component},
			NotBefore:          time.Now().Add(-time.Hour),
			NotAfter:           time.Now().Add(time.Hour),
			KeyUsage:           x509.KeyUsageDigitalSignature,
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{eku},
			ExtraExtensions:    []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: mitPKINITSequence(otherName)}},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	kdcCertificate, kdcKey := makeCertificate("krbtgt", true)
	clientCertificate, clientKey := makeCertificate(mitUser, false)
	return ca, kdcCertificate, kdcKey, clientCertificate, clientKey
}

func mitPKINITTLV(tag byte, content []byte) []byte {
	return append(append([]byte{tag, byte(len(content))}, content...), nil...)
}

func mitPKINITSequence(values ...[]byte) []byte {
	var content []byte
	for _, value := range values {
		content = append(content, value...)
	}
	return mitPKINITTLV(0x30, content)
}

func mitPKINITExplicit(tag int, value []byte) []byte {
	return mitPKINITTLV(0xa0|byte(tag), value)
}

func mitPKINITContext(tag int, value []byte) []byte {
	return mitPKINITTLV(0xa0|byte(tag), value)
}

func mitPKINITGeneralString(value string) []byte {
	return mitPKINITTLV(0x1b, []byte(value))
}

func mitPKINITInteger(value int64) []byte {
	return mitPKINITTLV(0x02, []byte{byte(value)})
}

func mitPKINTOID(value asn1.ObjectIdentifier) []byte {
	encoded, _ := asn1.Marshal(value)
	return encoded
}
