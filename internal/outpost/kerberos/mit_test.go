package kerberos

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"

	"goauthentik.io/internal/outpost/ak"
	api "goauthentik.io/packages/client-go"
)

const (
	mitRealm    = "MITKDC.TEST"
	mitUser     = "alice"
	mitPassword = "alice-password"
	mitService  = "host/service.test"
)

type mitHarness struct {
	config          string
	cache           string
	keytabPath      string
	trace           string
	passwordChanged chan string
}

func startMITKDC(t *testing.T, forceTCP bool) *mitHarness {
	return startMITKDCWithKpasswd(t, forceTCP, false)
}

func startMITKDCWithKpasswd(t *testing.T, forceTCP, withKpasswd bool) *mitHarness {
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
	userKey, err := etype.StringToKey([]byte(mitPassword), []byte(mitRealm+mitUser), nil)
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
				[]byte(request.Password), []byte(mitRealm+request.Username), nil,
			)
			if err != nil {
				http.Error(w, "bad password", http.StatusBadRequest)
				return
			}
			passwordChanged <- request.Password
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Query().Get("username") != mitUser {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"username": mitUser,
			"kvno":     1,
			"salt":     mitRealm + mitUser,
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
		realm:      mitRealm,
		masterKey:  []byte("provider master key"),
		allowed:    map[int32]bool{18: true},
		services:   make(map[string]kdb.PrincipalRecord),
		cache:      make(map[string]cachedUserKey),
		server:     outpost,
		providerID: 1,
	}
	serviceRecord, err := store.serviceRecord(mitService, 1, map[string]interface{}{
		"18": base64.StdEncoding.EncodeToString(serviceKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.services[principalKey(serviceRecord.Name)] = serviceRecord

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
	go func() { done <- server.ListenAndServe(ctx, udpConn, tcpListener) }()
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
		passwordChanged: passwordChanged,
	}
}

func (h *mitHarness) run(t *testing.T, input, command string, args ...string) string {
	t.Helper()
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
		"KRB5CCNAME=FILE:"+h.cache,
		"KRB5_KTNAME=FILE:"+h.keytabPath,
	)
	if h.trace != "" {
		cmd.Env = append(cmd.Env, "KRB5_TRACE="+h.trace)
	}
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		trace := ""
		if h.trace != "" {
			if data, traceErr := os.ReadFile(h.trace); traceErr == nil {
				trace = "\nKRB5_TRACE:\n" + string(data)
			}
		}
		t.Fatalf("%s %v failed: %v\n%s%s", command, args, err, output, trace)
	}
	return string(output)
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

func TestMITInteropPKINIT(t *testing.T) {
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
			"username": mitUser,
			"kvno":     1,
			"salt":     mitRealm + mitUser,
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
	store := &providerStore{
		realm:      mitRealm,
		allowed:    map[int32]bool{18: true},
		services:   make(map[string]kdb.PrincipalRecord),
		cache:      make(map[string]cachedUserKey),
		server:     &KerberosServer{ac: &ak.APIController{Client: api.NewAPIClient(cfg)}},
		providerID: 1,
	}
	krbtgtRecord, err := store.serviceRecord("krbtgt/"+mitRealm, 1, map[string]interface{}{
		"18": base64.StdEncoding.EncodeToString(krbtgtKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.services[principalKey(krbtgtRecord.Name)] = krbtgtRecord

	server := &kdc.Server{
		Realm:             mitRealm,
		DB:                store,
		ClockSkew:         5 * time.Minute,
		MaxTicketLife:     10 * time.Hour,
		MaxRenewableLife:  24 * time.Hour,
		PKINITCertificate: kdcCertificate,
		PKINITSigner:      kdcKey,
		PKINITClientCAs:   roots,
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
	}
	out := h.run(t, "", "kinit", "-X", "X509_user_identity=FILE:"+clientCertPath+","+clientKeyPath, mitUser)
	t.Logf("kinit PKINIT output:\n%s", out)
	klist := h.run(t, "", "klist")
	t.Logf("klist after PKINIT kinit:\n%s", klist)
	if !strings.Contains(klist, "krbtgt/"+mitRealm+"@"+mitRealm) {
		t.Fatalf("klist does not show PKINIT TGT:\n%s", klist)
	}
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
