package kerberos

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	log "github.com/sirupsen/logrus"

	"goauthentik.io/internal/config"
	"goauthentik.io/internal/outpost/ak"
	api "goauthentik.io/packages/client-go"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		expression string
		want       time.Duration
	}{
		{"hours=10", 10 * time.Hour},
		{"days=1;hours=2;minutes=3", 26*time.Hour + 3*time.Minute},
		{"seconds=1.5", 1500 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.expression, func(t *testing.T) {
			got, err := parseDuration(test.expression)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("parseDuration(%q) = %s, want %s", test.expression, got, test.want)
			}
		})
	}
}

func TestParseDurationRejectsInvalidExpression(t *testing.T) {
	if got, err := parseDuration(""); err != nil || got != 0 {
		t.Fatalf("parseDuration(\"\") = %s, %v; want zero, nil", got, err)
	}
	for _, expression := range []string{"hours", "nonsense=1"} {
		t.Run(expression, func(t *testing.T) {
			if _, err := parseDuration(expression); err == nil {
				t.Fatalf("parseDuration(%q) succeeded", expression)
			}
		})
	}
}

func TestRefreshCopiesCachesWithoutRacingRequests(t *testing.T) {
	t.Parallel()
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var response any
		switch r.URL.Path {
		case "/api/v3/outposts/kerberos/":
			response = map[string]any{
				"pagination": map[string]int{
					"count": 1, "next": 0, "previous": 0, "current": 1,
					"total_pages": 1, "start_index": 0, "end_index": 1,
				},
				"results": []map[string]any{{
					"pk":                            1,
					"name":                          "test",
					"realm_name":                    testRealm,
					"maximum_ticket_lifetime":       3600,
					"maximum_ticket_renew_lifetime": 3600,
					"allowed_enctypes":              []int{18},
					"master_key":                    base64.StdEncoding.EncodeToString([]byte("master key")),
					"application_slug":              "test",
				}},
				"autocomplete": map[string]any{},
			}
		case "/api/v3/outposts/kerberos/1/service_principals/":
			response = map[string]any{
				"pagination": map[string]int{
					"count": 0, "next": 0, "previous": 0, "current": 1,
					"total_pages": 1, "start_index": 0, "end_index": 0,
				},
				"results":      []any{},
				"autocomplete": map[string]any{},
			}
		case "/api/v3/outposts/kerberos/1/realm_trusts/":
			response = map[string]any{
				"pagination": map[string]int{
					"count": 0, "next": 0, "previous": 0, "current": 1,
					"total_pages": 1, "start_index": 0, "end_index": 0,
				},
				"results":      []any{},
				"autocomplete": map[string]any{},
			}
		default:
			http.NotFound(w, r)
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode response: %v", err)
		}
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

	client, err := principal.Parse("alice@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	service, err := principal.Parse("host/example@" + testRealm)
	if err != nil {
		t.Fatal(err)
	}
	oldStore := &providerStore{
		realm:    testRealm,
		services: make(map[string]kdb.PrincipalRecord),
		trusts:   make(map[string]kdb.PrincipalRecord),
		cache:    map[string]cachedUserKey{"alice": {expires: time.Now().Add(time.Minute)}},
		accessCache: map[string]cachedAccessCheck{
			"username\x00alice\x00host/example": {
				allowed: true,
				expires: time.Now().Add(time.Minute),
			},
		},
	}
	server := &KerberosServer{
		log: log.NewEntry(log.New()),
		ac:  &ak.APIController{Client: api.NewAPIClient(cfg)},
		providers: map[int32]*ProviderInstance{
			1: {Store: oldStore},
		},
	}
	oldStore.server = server

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if _, _, err := oldStore.Lookup(*client); err != nil {
					errs <- err
				}
				if err := oldStore.Authorize(*client, *service, false); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 20 {
			if err := server.Refresh(); err != nil {
				errs <- err
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSyncListenersRebindsProtocolTransports(t *testing.T) {
	listen := config.Get().Listen
	t.Cleanup(func() {
		config.Get().Listen = listen
	})
	config.Get().Listen.Kerberos = []string{"127.0.0.1:0"}
	provider := api.NewKerberosOutpostConfig(1, "test", testRealm, 3600, 3600, "test")
	provider.SetTcpEnabled(true)
	provider.SetUdpEnabled(false)
	server := &KerberosServer{
		log:         log.NewEntry(log.New()),
		providers:   map[int32]*ProviderInstance{1: {Config: *provider}},
		kadminConns: make(map[net.Conn]struct{}),
		started:     true,
		stop:        make(chan struct{}),
	}
	if err := server.syncListeners(); err != nil {
		t.Fatal(err)
	}
	if len(server.tcp) != 1 || len(server.udp) != 0 {
		t.Fatalf("initial listeners = tcp %d, udp %d; want tcp 1, udp 0", len(server.tcp), len(server.udp))
	}
	tcpAddress := server.tcp[0].Addr().String()
	conn, err := net.Dial("tcp", tcpAddress)
	if err != nil {
		t.Fatalf("dial initial TCP listener: %v", err)
	}
	_ = conn.Close()

	server.providers[1].Config.SetTcpEnabled(false)
	server.providers[1].Config.SetUdpEnabled(true)
	if err := server.syncListeners(); err != nil {
		t.Fatal(err)
	}
	if len(server.tcp) != 0 || len(server.udp) != 1 {
		t.Fatalf("rebound listeners = tcp %d, udp %d; want tcp 0, udp 1", len(server.tcp), len(server.udp))
	}
	if conn, err := net.DialTimeout("tcp", tcpAddress, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("old TCP listener still accepts connections")
	}
	if err := server.Stop(); err != nil {
		t.Fatal(err)
	}
}
