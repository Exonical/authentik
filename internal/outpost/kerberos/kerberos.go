package kerberos

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/iprop"
	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/kkdcp"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/transport"
	log "github.com/sirupsen/logrus"

	"goauthentik.io/internal/config"
	"goauthentik.io/internal/outpost/ak"
	"goauthentik.io/internal/utils"
	"golang.org/x/sync/errgroup"
)

type KerberosServer struct {
	log *log.Entry
	ac  *ak.APIController
	cs  *ak.CryptoStore

	providers    map[int32]*ProviderInstance
	mu           sync.Mutex
	listenerMu   sync.Mutex
	started      bool
	stop         chan struct{}
	udp          []net.PacketConn
	tcp          []net.Listener
	kpasswdUDP   []net.PacketConn
	kpasswdTCP   []net.Listener
	kadmin       []net.Listener
	kadminServer *kadm5.Server
	kadminConns  map[net.Conn]struct{}
	kkdcp        []net.Listener
	kkdcpHTTP    []*http.Server
	iprop        []net.Listener
	ipropServer  *iprop.Server
}

func NewServer(ac *ak.APIController) ak.Outpost {
	return &KerberosServer{
		log:         log.WithField("logger", "authentik.outpost.kerberos"),
		ac:          ac,
		cs:          ak.NewCryptoStore(ac.Client.CryptoAPI),
		providers:   make(map[int32]*ProviderInstance),
		kadminConns: make(map[net.Conn]struct{}),
	}
}

func (rs *KerberosServer) Start() error {
	hasUDP, hasTCP, hasKpasswdUDP, hasKpasswdTCP, hasKKDCP, hasKadmin, hasIprop := rs.listenerState()
	if !hasUDP && !hasTCP && !hasKpasswdUDP && !hasKpasswdTCP && !hasKKDCP && !hasKadmin && !hasIprop {
		return errors.New("all kerberos providers have both UDP and TCP disabled")
	}
	rs.mu.Lock()
	rs.started = true
	if rs.stop == nil {
		rs.stop = make(chan struct{})
	}
	stop := rs.stop
	rs.mu.Unlock()
	if err := rs.syncListeners(); err != nil {
		rs.mu.Lock()
		rs.started = false
		rs.mu.Unlock()
		return err
	}
	metricsRouter := ak.MetricsRouter()
	for _, address := range config.Get().Listen.Metrics {
		address := address
		go func() {
			ak.RunMetricsServer(address, metricsRouter)
		}()
	}
	go func() {
		ak.RunMetricsUnix(metricsRouter)
	}()
	<-stop
	return nil
}

func (rs *KerberosServer) Stop() error {
	rs.listenerMu.Lock()
	rs.mu.Lock()
	providers := make([]*ProviderInstance, 0, len(rs.providers))
	for _, provider := range rs.providers {
		providers = append(providers, provider)
	}
	udp := append([]net.PacketConn(nil), rs.udp...)
	tcp := append([]net.Listener(nil), rs.tcp...)
	kpasswdUDP := append([]net.PacketConn(nil), rs.kpasswdUDP...)
	kpasswdTCP := append([]net.Listener(nil), rs.kpasswdTCP...)
	kadmin := append([]net.Listener(nil), rs.kadmin...)
	kadminConns := make([]net.Conn, 0, len(rs.kadminConns))
	for conn := range rs.kadminConns {
		kadminConns = append(kadminConns, conn)
	}
	kkdcp := append([]net.Listener(nil), rs.kkdcp...)
	kkdcpHTTP := append([]*http.Server(nil), rs.kkdcpHTTP...)
	ipropListeners := append([]net.Listener(nil), rs.iprop...)
	rs.udp = nil
	rs.tcp = nil
	rs.kpasswdUDP = nil
	rs.kpasswdTCP = nil
	rs.kadmin = nil
	rs.kkdcp = nil
	rs.kkdcpHTTP = nil
	rs.iprop = nil
	rs.ipropServer = nil
	rs.started = false
	if rs.stop != nil {
		close(rs.stop)
		rs.stop = nil
	}
	rs.mu.Unlock()
	rs.listenerMu.Unlock()
	for _, provider := range providers {
		provider.stopKprop()
		provider.stopAudit()
	}
	var errs errgroup.Group
	for _, listener := range udp {
		listener := listener
		errs.Go(listener.Close)
	}
	for _, listener := range tcp {
		listener := listener
		errs.Go(listener.Close)
	}
	for _, listener := range kpasswdUDP {
		listener := listener
		errs.Go(listener.Close)
	}
	for _, listener := range kpasswdTCP {
		listener := listener
		errs.Go(listener.Close)
	}
	for _, listener := range kadmin {
		listener := listener
		errs.Go(listener.Close)
	}
	for _, conn := range kadminConns {
		errs.Go(conn.Close)
	}
	for _, server := range kkdcpHTTP {
		server := server
		errs.Go(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return server.Shutdown(ctx)
		})
	}
	for _, listener := range kkdcp {
		listener := listener
		errs.Go(listener.Close)
	}
	for _, listener := range ipropListeners {
		listener := listener
		errs.Go(listener.Close)
	}
	return errs.Wait()
}

func (rs *KerberosServer) listenerState() (bool, bool, bool, bool, bool, bool, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	hasUDP, hasTCP, hasKpasswdUDP, hasKpasswdTCP, hasKKDCP, hasKadmin, hasIprop := false, false, false, false, false, false, false
	for _, provider := range rs.providers {
		hasUDP = hasUDP || provider.Config.GetUdpEnabled()
		hasTCP = hasTCP || provider.Config.GetTcpEnabled()
		hasKpasswdUDP = hasKpasswdUDP ||
			(provider.Config.GetKpasswdEnabled() && provider.Config.GetUdpEnabled())
		hasKpasswdTCP = hasKpasswdTCP ||
			(provider.Config.GetKpasswdEnabled() && provider.Config.GetTcpEnabled())
		hasKKDCP = hasKKDCP || provider.Config.GetKkdcpEnabled()
		hasKadmin = hasKadmin || provider.Config.GetKadminEnabled()
		hasIprop = hasIprop || provider.Config.GetIpropEnabled()
	}
	return hasUDP, hasTCP, hasKpasswdUDP, hasKpasswdTCP, hasKKDCP, hasKadmin, hasIprop
}

func (rs *KerberosServer) syncListeners() error {
	rs.listenerMu.Lock()
	defer rs.listenerMu.Unlock()
	rs.mu.Lock()
	started := rs.started
	rs.mu.Unlock()
	if !started {
		return nil
	}
	hasUDP, hasTCP, hasKpasswdUDP, hasKpasswdTCP, hasKKDCP, hasKadmin, hasIprop := rs.listenerState()
	if err := rs.syncKerberosListeners(hasUDP, hasTCP); err != nil {
		return err
	}
	if err := rs.syncKpasswdListeners(hasKpasswdUDP, hasKpasswdTCP); err != nil {
		return err
	}
	if err := rs.syncKadminListeners(hasKadmin); err != nil {
		return err
	}
	if err := rs.syncKKDCPListeners(hasKKDCP); err != nil {
		return err
	}
	return rs.syncIpropListeners(hasIprop)
}

func (rs *KerberosServer) syncIpropListeners(enabled bool) error {
	if !enabled {
		rs.mu.Lock()
		listeners := rs.iprop
		rs.iprop = nil
		rs.ipropServer = nil
		rs.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		return nil
	}
	rs.mu.Lock()
	bound := len(rs.iprop) > 0
	currentServer := rs.ipropServer
	var server *iprop.Server
	for _, provider := range rs.providers {
		if provider.Iprop != nil {
			server = provider.Iprop
			break
		}
	}
	rs.mu.Unlock()
	if server == nil {
		return nil
	}
	if bound && currentServer == server {
		return nil
	}
	if bound {
		rs.mu.Lock()
		listeners := rs.iprop
		rs.iprop = nil
		rs.ipropServer = nil
		rs.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}
	listeners := make([]net.Listener, 0, len(config.Get().Listen.Iprop))
	for _, address := range config.Get().Listen.Iprop {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			for _, boundListener := range listeners {
				_ = boundListener.Close()
			}
			return err
		}
		listeners = append(listeners, listener)
	}
	rs.mu.Lock()
	rs.iprop = listeners
	rs.ipropServer = server
	rs.mu.Unlock()
	for _, listener := range listeners {
		listener := listener
		rs.detachedServe("iprop", func() error { return server.Serve(listener) })
	}
	return nil
}

func (rs *KerberosServer) detachedServe(name string, serve func() error) {
	go func() {
		if err := serve(); err != nil &&
			!errors.Is(err, net.ErrClosed) &&
			!errors.Is(err, io.EOF) &&
			!errors.Is(err, http.ErrServerClosed) {
			rs.log.WithError(err).WithField("listener", name).Warn("Kerberos listener stopped")
		}
	}()
}

func (rs *KerberosServer) syncKerberosListeners(hasUDP, hasTCP bool) error {
	if !hasUDP {
		rs.mu.Lock()
		listeners := rs.udp
		rs.udp = nil
		rs.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
	} else {
		rs.mu.Lock()
		bound := len(rs.udp) > 0
		rs.mu.Unlock()
		if !bound {
			listeners := make([]net.PacketConn, 0, len(config.Get().Listen.Kerberos))
			for _, address := range config.Get().Listen.Kerberos {
				listener, err := net.ListenPacket("udp", address)
				if err != nil {
					for _, boundListener := range listeners {
						_ = boundListener.Close()
					}
					return err
				}
				listeners = append(listeners, listener)
			}
			rs.mu.Lock()
			rs.udp = listeners
			rs.mu.Unlock()
			for _, listener := range listeners {
				listener := listener
				rs.detachedServe("kerberos UDP", func() error { return rs.serveUDP(listener) })
			}
		}
	}
	if !hasTCP {
		rs.mu.Lock()
		listeners := rs.tcp
		rs.tcp = nil
		rs.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
	} else {
		rs.mu.Lock()
		bound := len(rs.tcp) > 0
		rs.mu.Unlock()
		if !bound {
			listeners := make([]net.Listener, 0, len(config.Get().Listen.Kerberos))
			for _, address := range config.Get().Listen.Kerberos {
				listener, err := net.Listen("tcp", address)
				if err != nil {
					for _, boundListener := range listeners {
						_ = boundListener.Close()
					}
					return err
				}
				listeners = append(listeners, listener)
			}
			rs.mu.Lock()
			rs.tcp = listeners
			rs.mu.Unlock()
			for _, listener := range listeners {
				listener := listener
				rs.detachedServe("kerberos TCP", func() error { return rs.serveTCP(listener) })
			}
		}
	}
	return nil
}

func (rs *KerberosServer) syncKpasswdListeners(hasUDP, hasTCP bool) error {
	if !hasUDP {
		rs.mu.Lock()
		listeners := rs.kpasswdUDP
		rs.kpasswdUDP = nil
		rs.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
	} else {
		rs.mu.Lock()
		bound := len(rs.kpasswdUDP) > 0
		rs.mu.Unlock()
		if !bound {
			listeners := make([]net.PacketConn, 0, len(config.Get().Listen.Kpasswd))
			for _, address := range config.Get().Listen.Kpasswd {
				listener, err := net.ListenPacket("udp", address)
				if err != nil {
					for _, boundListener := range listeners {
						_ = boundListener.Close()
					}
					return err
				}
				listeners = append(listeners, listener)
			}
			rs.mu.Lock()
			rs.kpasswdUDP = listeners
			rs.mu.Unlock()
			for _, listener := range listeners {
				listener := listener
				rs.detachedServe("kpasswd UDP", func() error { return rs.serveKpasswdUDP(listener) })
			}
		}
	}
	if !hasTCP {
		rs.mu.Lock()
		listeners := rs.kpasswdTCP
		rs.kpasswdTCP = nil
		rs.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
	} else {
		rs.mu.Lock()
		bound := len(rs.kpasswdTCP) > 0
		rs.mu.Unlock()
		if !bound {
			listeners := make([]net.Listener, 0, len(config.Get().Listen.Kpasswd))
			for _, address := range config.Get().Listen.Kpasswd {
				listener, err := net.Listen("tcp", address)
				if err != nil {
					for _, boundListener := range listeners {
						_ = boundListener.Close()
					}
					return err
				}
				listeners = append(listeners, listener)
			}
			rs.mu.Lock()
			rs.kpasswdTCP = listeners
			rs.mu.Unlock()
			for _, listener := range listeners {
				listener := listener
				rs.detachedServe("kpasswd TCP", func() error { return rs.serveKpasswdTCP(listener) })
			}
		}
	}
	return nil
}

func (rs *KerberosServer) syncKadminListeners(enabled bool) error {
	if !enabled {
		rs.mu.Lock()
		listeners := rs.kadmin
		rs.kadmin = nil
		rs.mu.Unlock()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		return nil
	}
	rs.mu.Lock()
	bound := len(rs.kadmin) > 0
	rs.mu.Unlock()
	if bound {
		return nil
	}
	listeners := make([]net.Listener, 0, len(config.Get().Listen.Kadmin))
	for _, address := range config.Get().Listen.Kadmin {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			for _, boundListener := range listeners {
				_ = boundListener.Close()
			}
			return err
		}
		listeners = append(listeners, listener)
	}
	rs.mu.Lock()
	rs.kadmin = listeners
	rs.mu.Unlock()
	for _, listener := range listeners {
		listener := listener
		rs.detachedServe("kadmin", func() error { return rs.serveKadmin(listener) })
	}
	return nil
}

func (rs *KerberosServer) syncKKDCPListeners(enabled bool) error {
	if !enabled {
		rs.mu.Lock()
		listeners := rs.kkdcp
		servers := rs.kkdcpHTTP
		rs.kkdcp = nil
		rs.kkdcpHTTP = nil
		rs.mu.Unlock()
		for _, server := range servers {
			_ = server.Close()
		}
		for _, listener := range listeners {
			_ = listener.Close()
		}
		return nil
	}
	rs.mu.Lock()
	bound := len(rs.kkdcp) > 0
	rs.mu.Unlock()
	if bound {
		return nil
	}
	listeners := make([]net.Listener, 0, len(config.Get().Listen.KKDCP))
	servers := make([]*http.Server, 0, len(config.Get().Listen.KKDCP))
	for _, address := range config.Get().Listen.KKDCP {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			for _, boundListener := range listeners {
				_ = boundListener.Close()
			}
			return err
		}
		tlsConfig := utils.GetTLSConfig()
		tlsConfig.GetCertificate = rs.kkdcpCertificate
		tlsListener := tls.NewListener(listener, tlsConfig)
		server := &http.Server{Handler: rs.kkdcpHandler()}
		listeners = append(listeners, tlsListener)
		servers = append(servers, server)
	}
	rs.mu.Lock()
	rs.kkdcp = listeners
	rs.kkdcpHTTP = servers
	rs.mu.Unlock()
	for index, listener := range listeners {
		listener := listener
		server := servers[index]
		rs.detachedServe("KKDCP", func() error { return server.Serve(listener) })
	}
	return nil
}

type singleConnListener struct {
	conn net.Conn
	used bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.used {
		return nil, net.ErrClosed
	}
	l.used = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func (rs *KerberosServer) serveKadmin(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		rs.mu.Lock()
		server := rs.kadminServer
		if rs.kadminConns == nil {
			rs.kadminConns = make(map[net.Conn]struct{})
		}
		rs.kadminConns[conn] = struct{}{}
		rs.mu.Unlock()
		if server == nil {
			_ = conn.Close()
			rs.mu.Lock()
			delete(rs.kadminConns, conn)
			rs.mu.Unlock()
			continue
		}
		go func() {
			defer func() {
				_ = conn.Close()
				rs.mu.Lock()
				delete(rs.kadminConns, conn)
				rs.mu.Unlock()
			}()
			_ = server.Serve(&singleConnListener{conn: conn})
		}()
	}
}

func (rs *KerberosServer) serveUDP(conn net.PacketConn) error {
	buffer := make([]byte, 64*1024)
	for {
		size, address, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		response, err := rs.handleTransport(buffer[:size], true)
		if err != nil {
			rs.log.WithError(err).Warn("failed to handle kerberos request")
			continue
		}
		if _, err := conn.WriteTo(response, address); err != nil {
			return err
		}
	}
}

func (rs *KerberosServer) serveTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			for {
				request, err := transport.ReadTCPFrame(conn, transport.DefaultMaxFrameSize)
				if err != nil {
					return
				}
				response, err := rs.handleTransport(request, false)
				if err != nil {
					return
				}
				if err := transport.WriteTCPFrame(conn, response); err != nil {
					return
				}
			}
		}()
	}
}

// handle routes a request to the provider matching the request realm.
// Accepted limitation: there is no TGS authenticator replay cache.
func (rs *KerberosServer) handle(data []byte) ([]byte, error) {
	return rs.handleTransport(data, true)
}

func (rs *KerberosServer) handleTransport(data []byte, udp bool) ([]byte, error) {
	provider, err := rs.providerForRequest(data)
	if err != nil {
		return nil, err
	}
	if udp && !provider.Config.GetUdpEnabled() {
		return nil, errors.New("UDP is disabled for kerberos provider")
	}
	if !udp && !provider.Config.GetTcpEnabled() {
		return nil, errors.New("TCP is disabled for kerberos provider")
	}
	return provider.KDC.HandleMessage(data), nil
}

func (rs *KerberosServer) handleKKDCP(_ context.Context, data []byte) ([]byte, error) {
	provider, err := rs.providerForRequest(data)
	if err != nil {
		return nil, err
	}
	if provider.KKDCPCertificate == nil {
		return nil, errors.New("KKDCP is disabled for kerberos provider")
	}
	return provider.KDC.HandleMessage(data), nil
}

func (rs *KerberosServer) kkdcpCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, provider := range rs.providers {
		if provider.KKDCPCertificate != nil {
			certificate := *provider.KKDCPCertificate
			return &certificate, nil
		}
	}
	return nil, errors.New("no KKDCP TLS certificate is configured")
}

func (rs *KerberosServer) kkdcpHandler() http.Handler {
	return &kkdcp.Handler{
		Backend:          rs.handleKKDCP,
		RequireTargetURL: "/KdcProxy",
	}
}

func (rs *KerberosServer) providerForRequest(data []byte) (*ProviderInstance, error) {
	rs.mu.Lock()
	realm, realmErr := requestRealm(data)
	var provider *ProviderInstance
	if realmErr == nil {
		for _, candidate := range rs.providers {
			if candidate.Config.RealmName == realm {
				provider = candidate
				break
			}
		}
	}
	rs.mu.Unlock()
	if realmErr != nil {
		return nil, realmErr
	}
	if provider == nil {
		return nil, errors.New("no kerberos provider for realm")
	}
	return provider, nil
}

func requestRealm(data []byte) (string, error) {
	switch {
	case len(data) > 0 && data[0] == 0x6a:
		var request protocol.ASReq
		if err := asn1.Unmarshal(data, &request); err != nil {
			return "", err
		}
		return request.ReqBody.Realm, nil
	case len(data) > 0 && data[0] == 0x6c:
		var request protocol.TGSReq
		if err := asn1.Unmarshal(data, &request); err != nil {
			return "", err
		}
		return request.ReqBody.Realm, nil
	default:
		return "", errors.New("unsupported kerberos request")
	}
}

func (rs *KerberosServer) TimerFlowCacheExpiry(context.Context) {}

func (rs *KerberosServer) Type() string {
	return "kerberos"
}
