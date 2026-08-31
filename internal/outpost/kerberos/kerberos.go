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
	udp          []net.PacketConn
	tcp          []net.Listener
	kpasswdUDP   []net.PacketConn
	kpasswdTCP   []net.Listener
	kadmin       net.Listener
	kadminServer *kadm5.Server
	kkdcp        []net.Listener
	kkdcpHTTP    []*http.Server
}

func NewServer(ac *ak.APIController) ak.Outpost {
	return &KerberosServer{
		log:       log.WithField("logger", "authentik.outpost.kerberos"),
		ac:        ac,
		cs:        ak.NewCryptoStore(ac.Client.CryptoAPI),
		providers: make(map[int32]*ProviderInstance),
	}
}

func (rs *KerberosServer) Start() error {
	var group errgroup.Group
	hasUDP, hasTCP, hasKpasswdUDP, hasKpasswdTCP, hasKKDCP, hasKadmin := false, false, false, false, false, false
	rs.mu.Lock()
	for _, provider := range rs.providers {
		hasUDP = hasUDP || provider.Config.GetUdpEnabled()
		hasTCP = hasTCP || provider.Config.GetTcpEnabled()
		hasKpasswdUDP = hasKpasswdUDP ||
			(provider.Config.GetKpasswdEnabled() && provider.Config.GetUdpEnabled())
		hasKpasswdTCP = hasKpasswdTCP ||
			(provider.Config.GetKpasswdEnabled() && provider.Config.GetTcpEnabled())
		hasKKDCP = hasKKDCP || provider.Config.GetKkdcpEnabled()
		hasKadmin = hasKadmin || provider.Config.GetKadminEnabled()
	}
	rs.mu.Unlock()
	if !hasUDP && !hasTCP && !hasKpasswdUDP && !hasKpasswdTCP && !hasKKDCP && !hasKadmin {
		return errors.New("all kerberos providers have both UDP and TCP disabled")
	}
	for _, address := range config.Get().Listen.Kerberos {
		if hasUDP {
			udp, err := net.ListenPacket("udp", address)
			if err != nil {
				return err
			}
			rs.mu.Lock()
			rs.udp = append(rs.udp, udp)
			rs.mu.Unlock()
			group.Go(func() error { return rs.serveUDP(udp) })
		}
		if hasTCP {
			tcp, err := net.Listen("tcp", address)
			if err != nil {
				return err
			}
			rs.mu.Lock()
			rs.tcp = append(rs.tcp, tcp)
			rs.mu.Unlock()
			group.Go(func() error { return rs.serveTCP(tcp) })
		}
	}
	if hasKpasswdUDP || hasKpasswdTCP {
		for _, address := range config.Get().Listen.Kpasswd {
			if hasKpasswdUDP {
				udp, err := net.ListenPacket("udp", address)
				if err != nil {
					return err
				}
				rs.mu.Lock()
				rs.kpasswdUDP = append(rs.kpasswdUDP, udp)
				rs.mu.Unlock()
				group.Go(func() error { return rs.serveKpasswdUDP(udp) })
			}
			if hasKpasswdTCP {
				tcp, err := net.Listen("tcp", address)
				if err != nil {
					return err
				}
				rs.mu.Lock()
				rs.kpasswdTCP = append(rs.kpasswdTCP, tcp)
				rs.mu.Unlock()
				group.Go(func() error { return rs.serveKpasswdTCP(tcp) })
			}
		}
	}
	if hasKadmin {
		for _, address := range config.Get().Listen.Kadmin {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return err
			}
			rs.mu.Lock()
			rs.kadmin = listener
			server := rs.kadminServer
			rs.mu.Unlock()
			if server != nil {
				group.Go(func() error { return server.Serve(listener) })
			}
		}
	}
	if hasKKDCP {
		for _, address := range config.Get().Listen.KKDCP {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return err
			}
			tlsConfig := utils.GetTLSConfig()
			rs.mu.Lock()
			for _, provider := range rs.providers {
				if provider.KKDCPCertificate != nil {
					tlsConfig.Certificates = append(tlsConfig.Certificates, *provider.KKDCPCertificate)
				}
			}
			rs.mu.Unlock()
			if len(tlsConfig.Certificates) == 0 {
				_ = listener.Close()
				continue
			}
			tlsListener := tls.NewListener(listener, tlsConfig)
			server := &http.Server{
				Handler: rs.kkdcpHandler(),
			}
			rs.mu.Lock()
			rs.kkdcp = append(rs.kkdcp, tlsListener)
			rs.kkdcpHTTP = append(rs.kkdcpHTTP, server)
			rs.mu.Unlock()
			group.Go(func() error {
				err := server.Serve(tlsListener)
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			})
		}
	}
	metricsRouter := ak.MetricsRouter()
	for _, address := range config.Get().Listen.Metrics {
		address := address
		group.Go(func() error {
			ak.RunMetricsServer(address, metricsRouter)
			return nil
		})
	}
	group.Go(func() error {
		ak.RunMetricsUnix(metricsRouter)
		return nil
	})
	err := group.Wait()
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (rs *KerberosServer) Stop() error {
	rs.mu.Lock()
	providers := make([]*ProviderInstance, 0, len(rs.providers))
	for _, provider := range rs.providers {
		providers = append(providers, provider)
	}
	udp := append([]net.PacketConn(nil), rs.udp...)
	tcp := append([]net.Listener(nil), rs.tcp...)
	kpasswdUDP := append([]net.PacketConn(nil), rs.kpasswdUDP...)
	kpasswdTCP := append([]net.Listener(nil), rs.kpasswdTCP...)
	kadmin := rs.kadmin
	kkdcp := append([]net.Listener(nil), rs.kkdcp...)
	kkdcpHTTP := append([]*http.Server(nil), rs.kkdcpHTTP...)
	rs.mu.Unlock()
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
	if kadmin != nil {
		errs.Go(kadmin.Close)
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
	return errs.Wait()
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
