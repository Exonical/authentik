package kerberos

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/transport"
	log "github.com/sirupsen/logrus"

	"goauthentik.io/internal/config"
	"goauthentik.io/internal/outpost/ak"
	"golang.org/x/sync/errgroup"
)

type KerberosServer struct {
	log *log.Entry
	ac  *ak.APIController

	providers map[int32]*ProviderInstance
	mu        sync.Mutex
	udp       []net.PacketConn
	tcp       []net.Listener
}

func NewServer(ac *ak.APIController) ak.Outpost {
	return &KerberosServer{
		log:       log.WithField("logger", "authentik.outpost.kerberos"),
		ac:        ac,
		providers: make(map[int32]*ProviderInstance),
	}
}

func (rs *KerberosServer) Start() error {
	var group errgroup.Group
	hasUDP, hasTCP := false, false
	rs.mu.Lock()
	for _, provider := range rs.providers {
		hasUDP = hasUDP || provider.Config.GetUdpEnabled()
		hasTCP = hasTCP || provider.Config.GetTcpEnabled()
	}
	rs.mu.Unlock()
	if !hasUDP && !hasTCP {
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
	defer rs.mu.Unlock()
	var errs errgroup.Group
	for _, listener := range rs.udp {
		listener := listener
		errs.Go(listener.Close)
	}
	for _, listener := range rs.tcp {
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
	if udp && !provider.Config.GetUdpEnabled() {
		return nil, errors.New("UDP is disabled for kerberos provider")
	}
	if !udp && !provider.Config.GetTcpEnabled() {
		return nil, errors.New("TCP is disabled for kerberos provider")
	}
	return provider.KDC.HandleMessage(data), nil
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
