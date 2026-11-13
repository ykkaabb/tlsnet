package mobilecore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/ykkaabb/tlsnet/internal/auth"
	"github.com/ykkaabb/tlsnet/internal/config"
	"github.com/ykkaabb/tlsnet/internal/control"
	"github.com/ykkaabb/tlsnet/internal/multipath"
	"github.com/ykkaabb/tlsnet/internal/transport/quicreality"
	"github.com/ykkaabb/tlsnet/internal/transport/tlsreality"
	"github.com/ykkaabb/tlsnet/internal/wire"
)

type packetSession interface {
	Welcome() control.Welcome
	Transport() string
	Send([]byte) error
	Receive() ([]byte, error)
	Close() error
}

func connectMobile(ctx context.Context, cfg *config.Config, keys *auth.Keys) (packetSession, error) {
	if cfg.Transport.QUIC.Enabled && cfg.Transport.Mode != "tls-multipath" {
		session, err := connectMobileQUIC(ctx, cfg, keys)
		if err == nil || cfg.Transport.Mode == "quic" || !cfg.Transport.TLS.Enabled {
			return session, err
		}
	}
	return connectMobileTLS(ctx, cfg, keys)
}

type mobileQUIC struct {
	ctx      context.Context
	cancel   context.CancelFunc
	tunnel   *quicreality.H3Tunnel
	welcome  control.Welcome
	sequence atomic.Uint64
	ordered  chan wire.Frame
	failures chan error
}

func connectMobileQUIC(parent context.Context, cfg *config.Config, keys *auth.Keys) (packetSession, error) {
	ctx, cancel := context.WithCancel(parent)
	packetConn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		cancel()
		return nil, err
	}
	server, err := net.ResolveUDPAddr("udp", cfg.Server.Address)
	if err != nil {
		_ = packetConn.Close()
		cancel()
		return nil, err
	}
	tunnel, err := quicreality.DialH3(ctx, packetConn, server, quicreality.H3Options{
		ServerName: cfg.Reality.ServerName, Keys: keys,
		TimeWindow:        cfg.Reality.TimeWindow.Duration,
		KeepAlive:         cfg.Transport.QUIC.KeepAlive.Duration,
		IdleTimeout:       cfg.Transport.QUIC.IdleTimeout.Duration,
		InitialPacketSize: cfg.Transport.QUIC.InitialPacketSize,
		DisablePMTU:       !cfg.Transport.QUIC.PathMTUDiscovery,
	})
	if err != nil {
		_ = packetConn.Close()
		cancel()
		return nil, err
	}
	welcome, err := exchangeHelloQUIC(ctx, tunnel, mobileHello(cfg, 0, ""))
	if err != nil {
		_ = tunnel.Close()
		cancel()
		return nil, err
	}
	input := make(chan wire.Frame, 1024)
	ordered := make(chan wire.Frame, 1024)
	failures := make(chan error, 1)
	go (multipath.Reorderer{Wait: cfg.Transport.TLS.ReorderWait.Duration}).Run(ctx, input, ordered)
	go func() {
		for {
			encoded, err := tunnel.Receive(ctx)
			if err != nil {
				select {
				case failures <- err:
				default:
				}
				return
			}
			frame, err := wire.UnmarshalFrame(encoded)
			if err == nil && frame.Type == wire.TypeData {
				select {
				case input <- frame:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return &mobileQUIC{
		ctx: ctx, cancel: cancel, tunnel: tunnel, welcome: welcome,
		ordered: ordered, failures: failures,
	}, nil
}

func (s *mobileQUIC) Welcome() control.Welcome { return s.welcome }
func (s *mobileQUIC) Transport() string        { return "quic-h3" }
func (s *mobileQUIC) Send(packet []byte) error {
	encoded, err := (wire.Frame{
		Type: wire.TypeData, Sequence: s.sequence.Add(1), Payload: packet,
	}).MarshalBinary()
	if err != nil {
		return err
	}
	return s.tunnel.Send(encoded)
}
func (s *mobileQUIC) Receive() ([]byte, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case err := <-s.failures:
		return nil, err
	case frame := <-s.ordered:
		return frame.Payload, nil
	}
}
func (s *mobileQUIC) Close() error {
	s.cancel()
	return s.tunnel.Close()
}

type mobileTLS struct {
	ctx      context.Context
	cancel   context.CancelFunc
	lanes    *multipath.Set
	welcome  control.Welcome
	ordered  chan wire.Frame
	failures chan error
}

func connectMobileTLS(parent context.Context, cfg *config.Config, keys *auth.Keys) (packetSession, error) {
	ctx, cancel := context.WithCancel(parent)
	primary, welcome, err := dialMobileLane(ctx, cfg, keys, mobileHello(cfg, 0, ""))
	if err != nil {
		cancel()
		return nil, err
	}
	lanes := multipath.NewSet()
	if err := lanes.Add(0, primary); err != nil {
		_ = primary.Close()
		cancel()
		return nil, err
	}
	connections := map[int]net.Conn{0: primary}
	for lane := 1; lane < cfg.Transport.TLS.Lanes; lane++ {
		conn, _, err := dialMobileLane(ctx, cfg, keys, mobileHello(cfg, lane, welcome.SessionID))
		if err != nil {
			continue
		}
		if err := lanes.Add(lane, conn); err != nil {
			_ = conn.Close()
			continue
		}
		connections[lane] = conn
	}
	input := make(chan wire.Frame, 1024)
	ordered := make(chan wire.Frame, 1024)
	failures := make(chan error, 1)
	go (multipath.Reorderer{Wait: cfg.Transport.TLS.ReorderWait.Duration}).Run(ctx, input, ordered)
	for id, conn := range connections {
		go readMobileLane(ctx, id, conn, lanes, input, failures)
	}
	return &mobileTLS{
		ctx: ctx, cancel: cancel, lanes: lanes, welcome: welcome,
		ordered: ordered, failures: failures,
	}, nil
}

func (s *mobileTLS) Welcome() control.Welcome { return s.welcome }
func (s *mobileTLS) Transport() string        { return "tls-multipath" }
func (s *mobileTLS) Send(packet []byte) error {
	return s.lanes.Write(wire.Frame{Type: wire.TypeData, Payload: packet})
}
func (s *mobileTLS) Receive() ([]byte, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case err := <-s.failures:
		return nil, err
	case frame := <-s.ordered:
		return frame.Payload, nil
	}
}
func (s *mobileTLS) Close() error {
	s.cancel()
	return s.lanes.Close()
}

func mobileHello(cfg *config.Config, lane int, sessionID string) control.Hello {
	return control.Hello{
		Node: cfg.Node.Name, Role: "client", RequestedAddress: cfg.Overlay.Address,
		Lane: lane, SessionID: sessionID,
	}
}

func exchangeHelloQUIC(ctx context.Context, tunnel *quicreality.H3Tunnel, hello control.Hello) (control.Welcome, error) {
	payload, err := control.Encode(hello)
	if err != nil {
		return control.Welcome{}, err
	}
	encoded, err := (wire.Frame{Type: wire.TypeClientHello, Payload: payload}).MarshalBinary()
	if err != nil {
		return control.Welcome{}, err
	}
	if err := tunnel.Send(encoded); err != nil {
		return control.Welcome{}, err
	}
	encoded, err = tunnel.Receive(ctx)
	if err != nil {
		return control.Welcome{}, err
	}
	frame, err := wire.UnmarshalFrame(encoded)
	if err != nil || frame.Type != wire.TypeServerHello {
		return control.Welcome{}, errors.New("invalid relay welcome")
	}
	var welcome control.Welcome
	if err := control.Decode(frame.Payload, &welcome); err != nil {
		return control.Welcome{}, err
	}
	if !welcome.Accepted {
		return control.Welcome{}, errors.New(welcome.Error)
	}
	return welcome, nil
}

func dialMobileLane(ctx context.Context, cfg *config.Config, keys *auth.Keys, hello control.Hello) (net.Conn, control.Welcome, error) {
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", cfg.Server.Address)
	if err != nil {
		return nil, control.Welcome{}, err
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		keepAlive := cfg.Transport.TLS.KeepAlive.Duration
		interval := keepAlive / 3
		if interval < time.Second {
			interval = time.Second
		}
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAliveConfig(net.KeepAliveConfig{
			Enable: true, Idle: keepAlive, Interval: interval, Count: 3,
		})
	}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn, err := tlsreality.Client(raw, tlsreality.ClientOptions{
		ServerName: cfg.Reality.ServerName, Keys: keys, TimeWindow: cfg.Reality.TimeWindow.Duration,
	})
	if err != nil {
		_ = raw.Close()
		return nil, control.Welcome{}, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, control.Welcome{}, err
	}
	payload, err := control.Encode(hello)
	if err != nil {
		_ = conn.Close()
		return nil, control.Welcome{}, err
	}
	if err := wire.WriteFrame(conn, wire.Frame{Type: wire.TypeClientHello, Payload: payload}); err != nil {
		_ = conn.Close()
		return nil, control.Welcome{}, err
	}
	frame, err := wire.ReadFrame(conn)
	if err != nil || frame.Type != wire.TypeServerHello {
		_ = conn.Close()
		return nil, control.Welcome{}, fmt.Errorf("read relay welcome: %w", err)
	}
	var welcome control.Welcome
	if err := control.Decode(frame.Payload, &welcome); err != nil {
		_ = conn.Close()
		return nil, control.Welcome{}, err
	}
	if !welcome.Accepted {
		_ = conn.Close()
		return nil, control.Welcome{}, errors.New(welcome.Error)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, welcome, nil
}

func readMobileLane(ctx context.Context, id int, conn net.Conn, lanes *multipath.Set, output chan<- wire.Frame, failures chan<- error) {
	defer func() {
		lanes.Remove(id)
		if lanes.Len() == 0 && ctx.Err() == nil {
			select {
			case failures <- multipath.ErrNoHealthyLane:
			default:
			}
		}
	}()
	for {
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			return
		}
		if frame.Type == wire.TypeData {
			select {
			case output <- frame:
			case <-ctx.Done():
				return
			}
		}
	}
}
