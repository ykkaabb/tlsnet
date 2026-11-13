package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ykkaabb/tlsnet/internal/auth"
	"github.com/ykkaabb/tlsnet/internal/config"
	"github.com/ykkaabb/tlsnet/internal/control"
	"github.com/ykkaabb/tlsnet/internal/overlay"
	"github.com/ykkaabb/tlsnet/internal/transport/tlsreality"
	"github.com/ykkaabb/tlsnet/internal/tun"
	"github.com/ykkaabb/tlsnet/internal/wire"
)

func Run(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	if cfg.Transport.Mode == "quic" || !cfg.Transport.TLS.Enabled {
		return errors.New("QUIC data transport is not wired into the runtime yet; enable TLS and use auto or tls-multipath")
	}
	keys, err := deriveKeys(cfg)
	if err != nil {
		return err
	}
	if cfg.Node.Role == "relay" {
		return runRelay(ctx, cfg, keys, logger)
	}
	return runNode(ctx, cfg, keys, logger)
}

func deriveKeys(cfg *config.Config) (*auth.Keys, error) {
	return auth.Derive(cfg.Auth.Password, cfg.Auth.NetworkName, cfg.Reality.ServerName, auth.KDFParams{
		MemoryMiB: cfg.Auth.KDFMemoryMiB, Iterations: cfg.Auth.KDFIterations, Parallelism: cfg.Auth.KDFParallelism,
	})
}

type relay struct {
	cfg       *config.Config
	keys      *auth.Keys
	logger    *slog.Logger
	tlsConfig *tls.Config
	allocator *control.Allocator
	routes    *overlay.RouteTable
	fallback  *tlsreality.Fallback
	mu        sync.RWMutex
	peers     map[string]*peer
}

type peer struct {
	node    string
	address netip.Addr
	conn    net.Conn
	sendMu  sync.Mutex
}

func runRelay(ctx context.Context, cfg *config.Config, keys *auth.Keys, logger *slog.Logger) error {
	pool := netip.MustParsePrefix(cfg.Overlay.Pool).Masked()
	relayPrefix := netip.MustParsePrefix(cfg.Overlay.Address)
	allocator, err := control.NewAllocator(pool, relayPrefix.Addr())
	if err != nil {
		return err
	}
	serverOptions := tlsreality.ServerOptions{
		ServerName: cfg.Reality.ServerName, Keys: keys, TimeWindow: cfg.Reality.TimeWindow.Duration,
	}
	tlsConfig, err := tlsreality.ServerConfig(serverOptions)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", cfg.Listen.TCP)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	hub := &relay{
		cfg: cfg, keys: keys, logger: logger, tlsConfig: tlsConfig, allocator: allocator,
		routes: overlay.NewRouteTable(), peers: make(map[string]*peer),
		fallback: &tlsreality.Fallback{
			Target: cfg.Reality.TCPTarget, DialTimeout: 5 * time.Second,
			MaxLifetime: cfg.Reality.FallbackMaxLifetime.Duration,
			MaxTotal:    cfg.Reality.FallbackMaxConnections, MaxPerIP: cfg.Reality.FallbackMaxPerIP,
		},
	}
	logger.Info("TCP relay listening", "address", cfg.Listen.TCP, "cover", cfg.Reality.ServerName)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Warn("accept failed", "error", err)
			continue
		}
		go hub.handle(ctx, conn, serverOptions)
	}
}

func (r *relay) handle(ctx context.Context, raw net.Conn, options tlsreality.ServerOptions) {
	defer raw.Close()
	helloTLS, err := tlsreality.PeekClientHello(raw, 0, 5*time.Second)
	if err != nil {
		r.logger.Debug("invalid TLS preface", "remote", raw.RemoteAddr(), "error", err)
		return
	}
	if !tlsreality.IsAuthorized(helloTLS, options) {
		_ = r.fallback.Relay(ctx, raw, helloTLS.Raw)
		return
	}
	conn, err := tlsreality.HandshakeServer(ctx, raw, helloTLS, r.tlsConfig)
	if err != nil {
		r.logger.Debug("authorized TLS handshake failed", "error", err)
		return
	}
	frame, err := wire.ReadFrame(conn)
	if err != nil || frame.Type != wire.TypeClientHello {
		return
	}
	var hello control.Hello
	if err := control.Decode(frame.Payload, &hello); err != nil || hello.Validate() != nil || hello.Lane != 0 {
		return
	}
	p, welcome, err := r.register(hello, conn)
	if err != nil {
		_ = sendWelcome(conn, control.Welcome{Accepted: false, Error: err.Error()})
		return
	}
	defer r.unregister(p)
	if err := sendWelcome(conn, welcome); err != nil {
		return
	}
	r.logger.Info("node connected", "node", p.node, "address", p.address)
	for {
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			return
		}
		if frame.Type != wire.TypeData {
			continue
		}
		packet, err := overlay.ParsePacket(frame.Payload)
		if err != nil || !r.routes.AllowsSource(p.node, packet.Source) {
			continue
		}
		targetName, ok := r.routes.Lookup(packet.Target)
		if !ok || targetName == p.node {
			continue
		}
		r.mu.RLock()
		target := r.peers[targetName]
		r.mu.RUnlock()
		if target != nil {
			_ = target.send(frame)
		}
	}
}

func (r *relay) register(hello control.Hello, conn net.Conn) (*peer, control.Welcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.peers[hello.Node]; exists {
		return nil, control.Welcome{}, errors.New("node is already connected")
	}
	allowed := make(map[netip.Prefix]struct{})
	for _, route := range r.cfg.Relay.AllowedRoutes[hello.Node] {
		allowed[netip.MustParsePrefix(route).Masked()] = struct{}{}
	}
	for _, route := range hello.AdvertiseRoutes {
		prefix := netip.MustParsePrefix(route).Masked()
		if _, ok := allowed[prefix]; !ok {
			return nil, control.Welcome{}, fmt.Errorf("node %q is not allowed to advertise %s", hello.Node, prefix)
		}
	}
	var requested netip.Addr
	if hello.RequestedAddress != "" && hello.RequestedAddress != "auto" {
		requested = netip.MustParsePrefix(hello.RequestedAddress).Addr()
	}
	address, err := r.allocator.Allocate(hello.Node, requested)
	if err != nil {
		return nil, control.Welcome{}, err
	}
	prefixes := []netip.Prefix{netip.PrefixFrom(address, 32)}
	for _, route := range hello.AdvertiseRoutes {
		prefixes = append(prefixes, netip.MustParsePrefix(route))
	}
	if err := r.routes.AddBatch(hello.Node, prefixes); err != nil {
		r.allocator.Release(hello.Node)
		return nil, control.Welcome{}, err
	}
	p := &peer{node: hello.Node, address: address, conn: conn}
	r.peers[hello.Node] = p
	session := make([]byte, 16)
	_, _ = rand.Read(session)
	pool := netip.MustParsePrefix(r.cfg.Overlay.Pool)
	welcome := control.Welcome{
		Accepted: true, Address: netip.PrefixFrom(address, pool.Bits()).String(),
		Routes: r.cfg.Overlay.AcceptRoutes, MTU: r.cfg.Overlay.MTU,
		SessionID: base64.RawURLEncoding.EncodeToString(session),
	}
	return p, welcome, nil
}

func (r *relay) unregister(p *peer) {
	r.mu.Lock()
	if r.peers[p.node] == p {
		delete(r.peers, p.node)
	}
	r.mu.Unlock()
	r.routes.RemovePeer(p.node)
	r.allocator.Release(p.node)
	r.logger.Info("node disconnected", "node", p.node)
}

func (p *peer) send(frame wire.Frame) error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	return wire.WriteFrame(p.conn, frame)
}

func sendWelcome(conn net.Conn, welcome control.Welcome) error {
	payload, err := control.Encode(welcome)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, wire.Frame{Type: wire.TypeServerHello, Payload: payload})
}

func runNode(ctx context.Context, cfg *config.Config, keys *auth.Keys, logger *slog.Logger) error {
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", cfg.Server.Address)
	if err != nil {
		return err
	}
	defer raw.Close()
	conn, err := tlsreality.Client(raw, tlsreality.ClientOptions{
		ServerName: cfg.Reality.ServerName, Keys: keys, TimeWindow: cfg.Reality.TimeWindow.Duration,
	})
	if err != nil {
		return err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}
	hello := control.Hello{
		Node: cfg.Node.Name, Role: cfg.Node.Role, RequestedAddress: cfg.Overlay.Address,
		AdvertiseRoutes: cfg.Overlay.AdvertiseRoutes, Lane: 0,
	}
	payload, err := control.Encode(hello)
	if err != nil {
		return err
	}
	if err := wire.WriteFrame(conn, wire.Frame{Type: wire.TypeClientHello, Payload: payload}); err != nil {
		return err
	}
	frame, err := wire.ReadFrame(conn)
	if err != nil || frame.Type != wire.TypeServerHello {
		return fmt.Errorf("read relay welcome: %w", err)
	}
	var welcome control.Welcome
	if err := control.Decode(frame.Payload, &welcome); err != nil {
		return err
	}
	if !welcome.Accepted {
		return errors.New(welcome.Error)
	}
	routes := cfg.Overlay.AcceptRoutes
	device, err := tun.Open(tun.Config{Name: cfg.Overlay.Name, Address: welcome.Address, MTU: welcome.MTU, Routes: routes})
	if err != nil {
		return err
	}
	defer device.Close()
	if cfg.Node.Role == "gateway" && cfg.Gateway.NAT {
		assigned := netip.MustParsePrefix(welcome.Address).Masked()
		cleanup, err := tun.EnableGatewayNAT(cfg.Gateway.LANInterface, assigned.String())
		if err != nil {
			return err
		}
		defer cleanup()
		logger.Info("gateway NAT enabled", "lan_interface", cfg.Gateway.LANInterface, "source", assigned)
	}
	logger.Info("overlay ready", "interface", device.Name(), "address", welcome.Address, "transport", "tls")

	var sequence atomic.Uint64
	writeErrors := make(chan error, 1)
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, err := device.Read(buffer)
			if err != nil {
				writeErrors <- err
				return
			}
			packet := append([]byte(nil), buffer[:n]...)
			if err := wire.WriteFrame(conn, wire.Frame{Type: wire.TypeData, Sequence: sequence.Add(1), Payload: packet}); err != nil {
				writeErrors <- err
				return
			}
		}
	}()
	for {
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			select {
			case writeErr := <-writeErrors:
				return writeErr
			default:
				return err
			}
		}
		if frame.Type == wire.TypeData {
			if _, err := device.Write(frame.Payload); err != nil {
				return err
			}
		}
	}
}
