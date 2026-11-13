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

	"github.com/quic-go/quic-go"
	"github.com/ykkaabb/tlsnet/internal/auth"
	"github.com/ykkaabb/tlsnet/internal/config"
	"github.com/ykkaabb/tlsnet/internal/control"
	"github.com/ykkaabb/tlsnet/internal/multipath"
	"github.com/ykkaabb/tlsnet/internal/overlay"
	"github.com/ykkaabb/tlsnet/internal/transport/quicreality"
	"github.com/ykkaabb/tlsnet/internal/transport/tlsreality"
	"github.com/ykkaabb/tlsnet/internal/tun"
	"github.com/ykkaabb/tlsnet/internal/wire"
)

func Run(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	keys, err := deriveKeys(cfg)
	if err != nil {
		return err
	}
	if cfg.Node.Role == "relay" {
		return runRelay(ctx, cfg, keys, logger)
	}
	return runNodeLoop(ctx, cfg, keys, logger)
}

func runNodeLoop(ctx context.Context, cfg *config.Config, keys *auth.Keys, logger *slog.Logger) error {
	backoff := time.Second
	for {
		started := time.Now()
		err := runNodeAttempt(ctx, cfg, keys, logger)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			err = errors.New("transport stopped without an error")
		}
		if time.Since(started) >= time.Minute {
			backoff = time.Second
		}
		logger.Warn("overlay disconnected; reconnecting", "error", err, "after", backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func runNodeAttempt(ctx context.Context, cfg *config.Config, keys *auth.Keys, logger *slog.Logger) error {
	if cfg.Transport.QUIC.Enabled && cfg.Transport.Mode != "tls-multipath" {
		err := runNodeH3(ctx, cfg, keys, logger)
		if err == nil || ctx.Err() != nil || cfg.Transport.Mode == "quic" || !cfg.Transport.TLS.Enabled {
			return err
		}
		logger.Warn("QUIC unavailable; falling back to multipath TLS", "error", err)
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
	sessions  map[string]*peer
}

type peer struct {
	node      string
	sessionID string
	address   netip.Addr
	lanes     *multipath.Set
	ctx       context.Context
	cancel    context.CancelFunc
	incoming  chan wire.Frame
	ordered   chan wire.Frame
	stats     trafficStats
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
	var tlsConfig *tls.Config
	if cfg.Transport.TLS.Enabled && cfg.Transport.Mode != "quic" {
		tlsConfig, err = tlsreality.ServerConfig(serverOptions)
		if err != nil {
			return err
		}
	}
	hub := &relay{
		cfg: cfg, keys: keys, logger: logger, tlsConfig: tlsConfig, allocator: allocator,
		routes: overlay.NewRouteTable(), peers: make(map[string]*peer), sessions: make(map[string]*peer),
		fallback: &tlsreality.Fallback{
			Target: cfg.Reality.TCPTarget, DialTimeout: 5 * time.Second,
			MaxLifetime: cfg.Reality.FallbackMaxLifetime.Duration,
			MaxTotal:    cfg.Reality.FallbackMaxConnections, MaxPerIP: cfg.Reality.FallbackMaxPerIP,
		},
	}
	quicErrors := make(chan error, 1)
	if cfg.Transport.QUIC.Enabled && cfg.Transport.Mode != "tls-multipath" {
		go func() {
			err := hub.runQUIC(ctx)
			if err != nil && ctx.Err() == nil {
				logger.Error("QUIC relay stopped", "error", err)
			}
			quicErrors <- err
		}()
	}
	if !cfg.Transport.TLS.Enabled || cfg.Transport.Mode == "quic" {
		select {
		case <-ctx.Done():
			return nil
		case err := <-quicErrors:
			return err
		}
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
	tuneTCP(raw, r.cfg.Transport.TLS.KeepAlive.Duration, r.cfg.Transport.TLS.TCPUserTimeout.Duration)
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
	if err := control.Decode(frame.Payload, &hello); err != nil || hello.Validate() != nil ||
		!control.VerifyHello(hello, r.keys.Session[:]) {
		return
	}
	var p *peer
	var welcome control.Welcome
	if hello.SessionID == "" {
		p, welcome, err = r.register(hello, conn)
	} else {
		p, welcome, err = r.attach(hello, conn)
	}
	if err != nil {
		_ = sendWelcome(conn, control.Welcome{Accepted: false, Error: err.Error()})
		return
	}
	defer r.detach(p, hello.Lane)
	if err := sendWelcome(conn, welcome); err != nil {
		return
	}
	if hello.SessionID == "" {
		r.logger.Info("node connected", "node", p.node, "address", p.address)
	} else {
		r.logger.Info("transport lane joined", "node", p.node, "lane", hello.Lane)
	}
	for {
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			return
		}
		if frame.Type == wire.TypeData {
			select {
			case p.incoming <- frame:
			case <-p.ctx.Done():
				return
			}
		}
	}
}

func (r *relay) register(hello control.Hello, conn multipath.Lane) (*peer, control.Welcome, error) {
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
	session := make([]byte, 16)
	_, _ = rand.Read(session)
	sessionID := base64.RawURLEncoding.EncodeToString(session)
	peerContext, cancel := context.WithCancel(context.Background())
	p := &peer{
		node: hello.Node, sessionID: sessionID, address: address, lanes: multipath.NewSet(),
		ctx: peerContext, cancel: cancel, incoming: make(chan wire.Frame, 1024), ordered: make(chan wire.Frame, 1024),
	}
	if err := p.lanes.Add(0, conn); err != nil {
		cancel()
		r.routes.RemovePeer(hello.Node)
		r.allocator.Release(hello.Node)
		return nil, control.Welcome{}, err
	}
	r.peers[hello.Node] = p
	r.sessions[sessionID] = p
	go (multipath.Reorderer{Wait: r.cfg.Transport.TLS.ReorderWait.Duration}).Run(peerContext, p.incoming, p.ordered)
	go r.routePeer(p)
	go reportTraffic(peerContext, r.logger, r.cfg.Logging.StatsInterval.Duration, "relay/"+p.node, &p.stats)
	pool := netip.MustParsePrefix(r.cfg.Overlay.Pool)
	welcome := control.Welcome{
		Accepted: true, Address: netip.PrefixFrom(address, pool.Bits()).String(),
		Routes: r.cfg.Overlay.AcceptRoutes, MTU: r.cfg.Overlay.MTU,
		SessionID: sessionID,
	}
	return p, welcome, nil
}

func (r *relay) attach(hello control.Hello, conn multipath.Lane) (*peer, control.Welcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.sessions[hello.SessionID]
	if p == nil || p.node != hello.Node {
		return nil, control.Welcome{}, errors.New("unknown transport session")
	}
	if err := p.lanes.Add(hello.Lane, conn); err != nil {
		return nil, control.Welcome{}, err
	}
	pool := netip.MustParsePrefix(r.cfg.Overlay.Pool)
	return p, control.Welcome{
		Accepted: true, Address: netip.PrefixFrom(p.address, pool.Bits()).String(),
		MTU: r.cfg.Overlay.MTU, SessionID: p.sessionID,
	}, nil
}

func (r *relay) detach(p *peer, lane int) {
	p.lanes.Remove(lane)
	if p.lanes.Len() != 0 {
		return
	}
	r.mu.Lock()
	if r.peers[p.node] != p {
		r.mu.Unlock()
		return
	}
	delete(r.peers, p.node)
	delete(r.sessions, p.sessionID)
	r.mu.Unlock()
	p.cancel()
	r.routes.RemovePeer(p.node)
	r.allocator.Release(p.node)
	r.logger.Info("node disconnected", "node", p.node)
}

func (r *relay) routePeer(p *peer) {
	for {
		select {
		case <-p.ctx.Done():
			return
		case frame := <-p.ordered:
			packet, err := overlay.ParsePacket(frame.Payload)
			if err != nil || !r.routes.AllowsSource(p.node, packet.Source) {
				p.stats.drop()
				continue
			}
			p.stats.received(len(frame.Payload))
			targetName, ok := r.routes.Lookup(packet.Target)
			if !ok || targetName == p.node {
				p.stats.drop()
				continue
			}
			r.mu.RLock()
			target := r.peers[targetName]
			r.mu.RUnlock()
			if target != nil {
				if err := target.lanes.Write(wire.Frame{Type: wire.TypeData, Payload: frame.Payload}); err != nil {
					target.stats.fail()
				} else {
					target.stats.sent(len(frame.Payload))
				}
			} else {
				p.stats.drop()
			}
		}
	}
}

func (r *relay) runQUIC(ctx context.Context) error {
	packetConn, err := net.ListenPacket("udp", r.cfg.Listen.UDP)
	if err != nil {
		return err
	}
	target, err := net.ResolveUDPAddr("udp", r.cfg.Reality.UDPTarget)
	if err != nil {
		_ = packetConn.Close()
		return err
	}
	fallback := &quicreality.UDPFallback{
		Listener: packetConn, Target: target,
		IdleTimeout: r.cfg.Reality.FallbackIdleTimeout.Duration,
		MaxMappings: r.cfg.Reality.FallbackMaxConnections,
	}
	defer fallback.Close()
	gate := &quicreality.Gate{
		PacketConn: packetConn, RouteKey: r.keys.QUICRoute[:],
		TimeWindow:       r.cfg.Reality.TimeWindow.Duration,
		AuthorizationTTL: 3 * r.cfg.Transport.QUIC.KeepAlive.Duration,
		Forwarder:        fallback,
	}
	transport := &quic.Transport{Conn: gate}
	defer transport.Close()
	options := r.h3Options()
	tlsConfig, err := quicreality.ServerTLSConfig(options)
	if err != nil {
		return err
	}
	listener, err := transport.Listen(tlsConfig, appQUICConfig(r.cfg))
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	r.logger.Info("QUIC relay listening", "address", r.cfg.Listen.UDP, "cover", r.cfg.Reality.ServerName)
	for {
		connection, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			err := quicreality.ServeH3Connection(connection, options, func(tunnel *quicreality.H3Tunnel) {
				r.handleH3(ctx, tunnel)
			})
			if err != nil && ctx.Err() == nil {
				r.logger.Debug("HTTP/3 connection closed", "error", err)
			}
		}()
	}
}

func (r *relay) handleH3(ctx context.Context, tunnel *quicreality.H3Tunnel) {
	handshakeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	encoded, err := tunnel.Receive(handshakeContext)
	if err != nil {
		return
	}
	frame, err := wire.UnmarshalFrame(encoded)
	if err != nil || frame.Type != wire.TypeClientHello {
		return
	}
	var hello control.Hello
	if err := control.Decode(frame.Payload, &hello); err != nil || hello.Validate() != nil || hello.Lane != 0 ||
		!control.VerifyHello(hello, r.keys.Session[:]) {
		return
	}
	lane := &h3WriteLane{tunnel: tunnel}
	p, welcome, err := r.register(hello, lane)
	if err != nil {
		_ = sendWelcomeH3(tunnel, control.Welcome{Accepted: false, Error: err.Error()})
		return
	}
	defer r.detach(p, 0)
	if err := sendWelcomeH3(tunnel, welcome); err != nil {
		return
	}
	r.logger.Info("node connected", "node", p.node, "address", p.address, "transport", "quic")
	for {
		encoded, err := tunnel.Receive(p.ctx)
		if err != nil {
			return
		}
		frame, err := wire.UnmarshalFrame(encoded)
		if err == nil && frame.Type == wire.TypeData {
			select {
			case p.incoming <- frame:
			case <-p.ctx.Done():
				return
			}
		}
	}
}

func (r *relay) h3Options() quicreality.H3Options {
	return quicreality.H3Options{
		ServerName: r.cfg.Reality.ServerName, Keys: r.keys,
		TimeWindow:        r.cfg.Reality.TimeWindow.Duration,
		KeepAlive:         r.cfg.Transport.QUIC.KeepAlive.Duration,
		IdleTimeout:       r.cfg.Transport.QUIC.IdleTimeout.Duration,
		InitialPacketSize: r.cfg.Transport.QUIC.InitialPacketSize,
		DisablePMTU:       !r.cfg.Transport.QUIC.PathMTUDiscovery,
	}
}

type h3WriteLane struct {
	tunnel *quicreality.H3Tunnel
	closed atomic.Bool
}

func (l *h3WriteLane) Read([]byte) (int, error) {
	return 0, errors.New("HTTP/3 lane does not expose stream reads")
}

func (l *h3WriteLane) Write(data []byte) (int, error) {
	if l.closed.Load() {
		return 0, net.ErrClosed
	}
	if err := l.tunnel.Send(data); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (l *h3WriteLane) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	return l.tunnel.Close()
}

func sendWelcomeH3(tunnel *quicreality.H3Tunnel, welcome control.Welcome) error {
	payload, err := control.Encode(welcome)
	if err != nil {
		return err
	}
	encoded, err := (wire.Frame{Type: wire.TypeServerHello, Payload: payload}).MarshalBinary()
	if err != nil {
		return err
	}
	return tunnel.Send(encoded)
}

func appQUICConfig(cfg *config.Config) *quic.Config {
	return &quic.Config{
		EnableDatagrams:         true,
		KeepAlivePeriod:         cfg.Transport.QUIC.KeepAlive.Duration,
		MaxIdleTimeout:          cfg.Transport.QUIC.IdleTimeout.Duration,
		InitialPacketSize:       cfg.Transport.QUIC.InitialPacketSize,
		DisablePathMTUDiscovery: !cfg.Transport.QUIC.PathMTUDiscovery,
	}
}

func sendWelcome(conn net.Conn, welcome control.Welcome) error {
	payload, err := control.Encode(welcome)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, wire.Frame{Type: wire.TypeServerHello, Payload: payload})
}

func runNodeH3(ctx context.Context, cfg *config.Config, keys *auth.Keys, logger *slog.Logger) error {
	packetConn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return err
	}
	server, err := net.ResolveUDPAddr("udp", cfg.Server.Address)
	if err != nil {
		_ = packetConn.Close()
		return err
	}
	options := quicreality.H3Options{
		ServerName: cfg.Reality.ServerName, Keys: keys,
		TimeWindow:        cfg.Reality.TimeWindow.Duration,
		KeepAlive:         cfg.Transport.QUIC.KeepAlive.Duration,
		IdleTimeout:       cfg.Transport.QUIC.IdleTimeout.Duration,
		InitialPacketSize: cfg.Transport.QUIC.InitialPacketSize,
		DisablePMTU:       !cfg.Transport.QUIC.PathMTUDiscovery,
	}
	tunnel, err := quicreality.DialH3(ctx, packetConn, server, options)
	if err != nil {
		_ = packetConn.Close()
		return err
	}
	defer tunnel.Close()
	hello := control.Hello{
		Node: cfg.Node.Name, Role: cfg.Node.Role, RequestedAddress: cfg.Overlay.Address,
		AdvertiseRoutes: cfg.Overlay.AdvertiseRoutes, Lane: 0,
	}
	if err := control.SignHello(&hello, keys.Session[:]); err != nil {
		return err
	}
	payload, err := control.Encode(hello)
	if err != nil {
		return err
	}
	encoded, err := (wire.Frame{Type: wire.TypeClientHello, Payload: payload}).MarshalBinary()
	if err != nil {
		return err
	}
	if err := tunnel.Send(encoded); err != nil {
		return err
	}
	encoded, err = tunnel.Receive(ctx)
	if err != nil {
		return err
	}
	frame, err := wire.UnmarshalFrame(encoded)
	if err != nil || frame.Type != wire.TypeServerHello {
		return errors.New("invalid QUIC relay welcome")
	}
	var welcome control.Welcome
	if err := control.Decode(frame.Payload, &welcome); err != nil {
		return err
	}
	if !welcome.Accepted {
		return errors.New(welcome.Error)
	}
	device, cleanup, err := openNodeDevice(cfg, welcome, logger)
	if err != nil {
		return err
	}
	defer device.Close()
	defer cleanup()
	logger.Info("overlay ready", "interface", device.Name(), "address", welcome.Address, "transport", "quic-h3")

	nodeContext, cancel := context.WithCancel(ctx)
	defer cancel()
	incoming := make(chan wire.Frame, 1024)
	ordered := make(chan wire.Frame, 1024)
	failures := make(chan error, 1)
	stats := &trafficStats{}
	go reportTraffic(nodeContext, logger, cfg.Logging.StatsInterval.Duration, "node/"+cfg.Node.Name, stats)
	go (multipath.Reorderer{Wait: cfg.Transport.TLS.ReorderWait.Duration}).Run(nodeContext, incoming, ordered)
	go func() {
		for {
			encoded, err := tunnel.Receive(nodeContext)
			if err != nil {
				reportFailure(failures, err)
				return
			}
			frame, err := wire.UnmarshalFrame(encoded)
			if err == nil && frame.Type == wire.TypeData {
				select {
				case incoming <- frame:
				case <-nodeContext.Done():
					return
				}
			}
		}
	}()
	var sequence atomic.Uint64
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, err := device.Read(buffer)
			if err != nil {
				stats.fail()
				reportFailure(failures, err)
				return
			}
			frame := wire.Frame{Type: wire.TypeData, Sequence: sequence.Add(1), Payload: append([]byte(nil), buffer[:n]...)}
			encoded, err := frame.MarshalBinary()
			if err == nil {
				err = tunnel.Send(encoded)
			}
			if err != nil {
				stats.fail()
				reportFailure(failures, err)
				return
			}
			stats.sent(n)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failures:
			return err
		case frame := <-ordered:
			if _, err := device.Write(frame.Payload); err != nil {
				stats.fail()
				return err
			}
			stats.received(len(frame.Payload))
		}
	}
}

func openNodeDevice(cfg *config.Config, welcome control.Welcome, logger *slog.Logger) (tun.Device, func(), error) {
	device, err := tun.Open(tun.Config{
		Name: cfg.Overlay.Name, Address: welcome.Address, MTU: welcome.MTU, Routes: cfg.Overlay.AcceptRoutes,
	})
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {}
	if cfg.Node.Role == "gateway" && cfg.Gateway.NAT {
		assigned := netip.MustParsePrefix(welcome.Address).Masked()
		cleanup, err = tun.EnableGatewayNAT(cfg.Gateway.LANInterface, assigned.String())
		if err != nil {
			_ = device.Close()
			return nil, nil, err
		}
		logger.Info("gateway NAT enabled", "lan_interface", cfg.Gateway.LANInterface, "source", assigned)
	}
	return device, cleanup, nil
}

func runNode(ctx context.Context, cfg *config.Config, keys *auth.Keys, logger *slog.Logger) error {
	hello := control.Hello{
		Node: cfg.Node.Name, Role: cfg.Node.Role, RequestedAddress: cfg.Overlay.Address,
		AdvertiseRoutes: cfg.Overlay.AdvertiseRoutes, Lane: 0,
	}
	primary, welcome, err := dialLane(ctx, cfg, keys, hello)
	if err != nil {
		return err
	}
	lanes := multipath.NewSet()
	defer lanes.Close()
	if err := lanes.Add(0, primary); err != nil {
		return err
	}
	connections := map[int]net.Conn{0: primary}
	for lane := 1; lane < cfg.Transport.TLS.Lanes; lane++ {
		laneHello := hello
		laneHello.Lane = lane
		laneHello.SessionID = welcome.SessionID
		conn, _, err := dialLane(ctx, cfg, keys, laneHello)
		if err != nil {
			logger.Warn("transport lane failed to join", "lane", lane, "error", err)
			continue
		}
		if err := lanes.Add(lane, conn); err != nil {
			_ = conn.Close()
			continue
		}
		connections[lane] = conn
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
	logger.Info("overlay ready", "interface", device.Name(), "address", welcome.Address, "transport", "tls-multipath", "lanes", lanes.Len())

	nodeContext, cancel := context.WithCancel(ctx)
	defer cancel()
	incoming := make(chan wire.Frame, 1024)
	ordered := make(chan wire.Frame, 1024)
	failures := make(chan error, 1)
	stats := &trafficStats{}
	go reportTraffic(nodeContext, logger, cfg.Logging.StatsInterval.Duration, "node/"+cfg.Node.Name, stats)
	go (multipath.Reorderer{Wait: cfg.Transport.TLS.ReorderWait.Duration}).Run(nodeContext, incoming, ordered)
	for id, conn := range connections {
		go maintainLane(nodeContext, id, conn, cfg, keys, hello, welcome.SessionID, lanes, incoming, failures, logger)
	}
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, err := device.Read(buffer)
			if err != nil {
				stats.fail()
				reportFailure(failures, err)
				return
			}
			packet := append([]byte(nil), buffer[:n]...)
			if err := lanes.Write(wire.Frame{Type: wire.TypeData, Payload: packet}); err != nil {
				stats.fail()
				reportFailure(failures, err)
				return
			}
			stats.sent(n)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failures:
			return err
		case frame := <-ordered:
			if _, err := device.Write(frame.Payload); err != nil {
				stats.fail()
				return err
			}
			stats.received(len(frame.Payload))
		}
	}
}

func dialLane(ctx context.Context, cfg *config.Config, keys *auth.Keys, hello control.Hello) (net.Conn, control.Welcome, error) {
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", cfg.Server.Address)
	if err != nil {
		return nil, control.Welcome{}, err
	}
	tuneTCP(raw, cfg.Transport.TLS.KeepAlive.Duration, cfg.Transport.TLS.TCPUserTimeout.Duration)
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
	if err := control.SignHello(&hello, keys.Session[:]); err != nil {
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

func maintainLane(
	ctx context.Context, id int, conn net.Conn, cfg *config.Config, keys *auth.Keys,
	baseHello control.Hello, sessionID string, lanes *multipath.Set, output chan<- wire.Frame,
	failures chan<- error, logger *slog.Logger,
) {
	backoff := time.Second
	for {
		for {
			frame, err := wire.ReadFrame(conn)
			if err != nil {
				break
			}
			if frame.Type == wire.TypeData {
				select {
				case output <- frame:
				case <-ctx.Done():
					return
				}
			}
		}
		lanes.Remove(id)
		if ctx.Err() != nil {
			return
		}
		if lanes.Len() == 0 {
			reportFailure(failures, multipath.ErrNoHealthyLane)
			return
		}
		logger.Warn("transport lane disconnected; repairing", "lane", id, "after", backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		hello := baseHello
		hello.Lane = id
		hello.SessionID = sessionID
		replacement, _, err := dialLane(ctx, cfg, keys, hello)
		if err != nil {
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		if err := lanes.Add(id, replacement); err != nil {
			_ = replacement.Close()
			continue
		}
		conn = replacement
		backoff = time.Second
		logger.Info("transport lane restored", "lane", id)
	}
}

func reportFailure(target chan<- error, err error) {
	select {
	case target <- err:
	default:
	}
}

func tuneTCP(conn net.Conn, keepAlive, userTimeout time.Duration) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if keepAlive <= 0 {
		keepAlive = 20 * time.Second
	}
	interval := keepAlive / 3
	if interval < time.Second {
		interval = time.Second
	}
	_ = tcp.SetNoDelay(true)
	_ = tcp.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable: true, Idle: keepAlive, Interval: interval, Count: 3,
	})
	_ = setTCPUserTimeout(tcp, userTimeout)
}
