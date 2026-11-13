package quicreality

import (
	"errors"
	"net"
	"sync"
	"time"
)

type PacketForwarder interface {
	Forward(packet []byte, source net.Addr)
}

type Gate struct {
	net.PacketConn
	RouteKey         []byte
	TimeWindow       time.Duration
	AuthorizationTTL time.Duration
	Forwarder        PacketForwarder
	Now              func() time.Time

	mu         sync.Mutex
	authorized map[string]time.Time
}

func (g *Gate) ReadFrom(buffer []byte) (int, net.Addr, error) {
	if g.PacketConn == nil {
		return 0, nil, errors.New("QUIC gate has no packet connection")
	}
	for {
		n, source, err := g.PacketConn.ReadFrom(buffer)
		if err != nil {
			return 0, nil, err
		}
		now := time.Now()
		if g.Now != nil {
			now = g.Now()
		}
		if g.isAuthorized(source, now) {
			g.authorize(source, now)
			return n, source, nil
		}
		if VerifyProbe(buffer[:n], g.RouteKey, now, g.TimeWindow) {
			g.authorize(source, now)
			continue
		}
		if g.Forwarder != nil {
			packet := append([]byte(nil), buffer[:n]...)
			g.Forwarder.Forward(packet, source)
		}
	}
}

func (g *Gate) authorize(source net.Addr, now time.Time) {
	ttl := g.AuthorizationTTL
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	key := source.String()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.authorized == nil {
		g.authorized = make(map[string]time.Time)
	}
	g.authorized[key] = now.Add(ttl)
	if len(g.authorized) > 1024 {
		for endpoint, expires := range g.authorized {
			if !expires.After(now) {
				delete(g.authorized, endpoint)
			}
		}
	}
}

func (g *Gate) isAuthorized(source net.Addr, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	expires, ok := g.authorized[source.String()]
	if ok && !expires.After(now) {
		delete(g.authorized, source.String())
		return false
	}
	return ok
}
