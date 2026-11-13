package app

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ykkaabb/tlsnet/internal/config"
	"github.com/ykkaabb/tlsnet/internal/control"
	"github.com/ykkaabb/tlsnet/internal/overlay"
)

func testRelay(t *testing.T) *relay {
	t.Helper()
	pool := netip.MustParsePrefix("10.91.0.0/24")
	allocator, err := control.NewAllocator(pool, netip.MustParseAddr("10.91.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	return &relay{
		cfg: &config.Config{
			Overlay: config.Overlay{Pool: pool.String(), MTU: 1280},
			Relay: config.Relay{AllowedRoutes: map[string][]string{
				"home": {"192.168.3.0/24"},
			}},
			Transport: config.Transport{TLS: config.TLSTransport{ReorderWait: config.Duration{Duration: time.Millisecond}}},
		},
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		allocator: allocator,
		routes:    overlay.NewRouteTable(),
		peers:     make(map[string]*peer),
		sessions:  make(map[string]*peer),
	}
}

func TestRelayKeepsSessionUntilLastLaneLeaves(t *testing.T) {
	hub := testRelay(t)
	server0, client0 := net.Pipe()
	defer client0.Close()
	p, welcome, err := hub.register(control.Hello{
		Node: "home", Role: "gateway", RequestedAddress: "10.91.0.2/24",
		AdvertiseRoutes: []string{"192.168.3.0/24"},
	}, server0)
	if err != nil {
		t.Fatal(err)
	}
	server1, client1 := net.Pipe()
	defer client1.Close()
	attached, _, err := hub.attach(control.Hello{
		Node: "home", Role: "gateway", Lane: 1, SessionID: welcome.SessionID,
	}, server1)
	if err != nil {
		t.Fatal(err)
	}
	if attached != p || p.lanes.Len() != 2 {
		t.Fatal("second lane did not join session")
	}
	hub.detach(p, 0)
	if p.lanes.Len() != 1 || hub.peers["home"] != p {
		t.Fatal("session was removed with a healthy lane remaining")
	}
	hub.detach(p, 1)
	if hub.peers["home"] != nil || hub.sessions[welcome.SessionID] != nil {
		t.Fatal("empty session was not removed")
	}
}

func TestRelayRejectsUnauthorizedAdvertisedRoute(t *testing.T) {
	hub := testRelay(t)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_, _, err := hub.register(control.Hello{
		Node: "home", Role: "gateway", AdvertiseRoutes: []string{"0.0.0.0/0"},
	}, server)
	if err == nil {
		t.Fatal("unauthorized route was accepted")
	}
}
