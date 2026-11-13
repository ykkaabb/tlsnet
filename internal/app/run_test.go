package app

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ykkaabb/tlsnet/internal/config"
	"github.com/ykkaabb/tlsnet/internal/control"
	"github.com/ykkaabb/tlsnet/internal/overlay"
	"github.com/ykkaabb/tlsnet/internal/wire"
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

type fakeRelayDevice struct {
	reads  chan []byte
	writes chan []byte
	closed chan struct{}
}

func newFakeRelayDevice() *fakeRelayDevice {
	return &fakeRelayDevice{reads: make(chan []byte, 1), writes: make(chan []byte, 1), closed: make(chan struct{})}
}

func (d *fakeRelayDevice) Read(dst []byte) (int, error) {
	select {
	case packet := <-d.reads:
		return copy(dst, packet), nil
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *fakeRelayDevice) Write(src []byte) (int, error) {
	packet := append([]byte(nil), src...)
	select {
	case d.writes <- packet:
		return len(src), nil
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *fakeRelayDevice) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

func (d *fakeRelayDevice) Name() string { return "fake0" }

func ipv4Packet(source, target string) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	sourceBytes := netip.MustParseAddr(source).As4()
	targetBytes := netip.MustParseAddr(target).As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], targetBytes[:])
	return packet
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

func TestRelayVirtualAddressParticipatesInOverlay(t *testing.T) {
	hub := testRelay(t)
	device := newFakeRelayDevice()
	defer device.Close()
	hub.device = device
	hub.address = netip.MustParseAddr("10.91.0.1")
	server, client := net.Pipe()
	defer client.Close()
	peer, _, err := hub.register(control.Hello{
		Node: "home", Role: "gateway", RequestedAddress: "10.91.0.2/24",
		AdvertiseRoutes: []string{"192.168.3.0/24"},
	}, server)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.detach(peer, 0)

	peer.incoming <- wire.Frame{
		Type: wire.TypeData, Sequence: 1, Payload: ipv4Packet("10.91.0.2", "10.91.0.1"),
	}
	select {
	case packet := <-device.writes:
		if target := netip.AddrFrom4([4]byte(packet[16:20])); target != hub.address {
			t.Fatalf("target=%s", target)
		}
	case <-time.After(time.Second):
		t.Fatal("peer packet was not injected into relay TUN")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.routeLocal(ctx)
	device.reads <- ipv4Packet("10.91.0.1", "10.91.0.2")
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	frame, err := wire.ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != wire.TypeData {
		t.Fatalf("frame type=%d", frame.Type)
	}
}
