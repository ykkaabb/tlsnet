package quicreality

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ykkaabb/tlsnet/internal/auth"
)

func quicKey(t *testing.T, password string) []byte {
	t.Helper()
	keys, err := auth.Derive(password, "testnet", "www.speedtest.cn", auth.KDFParams{MemoryMiB: 1, Iterations: 1, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	return keys.QUICRoute[:]
}

func TestProbeLooksLikeQUICInitialAndVerifies(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	key := quicKey(t, "password")
	packet, err := NewProbe(key, now, time.Minute, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != ProbeSize || packet[0]&0xc0 != 0xc0 {
		t.Fatalf("invalid probe shape: length=%d first=%02x", len(packet), packet[0])
	}
	if !VerifyProbe(packet, key, now, time.Minute) {
		t.Fatal("valid probe was rejected")
	}
	if VerifyProbe(packet, quicKey(t, "wrong password"), now, time.Minute) {
		t.Fatal("probe verified with wrong password")
	}
}

func TestProbeRejectsMalformedPackets(t *testing.T) {
	key := quicKey(t, "password")
	now := time.Unix(1_800_000_000, 0)
	for _, packet := range [][]byte{nil, {0xc0}, bytes.Repeat([]byte{0xff}, 64)} {
		if VerifyProbe(packet, key, now, time.Minute) {
			t.Fatalf("accepted malformed packet %x", packet)
		}
	}
}

func TestGateDropsProbeThenPassesAuthorizedEndpoint(t *testing.T) {
	key := quicKey(t, "password")
	now := time.Unix(1_800_000_000, 0)
	probe, err := NewProbe(key, now, time.Minute, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345}
	conn := &packetQueue{packets: make(chan queuedPacket, 2)}
	conn.packets <- queuedPacket{data: probe, source: source}
	conn.packets <- queuedPacket{data: []byte("real QUIC packet"), source: source}
	gate := &Gate{
		PacketConn:       conn,
		RouteKey:         key,
		TimeWindow:       time.Minute,
		AuthorizationTTL: 10 * time.Second,
		Now:              func() time.Time { return now },
	}
	buffer := make([]byte, ProbeSize)
	n, gotSource, err := gate.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "real QUIC packet" || gotSource.String() != source.String() {
		t.Fatalf("unexpected packet %q from %v", buffer[:n], gotSource)
	}
}

type queuedPacket struct {
	data   []byte
	source net.Addr
}

type packetQueue struct {
	packets chan queuedPacket
}

func (p *packetQueue) ReadFrom(dst []byte) (int, net.Addr, error) {
	packet, ok := <-p.packets
	if !ok {
		return 0, nil, errors.New("closed")
	}
	return copy(dst, packet.data), packet.source, nil
}

func (p *packetQueue) WriteTo(data []byte, target net.Addr) (int, error) {
	return len(data), nil
}

func (p *packetQueue) Close() error                     { close(p.packets); return nil }
func (p *packetQueue) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (p *packetQueue) SetDeadline(time.Time) error      { return nil }
func (p *packetQueue) SetReadDeadline(time.Time) error  { return nil }
func (p *packetQueue) SetWriteDeadline(time.Time) error { return nil }
