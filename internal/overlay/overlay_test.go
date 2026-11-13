package overlay

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 91, 0, 2})
	copy(packet[16:20], []byte{192, 168, 3, 200})
	got, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source.String() != "10.91.0.2" || got.Target.String() != "192.168.3.200" {
		t.Fatalf("unexpected packet metadata: %+v", got)
	}
}

func TestParseIPv6(t *testing.T) {
	packet := make([]byte, 40)
	packet[0] = 0x60
	source := netip.MustParseAddr("fd00::2").As16()
	target := netip.MustParseAddr("fd00::1").As16()
	copy(packet[8:24], source[:])
	copy(packet[24:40], target[:])
	got, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source.String() != "fd00::2" || got.Target.String() != "fd00::1" {
		t.Fatalf("unexpected packet metadata: %+v", got)
	}
}

func TestRouteTableLongestPrefixAndSourceValidation(t *testing.T) {
	table := NewRouteTable()
	if err := table.AddBatch("gateway", []netip.Prefix{netip.MustParsePrefix("192.168.3.0/24")}); err != nil {
		t.Fatal(err)
	}
	if err := table.AddBatch("host", []netip.Prefix{netip.MustParsePrefix("192.168.3.200/32")}); err != nil {
		t.Fatal(err)
	}
	peer, ok := table.Lookup(netip.MustParseAddr("192.168.3.200"))
	if !ok || peer != "host" {
		t.Fatalf("lookup returned %q, %v", peer, ok)
	}
	peer, ok = table.Lookup(netip.MustParseAddr("192.168.3.42"))
	if !ok || peer != "gateway" {
		t.Fatalf("lookup returned %q, %v", peer, ok)
	}
	if !table.AllowsSource("gateway", netip.MustParseAddr("192.168.3.42")) {
		t.Fatal("gateway source was rejected")
	}
	if table.AllowsSource("host", netip.MustParseAddr("192.168.3.42")) {
		t.Fatal("spoofed host source was accepted")
	}
}

func TestRouteBatchIsAtomic(t *testing.T) {
	table := NewRouteTable()
	occupied := netip.MustParsePrefix("10.91.0.2/32")
	newRoute := netip.MustParsePrefix("10.91.0.3/32")
	if err := table.AddBatch("first", []netip.Prefix{occupied}); err != nil {
		t.Fatal(err)
	}
	if err := table.AddBatch("second", []netip.Prefix{newRoute, occupied}); err == nil {
		t.Fatal("accepted conflicting batch")
	}
	if peer, ok := table.Lookup(newRoute.Addr()); ok || peer != "" {
		t.Fatal("part of rejected batch was installed")
	}
}
