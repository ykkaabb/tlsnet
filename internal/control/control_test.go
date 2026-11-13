package control

import (
	"net/netip"
	"strings"
	"testing"
)

func TestStrictMessageDecode(t *testing.T) {
	var hello Hello
	data := []byte("{\"node\":\"home\",\"role\":\"gateway\",\"lane\":0,\"extra\":true}")
	if err := Decode(data, &hello); err == nil {
		t.Fatal("accepted unknown control field")
	}
	encoded, err := Encode(Hello{Node: "home", Role: "gateway", Lane: 0, AdvertiseRoutes: []string{"192.168.3.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := Decode(encoded, &hello); err != nil {
		t.Fatal(err)
	}
	if err := hello.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestHelloAuthenticationCoversControlFields(t *testing.T) {
	key := []byte("test-session-key")
	hello := Hello{Node: "home", Role: "gateway", Lane: 0, AdvertiseRoutes: []string{"192.168.3.0/24"}}
	if err := SignHello(&hello, key); err != nil {
		t.Fatal(err)
	}
	if !VerifyHello(hello, key) {
		t.Fatal("signed hello did not verify")
	}
	hello.AdvertiseRoutes[0] = "0.0.0.0/0"
	if VerifyHello(hello, key) {
		t.Fatal("modified hello retained valid authentication")
	}
}

func TestAllocatorReservationAndReuse(t *testing.T) {
	pool := netip.MustParsePrefix("10.91.0.0/29")
	relay := netip.MustParseAddr("10.91.0.1")
	allocator, err := NewAllocator(pool, relay)
	if err != nil {
		t.Fatal(err)
	}
	first, err := allocator.Allocate("first", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if first.String() != "10.91.0.2" {
		t.Fatalf("allocated %s", first)
	}
	if _, err := allocator.Allocate("second", first); err == nil || !strings.Contains(err.Error(), "used") {
		t.Fatalf("unexpected conflict result: %v", err)
	}
	allocator.Release("first")
	second, err := allocator.Allocate("second", first)
	if err != nil || second != first {
		t.Fatalf("address was not reusable: %s, %v", second, err)
	}
}

func TestAllocatorHandlesLargePoolWithoutScanningIt(t *testing.T) {
	allocator, err := NewAllocator(netip.MustParsePrefix("10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}
	address, err := allocator.Allocate("first", netip.Addr{})
	if err != nil || address.String() != "10.0.0.1" {
		t.Fatalf("address=%s err=%v", address, err)
	}
}
