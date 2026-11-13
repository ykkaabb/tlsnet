package tun

import "testing"

func TestPrefixMask(t *testing.T) {
	for bits, want := range map[int]string{
		0: "0.0.0.0", 8: "255.0.0.0", 24: "255.255.255.0", 32: "255.255.255.255",
	} {
		if got := prefixMask(bits); got != want {
			t.Fatalf("/%d mask=%s, want %s", bits, got, want)
		}
	}
}
