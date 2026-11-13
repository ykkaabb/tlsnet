package tun

import (
	"io"
	"net/netip"
)

type Config struct {
	Name    string
	Address string
	MTU     int
	Routes  []string
}

type Device interface {
	io.ReadWriteCloser
	Name() string
}

func EnableGatewayNAT(lanInterface, overlayPrefix string) (func(), error) {
	return enableGatewayNAT(lanInterface, overlayPrefix)
}

func prefixMask(bits int) string {
	var bytes [4]byte
	for index := 0; index < bits; index++ {
		bytes[index/8] |= 1 << (7 - index%8)
	}
	return netip.AddrFrom4(bytes).String()
}
