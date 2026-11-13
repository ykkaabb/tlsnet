package tun

import "io"

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
