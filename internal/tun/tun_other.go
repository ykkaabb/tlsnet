//go:build !linux

package tun

import "errors"

func Open(Config) (Device, error) {
	return nil, errors.New("TUN runtime is currently implemented on Linux only")
}

func enableGatewayNAT(string, string) (func(), error) {
	return nil, errors.New("gateway NAT is currently implemented on Linux only")
}
