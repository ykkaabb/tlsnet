//go:build linux

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTun    = 0x0001
	iffNoPI   = 0x1000
)

type ifReq struct {
	Name    [16]byte
	Flags   uint16
	Padding [22]byte
}

type device struct {
	*os.File
	name string
}

func Open(config Config) (Device, error) {
	if len(config.Name) == 0 || len(config.Name) >= 16 {
		return nil, fmt.Errorf("invalid TUN interface name %q", config.Name)
	}
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var request ifReq
	copy(request.Name[:], config.Name)
	request.Flags = iffTun | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&request)))
	if errno != 0 {
		_ = file.Close()
		return nil, errno
	}
	if err := configure(config); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &device{File: file, name: config.Name}, nil
}

func (d *device) Name() string { return d.name }

func configure(config Config) error {
	commands := [][]string{
		{"link", "set", "dev", config.Name, "mtu", fmt.Sprint(config.MTU)},
		{"addr", "replace", config.Address, "dev", config.Name},
		{"link", "set", "dev", config.Name, "up"},
	}
	for _, route := range config.Routes {
		commands = append(commands, []string{"route", "replace", route, "dev", config.Name})
	}
	for _, arguments := range commands {
		output, err := exec.Command("ip", arguments...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ip %v: %w: %s", arguments, err, output)
		}
	}
	return nil
}

func enableGatewayNAT(lanInterface, overlayPrefix string) (func(), error) {
	if output, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("enable IPv4 forwarding: %w: %s", err, output)
	}
	rule := []string{"-t", "nat", "-C", "POSTROUTING", "-s", overlayPrefix, "-o", lanInterface, "-j", "MASQUERADE"}
	if err := exec.Command("iptables", rule...).Run(); err == nil {
		return func() {}, nil
	}
	add := append([]string{"-t", "nat", "-A", "POSTROUTING"}, rule[4:]...)
	if output, err := exec.Command("iptables", add...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("add gateway NAT rule: %w: %s", err, output)
	}
	return func() {
		remove := append([]string{"-t", "nat", "-D", "POSTROUTING"}, rule[4:]...)
		_ = exec.Command("iptables", remove...).Run()
	}, nil
}
