//go:build windows

package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type windowsDevice struct {
	device wgtun.Device
	name   string
}

func Open(config Config) (Device, error) {
	if config.Name == "" {
		return nil, errors.New("TUN interface name is required")
	}
	device, err := wgtun.CreateTUN(config.Name, config.MTU)
	if err != nil {
		return nil, fmt.Errorf("create Wintun adapter (run elevated and place wintun.dll beside tlsnet.exe): %w", err)
	}
	if err := configureWindows(config); err != nil {
		_ = device.Close()
		return nil, err
	}
	return &windowsDevice{device: device, name: config.Name}, nil
}

func (d *windowsDevice) Read(dst []byte) (int, error) {
	buffers := [][]byte{dst}
	sizes := make([]int, 1)
	count, err := d.device.Read(buffers, sizes, 0)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func (d *windowsDevice) Write(src []byte) (int, error) {
	count, err := d.device.Write([][]byte{src}, 0)
	if err != nil {
		return 0, err
	}
	if count != 1 {
		return 0, errors.New("Wintun did not accept packet")
	}
	return len(src), nil
}

func (d *windowsDevice) Close() error { return d.device.Close() }
func (d *windowsDevice) Name() string { return d.name }

func configureWindows(config Config) error {
	address, err := netip.ParsePrefix(config.Address)
	if err != nil || !address.Addr().Is4() {
		return errors.New("Windows TUN address must be an IPv4 prefix")
	}
	mask := prefixMask(address.Bits())
	commands := [][]string{
		{"interface", "ipv4", "set", "address", "name=" + config.Name, "source=static",
			"address=" + address.Addr().String(), "mask=" + mask, "gateway=none", "store=active"},
		{"interface", "ipv4", "set", "subinterface", config.Name,
			fmt.Sprintf("mtu=%d", config.MTU), "store=active"},
	}
	for _, route := range config.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("invalid Windows route %q", route)
		}
		_ = exec.Command(
			"netsh", "interface", "ipv4", "delete", "route",
			prefix.Masked().String(), config.Name, "store=active",
		).Run()
		commands = append(commands, []string{
			"interface", "ipv4", "add", "route", prefix.Masked().String(), config.Name,
			"nexthop=0.0.0.0", "store=active",
		})
	}
	for _, arguments := range commands {
		output, err := exec.Command("netsh", arguments...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh %v: %w: %s", arguments, err, output)
		}
	}
	return nil
}

func enableGatewayNAT(string, string) (func(), error) {
	return nil, errors.New("gateway NAT is currently implemented on Linux only")
}
