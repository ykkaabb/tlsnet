package enroll

import (
	"errors"
	"net/netip"
	"time"

	"github.com/ykkaabb/tlsnet/internal/config"
)

func Build(role, node, password, lanInterface string, code JoinCode) (*config.Config, error) {
	if role != "relay" && role != "gateway" && role != "client" {
		return nil, errors.New("role must be relay, gateway, or client")
	}
	if err := code.Validate(); err != nil {
		return nil, err
	}
	pool := netip.MustParsePrefix(code.OverlayPool).Masked()
	homeSubnet := netip.MustParsePrefix(code.HomeSubnet).Masked().String()
	relayAddress := pool.Addr().Next()
	gatewayAddress := relayAddress.Next()
	cfg := &config.Config{
		ConfigVersion: config.CurrentVersion,
		Node:          config.Node{Role: role, Name: node},
		Auth: config.Auth{
			NetworkName: code.NetworkName, Password: password, KDF: "argon2id",
			KDFMemoryMiB: 64, KDFIterations: 3, KDFParallelism: 2,
		},
		Reality: config.Reality{
			ServerName: code.ServerName, TCPTarget: code.ServerName + ":443", UDPTarget: code.ServerName + ":443",
			TimeWindow: config.Duration{Duration: time.Minute}, FallbackMaxPerIP: 4,
			FallbackMaxConnections: 128, FallbackIdleTimeout: config.Duration{Duration: 15 * time.Second},
			FallbackMaxLifetime: config.Duration{Duration: 2 * time.Minute},
		},
		Transport: config.Transport{
			Mode: "auto",
			QUIC: config.QUICTransport{
				Enabled: true, Reality: true, ALPN: "h3", KeepAlive: config.Duration{Duration: 15 * time.Second},
				IdleTimeout: config.Duration{Duration: time.Minute}, InitialPacketSize: 1200, PathMTUDiscovery: true,
			},
			TLS: config.TLSTransport{
				Enabled: true, Reality: true, Lanes: 4, ReorderWait: config.Duration{Duration: 5 * time.Millisecond},
				KeepAlive: config.Duration{Duration: 20 * time.Second}, TCPUserTimeout: config.Duration{Duration: 30 * time.Second},
			},
		},
		Overlay: config.Overlay{Name: "tlsnet0", Pool: pool.String(), MTU: 1280},
		Logging: config.Logging{Level: "info", StatsInterval: config.Duration{Duration: 10 * time.Second}},
	}
	switch role {
	case "relay":
		cfg.Listen = config.Listen{TCP: ":" + portOf(code.ServerAddress), UDP: ":" + portOf(code.ServerAddress)}
		cfg.Relay.AllowedRoutes = map[string][]string{code.HomeNode: {homeSubnet}}
		cfg.Overlay.Address = netip.PrefixFrom(relayAddress, pool.Bits()).String()
	case "gateway":
		cfg.Server.Address = code.ServerAddress
		cfg.Overlay.Address = netip.PrefixFrom(gatewayAddress, pool.Bits()).String()
		cfg.Overlay.AdvertiseRoutes = []string{homeSubnet}
		cfg.Gateway = config.Gateway{NAT: true, LANInterface: lanInterface}
	case "client":
		cfg.Server.Address = code.ServerAddress
		cfg.Overlay.Address = "auto"
		cfg.Overlay.AcceptRoutes = []string{pool.String(), homeSubnet}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func portOf(address string) string {
	for index := len(address) - 1; index >= 0; index-- {
		if address[index] == ':' {
			return address[index+1:]
		}
	}
	return "443"
}
