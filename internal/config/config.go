package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const CurrentVersion = 1

type Config struct {
	ConfigVersion int       `toml:"config_version"`
	Node          Node      `toml:"node"`
	Auth          Auth      `toml:"auth"`
	Listen        Listen    `toml:"listen"`
	Server        Server    `toml:"server"`
	Relay         Relay     `toml:"relay"`
	Reality       Reality   `toml:"reality"`
	Transport     Transport `toml:"transport"`
	Overlay       Overlay   `toml:"overlay"`
	Gateway       Gateway   `toml:"gateway"`
	Logging       Logging   `toml:"logging"`
}

type Node struct {
	Role string `toml:"role"`
	Name string `toml:"name"`
}

type Auth struct {
	NetworkName    string `toml:"network_name"`
	Password       string `toml:"password"`
	KDF            string `toml:"kdf"`
	KDFMemoryMiB   uint32 `toml:"kdf_memory_mib"`
	KDFIterations  uint32 `toml:"kdf_iterations"`
	KDFParallelism uint8  `toml:"kdf_parallelism"`
}

type Listen struct {
	TCP string `toml:"tcp"`
	UDP string `toml:"udp"`
}

type Server struct {
	Address string `toml:"address"`
}

type Relay struct {
	AllowedRoutes map[string][]string `toml:"allowed_routes"`
}

type Reality struct {
	ServerName             string   `toml:"server_name"`
	TCPTarget              string   `toml:"tcp_target"`
	UDPTarget              string   `toml:"udp_target"`
	TimeWindow             Duration `toml:"time_window"`
	FallbackMaxPerIP       int      `toml:"fallback_max_connections_per_ip"`
	FallbackMaxConnections int      `toml:"fallback_max_connections"`
	FallbackIdleTimeout    Duration `toml:"fallback_idle_timeout"`
	FallbackMaxLifetime    Duration `toml:"fallback_max_lifetime"`
}

type Transport struct {
	Mode string        `toml:"mode"`
	QUIC QUICTransport `toml:"quic"`
	TLS  TLSTransport  `toml:"tls"`
}

type QUICTransport struct {
	Enabled           bool     `toml:"enabled"`
	Reality           bool     `toml:"reality"`
	ALPN              string   `toml:"alpn"`
	KeepAlive         Duration `toml:"keepalive"`
	IdleTimeout       Duration `toml:"idle_timeout"`
	InitialPacketSize uint16   `toml:"initial_packet_size"`
	PathMTUDiscovery  bool     `toml:"path_mtu_discovery"`
}

type TLSTransport struct {
	Enabled        bool     `toml:"enabled"`
	Reality        bool     `toml:"reality"`
	Lanes          int      `toml:"lanes"`
	ReorderWait    Duration `toml:"reorder_wait"`
	KeepAlive      Duration `toml:"keepalive"`
	TCPUserTimeout Duration `toml:"tcp_user_timeout"`
}

type Overlay struct {
	Name            string   `toml:"name"`
	Address         string   `toml:"address"`
	Pool            string   `toml:"pool"`
	MTU             int      `toml:"mtu"`
	AdvertiseRoutes []string `toml:"advertise_routes"`
	AcceptRoutes    []string `toml:"accept_routes"`
}

type Gateway struct {
	NAT          bool   `toml:"nat"`
	LANInterface string `toml:"lan_interface"`
}

type Logging struct {
	Level         string   `toml:"level"`
	StatsInterval Duration `toml:"stats_interval"`
}

func Load(path string) (*Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat config: %w", err)
	}
	if info.IsDir() {
		return nil, errors.New("config path is a directory")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

func Encode(cfg *Config) ([]byte, error) {
	if cfg == nil {
		return nil, errors.New("configuration is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := toml.NewEncoder(&output).Encode(cfg); err != nil {
		return nil, fmt.Errorf("encode TOML: %w", err)
	}
	return output.Bytes(), nil
}

func Parse(data []byte) (*Config, error) {
	var cfg Config
	meta, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("decode TOML: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) != 0 {
		return nil, fmt.Errorf("unknown TOML field %q", undecoded[0].String())
	}
	cfg.defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) defaults() {
	if c.Auth.KDF == "" {
		c.Auth.KDF = "argon2id"
	}
	if c.Auth.KDFMemoryMiB == 0 {
		c.Auth.KDFMemoryMiB = 64
	}
	if c.Auth.KDFIterations == 0 {
		c.Auth.KDFIterations = 3
	}
	if c.Auth.KDFParallelism == 0 {
		c.Auth.KDFParallelism = 2
	}
	if c.Listen.TCP == "" {
		c.Listen.TCP = "0.0.0.0:443"
	}
	if c.Listen.UDP == "" {
		c.Listen.UDP = "0.0.0.0:443"
	}
	defaultDuration(&c.Reality.TimeWindow, time.Minute)
	if c.Reality.FallbackMaxPerIP == 0 {
		c.Reality.FallbackMaxPerIP = 4
	}
	if c.Reality.FallbackMaxConnections == 0 {
		c.Reality.FallbackMaxConnections = 128
	}
	defaultDuration(&c.Reality.FallbackIdleTimeout, 15*time.Second)
	defaultDuration(&c.Reality.FallbackMaxLifetime, 2*time.Minute)
	if c.Transport.Mode == "" {
		c.Transport.Mode = "auto"
	}
	if c.Transport.QUIC.ALPN == "" {
		c.Transport.QUIC.ALPN = "h3"
	}
	defaultDuration(&c.Transport.QUIC.KeepAlive, 15*time.Second)
	defaultDuration(&c.Transport.QUIC.IdleTimeout, 60*time.Second)
	if c.Transport.QUIC.InitialPacketSize == 0 {
		c.Transport.QUIC.InitialPacketSize = 1200
	}
	if c.Transport.TLS.Lanes == 0 {
		c.Transport.TLS.Lanes = 4
	}
	defaultDuration(&c.Transport.TLS.ReorderWait, 5*time.Millisecond)
	defaultDuration(&c.Transport.TLS.KeepAlive, 20*time.Second)
	defaultDuration(&c.Transport.TLS.TCPUserTimeout, 30*time.Second)
	if c.Overlay.Name == "" {
		c.Overlay.Name = "tlsnet0"
	}
	if c.Overlay.MTU == 0 {
		c.Overlay.MTU = 1280
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	defaultDuration(&c.Logging.StatsInterval, 10*time.Second)
}

func defaultDuration(dst *Duration, value time.Duration) {
	if dst.Duration == 0 {
		dst.Duration = value
	}
}

func (c *Config) Validate() error {
	if c.ConfigVersion != CurrentVersion {
		return fmt.Errorf("config_version must be %d", CurrentVersion)
	}
	if c.Node.Role != "relay" && c.Node.Role != "gateway" && c.Node.Role != "client" {
		return errors.New("node.role must be relay, gateway, or client")
	}
	if strings.TrimSpace(c.Node.Name) == "" {
		return errors.New("node.name is required")
	}
	if strings.TrimSpace(c.Auth.NetworkName) == "" {
		return errors.New("auth.network_name is required")
	}
	if c.Auth.Password == "" {
		return errors.New("auth.password is required")
	}
	if c.Auth.KDF != "argon2id" {
		return errors.New("auth.kdf must be argon2id")
	}
	if c.Auth.KDFMemoryMiB < 1 || c.Auth.KDFMemoryMiB > 1024 {
		return errors.New("auth.kdf_memory_mib must be 1..1024")
	}
	if c.Auth.KDFIterations < 1 || c.Auth.KDFIterations > 20 {
		return errors.New("auth.kdf_iterations must be 1..20")
	}
	if c.Auth.KDFParallelism < 1 || c.Auth.KDFParallelism > 64 {
		return errors.New("auth.kdf_parallelism must be 1..64")
	}
	if c.Reality.TimeWindow.Duration <= 0 {
		return errors.New("reality.time_window must be positive")
	}
	if c.Reality.FallbackIdleTimeout.Duration <= 0 || c.Reality.FallbackMaxLifetime.Duration <= 0 {
		return errors.New("reality fallback timeouts must be positive")
	}
	if err := validateDNSName(c.Reality.ServerName); err != nil {
		return fmt.Errorf("reality.server_name: %w", err)
	}
	if err := validateHostPort(c.Reality.TCPTarget); err != nil {
		return fmt.Errorf("reality.tcp_target: %w", err)
	}
	if c.Reality.UDPTarget != "" {
		if err := validateHostPort(c.Reality.UDPTarget); err != nil {
			return fmt.Errorf("reality.udp_target: %w", err)
		}
	}
	if c.Node.Role == "relay" {
		if err := validateHostPort(c.Listen.TCP); err != nil {
			return fmt.Errorf("listen.tcp: %w", err)
		}
		if err := validateHostPort(c.Listen.UDP); err != nil {
			return fmt.Errorf("listen.udp: %w", err)
		}
	} else if err := validateHostPort(c.Server.Address); err != nil {
		return fmt.Errorf("server.address: %w", err)
	}
	switch c.Transport.Mode {
	case "auto":
		if !c.Transport.QUIC.Enabled && !c.Transport.TLS.Enabled {
			return errors.New("auto mode requires at least one enabled transport")
		}
	case "quic":
		if !c.Transport.QUIC.Enabled {
			return errors.New("quic mode requires transport.quic.enabled")
		}
	case "tls-multipath":
		if !c.Transport.TLS.Enabled {
			return errors.New("tls-multipath mode requires transport.tls.enabled")
		}
	default:
		return errors.New("transport.mode must be auto, quic, or tls-multipath")
	}
	if c.Transport.TLS.Lanes < 1 || c.Transport.TLS.Lanes > 16 {
		return errors.New("transport.tls.lanes must be 1..16")
	}
	if c.Transport.QUIC.InitialPacketSize < 1200 || c.Transport.QUIC.InitialPacketSize > 1452 {
		return errors.New("transport.quic.initial_packet_size must be 1200..1452")
	}
	if c.Transport.QUIC.KeepAlive.Duration <= 0 || c.Transport.QUIC.IdleTimeout.Duration <= 0 {
		return errors.New("transport.quic timeouts must be positive")
	}
	if c.Transport.TLS.ReorderWait.Duration <= 0 || c.Transport.TLS.KeepAlive.Duration <= 0 || c.Transport.TLS.TCPUserTimeout.Duration <= 0 {
		return errors.New("transport.tls timeouts must be positive")
	}
	if c.Overlay.MTU < 576 || c.Overlay.MTU > 9000 {
		return errors.New("overlay.mtu must be 576..9000")
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		return errors.New("logging.level must be debug, info, warn, or error")
	}
	if c.Logging.StatsInterval.Duration <= 0 {
		return errors.New("logging.stats_interval must be positive")
	}
	if c.Overlay.Address != "" && c.Overlay.Address != "auto" {
		if _, err := netip.ParsePrefix(c.Overlay.Address); err != nil {
			return fmt.Errorf("overlay.address: %w", err)
		}
	}
	if c.Node.Role == "relay" {
		pool, err := netip.ParsePrefix(c.Overlay.Pool)
		if err != nil {
			return fmt.Errorf("overlay.pool: %w", err)
		}
		if !pool.Addr().Is4() || pool.Bits() > 30 {
			return errors.New("overlay.pool must be an IPv4 prefix of /30 or larger")
		}
		pool = pool.Masked()
		relayAddress, err := netip.ParsePrefix(c.Overlay.Address)
		if err != nil || !relayAddress.Addr().Is4() {
			return errors.New("relay overlay.address must be a concrete IPv4 prefix")
		}
		if relayAddress.Bits() != pool.Bits() || !pool.Contains(relayAddress.Addr()) ||
			relayAddress.Addr() == pool.Addr() || !pool.Contains(relayAddress.Addr().Next()) {
			return errors.New("relay overlay.address must be a usable address inside overlay.pool with the same prefix length")
		}
		for node, routes := range c.Relay.AllowedRoutes {
			if strings.TrimSpace(node) == "" {
				return errors.New("relay.allowed_routes contains an empty node name")
			}
			for _, route := range routes {
				if _, err := netip.ParsePrefix(route); err != nil {
					return fmt.Errorf("relay.allowed_routes.%s contains invalid route %q", node, route)
				}
			}
		}
	}
	for _, route := range append(append([]string{}, c.Overlay.AdvertiseRoutes...), c.Overlay.AcceptRoutes...) {
		if _, err := netip.ParsePrefix(route); err != nil {
			return fmt.Errorf("invalid overlay route %q: %w", route, err)
		}
	}
	if c.Node.Role == "gateway" && c.Gateway.NAT && strings.TrimSpace(c.Gateway.LANInterface) == "" {
		return errors.New("gateway.lan_interface is required when gateway.nat is true")
	}
	return nil
}

func validateHostPort(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value is required")
	}
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return err
	}
	if port == "" {
		return errors.New("port is required")
	}
	return nil
}

func validateDNSName(name string) error {
	if net.ParseIP(name) != nil {
		return errors.New("must be a DNS name, not an IP address")
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 || !strings.Contains(name, ".") {
		return errors.New("must be a dotted DNS name")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label")
		}
		for _, r := range label {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
				return errors.New("invalid DNS character")
			}
		}
	}
	return nil
}
