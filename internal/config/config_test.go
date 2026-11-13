package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadClientDefaults(t *testing.T) {
	path := writeConfig(t, `
config_version = 1
[node]
role = "client"
name = "laptop"
[auth]
network_name = "testnet"
password = "a long test password"
[server]
address = "203.0.113.1:443"
[reality]
server_name = "www.speedtest.cn"
tcp_target = "www.speedtest.cn:443"
[transport]
mode = "auto"
[transport.quic]
enabled = true
reality = true
[transport.tls]
enabled = true
reality = true
[overlay]
address = "auto"
accept_routes = ["192.168.3.0/24"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Transport.TLS.Lanes != 4 || cfg.Overlay.MTU != 1280 {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg.Reality.TimeWindow.Duration != time.Minute {
		t.Fatalf("time window=%s", cfg.Reality.TimeWindow.Duration)
	}
}

func TestRejectsUnknownField(t *testing.T) {
	path := writeConfig(t, `
config_version = 1
unknown = true
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "unknown TOML field") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRejectsInvalidMode(t *testing.T) {
	cfg := Config{
		ConfigVersion: 1,
		Node:          Node{Role: "client", Name: "node"},
		Auth:          Auth{NetworkName: "net", Password: "pw", KDF: "argon2id", KDFMemoryMiB: 1, KDFIterations: 1, KDFParallelism: 1},
		Server:        Server{Address: "203.0.113.1:443"},
		Reality:       Reality{ServerName: "www.speedtest.cn", TCPTarget: "www.speedtest.cn:443"},
		Transport:     Transport{Mode: "invalid", QUIC: QUICTransport{InitialPacketSize: 1200}, TLS: TLSTransport{Lanes: 4}},
		Overlay:       Overlay{MTU: 1280},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "transport.mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}
