package main

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	version          = "0.5.0"
	maxPacket        = 65535
	authWindow       = 5 * time.Minute
	defaultPort      = 18443
	defaultMTU       = 1350
	defaultStats     = 10
	defaultSlowWrite = 100
)

var (
	authMagic = []byte("TLSTUN03")
	authOK    = []byte("OK01")
	decoyHTTP = []byte("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 10\r\nConnection: close\r\nCache-Control: no-store\r\n\r\nNot Found\n")
)

type config struct {
	Role        string            `json:"role"`
	Tun         tunConfig         `json:"tun"`
	TLS         tlsConfig         `json:"tls"`
	Inner       innerConfig       `json:"inner"`
	Diagnostics diagnosticsConfig `json:"diagnostics"`
	Performance performanceConfig `json:"performance"`
}

type tunConfig struct {
	Name    string   `json:"name"`
	Address string   `json:"address"`
	MTU     int      `json:"mtu"`
	Routes  []string `json:"routes"`
}

type tlsConfig struct {
	Listen      string `json:"listen"`
	Server      string `json:"server"`
	Port        int    `json:"port"`
	ServerName  string `json:"server_name"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

type innerConfig struct {
	AuthKey string `json:"auth_key"`
}

type diagnosticsConfig struct {
	IntervalSeconds int `json:"interval_seconds"`
	SlowWriteMS     int `json:"slow_write_ms"`
}

type performanceConfig struct {
	SocketBufferBytes    int `json:"socket_buffer_bytes"`
	TCPUserTimeoutSecond int `json:"tcp_user_timeout_seconds"`
	ParallelConnections  int `json:"parallel_connections"`
	ReorderWaitMS        int `json:"reorder_wait_ms"`
}

type tunDevice interface {
	io.ReadWriteCloser
	Fd() uintptr
}

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *config) defaults() {
	if c.Tun.Name == "" {
		c.Tun.Name = "tlstun0"
	}
	if c.Tun.MTU == 0 {
		c.Tun.MTU = defaultMTU
	}
	if c.TLS.Port == 0 {
		c.TLS.Port = defaultPort
	}
	if c.Diagnostics.IntervalSeconds == 0 {
		c.Diagnostics.IntervalSeconds = defaultStats
	}
	if c.Diagnostics.SlowWriteMS == 0 {
		c.Diagnostics.SlowWriteMS = defaultSlowWrite
	}
	if c.Performance.TCPUserTimeoutSecond == 0 {
		c.Performance.TCPUserTimeoutSecond = 30
	}
	if c.Performance.ParallelConnections == 0 {
		c.Performance.ParallelConnections = 4
	}
	if c.Performance.ReorderWaitMS == 0 {
		c.Performance.ReorderWaitMS = 5
	}
}

func (c *config) validate() error {
	if c.Role != "server" && c.Role != "client" {
		return errors.New("role must be server or client")
	}
	if len(c.Tun.Name) == 0 || len(c.Tun.Name) >= 16 {
		return errors.New("invalid TUN interface name")
	}
	if _, _, err := net.ParseCIDR(c.Tun.Address); err != nil {
		return fmt.Errorf("tun.address: %w", err)
	}
	if c.Tun.MTU < 576 || c.Tun.MTU > 9000 {
		return errors.New("tun.mtu must be between 576 and 9000")
	}
	for _, route := range c.Tun.Routes {
		if _, _, err := net.ParseCIDR(route); err != nil {
			return fmt.Errorf("invalid route %s: %w", route, err)
		}
	}
	if c.TLS.Port < 1 || c.TLS.Port > 65535 {
		return errors.New("tls.port must be valid")
	}
	if err := validateDNSName(c.TLS.ServerName); err != nil {
		return err
	}
	if c.Role == "server" && (c.TLS.Certificate == "" || c.TLS.PrivateKey == "") {
		return errors.New("server certificate and private_key are required")
	}
	if c.Role == "client" && c.TLS.Server == "" {
		return errors.New("tls.server is required")
	}
	key, err := decodeAuthKey(c.Inner.AuthKey)
	if err != nil || len(key) != 32 {
		return errors.New("inner.auth_key must be base64 for exactly 32 bytes")
	}
	if c.Diagnostics.IntervalSeconds < 1 || c.Diagnostics.IntervalSeconds > 3600 {
		return errors.New("diagnostics.interval_seconds must be 1..3600")
	}
	if c.Diagnostics.SlowWriteMS < 1 || c.Diagnostics.SlowWriteMS > 60000 {
		return errors.New("diagnostics.slow_write_ms must be 1..60000")
	}
	if c.Performance.ParallelConnections < 1 || c.Performance.ParallelConnections > 16 {
		return errors.New("performance.parallel_connections must be 1..16")
	}
	if c.Performance.ReorderWaitMS < 1 || c.Performance.ReorderWaitMS > 1000 {
		return errors.New("performance.reorder_wait_ms must be 1..1000")
	}
	return nil
}

func validateDNSName(name string) error {
	if net.ParseIP(name) != nil {
		return errors.New("tls.server_name must be a DNS name, not an IP")
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 || !strings.Contains(name, ".") {
		return errors.New("tls.server_name must be a dotted DNS name")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid tls.server_name")
		}
		for _, r := range label {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
				return errors.New("invalid tls.server_name")
			}
		}
	}
	return nil
}

func decodeAuthKey(s string) ([]byte, error) { return base64.StdEncoding.Strict().DecodeString(s) }

func fingerprint(cert []byte) [32]byte { return sha256.Sum256(cert) }

func fingerprintText(fp [32]byte) string {
	parts := make([]string, len(fp))
	for i, b := range fp {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func authTag(key, role, transcript []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(role)
	_, _ = h.Write(transcript)
	return h.Sum(nil)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func clientAuthenticate(conn net.Conn, key []byte, fp [32]byte) error {
	transcript := make([]byte, 72)
	binary.BigEndian.PutUint64(transcript[:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(transcript[8:40]); err != nil {
		return err
	}
	copy(transcript[40:], fp[:])
	request := make([]byte, 0, 112)
	request = append(request, authMagic...)
	request = append(request, transcript...)
	request = append(request, authTag(key, []byte("client"), transcript)...)
	if err := writeAll(conn, request); err != nil {
		return err
	}
	response := make([]byte, 36)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	expected := append(append([]byte{}, authOK...), authTag(key, []byte("server"), transcript)...)
	if !hmac.Equal(response, expected) {
		return errors.New("tunnel authentication failed")
	}
	return nil
}

func serverAuthenticate(conn net.Conn, key []byte, fp [32]byte) error {
	magic := make([]byte, 8)
	if _, err := io.ReadFull(conn, magic); err != nil {
		return err
	}
	if !hmac.Equal(magic, authMagic) {
		_ = writeAll(conn, decoyHTTP)
		return errors.New("invalid tunnel protocol; returned HTTPS decoy response")
	}
	request := make([]byte, 104)
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	timestamp := int64(binary.BigEndian.Uint64(request[:8]))
	delta := time.Now().Unix() - timestamp
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Second > authWindow {
		return errors.New("authentication timestamp expired")
	}
	if !hmac.Equal(request[40:72], fp[:]) {
		return errors.New("TLS certificate fingerprint binding failed")
	}
	if !hmac.Equal(request[72:], authTag(key, []byte("client"), request[:72])) {
		return errors.New("tunnel authentication failed")
	}
	response := append(append([]byte{}, authOK...), authTag(key, []byte("server"), request[:72])...)
	return writeAll(conn, response)
}

type counters struct {
	txPackets, txBytes, rxPackets, rxBytes     atomic.Uint64
	wTxPackets, wTxBytes, wRxPackets, wRxBytes atomic.Uint64
	slowWrites, tlsWriteMaxNS, tunWriteMaxNS   atomic.Uint64
	sessionTLSMaxNS, sessionTunMaxNS           atomic.Uint64
}

func atomicMax(v *atomic.Uint64, n uint64) {
	for old := v.Load(); n > old; old = v.Load() {
		if v.CompareAndSwap(old, n) {
			return
		}
	}
}

func (s *counters) recordTX(n int, d time.Duration, slow time.Duration) {
	s.txPackets.Add(1)
	s.txBytes.Add(uint64(n))
	s.wTxPackets.Add(1)
	s.wTxBytes.Add(uint64(n))
	atomicMax(&s.tlsWriteMaxNS, uint64(d))
	atomicMax(&s.sessionTLSMaxNS, uint64(d))
	if d >= slow {
		s.slowWrites.Add(1)
	}
}

func (s *counters) recordRX(n int, d time.Duration) {
	s.rxPackets.Add(1)
	s.rxBytes.Add(uint64(n))
	s.wRxPackets.Add(1)
	s.wRxBytes.Add(uint64(n))
	atomicMax(&s.tunWriteMaxNS, uint64(d))
	atomicMax(&s.sessionTunMaxNS, uint64(d))
}

func reportStats(ctx context.Context, stats *counters, tcp *net.TCPConn, cfg diagnosticsConfig) {
	ticker := time.NewTicker(time.Duration(cfg.IntervalSeconds) * time.Second)
	defer ticker.Stop()
	previous := uint32(0)
	if health, ok := readTCPInfo(tcp); ok {
		previous = health.TotalRetrans
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			txp, txb := stats.wTxPackets.Swap(0), stats.wTxBytes.Swap(0)
			rxp, rxb := stats.wRxPackets.Swap(0), stats.wRxBytes.Swap(0)
			tlsMax, tunMax := time.Duration(stats.tlsWriteMaxNS.Swap(0)), time.Duration(stats.tunWriteMaxNS.Swap(0))
			slow := stats.slowWrites.Swap(0)
			if h, ok := readTCPInfo(tcp); ok {
				delta := h.TotalRetrans - previous
				previous = h.TotalRetrans
				seconds := float64(cfg.IntervalSeconds)
				log.Printf("stats window=%ds tx=%dpkts/%dbytes/%.2fMbps rx=%dpkts/%dbytes/%.2fMbps tls_write_max=%.1fms slow_writes=%d tun_write_max=%.1fms tcp_rtt=%.3fms rttvar=%.3fms cwnd=%d unacked=%d lost=%d retrans_now=%d retrans_total=%d retrans_delta=%d pmtu=%d", cfg.IntervalSeconds, txp, txb, float64(txb)*8/seconds/1e6, rxp, rxb, float64(rxb)*8/seconds/1e6, float64(tlsMax)/float64(time.Millisecond), slow, float64(tunMax)/float64(time.Millisecond), float64(h.RTTUS)/1000, float64(h.RTTVarUS)/1000, h.CWND, h.Unacked, h.Lost, h.Retrans, h.TotalRetrans, delta, h.PMTU)
			}
		}
	}
}

func bridge(parent context.Context, tun tunDevice, tlsConn *tls.Conn, tcp *net.TCPConn, diag diagnosticsConfig) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stats := &counters{}
	go reportStats(ctx, stats, tcp, diag)
	errorsCh := make(chan error, 2)
	slow := time.Duration(diag.SlowWriteMS) * time.Millisecond
	go func() {
		frame := make([]byte, maxPacket+4)
		keepalive := time.NewTicker(15 * time.Second)
		defer keepalive.Stop()
		for {
			ready, err := waitTunReadable(ctx, tun.Fd(), time.Second)
			if err != nil {
				errorsCh <- err
				return
			}
			if ready {
				n, err := tun.Read(frame[4:])
				if err != nil {
					errorsCh <- err
					return
				}
				if n > 0 {
					binary.BigEndian.PutUint32(frame[:4], uint32(n))
					started := time.Now()
					err = writeAll(tlsConn, frame[:n+4])
					elapsed := time.Since(started)
					stats.recordTX(n, elapsed, slow)
					if elapsed >= slow {
						log.Printf("WARNING TLS write blocked for %.1fms while sending %d bytes; possible outer TCP congestion", float64(elapsed)/float64(time.Millisecond), n)
					}
					if err != nil {
						errorsCh <- err
						return
					}
				}
			}
			select {
			case <-ctx.Done():
				errorsCh <- ctx.Err()
				return
			case <-keepalive.C:
				if err := writeAll(tlsConn, []byte{0, 0, 0, 0}); err != nil {
					errorsCh <- err
					return
				}
			default:
			}
		}
	}()
	go func() {
		header := make([]byte, 4)
		packet := make([]byte, maxPacket)
		for {
			if _, err := io.ReadFull(tlsConn, header); err != nil {
				errorsCh <- err
				return
			}
			n := int(binary.BigEndian.Uint32(header))
			if n > maxPacket {
				errorsCh <- fmt.Errorf("invalid frame length %d", n)
				return
			}
			if n == 0 {
				continue
			}
			if _, err := io.ReadFull(tlsConn, packet[:n]); err != nil {
				errorsCh <- err
				return
			}
			started := time.Now()
			if err := writeAll(tun, packet[:n]); err != nil {
				errorsCh <- err
				return
			}
			stats.recordRX(n, time.Since(started))
		}
	}()
	err := <-errorsCh
	cancel()
	_ = tlsConn.Close()
	log.Printf("session summary tx=%dpkts/%dbytes rx=%dpkts/%dbytes tls_write_max=%.1fms tun_write_max=%.1fms", stats.txPackets.Load(), stats.txBytes.Load(), stats.rxPackets.Load(), stats.rxBytes.Load(), float64(stats.sessionTLSMaxNS.Load())/float64(time.Millisecond), float64(stats.sessionTunMaxNS.Load())/float64(time.Millisecond))
	return err
}

func serverTLSConfig(c *config) (*tls.Config, [32]byte, error) {
	certificate, err := tls.LoadX509KeyPair(c.TLS.Certificate, c.TLS.PrivateKey)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if len(certificate.Certificate) == 0 {
		return nil, [32]byte{}, errors.New("empty certificate chain")
	}
	fp := fingerprint(certificate.Certificate[0])
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, fp, nil
}

func clientTLSConfig(c *config) *tls.Config {
	return &tls.Config{ServerName: c.TLS.ServerName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
}

func runServer(ctx context.Context, c *config, tun tunDevice, key []byte) error {
	tlsCfg, fp, err := serverTLSConfig(c)
	if err != nil {
		return err
	}
	listen := c.TLS.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(listen, fmt.Sprint(c.TLS.Port)))
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	log.Printf("TLS server listening on %s:%d; camouflage SNI %s; certificate SHA-256 %s", listen, c.TLS.Port, c.TLS.ServerName, fingerprintText(fp))
	for {
		raw, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		tcp := raw.(*net.TCPConn)
		if err := setSocketOptions(tcp, c.Performance); err != nil {
			_ = raw.Close()
			log.Printf("socket setup failed: %v", err)
			continue
		}
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		tlsConn := tls.Server(raw, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			log.Printf("TLS handshake failed from %s: %v", raw.RemoteAddr(), err)
			_ = raw.Close()
			continue
		}
		if err := serverAuthenticate(tlsConn, key, fp); err != nil {
			log.Printf("connection rejected from %s: %v", raw.RemoteAddr(), err)
			_ = raw.Close()
			continue
		}
		_ = raw.SetDeadline(time.Time{})
		state := tlsConn.ConnectionState()
		log.Printf("tunnel connected from %s using TLS 0x%x %s; SNI %s; ALPN %s", raw.RemoteAddr(), state.Version, tls.CipherSuiteName(state.CipherSuite), state.ServerName, state.NegotiatedProtocol)
		if err := bridge(ctx, tun, tlsConn, tcp, c.Diagnostics); err != nil && ctx.Err() == nil {
			log.Printf("connection closed: %v", err)
		}
	}
}

func runClient(ctx context.Context, c *config, tun tunDevice, key []byte) error {
	delay := time.Second
	for ctx.Err() == nil {
		dialer := net.Dialer{Timeout: 10 * time.Second}
		raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(c.TLS.Server, fmt.Sprint(c.TLS.Port)))
		if err == nil {
			tcp := raw.(*net.TCPConn)
			err = setSocketOptions(tcp, c.Performance)
			if err == nil {
				_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
				tlsConn := tls.Client(raw, clientTLSConfig(c))
				err = tlsConn.HandshakeContext(ctx)
				if err == nil {
					state := tlsConn.ConnectionState()
					if len(state.PeerCertificates) == 0 {
						err = errors.New("server provided no certificate")
					} else {
						fp := fingerprint(state.PeerCertificates[0].Raw)
						err = clientAuthenticate(tlsConn, key, fp)
						if err == nil {
							_ = raw.SetDeadline(time.Time{})
							log.Printf("tunnel connected using TLS 0x%x %s; SNI %s; ALPN %s; authenticated certificate SHA-256 %s", state.Version, tls.CipherSuiteName(state.CipherSuite), c.TLS.ServerName, state.NegotiatedProtocol, fingerprintText(fp))
							delay = time.Second
							err = bridge(ctx, tun, tlsConn, tcp, c.Diagnostics)
						}
					}
				}
				_ = raw.Close()
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		log.Printf("connect/disconnect: %v; retrying in %s", err, delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
	return nil
}

func main() {
	configPath := flag.String("config", "/etc/tlstun/config.json", "configuration file")
	showVersion := flag.Bool("version", false, "show version")
	flag.Parse()
	if *showVersion {
		fmt.Printf("TlsTun %s\n", version)
		return
	}
	if flag.NArg() == 1 && flag.Arg(0) == "derive-key" {
		password, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		key, err := pbkdf2.Key(sha256.New, string(password), []byte("TlsTun v0.3 password key"), 600_000, 32)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(key))
		return
	}
	if flag.NArg() != 1 || flag.Arg(0) != "run" && flag.Arg(0) != "check" {
		fmt.Fprintln(os.Stderr, "usage: tlstun [--config FILE] run|check | tlstun derive-key")
		os.Exit(2)
	}
	c, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if flag.Arg(0) == "check" {
		fmt.Printf("valid %s configuration for TlsTun %s\n", c.Role, version)
		return
	}
	if os.Geteuid() != 0 {
		log.Fatal("run mode must be started as root")
	}
	key, _ := decodeAuthKey(c.Inner.AuthKey)
	tun, err := openTun(&c.Tun)
	if err != nil {
		log.Fatal(err)
	}
	defer tun.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if c.Role == "server" {
		err = runMultiServer(ctx, c, tun, key)
	} else {
		err = runMultiClient(ctx, c, tun, key)
	}
	if err != nil {
		log.Fatal(err)
	}
}
