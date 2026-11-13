package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

func TestAuthenticationCompatibility(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	key := bytes.Repeat([]byte("k"), 32)
	fp := fingerprint([]byte("certificate"))
	done := make(chan error, 1)
	go func() { done <- serverAuthenticate(right, key, fp) }()
	if err := clientAuthenticate(left, key, fp); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHMACTag(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	got := authTag(key, []byte("client"), []byte("data"))
	h := hmac.New(sha256.New, key)
	h.Write([]byte("clientdata"))
	if !hmac.Equal(got, h.Sum(nil)) {
		t.Fatal("HMAC mismatch")
	}
}

func TestConfigDefaults(t *testing.T) {
	c := config{Role: "client", Tun: tunConfig{Address: "10.90.0.2/30"}, TLS: tlsConfig{Server: "203.0.113.1", ServerName: "www.speedtest.cn"}, Inner: innerConfig{AuthKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 32))}}
	c.defaults()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.TLS.Port != 18443 || c.Diagnostics.IntervalSeconds != 10 || c.Performance.ParallelConnections != 4 || c.Performance.ReorderWaitMS != 5 {
		t.Fatal("defaults not applied")
	}
}

func TestLaneAuthentication(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	key := bytes.Repeat([]byte("l"), 32)
	meta := laneMeta{Index: 2, Count: 4}
	copy(meta.Group[:], []byte("test-lane-group!"))
	done := make(chan error, 1)
	go func() {
		got, err := serverJoinLane(right, key)
		if err == nil && got != meta {
			err = fmt.Errorf("lane metadata mismatch: got %+v want %+v", got, meta)
		}
		done <- err
	}()
	if err := clientJoinLane(left, key, meta); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type testTun struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (t *testTun) Read(p []byte) (int, error) { return 0, io.EOF }
func (t *testTun) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.b.Write(p)
}
func (t *testTun) Close() error { return nil }
func (t *testTun) Fd() uintptr  { return 0 }
func (t *testTun) Bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.b.Bytes()...)
}

func testPacket(sequence uint64, payload string) *packetFrame {
	data := make([]byte, frameHeaderSize+len(payload))
	copy(data[frameHeaderSize:], payload)
	return &packetFrame{data: data, payload: len(payload), sequence: sequence}
}

func waitForTun(t *testing.T, tun *testTun, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if string(tun.Bytes()) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("TUN output %q, want %q", tun.Bytes(), want)
}

func TestBoundedReorderPreservesNormalOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tun := &testTun{}
	received := make(chan *packetFrame, 2)
	stats := &multiCounters{}
	pool := &sync.Pool{New: func() any { return &packetFrame{} }}
	done := make(chan error, 1)
	go func() { done <- reorderToTun(ctx, tun, received, stats, pool, 20*time.Millisecond) }()
	received <- testPacket(2, "two")
	received <- testPacket(1, "one")
	waitForTun(t, tun, "onetwo")
	cancel()
	<-done
	if stats.rxGapDrops.Load() != 0 || stats.rxLateDrops.Load() != 0 {
		t.Fatalf("unexpected reorder drops: gap=%d late=%d", stats.rxGapDrops.Load(), stats.rxLateDrops.Load())
	}
}

func TestBoundedReorderSkipsBlockedLane(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tun := &testTun{}
	received := make(chan *packetFrame, 1)
	stats := &multiCounters{}
	pool := &sync.Pool{New: func() any { return &packetFrame{} }}
	done := make(chan error, 1)
	go func() { done <- reorderToTun(ctx, tun, received, stats, pool, 2*time.Millisecond) }()
	received <- testPacket(2, "two")
	waitForTun(t, tun, "two")
	cancel()
	<-done
	if stats.rxGapDrops.Load() != 1 {
		t.Fatalf("gap drops=%d, want 1", stats.rxGapDrops.Load())
	}
}

func TestAdaptiveLaneSelection(t *testing.T) {
	lanes := make([]*tunnelLane, 3)
	for i := range lanes {
		lanes[i] = &tunnelLane{send: make(chan *packetFrame, laneQueueDepth)}
		lanes[i].active.Store(true)
	}
	lanes[0].pendingBytes.Store(8_000)
	lanes[1].pendingBytes.Store(1_000)
	lanes[2].pendingBytes.Store(0)
	lanes[2].avoidUntilNS.Store(time.Now().Add(time.Second).UnixNano())
	if got := chooseLane(lanes, 0, time.Now().UnixNano()); got != 1 {
		t.Fatalf("selected lane %d, want healthy low-backlog lane 1", got)
	}
	lanes[1].active.Store(false)
	if got := chooseLane(lanes, 0, time.Now().UnixNano()); got != 0 {
		t.Fatalf("selected lane %d, want remaining healthy lane 0", got)
	}
}

func TestFourLaneTLSGroupHandshake(t *testing.T) {
	cert := testCertificate(t)
	key := bytes.Repeat([]byte("m"), 32)
	fp := fingerprint(cert.Certificate[0])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	serverConfig := config{Performance: performanceConfig{ParallelConnections: 4, ReorderWaitMS: 5, TCPUserTimeoutSecond: 30}}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	serverResults := make(chan *tunnelLane, 4)
	serverErrors := make(chan error, 4)
	go func() {
		for i := 0; i < 4; i++ {
			raw, err := listener.Accept()
			if err != nil {
				serverErrors <- err
				return
			}
			go func(raw net.Conn) {
				lane, err := acceptMultiLane(context.Background(), raw, &serverConfig, serverTLS, key, fp)
				if err != nil {
					serverErrors <- err
					return
				}
				serverResults <- lane
			}(raw)
		}
	}()
	clientConfig := config{
		TLS:         tlsConfig{Server: "127.0.0.1", Port: port, ServerName: "www.speedtest.cn"},
		Performance: performanceConfig{ParallelConnections: 4, ReorderWaitMS: 5, TCPUserTimeoutSecond: 30},
	}
	var group [16]byte
	copy(group[:], []byte("four-lane-test!!"))
	clientLanes, err := dialMultiGroup(context.Background(), &clientConfig, key, group)
	if err != nil {
		t.Fatal(err)
	}
	defer closeLanes(clientLanes)
	seen := make(map[uint16]bool)
	serverLanes := make([]*tunnelLane, 0, 4)
	defer func() { closeLanes(serverLanes) }()
	for len(serverLanes) < 4 {
		select {
		case lane := <-serverResults:
			serverLanes = append(serverLanes, lane)
			seen[lane.meta.Index] = true
		case err := <-serverErrors:
			t.Fatal(err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for TLS lane group")
		}
	}
	for i := uint16(0); i < 4; i++ {
		if !seen[i] {
			t.Fatalf("server did not receive lane %d", i)
		}
	}
}

func TestPasswordDerivationCompatibility(t *testing.T) {
	password := "correct horse battery staple"
	key, err := pbkdf2.Key(sha256.New, password, []byte("TlsTun v0.3 password key"), 600_000, 32)
	if err != nil {
		t.Fatal(err)
	}
	want, err := pbkdf2.Key(sha256.New, password, []byte("TlsTun v0.3 password key"), 600_000, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, want) || len(key) != 32 {
		t.Fatal("password derivation is not deterministic")
	}
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "www.speedtest.cn"}, DNSNames: []string{"www.speedtest.cn"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestTLSRoundTripSNIAndALPN(t *testing.T) {
	cert := testCertificate(t)
	key := bytes.Repeat([]byte("x"), 32)
	fp := fingerprint(cert.Certificate[0])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer raw.Close()
		conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
		if err := conn.Handshake(); err != nil {
			serverResult <- err
			return
		}
		state := conn.ConnectionState()
		if state.ServerName != "www.speedtest.cn" || state.NegotiatedProtocol != "http/1.1" {
			serverResult <- fmt.Errorf("unexpected TLS state: %+v", state)
			return
		}
		if err := serverAuthenticate(conn, key, fp); err != nil {
			serverResult <- err
			return
		}
		var header [4]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			serverResult <- err
			return
		}
		n := binary.BigEndian.Uint32(header[:])
		packet := make([]byte, n)
		if _, err := io.ReadFull(conn, packet); err != nil {
			serverResult <- err
			return
		}
		binary.BigEndian.PutUint32(header[:], n)
		if err := writeAll(conn, append(header[:], packet...)); err != nil {
			serverResult <- err
			return
		}
		serverResult <- nil
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{ServerName: "www.speedtest.cn", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := clientAuthenticate(conn, key, fingerprint(conn.ConnectionState().PeerCertificates[0].Raw)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("through-native-tls")
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(conn, append(header[:], payload...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint32(header[:]))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("unexpected response %q", response)
	}
	conn.Close()
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}
