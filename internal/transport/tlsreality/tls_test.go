package tlsreality

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ykkaabb/tlsnet/internal/auth"
)

func transportKeys(t *testing.T, password string) *auth.Keys {
	t.Helper()
	keys, err := auth.Derive(password, "testnet", "www.speedtest.cn", auth.KDFParams{MemoryMiB: 1, Iterations: 1, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestTLSRealityHandshake(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	window := time.Minute
	keys := transportKeys(t, "test password")
	serverOptions := ServerOptions{ServerName: "www.speedtest.cn", Keys: keys, TimeWindow: window, Now: func() time.Time { return now }}
	serverConfig, err := ServerConfig(serverOptions)
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	serverResult := make(chan error, 1)
	go func() {
		hello, err := PeekClientHello(serverRaw, 0, time.Second)
		if err != nil {
			serverResult <- err
			return
		}
		if !IsAuthorized(hello, serverOptions) {
			serverResult <- context.Canceled
			return
		}
		conn, err := HandshakeServer(context.Background(), serverRaw, hello, serverConfig)
		if err == nil {
			_, err = conn.Write([]byte("ready"))
		}
		serverResult <- err
	}()

	client, err := Client(clientRaw, ClientOptions{ServerName: "www.speedtest.cn", Keys: keys, TimeWindow: window, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 5)
	if _, err := client.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "ready" {
		t.Fatalf("unexpected response %q", buffer)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestTLSRealityRejectsWrongPasswordBeforeHandshake(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	window := time.Minute
	clientKeys := transportKeys(t, "client password")
	serverKeys := transportKeys(t, "server password")
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	result := make(chan bool, 1)
	go func() {
		hello, err := PeekClientHello(serverRaw, 0, time.Second)
		result <- err == nil && IsAuthorized(hello, ServerOptions{
			ServerName: "www.speedtest.cn",
			Keys:       serverKeys,
			TimeWindow: window,
			Now:        func() time.Time { return now },
		})
	}()
	client, err := Client(clientRaw, ClientOptions{
		ServerName: "www.speedtest.cn",
		Keys:       clientKeys,
		TimeWindow: window,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = client.Handshake()
	if <-result {
		t.Fatal("wrong password was authorized")
	}
}
