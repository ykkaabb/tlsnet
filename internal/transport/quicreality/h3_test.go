package quicreality

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/ykkaabb/tlsnet/internal/auth"
)

func TestH3TunnelDatagramRoundTrip(t *testing.T) {
	keys, err := auth.Derive("password", "testnet", "www.speedtest.cn", auth.KDFParams{
		MemoryMiB: 1, Iterations: 1, Parallelism: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	options := H3Options{
		ServerName: "www.speedtest.cn", Keys: keys, TimeWindow: time.Minute,
		KeepAlive: time.Second, IdleTimeout: 5 * time.Second, InitialPacketSize: 1200,
		Now: func() time.Time { return now },
	}
	serverPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTransport := &quic.Transport{Conn: serverPacketConn}
	defer serverTransport.Close()
	tlsConfig, err := ServerTLSConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverTransport.Listen(tlsConfig, quicConfig(options))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(ctx)
		if err != nil {
			serverResult <- err
			return
		}
		serverResult <- ServeH3Connection(connection, options, func(tunnel *H3Tunnel) {
			packet, err := tunnel.Receive(ctx)
			if err == nil {
				err = tunnel.Send(packet)
			}
			if err != nil {
				_ = connection.CloseWithError(1, err.Error())
			}
		})
	}()

	clientPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := DialH3(ctx, clientPacketConn, serverPacketConn.LocalAddr(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	if err := tunnel.Send([]byte("packet")); err != nil {
		t.Fatal(err)
	}
	response, err := tunnel.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "packet" {
		t.Fatalf("unexpected datagram %q", response)
	}
	_ = tunnel.Close()
	select {
	case err := <-serverResult:
		if err != nil {
			t.Logf("server closed with: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP/3 server did not stop")
	}
}
