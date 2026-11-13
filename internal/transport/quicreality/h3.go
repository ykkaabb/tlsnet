package quicreality

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/ykkaabb/tlsnet/internal/auth"
)

const tunnelPath = "/api/speedtest/upload"

type H3Options struct {
	ServerName        string
	Keys              *auth.Keys
	TimeWindow        time.Duration
	KeepAlive         time.Duration
	IdleTimeout       time.Duration
	InitialPacketSize uint16
	DisablePMTU       bool
	Now               func() time.Time
}

type H3Tunnel struct {
	send    func([]byte) error
	receive func(context.Context) ([]byte, error)
	close   func() error
}

func (t *H3Tunnel) Send(packet []byte) error {
	if t == nil || t.send == nil {
		return errors.New("HTTP/3 tunnel is closed")
	}
	return t.send(packet)
}

func (t *H3Tunnel) Receive(ctx context.Context) ([]byte, error) {
	if t == nil || t.receive == nil {
		return nil, errors.New("HTTP/3 tunnel is closed")
	}
	return t.receive(ctx)
}

func (t *H3Tunnel) Close() error {
	if t == nil || t.close == nil {
		return nil
	}
	return t.close()
}

func DialH3(ctx context.Context, packetConn net.PacketConn, server net.Addr, options H3Options) (*H3Tunnel, error) {
	if packetConn == nil || server == nil {
		return nil, errors.New("packet connection and server address are required")
	}
	if err := validateH3Options(options); err != nil {
		return nil, err
	}
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	if err := SendProbe(packetConn, server, options.Keys.QUICRoute[:], now(), options.TimeWindow); err != nil {
		return nil, fmt.Errorf("send QUIC admission probe: %w", err)
	}
	transport := &quic.Transport{Conn: packetConn}
	connection, err := transport.Dial(ctx, server, clientTLSConfig(options, now), quicConfig(options))
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	h3Transport := &http3.Transport{EnableDatagrams: true, QUICConfig: quicConfig(options)}
	client := h3Transport.NewClientConn(connection)
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		_ = connection.CloseWithError(0, "")
		_ = transport.Close()
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Scheme: "https", Host: options.ServerName, Path: tunnelPath},
		Host:   options.ServerName,
		Header: http.Header{
			"Accept":        []string{"application/octet-stream"},
			"Authorization": []string{"Bearer " + h3Authorization(options.Keys.Session[:])},
			"User-Agent":    []string{"Mozilla/5.0"},
		},
	}
	if err := stream.SendRequestHeader(request); err != nil {
		_ = connection.CloseWithError(0, "")
		_ = transport.Close()
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		_ = connection.CloseWithError(0, "")
		_ = transport.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = connection.CloseWithError(0, "")
		_ = transport.Close()
		return nil, fmt.Errorf("HTTP/3 camouflage endpoint returned %s", response.Status)
	}
	return &H3Tunnel{
		send:    stream.SendDatagram,
		receive: stream.ReceiveDatagram,
		close: func() error {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			_ = connection.CloseWithError(0, "")
			return transport.Close()
		},
	}, nil
}

func ServeH3Connection(connection *quic.Conn, options H3Options, handler func(*H3Tunnel)) error {
	if connection == nil || handler == nil {
		return errors.New("QUIC connection and tunnel handler are required")
	}
	if err := validateH3Options(options); err != nil {
		return err
	}
	server := &http3.Server{
		EnableDatagrams: true,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			expected := "Bearer " + h3Authorization(options.Keys.Session[:])
			if request.Method != http.MethodPost || request.URL.Path != tunnelPath ||
				!hmac.Equal([]byte(request.Header.Get("Authorization")), []byte(expected)) {
				http.NotFound(writer, request)
				return
			}
			writer.Header().Set("Content-Type", "application/octet-stream")
			writer.WriteHeader(http.StatusOK)
			streamer, ok := writer.(http3.HTTPStreamer)
			if !ok {
				return
			}
			stream, err := streamer.HTTPStream()
			if err != nil {
				return
			}
			handler(&H3Tunnel{
				send:    stream.SendDatagram,
				receive: stream.ReceiveDatagram,
				close: func() error {
					stream.CancelRead(0)
					stream.CancelWrite(0)
					return nil
				},
			})
		}),
	}
	return server.ServeQUICConn(connection)
}

func ServerTLSConfig(options H3Options) (*tls.Config, error) {
	if err := validateH3Options(options); err != nil {
		return nil, err
	}
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	manager, err := auth.NewCertificateManager(
		options.ServerName, options.Keys.Certificate[:], 6*time.Hour, time.Hour, now,
	)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		NextProtos:     []string{http3.NextProtoH3},
		GetCertificate: manager.GetCertificate,
	}, nil
}

func clientTLSConfig(options H3Options, now func() time.Time) *tls.Config {
	return &tls.Config{
		ServerName: options.ServerName, MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			return auth.VerifyServerCertificate(
				state.PeerCertificates[0], options.ServerName, options.Keys.Certificate[:], now(), options.TimeWindow,
			)
		},
	}
}

func quicConfig(options H3Options) *quic.Config {
	return &quic.Config{
		EnableDatagrams: true, KeepAlivePeriod: options.KeepAlive,
		MaxIdleTimeout: options.IdleTimeout, InitialPacketSize: uint16(options.InitialPacketSize),
		DisablePathMTUDiscovery: options.DisablePMTU,
	}
}

func validateH3Options(options H3Options) error {
	if options.ServerName == "" || options.Keys == nil || options.TimeWindow <= 0 {
		return errors.New("server name, keys, and positive time window are required")
	}
	if options.KeepAlive <= 0 || options.IdleTimeout <= 0 || options.InitialPacketSize < 1200 {
		return errors.New("invalid QUIC transport parameters")
	}
	return nil
}

func h3Authorization(key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("tlsnet/http3-tunnel/v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
