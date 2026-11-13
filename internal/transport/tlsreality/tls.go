package tlsreality

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ykkaabb/tlsnet/internal/auth"
)

const ALPN = "tlsnet/1"

type ClientOptions struct {
	ServerName string
	Keys       *auth.Keys
	TimeWindow time.Duration
	Now        func() time.Time
}

type ServerOptions struct {
	ServerName string
	Keys       *auth.Keys
	TimeWindow time.Duration
	Now        func() time.Time
	Lifetime   time.Duration
}

func Client(conn net.Conn, options ClientOptions) (*tls.Conn, error) {
	if conn == nil || options.Keys == nil || options.ServerName == "" || options.TimeWindow <= 0 {
		return nil, errors.New("connection, keys, server name, and positive time window are required")
	}
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	token, err := auth.NewTCPToken(options.Keys.TCPRoute[:], now(), options.TimeWindow, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("create TCP route token: %w", err)
	}
	config := &tls.Config{
		ServerName:         options.ServerName,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPN},
		InsecureSkipVerify: true,
		Rand:               &prefixReader{prefix: token[:], source: rand.Reader},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			return auth.VerifyServerCertificate(state.PeerCertificates[0], options.ServerName, options.Keys.Certificate[:], now(), options.TimeWindow)
		},
	}
	return tls.Client(conn, config), nil
}

func ServerConfig(options ServerOptions) (*tls.Config, error) {
	if options.Keys == nil || options.ServerName == "" || options.TimeWindow <= 0 {
		return nil, errors.New("keys, server name, and positive time window are required")
	}
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	if options.Lifetime <= 0 {
		options.Lifetime = 6 * time.Hour
	}
	manager, err := auth.NewCertificateManager(
		options.ServerName, options.Keys.Certificate[:], options.Lifetime, options.Lifetime/6, now,
	)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		NextProtos:     []string{ALPN},
		GetCertificate: manager.GetCertificate,
	}, nil
}

func IsAuthorized(hello ClientHello, options ServerOptions) bool {
	if options.Keys == nil || options.TimeWindow <= 0 || !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), strings.TrimSuffix(options.ServerName, ".")) {
		return false
	}
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	return auth.VerifyTCPToken(hello.Random[:], options.Keys.TCPRoute[:], now(), options.TimeWindow)
}

func HandshakeServer(ctx context.Context, conn net.Conn, hello ClientHello, config *tls.Config) (*tls.Conn, error) {
	if conn == nil || config == nil {
		return nil, errors.New("connection and TLS config are required")
	}
	tlsConn := tls.Server(&replayConn{Conn: conn, replay: hello.Raw}, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != ALPN {
		return nil, errors.New("TLSNet ALPN was not negotiated")
	}
	return tlsConn, nil
}

type replayConn struct {
	net.Conn
	mu     sync.Mutex
	replay []byte
}

func (c *replayConn) Read(dst []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.replay) != 0 {
		n := copy(dst, c.replay)
		c.replay = c.replay[n:]
		return n, nil
	}
	return c.Conn.Read(dst)
}

type prefixReader struct {
	mu     sync.Mutex
	prefix []byte
	source io.Reader
}

func (r *prefixReader) Read(dst []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.prefix) != 0 {
		n := copy(dst, r.prefix)
		r.prefix = r.prefix[n:]
		if n == len(dst) {
			return n, nil
		}
		more, err := r.source.Read(dst[n:])
		return n + more, err
	}
	return r.source.Read(dst)
}
