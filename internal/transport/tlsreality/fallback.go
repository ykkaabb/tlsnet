package tlsreality

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type Fallback struct {
	Target      string
	DialTimeout time.Duration
	MaxLifetime time.Duration
	MaxTotal    int
	MaxPerIP    int

	mu      sync.Mutex
	perIP   map[string]int
	current int
}

func (f *Fallback) Relay(ctx context.Context, client net.Conn, prefix []byte) error {
	if client == nil || f.Target == "" {
		return errors.New("fallback client and target are required")
	}
	ip := remoteIP(client.RemoteAddr())
	if !f.acquire(ip) {
		return errors.New("fallback connection limit reached")
	}
	defer f.release(ip)

	dialTimeout := f.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	upstream, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", f.Target)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if len(prefix) != 0 {
		if _, err := io.Copy(upstream, bytes.NewReader(prefix)); err != nil {
			return err
		}
	}
	if f.MaxLifetime > 0 {
		deadline := time.Now().Add(f.MaxLifetime)
		_ = client.SetDeadline(deadline)
		_ = upstream.SetDeadline(deadline)
	}

	errCh := make(chan error, 2)
	go copyHalf(upstream, client, errCh)
	go copyHalf(client, upstream, errCh)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func copyHalf(dst, src net.Conn, result chan<- error) {
	_, err := io.Copy(dst, src)
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	result <- err
}

func (f *Fallback) acquire(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.perIP == nil {
		f.perIP = make(map[string]int)
	}
	if f.MaxTotal > 0 && f.current >= f.MaxTotal {
		return false
	}
	if f.MaxPerIP > 0 && f.perIP[ip] >= f.MaxPerIP {
		return false
	}
	f.current++
	f.perIP[ip]++
	return true
}

func (f *Fallback) release(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.current--
	f.perIP[ip]--
	if f.perIP[ip] == 0 {
		delete(f.perIP, ip)
	}
}

func remoteIP(address net.Addr) string {
	if address == nil {
		return "unknown"
	}
	if tcp, ok := address.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		return host
	}
	return address.String()
}
