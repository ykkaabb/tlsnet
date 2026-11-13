package mobilecore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"

	"github.com/ykkaabb/tlsnet/internal/auth"
	"github.com/ykkaabb/tlsnet/internal/config"
)

type Engine struct {
	mu        sync.Mutex
	config    *config.Config
	keys      *auth.Keys
	session   packetSession
	cancel    context.CancelFunc
	tun       *os.File
	status    string
	lastError string
}

type sessionInfo struct {
	Address   string
	MTU       int
	Routes    []string
	Transport string
}

func NewEngine(configText string) (*Engine, error) {
	cfg, err := config.Parse([]byte(configText))
	if err != nil {
		return nil, err
	}
	if cfg.Node.Role != "client" {
		return nil, errors.New("Android supports the client role only")
	}
	for _, route := range cfg.Overlay.AcceptRoutes {
		prefix := netip.MustParsePrefix(route)
		if prefix.Bits() == 0 {
			return nil, errors.New("Android currently supports split routes only; 0.0.0.0/0 is not allowed")
		}
	}
	keys, err := auth.Derive(cfg.Auth.Password, cfg.Auth.NetworkName, cfg.Reality.ServerName, auth.KDFParams{
		MemoryMiB: cfg.Auth.KDFMemoryMiB, Iterations: cfg.Auth.KDFIterations, Parallelism: cfg.Auth.KDFParallelism,
	})
	if err != nil {
		return nil, err
	}
	return &Engine{config: cfg, keys: keys, status: "idle"}, nil
}

func (e *Engine) Prepare() (string, error) {
	e.mu.Lock()
	if e.session != nil {
		e.mu.Unlock()
		return "", errors.New("engine is already prepared")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.status = "connecting"
	e.lastError = ""
	e.mu.Unlock()

	session, err := connectMobile(ctx, e.config, e.keys)
	if err != nil {
		cancel()
		e.setError(err)
		return "", err
	}
	info := sessionInfo{
		Address: session.Welcome().Address, MTU: session.Welcome().MTU,
		Routes: append([]string(nil), e.config.Overlay.AcceptRoutes...), Transport: session.Transport(),
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		_ = session.Close()
		cancel()
		e.setError(err)
		return "", err
	}
	e.mu.Lock()
	e.session = session
	e.status = "prepared"
	e.mu.Unlock()
	return string(encoded), nil
}

func (e *Engine) Run(tunFD int) error {
	if tunFD < 0 {
		return errors.New("invalid VPN file descriptor")
	}
	e.mu.Lock()
	if e.session == nil || e.cancel == nil {
		e.mu.Unlock()
		return errors.New("call Prepare before Run")
	}
	if e.tun != nil {
		e.mu.Unlock()
		return errors.New("engine is already running")
	}
	file := os.NewFile(uintptr(tunFD), "tlsnet-vpn")
	if file == nil {
		e.mu.Unlock()
		return errors.New("could not take ownership of VPN file descriptor")
	}
	e.tun = file
	e.status = "running"
	session := e.session
	e.mu.Unlock()

	errorsChannel := make(chan error, 2)
	go pumpTunToSession(file, session, errorsChannel)
	go pumpSessionToTun(file, session, errorsChannel)
	err := <-errorsChannel
	if errors.Is(err, context.Canceled) || errors.Is(err, os.ErrClosed) {
		err = nil
	}
	if err != nil {
		e.setError(err)
	}
	e.Stop()
	return err
}

func (e *Engine) Stop() {
	e.mu.Lock()
	cancel := e.cancel
	session := e.session
	file := e.tun
	e.cancel = nil
	e.session = nil
	e.tun = nil
	if e.status != "error" {
		e.status = "stopped"
	}
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if file != nil {
		_ = file.Close()
	}
	if session != nil {
		_ = session.Close()
	}
}

func (e *Engine) Status() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

func (e *Engine) LastError() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastError
}

func (e *Engine) setError(err error) {
	e.mu.Lock()
	e.status = "error"
	e.lastError = err.Error()
	e.mu.Unlock()
}

func pumpTunToSession(tun io.Reader, session packetSession, result chan<- error) {
	buffer := make([]byte, 65535)
	for {
		n, err := tun.Read(buffer)
		if err != nil {
			result <- err
			return
		}
		if n == 0 {
			continue
		}
		packet := append([]byte(nil), buffer[:n]...)
		if err := session.Send(packet); err != nil {
			result <- fmt.Errorf("send overlay packet: %w", err)
			return
		}
	}
}

func pumpSessionToTun(tun io.Writer, session packetSession, result chan<- error) {
	for {
		packet, err := session.Receive()
		if err != nil {
			result <- fmt.Errorf("receive overlay packet: %w", err)
			return
		}
		if _, err := tun.Write(packet); err != nil {
			result <- err
			return
		}
	}
}
