//go:build windows

package windowsapp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ykkaabb/tlsnet/internal/app"
	"github.com/ykkaabb/tlsnet/internal/config"
	"golang.org/x/sys/windows/svc"
)

const (
	serviceName = "TlsNet"
	fallbackControlPort = 24831
)

type serviceHandler struct{}

type tunnelController struct {
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	running   bool
	lastError string
	startedAt time.Time
	logPath   string
}

type statusResponse struct {
	Service   string `json:"service"`
	Tunnel    string `json:"tunnel"`
	LastError string `json:"last_error,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
}

func runService() error {
	return svc.Run(serviceName, serviceHandler{})
}

func (serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	data, err := programDataDirectory()
	if err != nil {
		return true, 1
	}
	tokenBytes, _ := os.ReadFile(filepath.Join(data, "control.token"))
	controlAddress := controlAddressFromDirectory(data)
	controller := &tunnelController{logPath: filepath.Join(data, "tlsnet.log")}
	api := &http.Server{
		Addr:              controlAddress,
		Handler:           controlHandler(controller, string(tokenBytes), data),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	listener, listenErr := net.Listen("tcp", controlAddress)
	if listenErr != nil {
		return true, 2
	}
	go func() { _ = api.Serve(listener) }()
	if _, err := os.Stat(filepath.Join(data, "config.toml")); err == nil {
		if err := controller.start(); err != nil {
			_ = listener.Close()
			return true, 3
		}
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			changes <- request.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			controller.stop()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = api.Shutdown(ctx)
			cancel()
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}

func controlHandler(controller *tunnelController, token, dataDirectory string) http.Handler {
	mux := http.NewServeMux()
	authorized := func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			provided := request.Header.Get("X-TlsNet-Token")
			if token == "" || len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
				http.Error(writer, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(writer, request)
		}
	}
	mux.HandleFunc("GET /status", authorized(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, controller.status())
	}))
	mux.HandleFunc("POST /start", authorized(func(writer http.ResponseWriter, _ *http.Request) {
		if err := controller.start(); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(writer, controller.status())
	}))
	mux.HandleFunc("POST /stop", authorized(func(writer http.ResponseWriter, _ *http.Request) {
		controller.stop()
		writeJSON(writer, controller.status())
	}))
	mux.HandleFunc("POST /config", authorized(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 1024*1024))
		if err != nil {
			http.Error(writer, "configuration is too large", http.StatusBadRequest)
			return
		}
		if _, err := config.Parse(body); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if err := replaceFile(filepath.Join(dataDirectory, "config.toml"), body, 0o600); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		controller.stop()
		if err := controller.start(); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(writer, controller.status())
	}))
	mux.HandleFunc("GET /logs", authorized(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		contents, err := tailFile(controller.logPath, 256*1024)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = writer.Write(contents)
	}))
	return mux
}

func (controller *tunnelController) start() error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.running {
		return nil
	}
	data, err := programDataDirectory()
	if err != nil {
		return err
	}
	cfg, err := config.Load(filepath.Join(data, "config.toml"))
	if err != nil {
		controller.lastError = err.Error()
		return err
	}
	if err := os.MkdirAll(filepath.Dir(controller.logPath), 0o700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(controller.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	level := new(slog.Level)
	if err := level.UnmarshalText([]byte(cfg.Logging.Level)); err != nil {
		_ = logFile.Close()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	controller.cancel = cancel
	controller.done = done
	controller.running = true
	controller.lastError = ""
	controller.startedAt = time.Now()
	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: level}))
	go func() {
		err := app.Run(ctx, cfg, logger)
		_ = logFile.Close()
		controller.mu.Lock()
		if controller.done == done {
			controller.running = false
			controller.cancel = nil
			controller.done = nil
			if err != nil && ctx.Err() == nil {
				controller.lastError = err.Error()
			}
		}
		controller.mu.Unlock()
		close(done)
	}()
	return nil
}

func (controller *tunnelController) stop() {
	controller.mu.Lock()
	cancel := controller.cancel
	done := controller.done
	controller.cancel = nil
	controller.done = nil
	controller.running = false
	controller.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

func (controller *tunnelController) status() statusResponse {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	result := statusResponse{Service: "running", Tunnel: "stopped", LastError: controller.lastError}
	if controller.running {
		result.Tunnel = "running"
		result.StartedAt = controller.startedAt.Format(time.RFC3339)
	}
	return result
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func replaceFile(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	_ = os.Remove(path)
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func tailFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	offset := info.Size() - maximum
	if offset < 0 {
		offset = 0
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func programDataDirectory() (string, error) {
	root := os.Getenv("ProgramData")
	if root == "" {
		return "", fmt.Errorf("ProgramData is not set")
	}
	return filepath.Join(root, "TlsNet"), nil
}
