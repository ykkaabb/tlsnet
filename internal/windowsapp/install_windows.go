//go:build windows

package windowsapp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ykkaabb/tlsnet/internal/config"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func localDataDirectory() (string, error) {
	root := os.Getenv("LOCALAPPDATA")
	if root == "" {
		return "", errors.New("LOCALAPPDATA is not set")
	}
	return filepath.Join(root, "TlsNet"), nil
}

func ensureLocalToken() (string, string, error) {
	directory, err := localDataDirectory()
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", "", err
	}
	path := filepath.Join(directory, "control.token")
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) == 64 {
		if _, err := ensureControlPort(directory); err != nil {
			return "", "", err
		}
		return strings.TrimSpace(string(data)), path, nil
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(value)
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		return "", "", err
	}
	if _, err := ensureControlPort(directory); err != nil {
		return "", "", err
	}
	return token, path, nil
}

func ensureControlPort(directory string) (int, error) {
	path := filepath.Join(directory, "control.port")
	if data, err := os.ReadFile(path); err == nil {
		if port, parseErr := strconv.Atoi(strings.TrimSpace(string(data))); parseErr == nil && port >= 1024 && port <= 65535 {
			return port, nil
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("choose control port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	if err := os.WriteFile(path, []byte(strconv.Itoa(port)), 0o600); err != nil {
		return 0, err
	}
	return port, nil
}

func readLocalToken() (string, error) {
	directory, err := localDataDirectory()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(directory, "control.token"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func installService(configPath, tokenPath string) error {
	token := windows.Token(0)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	if !token.IsElevated() {
		return errors.New("installation requires administrator approval")
	}

	configuration, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read pending configuration: %w", err)
	}
	if _, err := config.Parse(configuration); err != nil {
		return fmt.Errorf("invalid pending configuration: %w", err)
	}
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("read control token: %w", err)
	}
	if len(strings.TrimSpace(string(tokenBytes))) != 64 {
		return errors.New("invalid control token")
	}
	portBytes, err := os.ReadFile(filepath.Join(filepath.Dir(tokenPath), "control.port"))
	if err != nil {
		return fmt.Errorf("read control port: %w", err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(string(portBytes)))
	if err != nil || port < 1024 || port > 65535 {
		return errors.New("invalid control port")
	}

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if len(embeddedWintun) == 0 {
		return errors.New("the application does not contain the Wintun driver")
	}
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		return errors.New("ProgramFiles is not set")
	}
	installDirectory := filepath.Join(programFiles, "TlsNet")
	dataDirectory, err := programDataDirectory()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(installDirectory, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDirectory, 0o700); err != nil {
		return err
	}

	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()
	existing, _ := manager.OpenService(serviceName)
	if existing != nil {
		status, queryErr := existing.Query()
		if queryErr == nil && status.State != svc.Stopped {
			_, _ = existing.Control(svc.Stop)
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				status, queryErr = existing.Query()
				if queryErr != nil || status.State == svc.Stopped {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
		}
		existing.Close()
	}
	// Remove the legacy elevated scheduled task used by script-based releases.
	_ = exec.Command("schtasks.exe", "/Delete", "/TN", serviceName, "/F").Run()

	installedExecutable := filepath.Join(installDirectory, "TlsNet.exe")
	if err := copyFile(executable, installedExecutable); err != nil {
		return fmt.Errorf("install application: %w", err)
	}
	if err := os.WriteFile(filepath.Join(installDirectory, "wintun.dll"), embeddedWintun, 0o644); err != nil {
		return fmt.Errorf("install Wintun: %w", err)
	}
	if err := os.WriteFile(filepath.Join(installDirectory, "WINTUN-LICENSE.txt"), embeddedWintunLicense, 0o644); err != nil {
		return fmt.Errorf("install Wintun license: %w", err)
	}
	if err := replaceFile(filepath.Join(dataDirectory, "config.toml"), configuration, 0o600); err != nil {
		return err
	}
	if err := replaceFile(filepath.Join(dataDirectory, "control.token"), []byte(strings.TrimSpace(string(tokenBytes))), 0o600); err != nil {
		return err
	}
	if err := replaceFile(filepath.Join(dataDirectory, "control.port"), []byte(strconv.Itoa(port)), 0o600); err != nil {
		return err
	}
	aclOutput, aclErr := exec.Command(
		"icacls.exe", dataDirectory, "/inheritance:r", "/grant:r",
		"*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C",
	).CombinedOutput()
	if aclErr != nil {
		return fmt.Errorf("protect service data: %w: %s", aclErr, strings.TrimSpace(string(aclOutput)))
	}

	service, openErr := manager.OpenService(serviceName)
	if openErr != nil {
		service, err = manager.CreateService(serviceName, installedExecutable, mgr.Config{
			DisplayName: "TlsNet Virtual Network",
			Description: "TlsNet encrypted virtual network service",
			StartType:   mgr.StartAutomatic,
		}, "service")
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
	}
	defer service.Close()
	if err := service.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	var healthErr error
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, healthErr = controlRequest("GET", "/status", nil); healthErr == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if healthErr != nil {
		return fmt.Errorf("service started but health check failed: %w", healthErr)
	}
	_ = os.Remove(configPath)
	return nil
}

func copyFile(source, destination string) error {
	sourcePath, _ := filepath.Abs(source)
	destinationPath, _ := filepath.Abs(destination)
	if strings.EqualFold(sourcePath, destinationPath) {
		return nil
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.Create(destination)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func controlRequest(method, endpoint string, body io.Reader) ([]byte, error) {
	token, err := readLocalToken()
	if err != nil {
		return nil, err
	}
	localDirectory, err := localDataDirectory()
	if err != nil {
		return nil, err
	}
	controlAddress := controlAddressFromDirectory(localDirectory)
	request, err := http.NewRequest(method, "http://"+controlAddress+endpoint, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-TlsNet-Token", token)
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if readErr != nil {
		return nil, readErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("service returned %s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func controlAddressFromDirectory(directory string) string {
	port := fallbackControlPort
	if data, err := os.ReadFile(filepath.Join(directory, "control.port")); err == nil {
		if parsed, parseErr := strconv.Atoi(strings.TrimSpace(string(data))); parseErr == nil && parsed >= 1024 && parsed <= 65535 {
			port = parsed
		}
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func launchElevated(configPath, tokenPath string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(executable)
	parameters, _ := windows.UTF16PtrFromString(fmt.Sprintf("--install %q %q", configPath, tokenPath))
	directory, _ := windows.UTF16PtrFromString(filepath.Dir(executable))
	err = windows.ShellExecute(0, verb, file, parameters, directory, windows.SW_SHOWNORMAL)
	if err != nil {
		return fmt.Errorf("administrator approval was cancelled or failed: %w", err)
	}
	return nil
}

func openTextInNotepad(contents []byte) error {
	directory, err := localDataDirectory()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	path := filepath.Join(directory, "latest.log")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		return err
	}
	return exec.Command("notepad.exe", path).Start()
}
