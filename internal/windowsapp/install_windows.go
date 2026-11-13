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

func requireElevated() error {
	token := windows.Token(0)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	if !token.IsElevated() {
		return errors.New("this operation requires administrator approval")
	}
	return nil
}

func installService(configPath, tokenPath string) error {
	if err := requireElevated(); err != nil {
		return err
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
	if err := protectServicePath(dataDirectory, true); err != nil {
		return fmt.Errorf("protect service data directory: %w", err)
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
	for _, name := range []string{"config.toml", "control.token", "control.port"} {
		if err := protectServicePath(filepath.Join(dataDirectory, name), false); err != nil {
			return fmt.Errorf("protect service data file %s: %w", name, err)
		}
	}
	logPath := filepath.Join(dataDirectory, "tlsnet.log")
	if _, err := os.Stat(logPath); err == nil {
		if err := protectServicePath(logPath, false); err != nil {
			return fmt.Errorf("protect service log: %w", err)
		}
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
	} else {
		output, configureErr := exec.Command("sc.exe", "config", serviceName, "start=", "auto").CombinedOutput()
		if configureErr != nil {
			service.Close()
			return fmt.Errorf("enable automatic startup: %w: %s", configureErr, strings.TrimSpace(string(output)))
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

func stopWindowsService(service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return fmt.Errorf("query service: %w", err)
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err := service.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		status, err = service.Query()
		if err != nil || status.State == svc.Stopped {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("timed out waiting for the service to stop")
}

func configureServiceStart(mode string) error {
	output, err := exec.Command("sc.exe", "config", serviceName, "start=", mode).CombinedOutput()
	if err != nil {
		return fmt.Errorf("configure service startup: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func manageService(action string) (string, error) {
	if err := requireElevated(); err != nil {
		return "", err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("connect service manager: %w", err)
	}
	defer manager.Disconnect()

	service, openErr := manager.OpenService(serviceName)
	if openErr != nil && action != "--service-uninstall" {
		return "", errors.New("TlsNet service is not installed")
	}

	switch action {
	case "--service-stop":
		defer service.Close()
		if err := stopWindowsService(service); err != nil {
			return "", err
		}
		return "后台服务已停止。本次开机期间不会运行；自动启动仍然保留，下次开机会再次启动。", nil

	case "--service-disable":
		defer service.Close()
		if err := stopWindowsService(service); err != nil {
			return "", err
		}
		if err := configureServiceStart("demand"); err != nil {
			return "", err
		}
		return "后台服务已停止，并已禁用开机自动启动。程序和配置均已保留。", nil

	case "--service-enable":
		defer service.Close()
		if err := configureServiceStart("auto"); err != nil {
			return "", err
		}
		status, queryErr := service.Query()
		if queryErr != nil {
			return "", fmt.Errorf("query service: %w", queryErr)
		}
		if status.State == svc.Stopped {
			if err := service.Start(); err != nil {
				return "", fmt.Errorf("start service: %w", err)
			}
		}
		return "已启用开机自动启动，后台服务正在运行。", nil

	case "--service-uninstall":
		if service != nil {
			if err := stopWindowsService(service); err != nil {
				service.Close()
				return "", err
			}
			if err := service.Delete(); err != nil {
				service.Close()
				return "", fmt.Errorf("delete service: %w", err)
			}
			service.Close()
		}
		_ = exec.Command("schtasks.exe", "/Delete", "/TN", serviceName, "/F").Run()

		programFiles := os.Getenv("ProgramFiles")
		if programFiles == "" {
			return "", errors.New("ProgramFiles is not set")
		}
		dataDirectory, err := programDataDirectory()
		if err != nil {
			return "", err
		}
		localDirectory, err := localDataDirectory()
		if err != nil {
			return "", err
		}
		var removalErrors []string
		for _, directory := range []string{
			filepath.Join(programFiles, "TlsNet"),
			dataDirectory,
			localDirectory,
		} {
			if err := os.RemoveAll(directory); err != nil {
				removalErrors = append(removalErrors, directory+": "+err.Error())
			}
		}
		if len(removalErrors) > 0 {
			return "", fmt.Errorf("service was removed, but some files could not be deleted:\n%s", strings.Join(removalErrors, "\n"))
		}
		return "TlsNet 后台服务、开机自启、虚拟网卡配置和本机配置数据均已删除。你下载到其他目录的安装程序可直接手动删除。", nil
	default:
		if service != nil {
			service.Close()
		}
		return "", errors.New("unknown service operation")
	}
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

func protectServicePath(path string, directory bool) error {
	// Protected DACL: LocalSystem and built-in Administrators have full access.
	// Apply an inheritable ACL to the directory and explicit ACLs to existing
	// files so upgrades also repair permissions left by older installers.
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	if directory {
		sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
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
	data, err := controlRequestAt(controlAddress, method, endpoint, body, token)
	if err == nil || method != "GET" || controlAddress == net.JoinHostPort("127.0.0.1", strconv.Itoa(fallbackControlPort)) {
		return data, err
	}
	// Older installations can fall back to the built-in port when their
	// protected port file is unreadable. Discover that listener on safe GETs,
	// then persist the address so later POST operations use the same endpoint.
	fallbackAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(fallbackControlPort))
	data, fallbackErr := controlRequestAt(fallbackAddress, method, endpoint, body, token)
	if fallbackErr != nil {
		return nil, fmt.Errorf("configured control endpoint failed (%v); fallback endpoint failed (%w)", err, fallbackErr)
	}
	_ = os.WriteFile(filepath.Join(localDirectory, "control.port"), []byte(strconv.Itoa(fallbackControlPort)), 0o600)
	return data, nil
}

func controlRequestAt(controlAddress, method, endpoint string, body io.Reader, token string) ([]byte, error) {
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

func launchElevatedAction(action string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(executable)
	parameters, _ := windows.UTF16PtrFromString(action)
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
