//go:build windows

package windowsapp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/ykkaabb/tlsnet/internal/config"
	"github.com/ykkaabb/tlsnet/internal/enroll"
	"golang.org/x/sys/windows"
)

var (
	user32                 = windows.NewLazySystemDLL("user32.dll")
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	gdi32                  = windows.NewLazySystemDLL("gdi32.dll")
	procRegisterClassExW   = user32.NewProc("RegisterClassExW")
	procCreateWindowExW    = user32.NewProc("CreateWindowExW")
	procDefWindowProcW     = user32.NewProc("DefWindowProcW")
	procShowWindow         = user32.NewProc("ShowWindow")
	procUpdateWindow       = user32.NewProc("UpdateWindow")
	procGetMessageW        = user32.NewProc("GetMessageW")
	procTranslateMessage   = user32.NewProc("TranslateMessage")
	procDispatchMessageW   = user32.NewProc("DispatchMessageW")
	procPostQuitMessage    = user32.NewProc("PostQuitMessage")
	procDestroyWindow      = user32.NewProc("DestroyWindow")
	procSendMessageW       = user32.NewProc("SendMessageW")
	procSetWindowTextW     = user32.NewProc("SetWindowTextW")
	procEnableWindow      = user32.NewProc("EnableWindow")
	procGetWindowTextW     = user32.NewProc("GetWindowTextW")
	procGetWindowTextLenW  = user32.NewProc("GetWindowTextLengthW")
	procMessageBoxW        = user32.NewProc("MessageBoxW")
	procLoadCursorW        = user32.NewProc("LoadCursorW")
	procGetModuleHandleW   = kernel32.NewProc("GetModuleHandleW")
	procGetStockObject     = gdi32.NewProc("GetStockObject")
	mainWindow      uintptr
	joinEdit        uintptr
	passwordEdit    uintptr
	nodeEdit        uintptr
	statusLabel     uintptr
	saveButton      uintptr
	startButton     uintptr
	stopButton      uintptr
	logsButton      uintptr
	serviceNeedsUpgrade bool
)

const (
	className = "TlsNetWindow"

	windowOverlapped  = 0x00CF0000
	windowChild       = 0x40000000
	windowVisible     = 0x10000000
	windowBorder      = 0x00800000
	windowTabStop     = 0x00010000
	windowVScroll     = 0x00200000
	editMultiLine     = 0x0004
	editAutoVScroll   = 0x0040
	editWantReturn    = 0x1000
	editPassword      = 0x0020
	buttonDefault     = 0x00000001
	colorWindow       = 5
	defaultGUIFont    = 17
	cursorArrow       = 32512
	showNormal        = 1
	wmCreate          = 0x0001
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmCommand         = 0x0111
	wmSetFont         = 0x0030
	messageInfo       = 0x00000040
	messageError      = 0x00000010
	messageWarning    = 0x00000030
	messageYesNo      = 0x00000004
	messageSetForeground = 0x00010000
	dialogYes         = 6

	idJoin    = 100
	idPassword = 101
	idNode     = 102
	idStatus   = 103
	idSave           = 200
	idStop           = 201
	idRefresh        = 202
	idLogs           = 203
	idServiceStop    = 204
	idServiceDisable = 205
	idServiceEnable  = 206
	idUninstall      = 207
	idStart          = 208
)

type point struct {
	x int32
	y int32
}

type message struct {
	hwnd     uintptr
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	point    point
	private  uint32
}

type windowClass struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	classExtra int32
	windowExtra int32
	instance   uintptr
	icon       uintptr
	cursor     uintptr
	background uintptr
	menuName   *uint16
	className  *uint16
	iconSmall  uintptr
}

func runGUI(version string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	instance, _, _ := procGetModuleHandleW.Call(0)
	classPointer := utf16(className)
	cursor, _, _ := procLoadCursorW.Call(0, cursorArrow)
	class := windowClass{
		size: uint32(unsafe.Sizeof(windowClass{})), wndProc: syscall.NewCallback(windowProcedure),
		instance: instance, cursor: cursor, background: colorWindow + 1, className: classPointer,
	}
	registered, _, registerErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&class)))
	if registered == 0 {
		return registerErr
	}
	title := fmt.Sprintf("TlsNet %s", version)
	mainWindow, _, _ = procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(classPointer)), uintptr(unsafe.Pointer(utf16(title))), windowOverlapped,
		0x80000000, 0x80000000, 680, 650, 0, 0, instance, 0,
	)
	if mainWindow == 0 {
		return windows.GetLastError()
	}
	procShowWindow.Call(mainWindow, showNormal)
	procUpdateWindow.Call(mainWindow)
	loadFormState()
	refreshStatus()
	var current message
	for {
		result, _, err := procGetMessageW.Call(uintptr(unsafe.Pointer(&current)), 0, 0, 0)
		if int32(result) == -1 {
			return err
		}
		if result == 0 {
			return nil
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&current)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&current)))
	}
}

func windowProcedure(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	switch message {
	case wmCreate:
		createControls(hwnd)
		return 0
	case wmCommand:
		switch uint16(wParam & 0xffff) {
		case idSave:
			if serviceNeedsUpgrade {
				upgradeInstalledService()
			} else {
				saveConfigurationFromForm()
			}
		case idStart:
			if _, err := controlRequest("POST", "/start", nil); err != nil {
				messageBox("TlsNet", err.Error(), messageError)
			}
			refreshStatus()
		case idStop:
			if _, err := controlRequest("POST", "/stop", nil); err != nil {
				messageBox("TlsNet", err.Error(), messageError)
			}
			refreshStatus()
		case idRefresh:
			refreshStatus()
		case idLogs:
			contents, err := controlRequest("GET", "/logs", nil)
			if err != nil {
				messageBox("TlsNet", "后台服务尚未就绪，暂时无法读取日志。\n\n"+err.Error(), messageError)
			} else if err := openTextInNotepad(contents); err != nil {
				messageBox("TlsNet", err.Error(), messageError)
			}
		case idServiceStop:
			runElevatedServiceAction(
				"--service-stop",
				"停止 TlsNet 后台服务",
				"停止后，本次开机期间 TlsNet 不再运行；开机自启仍保留，下次开机会再次启动。\n\n是否继续？",
			)
		case idServiceDisable:
			runElevatedServiceAction(
				"--service-disable",
				"禁用 TlsNet 开机自启",
				"这会立即停止后台服务，并禁用开机自动启动。程序和配置会保留，之后可以在这里重新启用。\n\n是否继续？",
			)
		case idServiceEnable:
			runElevatedServiceAction(
				"--service-enable",
				"启用 TlsNet 开机自启",
				"这会启用开机自动启动，并立即启动后台服务。\n\n是否继续？",
			)
		case idUninstall:
			runElevatedServiceAction(
				"--service-uninstall",
				"彻底卸载 TlsNet",
				"这会停止并删除后台服务，同时删除 TlsNet 的程序副本、虚拟网卡配置、网络配置、日志和本机凭据。\n\n你单独下载的这个安装程序不会被删除。此操作不可撤销，是否继续？",
			)
		}
		return 0
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	result, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return result
}

func createControls(hwnd uintptr) {
	font, _, _ := procGetStockObject.Call(defaultGUIFont)
	createControl("STATIC", "节点名称", windowChild|windowVisible, 24, 22, 110, 24, hwnd, 0, font)
	nodeEdit = createControl("EDIT", hostname(), windowChild|windowVisible|windowBorder|windowTabStop, 135, 18, 500, 28, hwnd, idNode, font)
	createControl("STATIC", "Join code", windowChild|windowVisible, 24, 62, 110, 24, hwnd, 0, font)
	joinEdit = createControl("EDIT", "", windowChild|windowVisible|windowBorder|windowTabStop|windowVScroll|editMultiLine|editAutoVScroll|editWantReturn, 24, 88, 611, 190, hwnd, idJoin, font)
	createControl("STATIC", "网络密码", windowChild|windowVisible, 24, 296, 110, 24, hwnd, 0, font)
	passwordEdit = createControl("EDIT", "", windowChild|windowVisible|windowBorder|windowTabStop|editPassword, 135, 292, 500, 28, hwnd, idPassword, font)
	statusLabel = createControl("STATIC", "状态：正在检查……", windowChild|windowVisible, 24, 345, 611, 58, hwnd, idStatus, font)
	saveButton = createControl("BUTTON", "安装并连接", windowChild|windowVisible|windowTabStop|buttonDefault, 24, 420, 150, 38, hwnd, idSave, font)
	startButton = createControl("BUTTON", "连接隧道", windowChild|windowVisible|windowTabStop, 186, 420, 100, 38, hwnd, idStart, font)
	stopButton = createControl("BUTTON", "断开隧道", windowChild|windowVisible|windowTabStop, 298, 420, 100, 38, hwnd, idStop, font)
	createControl("BUTTON", "刷新状态", windowChild|windowVisible|windowTabStop, 410, 420, 100, 38, hwnd, idRefresh, font)
	logsButton = createControl("BUTTON", "查看日志", windowChild|windowVisible|windowTabStop, 522, 420, 113, 38, hwnd, idLogs, font)
	createControl("BUTTON", "停止服务", windowChild|windowVisible|windowTabStop, 24, 480, 140, 38, hwnd, idServiceStop, font)
	createControl("BUTTON", "禁用自启", windowChild|windowVisible|windowTabStop, 181, 480, 140, 38, hwnd, idServiceDisable, font)
	createControl("BUTTON", "启用自启", windowChild|windowVisible|windowTabStop, 338, 480, 140, 38, hwnd, idServiceEnable, font)
	createControl("BUTTON", "彻底卸载", windowChild|windowVisible|windowTabStop, 495, 480, 140, 38, hwnd, idUninstall, font)
	createControl("STATIC", "安装、服务管理和卸载会请求管理员权限；普通连接与查看状态不需要。", windowChild|windowVisible, 24, 545, 611, 40, hwnd, 0, font)
}

func createControl(class, text string, style uintptr, x, y, width, height int, parent uintptr, id uint16, font uintptr) uintptr {
	handle, _, _ := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(utf16(class))), uintptr(unsafe.Pointer(utf16(text))), style,
		uintptr(x), uintptr(y), uintptr(width), uintptr(height), parent, uintptr(id), 0, 0)
	if handle != 0 && font != 0 {
		procSendMessageW.Call(handle, wmSetFont, font, 1)
	}
	return handle
}

func saveConfigurationFromForm() {
	node := strings.TrimSpace(windowText(nodeEdit))
	joinText := strings.TrimSpace(windowText(joinEdit))
	password := windowText(passwordEdit)
	if node == "" || joinText == "" || password == "" {
		messageBox("TlsNet", "请填写节点名称、join code 和网络密码。", messageError)
		return
	}
	joinCode, err := enroll.Decode(joinText)
	if err != nil {
		messageBox("TlsNet", err.Error(), messageError)
		return
	}
	cfg, err := enroll.Build("client", node, password, "", joinCode)
	if err != nil {
		messageBox("TlsNet", err.Error(), messageError)
		return
	}
	encoded, err := config.Encode(cfg)
	if err != nil {
		messageBox("TlsNet", err.Error(), messageError)
		return
	}
	if err := saveFormState(guiFormState{Node: node, JoinCode: joinText, Password: password}); err != nil {
		messageBox("TlsNet", "保存界面配置失败：\n"+err.Error(), messageError)
		return
	}
	if _, err := controlRequest("GET", "/status", nil); err == nil {
		if _, err := controlRequest("POST", "/config", bytes.NewReader(encoded)); err != nil {
			messageBox("TlsNet", err.Error(), messageError)
			return
		}
		setWindowText(statusLabel, "状态：配置已保存")
		refreshStatus()
		return
	}
	_, tokenPath, err := ensureLocalToken()
	if err != nil {
		messageBox("TlsNet", err.Error(), messageError)
		return
	}
	localDirectory, err := localDataDirectory()
	if err != nil {
		messageBox("TlsNet", err.Error(), messageError)
		return
	}
	pending := filepath.Join(localDirectory, "pending.toml")
	if err := os.WriteFile(pending, encoded, 0o600); err != nil {
		messageBox("TlsNet", err.Error(), messageError)
		return
	}
	if !confirmBox(
		"安装 TlsNet 后台服务",
		"首次连接需要安装 Wintun 虚拟网卡和以 LocalSystem 运行的 TlsNet 后台服务。\n\n是否继续？",
	) {
		return
	}
	if err := launchElevated(pending, tokenPath); err != nil {
		messageBox("TlsNet", err.Error(), messageError)
		return
	}
	enableControl(saveButton, false)
	enableControl(startButton, false)
	enableControl(stopButton, false)
	setWindowText(statusLabel, "状态：等待管理员确认并安装后台服务；完成后点击“刷新状态”")
}

func runElevatedServiceAction(action, title, prompt string) {
	if !confirmBox(title, prompt) {
		return
	}
	if err := launchElevatedAction(action); err != nil {
		messageBox("TlsNet", err.Error(), messageError)
		return
	}
	setWindowText(statusLabel, "状态：系统正在执行服务操作；完成后点击“刷新状态”")
}

func upgradeInstalledService() {
	if !confirmBox(
		"升级 TlsNet 后台服务",
		"将使用当前程序覆盖旧后台服务，同时保留现有网络配置、密码、控制端口和开机自启设置。\n\n是否继续？",
	) {
		return
	}
	if err := launchElevatedAction("--upgrade"); err != nil {
		messageBox("TlsNet", err.Error(), messageError)
		return
	}
	enableControl(saveButton, false)
	enableControl(startButton, false)
	enableControl(stopButton, false)
	setWindowText(statusLabel, "状态：正在升级后台服务；完成后点击“刷新状态”")
}

func refreshStatus() {
	previouslyNeededUpgrade := serviceNeedsUpgrade
	data, err := controlRequest("GET", "/status", nil)
	if err != nil {
		serviceNeedsUpgrade = false
		setWindowText(statusLabel, "状态：尚未安装，或后台服务未运行")
		setWindowText(saveButton, "安装并连接")
		enableControl(saveButton, true)
		enableControl(startButton, false)
		enableControl(stopButton, false)
		enableControl(logsButton, false)
		return
	}
	var status statusResponse
	if err := json.Unmarshal(data, &status); err != nil {
		setWindowText(statusLabel, "状态：后台服务响应异常")
		return
	}
	serviceNeedsUpgrade = status.Version == "" || status.Version != applicationVersion
	if serviceNeedsUpgrade {
		setWindowText(saveButton, "升级并保留配置")
	} else {
		setWindowText(saveButton, "保存配置")
		if previouslyNeededUpgrade && strings.TrimSpace(windowText(joinEdit)) == "" {
			loadFormState()
		}
	}
	enableControl(saveButton, true)
	enableControl(logsButton, true)
	enableControl(startButton, status.Tunnel != "running")
	enableControl(stopButton, status.Tunnel == "running")
	text := "状态：服务已运行；隧道=" + status.Tunnel
	if status.LastError != "" {
		text += "；错误=" + status.LastError
	}
	setWindowText(statusLabel, text)
}

type guiFormState struct {
	Node     string `json:"node"`
	JoinCode string `json:"join_code"`
	Password string `json:"password"`
}

func loadFormState() {
	if state, err := readFormState(); err == nil {
		applyFormState(state)
		return
	}
	var encoded []byte
	if data, err := controlRequest("GET", "/config", nil); err == nil {
		encoded = data
	} else if directory, dirErr := localDataDirectory(); dirErr == nil {
		encoded, _ = os.ReadFile(filepath.Join(directory, "pending.toml"))
	}
	if len(encoded) == 0 {
		return
	}
	cfg, err := config.Parse(encoded)
	if err != nil || cfg.Node.Role != "client" {
		return
	}
	joinCode, err := joinCodeFromClientConfig(cfg)
	if err != nil {
		return
	}
	state := guiFormState{Node: cfg.Node.Name, JoinCode: joinCode, Password: cfg.Auth.Password}
	applyFormState(state)
	_ = saveFormState(state)
}

func applyFormState(state guiFormState) {
	if strings.TrimSpace(state.Node) != "" {
		setWindowText(nodeEdit, state.Node)
	}
	setWindowText(joinEdit, state.JoinCode)
	setWindowText(passwordEdit, state.Password)
}

func joinCodeFromClientConfig(cfg *config.Config) (string, error) {
	pool := strings.TrimSpace(cfg.Overlay.Pool)
	homeSubnet := ""
	for _, route := range cfg.Overlay.AcceptRoutes {
		if strings.TrimSpace(route) != "" && route != pool {
			homeSubnet = route
			break
		}
	}
	if pool == "" || homeSubnet == "" {
		return "", fmt.Errorf("installed configuration does not contain reusable join routes")
	}
	return (enroll.JoinCode{
		ServerAddress: cfg.Server.Address,
		NetworkName:   cfg.Auth.NetworkName,
		ServerName:    cfg.Reality.ServerName,
		OverlayPool:   pool,
		HomeNode:      "home",
		HomeSubnet:    homeSubnet,
	}).Encode()
}

func saveFormState(state guiFormState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	protected, err := protectUserData(encoded)
	if err != nil {
		return err
	}
	directory, err := localDataDirectory()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return replaceFile(filepath.Join(directory, "form.dat"), protected, 0o600)
}

func readFormState() (guiFormState, error) {
	directory, err := localDataDirectory()
	if err != nil {
		return guiFormState{}, err
	}
	protected, err := os.ReadFile(filepath.Join(directory, "form.dat"))
	if err != nil {
		return guiFormState{}, err
	}
	encoded, err := unprotectUserData(protected)
	if err != nil {
		return guiFormState{}, err
	}
	var state guiFormState
	if err := json.Unmarshal(encoded, &state); err != nil {
		return guiFormState{}, err
	}
	return state, nil
}

func protectUserData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...), nil
}

func unprotectUserData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	var description *uint16
	if err := windows.CryptUnprotectData(&input, &description, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, err
	}
	if description != nil {
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(description)))
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...), nil
}

func windowText(handle uintptr) string {
	length, _, _ := procGetWindowTextLenW.Call(handle)
	buffer := make([]uint16, length+1)
	procGetWindowTextW.Call(handle, uintptr(unsafe.Pointer(&buffer[0])), length+1)
	return windows.UTF16ToString(buffer)
}

func setWindowText(handle uintptr, value string) {
	procSetWindowTextW.Call(handle, uintptr(unsafe.Pointer(utf16(value))))
}

func enableControl(handle uintptr, enabled bool) {
	value := uintptr(0)
	if enabled {
		value = 1
	}
	procEnableWindow.Call(handle, value)
}

func utf16(value string) *uint16 {
	pointer, _ := windows.UTF16PtrFromString(value)
	return pointer
}

func unsafePointer(value *uint16) unsafe.Pointer { return unsafe.Pointer(value) }

func confirmBox(title, text string) bool {
	titlePointer := utf16(title)
	textPointer := utf16(text)
	result, _, _ := procMessageBoxW.Call(
		mainWindow,
		uintptr(unsafe.Pointer(textPointer)),
		uintptr(unsafe.Pointer(titlePointer)),
		messageYesNo|messageWarning|messageSetForeground,
	)
	return result == dialogYes
}

func hostname() string {
	value, err := os.Hostname()
	if err != nil || strings.TrimSpace(value) == "" {
		return "windows"
	}
	return value
}
