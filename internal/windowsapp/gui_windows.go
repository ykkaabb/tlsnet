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
	messageSetForeground = 0x00010000

	idJoin    = 100
	idPassword = 101
	idNode     = 102
	idStatus   = 103
	idConnect  = 200
	idStop     = 201
	idRefresh  = 202
	idLogs     = 203
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
		0x80000000, 0x80000000, 680, 570, 0, 0, instance, 0,
	)
	if mainWindow == 0 {
		return windows.GetLastError()
	}
	procShowWindow.Call(mainWindow, showNormal)
	procUpdateWindow.Call(mainWindow)
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
		case idConnect:
			connectFromForm()
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
				messageBox("TlsNet", err.Error(), messageError)
			} else if err := openTextInNotepad(contents); err != nil {
				messageBox("TlsNet", err.Error(), messageError)
			}
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
	createControl("BUTTON", "安装 / 保存并连接", windowChild|windowVisible|windowTabStop|buttonDefault, 24, 420, 210, 38, hwnd, idConnect, font)
	createControl("BUTTON", "断开", windowChild|windowVisible|windowTabStop, 250, 420, 110, 38, hwnd, idStop, font)
	createControl("BUTTON", "刷新状态", windowChild|windowVisible|windowTabStop, 375, 420, 120, 38, hwnd, idRefresh, font)
	createControl("BUTTON", "查看日志", windowChild|windowVisible|windowTabStop, 510, 420, 125, 38, hwnd, idLogs, font)
	createControl("STATIC", "首次安装会出现一次 UAC；之后本界面不需要管理员权限。", windowChild|windowVisible, 24, 480, 611, 28, hwnd, 0, font)
}

func createControl(class, text string, style uintptr, x, y, width, height int, parent uintptr, id uint16, font uintptr) uintptr {
	handle, _, _ := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(utf16(class))), uintptr(unsafe.Pointer(utf16(text))), style,
		uintptr(x), uintptr(y), uintptr(width), uintptr(height), parent, uintptr(id), 0, 0)
	if handle != 0 && font != 0 {
		procSendMessageW.Call(handle, wmSetFont, font, 1)
	}
	return handle
}

func connectFromForm() {
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
	if _, err := controlRequest("GET", "/status", nil); err == nil {
		if _, err := controlRequest("POST", "/config", bytes.NewReader(encoded)); err != nil {
			messageBox("TlsNet", err.Error(), messageError)
			return
		}
		setWindowText(statusLabel, "状态：配置已保存，正在连接")
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
	if err := launchElevated(pending, tokenPath); err != nil {
		messageBox("TlsNet", err.Error(), messageError)
		return
	}
	setWindowText(statusLabel, "状态：等待管理员确认并安装后台服务；完成后点击“刷新状态”")
}

func refreshStatus() {
	data, err := controlRequest("GET", "/status", nil)
	if err != nil {
		setWindowText(statusLabel, "状态：尚未安装，或后台服务未运行")
		return
	}
	var status statusResponse
	if err := json.Unmarshal(data, &status); err != nil {
		setWindowText(statusLabel, "状态：后台服务响应异常")
		return
	}
	text := "状态：服务已运行；隧道=" + status.Tunnel
	if status.LastError != "" {
		text += "；错误=" + status.LastError
	}
	setWindowText(statusLabel, text)
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

func utf16(value string) *uint16 {
	pointer, _ := windows.UTF16PtrFromString(value)
	return pointer
}

func unsafePointer(value *uint16) unsafe.Pointer { return unsafe.Pointer(value) }

func hostname() string {
	value, err := os.Hostname()
	if err != nil || strings.TrimSpace(value) == "" {
		return "windows"
	}
	return value
}
