//go:build windows

package windowsapp

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func Main(arguments []string, version string) {
	if len(arguments) > 1 && arguments[1] == "service" {
		if err := runService(); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(arguments) > 1 && arguments[1] == "--install" {
		if len(arguments) != 4 {
			messageBox("TlsNet 安装失败", "安装参数不完整。", messageError)
			os.Exit(2)
		}
		if err := installService(arguments[2], arguments[3]); err != nil {
			messageBox("TlsNet 安装失败", err.Error(), messageError)
			os.Exit(1)
		}
		messageBox("TlsNet", "安装完成，后台服务已经启动。以后直接打开 TlsNet 即可，不再需要管理员权限。", messageInfo)
		return
	}
	if len(arguments) == 2 && strings.HasPrefix(arguments[1], "--service-") {
		message, err := manageService(arguments[1])
		if err != nil {
			messageBox("TlsNet 服务操作失败", err.Error(), messageError)
			os.Exit(1)
		}
		messageBox("TlsNet", message, messageInfo)
		return
	}
	if err := runGUI(version); err != nil {
		messageBox("TlsNet", fmt.Sprintf("应用程序启动失败：\n%s", err), messageError)
		os.Exit(1)
	}
}

func messageBox(title, text string, kind uint32) {
	titlePointer, _ := windows.UTF16PtrFromString(title)
	textPointer, _ := windows.UTF16PtrFromString(text)
	_, _, _ = procMessageBoxW.Call(0, uintptr(unsafePointer(textPointer)), uintptr(unsafePointer(titlePointer)), uintptr(kind|messageSetForeground))
}
