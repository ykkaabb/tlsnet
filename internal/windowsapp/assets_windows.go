//go:build windows

package windowsapp

import _ "embed"

var (
	//go:embed assets/wintun.dll
	embeddedWintun []byte

	//go:embed assets/WINTUN-LICENSE.txt
	embeddedWintunLicense []byte
)
