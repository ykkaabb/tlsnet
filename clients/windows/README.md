# Windows client

TlsNet uses the official WireGuard TUN package and the signed Wintun driver.

Build and assemble an AMD64 directory from an elevated PowerShell:

```powershell
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -o dist\windows-amd64\tlsnet.exe .\cmd\tlsnet
.\scripts\get-wintun.ps1
Copy-Item .\configs\client.example.toml .\dist\windows-amd64\config.toml
```

Edit `config.toml`, then run PowerShell as Administrator:

```powershell
.\tlsnet.exe check -c .\config.toml
.\tlsnet.exe run -c .\config.toml
```

To install it as a hidden elevated startup task with automatic restart:

```powershell
.\scripts\install-windows.ps1 `
  -Binary .\dist\windows-amd64\tlsnet.exe `
  -Wintun .\dist\windows-amd64\wintun.dll `
  -Config .\config.toml
```

Remove the program while preserving its configuration with
`.\scripts\uninstall-windows.ps1`; add `-Purge` to remove the configuration too.

`wintun.dll` must remain beside `tlsnet.exe`. The download script fetches the
official signed Wintun 0.14.1 archive and refuses to extract it unless its
SHA-256 matches the value published at <https://www.wintun.net/>.
