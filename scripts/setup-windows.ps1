[CmdletBinding()]
param(
    [string]$Binary = (Join-Path (Split-Path -Parent $PSScriptRoot) "tlsnet.exe"),
    [string]$Wintun = (Join-Path (Split-Path -Parent $PSScriptRoot) "wintun.dll")
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this setup from an elevated PowerShell session."
}

$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$wintunPath = (Resolve-Path -LiteralPath $Wintun).Path
$installer = Join-Path $PSScriptRoot "install-windows.ps1"
$installedConfig = Join-Path $env:ProgramData "TlsNet\config.toml"

if (Test-Path -LiteralPath $installedConfig) {
    $answer = Read-Host "Reuse existing $installedConfig? [Y/n]"
    if ([string]::IsNullOrWhiteSpace($answer) -or $answer -notmatch '^[Nn]$') {
        & $installer -Binary $binaryPath -Wintun $wintunPath -Config $installedConfig
        if ($LASTEXITCODE -ne 0) { throw "Installation failed." }
        return
    }
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("tlsnet-setup-" + [guid]::NewGuid().ToString("N"))
$temporaryConfig = Join-Path $temporary "config.toml"
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    & $binaryPath configure -role client -o $temporaryConfig
    if ($LASTEXITCODE -ne 0) { throw "Configuration wizard failed." }
    & $installer -Binary $binaryPath -Wintun $wintunPath -Config $temporaryConfig
    if ($LASTEXITCODE -ne 0) { throw "Installation failed." }
}
finally {
    if (Test-Path -LiteralPath $temporaryConfig) {
        Clear-Content -LiteralPath $temporaryConfig -Force
    }
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}

Write-Host "Setup complete. Logs: $env:ProgramData\TlsNet\tlsnet.log"
