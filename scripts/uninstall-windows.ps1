[CmdletBinding()]
param([switch]$Purge)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from an elevated PowerShell session."
}

Stop-ScheduledTask -TaskName "TlsNet" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "TlsNet" -Confirm:$false -ErrorAction SilentlyContinue
$programDirectory = Join-Path $env:ProgramFiles "TlsNet"
if (Test-Path -LiteralPath $programDirectory) {
    Remove-Item -LiteralPath $programDirectory -Recurse -Force
}
if ($Purge) {
    $dataDirectory = Join-Path $env:ProgramData "TlsNet"
    if (Test-Path -LiteralPath $dataDirectory) {
        Remove-Item -LiteralPath $dataDirectory -Recurse -Force
    }
    Write-Host "TlsNet and its configuration were removed."
} else {
    Write-Host "TlsNet was removed; $env:ProgramData\TlsNet\config.toml was preserved."
}
