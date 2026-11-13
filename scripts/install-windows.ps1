[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Config,
    [string]$Wintun = (Join-Path (Split-Path -Parent $Binary) "wintun.dll")
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell session."
}

$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$configPath = (Resolve-Path -LiteralPath $Config).Path
$wintunPath = (Resolve-Path -LiteralPath $Wintun).Path
& $binaryPath check -c $configPath
if ($LASTEXITCODE -ne 0) { throw "TlsNet rejected the configuration." }

$programDirectory = Join-Path $env:ProgramFiles "TlsNet"
$dataDirectory = Join-Path $env:ProgramData "TlsNet"
New-Item -ItemType Directory -Force -Path $programDirectory, $dataDirectory | Out-Null
Copy-Item -LiteralPath $binaryPath -Destination (Join-Path $programDirectory "tlsnet.exe") -Force
Copy-Item -LiteralPath $wintunPath -Destination (Join-Path $programDirectory "wintun.dll") -Force
Copy-Item -LiteralPath $configPath -Destination (Join-Path $dataDirectory "config.toml") -Force
& icacls.exe $dataDirectory /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

$installedBinary = Join-Path $programDirectory "tlsnet.exe"
$installedConfig = Join-Path $dataDirectory "config.toml"
$logPath = Join-Path $dataDirectory "tlsnet.log"
$command = "& '$installedBinary' run -c '$installedConfig' *>> '$logPath'"
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "{0}"' -f $command)
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName "TlsNet" -Action $action -Trigger $trigger `
    -Principal $taskPrincipal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "TlsNet"
Get-ScheduledTask -TaskName "TlsNet" | Format-List TaskName, State
