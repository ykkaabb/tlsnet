[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repository = "ykkaabb/tlsnet"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Open PowerShell as Administrator, then run the bootstrap command again."
}

$architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($architecture -ne "X64") {
    throw "Unsupported Windows architecture: $architecture. The current release supports x64 Windows."
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("tlsnet-bootstrap-" + [guid]::NewGuid().ToString("N"))
$archive = Join-Path $temporary "tlsnet.zip"
$checksumFile = Join-Path $temporary "SHA256SUMS"
$package = Join-Path $temporary "package"
New-Item -ItemType Directory -Path $temporary, $package | Out-Null

try {
    $headers = @{
        Accept = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent" = "TlsNet-bootstrap"
    }
    $release = Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$repository/releases/latest"
    $tag = [string]$release.tag_name
    if ([string]::IsNullOrWhiteSpace($tag)) {
        throw "The latest TlsNet release has no tag."
    }

    $asset = "tlsnet-$tag-windows-amd64.zip"
    $base = "https://github.com/$repository/releases/download/$tag"
    Write-Host "Downloading TlsNet $tag for windows/amd64..."
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $archive
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $checksumFile

    $escapedAsset = [regex]::Escape($asset)
    $checksumLine = Get-Content -LiteralPath $checksumFile |
        Where-Object { $_ -match "(?:^|\s)$escapedAsset$" } |
        Select-Object -First 1
    if (-not $checksumLine) {
        throw "Release checksum for $asset is missing."
    }
    $expected = ($checksumLine -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "TlsNet archive SHA-256 mismatch."
    }

    Expand-Archive -LiteralPath $archive -DestinationPath $package
    $setup = Join-Path $package "scripts\setup-windows.ps1"
    $binary = Join-Path $package "tlsnet.exe"
    $wintun = Join-Path $package "wintun.dll"
    foreach ($required in @($setup, $binary, $wintun)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Downloaded package is incomplete: $required"
        }
    }

    $powerShell = (Get-Process -Id $PID).Path
    & $powerShell -NoProfile -ExecutionPolicy Bypass -File $setup -Binary $binary -Wintun $wintun
    if ($LASTEXITCODE -ne 0) {
        throw "TlsNet setup failed with exit code $LASTEXITCODE."
    }
}
finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}
