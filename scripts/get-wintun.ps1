param(
    [string]$Destination = (Join-Path $PSScriptRoot "..\dist\windows-amd64")
)

$ErrorActionPreference = "Stop"
$version = "0.14.1"
$expectedSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$downloadUrl = "https://www.wintun.net/builds/wintun-$version.zip"
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("tlsnet-wintun-" + [guid]::NewGuid())
$archive = Join-Path $temporary "wintun.zip"
$expanded = Join-Path $temporary "expanded"

try {
    New-Item -ItemType Directory -Path $temporary, $expanded, $Destination -Force | Out-Null
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archive
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actual -ne $expectedSha256) {
        throw "Wintun archive SHA-256 mismatch: expected $expectedSha256, got $actual"
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $expanded
    Copy-Item -LiteralPath (Join-Path $expanded "wintun\bin\amd64\wintun.dll") -Destination (Join-Path $Destination "wintun.dll") -Force
    Copy-Item -LiteralPath (Join-Path $expanded "wintun\LICENSE.txt") -Destination (Join-Path $Destination "WINTUN-LICENSE.txt") -Force
    Write-Host "Installed signed Wintun $version into $Destination"
}
finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}
