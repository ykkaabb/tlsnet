param(
    [switch]$SkipApk
)

$ErrorActionPreference = "Stop"
if (-not $env:ANDROID_HOME -and -not $env:ANDROID_SDK_ROOT) {
    throw "Set ANDROID_HOME or ANDROID_SDK_ROOT to an Android SDK containing an NDK."
}

$repository = Split-Path -Parent $PSScriptRoot
$libraryDirectory = Join-Path $repository "clients\android\app\libs"
$aar = Join-Path $libraryDirectory "tlsnet.aar"
New-Item -ItemType Directory -Path $libraryDirectory -Force | Out-Null

Push-Location $repository
try {
    go tool gomobile init
    go tool gomobile bind -target=android -androidapi 26 -trimpath -o $aar ./mobilecore
    if (-not $SkipApk) {
        Push-Location (Join-Path $repository "clients\android")
        try {
            gradle --no-daemon :app:assembleDebug
        }
        finally {
            Pop-Location
        }
    }
}
finally {
    Pop-Location
}
