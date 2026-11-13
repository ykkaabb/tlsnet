# Android client

The Android client uses `VpnService` for a no-root split tunnel and a gomobile
AAR for the same QUIC/HTTP3 and multipath TLS core used by desktop clients.
Android 8.0 (API 26) or newer is required.

## Build

Install Go 1.26+, JDK 17, Android SDK 35, an Android NDK, and Gradle 8.11+.
Set `ANDROID_HOME` or `ANDROID_SDK_ROOT`, then run:

```bash
./scripts/build-android.sh
```

On Windows:

```powershell
.\scripts\build-android.ps1
```

The scripts first generate `app/libs/tlsnet.aar` with the repository-pinned
`gomobile` tool, then build `app/build/outputs/apk/debug/app-debug.apk`.

`./scripts/build-android.sh --release` builds a minified release APK when the four
`TLSNET_SIGNING_*` environment variables are present. The repository Release workflow
uses a persistent private signing key stored only in GitHub Actions Secrets, so its
APK can be upgraded in place; the key and passwords are never committed.

## Use

1. Install the APK and open TlsNet.
2. Edit the TOML configuration. Use a unique Android node name.
3. Tap **Connect** and approve the Android VPN prompt.
4. Keep the persistent notification enabled; its action disconnects the tunnel.

The first Android release intentionally rejects `0.0.0.0/0`. Only the overlay
and home LAN prefixes are installed, so TlsNet's public TCP/UDP sockets cannot
be routed recursively into their own VPN.
