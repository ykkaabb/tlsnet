# Android client

Planned first-release client:

- minimum Android 8.0 (API 26);
- Kotlin application and foreground `VpnService`;
- Go packet/transport core packaged as an AAR;
- user-approved split tunnel for the overlay and home LAN routes;
- two TLS lanes on cellular and four lanes on Wi-Fi;
- reconnect after Wi-Fi/cellular handover;
- no Root and no third-party account dependency;
- locally signed, sideloadable APK.

This directory intentionally contains no generated Android Studio files yet. The
control-plane message schema and reusable Go core will be separated from the Linux
prototype before the Gradle project is generated.
