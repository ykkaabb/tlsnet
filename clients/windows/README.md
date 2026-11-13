# Windows client

Download `tlsnet-*-windows-amd64.exe` from the latest GitHub Release and run it
normally. The native GUI accepts the relay join code, node name, and network
password.

The first connection requests one UAC approval so the application can install
its embedded, signed Wintun driver and the `TlsNet` Windows service. The tunnel
runs in that service. Subsequent GUI launches, configuration updates,
connect/disconnect operations, status checks, and log viewing do not require an
administrator token.

Service files are installed under `%ProgramFiles%\TlsNet`; protected runtime
configuration and logs are stored under `%ProgramData%\TlsNet`. The per-user
control token is stored under `%LOCALAPPDATA%\TlsNet` and authenticates the GUI
to the loopback-only service API.

The release also contains a ZIP with the executable and the Wintun license for
offline archiving. The standalone executable already embeds Wintun, so no DLL
or PowerShell installer is required beside it.
