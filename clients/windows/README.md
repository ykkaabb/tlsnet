# Windows client

Download `tlsnet-*-windows-amd64.exe` from the latest GitHub Release and run it
normally. The native GUI accepts the relay join code, node name, and network
password.

The first connection requests one UAC approval so the application can install
its embedded, signed Wintun driver and the `TlsNet` Windows service. The tunnel
runs in that service. Subsequent GUI launches, configuration updates,
connect/disconnect operations, status checks, and log viewing do not require an
administrator token.

The GUI keeps tunnel and service lifecycle operations separate:

- **Disconnect tunnel** stops only the current virtual-network connection.
- **Stop service** stops it until the next boot while retaining automatic startup.
- **Disable startup** stops the service and changes it to manual startup; **Enable
  startup** restores automatic startup and starts it immediately.
- **Uninstall completely** removes the Windows service, installed application
  copy, service configuration, logs, and the per-user control credentials. The
  originally downloaded standalone executable remains so it can be deleted or
  used for a new installation.

Service lifecycle changes request administrator approval and are preceded by a
separate confirmation inside TlsNet. This remains explicit even on Windows
systems whose UAC policy automatically approves elevation for administrators.

The local control API remains available when tunnel initialization fails. The
GUI status and log view therefore report the underlying configuration, driver,
or network error instead of reducing it to a generic connection-refused error.

Service files are installed under `%ProgramFiles%\TlsNet`; protected runtime
configuration and logs are stored under `%ProgramData%\TlsNet`. The per-user
control token is stored under `%LOCALAPPDATA%\TlsNet` and authenticates the GUI
to the loopback-only service API.

The release also contains a ZIP with the executable and the Wintun license for
offline archiving. The standalone executable already embeds Wintun, so no DLL
or PowerShell installer is required beside it.
