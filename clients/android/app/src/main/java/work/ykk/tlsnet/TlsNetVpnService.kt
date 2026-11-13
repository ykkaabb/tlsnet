package work.ykk.tlsnet

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import mobilecore.Engine
import mobilecore.Mobilecore
import org.json.JSONObject
import java.net.InetAddress
import java.util.concurrent.Executors

class TlsNetVpnService : VpnService() {
    private val executor = Executors.newSingleThreadExecutor()
    @Volatile private var engine: Engine? = null
    @Volatile private var vpn: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
            }
            ACTION_CONNECT -> {
                val config = intent.getStringExtra(EXTRA_CONFIG)
                if (config.isNullOrBlank()) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                startForeground(NOTIFICATION_ID, notification("Connecting…"))
                executor.execute { connect(config) }
            }
        }
        return START_NOT_STICKY
    }

    private fun connect(config: String) {
        stopTunnel()
        try {
            val current = Mobilecore.newEngine(config)
            engine = current
            val info = JSONObject(current.prepare())
            val address = parsePrefix(info.getString("Address"))
            val builder = Builder()
                .setSession("TlsNet")
                .setMtu(info.getInt("MTU"))
                .addAddress(address.first, address.second)
                .allowFamily(android.system.OsConstants.AF_INET)
            val routes = info.getJSONArray("Routes")
            for (index in 0 until routes.length()) {
                val route = parsePrefix(routes.getString(index))
                builder.addRoute(route.first, route.second)
            }
            if (Build.VERSION.SDK_INT >= 29) {
                builder.setBlocking(true)
            }
            val descriptor = builder.establish() ?: error("Android refused to establish VPN")
            vpn = descriptor
            val fd = descriptor.detachFd()
            updateNotification("Connected via " + info.getString("Transport"))
            current.run(fd.toLong())
        } catch (error: Throwable) {
            updateNotification("Disconnected: " + (error.message ?: error.javaClass.simpleName))
        } finally {
            stopTunnel()
            stopForeground(STOP_FOREGROUND_DETACH)
            stopSelf()
        }
    }

    private fun parsePrefix(value: String): Pair<InetAddress, Int> {
        val separator = value.lastIndexOf('/')
        require(separator > 0) { "Invalid prefix: " + value }
        return InetAddress.getByName(value.substring(0, separator)) to
            value.substring(separator + 1).toInt()
    }

    private fun stopTunnel() {
        engine?.stop()
        engine = null
        vpn?.close()
        vpn = null
    }

    override fun onRevoke() {
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(
                CHANNEL_ID, "TlsNet VPN", NotificationManager.IMPORTANCE_LOW,
            ))
        }
    }

    private fun notification(text: String): Notification {
        val activity = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, TlsNetVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("TlsNet")
            .setContentText(text)
            .setContentIntent(activity)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", stop)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(
            NOTIFICATION_ID, notification(text),
        )
    }

    companion object {
        const val ACTION_CONNECT = "work.ykk.tlsnet.CONNECT"
        const val ACTION_STOP = "work.ykk.tlsnet.STOP"
        const val EXTRA_CONFIG = "config"
        private const val CHANNEL_ID = "tlsnet-vpn"
        private const val NOTIFICATION_ID = 1
    }
}
