package work.ykk.tlsnet

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {
    private lateinit var editor: EditText
    private lateinit var status: TextView
    private var pendingConfig: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 10)
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }
        status = TextView(this).apply {
            text = "Ready"
            textSize = 16f
            setPadding(0, 0, 0, 16)
        }
        editor = EditText(this).apply {
            hint = getString(R.string.configuration)
            gravity = android.view.Gravity.TOP or android.view.Gravity.START
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            typeface = android.graphics.Typeface.MONOSPACE
            setHorizontallyScrolling(true)
            setText(loadConfiguration())
        }
        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val connect = Button(this).apply {
            text = getString(R.string.connect)
            setOnClickListener { requestConnect() }
        }
        val disconnect = Button(this).apply {
            text = getString(R.string.disconnect)
            setOnClickListener {
                startService(Intent(this@MainActivity, TlsNetVpnService::class.java).apply {
                    action = TlsNetVpnService.ACTION_STOP
                })
                status.text = "Disconnect requested"
            }
        }
        buttons.addView(connect, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        buttons.addView(disconnect, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(status)
        root.addView(editor, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f,
        ))
        root.addView(buttons)
        setContentView(root)
    }

    private fun requestConnect() {
        val config = editor.text.toString()
        if (config.isBlank()) {
            Toast.makeText(this, "Configuration is empty", Toast.LENGTH_LONG).show()
            return
        }
        getSharedPreferences(PREFERENCES, MODE_PRIVATE).edit().putString(CONFIG_KEY, config).apply()
        val permission = VpnService.prepare(this)
        if (permission != null) {
            pendingConfig = config
            startActivityForResult(permission, VPN_REQUEST)
        } else {
            startTunnel(config)
        }
    }

    @Deprecated("Deprecated by Android, retained for API 26 compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK) {
                pendingConfig?.let { startTunnel(it) }
            } else {
                status.text = "VPN permission denied"
            }
            pendingConfig = null
        }
    }

    private fun startTunnel(config: String) {
        val intent = Intent(this, TlsNetVpnService::class.java).apply {
            action = TlsNetVpnService.ACTION_CONNECT
            putExtra(TlsNetVpnService.EXTRA_CONFIG, config)
        }
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        status.text = "Connecting…"
    }

    private fun loadConfiguration(): String {
        val saved = getSharedPreferences(PREFERENCES, MODE_PRIVATE).getString(CONFIG_KEY, null)
        if (saved != null) return saved
        return resources.openRawResource(R.raw.default_config).bufferedReader().use { it.readText() }
    }

    companion object {
        private const val VPN_REQUEST = 100
        private const val PREFERENCES = "tlsnet"
        private const val CONFIG_KEY = "config"
    }
}
