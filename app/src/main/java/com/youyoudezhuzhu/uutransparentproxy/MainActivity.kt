package com.youyoudezhuzhu.uutransparentproxy

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.textfield.MaterialAutoCompleteTextView
import com.youyoudezhuzhu.uutransparentproxy.databinding.ActivityMainBinding
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val notifPermLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        requestNotifIfNeeded()
        setupLogView()
        setupInterfaces()
        setupControls()

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                ProxyEngine.state.collect { render(it) }
            }
        }
    }

    private fun requestNotifIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun setupLogView() {
        binding.logView.movementMethod = ScrollingMovementMethod()
        // 允许长按选中复制（在布局已设 android:textIsSelectable="true"）
        binding.btnClearLog.setOnClickListener { ProxyEngine.clearLog() }
        binding.btnCopyLog.setOnClickListener { copyLog() }
        binding.btnShareLog.setOnClickListener { shareLog() }
    }

    private fun copyLog() {
        val text = ProxyEngine.localLog().joinToString("\n")
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("uuproxy-log", text))
        Toast.makeText(this, "日志已复制，可直接粘贴发送", Toast.LENGTH_SHORT).show()
    }

    private fun shareLog() {
        val text = ProxyEngine.localLog().joinToString("\n")
        val i = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
        }
        startActivity(Intent.createChooser(i, "分享日志"))
    }

    private fun setupInterfaces() {
        val list = IptablesManager.listInterfaces()
        val detectedH = IptablesManager.detectHotspotInterface().orEmpty()
        val detectedW = IptablesManager.detectWanInterface().orEmpty()
        val hAdapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, (list + detectedH).toTypedArray())
        val wAdapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, (list + detectedW).toTypedArray())
        (binding.etHotspot.editText as? MaterialAutoCompleteTextView)?.setAdapter(hAdapter)
        (binding.etWan.editText as? MaterialAutoCompleteTextView)?.setAdapter(wAdapter)
        binding.etHotspot.editText?.setText(detectedH)
        binding.etWan.editText?.setText(detectedW)
        binding.statusHint.text = "自动探测 → 热点: $detectedH  |  WAN: $detectedW"
    }

    private fun setupControls() {
        binding.btnStart.setOnClickListener {
            if (ProxyEngine.isRunning()) {
                ProxyForegroundService.stop(this)
            } else {
                val cfg = readConfig()
                ProxyEngine.config.value = cfg
                ProxyForegroundService.start(this)
            }
        }

        binding.btnReset.setOnClickListener {
            ProxyEngine.reset()
            Toast.makeText(this, "已执行紧急重置网络", Toast.LENGTH_SHORT).show()
        }

        binding.btnDetect.setOnClickListener {
            val h = IptablesManager.detectHotspotInterface().orEmpty()
            val w = IptablesManager.detectWanInterface().orEmpty()
            binding.etHotspot.editText?.setText(h)
            binding.etWan.editText?.setText(w)
            binding.statusHint.text = "重新探测 → 热点: $h  |  WAN: $w"
        }
    }

    private fun readConfig(): ProxyConfig {
        val h = binding.etUpstreamHost.editText?.text?.toString()?.trim().orEmpty()
        val p = binding.etUpstreamPort.editText?.text?.toString()?.trim()?.toIntOrNull() ?: 8088
        val proto = if (binding.rbHttp.isChecked) 1 else 0
        val udp = binding.swUdp.isChecked
        val hotspot = binding.etHotspot.editText?.text?.toString()?.trim().orEmpty()
        val wan = binding.etWan.editText?.text?.toString()?.trim().orEmpty()
        return ProxyConfig(
            upstreamHost = h.ifBlank { "6.6.6.6" },
            upstreamPort = p,
            protocol = proto,
            tcpPort = 23333,
            udpPort = 23334,
            udpEnabled = udp,
            hotspotInterface = hotspot,
            wanInterface = wan
        )
    }

    private fun render(st: UiState) {
        binding.tvStatus.text = if (st.running) "加速中" else "未启动"
        binding.tvStatus.setTextColor(
            ContextCompat.getColor(this, if (st.running) R.color.status_on else R.color.status_off)
        )
        // 同步开关（防止用户切换时被回写）
        binding.btnStart.isChecked = st.running
        binding.tvDevices.text = "${st.activeClients} 台"
        binding.tvRx.text = "%s/s".format(fmtRate(st.rxRate))
        binding.tvTx.text = "%s/s".format(fmtRate(st.txRate))
        binding.tvTotal.text = "累计 ↓%s  ↑%s".format(fmtBytes(st.rxBytes), fmtBytes(st.txBytes))
        if (st.message.isNotBlank()) binding.statusHint.text = st.message

        // 错误提示（红字醒目显示）
        val err = st.message.contains("失败") || st.message.contains("未获取") ||
                st.message.contains("✗") || st.message.contains("不可达") ||
                st.message.contains("无法") || st.message.contains("异常")
        binding.tvError.visibility = if (err) View.VISIBLE else View.GONE
        binding.tvError.text = st.message

        // 日志
        val log = st.logLines.joinToString("\n")
        if (log.isNotBlank()) { binding.logView.text = log }
        binding.logView.scrollTo(0, binding.logView.lineCount * 14)
    }

    private fun fmtRate(bps: Long): String =
        if (bps >= 1024 * 1024) String.format("%.2f MB", bps / 1024.0 / 1024.0)
        else String.format("%.0f KB", bps / 1024.0)

    private fun fmtBytes(b: Long): String =
        if (b >= 1024 * 1024 * 1024) String.format("%.2f GB", b / 1024.0 / 1024.0 / 1024.0)
        else if (b >= 1024 * 1024) String.format("%.1f MB", b / 1024.0 / 1024.0)
        else String.format("%.0f KB", b / 1024.0)
}
