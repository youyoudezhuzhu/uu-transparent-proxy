package com.youyoudezhuzhu.uutransparentproxy

import android.content.Context
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

/** UI 整体状态。 */
data class UiState(
    val running: Boolean = false,
    val rootGranted: Boolean = false,
    val hotspotIface: String = "",
    val wanIface: String = "",
    val upstreamHost: String = "6.6.6.6",
    val upstreamPort: Int = 8088,
    val protocol: Int = 0,
    val udpEnabled: Boolean = true,
    val activeClients: Int = 0,
    val rxBytes: Long = 0,
    val txBytes: Long = 0,
    val rxRate: Long = 0,   // bytes/s
    val txRate: Long = 0,
    val message: String = "",
    val logLines: List<String> = emptyList()
) {
    val rxRateMb: Double get() = rxRate / 1024.0 / 1024.0
    val txRateMb: Double get() = txRate / 1024.0 / 1024.0
}

/**
 * ProxyEngine —— 单例编排核心（服务与界面共享）。
 *
 * 职责：验证 root → 启动 Native 守护进程 → 应用 iptables/REDIRECT/SNAT →
 * 轮询统计 → 维护 [UiState]；stop 时原子清 iptables + 关 Native。
 */
object ProxyEngine {

    private val TAG = "UUProxy"
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    val config = MutableStateFlow(ProxyConfig())

    private val native = NativeProxy()

    @Volatile private var running = false
    @Volatile private var statsThread: Thread? = null
    @Volatile private var lastRx = 0L
    @Volatile private var lastTx = 0L
    @Volatile private var lastSampleAt = 0L

    private val logBuffer = CopyOnWriteArrayList<String>()
    private const val MAX_LOG = 400

    // ------------------------------------------------------------------
    // Logcat 内建缓冲（服务会把流式日志推到这里，UI 读取后清空）
    // ------------------------------------------------------------------
    fun pushLocalLog(line: String) {
        val ts = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val full = "$ts  $line"
        synchronized(logBuffer) {
            if (logBuffer.size >= MAX_LOG) logBuffer.removeAt(0)
            logBuffer.add(full)
            _state.value = _state.value.copy(logLines = logBuffer.toList())
        }
    }

    fun clearLog() {
        synchronized(logBuffer) {
            logBuffer.clear()
            _state.value = _state.value.copy(logLines = emptyList())
        }
    }

    fun localLog(): List<String> = synchronized(logBuffer) { logBuffer.toList() }

    // ------------------------------------------------------------------
    // 生命周期
    // ------------------------------------------------------------------

    /** 是否已运行。 */
    fun isRunning() = running

    /**
     * 启动。context 仅用于日志/前台服务提示。
     * @throws IllegalStateException 无 root、未探测到接口或绑定失败。
     */
    fun start(context: Context, cfg: ProxyConfig) {
        if (running) { pushLocalLog("已在运行，忽略重复启动"); return }

        if (!RootShell.hasRoot()) {
            _state.value = _state.value.copy(rootGranted = false, message = "未获取到 Root(su)，无法启动")
            pushLocalLog("Root 校验失败")
            return
        }
        _state.value = _state.value.copy(rootGranted = true, message = "Root OK")

        // 接口探测
        val hotspot = cfg.hotspotInterface.ifBlank { IptablesManager.detectHotspotInterface().orEmpty() }
        val wan = cfg.wanInterface.ifBlank { IptablesManager.detectWanInterface().orEmpty() }
        if (hotspot.isBlank()) {
            _state.value = _state.value.copy(message = "未探测到热点接口，请手动选择")
            pushLocalLog("未探测到热点接口")
            return
        }
        pushLocalLog("热点接口 detectHotspot=$hotspot  WAN=$wan")

        // 预检上游代理可达性（连 6.6.6.6:8088，3s 超时）
        val reachable = probeUpstream(cfg.upstreamHost, cfg.upstreamPort)
        pushLocalLog(
            if (reachable) "上游代理 ${cfg.upstreamHost}:${cfg.upstreamPort} 可达 ✓"
            else "⚠ 上游代理 ${cfg.upstreamHost}:${cfg.upstreamPort} 不可达 ✗ (请确认 UU 已开加速; 若仍不可达可能需把 6.6.6.6 加到 lo)"
        )

        // 启动 Native 代理
        val rc = native.startProxy(
            cfg.upstreamHost, cfg.upstreamPort, cfg.protocol,
            cfg.tcpPort, cfg.udpPort, if (cfg.udpEnabled) 1 else 0
        )
        if (rc != 0) {
            _state.value = _state.value.copy(message = "Native 代理启动失败(端口绑定异常)")
            pushLocalLog("Native startProxy rc=$rc")
            return
        }

        // 应用 iptables
        val scripts = IptablesManager.buildEnableScript(
            hotspot, wan, cfg.tcpPort, cfg.udpPort, cfg.udpEnabled,
            cfg.upstreamHost, cfg.upstreamPort
        )
        val r = RootShell.exec(scripts)
        pushLocalLog("iptables 应用 rc=${r.exitCode}")
        if (!r.ok) {
            // 规则没全成也继续（很可能部分失败），但要提示
            pushLocalLog("iptables 部分失败: ${r.output.take(200)}")
        }

        running = true
        config.value = cfg
        _state.value = _state.value.copy(
            running = true,
            hotspotIface = hotspot,
            wanIface = wan,
            upstreamHost = cfg.upstreamHost,
            upstreamPort = cfg.upstreamPort,
            protocol = cfg.protocol,
            udpEnabled = cfg.udpEnabled,
            message = "加速中 · 已劫持 $hotspot 流量 → ${cfg.upstreamHost}:${cfg.upstreamPort}"
        )
        pushLocalLog("启动完成 § $hotspot/$wan → ${cfg.upstreamHost}:${cfg.upstreamPort} proto=${if (cfg.protocol==1)"HTTP" else "SOCKS5"}")

        startStatsLoop()
    }

    /** 停止：关 Native + 原子清 iptables。 */
    fun stop() {
        if (!running) { pushLocalLog("未在运行"); return }
        running = false
        stopStatsLoop()

        native.stopProxy()
        val r = RootShell.exec(IptablesManager.removeAllRules())
        pushLocalLog("已停止，iptables 清理 rc=${r.exitCode}")

        _state.value = _state.value.copy(running = false, message = "已停止，规则已清理", rxRate = 0, txRate = 0)
    }

    /** 紧急重置网络。 */
    fun reset() {
        if (running) {
            running = false
            stopStatsLoop()
            native.stopProxy()
        }
        val r = IptablesManager.resetNetwork()
        pushLocalLog("紧急重置网络 rc=${r.exitCode}")
        _state.value = _state.value.copy(running = false, message = "已重置网络", rxRate = 0, txRate = 0)
    }

    // ------------------------------------------------------------------
    // 统计轮询
    // ------------------------------------------------------------------
    private fun startStatsLoop() {
        lastRx = native.getRxBytes()
        lastTx = native.getTxBytes()
        lastSampleAt = System.currentTimeMillis()
        statsThread = Thread {
            while (running) {
                Thread.sleep(1000)
                val rx = native.getRxBytes()
                val tx = native.getTxBytes()
                val now = System.currentTimeMillis()
                val dt = (now - lastSampleAt).coerceAtLeast(1)
                val rxRate = ((rx - lastRx) * 1000 / dt).coerceAtLeast(0)
                val txRate = ((tx - lastTx) * 1000 / dt).coerceAtLeast(0)
                lastRx = rx; lastTx = tx; lastSampleAt = now
                val clients = native.getActiveClients()
                _state.value = _state.value.copy(
                    rxBytes = rx, txBytes = tx, rxRate = rxRate, txRate = txRate,
                    activeClients = clients
                )
            }
        }.apply {
            isDaemon = true
            name = "uuproxy-stats"
            start()
        }
    }

    private fun stopStatsLoop() {
        val t = statsThread
        statsThread = null
        t?.interrupt()
    }

    /** 用普通 socket 探测上游代理是否可达（本机出网连 6.6.6.6:8088）。 */
    private fun probeUpstream(host: String, port: Int): Boolean {
        return try {
            val s = java.net.Socket()
            s.connect(java.net.InetSocketAddress(host, port), 3000)
            s.close()
            true
        } catch (e: Exception) {
            false
        }
    }

    /** 重启时接入应用自身日志入口。 */
    fun logI(msg: String) { Log.i(TAG, msg); pushLocalLog(msg) }
    fun logE(msg: String) { Log.e(TAG, msg); pushLocalLog(msg) }
}
