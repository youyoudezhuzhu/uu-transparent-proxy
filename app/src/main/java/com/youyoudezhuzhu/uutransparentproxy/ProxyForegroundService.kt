package com.youyoudezhuzhu.uutransparentproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * ProxyForegroundService —— 持有 Foreground 通知，让代理在 App 退到后台时
 * 仍持续运行。所有实际逻辑在 [ProxyEngine]（单例），服务只是生命周期载体。
 */
class ProxyForegroundService : Service() {

    companion object {
        const val CHANNEL_ID = "uuproxy_channel"
        const val NOTIF_ID = 1001
        const val ACTION_START = "com.uuproxy.START"
        const val ACTION_STOP = "com.uuproxy.STOP"

        fun start(context: Context) {
            val i = Intent(context, ProxyForegroundService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(i)
            else context.startService(i)
        }
        fun stop(context: Context) {
            val i = Intent(context, ProxyForegroundService::class.java).setAction(ACTION_STOP)
            context.startService(i)
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        // 订阅引擎状态，实时刷新通知文案
        scope.launch {
            ProxyEngine.state.collect { st -> updateNotification(st) }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                startForeground(NOTIF_ID, buildNotification(ProxyEngine.state.value))
                // 引擎操作放 IO 线程，避免阻塞前台服务进场
                scope.launch(Dispatchers.IO) {
                    ProxyEngine.start(this@ProxyForegroundService, ProxyEngine.config.value)
                }
            }
            ACTION_STOP -> {
                ProxyEngine.stop()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            else -> Unit
        }
        return START_STICKY
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val ch = NotificationChannel(
                CHANNEL_ID, "UU 透明代理", NotificationManager.IMPORTANCE_LOW
            )
            ch.description = "UU 热点透明代理运行状态"
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }

    private fun buildNotification(st: UiState): Notification {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val title = if (st.running) "UU 透明代理 · 加速中" else "UU 透明代理 · 已停止"
        val text = if (st.running) {
            "设备 ${st.activeClients} · ↓${fmt(st.rxRate)} ↑${fmt(st.txRate)} · ${st.hotspotIface}"
        } else {
            "点击进入开启加速"
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_stat_proxy)
            .setOngoing(st.running)
            .setContentIntent(pi)
            .build()
    }

    private fun updateNotification(st: UiState) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIF_ID, buildNotification(st))
    }

    private fun fmt(bps: Long): String =
        if (bps >= 1024 * 1024) String.format("%.1fMB/s", bps / 1024.0 / 1024.0)
        else String.format("%.0fKB/s", bps / 1024.0)

    override fun onDestroy() {
        scope.cancel()
        LogcatHelper.stop()
        super.onDestroy()
    }
}
