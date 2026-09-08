package com.youyoudezhuzhu.uutransparentproxy

import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * LogcatHelper —— 流式捕获 logcat 中本应用及 native 守护进程(标签 uuproxy)的
 * 日志，实时推给 [ProxyEngine] 的 UI 缓冲。
 *
 * 有 root 时用 `su -c "logcat -s"` 读全量；无 root 退化为 `logcat -s`（只读
 * 本进程标签）。读到行即回调，不阻塞 UI。
 */
object LogcatHelper {

    @Volatile private var process: Process? = null

    /** 开启后台捕获线程。标签不足可追加。 */
    fun start(tags: Array<String>, onLine: (String) -> Unit) {
        stop()
        val spec = tags.joinToString(" ") { "$it:*" }
        val cmd = if (RootShell.hasRoot()) arrayOf("su", "-c", "logcat -v time $spec")
                  else arrayOf("logcat", "-v", "time", *tags.map { "$it:*" }.toTypedArray())
        try {
            val p = ProcessBuilder(*cmd)
                .redirectErrorStream(true)
                .start()
            process = p
            Thread {
                try {
                    val reader = BufferedReader(InputStreamReader(p.inputStream))
                    var line: String?
                    while (p.isAlive && reader.readLine().also { line = it } != null) {
                        onLine(line!!)
                    }
                } catch (_: Exception) { }
            }.apply { isDaemon = true; name = "uuproxy-logcat"; start() }
        } catch (e: Exception) {
            onLine("logcat 启动失败: ${e.message}")
        }
    }

    fun stop() {
        val p = process
        process = null
        p?.destroy()
    }
}
