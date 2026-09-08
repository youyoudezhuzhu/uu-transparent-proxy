package com.youyoudezhuzhu.uutransparentproxy

import java.io.DataInputStream
import java.io.DataOutputStream

/** 一条 shell 命令的执行结果。 */
data class ShellResult(val exitCode: Int, val output: String) {
    val ok: Boolean get() = exitCode == 0
}

/**
 * RootShell —— 所有需要 su 的操作统一走这里。
 *
 * 本应用严禁 VPNService / Shizuku，只依赖 Root(su)。所有 iptables、
 * sysctl、ip route 命令通过 `su -c` 以 root 身份执行。
 */
object RootShell {

    /** 检查是否拿到 root。 */
    fun hasRoot(): Boolean {
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            p.outputStream.close()
            val out = p.inputStream.bufferedReader().readText()
            val err = p.errorStream.bufferedReader().readText()
            p.waitFor()
            // 出现 "uid=0(root)" 即 root 可用
            (out + err).contains("uid=0(root)")
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 以 root 执行一段 shell。多条命令用 `;` 拼接即可（root 会话内）。
     */
    fun exec(command: String): ShellResult {
        return try {
            val proc = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()

            val sout = DataInputStream(proc.inputStream).readBytes().toString(Charsets.UTF_8)
            val exitCode = proc.waitFor()
            ShellResult(exitCode, sout.trim())
        } catch (e: Exception) {
            ShellResult(-1, e.message ?: "su exec failed")
        }
    }

    /** 逐条执行多条命令，返回最后一条的退出码 + 汇总输出。 */
    fun exec(commands: List<String>): ShellResult {
        if (commands.isEmpty()) return ShellResult(0, "")
        // 用 shell 脚本包裹，保证顺序执行
        val script = commands.joinToString("\n") { it }
        return exec(script)
    }

    /** 把某命令变成写文件并回显结果，便于验证落盘/生效（root）。 */
    fun execEcho(command: String): ShellResult = exec("$command; echo \"__RC=$?\"")
}
