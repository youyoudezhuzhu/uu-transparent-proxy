package com.youyoudezhuzhu.uutransparentproxy

/**
 * NativeProxy —— libuuproxy.so 的 JNI 绑定（实例外部方法）。
 *
 * JNI 符号名与 `app/src/main/jni/native-lib.c` 一一对应：
 *   Java_com_youyoudezhuzhu_uutransparentproxy_NativeProxy_<fn>
 * 采用 Kotlin class + 实例外部方法，JNI 回调时第二个参数为 jobject。
 */
class NativeProxy {

    init {
        System.loadLibrary("uuproxy")
    }

    /**
     * 启动本地代理守护进程（运行于应用进程内的原生线程，绑定高端口无需 root）。
     *
     * @param upHost   上游 UU 代理地址（默认 6.6.6.6）
     * @param upPort   上游 UU 代理端口（默认 8088）
     * @param protocol 0=SOCKS5，1=HTTP CONNECT
     * @param tcpPort  本地 TCP 劫持监听端口
     * @param udpPort  本地 UDP 监听端口
     * @param udpEnabled 是否启用 UDP 转发（1/0）
     * @return 0 成功，-1 失败（已启动或绑定失败）
     */
    external fun startProxy(
        upHost: String, upPort: Int, protocol: Int,
        tcpPort: Int, udpPort: Int, udpEnabled: Int
    ): Int

    /** 停止代理守护进程。 */
    external fun stopProxy()

    /** 累计下行字节（上游 -> 客户端）。 */
    external fun getRxBytes(): Long

    /** 累计上行字节（客户端 -> 上游）。 */
    external fun getTxBytes(): Long

    /** 当前活跃客户端连接数。 */
    external fun getActiveClients(): Int
}
