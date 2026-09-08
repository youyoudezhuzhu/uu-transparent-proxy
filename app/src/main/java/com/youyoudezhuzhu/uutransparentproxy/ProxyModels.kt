package com.youyoudezhuzhu.uutransparentproxy

/** 代理配置。 */
data class ProxyConfig(
    val upstreamHost: String = "6.6.6.6",
    val upstreamPort: Int = 8088,
    /** 0=SOCKS5，1=HTTP CONNECT（Switch/主机默认 HTTP，对齐 UU 代理） */
    val protocol: Int = 1,
    val tcpPort: Int = 23333,
    val udpPort: Int = 23334,
    val udpEnabled: Boolean = true,
    val hotspotInterface: String = "ap0",
    val wanInterface: String = "wlan0"
)

/** 运行时统计。 */
data class RuntimeStats(
    val rxBytes: Long,
    val txBytes: Long,
    val rxRate: Long,   // bytes/sec，UI 展示即换算 MB/s
    val txRate: Long,
    val activeClients: Int,
    val running: Boolean
)
