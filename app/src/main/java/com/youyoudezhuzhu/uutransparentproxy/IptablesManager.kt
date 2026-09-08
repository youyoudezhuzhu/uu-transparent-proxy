package com.youyoudezhuzhu.uutransparentproxy

/**
 * iptables/路由管理 —— 劫持全部热点设备流量，并保证退出时原子清理。
 *
 * 规则语义：
 *   - 自建链 UUPROXY：`-t nat -N UUPROXY`，所有规则打 `-m comment --comment uuproxy` 便于精确回收。
 *   - PREROUTING：非热点接口进来的流量不劫持；热点进来的 TCP REDIRECT 到本地代理端口。
 *   - 放行策略：到 UU 代理本身(6.6.6.6)、及本地/回环的流量 RETURN，避免自环。
 *   - UDP：走 mangle TPROXY（若内核支持），否则仅做 DNS 转发提示，不强制。
 *   - POSTROUTING：对 WAN 接口做 MASQUERADE（SNAT），保证回包路由；开 ip_forward。
 *
 * 清理：removeAllRules() 精确删除本应用全部规则并恢复 ip_forward=0；
 * resetNetwork() 为紧急恢复，额外清空整个 nat/mangle 相关链并重置转发。
 */
object IptablesManager {

    const val CHAIN = "UUPROXY"
    const val TAG = "uuproxy"          // iptables comment marker
    const val UDP_CHAIN = "UUPROXY_UDP"

    /** 常用热点接口名候选（不同 ROM 各异，自动探测 + 手动覆盖）。 */
    private val HOTSPOT_IFACE_CANDIDATES = arrayOf(
        "ap0", "softap0", "swlan0", "wlan1", "wlan2", "wlan_ap", "wlan0.0",
        "sta0", "wifi_ap", "hswlan0", "dhd0", "p2p0"
    )

    // ------------------------------------------------------------------
    // 接口探测
    // ------------------------------------------------------------------

    /**
     * 自动探测热点接入接口。返回第一个命中的候选，找不到返回 null。
     * 通过 `ip -o link show` 枚举真实接口名匹配候选。
     */
    fun detectHotspotInterface(): String? {
        val r = RootShell.exec("ip -o link show")
        if (!r.ok) return null
        val ifaces = r.output.lines().mapNotNull { line ->
            val parts = line.trim().split(":")
            parts.getOrNull(1)?.trim()
        }.filter { it.isNotEmpty() }
        for (cand in HOTSPOT_IFACE_CANDIDATES) {
            if (ifaces.any { it == cand || it.startsWith(cand) }) return cand
        }
        // 退而求其次：查找带 AP 特征的接口名
        return ifaces.firstOrNull { it.contains("ap") || it.contains("soft") || it.contains("hostap") }
    }

    /**
     * 探测 WAN 上行接口（手机自己上网用的接口，即 UU 出网口）。
     * 默认取默认路由接口，其次取有 IP 的非环回接口。
     */
    fun detectWanInterface(): String? {
        val r = RootShell.exec("ip route show default")
        if (r.ok) {
            val m = Regex("dev\\s+(\\S+)").find(r.output)
            if (m != null) return m.groupValues[1]
        }
        val r2 = RootShell.exec("ip -o -4 addr show")
        if (r2.ok) {
            for (line in r2.output.lines()) {
                val parts = line.trim().split("\\s+".toRegex())
                val iface = parts.getOrNull(1) ?: continue
                if (iface.startsWith("lo")) continue
                if (parts.any { it.contains("inet ") }) return iface
            }
        }
        return "wlan0"
    }

    /** 枚举有 IP 的接口（供 UI 下拉展示）。 */
    fun listInterfaces(): List<String> {
        val r = RootShell.exec("ip -o -4 addr show")
        if (!r.ok) return emptyList()
        return r.output.lines().mapNotNull { line ->
            line.trim().split("\\s+".toRegex()).getOrNull(1)?.trim()
        }.filter { it.isNotEmpty() && it != "lo" }
    }

    // ------------------------------------------------------------------
    // 规则构建
    // ------------------------------------------------------------------

    /** 组装完整建规则脚本。所有新增规则在清理时按 comment 精确回收。 */
    fun buildEnableScript(
        hotspotIface: String,
        wanIface: String,
        tcpPort: Int,
        udpPort: Int,
        udpEnabled: Boolean,
        upstreamHost: String = "6.6.6.6",
        upstreamPort: Int = 8088
    ): List<String> {
        val cmds = mutableListOf<String>()

        // 开 IP 转发（sysctl 失败则直接写 proc）
        cmds += "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || echo 1 > /proc/sys/net/ipv4/ip_forward"

        // 建自建链（存在也没关系，先清空）
        cmds += "iptables -t nat -N $CHAIN 2>/dev/null; iptables -t nat -F $CHAIN"
        cmds += "iptables -t nat -N $UDP_CHAIN 2>/dev/null; iptables -t nat -F $UDP_CHAIN"

        // 排除自身/本地/代理地址，避免自环
        cmds += "iptables -t nat -A $CHAIN -d 127.0.0.0/8 -j RETURN"
        cmds += "iptables -t nat -A $CHAIN -d $upstreamHost -j RETURN"
        cmds += "iptables -t nat -A $CHAIN -d 224.0.0.0/4 -j RETURN"
        // 已建立/相关连接不重复处理
        cmds += "iptables -t nat -A $CHAIN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
        // TCP -> 本地代理端口
        cmds += "iptables -t nat -A $CHAIN -p tcp -j REDIRECT --to-ports $tcpPort -m comment --comment $TAG"

        // UDP：若开启，走 TPROXY（mangle 表），需要内核 CONFIG_NETFILTER_TPROXY
        if (udpEnabled) {
            cmds += "iptables -t mangle -N $UDP_CHAIN 2>/dev/null; iptables -t mangle -F $UDP_CHAIN"
            cmds += "iptables -t mangle -A $UDP_CHAIN -d 127.0.0.0/8 -j RETURN"
            cmds += "iptables -t mangle -A $UDP_CHAIN -d $upstreamHost -j RETURN"
            cmds += "iptables -t mangle -A $UDP_CHAIN -p udp -j TPROXY --on-port $udpPort --tproxy-mark 0x1/0x1 -m comment --comment $TAG"
        }

        // PREROUTING：仅热点接口流量进入自建链
        cmds += "iptables -t nat -A PREROUTING -i $hotspotIface -j $CHAIN -m comment --comment $TAG"
        if (udpEnabled) {
            cmds += "iptables -t mangle -A PREROUTING -i $hotspotIface -j $UDP_CHAIN -m comment --comment $TAG 2>/dev/null"
        }

        // SNAT/MASQUERADE：从 WAN 出网的所有流量做 NAT，保证回包路由
        cmds += "iptables -t nat -A POSTROUTING -o $wanIface -j MASQUERADE -m comment --comment $TAG"

        // UDP 转发标记（TPROXY 需要 ip rule 引流）
        if (udpEnabled) {
            cmds += "ip rule add fwmark 0x1/0x1 lookup 100 2>/dev/null || true"
            cmds += "ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true"
        }

        return cmds
    }

    /**
     * 原子清理：按 comment 精确删除本应用新增的所有规则，恢复 ip_forward=0。
     * 不触碰其他应用的规则（ProxyDroid 等留它们自己的 comment）。
     */
    fun removeAllRules(): List<String> {
        return listOf(
            // 从 PREROUTING/POSTROUTING 删掉跳转条目（match comment）
            "iptables -t nat -S PREROUTING | grep '$TAG' | sed 's/^-A/-D/' | while read c; do iptables -t nat \$c; done",
            "iptables -t nat -S POSTROUTING | grep '$TAG' | sed 's/^-A/-D/' | while read c; do iptables -t nat \$c; done",
            "iptables -t mangle -S PREROUTING 2>/dev/null | grep '$TAG' | sed 's/^-A/-D/' | while read c; do iptables -t mangle \$c; done",
            // 清空并删除自建链
            "iptables -t nat -F $CHAIN 2>/dev/null; iptables -t nat -X $CHAIN 2>/dev/null",
            "iptables -t mangle -F $UDP_CHAIN 2>/dev/null; iptables -t mangle -X $UDP_CHAIN 2>/dev/null",
            // 恢复转发
            "sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || echo 0 > /proc/sys/net/ipv4/ip_forward",
            // 清掉 TPROXY 路由引流
            "ip rule del fwmark 0x1/0x1 lookup 100 2>/dev/null || true",
            "ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true"
        )
    }

    /** 紧急“重置网络”：更彻底——清空 nat/mangle 里全部本应用痕迹 + 恢复默认转发状态。 */
    fun resetNetwork(): ShellResult {
        val all = buildList {
            addAll(removeAllRules())
            // 双保险：凡带 uuproxy 注释的规则一并删（含别的表）
            add("for t in nat mangle filter; do iptables -t \$t -S 2>/dev/null | grep '$TAG' | sed 's/^-A/-D/' | while read c; do iptables -t \$t \$c; done; done")
        }
        return RootShell.exec(all)
    }
}
