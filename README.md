# UU 热点透明代理网关（Root Transparent Proxy for UU）

在 **UU 加速器开启热点加速、监听 `6.6.6.6:8088` 代理**时，本应用**劫持所有连接手机热点的设备流量**，无需在主机端做任何代理 / WiFi 设置，即插即用。主机连接到你的热点，游戏走你的 UU 加速。

> 核心：`Root(su) + iptables NAT/REDIRECT + IP 转发 + SNAT + 协议转换守护进程`
> 严禁使用 VPNService，严禁依赖 Shizuku。

---

## 目录

1. [前置可行性分析（为什么放弃免 Root 方案）](#一前置可行性分析)
2. [项目目标](#二核心目标)
3. [工作原理](#三工作原理)
4. [功能特性](#四功能特性)
5. [环境要求](#五环境要求)
6. [架构说明](#六架构说明)
7. [编译教程](#七编译教程)
8. [使用教程](#八使用教程)
9. [技术细节](#九技术细节)
10. [参考项目](#十参考项目)
11. [免责声明](#十一免责声明)

---

## 一、前置可行性分析

### 为什么放弃免 Root 方案？

**1. VPNService 被 UU 占用，且热点流量根本不经过虚拟网卡**

- Android 全局**只允许一个活跃的 `VPNService`**。UU 加速器开启热点加速时，自身已经建立了一条 VPN 隧道（它靠这条隧道把加速包打出去）。我们若再起一个 `VPNService`，系统会报 “Another VPN app is already running”，或直接把 UU 的隧道顶掉——二者无法共存。
- 更致命的是：**VPN 虚拟网卡只作用于“本机进程”的路由**。`VpnService` 通过 `getVpnInterface()` 拿到的是绑在路由表的虚拟接口，它只管**手机自己**的进程流量。而**热点客户端（其他设备）发出的数据包，在软 AP 上是独立的路由路径**——它们从 `ap0` 进来，走内核转发，根本不会经过 VPN 虚拟网卡。所以无论我们想不想，**VPNService 都看不见、劫持不到热点设备的流量**。

**2. WiFi P2P / USB 共享——接口与路由表兼容性硬伤**

- 在“已有 UU 热点（`ap0`）+ 已有 WiFi 连接（`wlan0`）”的前提下，再创建 WiFi Direct（P2P）或 USB 共享接口，会带来一连串**无法稳定解决的冲突**：
  - **IP 子网冲突**：P2P/USB 接口需要分配自己的网段，极易与 UU 的 AP 网段、现有 DHCP 地址池撞网。
  - **路由表冲突**：同时存在默认路由和多条优先级不同的直连路由，`ip rule`/`metric` 的优先级会让数据包走错接口，或陷入路由黑洞。
  - **数据链路不通**：UU 已经占用了软 AP 接口，我们无法再“在它占用的热点上”插一个透明代理层。想让另一台设备把流量切到 P2P，再在 P2P 接口上做透明代理，需要改配置设备的路由——但这**根本不是透明/即插即用**，而且相当多安卓 ROM 的 P2P 接口在“热点已开启”状态下根本起不来。

**3. 结论**

“要劫走所有连接热点的设备流量”这件事，本质上**就是一台路由器/网关的职责**——必须在**链路层 + 网络层**看到并改写每一个经过的数据包。Android 的非 Root 应用做不到这一点（VPN、P2P、USB 都受前面所述限制）。

**最终选定方案：Root + iptables**

- `iptables -t nat PREROUTING` 在**包进入内核、尚未路由**时，就能命中热点接口进来的 TCP 流量，`REDIRECT` 到本地守护进程监听端口；
- 守护进程用 `SO_ORIGINAL_DST` 读出原始目的地址，经 UU 代理（`6.6.6.6:8088`）隧道出去；
- 开 `net.ipv4.ip_forward=1`，配 `POSTROUTING MASQUERADE`（SNAT），保证回包能正确回到客户端；
- UDP 用 mangle 表 `TPROXY` + SOCKS5 UDP ASSOCIATE 处理 DNS 与游戏 UDP。

这才是**唯一**能同时做到“透明、即插即用、覆盖所有热点设备流量”的技术路径。

---

## 二、核心目标

当 UU 加速器开启热点加速并监听 `6.6.6.6:8088` 代理时，本 App：

- **劫持**所有连接手机热点的设备流量；
- **无需**在主机端配置任何代理 / WiFi 设置，即插即用；
- 设备流量**通过 UU 的代理链路**出网，转发回加速后的游戏服务器。

---

## 三、工作原理

```
 [主机(游戏机/手机)]                             [安卓手机(热点)]
        │                                              │
        │ (连热点, 无任何代理设置)                       │  SoftAP 接口 (ap0 / wlan1 ...)
        └───────────────► ip_forward=1 ◄───────────────┘
                                        │
                         ┌──────────────┴────────────────┐
                         │  iptables -t nat PREROUTING     │
                         │  -i ap0 -p tcp  → REDIRECT      │
                         │       --to-ports 23333          │
                         └──────────────┬────────────────┘
                                        │  (TCP 被劫持到本地)
                         ┌──────────────┴────────────────┐
                         │  协议转换守护进程                │
                         │  libuuproxy.so (JNI/native)     │
                         │  · 读 SO_ORIGINAL_DST           │
                         │  · 封装 SOCKS5 CONNECT / HTTP    │
                         │    CONNECT                      │
                         └──────────────┬────────────────┘
                                        │
                              ┌─────────┴──────────┐
                              │  UU 加速器代理      │
                              │  6.6.6.6:8088      │
                              └─────────┬──────────┘
                                        │
                                 ┌──────┴──────┐
                                 │ 游戏服务器  │
                                 └─────────────┘
```

**关键点：** UU 代理监听在 `6.6.6.6:8088`（热点网关的本地地址）。守护进程运行在手机本机，连接 `6.6.6.6:8088` 即直达 UU 代理监听端口，再把原始 TCP 流以 SOCKS5/HTTP CONNECT 交给 UU，UU 负责落地到真实游戏服务器。回包由 UU 沿同一条代理连接返回，再由本地守护进程写回热点。整条链对主机完全透明。

---

## 四、功能特性

- ✅ **Root(su) 底层**，禁用 VPNService，不依赖 Shizuku
- ✅ **TCP 劫持**：`iptables -t nat PREROUTING -i <热点> -p tcp -j REDIRECT --to-ports <端口>`
- ✅ **UDP 转发**：`mangle PREROUTING TPROXY` + SOCKS5 UDP ASSOCIATE（DNS 转发 + 游戏 UDP），内核支持 `CONFIG_NETFILTER_TPROXY` 时生效
- ✅ **协议转换守护进程**：自定义 native 实现（等价 redsocks 算法），支持 **SOCKS5** 与 **HTTP CONNECT** 两种上游封装
- ✅ **核心路由**：`net.ipv4.ip_forward=1` + `POSTROUTING MASQUERADE`（SNAT）保证回包
- ✅ **生命周期与安全**：App 退出 / UU 断开时**原子清理**全部新增 iptables/IP 规则与路由表项，防止主机断网；内置**紧急“重置网络”按钮**
- ✅ **兼容性适配**：自动探测热点接口（`ap0`/`wlan1`/`softap0`/`swlan0`/`hostap`…）与 WAN 接口，也支持手动覆盖
- ✅ **Material Design 界面**：加速状态、连接设备数、上下行实时速率、功能开关、Logcat 实时日志面板
- ✅ **GitHub Actions 云编译**：一键产出未签名 Debug APK

---

## 五、环境要求

| 项 | 要求 |
|----|------|
| 手机 | **已 Root**，内核含 `iptables` 与 `CONFIG_NETFILTER`（绝大多数 Root 机型具备） |
| 需要功能 | 热点（Soft AP）能用；UU 加速器已开启热点加速 |
| UDP 转发 | 额外要求内核含 `CONFIG_NETFILTER_TPROXY`（不确定也能用，仅 TCP 生效） |
| Android | minSdk 26（8.0+） |
| 主机端 | 无需任何配置，连热点即用 |

> **注意**：不同 ROM 的 SoftAP 接口名不同（`ap0`、`wlan1`、`swlan0`…），App 会自动探测，探测不到可在界面手动填写。

---

## 六、架构说明

### 1. 工程结构

```
uu-transparent-proxy/
├── README.md
├── settings.gradle.kts / build.gradle.kts / gradle.properties
├── gradlew / gradlew.bat / gradle/wrapper/*
├── .github/workflows/build.yml        # 云编译 workflow
└── app/
    ├── build.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/youyoudezhuzhu/uutransparentproxy/
        │   ├── MainActivity.kt          # MD3 主页
        │   ├── ProxyForegroundService.kt# 前台服务，保活
        │   ├── ProxyEngine.kt           # 单例编排核心 + UiState
        │   ├── RootShell.kt             # su 执行
        │   ├── IptablesManager.kt       # iptables/路由/接口探测/原子清理
        │   ├── NativeProxy.kt           # libuuproxy.so JNI 绑定
        │   ├── LogcatHelper.kt          # logcat 流式捕获
        │   └── ProxyModels.kt           # 配置/统计数据类
        ├── jni/
        │   ├── CMakeLists.txt
        │   ├── native-lib.c             # 自包含代理守护进程
        │   └── third_party/redsocks/    # redsocks/redsocks2 参考源码说明
        └── res/
            ├── layout/activity_main.xml # MD3 卡片式主页
            ├── values/ (colors/strings/themes)
            └── drawable/ + mipmap-anydpi-v26/ (图标)
```

### 2. Native 守护进程（`native-lib.c`）

- 以 **JNI 共享库 `libuuproxy.so`** 形态打进 APK，绑定**高端口**（默认 TCP `23333` / UDP `23334`），**无需 root 权限绑定**，运行在应用进程内。
- **TCP**：`accept` 被 REDIRECT 进来的连接 → `getsockopt(SO_ORIGINAL_DST)` 读原始目的 → 连接上游 `6.6.6.6:8088` → 按所选协议发 **SOCKS5 CONNECT**（可选账号密码）或 **HTTP CONNECT** → 双向多线程转发。
- **UDP**：建立 **SOCKS5 UDP ASSOCIATE**，对 TPROXY 引入的 UDP 封装为 SOCKS5 UDP 包转发；对 DNS 同样走该链路。
- 统计：原子计数器累计上行/下行字节与活跃连接数，供 UI 展示。

### 3. iptables / 路由（`IptablesManager.kt`）

**建链语义**（所有新增规则打 `-m comment --comment uuproxy`，便于精确回收）：

```bash
# IP 转发
sysctl -w net.ipv4.ip_forward=1 || echo 1 > /proc/sys/net/v4/ip_forward

# 自建链
iptables -t nat -N UUPROXY
# 放行本地/代理自身/组播，防自环
iptables -t nat -A UUPROXY -d 127.0.0.0/8 -j RETURN
iptables -t nat -A UUPROXY -d 6.6.6.6 -j RETURN
iptables -t nat -A UUPROXY -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# 热点进来的 TCP 全部 REDIRECT 到本地代理端口
iptables -t nat -A UUPROXY -p tcp -j REDIRECT --to-ports 23333 -m comment --comment uuproxy
iptables -t nat -A PREROUTING -i ap0 -j UUPROXY -m comment --comment uuproxy

# UDP (TPROXY, 内核支持时)
iptables -t mangle -N UUPROXY_UDP
iptables -t mangle -A UUPROXY_UDP -p udp -j TPROXY --on-port 23334 --tproxy-mark 0x1/0x1 -m comment --comment uuproxy
iptables -t mangle -A PREROUTING -i ap0 -j UUPROXY_UDP -m comment --comment uuproxy

# SNAT
iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE -m comment --comment uuproxy
```

**原子清理**：按 comment 逐条 `-D` 回滚，删除自建链，恢复 `ip_forward=0`，移除 TPROXY 的 `ip rule`/`ip route`。**绝不触碰其它应用的规则**（ProxyDroid 等各有自己的 comment）。

### 4. 为什么 redsocks 是“内置/引用”而非“编译进 APK”

原生 `redsocks` 依赖 `libevent`（`redsocks2` 还可选 `libcrypto`），打进 APK 会多 1~2MB 原生体积并引入交叉编译复杂度。本项目的守护进程用**自包含 C** 重实现了与 redsocks **完全相同的透明代理算法**（`SO_ORIGINAL_DST` + SOCKS5/HTTP CONNECT 到上游），零外部依赖（只用 NDK 自带 `libc`/`liblog`/pthread）。`redsocks` 源码作为权威参考随仓库入库（`app/src/main/jni/third_party/redsocks/`），需要直接编译 redsocks2 的方案见该目录 README。

---

## 七、编译教程

### 方式一：GitHub Actions 云编译（推荐，无需本地 Android SDK）

1. Fork / 自建仓库，把本项目推送上去；
2. 仓库 `Actions` 页签确认 workflow `Build APK (Cloud)` 已启用；
3. 手动触发（`workflow_dispatch`）或 push 到 `main` 自动触发；
4. 构建成功后，在本次 Run 的 **Artifacts** 下载 `uu-transparent-proxy-debug`（未签名 Debug APK）。

> Debug 包未签名，直装前需自行签名或用 `apksigner` 临时签名；如需 Release 签名，在 workflow 里加 `keytool` 自签即可（参见 `android-apk-cloud-build` 技能的签名片段）。

### 方式二：本地编译

需 Android SDK + NDK 26.1 + JDK 17：

```bash
git clone <你的仓库> && cd uu-transparent-proxy
chmod +x gradlew
./gradlew assembleDebug          # 产物 app/build/outputs/apk/debug/*.apk
./gradlew assembleRelease        # 如需 release
```

依赖下载较慢（首次拉 NDK/AGP/依赖），可用 `--offline` 复用本地缓存。

---

## 八、使用教程

1. **开启热点**：先别急着开 UU。在手机上开启热点（让另一台设备连上）。
2. **打开 UU 加速器**：开启“热点加速”，确认其监听 `6.6.6.6:8088`。
3. **打开本 App**：
   - 主页显示已探测到的热点接口与 WAN 接口（可手动改 / 点“重新探测”）；
   - 确认上游地址 `6.6.6.6`、端口 `8088`、转发协议（优先 SOCKS5）、UDP 开关；
   - 打开 **“启用加速”** 开关。
4. **主机连接热点**：设备连上热点，游戏直接进——无需任何代理设置。
5. **查看状态**：主页实时显示加速状态、连接设备数、上下行速率与 Logcat 日志。
6. **停止**：关闭开关即可，App 自动原子清空全部 iptables 与路由规则，主机恢复正常网络。
7. **出问题**：点 **“重置网络”** 执行紧急恢复，再手动排查。

---

## 九、技术细节

### TCP 原始目的地址
被 `REDIRECT` 的连接，通过 `getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &dst, &len)` 拿到客户端原本想访问的目的 IP:Port，再据此向 UU 代理发起 `CONNECT`。

### SOCKS5 CONNECT 握手
```
C->S: 05 01 00
S->C: 05 00
C->S: 05 01 00 01 [4B IPv4] [2B port]
S->C: 05 00 00 01 [BND.ADDR] [BND.PORT]
```

### HTTP CONNECT 握手
```
C->S: CONNECT <ip>:<port> HTTP/1.1\r\nHost: <ip>:<port>\r\nProxy-Connection: keep-alive\r\n\r\n
S->C: HTTP/1.1 200 Connection established\r\n\r\n
```

### UDP（TPROXY + UDP ASSOCIATE）
- 内核 mangle 表 `TPROXY --on-port 23334 --tproxy-mark` 把 UDP 引入本地；
- 守护进程起线程建立 SOCKS5 **UDP ASSOCIATE**，把每个 UDP 包封装为 `RSV(2)+FRAG(1)+ATYP(1)+ADDR+PORT+DATA` 发往代理的 UDP 中继地址；
- 对 DNS（:53）走同一链路，即“DNS 转发”。

### 自动接口探测
```
ip -o link show      # 枚举接口
ip route show default  # WAN 默认路由口
```
候选匹配热点名：`ap0`、`softap0`、`swlan0`、`wlan1`、`wlan2`、`hostap`、`sta0`、`dhd0`、`wifi_ap`、`p2p0`。

---

## 十、参考项目

| 项目 | 借鉴点 |
|------|--------|
| [redsocks](https://github.com/darkk/redsocks) | 透明 TCP → SOCKS4a/5 + HTTP CONNECT、`SO_ORIGINAL_DST` |
| [redsocks2](https://github.com/semigodking/redsocks) | UDP（`redudp`：TPROXY + `IP_RECVORIGDSTADDR` + SOCKS5 UDP ASSOCIATE） |
| [ProxyDroid](https://github.com/madeye/proxy) | iptables `REDIRECT`/`TPROXY` 规则、可增删的规则生命周期 |
| [SocksProxy-Android](https://github.com/Julian-Chu/SocksProxy-Android) | `SO_ORIGINAL_DST` 处理、Android 代理架构 |

本项目 Native 守护进程自包含实现上述算法，源码随仓库入库作参考。

---

## 十一、免责声明

- 本工具仅供**个人研究、学习网络转发原理**使用。
- 使用 Root + iptables 修改系统网络行为存在风险，可能影响系统稳定性；请在**知情并自行承担风险**的前提下使用。
- 请遵守所在地法律法规与服务条款，勿用于任何违规用途。
- 因使用本工具产生的任何设备/网络问题，作者不承担责任。

---

**License**：MIT

> 打包 / 云编译 / Release 发布流程参考自 `android-apk-cloud-build` 技能沉淀。
