<p align="center">
  <img src="resources/icon.png" width="128" height="128" alt="Naive Client Icon" />
</p>

<h1 align="center">Naive Client</h1>

<p align="center">
  <strong>基于 <a href="https://github.com/egoist/mygo">MyGo</a> 原生 GPU 渲染的跨平台三内核客户端工作台、智能分流网关与 TUN / Tailscale / Cloudflare 网络管理中心</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Release-0.1.5-blue" alt="Latest Version" />
  <img src="https://img.shields.io/badge/Go-1.27+-00ADD8?style=flat&logo=go" alt="Go Version" />
  <img src="https://img.shields.io/badge/GUI-MyGo%20(Pure%20Go%20GPU)-blue" alt="GUI Framework" />
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-green" alt="Platforms" />
  <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License" />
</p>

---

## 💡 核心特性

### ⚡ 纯 Go 原生渲染与三内核架构
- **极轻量原生 GPU 渲染**：基于 `egoist/mygo` 纯 Go 图形栈直连操作系统现代图形 API（Metal、Direct3D、OpenGL），摒弃 Electron/Web 庞大运行时，冷启动秒开，极致流畅。
- **三内核（Tri-Core）统一调度**：同时整合 **NaiveProxy** 原生内核、**Sing-box** 嵌入式内核与 **Xray** 引擎，统一管理 Shadowsocks、VLESS、VMess、Trojan 与 NaiveProxy 等多协议节点。
- **Sidecar 隔离与进程硬绑定**：NaiveProxy 节点通过 Sidecar 独立进程托管，消除 CGO 依赖；集成系统级父子进程生命周期绑定，彻底杜绝孤儿进程残留。
- **内核在线无感热更新**：全自动检查、下载校验 SHA256 摘要，原子替换核心可执行文件并平滑热重启运行中服务。

### 🌐 云网络与私有网格（Cloudflare & Tailscale）
- **Cloudflare WARP & Tunnel 原生集成**：内置 Cloudflare WARP（支持 MASQUE over HTTP/3 与 WireGuard 模式）及 Cloudflare Tunnel (`cloudflared`) 双向穿透，支持一键免配置注册与网络打通。
- **Tailscale (Tailnet) 原生网格**：内嵌 Tailscale 虚拟网格引擎与专属控制面板，安全加密持久化 Auth Key，实时展示分配的 Tailnet 节点 IP，并支持 MagicDNS 内部域名解析。

### 🛡️ 系统级 TUN 全局接管与网络加固
- **透明流量全量接管**：跨平台系统级 TUN 虚拟网卡模式，全面透明接管本机所有网络流量。
- **特权网络助手（Privileged Helper）**：独立特权助手管理系统路由（`0/1` 与 `128/1`）；自动为节点服务器 IP 注入直连物理避让路由，彻底杜绝路由回环与日志刷屏；Windows 下自动劫持 DNS 防止泄漏。
- **自适应网络保护与回退**：TUN 启动异常或取消授权时平滑自动回退至端口代理模式；正常退出或崩溃时秒级自动清理虚拟网卡并复原系统物理网络，杜绝断网隐患。

### 🎯 智能路由池、健康诊断与 WARP 兜底
- **智能路由池（Smart Routing Pool）**：支持基于标签（Tag）调度与多节点并发优选；单端口混合 SOCKS5 / HTTP 统一入站。
- **真实流量质量遥测**：持续追踪业务真实首包延迟（TTFB）与滑动窗口成功率；引入空闲节点指数衰减（Passive EWMA Decay）与健康探测快洗机制，避免冷启动恢复死锁。
- **实时停顿探测与快速故障转移**：设置 8 秒硬超时与 3.5 秒首包停顿探测，毫秒级快速切走假死节点；多根域名相关性校验，隔离单站异常，杜绝熔断误触发。
- **节点健康诊断与 WARP 智能兜底**：内置节点连接诊断与智能排错引导；代理池节点异常时支持自动无缝回退至 Cloudflare WARP 兜底通道；零可用节点时严格拦截，防真实 IP 泄漏。

### 🧭 智能规则分流、标准 DNS 与广告拦截
- **可视化分流工作台**：内置 6 大精调预设（AI 国际/国内服务、流媒体、国内直连、广告拦截等）与全量 CRUD 规则抽屉；流式增量加载 `geoip.dat` 与 `geosite.dat`，大幅降低内存与堆碎片。
- **三级 Split-DoH 与反向映射**：国内 / 远程 / 引导三级 DNS 架构，根除 DoH 自解析死锁；支持 TLS SNI / HTTP Host 嗅探与 DNS 反向映射（Reverse Mapping），精准还原请求域名；支持优先 IPv4。
- **Pi-hole 广告拦截与 24h 洞察**：零拷贝后缀树毫秒级阻断广告与追踪；「洞察」看板提供 24 小时趋势折线图、真实 RTT 耗时、链路追踪（Chain）与阻断聚合折叠。

### 📊 独立诊断日志与现代工作台体验
- **双形态日志工作台**：除轻量侧拉日志抽屉外，新增独立「诊断日志」页面，支持按日志级别、核心子系统实时追踪、关键词检索与一键导出排障。
- **平滑自驱动折叠侧栏**：支持 40x40 紧凑图标导轨与展开式侧栏平滑弹簧切换，一键在全局 / 规则 / 直连 / TUN 等流量模式间快速切换。
- **批量导入与全量国际化**：支持剪贴板多行批量导入、智能 SNI 识别、导出 V2rayN / Naive 链接；全应用类型安全中英文国际化与主题无缝切换。

---

## 🚀 快速上手

### 环境要求

- **Go**：1.27 或更高版本
- **系统支持**：
  - macOS 13.0+（原生 Apple Silicon / Intel）
  - Linux（X11 / Wayland）
  - Windows 10/11

### 本地开发运行

```bash
# 1. 克隆代码仓库
git clone https://github.com/jonkimi/mygo-naive-client.git
cd naive-client

# 2. 下载依赖
go mod download

# 3. 本地直接运行
go run .
```

### 多语言国际化代码生成

修改或新增 `locales/*.json` 文案后，运行 MyGo 工具重新生成类型安全编目：

```bash
go tool mygo generate
```

### 运行自动化测试

```bash
go test -v ./...
```

---

## 📦 打包构建

本项目使用 [`MyGo`](https://github.com/egoist/mygo) CLI 工具进行跨平台打包：

```bash
# 构建单可执行程序
go tool mygo build

# 构建桌面应用包 (在 macOS 下生成 .app 捆绑包与 dmg 镜像)
go tool mygo bundle
```

构建产物将输出在 `build/` 目录下。

---

## ⌨️ 常用快捷键

| 快捷键 (macOS) | 快捷键 (Win / Linux) | 功能说明 |
| :--- | :--- | :--- |
| <kbd>Cmd</kbd> + <kbd>,</kbd> | <kbd>Ctrl</kbd> + <kbd>,</kbd> | 快速呼出全局偏好设置 |
| <kbd>Cmd</kbd> + <kbd>Q</kbd> | <kbd>Ctrl</kbd> + <kbd>Q</kbd> | 退出应用程序 |

---

## 📖 导入格式说明

在主界面点击 **「剪贴板导入」**，支持粘贴单行/多行链接或完整的 `config.json`：

1. **标准 HTTP/HTTPS 节点**：
   ```text
   https://username:password@example.com:443#香港节点
   ```
2. **Naive 协议前缀格式**：
   ```text
   naive+https://username:password@example.com:443#日本节点
   ```
3. **带 SNI 参数格式**（自动识别 `sni` 为节点地址）：
   ```text
   naive+https://user:pass@1.2.3.4:443?security=tls&sni=my-sni-domain.com#美国节点
   ```
4. **外部代理协议**：
   ```text
   socks5://127.0.0.1:10808#本地SOCKS代理
   ```
5. **完整 JSON 配置**：
   ```json
   {
     "listen": "socks://127.0.0.1:1080",
     "proxy": "https://user:pass@example.com"
   }
   ```

---

## 📄 开源许可

本项目遵循 AGPL-3.0 许可证，详情请参阅 [LICENSE](LICENSE) 文件。
