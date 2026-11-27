<p align="center">
  <img src="resources/icon.png" width="128" height="128" alt="Naive Client Icon" />
</p>

<h1 align="center">Naive Client</h1>

<p align="center">
  <strong>基于 <a href="https://github.com/egoist/mygo">MyGo</a> 原生 GPU 渲染的跨平台代理客户端工作台、智能分流网关与 TUN / Tailscale / Cloudflare 网络管理中心</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Release-0.1.11-blue" alt="Latest Version" />
  <img src="https://img.shields.io/badge/Go-1.27+-00ADD8?style=flat&logo=go" alt="Go Version" />
  <img src="https://img.shields.io/badge/GUI-MyGo%20(Pure%20Go%20GPU)-blue" alt="GUI Framework" />
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-green" alt="Platforms" />
  <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License" />
</p>

---

## 💡 核心特性

### ⚡ 纯 Go 原生渲染与多协议统一架构
- **极轻量原生 GPU 渲染**：基于 `egoist/mygo` 纯 Go 图形栈直连操作系统现代图形 API（Metal、Direct3D、OpenGL），摒弃 Electron/Web 庞大运行时，冷启动秒开，极致流畅。
- **主流代理协议统一调度**：兼容主流代理协议及各类安全传输配置，由统一本地网关与多引擎调度架构集中托管，提供一致的节点管理、测速与路由体验。
- **进程隔离与生命周期绑定**：外部代理进程通过独立 Sidecar 沙箱机制托管并动态分配本地端口；集成系统级父子进程生命周期绑定与启动孤儿清理，彻底杜绝主程序退出后的进程残留。
- **核心组件在线热更新**：全自动检查版本并校验 SHA256 摘要，原子替换核心可执行文件后平滑热重启运行中服务。

### 🌐 云网络与私有网格（Cloudflare & Tailscale）
- **Cloudflare WARP & Tunnel 原生集成**：内置 Cloudflare WARP（支持优选接入点自适应扫描、丢包感知与抗阻断参数配置）及 Cloudflare Tunnel (`cloudflared`) 双向穿透，支持一键免配置设备注册与链路打通。
- **Tailscale (Tailnet) 原生网格**：支持内嵌节点与本机服务双模式接入，安全加密持久化 Auth Key，实时展示分配的 Tailnet 节点 IP，并支持 MagicDNS 内部域名解析与主机路由直连。

### 🛡️ 系统级 TUN 全局接管与网络加固
- **透明流量全量接管**：跨平台系统级 TUN 虚拟网卡模式，全面透明接管本机全量网络流量，原生支持双栈 IPv4 / IPv6。
- **特权网络助手（Privileged Helper）**：独立特权助手按需接管系统路由；自动为节点服务器注入物理避让路由，彻底杜绝路由回环与日志刷屏；异常或取消授权时平滑回退至本地端口代理模式，正常退出或崩溃时自动清理虚拟网卡并复原系统物理网络。

### 🎯 智能路由池、三态熔断与健康诊断
- **智能路由池（Smart Routing Pool）**：支持按节点或标签（Tag）组合调度与并发优选，提供平滑加权（EWMA）与按序故障转移策略，以及单端口统一本地代理入站（支持局域网接入与双栈回环）。
- **真实流量质量遥测与三态熔断**：持续追踪业务真实首包延迟（TTFB）、滑动窗口成功率与每节点 IPv6 出口探测；配备三态熔断器（正常、熔断冷却、半开连续探测恢复）、3.5 秒首包停顿探测与 8 秒硬超时，毫秒级快速切走假死节点并避免抖动误触发。
- **节点测速、健康诊断与 WARP 兜底**：支持延迟测速与可随时取消的下载带宽测速；内置节点连接诊断引导；代理池节点异常时支持自动无缝回退至 Cloudflare WARP 兜底通道，零可用节点时严格拦截防真实 IP 泄漏。

### 🧭 智能规则分流、加密 DNS 与广告拦截
- **可视化分流工作台**：内置精调预设规则（AI 服务、流媒体、国内直连、局域网、广告拦截等）与全量 CRUD 规则抽屉；支持灵活指定节点、标签代理池或直连/拦截动作；流式增量加载 `geoip.dat` 与 `geosite.dat`，大幅降低内存占用与堆碎片。
- **分级加密 DNS 与反向映射**：国内 / 远程 / 引导多级加密 DNS 解析架构与乐观缓存（Optimistic Cache），结合流量智能嗅探与 DNS 反向映射（Reverse Mapping）精准还原请求域名，根除解析死锁与污染；支持优先 IPv4 与完整 IPv6 解析策略。
- **高效广告拦截与 24h 洞察看板**：内置基于前缀/后缀树的高效域名拦截引擎，毫秒级阻断广告与追踪域名；「洞察」看板提供 24 小时趋势折线图、客户端应用名称识别、真实 RTT 耗时、路由链路追踪与阻断聚合折叠。

### 📊 双层诊断日志与现代工作台体验
- **独立诊断日志与全局日志抽屉**：除轻量侧拉日志抽屉外，提供两层式「诊断日志」工作台，分栏独立追踪网关核心、客户端事件与各节点子进程实时日志，支持级别过滤、关键字高亮检索、选行复制与一键导出排障。
- **现代交互与折叠侧栏**：支持紧凑图标导轨与展开式侧栏平滑切换、统一侧滑详情抽屉，以及在全局 / 规则 / 直连 / TUN 等流量模式间一键切换。
- **批量导入导出与全量国际化**：支持剪贴板多行代理节点链接与配置文件批量导入导出、智能传输参数识别；全应用类型安全中英文国际化与明暗主题无缝切换。

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
| <kbd>Cmd</kbd> + <kbd>1</kbd> ~ <kbd>7</kbd> | <kbd>Ctrl</kbd> + <kbd>1</kbd> ~ <kbd>7</kbd> | 切换工作台视图（节点 / 分流 / 洞察 / 组网 / Cloudflare / 运行日志 / 设置） |
| <kbd>Cmd</kbd> + <kbd>,</kbd> | <kbd>Ctrl</kbd> + <kbd>,</kbd> | 快速呼出设置页面 |
| <kbd>Cmd</kbd> + <kbd>B</kbd> | <kbd>Ctrl</kbd> + <kbd>B</kbd> | 展开或收起左侧导航栏 |
| <kbd>Esc</kbd> | <kbd>Esc</kbd> | 关闭当前打开的抽屉或弹窗 |
| <kbd>Cmd</kbd> + <kbd>N</kbd> | <kbd>Ctrl</kbd> + <kbd>N</kbd> | 新建代理节点 |
| <kbd>Cmd</kbd> + <kbd>Shift</kbd> + <kbd>V</kbd> | <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>V</kbd> | 从剪贴板导入节点 |
| <kbd>Cmd</kbd> + <kbd>R</kbd> | <kbd>Ctrl</kbd> + <kbd>R</kbd> | 检查核心组件更新 |
| <kbd>Cmd</kbd> + <kbd>Q</kbd> | <kbd>Ctrl</kbd> + <kbd>Q</kbd> | 退出应用程序 |

---

## 📄 开源许可

本项目遵循 AGPL-3.0 许可证，详情请参阅 [LICENSE](LICENSE) 文件。
