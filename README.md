<p align="center">
  <img src="resources/icon.png" width="128" height="128" alt="Naive Client Icon" />
</p>

<h1 align="center">Naive Client</h1>

<p align="center">
  <strong>基于 <a href="https://github.com/egoist/mygo">MyGo</a> 原生 GPU 渲染的跨平台三内核客户端工作台、智能分流网关与 TUN / Tailscale 网络管理中心</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Release-0.1.3-blue" alt="Latest Version" />
  <img src="https://img.shields.io/badge/Go-1.27+-00ADD8?style=flat&logo=go" alt="Go Version" />
  <img src="https://img.shields.io/badge/GUI-MyGo%20(Pure%20Go%20GPU)-blue" alt="GUI Framework" />
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-green" alt="Platforms" />
  <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License" />
  <img src="https://img.shields.io/badge/Memory-70MB~%20Idle-brightgreen" alt="Memory Footprint" />
</p>

---

## 💡 特性一览

### 🚀 极轻量原生 GPU 渲染体验
- **Pure Go 原生渲染**：基于 `egoist/mygo` 纯 Go 图形栈，直连操作系统底层现代图形 API（macOS Metal、Windows Direct3D、Linux OpenGL/Wayland）。
- **零 Web 运行时开销**：摒弃 Electron、Chromium 或 WebKit 等庞大浏览器运行时，日常空闲内存仅 **70MB~**，启动秒开且帧率稳定流畅。

### 🌐 系统级 TUN 全局接管与网络助手
- **透明流量接管**：跨平台系统级 TUN 虚拟网卡模式，全面透明接管本机所有进程网络流量，支持免代理环境应用平滑上网。
- **跨平台特权网络助手**：内置独立的 Privileged Helper，通过跨平台安全套接字传递 TUN 设备文件描述符，严格最小特权设计。
- **自适应网络保护与恢复**：客户端正常退出或意外崩溃时，网络助手自动清理虚拟设备并秒级恢复物理网卡与系统网络配置，杜绝断网隐患。

### 🔒 Tailscale (Tailnet) 私有网络无缝集成
- **原生 Tailscale 引擎**：内嵌 Tailscale 虚拟网格引擎与独立工作台面板，支持在单一客户端中便捷管理企业或私有网络接入。
- **安全凭据与状态卡片**：安全持久化加密 Auth Key，实时分配并展示专属 Tailnet 节点 IP，一览内网设备连接状态。

### ⚙️ 三内核架构（Tri-Core）与多协议节点管理
- **三内核统一调度**：同时整合并托管 **NaiveProxy** 原生内核、**Sing-box** 嵌入式内核与 **Xray** 引擎，支持多协议节点统一管理。
- **多协议节点编辑器**：支持灵活编辑与配置 Shadowsocks、VLESS、VMess、Trojan 与 NaiveProxy 等主流协议。
- **Sidecar 独立隔离**：NaiveProxy 节点通过 Sidecar 独立进程托管，消除 CGO 依赖与动态库冲突，完美支持跨平台纯 Go 编译分发。
- **内核在线热更新**：支持在线全自动检查、下载校验 SHA256 摘要与平滑热替换各核心可执行文件。

### ⚡ 智能路由池与自适应遥测网关
- **智能路由池（Smart Routing Pool）**：提供直观的代理池策略卡片与弹出面板，支持基于标签（Tag）调度与多节点并发优选，实现毫秒级故障转移与高可用保障。
- **全方位真实流量遥测**：内置质量监测引擎，持续追踪业务流量真实首包延迟（TTFB）、滑动窗口成功率、静默/冷启动探针、RTO 停顿与自适应熔断逃逸。
- **混合协议统一入站**：提供单端口混合 SOCKS5 / HTTP 统一入站网关，支持启动前自动检测端口冲突。
- **智能故障熔断与防直连泄漏**：当指定标签或全局代理池 0 节点在线时**严格拦截请求**，杜绝静默回退物理网卡暴露真实 IP。

### 🧭 智能规则分流引擎与可视化工作台
- **开箱即用预设规则组**：内置 6 大精调预设卡片（AI 国际与国内服务预设 `category-ai-!cn` / `category-ai-cn`、流媒体、国内直连、广告拦截等）。
- **细粒度多维度匹配**：支持 Domain 域名、IP/CIDR、GeoSite、GeoIP、Port 端口、Protocol 协议等多条件组合分流。
- **可视化规则抽屉**：抽屉式规则编辑器，提供全量 CRUD 操作；集成 Chips 标签选择器与 GeoSite / GeoIP 标签快速联想。
- **分流优先级严谨设计**：自定义规则排在预设规则之前优先命中，规则生效顺序直观可视。

### 🌐 标准三级 Split-DoH 与透明流量嗅探
- **标准三级 DNS 架构**：国内 DNS (Domestic)、远程 DNS (Remote) 与引导 DNS (Bootstrap)，彻底根除 DoH 解析自循环与递归死锁。
- **预设丰富与自定义上游**：国内 DNS 默认采用阿里 DoH (`https://223.5.5.5/dns-query`)，内置腾讯 DNSPod、Cloudflare、Google、Quad9 等丰富预设，支持自由配置自定义 DoH。
- **透明流量嗅探与 IP 反查**：内置 TLS SNI 与 HTTP Host 流量嗅探器，结合 IP-Domain 映射缓存与并发重复去重，精准还原纯 IP 请求的原始域名。
- **智能 IPv4 优先**：支持一键开启「优先 IPv4」选项，智能拦截 AAAA 记录查询并优先直连 IPv4，规避部分网络环境下的 IPv6 超时与解析黑洞。

### 🛡️ 高性能广告拦截与 24 小时洞察看板
- **Pi-hole 后缀树算法**：基于 Suffix Trie 的超轻量广告与追踪域名阻断，零拷贝毫秒级极速阻断广告与追踪域名。
- **共享 Geodata 数据库**：与分流规则共享 Geosite 广告数据库，并在禁用时自动释放缓存内存。
- **「洞察 (Insights)」数据看板**：全新重构 24 小时实时拦截比例、折线趋势图、精确查询耗时、端到端落地节点标记（Chain 链路追踪）与失败高亮。

### 🗄️ 流式 Geodata 规则库与极致内存优化
- **流式 Protobuf 解析**：采用流式增量解析与标签缓存技术加载 `geoip.dat` 与 `geosite.dat`，大幅消除小对象内存分配与堆碎片。
- **增量标签差量加载**：规则启停按需差量加载 Tag，未激活的规则不占用额外内存。
- **规则库在线更新**：支持一键在线更新规则库，支持自定义配置直连或跟随代理通道下载。

### 🎨 现代工作台交互与全应用国际化
- **统一导航侧栏状态卡片**：聚合网关状态、Tailnet 指示、流量模式切换（全局/规则/直连）与快捷键导轨，信息层级更紧凑清晰。
- **节点详情抽屉（Node Drawer）**：独立节点属性抽屉，便捷查看节点协议参数、实时带宽及遥测健康度。
- **自驱动平滑折叠侧栏**：支持 40x40 紧凑图标导轨与展开式侧栏切换，带有平滑弹簧（Spring）过渡动画与悬停展开指示。
- **优雅抽屉过渡动效**：全局日志抽屉、规则抽屉与节点抽屉均采用 MyGo `ElementTransition` 实现丝滑滑入与背景遮罩淡入淡出。
- **全量中英文多语言国际化**：基于 `locales/*.json` 与 `mygo generate` 自动生成类型安全的多语言编目，支持跟随系统或手动切换。

### 📋 强大的批量导入与导出
- **多行批量导入**：支持同时粘贴多行链接批量导入节点；支持 `https://user:pass@host:port`、`naive+https://`、`quic://`、外部代理（`socks5://`、`http://`）以及完整的 `config.json`。
- **智能 SNI 识别**：若导入链接含有 `?security=tls&sni=example.com` 参数，自动将 `sni` 作为远端节点地址（保留原始端口与认证信息）。
- **自动端口分配**：批量导入时智能分配未占用的本地监听端口（从 1080 起递增）。
- **一键分享**：支持导出 V2rayN 格式链接（`socks://127.0.0.1:port#alias`）与 Naive 分享链接。

### 🔄 GitHub Releases 追踪与无感热更新
- 自动跟踪 [klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy/releases) 最新发布版本并提示更新。
- 内置纯 Go 实现的 `.tar.xz`（LZMA2 解压）与 `.zip` 归档解包器，无需系统安装第三方解压工具。
- **无感热更新**：一键自动下载新版本、校验 SHA256 摘要、原子替换本地可执行文件，并**自动热重启更新前正在运行中的所有服务**。
- 支持配置 GitHub 镜像加速前缀、专用更新代理，或直接通过当前运行中的本地服务代理下载更新。

### 💻 深度系统集成
- **系统托盘**：系统托盘菜单常驻，可在托盘快速启停任意服务或全部服务。
- **开机自启**：支持开机静默随系统启动。
- **外观主题**：支持跟随系统、明亮与暗黑主题切换；macOS 下支持灵活切换程序坞（Dock）与仅菜单栏模式。

---

## 🚀 快速上手

### 环境要求

- **Go**：1.27 或更高版本
- **系统支持**：
  - macOS 13.0+（原生支持 Apple Silicon 与 Intel）
  - Linux（X11 / Wayland，需安装基础 C 运行时与图形库）
  - Windows 10/11

### 本地开发运行

```bash
# 1. 克隆代码仓库
git clone https://github.com/your-username/naive-client.git
cd naive-client

# 2. 下载依赖
go mod download

# 3. 本地直接运行
go run .
```

### 多语言国际化代码生成

若修改或新增了 `locales/*.json` 中的文案，使用 MyGo 工具重新生成类型安全的语言编目：

```bash
go tool mygo generate
```

### 运行自动化测试

项目遵循严格的行为与测试规范：

```bash
go test -v ./...
```

---

## 📦 打包构建

本项目使用 [`MyGo`](https://github.com/egoist/mygo) CLI 工具进行跨平台打包：

```bash
# 安装 / 使用 MyGo 工具构建可执行程序
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

在主界面点击 **「剪贴板导入」**，支持粘贴多行（每行一条）或完整的 `config.json`：

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
