<p align="center">
  <img src="resources/icon.png" width="128" height="128" alt="Naive Client Icon" />
</p>

<h1 align="center">Naive Client</h1>

<p align="center">
  <strong>基于 <a href="https://github.com/egoist/mygo">MyGo</a> 原生 GPU 渲染的跨平台 NaiveProxy 客户端工作台与智能分流网关</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Release-0.1.2-blue" alt="Latest Version" />
  <img src="https://img.shields.io/badge/Go-1.27+-00ADD8?style=flat&logo=go" alt="Go Version" />
  <img src="https://img.shields.io/badge/GUI-MyGo%20(Pure%20Go%20GPU)-blue" alt="GUI Framework" />
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-green" alt="Platforms" />
  <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License" />
  <img src="https://img.shields.io/badge/Memory-~50MB%20Idle-brightgreen" alt="Memory Footprint" />
</p>

---

## 💡 特性一览

### 🚀 极轻量原生 GPU 渲染体验
- **Pure Go 原生渲染**：基于 `egoist/mygo` 纯 Go 图形栈，直连操作系统底层现代图形 API（macOS Metal、Windows Direct3D、Linux OpenGL/Wayland）。
- **零 Web 运行时开销**：摒弃 Electron、Chromium 或 WebKit 等庞大浏览器运行时，日常空闲内存仅约 **50MB**，启动秒开且帧率稳定流畅。

### ⚡ 统一入站代理网关与真实流量遥测 (Phase 1)
- **混合协议统一入站**：提供单端口混合 SOCKS5 / HTTP 统一入站网关，支持启动前自动检测端口冲突。
- **自适应真实流量遥测**：内置质量监测引擎，持续追踪业务流量真实 RTT 延迟、抖动与请求成功率，多节点并发动态评分。
- **域名亲和防抖优选**：基于主域名的记忆优选调度算法，保持会话稳定性的同时自动选择最佳健康节点。
- **智能故障熔断与防直连泄漏**：节点故障毫秒级自动容灾切换；当指定标签（Tag）或全局代理池为 0 可用节点时**严格拦截请求**，杜绝静默回退物理网卡暴露真实 IP。
- **一键系统代理接管**：跨平台深度适配 macOS、Windows、Linux 系统网络代理设置，开关随心。

### 🧭 智能规则分流引擎与可视化工作台 (Phase 2)
- **开箱即用预设规则组**：内置 6 大精调预设卡片（AI 国际与国内服务预设 `category-ai-!cn` / `category-ai-cn`、流媒体、国内直连、广告拦截等）。
- **细粒度多维度匹配**：支持 Domain 域名、IP/CIDR、GeoSite、GeoIP、Port 端口、Protocol 协议等多条件组合分流。
- **可视化规则抽屉**：抽屉式规则编辑器，提供全量 CRUD 操作；集成 Chips 标签选择器与 GeoSite / GeoIP 标签快速联想。
- **分流优先级严谨设计**：自定义规则排在预设规则之前优先命中，规则生效顺序直观可视。

### 🌐 标准三级 Split-DoH 与透明流量嗅探 (ADR 0003)
- **标准三级 DNS 架构**：国内 DNS (Domestic)、远程 DNS (Remote) 与引导 DNS (Bootstrap)，彻底根除 DoH 解析自循环与递归死锁。
- **预设丰富与自定义上游**：国内 DNS 默认采用阿里 DoH (`https://223.5.5.5/dns-query`)，内置腾讯 DNSPod、Cloudflare、Google、Quad9 等丰富预设，支持自由配置自定义 DoH。
- **透明流量嗅探与 IP 反查**：内置 TLS SNI 与 HTTP Host 流量嗅探器，结合 IP-Domain 映射缓存，精准还原直连或透明代理纯 IP 请求的原始域名。
- **智能 IPv4 优先**：支持一键开启「优先 IPv4」选项，智能拦截 AAAA 记录查询并优先直连 IPv4，规避部分网络环境下的 IPv6 超时与解析黑洞。

### 🛡️ 高性能广告拦截与 24 小时洞察看板 (ADR 0004)
- **Pi-hole 后缀树算法**：基于 Suffix Trie 的超轻量广告与追踪域名阻断，零拷贝毫秒级极速阻断广告与追踪域名。
- **共享 Geodata 数据库**：与分流规则共享 Geosite 广告数据库，并在禁用时自动释放缓存内存。
- **「洞察 (Insights)」数据看板**：直观呈现 24 小时实时拦截比例、每小时查询走势折线图、Top 拦截域名榜单与 Top 放行域名榜单，等高对比清晰易读。

### 🗄️ 流式 Geodata 规则库与极致内存优化
- **流式 Protobuf 解析**：采用流式增量解析与标签缓存技术加载 `geoip.dat` 与 `geosite.dat`，大幅消除小对象内存分配与堆碎片。
- **增量标签差量加载**：规则启停按需差量加载 Tag，未激活的规则不占用额外内存。
- **规则库在线更新**：支持一键在线更新规则库，支持自定义配置直连或跟随代理通道下载。

### 🖥️ 多节点并发管理与测速诊断
- **独立进程守护**：每个 NaiveProxy 进程独立隔离，支持本地 TCP 端口冲突探测与指数退避崩溃自动重启（最多 3 次）。
- **高精度测速**：基于 HTTP 204 精确测量代理握手与 RTT 延迟；多协程实时流式采样测速，直观展示实时带宽吞吐。
- **环形缓冲与全局日志抽屉**：每个节点独立保留环形缓冲区日志；全新独立滑入式全局日志抽屉，支持清空、复制与遮罩淡入淡出动效。

### 🎨 现代工作台交互与全应用国际化 (ADR 0008)
- **自驱动平滑折叠侧栏**：支持 40x40 紧凑图标导轨与展开式侧栏切换，带有平滑弹簧（Spring）过渡动画与悬停展开指示。
- **优雅抽屉过渡动效**：全局日志抽屉与规则抽屉均采用 MyGo `ElementTransition` 实现丝滑滑入与背景遮罩淡入淡出。
- **独立偏好设置页**：统一将内核管理、网络代理、下载通道与 DNS 整合至 Settings 页面，支持标准 `Cmd+,`（macOS）或快捷键秒级呼出。
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

## 🛠️ 项目结构

```text
├── main.go                       # 应用程序主入口
├── mygo.json                     # MyGo 跨平台打包、元数据与 i18n 配置
├── locales/                      # 应用多语言国际化目录
│   ├── locales.go                # 语言检测与解析
│   ├── en.json                   # 英文文案目录
│   ├── zh-Hans.json              # 简体中文文案目录
│   └── catalog_gen.go            # mygo generate 自动生成的类型安全多语言编目
├── docs/                         # 项目设计与架构决策记录 (ADR)
│   ├── adr/                      # 架构决策文档 (0001~0008)
│   ├── TODOLIST.md               # 规则分流与控制面问题清单
│   └── glossary.md               # 专有名词与架构概念说明
├── internal/
│   ├── app/                      # UI 工作台界面、导航侧栏与交互逻辑
│   │   ├── app.go                # 应用核心状态持久化、生命周期管理
│   │   ├── ui_main.go            # 节点列表工作台（顶部栏、服务卡片、状态流）
│   │   ├── ui_sidebar.go         # 平滑折叠侧栏、导航导轨与快捷键切换
│   │   ├── ui_routing.go         # 规则分流工作台（预设规则网格、规则列表）
│   │   ├── ui_drawer_rule.go     # 规则编辑抽屉（多维匹配条件、Chips 标签选择器）
│   │   ├── ui_insights.go        # 洞察看板（24h 拦截率、查询趋势图、Top 统计）
│   │   ├── ui_drawer_log.go      # 全局平滑滑入式日志抽屉
│   │   ├── ui_settings.go        # 全局偏好设置（DNS、内核管理、下载通道、通用设置）
│   │   ├── ui_editor.go          # 节点编辑与多行批量导入弹窗
│   │   ├── settings.go           # 偏好设置状态与持久化逻辑
│   │   ├── palette.go            # 主题调色板与通用 UI 渲染组件
│   │   ├── icons.go              # 内置矢量图标集
│   │   ├── menu.go               # 原生应用主菜单定义
│   │   └── tray.go               # 系统托盘菜单常驻管理
│   ├── gateway/                  # 统一入站代理网关
│   │   └── gateway.go            # 混合 SOCKS5 / HTTP 统一入站、流量调度与分流拦截
│   ├── routing/                  # 智能规则分流引擎
│   │   └── router.go             # 预设规则组、多维匹配规则树、防直连泄漏机制
│   ├── dns/                      # 三级 Split-DoH 解析引擎
│   │   ├── resolver.go           # 国内/远程/引导 DoH 调度与优先 IPv4 拦截
│   │   ├── server.go             # 本地 DNS 服务入站
│   │   ├── ipcache/              # IP-Domain 映射缓存，用于纯 IP 域名还原
│   │   └── sniffer/              # TLS SNI 与 HTTP Host 透明流量嗅探器
│   ├── blocker/                  # 高性能广告与追踪拦截器
│   │   ├── engine.go             # 拦截引擎核心协调器
│   │   ├── trie.go               # 基于 Pi-hole 后缀树算法的高性能域名 Trie 树
│   │   ├── logger.go             # 24 小时滚动时间桶统计与 Top 域名排行
│   │   └── parser.go             # Adblock 规则解析器
│   ├── geodata/                  # 流式 Geodata 规则库引擎
│   │   ├── geodata.go            # 流式 Protobuf 解析器、增量标签缓存、零碎堆内存优化
│   │   └── updater.go            # geoip.dat / geosite.dat 在线下载与自动更新
│   ├── telemetry/                # 真实流量质量遥测
│   │   └── tracker.go            # RTT 延迟、抖动、域名亲和调度与智能故障熔断
│   ├── sysproxy/                 # 跨平台系统代理集成
│   │   └── sysproxy.go           # macOS / Windows / Linux 系统代理一键开关与恢复
│   ├── runner/                   # 多服务进程守护与测速引擎
│   │   ├── manager.go            # 独立进程生命周期管理、端口检查、崩溃重试
│   │   ├── probe.go              # SOCKS5/HTTP 代理拨号器、延迟测速、流式下载测速
│   │   └── logbuf.go             # 线程安全的环形实时日志缓冲区
│   ├── updater/                  # 核心无感更新器
│   │   ├── updater.go            # GitHub Releases 匹配、SHA256 校验、热替换重启
│   │   └── xz.go                 # 纯 Go 实现的 XZ / LZMA2 解压器
│   └── config/                   # 配置模型与链接解析
│       ├── config.go             # 对齐 USAGE.txt 的 Service 配置模型与 JSON 生成
│       └── share.go              # V2rayN 格式与 Naive 分享链接编解码、多行导入解析
```

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
