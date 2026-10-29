<p align="center">
  <img src="resources/icon.png" width="128" height="128" alt="Naive Client Icon" />
</p>

<h1 align="center">Naive Client</h1>

<p align="center">
  <strong>基于 <a href="https://github.com/egoist/mygo">MyGo</a> 原生 GPU 渲染的跨平台 NaiveProxy 客户端管理器</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.27+-00ADD8?style=flat&logo=go" alt="Go Version" />
  <img src="https://img.shields.io/badge/GUI-MyGo%20(Pure%20Go%20GPU)-blue" alt="GUI Framework" />
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-green" alt="Platforms" />
  <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License" />
  <img src="https://img.shields.io/badge/Memory-~50MB%20Idle-brightgreen" alt="Memory Footprint" />
</p>

---

## 💡 特性一览

- 🚀 **极轻量原生体验**：基于 `egoist/mygo` 纯 Go 原生 GPU 渲染（Metal / Direct3D / OpenGL），无需 Electron / WebKit 运行时，日常空闲内存仅约 **50MB**。
- ⚡ **多服务独立并发管理**：
  - 支持配置并同时运行多个独立的本地 Naive 服务（SOCKS5、HTTP、Redir）。
  - 启动前自动进行本地 TCP 端口冲突探测，避免启动失败或端口被静默占用。
  - 独立进程守护与自动故障重启机制（指数退避重启，最多 3 次）。
- 📊 **主面板直观状态与测速**：
  - 卡片式展示每个服务的运行状态（`运行中` / `启动中` / `已停止` / `异常`）、PID、本地监听端点与远端脱敏地址。
  - **延迟测速**：基于 HTTP 204 精确测量代理握手与 RTT 延迟。
  - **下载测速**：多协程实时流式采样测速，直观展示实时带宽吞吐。
  - **实时日志**：每个服务独立内置环形缓冲日志查看器，支持按需展开/收起、一键清空与复制。
- 📋 **强大的批量导入与导出**：
  - **多行批量导入**：支持同时粘贴多行链接批量导入节点；支持 `https://user:pass@host:port`、`naive+https://`、`quic://` 以及完整的 `config.json`。
  - **智能 SNI 识别**：若导入链接含有 `?security=tls&sni=example.com` 参数，自动将 `sni` 作为远端节点地址（保留原始端口与认证信息）。
  - **自动端口分配**：批量导入时智能分配未占用的本地监听端口（从 1080 起递增）。
  - **一键分享**：支持导出 V2rayN 格式链接（`socks://127.0.0.1:port#alias`）与 Naive 分享链接。
- 🔄 **GitHub Releases 追踪与无感热更新**：
  - 自动跟踪 [klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy/releases) 最新发布版本并提示更新。
  - 内置纯 Go 实现的 `.tar.xz`（LZMA2 解压）与 `.zip` 归档解包器，无需系统安装第三方解压工具。
  - **无感热更新**：一键自动下载新版本、校验 SHA256 摘要、原子替换本地可执行文件，并**自动热重启更新前正在运行中的所有服务**。
  - 支持配置 GitHub 镜像加速前缀、专用更新代理，或直接通过当前运行中的本地服务代理下载更新。
- 💻 **深度系统集成**：
  - **系统托盘**：系统托盘菜单常驻，可在托盘快速启停任意服务或全部服务。
  - **开机自启**：支持开机静默随系统启动。
  - **外观主题**：支持跟随系统、明亮与暗黑主题切换；macOS 下支持灵活切换程序坞（Dock）与仅菜单栏模式。

---

## 🛠️ 项目结构

```text
├── main.go                       # 应用程序入口
├── mygo.json                     # MyGo 跨平台打包与元数据配置
├── internal/
│   ├── app/                      # UI 界面、菜单栏、系统托盘与用户交互
│   │   ├── app.go                # 应用核心生命周期与状态持久化
│   │   ├── ui_main.go            # 主面板（顶部栏、服务卡片、实时日志）
│   │   ├── ui_editor.go          # 服务编辑弹窗、多行导入弹窗、删除弹窗
│   │   ├── ui_settings.go        # 全局偏好设置弹窗
│   │   ├── tray.go               # 系统托盘菜单管理
│   │   └── palette.go            # 主题调色板与 UI 通用组件
│   ├── config/                   # 配置模型与链接解析
│   │   ├── config.go             # 对齐 USAGE.txt 的 Service 配置模型与 JSON 生成
│   │   └── share.go              # V2rayN 格式与 Naive 分享链接编解码、多行导入解析
│   ├── runner/                   # 多服务进程守护与测速引擎
│   │   ├── manager.go            # 独立进程生命周期管理、端口检查、崩溃重试
│   │   ├── probe.go              # SOCKS5/HTTP 代理拨号器、延迟测速、流式下载测速
│   │   └── logbuf.go             # 线程安全的环形实时日志缓冲区
│   └── updater/                  # 核心无感更新器
│       ├── updater.go            # GitHub Releases 匹配、SHA256 校验、热替换重启
│       └── xz.go                 # 纯 Go 实现的 XZ / LZMA2 解压器
```

---

## 🚀 快速上手

### 环境要求

- **Go**：1.27 或更高版本
- **系统支持**：
  - macOS 13.0+（支持 Apple Silicon 与 Intel）
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

### 运行自动化测试

项目遵循严格的行为与测试规范：

```bash
go test -v ./...
```

---

## 📦 打包构建

本项目使用 [`MyGo`](https://github.com/egoist/mygo) CLI 工具进行跨平台打包：

```bash
# 安装 / 使用 MyGo 工具
go tool mygo build

# 构建桌面应用包 (在 macOS 下生成 .app 捆绑包)
go tool mygo bundle
```

构建产物将输出在 `build/` 目录下。

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
4. **完整 JSON 配置**：
   ```json
   {
     "listen": "socks://127.0.0.1:1080",
     "proxy": "https://user:pass@example.com"
   }
   ```

---

## 📄 开源许可

本项目遵循 AGPL-3.0 许可证，详情请参阅 [LICENSE](LICENSE) 文件。
