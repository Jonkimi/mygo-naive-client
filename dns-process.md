# DNS 解析处理流程 (Embedded Sing-Box DNS & Blocker Pipeline)

本文档说明 `naive-client` 在内嵌 `github.com/sagernet/sing-box` 主干引擎后，结合内置双层广告拦截器（`internal/blocker`）处理 DNS 请求的完整先后顺序与决策流程。

---

## 一、处理流程图 (Flowchart)

```mermaid
flowchart TD
    Start(["客户端或 TUN 发起 DNS 查询<br/>(sing-box DNS Router)"]) --> S1{"阶段 1: 本地 Hosts & Tailnet MagicDNS"}

    %% 阶段 1
    S1 -->|命中自定义静态 Hosts| RespHosts["返回 Hosts 对应静态 IP"]
    S1 -->|属于 *.ts.net / Peer 短名 / Split DNS| QueryMagic["路由至 sing-box Tailscale Endpoint<br/>或宿主机 MagicDNS (100.100.100.100)"]
    S1 -->|未命中| S_IPv4{"阶段 1.5: IPv4 优先策略<br/>(strategy: prefer_ipv4 / ipv4_only)"}

    %% 阶段 1.5
    S_IPv4 -->|启用抑制 IPv6 且为 AAAA 请求| NoIPv6["⚡ 快速返回空记录 (NODATA)<br/>阻断无出口 IPv6 握手超时"]
    S_IPv4 -->|放行查询| S2{"阶段 2: 前置广告拦截 Hook<br/>(internal/blocker Engine)"}

    %% 阶段 2
    S2 -->|命中黑名单/AdGuard订阅/category-ads-all| BlockAd["🚫 本地直接阻断并记入 24h 时间桶<br/>返回 RCODE Refused / NXDOMAIN / 0.0.0.0"]
    S2 -->|未命中或命中白名单 (Allowlist)| S3{"阶段 3: sing-box 原生 DNS 缓存"}

    %% 阶段 3
    S3 -->|有效缓存命中| CacheHit["⚡ 内存极速返回 (&lt;1ms)"]
    S3 -->|未命中缓存| S4{"阶段 4: sing-box DNS 规则分流<br/>(DNS Rule Evaluation)"}

    %% 阶段 4
    S4 -->|节点自身域名 / DoH 域名<br/>domain_resolver: bootstrap-dns| S4_Boot["4.1 Bootstrap DNS (直连 223.5.5.5 / 1.12.12.12)<br/>强制走 direct 出站，破除先有鸡还是先有蛋死锁"]
    S4 -->|私有域名 / 命中 DIRECT 规则 / geosite:cn<br/>server: domestic-doh| S4_Dom["4.2 国内直连 DoH (https://223.5.5.5/dns-query)<br/>detour: direct，保障国内 CDN 就近调度"]
    S4 -->|其余境外域名 / 命中代理规则<br/>server: remote-doh| S4_Remote["4.3 海外防污染 DoH (https://1.1.1.1/dns-query)<br/>detour: PROXY_POOL (经智能代理池隧道出境)"]

    %% 阶段 5
    S4_Boot --> S5["阶段 5: 写入缓存与失败监控"]
    S4_Dom --> S5
    S4_Remote --> S5

    S5 -->|解析成功| StoreCache["写入 sing-box DNS 缓存 & 记录 Live Stream 日志"]
    S5 -->|SERVFAIL / Timeout| FailMon["上报 FailureMonitor (FailureDNS)<br/>供用户一键诊断或切换规则"]
    StoreCache --> Done(["返回 100% 真实 IP 响应给客户端"])

    RespHosts --> Done
    QueryMagic --> Done
    NoIPv6 --> Done
    BlockAd --> Done
    CacheHit --> Done
```

---

## 二、详细阶段说明

### 阶段 1：本地 Hosts 与 Tailnet MagicDNS（最高优先级，豁免广告拦截）
- **自定义 Hosts**：通过 `sing-box` DNS 预定义映射或前置 Hook 优先匹配用户配置的静态域名。
- **MagicDNS 路由**：对 `*.ts.net`、Tailnet Peer 机器短名及 Tailnet Split DNS 域名，直接路由至内嵌 `sing-box` `tailscale` Endpoint 的 DNS 解析器或宿主机 `100.100.100.100:53`，不经过广告拦截器且不向公网上游泄漏。

### 阶段 1.5：IPv4 优先 / 抑制无出口 IPv6（`PreferIPv4`）
- 当用户开启 `PreferIPv4` 时，利用 `sing-box` 原生 DNS `strategy`（`ipv4_only` / `prefer_ipv4`）抑制无效的 `AAAA` 解析等待，防止本地宽带无 IPv6 出口时触发 Happy Eyeballs 超时。

### 阶段 2：Pi-hole 广告拦截前置 Hook（`internal/blocker`）
- 在发起任何外部 DNS 请求前，先调用进程内 `blocker.Engine.Match(domain)`（采用反向域名压缩前缀树 `Suffix Trie`，单次匹配 `< 200ns`）。
- 严格遵循优先级：$\text{Tailnet 豁免} \rightarrow \text{用户白名单} \rightarrow \text{订阅 @@|| 豁免} \rightarrow \text{用户黑名单} \rightarrow \text{外部订阅与 category-ads-all}$。
- 命中拦截时直接本地拦截，同步更新内存中的 **24 小时趋势时间桶 (`HourlyBuckets`)**、**Top 拦截榜单**与 **2000 条环形决策流日志**。

### 阶段 3 & 4：`sing-box` 原生分流 DoH 与 Bootstrap 防死锁
借助 `sing-box` 原生 DNS Transports 与 `detour` 机制，彻底淘汰手写的 `miekg/dns` 转发代码：
1. **Bootstrap DNS (`bootstrap-dns`)**：
   - 绑定为所有节点 Outbound（含 Sidecar 远端服务器域名与原生 Outbound 域名）及 DoH Server 自身的 `domain_resolver`。
   - 强制通过 `direct` 物理网卡直连解析（默认 `https://223.5.5.5/dns-query` 或 `223.5.5.5:53`），从根源上消除 TUN 模式下“解析代理服务器域名又需要走代理隧道”的死锁。
2. **国内直连 DoH (`domestic-doh`)**：
   - 匹配 `geosite:cn`、`geosite:private` 及用户自定义 `DIRECT` 规则的域名，通过 `detour: "direct"` 走物理网卡请求国内加密 DoH，兼顾防劫持与最佳本地 CDN 调度。
3. **海外代理隧道 DoH (`remote-doh`)**：
   - 其余非大陆域名通过 `detour: "PROXY_POOL"`（复用我们自定义的 `PoolOutbound` 智能代理池）经由健康度最优的代理隧道请求 `https://1.1.1.1/dns-query` 或 `https://dns.google/dns-query`，返回 **100% 真实无污染 IP（不使用 FakeIP）**。

### 阶段 5：连接层原生嗅探（`sing-box Sniff`）与二次拦截互补
- 当操作系统或应用拿到真实 IP 并向 `:10809` 或 `TUN` 网卡发起 TCP / QUIC 连接时，内嵌 `sing-box` Inbound 自动开启 `sniff: true`（支持 TLS ClientHello `SNI`、HTTP `Host` 及 QUIC Initial `SNI` 嗅探）。
- 即使客户端浏览器开启了内置加密 DoH 绕过了本地 DNS 阶段，连接进入 `sing-box` 路由层时仍会根据嗅探还原出的真实子域名再次触发 `blocker.Engine.Match(domain)` 与分流规则匹配，实现 **DNS 层 + 连接嗅探层 100% 闭环拦截与精准分流**。
