# DNS 解析处理流程 (DNS Processing Pipeline)

本文档说明 `naive-client` 内置 DNS 解析器（`internal/dns/resolver.go`）在处理客户端 DNS 请求时的完整先后顺序与决策流程。

---

## 一、处理流程图 (Flowchart)

```mermaid
flowchart TD
    Start(["客户端发起 DNS 查询请求<br/>(Resolve / ResolveMsg)"]) --> S1{"阶段 1: 本地 Hosts & Tailnet"}

    %% 阶段 1
    S1 -->|命中自定义 Hosts| RespHosts["返回 Hosts 对应静态 IP"]
    S1 -->|属于 *.ts.net 等 MagicDNS| QueryMagic["转发至 Tailnet MagicDNS 100.100.100.100"]
    S1 -->|未命中| S_IPv4{"阶段 1.5: IPv4 优先<br/>(Prefer IPv4)"}

    %% 阶段 1.5
    S_IPv4 -->|启用且为 AAAA 请求| NoIPv6["⚡ 快速返回 NODATA (空记录)<br/>阻断 IPv6 避免无出口超时"]
    S_IPv4 -->|未启用或 A 请求| S2{"阶段 2: DNS 防广告<br/>(Blocker Engine)"}

    %% 阶段 2
    S2 -->|命中广告/黑名单| BlockAd["🚫 本地直接阻断<br/>Type A: 0.0.0.0 (TTL 60s)<br/>Type AAAA: :: (TTL 60s)<br/>其他: NXDOMAIN"]
    S2 -->|未命中/白名单放行| S3{"阶段 3: 本地 DNS 缓存 & SWR"}

    %% 阶段 3
    S3 -->|有效缓存 (Fresh &lt; TTL)| CacheHit["⚡ 极速缓存命中 (&lt;1ms)<br/>调整 TTL 并直接返回"]
    S3 -->|软过期 (Stale-While-Revalidate)| SWR["⚡ 乐观返回陈旧缓存 (TTL 1s)<br/>后台异步并发刷新"]
    S3 -->|未命中缓存 / 缓存完全失效| S4{"阶段 4: 出站分流与上游解析<br/>(fetchAndCache)"}
    SWR -.->|后台异步请求| S4

    %% 阶段 4
    S4 -->|节点域名 / DoH 域名<br/>isBootstrap| S4_Boot["4.1 Bootstrap DNS 解析<br/>(纯 IP UDP/TCP 53 直连)<br/>解救先有鸡还是先有蛋死锁"]
    S4 -->|私有域名 / Router 直连规则<br/>isDomesticOrDirect| S4_Dom["4.2 国内 DoH 解析<br/>(如 223.5.5.5/dns-query)<br/>走物理网卡直连"]
    S4 -->|其余境外/代理域名<br/>默认海外链路| S4_Remote["4.3 国外远程 DoH 解析<br/>(如 1.1.1.1 / 8.8.8.8)<br/>通过代理节点池加密隧道出境"]

    %% 阶段 5
    S4_Boot --> S5["阶段 5: 结果记录与写入缓存"]
    S4_Dom --> S5
    S4_Remote --> S5

    S5 --> RecIP["记录 IP 到 IPCache<br/>(用于网关反向嗅探纯 IP 连接)"]
    RecIP --> StoreCache["写入内存 TTL & SWR 缓存池"]
    StoreCache --> Done(["返回 DNS 响应给客户端"])

    RespHosts --> Done
    QueryMagic --> Done
    NoIPv6 --> Done
    BlockAd --> Done
    CacheHit --> Done
    SWR --> Done
```

---

## 二、详细阶段说明

### 阶段 1：本地 Hosts 与 Tailnet MagicDNS
- **自定义 Hosts**：优先比对用户配置的静态域名映射。
- **MagicDNS**：若属于 Tailnet 内部网络（如 `*.ts.net`），交由 Tailnet 专有 DNS 服务器（`100.100.100.100`）解析，不向公网上游泄漏。

### 阶段 1.5：IPv4 优先 / 抑制 IPv6（Prefer IPv4，默认开启）
- **触发条件**：启用 `PreferIPv4` 且客户端发起 `Type AAAA` 查询。
- **处理动作**：立即构造标准 `NOERROR` 空 Answer 回包（NODATA）。
- **优势**：当用户的物理路由器或宽带未分配公网 IPv6 时，彻底防止系统 Happy Eyeballs 发起无谓的 IPv6 握手等待与连接超时，促使操作系统/浏览器以最快速度使用 IPv4（A 记录）直连或代理。

### 阶段 2：DNS 防广告拦截（Blocker Engine）
- **触发条件**：匹配内置 `geosite:category-ads-all`、用户黑名单（Denylist）或外部 ABP / AdGuard 订阅。
- **处理动作**：
  - A 记录：直接构造回包 `0.0.0.0`（TTL 60s）；
  - AAAA 记录：构造回包 `::`（TTL 60s）；
  - 其它记录：返回 `NXDOMAIN`（NameError）；
- **优势**：在出站建立 TCP 之前就将广告掐死在本地，**产生 0 网络请求、0 外网流量**。

### 阶段 3：本地 TTL 缓存与 SWR 异步刷新
- **Fresh Cache**：在 TTL 期限内直接内存返回，响应时间 $<1\text{ms}$。
- **Stale-While-Revalidate (SWR)**：在软过期窗口期内，优先将陈旧缓存以 1 秒 TTL 响应给客户端（保证客户端零等待），同时后台起 goroutine 异步发起第 4 阶段解析并刷新缓存。

### 阶段 4：分流决策与上游解析（Upstream Resolution）
若缓存未命中，按域名分类发起三种不同上游通道：
1. **引导 DNS（Bootstrap DNS）**：
   - **适用目标**：代理节点的 VPS 域名、DoH 服务器本身的域名；
   - **协议**：系统本地或纯 IP 的经典 UDP/TCP 53（如 `223.5.5.5:53`）；
   - **目的**：打破“想要连代理先要解析节点域名，但解析又依赖代理”的循环死锁。
2. **国内直连 DoH（Domestic DoH）**：
   - **适用目标**：局域网私有域名、或分流规则命中 `ActionDirect`（如 `geosite:cn`、直连规则白名单）；
   - **通道**：走物理网卡直连国内加密 DoH，防止 DNS 污染同时获得最近 CDN 路由。
3. **国外代理 DoH（Remote DoH）**：
   - **适用目标**：未命中直连的所有海外网站与被拦截服务；
   - **通道**：通过 naive 出站节点池加密隧道（`DialProxy`）打向远端海外 DoH，彻底杜绝 GFW DNS 投毒与污染。

### 阶段 5：IP 反向索引与缓存固化
- **`recordIPs`**：将解析出来的 IP 与域名的映射关系暂存入 `IPCache`。当有旧应用或底层工具直接向网关端口发起纯 IP 握手时，网关能反向找回原始域名，从而继续执行精准分流与测速遥测。
- **`storeCache`**：按上游 TTL 写入本地缓存字典。
