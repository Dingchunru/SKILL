---
name: tls-fingerprint-impersonation
description: 伪造 TLS ClientHello 与 JA4 指纹以实现浏览器仿冒。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, httpx, python3
metadata:
  tags: [recon, TLS, JA3, JA4, fingerprint, impersonation, HTTP, browser]
  category: recon
  related_skills:
    - http2-header-impersonation
    - stealth-browser-launch
    - humanize-automation
    - evasion-stack-guide
---

# TLS 指纹仿冒

伪造 TLS ClientHello 参数——加密套件、密钥交换组、签名算法和扩展顺序——以在 JA3/JA4 指纹层面匹配真实浏览器。使用打过补丁的 rustls 以与浏览器完全一致的配置重建 TLS 层。可绕过会把非浏览器 TLS 栈标记出来的 TLS 指纹检测（Cloudflare、Akamai、F5）。支持 20 个浏览器配置，包括 Chrome 100-142、Firefox 128-144、Safari iOS 18 以及 OkHttp 3-5（Android）。

## When to Use

- 即使 User-Agent 请求头正确，目标对 curl/httpx 仍返回 403 或封锁。
- Cloudflare 或 Akamai 正在对 TLS ClientHello 做指纹识别（JA3/JA4 与浏览器不匹配）。
- API 探测需要仿冒移动应用（Android 的 OkHttp 指纹）。
- 需要高吞吐的 HTTP 请求，且无需运行完整浏览器即可通过 TLS 指纹检查。
- 目标根据 TLS 指纹表现出不同行为（移动端与桌面端端点）。

## Prerequisites

- 具备 python3 的 `terminal`。
- Python：`pip install impit`（通过 PyO3 封装该 Rust 库）。
- 或 Node.js：`npm install impit`（原生绑定）。
- 或 Rust：在 Cargo.toml 中使用带补丁依赖的 `impit` crate。

## How to Run

```bash
# Check if a target blocks non-browser TLS
curl --max-time 30 --connect-timeout 10 -sk https://target.com | head -1
# If 403, test with browser impersonation:
python3 -c "
from impit import Impit
impit = Impit.builder().with_fingerprint('chrome142').build()
r = impit.get('https://target.com').text
print(r[:200])
"
```

## 快速检测

```bash
# Check if a target blocks non-browser TLS
curl --max-time 30 --connect-timeout 10 -sk https://target.com | head -1
# If 403, test with browser impersonation:
python3 -c "
from impit import Impit
impit = Impit.builder().with_fingerprint('chrome142').build()
r = impit.get('https://target.com').text
print(r[:200])
"
```

## Procedure

### 阶段 1 — 浏览器配置选择

为你的目标选择合适的指纹：

| 配置 | 使用场景 | 关键差异 |
|---|---|---|
| `chrome142` | 现代桌面端 | 最新 Chrome、后量子 KEX（X25519MLKEM768）、GREASE |
| `chrome100` | 旧版系统 | 较旧的加密套件，密钥交换中无 GREASE |
| `firefox144` | Firefox 桌面版 | 不同的伪首部顺序、FFDHE 组、SHA-1 签名 |
| `safari_ios18` | iOS 移动端 | 3DES 加密套件、重复签名算法、无会话票据 |
| `okhttp4` | Android 应用 | BoringSSL 配置、无 GREASE、无 ECH、更简单的加密套件 |
| `chrome124` | 常用默认 | 在现代兼容性与检测通过率之间取得良好平衡 |

```python
from impit import Impit

# Chrome 142 (latest)
client = Impit.builder().with_fingerprint("chrome142").build()

# Firefox 144
client = Impit.builder().with_fingerprint("firefox144").build()

# Safari iOS 18 (mobile API endpoints)
client = Impit.builder().with_fingerprint("ios18").build()

# OkHttp 4 (Android app impersonation)
client = Impit.builder().with_fingerprint("okhttp4").build()
```

### 阶段 2 — 基础请求

```python
from impit import Impit

impit = (
    Impit.builder()
    .with_fingerprint("chrome142")
    .with_ignore_tls_errors(True)  # for self-signed certs during recon
    .with_http3()                   # HTTP/3 support
    .with_fallback_to_vanilla(True) # retry without fingerprint if blocked
    .build()
)

response = impit.get("https://target.com")
print(response.status_code)
print(response.headers)
print(response.text()[:500])
```

### 阶段 3 — 使用代理

```python
impit = (
    Impit.builder()
    .with_fingerprint("chrome142")
    .with_proxy("http://user:pass@residential-proxy:8080")
    .with_default_timeout(15_000)  # 15 seconds in milliseconds
    .build()
)

response = impit.get("https://target.com/api/endpoint")
```

### 阶段 4 — 自定义请求头

```python
# Custom headers are merged with fingerprint defaults
# Fingerprint headers have lower priority — custom headers win on conflict
response = impit.get(
    "https://target.com/api/v1",
    headers={
        "X-Forwarded-For": "203.0.113.42",
        "Authorization": "Bearer token",
    }
)
```

### 阶段 5 — Cookie 会话

```python
from impit.cookie import Jar

impit = (
    Impit.builder()
    .with_fingerprint("chrome142")
    .with_cookie_store(Jar())  # persistent cookie jar
    .build()
)

# Login
impit.post("https://target.com/login", json={
    "username": "admin", "password": "admin"
})

# Authenticated request — cookies preserved automatically
response = impit.get("https://target.com/dashboard")
```

### 阶段 6 — 指纹选择逻辑

根据目标特征进行选择：

```python
def select_fingerprint(target_url):
    """Auto-select browser fingerprint based on target."""
    if "mobile" in target_url or "api/v2" in target_url:
        return "ios18"
    elif "android" in target_url or "play.google" in target_url:
        return "okhttp4"
    elif target_url.startswith("https://"):
        return "chrome142"  # default for modern HTTPS
    return "chrome124"
```

### 阶段 7 — JA4 哈希校验

验证你的 TLS 指纹是否正确生效：

```bash
# Test against a site that returns JA4 hash in response headers
python3 -c "
from impit import Impit
impit = Impit.builder().with_fingerprint('chrome142').build()
r = impit.get('https://cloudflare.com/cdn-cgi/trace')
print(r.text())
# Look for JA4 hash in trace output or response headers
"
```

## 浏览器指纹参考

### 各浏览器的 TLS 配置

| 特性 | Chrome 142 | Firefox 144 | Safari iOS 18 | OkHttp 4 |
|---|---|---|---|---|
| TLS 版本 | 1.3 + 1.2 | 1.3 + 1.2 | 1.3 + 1.2 | 1.3 + 1.2 |
| GREASE 加密套件 | ✅ (pos 1) | ❌ | ✅ | ❌ |
| GREASE 密钥交换 | ✅ (pos 1) | ❌ | ✅ | ❌ |
| 后量子（MLKEM768） | ✅ | ✅ | ✅ | ❌ |
| FFDHE 组 | ❌ | ✅ (2048/3072) | ❌ | ❌ |
| SHA-1 签名 | ❌ | ✅ | ✅ (legacy) | ✅ (RSA only) |
| ECH GREASE | ✅ | ✅ | ❌ | ❌ |
| 3DES 加密套件 | ❌ | ❌ | ✅ | ❌ |
| 证书压缩 | Brotli | Zlib+Brotli+Zstd | Zlib | ❌ |
| 委派凭证 | ❌ | ✅ | ❌ | ❌ |
| 会话票据 | ✅ | ✅ | ❌ | ✅ |
| 重复签名 | ❌ | ❌ | ✅ (RsaPssRsaSha384) | ❌ |

### 各浏览器的 HTTP/2 设置

| 浏览器 | 流窗口 | 连接窗口 | 伪首部顺序 |
|---|---|---|---|
| Chrome | 6,291,456 | 15,663,105 | `:method :authority :scheme :path` |
| Firefox | 131,072 | 12,517,377 | `:method :path :authority :scheme` |
| Safari iOS | 2,097,152 | 10,485,760 | `:method :scheme :authority :path` |
| OkHttp | 16,777,216 | 16,777,216 | `:method :path :authority :scheme` |

### Multipart 边界格式

| 浏览器 | 格式 | 示例 |
|---|---|---|
| Chrome | `----WebKitFormBoundary` + 16 位字母数字 | `----WebKitFormBoundaryx8fH3kLm9pQr2sTv` |
| Firefox | `----geckoformboundary` + 十六进制 u64 值 | `----geckoformboundary3fa8c10e5d6b2904` |
| OkHttp | UUID v4 | `550e8400-e29b-41d4-a716-446655440000` |

## Pitfalls

- **并非所有站点都使用 TLS 指纹识别。** 先用 curl 测试——若可行，则 TLS 指纹并非阻断原因。
- **指纹必须与 User-Agent 匹配。** 使用 Chrome 的 TLS 搭配 Firefox 的 UA 请求头会被检测到。
- **仅支持 HTTP/1.1 的站点不使用 HTTP/2 仿冒。** `with_http3()` 参数只对支持它的站点有意义。
- **OkHttp 3 仅支持 TLS 1.2。** 部分现代服务器会拒绝 TLS 1.2 连接。
- **TLS 指纹缓存使首次请求最慢。** `CryptoProvider` 实例按指纹缓存——后续请求很快。
- **Vanilla 回退可能泄漏你真实的 TLS 指纹。** 若隐蔽性至关重要，请禁用 `vanilla_fallback`。

## Verification

1. 使用 `https://www.howsmyssl.com/` 或 Cloudflare trace 端点确认 TLS 指纹与目标浏览器匹配。
2. 访问受 Cloudflare 保护的站点时检查 `cf-ja4` 响应头。
3. 验证使用浏览器指纹相比原生 curl 时，响应状态是否从 403 变为 200。
4. 使用多个浏览器配置测试，找出能通过目标检测的那一个。

---

## 相关技能

- **`http2-header-impersonation`** — HTTP/2 伪首部顺序与 SETTINGS 帧匹配。
- **`stealth-browser-launch`** — 针对重 JavaScript 目标，使用带 C++ 指纹补丁的完整浏览器自动化。
- **`humanize-automation`** — 类人交互模式，用于绕过行为检测。
