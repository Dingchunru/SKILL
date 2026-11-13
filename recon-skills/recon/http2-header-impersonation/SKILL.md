---
name: http2-header-impersonation
description: 按浏览器指纹配置伪造 HTTP/2 SETTINGS 帧与伪首部顺序。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, httpx, python3
metadata:
  tags: [recon, HTTP2, headers, fingerprint, impersonation, browser, JA4]
  category: recon
  related_skills:
    - tls-fingerprint-impersonation
    - stealth-browser-launch
    - evasion-stack-guide
---

# HTTP/2 请求头仿冒

伪造 HTTP/2 SETTINGS 帧、伪首部顺序以及浏览器特有的 HTTP 请求头，在协议层面与真实浏览器保持一致。目标是填补 TLS 指纹（ClientHello）与 JavaScript 指纹之间的检测空白 —— 即反机器人系统所分析的 HTTP/2 连接建立过程与请求头结构。可匹配 Chrome、Firefox、Safari iOS 和 OkHttp（Android）指纹配置，精确对齐窗口大小、请求头列表上限与请求头顺序。

## When to Use

- TLS 指纹已正确，但目标仍能检测出非浏览器的 HTTP 行为。
- 目标使用 HTTP/2 特有的检测手段（SETTINGS 帧分析、伪首部顺序）。
- 需要与浏览器完全一致的 `sec-ch-ua`、`Accept`、`Accept-Encoding`、`Priority` 和 `sec-fetch-*` 请求头。
- 移动端 API 端点要求 Android OkHttp 请求头指纹。
- 与 TLS 仿冒结合，构成完整的网络层浏览器指纹。

## Prerequisites

- 具备 python3 的 `terminal`。
- `pip install impit`（通过打过补丁的 h2 库支持 HTTP/2 仿冒）。
- 或者独立使用：参照下面的请求头列表手动配置 curl/httpx。

## How to Run

```bash
# Compare default client headers with a browser profile
export TARGET="https://target.com"

python3 - <<'PY'
import os
import requests

url = os.environ["TARGET"]
default = requests.get(url, timeout=15)
browser = requests.get(url, timeout=15, headers={
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.176 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
})
print(f"default: {default.status_code} {len(default.content)}b")
print(f"browser: {browser.status_code} {len(browser.content)}b")
if default.status_code != browser.status_code or len(default.content) != len(browser.content):
    print("DIFFERENTIAL — header-based detection likely")
PY
```

## 快速检测

```bash
# Check if target sends different responses based on HTTP headers
# Compare browser-like headers vs curl defaults

python3 -c "
import requests

# curl default headers
r1 = requests.get('https://target.com')
print(f'Default: {r1.status_code}')

# Browser-like headers
r2 = requests.get('https://target.com', headers={
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.176 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'sec-ch-ua': '\"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\"',
    'sec-ch-ua-platform': '\"Windows\"',
    'sec-ch-ua-mobile': '?0',
})
print(f'Browser: {r2.status_code}')
"
```

## Procedure

### 阶段 1 — 通过 impit 使用完整浏览器指纹

impit 库可从单一指纹配置中同时应用 HTTP/2 SETTINGS、伪首部顺序和 HTTP 请求头：

```python
from impit import Impit

# Chrome 142 — complete HTTP/2 + TLS + headers profile
impit = (
    Impit.builder()
    .with_fingerprint("chrome142")
    .build()
)

response = impit.get("https://target.com")
# Headers sent: sec-ch-ua, User-Agent, Accept, Accept-Encoding, Accept-Language,
#              sec-ch-ua-platform, sec-ch-ua-mobile, Priority, sec-fetch-*
# HTTP/2 SETTINGS: stream_window=6291456, conn_window=15663105, max_header=262144
# Pseudo-header order: :method :authority :scheme :path :protocol :status
```

### 阶段 2 — 手动配置请求头

对于没有 impit 的 curl/httpx，可手动配置请求头以匹配浏览器指纹：

#### Chrome 142 桌面端请求头

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.176 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br, zstd" \
  -H "sec-ch-ua: \"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not?A_Brand\";v=\"99\"" \
  -H "sec-ch-ua-arch: \"x86\"" \
  -H "sec-ch-ua-bitness: \"64\"" \
  -H "sec-ch-ua-full-version-list: \"Chromium\";v=\"142.0.7444.176\", \"Google Chrome\";v=\"142.0.7444.176\", \"Not?A_Brand\";v=\"99.0.0.0\"" \
  -H "sec-ch-ua-mobile: ?0" \
  -H "sec-ch-ua-model: \"\"" \
  -H "sec-ch-ua-platform: \"Windows\"" \
  -H "sec-ch-ua-platform-version: \"15.0.0\"" \
  -H "sec-ch-ua-wow64: ?0" \
  -H "sec-fetch-dest: document" \
  -H "sec-fetch-mode: navigate" \
  -H "sec-fetch-site: none" \
  -H "sec-fetch-user: ?1" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Priority: u=0, i"
```

#### Firefox 144 桌面端请求头

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Accept-Encoding: gzip, deflate, br, zstd" \
  -H "sec-ch-ua: \"Firefox\";v=\"144\", \"Not?A_Brand\";v=\"99\"" \
  -H "sec-ch-ua-mobile: ?0" \
  -H "sec-ch-ua-platform: \"Windows\"" \
  -H "sec-fetch-dest: document" \
  -H "sec-fetch-mode: navigate" \
  -H "sec-fetch-site: none" \
  -H "sec-fetch-user: ?1" \
  -H "TE: trailers" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Priority: u=0, i"
```

#### Safari iOS 18 请求头

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" \
  -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "sec-fetch-dest: document" \
  -H "sec-fetch-mode: navigate" \
  -H "sec-fetch-site: none"
```

#### OkHttp 4（Android）请求头

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" \
  -H "User-Agent: okhttp/4.12.0" \
  -H "Accept: application/json, text/plain, */*" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "Connection: Keep-Alive"
```

### 阶段 3 — 伪造 HTTP/2 SETTINGS 帧

HTTP/2 SETTINGS 帧在连接建立期间发送。curl 不会暴露这些帧 —— 需使用 impit 或打过补丁的 HTTP 客户端：

```python
from impit import Impit

# Chrome HTTP/2 SETTINGS:
#   SETTINGS_MAX_CONCURRENT_STREAMS: 1000
#   SETTINGS_INITIAL_WINDOW_SIZE: 6291456
#   SETTINGS_MAX_HEADER_LIST_SIZE: 262144
# Firefox HTTP/2 SETTINGS:
#   SETTINGS_MAX_CONCURRENT_STREAMS: 125
#   SETTINGS_INITIAL_WINDOW_SIZE: 131072

impit = Impit.builder().with_fingerprint("chrome142").build()
response = impit.get("https://target.com")
```

### 阶段 4 — 伪首部顺序

浏览器以特定顺序发送 HTTP/2 伪首部。这在 h2 库层面强制执行：

| 浏览器 | 伪首部顺序 |
|---|---|
| Chrome | `:method`、`:authority`、`:scheme`、`:path`、`:protocol`、`:status` |
| Firefox | `:method`、`:path`、`:authority`、`:scheme`、`:protocol`、`:status` |
| Safari iOS | `:method`、`:scheme`、`:authority`、`:path`、`:protocol`、`:status` |
| OkHttp | `:method`、`:path`、`:authority`、`:scheme`、`:protocol`、`:status` |

**检测：** 某些反向代理会检查伪首部顺序以区分浏览器。Firefox 将 `:path` 放在 `:authority` 之前 —— 这是独特的指纹。Safari 将 `:scheme` 放在第二位 —— 这是另一个区分点。

### 阶段 5 — 请求头优先级

自定义请求头优先于指纹默认值，以避免冲突：

```python
impit = Impit.builder().with_fingerprint("chrome142").build()

# Custom headers WIN over fingerprint defaults for same header name
response = impit.get("https://target.com", headers={
    "Authorization": "Bearer custom-token",
    "X-Custom-Header": "value",
})
# Authorization is added; all fingerprint headers still applied for unset names
```

### 阶段 6 — Accept-Encoding 策略

各浏览器的 Accept-Encoding 值差异显著：

| 浏览器 | Accept-Encoding |
|---|---|
| Chrome 142 | `gzip, deflate, br, zstd` |
| Chrome 100-116 | `gzip, deflate, br` |
| Firefox | `gzip, deflate, br, zstd` |
| Safari iOS | `gzip, deflate, br` |
| OkHttp 4 | `gzip, deflate, br` |

**检测：** 某些 CDN 会根据 Accept-Encoding 返回不同内容（brotli 与 zstd 能力画像）。请将编码能力与你要仿冒的目标浏览器对齐。

## Pitfalls

- **curl 无法伪造 HTTP/2 SETTINGS 帧。** 对 HTTP/1.1 目标，或当主要关注点是 TLS 指纹而非 HTTP/2 时，才使用基于 curl 的请求头。
- **在 HTTP/2 中请求头顺序很重要。** 某些检测器会检查请求头字段的顺序，而不只是它们是否存在。
- **`sec-ch-ua` 必须与 User-Agent 匹配。** 用 Chrome 请求头搭配 Firefox 的 UA 会造成不一致，从而被检测器标记。
- **`sec-ch-ua` 格式与版本相关。** Chrome 100+ 使用的品牌字符串与 Chrome 124+ 不同。
- **移动端请求头若未匹配 TLS 则会被检测。** 在桌面端 TLS 指纹上使用 Safari iOS 请求头会被标记。
- **自定义请求头会按大小写不敏感方式去重。** 将 `User-Agent` 作为自定义头添加会覆盖指纹中的 User-Agent。

## Verification

1. 对 `https://httpbin.org/headers` 进行测试 —— 验证所有发送的请求头与预期的浏览器指纹一致。
2. 如需验证 HTTP/2 SETTINGS，可使用 `https://nghttp2.org/httpbin/headers` 或本地 nghttp2 服务器。
3. 对比仿冒浏览器与真实浏览器的响应大小/内容 —— 响应完全一致说明请求头被接受。
4. 检查 Cloudflare 的 `cf-ja4` 请求头 —— 它同时编码了 HTTP/2 指纹与 TLS 指纹。

---

## 相关技能

- **`tls-fingerprint-impersonation`** —— TLS ClientHello 与 JA3/JA4 指纹伪造。
- **`stealth-browser-launch`** —— 带 C++ 指纹补丁的完整浏览器自动化。
