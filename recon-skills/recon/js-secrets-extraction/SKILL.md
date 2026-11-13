---
name: js-secrets-extraction
description: "分析 JS 打包文件与 source map，查找硬编码密钥、API 密钥、JWT 与内部端点"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [js, secrets, API-key, jwt, source-map, recon]
  category: recon
---

# JS 打包文件与 Source Map 分析 —— 密钥提取

## When to Use

- **始终**在初始 Web 枚举之后执行
- 当发现现代 SPA（React、Angular、Vue）时
- 当目标使用 Firebase、Supabase、Auth0 时
- 在许多目标上，产出比目录扫描更高

## Prerequisites

- 对目标具有明确授权、目标边界与速率限制。
- 工具：`curl`、`python3`、`waybackurls`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在命令执行前立即获得明确确认。

## How to Run

```bash
curl --max-time 30 --connect-timeout 10 -s "https://target.com" > index.html
grep -Eo 'src="[^"]*\.js"' index.html | cut -d'"' -f2 | while read js; do
  curl --max-time 30 --connect-timeout 10 -s "https://target.com$js" > "$(basename $js)"
done

# Search for secrets in bundles
grep -rEn "(apiKey|api_key|API_KEY|token|secret|password|clientId|client_id|auth0|firebase|supabase)[\"'\"]?[[:space:]]*[:=][[:space:]]*[\"'\'][^\"'\']{8,}" *.js
```

## Procedure

以下各阶段即为操作流程。保持每次探测有界（`--max-time`），将证据记录到 `OUTPUT_DIR` 下，并在 Pitfalls 中列出的停止条件处停止。

## 为什么要分析 JS 打包文件

现代 JavaScript 打包产物（Webpack、Vite、esbuild）通常包含：
- 硬编码的 API 密钥与令牌
- 内部 API URL
- Firebase、Auth0、Supabase 配置
- 环境变量（VITE_*、REACT_APP_*、NEXT_PUBLIC_*）
- 内部路由

## 打包文件下载与分析

```bash
curl --max-time 30 --connect-timeout 10 -s "https://target.com" > index.html
grep -Eo 'src="[^"]*\.js"' index.html | cut -d'"' -f2 | while read js; do
  curl --max-time 30 --connect-timeout 10 -s "https://target.com$js" > "$(basename $js)"
done

# Search for secrets in bundles
grep -rEn "(apiKey|api_key|API_KEY|token|secret|password|clientId|client_id|auth0|firebase|supabase)[\"'\"]?[[:space:]]*[:=][[:space:]]*[\"'\'][^\"'\']{8,}" *.js
```

## Source Map 重建

```bash
curl --max-time 30 --connect-timeout 10 -sI "https://target.com/assets/index-abc123.js.map"
curl --max-time 30 --connect-timeout 10 -sI "https://target.com/static/js/main.12345.js.map"

# If HTTP 200, use for reconstruction:
# https://unminify.com
# https://source-map-visualization.netlify.app
```

**真实案例**：某企业 Angular SPA 管理后台暴露了 2 个 JS 打包文件（各 250KB）：
- 内部 API URL（apiv3.empresa.com.br）
- Firebase API 密钥（AIzaSy...2GXA）
- 加密密钥（AD5oDjsJaTJOzLe1Llj9mz）
- Cloudinary 上传端点

## 按端口分析 URL

现代部署通常将主 SPA 放在 443 端口，而管理后台/API 放在其他端口（8080、8081、8084）。**务必检查所有已发现端口上的 JS 打包文件：**

```bash
# Check source maps on every open port
for port in 443 8080 8081 8084; do
  curl --max-time 30 --connect-timeout 10 -sI "https://target.com:$port/static/js/main.*.js.map" 2>/dev/null
  curl --max-time 30 --connect-timeout 10 -sI "https://target.com:$port/assets/index-*.js.map" 2>/dev/null
done
```

管理类应用或备用端口应用上的 source map 可能暴露与公开 SPA
不同的路由与配置集合。请独立分析
每个已获授权的应用。

## 管理后台 JS 分析模式

当发现位于单独端口的管理后台时，其 JS 打包文件通常包含与主站不同的密钥：

```python
base = "https://target.com:8080"  # Admin portal
js = requests.get(f"{base}/static/js/main.*.js").text

# 1. Extract ALL API URLs
api_urls = re.findall(r'https?://[^\"\'[[:space:]]\\n,)>\\]]+', js)
# 2. Find base API URL (the backend this admin talks to)
# 3. Look for hardcoded credentials, API keys, auth patterns
# 4. Extract route paths for the admin app
routes = re.findall(r'[\"\'](/[a-zA-Z0-9_/.-]*(?:admin|chat|bot|message|user|auth|login|token|config|setting|dashboard|hospital|pharmacy|drug|payment)[a-zA-Z0-9_/.-]*)[\"\']', js, re.IGNORECASE)
```

## Source Map 内容分析（1,200+ 文件）

当 source map 可用时，分析 `sourcesContent` 数组以查找硬编码密钥：

```python
import json, re
data = json.loads(open("bundle.js.map").read())
all_source = " ".join(data.get("sourcesContent", []))

# Search for credentials in the original source
patterns = {
    "password": r'[\"\']([^\"\']*(?:password|passwd|pwd)[^\"\']*)[\"\']\s*[:=]\s*[\"\']([^\"\']+)[\"\']',
    "token": r'[\"\']([^\"\']*(?:token|jwt|api_key|apikey|secret)[^\"\']*)[\"\']\s*[:=]\s*[\"\']([^\"\']+)[\"\']',
}
for name, pat in patterns.items():
    matches = re.findall(pat, all_source, re.IGNORECASE)
    if matches:
        print(f"[{name}] {matches[:5]}")
```
- Cloudinary 上传端点

## 密钥正则模式目录

```python
import re

patterns = {
    "Firebase API Key": r'apiKey:\s*[\"\']([^\"\']{30,})',
    "AWS Key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
    "Google API Key": r'AIza[0-9A-Za-z\\-_]{35}',
    "JWT": r'eyJ[A-Za-z0-9_\\-]{20,}\.[A-Za-z0-9_\\-]{20,}\.[A-Za-z0-9_\\-]{10,}',
    "Mercado Pago": r'APP_USR-[a-f0-9]{8,}',
    "Stripe": r'(?:sk_live|pk_live)_[A-Za-z0-9]{24,}',
    "Auth0 Domain": r'(?:domain|auth0_domain):\s*[\"\']([^\"\']+\.auth0\.com)',
    "Auth0 Client ID": r'(?:client_id|clientId|AUTH0_CLIENT_ID):\s*[\"\']([^\"\']{20,})',
    "Supabase URL": r'(?:supabaseUrl|SUPABASE_URL):\s*[\"\'](https://[^\"\']+\.supabase\.co)',
    "Supabase Key": r'(?:supabaseKey|anonKey|SUPABASE_ANON_KEY):\s*[\"\'](eyJ[A-Za-z0-9_\\-]+\.[A-Za-z0-9_\\-]+\.[A-Za-z0-9_\\-]+)',
    "Heroku": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    "Generic Secret": r'(?:secret|password|token|key):\s*[\"\']([^\"\']{8,})',
}
```

## 批量下载打包文件 + Grep

```python
import requests, re, json

base = "https://target.com"
html = requests.get(base).text

# Extract all JS URLs
js_urls = re.findall(r'src="([^"]*\.js)"', html)
for js_url in js_urls:
    if js_url.startswith("/"):
        js_url = base + js_url
    content = requests.get(js_url).text
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        for m in matches:
            if isinstance(m, tuple):
                m = m[0]
            if len(m) > 6:
                print(f"[{name}] {m[:80]}")
```

## Pitfalls

| 问题 | 解决方案 |
|-------|----------|
| 打包文件过大 | 使用带特定模式的 grep -Eo |
| 代码被压缩（变量名只有 1 个字符） | 使用 source map 进行重建 |
| 误报匹配 | 通过测试 API 端点来验证密钥 |
| 触发速率限制 | 在打包文件下载之间加入延迟 |

---

## 后端 URL 发现

JS 打包文件经常泄露生产后端 URL，使得可以直接攻击 API 从而绕过 CDN/WAF：

```bash
# Platform-specific backend URL patterns
grep -Eo 'https?://[a-zA-Z0-9.\-]+\.(fly\.dev|azurewebsites\.net|onrender\.com|vercel\.app|netlify\.app)[^"'\'' ]{0,40}' /tmp/*.js
grep -Eo 'https?://[a-zA-Z0-9.\-]+\.(supabase\.co|r2\.dev|blob\.vercel-storage\.com)[^"'\'' ]{0,40}' /tmp/*.js

# Edge function URLs
grep -Eo 'functions/v1/[a-zA-Z0-9_\-]+' /tmp/*.js

# Internal API paths
grep -Eo '["\x60]/api/v1/[a-zA-Z0-9_\-/]+["\x60]' /tmp/*.js
```

### 真实场景模式
| 模式 | 平台 | 示例 | 是否为密钥 |
|---------|----------|---------|---------|
| `*.fly.dev` | Fly.io | `ht-prod-backend.fly.dev` | ✅ 后端 URL |
| `*.azurewebsites.net` | Azure | `consigpro-api-prod-...` | ✅ 后端 URL |
| `*.onrender.com` | Render | `clickcity-api.onrender.com` | ✅ 后端 URL |
| `*.supabase.co` | Supabase | `jxhvjufqtabpeieyhkgk.supabase.co` | ✅ anon key 是公开的；后端 URL 属于情报 |
| `*.r2.dev` | Cloudflare R2 | `pub-xxx.r2.dev` | ✅ 存储 URL |
| `functions/v1/*` | Supabase Edge | `provision-openrouter-key` | ✅ 端点名称 |
| `dpl_*` | Vercel DPL | `dpl_BCoyPsxxYLZ...` | ❌ **不是密钥** —— 公开的部署 ID |

## Verification

```bash
# Test Firebase API key
curl --max-time 30 --connect-timeout 10 -s "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIza..."
# Test Supabase anon key
curl --max-time 30 --connect-timeout 10 -s "https://PROJECT.supabase.co/rest/v1/users?limit=1" -H "apikey: ANON_KEY" -H "Authorization: Bearer ANON_KEY"
```

### 阶段 5 — Source Map 利用

当 `.js.map` 文件遗留在生产环境时，可恢复完整的编译前源代码：

```bash
# Find .map files via Wayback Machine
curl --max-time 30 --connect-timeout 10 -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*\.js\.map$" \
  | sort -u > map_urls.txt

# Download and extract source
wget https://target.com/static/app.js.map
node -e "
const map = require('./app.js.map');
map.sources.forEach((src, i) => {
  const fs = require('fs');
  fs.writeFileSync(src.split('/').pop(), map.sourcesContent[i]);
});
print('Extracted ' + map.sources.length + ' source files');
"

# Quick check: does a JS file have an available map?
curl --max-time 30 --connect-timeout 10 -skI "https://target.com/static/app.js.map" | grep "200\|Content-Type"
```

### 阶段 6 — JS 深度爬取

递归爬取 JS 文件，提取其中内嵌的 URL、API 与 IP：

```bash
# lazyegg — crawls JS files for links, APIs, IPs
python3 lazyegg.py https://target.com
python3 lazyegg.py https://target.com/js/auth.js

# Combine with waybackurls for deep coverage
waybackurls target.com \
  | grep '\.js$' \
  | awk -F '?' '{print $1}' \
  | sort -u \
  | xargs -I{} bash -c 'python3 lazyegg.py "{}" --js_urls --domains --ips' \
  > lazyegg_output.txt

# subjs — extract JS URLs from any URL list
cat all_urls.txt | subjs | tee js_files_full.txt
```

### 阶段 7 — 逐文件 AI 辅助代码审查

JS 打包文件就是源代码 —— 即使是压缩过的。有纪律地逐文件（逐分块）审查，能发现自主智能体遗漏的问题：

```bash
# 1. Download all JS chunks
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Eo 'src="[^"]+\.js[^"]*"' | \
  cut -d'"' -f2 | while read js; do
    curl --max-time 30 --connect-timeout 10 -sk "$js" -o "chunks/$(basename $js)"
  done

# 2. Per-chunk pattern review for dangerous sinks
for chunk in chunks/*.js; do
  echo "=== $chunk ==="
  # eval / new Function (arbitrary code execution)
  grep -Pon 'eval\s*\(|new\s+Function\s*\(' "$chunk"
  # Hardcoded API keys/secrets
  grep -Pon '(?:api[_-]?key|secret|token|password|bearer)\s*[:=]\s*["\x27][^"\x27]{8,}' "$chunk"
  # postMessage without origin check
  grep -Pon 'postMessage\s*\(' "$chunk"
  # Prototype pollution patterns
  grep -Eon '__proto__|constructor\.prototype' "$chunk"
  # Debug/test code in production
  grep -Eoin 'debug|test|staging|localhost' "$chunk"
  # Client-trusted flags
  grep -Pon '(?:isAdmin|isVip|isPremium|isModerator|role)\s*[=:]\s*true' "$chunk"
done > ai_review_findings.txt

# 3. Review findings — each is a CANDIDATE, not confirmed
grep -c "===" ai_review_findings.txt  # files reviewed
grep -c ":" ai_review_findings.txt     # candidate findings
```

关键洞察：若告诉自主智能体在整个代码库中“查找缺陷”，它会耗尽预算且遗漏问题。而保证对每个文件以固定输出结构做一次全量扫描，则能产生可复现的命中。每一条发现仍需要人工进行 PoC 验证。
