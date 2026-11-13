---
name: staging-subdomain-hunt
description: 当生产环境经 WAF 加固时，通过 crt.sh 搜寻 staging 环境。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, subdomain, staging, takeover, wordpress]
  category: recon
  related_skills:
    - wp-mass-recon
    - deep-invade
    - subdomain-enumeration
    - wordpress-plugin-hunt
    - js-secrets-extraction
    - source-leak-hunt
    - phpinfo-to-rce
---

# Staging 与子域名搜寻技能

通过证书透明度（crt.sh）、DNS 爆破与 Web 探测发现 staging、开发及内部子域名。利用 staging 的安全落差——staging 环境的安全性通常弱于生产（无 WAF、启用调试、安装页可访问）。已在 7 个美国目标上验证有效，其中 staging 子域名暴露了生产环境不可见的 phpinfo、WordPress 安装页与内部 API。

## When to Use

- 在 `deep-invade` 阶段 5 中处理高价值目标时。
- 生产目标防护良好（有 WAF、无泄露）——转向 staging。
- 目标攻击面较大（电商、SaaS、加盟模式）。
- 主站已加固，需要额外的入口点时。
- 在 `subdomain-enumeration` 产出子域名列表之后。

## Prerequisites

- 具备 curl、httpx、jq 的 `terminal`。
- 目标域名（例如 `example.com`）。
- 用于 DNS 爆破：词表位于 `./tools/subdomains.txt`。

## How to Run

```bash
DOMAIN="example.com"

# crt.sh discovery
curl --max-time 30 --connect-timeout 10 -sk "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subs.txt

# Probe for live hosts
httpx -silent -l subs.txt -threads 50 -status-code -tech-detect -o alive_subs.txt

# Check for staging indicators
grep -iE 'staging|stage|dev|test|uat|beta' alive_subs.txt
```

## 快速参考

| 指标 | 含义 | 处置 |
|-----------|---------------|--------|
| `/wp-admin/install.php` 返回 200 | 全新 WordPress——尚未配置站点 | 安装接管 |
| `/wp-admin/upgrade.php` 返回 200 | WP 需要升级数据库 | 数据库信息泄露 |
| staging 上的 `info.php` / `phpinfo.php` | 启用了调试 | PHPInfo 分析（参见 phpinfo-to-rce） |
| staging 没有 Cloudflare/WAF | 可直接访问源站 | 对源站 IP 运行完整 deep-invade |
| staging 有 CORS 而生产没有 | staging 的 CORS 策略更弱 | 从 staging 上下文发起 CORS 攻击 |
| staging 上的 `.env` | 开发凭据泄露 | 凭据窃取，转向生产 |

## Procedure

### 步骤 1 — 证书透明度枚举

```bash
DOMAIN="$1"
OUTDIR="$OUTDIR/staging/$DOMAIN"
mkdir -p "$OUTDIR"

echo "[*] crt.sh enumeration for *.$DOMAIN"

# Primary crt.sh query
curl -sk --max-time 30 --connect-timeout 10 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sed 's/^www\.//' | sort -u > "$OUTDIR/crtsh_subs.txt"

# Also try without wildcard prefix
curl -sk --max-time 30 --connect-timeout 10 "https://crt.sh/?q=$DOMAIN&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sed 's/^www\.//' | sort -u >> "$OUTDIR/crtsh_subs.txt"

sort -u "$OUTDIR/crtsh_subs.txt" -o "$OUTDIR/crtsh_subs.txt"

sub_count=$(wc -l < "$OUTDIR/crtsh_subs.txt")
echo "[+] crt.sh: $sub_count unique subdomains"

# Categorize by pattern
echo ""
echo "[*] Staging/dev subdomains:"
grep -iE 'staging|stage|dev\.|development|test|uat|beta|sandbox|demo|preview|qa' "$OUTDIR/crtsh_subs.txt"

echo ""
echo "[*] Admin/internal subdomains:"
grep -iE 'admin|portal|internal|dashboard|manage|cp\.|control|panel|cpanel|webmail|mail\.' "$OUTDIR/crtsh_subs.txt"

echo ""
echo "[*] API subdomains:"
grep -iE 'api|rest|graphql|ws\.|websocket' "$OUTDIR/crtsh_subs.txt"

echo ""
echo "[*] Infrastructure subdomains:"
grep -iE 'cdn|static|assets|media|img|images|files|download|origin|proxy' "$OUTDIR/crtsh_subs.txt"

echo ""
echo "[*] Franchise/location subdomains:"
grep -iE 'franchise|location|store|shop|branch|office' "$OUTDIR/crtsh_subs.txt"
```

### 步骤 2 — 存活主机发现

```bash
DOMAIN="$1"
OUTDIR="$OUTDIR/staging/$DOMAIN"

echo "[*] Probing $(wc -l < "$OUTDIR/crtsh_subs.txt") subdomains..."

httpx -silent -l "$OUTDIR/crtsh_subs.txt" -threads 50 -status-code -tech-detect -title \
  -o "$OUTDIR/alive_subs.txt"

alive=$(wc -l < "$OUTDIR/alive_subs.txt")
echo "[+] $alive live hosts"

# Prioritize staging/dev
echo ""
echo "[*] Staging/dev LIVE:"
grep -iE 'staging|stage|dev\.|development|test|uat' "$OUTDIR/alive_subs.txt" | head -20
```

### 步骤 3 — WordPress 安装页检查（Staging 接管）

staging 站点经常安装了 WordPress 但尚未配置：

```bash
DOMAIN="$1"
OUTDIR="$OUTDIR/staging/$DOMAIN"

echo "[*] Checking for WordPress install pages on staging..."

for sub in $(grep -iE 'staging|stage|dev' "$OUTDIR/alive_subs.txt" | awk '{print $1}' | head -10); do
  echo "--- $sub ---"

  # Check install.php (fresh WP, no config)
  install_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 --connect-timeout 10 "$sub/wp-admin/install.php")
  if [[ "$install_code" == "200" ]]; then
    echo "  [TAKEOVER] /wp-admin/install.php — fresh WP install, can configure site!"
    # Extract form fields
    curl -sk --max-time 10 --connect-timeout 10 "$sub/wp-admin/install.php" | grep -Eo 'name="[^"]+"' | sort -u
  fi

  # Check upgrade.php (needs DB upgrade)
  upgrade_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 --connect-timeout 10 "$sub/wp-admin/upgrade.php")
  if [[ "$upgrade_code" == "200" ]]; then
    echo "  [INFO] /wp-admin/upgrade.php — DB upgrade page accessible"
  fi

  # Check setup-config.php (no wp-config)
  config_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 --connect-timeout 10 "$sub/wp-admin/setup-config.php")
  if [[ "$config_code" == "200" || "$config_code" == "409" ]]; then
    echo "  [INFO] /wp-admin/setup-config.php — wp-config missing or accessible"
  fi

  # Check for exposed info.php
  info_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "$sub/info.php")
  [[ "$info_code" == "200" ]] && echo "  [CRITICAL] /info.php exposed on staging!"

  # Check for .env on staging
  env_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "$sub/.env")
  [[ "$env_code" == "200" ]] && echo "  [CRITICAL] /.env exposed on staging!"
done
```

### 步骤 4 — 生产与 Staging 安全差距分析

```bash
DOMAIN="$1"
PROD="https://$DOMAIN"
STAGING=$(grep -iE 'staging|stage' "$OUTDIR/staging/$DOMAIN/alive_subs.txt" | head -1 | awk '{print $1}')

if [[ -n "$STAGING" ]]; then
  echo "[*] Comparing $PROD vs $STAGING"

  # Compare HTTP headers
  echo "=== Production Headers ==="
  curl --max-time 30 --connect-timeout 10 -skI "$PROD" 2>/dev/null | head -20

  echo ""
  echo "=== Staging Headers ==="
  curl --max-time 30 --connect-timeout 10 -skI "$STAGING" 2>/dev/null | head -20

  # Check for common staging weaknesses
  echo ""
  echo "[*] Staging-specific checks:"

  # Directory listing
  listing=$(curl -sk --max-time 5 --connect-timeout 5 "$STAGING/wp-content/uploads/" | grep -i "Index of")
  [[ -n "$listing" ]] && echo "  [WEAK] Directory listing enabled on uploads"

  # Debug mode
  debug=$(curl -sk --max-time 5 --connect-timeout 5 "$STAGING/" | grep -i "wp_debug\|debug mode\|error_reporting")
  [[ -n "$debug" ]] && echo "  [WEAK] Debug output visible"

  # CORS on staging
  cors=$(curl -skI --max-time 5 --connect-timeout 5 "$STAGING/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i "access-control-allow-credentials: true")
  [[ -n "$cors" ]] && echo "  [WEAK] CORS credential reflection on staging"

  # XMLRPC on staging
  xmlrpc=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 -X POST "$STAGING/xmlrpc.php" \
    -d '<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName></methodCall>')
  [[ "$xmlrpc" == "200" ]] && echo "  [WEAK] XMLRPC open on staging"
fi
```

### 步骤 5 — 加盟/多门店子域名枚举

针对加盟或多门店业务：

```bash
DOMAIN="$1"
OUTDIR="$OUTDIR/staging/$DOMAIN"

echo "[*] Franchise/location subdomains:"

# Extract location-based subdomains
grep -iE 'franchise|location|store|shop|branch|office|city|state' "$OUTDIR/alive_subs.txt" | while read -r line; do
  sub=$(echo "$line" | awk '{print $1}')
  echo "--- $sub ---"

  # Check if it's a WordPress site
  wp=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "$sub/wp-login.php")
  [[ "$wp" =~ ^(200|301|302)$ ]] && echo "  WordPress detected"

  # Check for WPSL (WP Store Locator) data
  wpsl=$(curl --max-time 30 --connect-timeout 10 -sk "$sub/wp-json/wpsl/v1/" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 'no')" 2>/dev/null)
  [[ "$wpsl" != "no" && "$wpsl" != "0" ]] && echo "  WPSL: $wpsl locations"

  # Check for store-specific data
  users=$(curl --max-time 30 --connect-timeout 10 -sk "$sub/wp-json/wp/v2/users" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null)
  [[ "$users" -gt 0 ]] && echo "  Users: $users"
done
```

## Pitfalls

- **crt.sh 速率限制。** 被限流时 crt.sh 可能返回空 JSON。查询之间间隔 2-3 秒，或直接查询 `crt.sh/?d=` 处的 PostgreSQL 转储。
- **通配符证书会隐藏子域名。** 若仅有 `*.example.com` 证书，各具体子域名不会出现在 crt.sh 中。使用 subfinder DNS 爆破作为后备。
- **staging 可能需要 VPN。** 某些 staging 环境有 IP 限制。
  仅从本次评估获批的源地址进行测试。
- **生产环境也可能存在 WordPress install.php。** 某些维护不善的生产站点同样可访问该页面。它并不总是 staging 特有。检查是否存在 "Welcome to WordPress" 标题文本，以确认是全新安装。
- **生产与 staging 的 CORS 可能不同。** 在断言存在安全控制差距之前，应在两种环境中测试同一组有界
  端点矩阵。

## Verification

- 每个 staging 子域名必须使用 httpx 探测以确认存活。
- WordPress install.php必须返回 HTTP 200，且响应体包含 "WordPress" + "installation"（而非重定向或 SPA）。
- staging 弱点必须与生产环境对比，以确认安全差距（例如生产有 WAF 而 staging 没有）。
- 来自 crt.sh 的内部子域名泄露必须核实属于目标的基础设施（而非同一证书中的无关域名）。
- 发现的凭据或配置值必须作为敏感
  证据处理。仅在获得明确授权与获批身份的情况下测试凭据；
  绝不能假设 staging 凭据可以在生产环境尝试。
