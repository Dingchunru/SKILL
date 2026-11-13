---
name: subdomain-enumeration
description: 在侦察启动阶段通过 crt.sh 与 subfinder 梳理子域。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, subfinder, httpx, dnsx, dig, jq
metadata:
  tags: [recon, subdomain, DNS, crt.sh, asset-discovery]
  category: recon
  related_skills:
    - wp-mass-recon
    - staging-subdomain-hunt
    - deep-invade
    - recon-playbook
---

# 子域枚举技能

综合运用证书透明度日志（crt.sh）、DNS 爆破和被动来源进行子域发现。这是任何侦察流程的第一步——你无法攻击你不知道其存在的东西。子域枚举往往能揭示预发布环境、内部管理面板、API 网关以及被遗忘的 WordPress 站点，它们都是比生产站点更软的目标。

## When to Use

- 对任意目标域名启动侦察时。
- 生产站点防护良好——寻找更软的入口点。
- 执行 `skill_view(name='wp-mass-recon')` 之后——为每个 WordPress 目标枚举子域。
- 为目标组织构建完整的资产清单。

## Prerequisites

- `curl`、`httpx`、`dig`、`jq`、`dnsx` 和 `subfinder`。
- 由操作者提供的 DNS 爆破字典。
- 获准向 crt.sh、crt.name 和 subfinder 的各提供方等第三方被动来源披露该域名。

## How to Run

```bash
DOMAIN="${1:-example.com}"
OUTPUT_ROOT="${OUTPUT_DIR:-./output}"
OUTDIR="$OUTPUT_ROOT/subdomains/$DOMAIN"

if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Invalid domain: $DOMAIN" >&2
  exit 2
fi

mkdir -p "$OUTDIR"

# Passive: crt.sh (retry: it frequently returns 502 while its database refreshes)
for attempt in 1 2 3; do
  curl -fsS --max-time 30 --connect-timeout 10 \
    "https://crt.sh/?q=%25.$DOMAIN&output=json" -o "$OUTDIR/crtsh_raw.json" && break
  sleep 15
done
jq -r '.[].name_value' "$OUTDIR/crtsh_raw.json" 2>/dev/null \
  | sed 's/\*\.//g' \
  | sort -u > "$OUTDIR/crtsh.txt"
# If crt.sh stays down, crtsh.txt ends up empty: keep going with crt.name/subfinder.

# crt.name (historical CT data; resolve names before probing)
curl -fsS --max-time 30 --connect-timeout 10 "https://crt.name/v1/search?apex=$DOMAIN" \
  | sed 's/\r$//' \
  | sed 's/^\*\.//' \
  | sort -u > "$OUTDIR/crtname.txt"

# Passive: subfinder
subfinder -d "$DOMAIN" -silent -timeout 30 > "$OUTDIR/subfinder.txt"

# Merge and deduplicate
cat "$OUTDIR/crtsh.txt" "$OUTDIR/crtname.txt" "$OUTDIR/subfinder.txt" \
  | grep -E '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' \
  | sort -u > "$OUTDIR/all_subs.txt"

# Probe live hosts
httpx -silent -l "$OUTDIR/all_subs.txt" -threads 50 -rate-limit 2 \
  -status-code -tech-detect -title -o "$OUTDIR/alive.txt"
```

## 快速参考

| 来源 | 方法 | 覆盖范围 | 速度 |
|--------|--------|----------|-------|
| crt.sh | 证书透明度 | 优秀（大多数证书） | 快（1-5s） |
| subfinder | 被动 API（VirusTotal、Shodan、DNSdumpster 等） | 很好 | 快（30-60s） |
| dnsx | 批量 DNS A/AAAA/CNAME 解析（比 dig 快 100 倍） | 良好（可发现非 HTTP 服务） | 快（10-30s） |
| httpx 探测 | 存活 HTTP/HTTPS 检查 | 最适用于 Web 攻击面 | 快（30-60s） |
| Google dork | `site:example.com` | 补充手段 | 手动 |

## Procedure

### 步骤 1 — 被动枚举（crt.sh + subfinder）

```bash
DOMAIN="$1"
OUTPUT_ROOT="${OUTPUT_DIR:-./output}"
OUTDIR="$OUTPUT_ROOT/subdomains/$DOMAIN"

if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Invalid domain: $DOMAIN" >&2
  exit 2
fi

mkdir -p "$OUTDIR"

echo "[*] Passive enumeration for $DOMAIN..."

# crt.sh — certificate transparency logs (retry: it frequently returns 502 while its database refreshes)
echo "[*] crt.sh query..."
for attempt in 1 2 3; do
  curl -fsS --max-time 30 --connect-timeout 10 \
    "https://crt.sh/?q=%25.$DOMAIN&output=json" -o "$OUTDIR/crtsh_raw.json" 2>/dev/null && break
  sleep 15
done
jq -r '.[].name_value' "$OUTDIR/crtsh_raw.json" 2>/dev/null | \
  sed 's/\*\.//g' | \
  sed 's/^www\.//' | \
  sort -u > "$OUTDIR/crtsh.txt"

crt_count=$(wc -l < "$OUTDIR/crtsh.txt")
echo "  crt.sh: $crt_count entries"
if [[ ! -s "$OUTDIR/crtsh.txt" ]]; then
  echo "  [!] crt.sh unavailable or empty after retries; results are incomplete" >&2
fi

# crt.name — historical certificate-transparency data
echo "[*] crt.name query..."
curl -fsS --max-time 30 --connect-timeout 10 "https://crt.name/v1/search?apex=$DOMAIN" 2>/dev/null | \
  sed 's/\r$//' | \
  sed 's/^\*\.//' | \
  sort -u > "$OUTDIR/crtname.txt"
crtname_count=$(wc -l < "$OUTDIR/crtname.txt")
echo "  crt.name: $crtname_count entries (historical; resolve before probing)"

# Also query with %25. (wildcard)
for attempt in 1 2 3; do
  curl -fsS --max-time 30 --connect-timeout 10 \
    "https://crt.sh/?q=%25.%25.$DOMAIN&output=json" -o "$OUTDIR/crtsh_wildcard_raw.json" 2>/dev/null && break
  sleep 15
done
jq -r '.[].name_value' "$OUTDIR/crtsh_wildcard_raw.json" 2>/dev/null | \
  sed 's/\*\.//g' | \
  sort -u > "$OUTDIR/crtsh_wildcard.txt"

# subfinder — passive API aggregation
echo "[*] subfinder..."
subfinder -d "$DOMAIN" -silent -timeout 30 2>/dev/null | sort -u > "$OUTDIR/subfinder.txt"
subf_count=$(wc -l < "$OUTDIR/subfinder.txt")
echo "  subfinder: $subf_count entries"

# Merge all passive sources
cat "$OUTDIR"/crtsh.txt "$OUTDIR"/crtsh_wildcard.txt "$OUTDIR"/crtname.txt "$OUTDIR"/subfinder.txt 2>/dev/null | \
  sed 's/^www\.//' | \
  grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | \
  sort -u > "$OUTDIR/all_passive.txt"

total=$(wc -l < "$OUTDIR/all_passive.txt")
echo ""
echo "[+] Total unique subdomains (passive): $total"
```

### 步骤 2 — DNS 解析

```bash
DOMAIN="$1"
OUTPUT_ROOT="${OUTPUT_DIR:-./output}"
OUTDIR="$OUTPUT_ROOT/subdomains/$DOMAIN"

echo "[*] Resolving subdomains..."

# Batch resolve with dnsx (100x faster than dig loop)
# -json keeps host->IP mapping (-resp-only would emit bare IPs and lose the hostname)
dnsx -silent -l "$OUTDIR/all_passive.txt" -a -json -o "$OUTDIR/resolved_raw.jsonl" 2>/dev/null
# Format output: subdomain => IP
while read -r line; do
  sub=$(echo "$line" | jq -r '.host // empty')
  ip=$(echo "$line" | jq -r '.a[0] // empty')
  [ -n "$sub" ] && [ -n "$ip" ] && echo "$sub => $ip"
done < "$OUTDIR/resolved_raw.jsonl" > "$OUTDIR/resolved.txt"

resolved=$(wc -l < "$OUTDIR/resolved.txt")
echo "[+] $resolved subdomains resolved to IPs"

# Count unique IPs
unique_ips=$(awk '{print $3}' "$OUTDIR/resolved.txt" | sort -u | wc -l)
echo "[+] $unique_ips unique IPs"

# Identify shared hosting (many subdomains → same IP)
echo ""
echo "[*] Shared hosting clusters:"
awk '{print $3}' "$OUTDIR/resolved.txt" | sort | uniq -c | sort -rn | head -10 | while read -r count ip; do
  [[ "$count" -gt 1 ]] && echo "  $ip: $count subdomains"
done
```

### 步骤 3 — 存活主机发现

```bash
DOMAIN="$1"
OUTPUT_ROOT="${OUTPUT_DIR:-./output}"
OUTDIR="$OUTPUT_ROOT/subdomains/$DOMAIN"

echo "[*] Probing live hosts..."

# httpx with tech detection
httpx -silent -l "$OUTDIR/all_passive.txt" -threads 50 \
  -status-code -tech-detect -title -location \
  -o "$OUTDIR/alive.txt" 2>/dev/null

alive=$(wc -l < "$OUTDIR/alive.txt")
echo "[+] $alive live hosts"

# Categorize by status code
echo ""
echo "[*] By HTTP status:"
echo "  200: $(grep -c '\[200\]' "$OUTDIR/alive.txt")"
echo "  301/302: $(grep -cE '\[301\]|\[302\]' "$OUTDIR/alive.txt")"
echo "  403: $(grep -c '\[403\]' "$OUTDIR/alive.txt")"
echo "  404: $(grep -c '\[404\]' "$OUTDIR/alive.txt")"

# Categorize by technology
echo ""
echo "[*] By technology:"
grep -Eo '\[[a-z-]+\]' "$OUTDIR/alive.txt" | tr -d '[]' | sort | uniq -c | sort -rn | head -15

# WordPress subdomains
echo ""
echo "[*] WordPress subdomains:"
grep -i 'wordpress' "$OUTDIR/alive.txt" | awk '{print $1}' | head -10

# Non-HTTP services (from DNS resolution)
echo ""
echo "[*] Interesting non-standard ports from DNS (MX, NS, etc.):"
dig +short "$DOMAIN" MX 2>/dev/null | head -5
dig +short "$DOMAIN" NS 2>/dev/null | head -5
dig +short "$DOMAIN" TXT 2>/dev/null | grep -i 'spf\|v=spf' | head -3
```

### 步骤 4 — 子域分类

```bash
DOMAIN="$1"
OUTPUT_ROOT="${OUTPUT_DIR:-./output}"
OUTDIR="$OUTPUT_ROOT/subdomains/$DOMAIN"

echo "[*] Categorizing subdomains..."

# Staging/Dev
echo ""
echo "=== STAGING / DEV ==="
grep -iE 'staging|stage|dev\.|development|test|uat|beta|sandbox|preview|qa' "$OUTDIR/all_passive.txt"

# Admin/Internal
echo ""
echo "=== ADMIN / INTERNAL ==="
grep -iE 'admin|portal|internal|dashboard|manage|cp\.|control|panel|cpanel|webmail|mail\.' "$OUTDIR/all_passive.txt"

# API
echo ""
echo "=== API ==="
grep -iE 'api|rest|graphql|ws\.|websocket' "$OUTDIR/all_passive.txt"

# Infrastructure
echo ""
echo "=== CDN / STATIC ==="
grep -iE 'cdn|static|assets|media|img|images|files|download|origin|proxy' "$OUTDIR/all_passive.txt"

# Email
echo ""
echo "=== EMAIL ==="
grep -iE 'mail\.|smtp|imap|pop|email|webmail|autodiscover' "$OUTDIR/all_passive.txt"

# Cloud
echo ""
echo "=== CLOUD ==="
grep -iE 'aws|azure|gcp|cloud|s3|bucket|firebase' "$OUTDIR/all_passive.txt"

# Legacy
echo ""
echo "=== LEGACY / OLD ==="
grep -iE 'old|old\.|v1|v2|legacy|archive|backup|bak' "$OUTDIR/all_passive.txt"
```

### 步骤 5 — 子域接管检查

```bash
DOMAIN="$1"
OUTPUT_ROOT="${OUTPUT_DIR:-./output}"
OUTDIR="$OUTPUT_ROOT/subdomains/$DOMAIN"

echo "[*] Checking for subdomain takeover opportunities..."

# Check for dangling CNAMEs (subdomains pointing to non-existent services)
# For bulk CNAME check: dnsx -silent -l all_passive.txt -cname -resp-only
while read -r sub; do
  cname=$(dig +short "$sub" CNAME 2>/dev/null)
  if [[ -n "$cname" ]]; then
    # Check if the CNAME target resolves
    cname_ip=$(dig +short "$cname" A 2>/dev/null)
    if [[ -z "$cname_ip" ]]; then
      echo "[TAKEOVER?] $sub => $cname (NOT RESOLVING)"

      # Identify provider from CNAME
      if echo "$cname" | grep -qi 'amazonaws.com'; then
        echo "  Provider: AWS (S3/CloudFront) — check if bucket/domain is claimable"
      elif echo "$cname" | grep -qi 'azure'; then
        echo "  Provider: Azure — check if resource is claimable"
      elif echo "$cname" | grep -qi 'github.io'; then
        echo "  Provider: GitHub Pages — check if repo name is available"
      elif echo "$cname" | grep -qi 'herokuapp.com'; then
        echo "  Provider: Heroku — check if app name is available"
      elif echo "$cname" | grep -qi 'vercel-dns.com'; then
        echo "  Provider: Vercel — check if project is claimable"
      elif echo "$cname" | grep -qi 'zendesk.com'; then
        echo "  Provider: Zendesk — check if help desk is claimable"
      fi
    fi
  fi
  sleep 0.5
done < "$OUTDIR/all_passive.txt"
```

## Pitfalls

- **crt.sh 限流。** 若被限流，crt.sh 可能返回空 JSON。可使用延迟，或直接查询 PostgreSQL dump。
- **subfinder 需要 API 密钥。** 部分来源（VirusTotal、Shodan）需要在 `~/.config/subfinder/provider-config.yaml` 中配置 API 密钥。缺少密钥时结果有限。
- **泛解析 DNS。** 若 `*.example.com` 解析到同一 IP，则所有子域在 httpx 中都会显示为“存活”。可解析一个随机字符串来检查是否存在泛解析：`dig RANDOMSTRING.example.com`。
- **Cloudflare 代理。** 位于 Cloudflare 之后的子域会显示 Cloudflare 的 IP，而非源站 IP。可使用 SecurityTrails 或 DNSDumpster 查询历史 DNS 记录。

## Verification

- 每个子域都必须用 httpx 探测，以确认其提供 HTTP/HTTPS 服务。
- 解析得到的 IP 必须与已知 CDN IP（Cloudflare、CloudFront、Fastly）交叉比对，避免把 CDN IP 误认为源站。
- 子域接管候选必须人工确认其 CNAME 目标确实未被占用。
- 所有存活子域都应记录：URL、HTTP 状态码、技术栈和页面标题。

### 阶段 7 — 排列组合与预测

从已发现的子域生成智能变体，以发现隐藏服务：

```bash
# gotator — generates permutations
gotator -sub all_subs.txt -perm permutations.txt -depth 1 -numbers 3 -md | sort -u > subs_permuted.txt

# Resolve permutations
puredns resolve subs_permuted.txt -r resolvers.txt -o subs_permuted_alive.txt

# Common permutation patterns for the wordlist
# %s-dev, dev-%s, %s-staging, staging-%s, %s-prod, %s-internal
# %s-admin, admin-%s, %s-api, api-%s, %s-test, test-%s
# %s-stg, stg-%s, %s-uat, uat-%s, %s-www, www-%s
```

### 阶段 8 — TLD 扩展

拥有 `target.com` 的公司常常忽略 `target.io`、`target.net`、`target.xyz`：

```bash
# tldbrute — discovers registered TLD variants
tldbrute -d target.com

# Manual IANA TLD list approach
wget -q https://data.iana.org/TLD/tlds-alpha-by-domain.txt
ROOT=$(echo "target.com" | cut -d. -f1)
cat tlds-alpha-by-domain.txt | tr '[:upper:]' '[:lower:]' \
  | while read tld; do echo "$ROOT.$tld"; sleep 0.2; done \
  | httpx -silent -mc 200 > tlds_alive.txt

# Expand existing subdomains across TLDs
cat all_subs.txt | while read sub; do
  cat tlds-alpha-by-domain.txt | tr '[:upper:]' '[:lower:]' \
    | sed "s/^/$sub./"
done | dnsx -silent > subs_tld_expanded.txt
```

### 阶段 9 — 证书实时监控

在新子域签发的瞬间捕获它们：

```bash
# gungnir — real-time certificate transparency monitoring
gungnir -d target.com

# certwatcher — alternative CT log monitor
certwatcher -d target.com --webhook https://hooks.slack.com/xxx
```
