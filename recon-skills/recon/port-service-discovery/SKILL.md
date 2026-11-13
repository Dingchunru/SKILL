---
name: port-service-discovery
description: 使用 Nmap 扫描 MySQL、Redis、FTP、SSH 及内部 API 服务。
version: 1.1.1
revision_date: 2026-11-13
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, masscan
metadata:
  tags: [recon, port-scan, mysql, FTP, SSH, internal-api]
  category: recon
  related_skills:
    - deep-invade
    - wp-mass-recon
    - cross-attack-chains
    - staging-subdomain-hunt
---

# 端口与服务发现技能

使用有范围的 Nmap 发现来识别与 Web 应用相邻的服务，包括数据库、远程管理、邮件、缓存以及非标准 API 端口。开放端口只是一个观察结果；服务身份与未授权访问需要单独验证。

## When to Use

- 在高价值目标上执行 `deep-invade` 的阶段 6。
- 当表层侦察未发现可利用的 Web 漏洞后 — 转向基础设施。
- 当目标是 SaaS 且在非标准端口上提供后端 API 时。
- 发现预发布子域名后 — 检查数据库/管理端口。

## Prerequisites

- 执行环境中具备 `nmap`。
- 目标域名或 IP 地址。
- 进行全端口扫描：需要耐心（扫描全部 65535 个端口可能需要 10-60 分钟）。

## How to Run

```bash
# Fast top-100 port scan (30 seconds)
nmap -F --open -T4 TARGET -oN nmap_fast.txt

# Top 1000 ports (2-3 minutes)
nmap --top-ports 1000 --open -T4 TARGET -oN nmap_1000.txt

# Service version detection on open ports
nmap -sV -p $(grep 'open' nmap_fast.txt | cut -d/ -f1 | tr '\n' ',') TARGET

# Firewall bypass: fragment packets
nmap -f -F TARGET
```

## 快速参考

| 端口 | 服务 | 发现严重级别 |
|------|---------|-----------------|
| 3306 | MySQL | 严重（若对互联网开放） |
| 27017 | MongoDB | 严重（若无认证） |
| 6379 | Redis | 严重（若无认证） |
| 5432 | PostgreSQL | 高 |
| 1433 | MS SQL Server | 高 |
| 21 | FTP | 高（是否允许匿名登录？） |
| 22 | SSH | 信息（检查弱认证） |
| 8080/8081/8082/8084 | 内部 API | 高（后端服务暴露） |
| 9200 | Elasticsearch | 高（数据暴露） |
| 25/587 | SMTP | 中（是否为开放中继？） |
| 110/143/993 | POP3/IMAP | 信息 |
| 8443 | HTTPS 备选（管理面板） | 中 |
| 9090 | Prometheus/Cockpit | 中 |
| 3000 | Grafana/Node.js 开发服务 | 中 |

## Procedure

### 步骤 1 — 快速 Top-100 扫描

```bash
TARGET="$1"
OUTDIR="$OUTDIR/ports"
mkdir -p "$OUTDIR"

echo "[*] Fast scan (top 100 ports) on $TARGET..."
nmap -F --open -T4 --max-retries 1 --host-timeout 60s "$TARGET" -oN "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null

echo "[*] Open ports:"
grep 'open' "$OUTDIR/${TARGET}_fast.nmap" || echo "  None found"
```

### 步骤 2 — 服务版本探测

```bash
TARGET="$1"
OUTDIR="$OUTDIR/ports"

# Get comma-separated list of open ports
OPEN_PORTS=$(grep '^[0-9]' "$OUTDIR/${TARGET}_fast.nmap" | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')

if [[ -n "$OPEN_PORTS" ]]; then
  echo "[*] Service detection on ports: $OPEN_PORTS"
  nmap -sV --version-intensity 5 -p "$OPEN_PORTS" "$TARGET" -oN "$OUTDIR/${TARGET}_services.nmap" 2>/dev/null

  echo "[*] Services:"
  grep 'open' "$OUTDIR/${TARGET}_services.nmap"
else
  echo "[-] No open ports found"
fi
```

### 步骤 3 — 关键暴露检查

```bash
TARGET="$1"
OUTDIR="$OUTDIR/ports"

echo "[*] Critical exposure assessment:"

# MySQL (3306)
if grep -q '3306.*open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo ""
  echo "[CRITICAL] MySQL 3306 OPEN — attempting banner grab..."
  # Try to get MySQL version
  mysql_info=$(timeout 5 nc -w 3 "$TARGET" 3306 </dev/null 2>/dev/null | head -1)
  [[ -n "$mysql_info" ]] && echo "  Banner: $mysql_info"

  # Test for no-auth MySQL
  echo "  Testing anonymous access..."
  # This typically requires mysql client; note methodology
  echo "  Manual check: mysql -h $TARGET -u root --skip-ssl"
  echo "  Manual check: mysql -h $TARGET -u admin --skip-ssl"
fi

# MongoDB (27017)
if grep -q '27017.*open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo ""
  echo "[CRITICAL] MongoDB 27017 OPEN"
  echo "  Manual check: mongosh mongodb://$TARGET:27017"
fi

# Redis (6379)
if grep -q '6379.*open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo ""
  echo "[HIGH] Redis 6379 OPEN — testing no-auth access..."
  redis_test=$(timeout 5 bash -c "echo -e 'PING\r\nINFO\r\n' | nc -w 3 '$TARGET' 6379 2>/dev/null")
  if echo "$redis_test" | grep -q "PONG"; then
    echo "  [CRITICAL] Redis NO AUTH — full access!"
    echo "  Response: $(echo "$redis_test" | head -5)"
  else
    echo "  Redis requires auth (or connection failed)"
  fi
fi

# Internal API ports (8080-8089)
for port in 8080 8081 8082 8084 8088 8443 3000 5000 9000 9090; do
  if grep -q "${port}.*open" "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
    echo ""
    echo "[HIGH] Port $port OPEN — probing HTTP..."
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "http://$TARGET:$port/" 2>/dev/null)

    if [[ "$http_code" != "000" ]]; then
      echo "  HTTP $http_code on port $port"
      title=$(curl -sk --max-time 5 --connect-timeout 5 "http://$TARGET:$port/" 2>/dev/null | grep -Po '<title>\K[^<]+')
      [[ -n "$title" ]] && echo "  Title: $title"

      # Check for Swagger/API docs
      for api_path in "swagger.json" "api-docs" "swagger-ui.html" "graphql" "actuator/health"; do
        api_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "http://$TARGET:$port/$api_path")
        [[ "$api_code" == "200" ]] && echo "  [API] http://$TARGET:$port/$api_path (HTTP 200)"
        sleep 0.2
      done
    fi
  fi
done

# FTP (21) — check for anonymous login
if grep -q '21.*open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo ""
  echo "[HIGH] FTP 21 OPEN — testing anonymous login..."
  anon_test=$(timeout 10 bash -c "echo -e 'anonymous\nanonymous\n' | nc -w 3 '$TARGET' 21 2>/dev/null")
  if echo "$anon_test" | grep -qi "230"; then
    echo "  [CRITICAL] Anonymous FTP login successful!"
  elif echo "$anon_test" | grep -qi "530\|331"; then
    echo "  Anonymous FTP: requires auth"
  fi
fi

# SSH (22) — check for weak ciphers
if grep -q '22.*open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo ""
  echo "[INFO] SSH 22 OPEN"
  ssh_banner=$(timeout 5 nc -w 3 "$TARGET" 22 </dev/null 2>/dev/null | head -1)
  [[ -n "$ssh_banner" ]] && echo "  Banner: $ssh_banner"
fi
```

### 步骤 4 — 扩展端口范围（快速扫描无结果时）

```bash
TARGET="$1"
OUTDIR="$OUTDIR/ports"

# If no ports found in top-100, expand to top-1000
if ! grep -q 'open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo "[*] No ports in top-100, scanning top-1000..."
  nmap --top-ports 1000 --open -T4 --max-retries 1 --host-timeout 120s "$TARGET" -oN "$OUTDIR/${TARGET}_1000.nmap" 2>/dev/null

  OPEN=$(grep 'open' "$OUTDIR/${TARGET}_1000.nmap")
  if [[ -z "$OPEN" ]]; then
    # Try SYN scan with fragmentation for firewall evasion
    echo "[*] Still nothing — trying fragmented SYN scan..."
    nmap -f -sS -F --open -T4 "$TARGET" -oN "$OUTDIR/${TARGET}_frag.nmap" 2>/dev/null
  fi
fi
```

### 步骤 5 — 防火墙/WAF 指纹识别

```bash
TARGET="$1"

echo "[*] WAF/CDN detection:"

# Check for Cloudflare
cf_header=$(curl -skI --max-time 5 --connect-timeout 5 "https://$TARGET/" 2>/dev/null | grep -i "cf-ray\|cloudflare")
[[ -n "$cf_header" ]] && echo "  Cloudflare detected"

# Check for AWS CloudFront
cf_header=$(curl -skI --max-time 5 --connect-timeout 5 "https://$TARGET/" 2>/dev/null | grep -i "x-amz-cf\|cloudfront")
[[ -n "$cf_header" ]] && echo "  AWS CloudFront detected"

# Check origin IP (bypass CDN)
echo "[*] Historical DNS records for origin IP discovery:"
# SecurityTrails, DNSDumpster, etc. — use HTTP fetch for these
echo "  Manual: securitytrails.com/domain/$TARGET/dns/a"
echo "  Manual: dnsdumpster.com"

# Try direct IP connection (if known)
# curl -sk --resolve "$TARGET:443:ORIGIN_IP" "https://$TARGET/"
```

## Pitfalls

- **nmap SYN 扫描需要原始套接字权限。** 当执行环境未授予该权限时，请使用 `-sT`（TCP connect）。
- **端口扫描存在速率限制。** 部分服务商（AWS、Cloudflare）会对端口扫描进行限速或拦截。对敏感目标使用 `-T2`（礼貌时序）和 `--max-retries 1`。
- **MySQL/MongoDB 的 banner 抓取可能不奏效。** 部分数据库需要 TLS 协商（MySQL 8.0+ 默认使用 `caching_sha2_password`）。Banner 可能为空。
- **内部 API 端口可能超时。** 部分服务仅对特定的 Host 头或合法 HTTP 请求作出响应。可使用 `curl` 配合多种 Host 头进行尝试。

## Verification

- 每个开放端口都必须通过服务版本探测（`nmap -sV`）确认。
- MySQL 访问必须通过实际连接尝试进行测试（不能仅凭端口开放判断）。
- Redis 无认证必须在对 `PING` 命令的响应中返回 `PONG`。
- FTP 匿名登录必须返回状态码 230（登录成功）。
- 所有发现都必须记录确切的端口、服务、版本和访问级别。
