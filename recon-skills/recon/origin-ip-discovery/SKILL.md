---
name: origin-ip-discovery
description: 通过 favicon 哈希、DNS 历史记录与 SSL 证书发现 CDN/WAF 背后的源站 IP。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, dnsx, python3, subfinder
metadata:
  tags: [recon, origin-ip, CDN, WAF, bypass, Cloudflare, favicon, DNS]
  category: recon
  related_skills:
    - subdomain-enumeration
    - vhost-enumeration
    - port-mass-scan
---

# 源站 IP 发现

发现 CDN/WAF 防护（Cloudflare、Akamai、Fastly）背后的真实服务器 IP。一旦找到源站 IP，原始服务器便暴露在外，不再受防火墙规则、速率限制或应用层过滤的保护。相关技术包括在 Shodan 中进行 favicon 哈希指纹识别、从被动数据源获取历史 DNS 记录、SSL 证书 SAN 字段匹配，以及 Google Analytics ID 交叉比对。

## When to Use

- 目标位于 Cloudflare/Akamai 之后，且对所有请求返回 403 或 CAPTCHA 验证。
- 需要直接访问源站以绕过 WAF 规则。
- 子域名枚举发现了位于非 CDN IP 上的内部/预发布主机。
- 目标在所有基础设施上使用同一个 favicon。
- 各 IP 的 SSL 证书共享同一组织名称。

## Prerequisites

- 具备 curl、python3 和 shodan CLI 的 `terminal`。
- Shodan API 密钥：`shodan init <KEY>`。
- 目标的 favicon 文件或 URL。

## How to Run

```bash
# Check Cloudflare presence
curl --max-time 30 --connect-timeout 10 -sI "https://target.com" | grep -i "cf-ray\|server: cloudflare"

# If Cloudflare detected, check for common origin leaks
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/cdn-cgi/trace" | grep -E "ip=|colo="
```

## 快速检测

```bash
# Check Cloudflare presence
curl --max-time 30 --connect-timeout 10 -sI "https://target.com" | grep -i "cf-ray\|server: cloudflare"

# If Cloudflare detected, check for common origin leaks
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/cdn-cgi/trace" | grep -E "ip=|colo="
```

## Procedure

### 阶段 1 — Favicon 哈希指纹

```bash
# Get favicon hash
FAVICON_URL="https://target.com/favicon.ico"
curl --max-time 30 --connect-timeout 10 -sk "$FAVICON_URL" -o favicon_target.ico

# Calculate hash
python3 -c "
import hashlib, base64
with open('favicon_target.ico', 'rb') as f:
    hash_bytes = base64.b64encode(hashlib.md5(f.read()).digest())
    print(f'favicon hash: {hash_bytes.decode()}')
"

# Search Shodan for IPs serving this favicon
HASH=$(python3 -c "
import hashlib, base64
with open('favicon_target.ico','rb') as f:
    print(base64.b64encode(hashlib.md5(f.read()).digest()).decode())
")
shodan search "http.favicon.hash:$HASH" --fields ip_str,port,org,hostnames

# Automatedtools
python3 favUp.py -ff favicon_target.ico --shodan-cli
python3 favUp.py --web target.com -sc
```

### 阶段 2 — 历史 DNS 记录

```bash
# SecurityTrails — DNS history
curl --max-time 30 --connect-timeout 10 -s "https://securitytrails.com/domain/target.com/history/a" \
  -H "APIKEY: $SECURITYTRAILS_KEY" \
  | jq '.records[].values[].ip' | sort -u

# AlienVault OTX — passive DNS
curl --max-time 30 --connect-timeout 10 -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns" \
  | jq '.passive_dns[].address' | sort -u

# Automatedtools
echo "target.com" | originiphunter
cat domains.txt | originiphunter
```

### 阶段 3 — SSL 证书搜索

```bash
# crt.sh — find all certs for the domain, extract unique IPs from SAN fields
curl --max-time 30 --connect-timeout 10 -s "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[].name_value' | tr ',' '\n' | sort -u > cert_domains.txt

# Censys — search by parsed names
# Web: https://search.censys.io — query: parsed.names: target.com

# Shodan — search by SSL subject CN
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port,org

# Netlas — deep infrastructure search
# Web: https://netlas.io — query: domain:*.target.com
```

### 阶段 4 — Google Analytics ID 交叉比对

```bash
# Extract Analytics ID from target pages
curl --max-time 30 --connect-timeout 10 -s "https://target.com" | grep -Po '(?:UA-|G-|GTM-)[A-Z0-9]+'

# Find all domains sharing the same GA ID
curl --max-time 30 --connect-timeout 10 -s "https://api.hackertarget.com/analyticslookup/?q=UA-XXXXXXXX-X"
curl --max-time 30 --connect-timeout 10 -s "https://builtwith.com/relationships/target.com"

# Automated
cat subdomains.txt | analyticsrelationships
```

### 阶段 5 — 常见源站泄露途径

```bash
# Direct IP in page source
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Po '\b(?:\d{1,3}\.){3}\d{1,3}\b' | sort -u

# DNS CNAME chain — may expose origin
dig target.com ANY +noall +answer
dig www.target.com CNAME +short

# MX records — mail server often shares infrastructure
dig target.com MX +short

# SPF records — may contain non-CDN IPs
dig target.com TXT +short | grep -Po '\b(?:\d{1,3}\.){3}\d{1,3}\b'

# Subdomain with different IP pattern
subfinder -d target.com -silent | dnsx -silent -a -resp-only | sort -u > all_ips.txt
# Filter out Cloudflare IPs (104.x, 172.64-71.x)
grep -vE '^104\.(1[6-9]|2[0-9]|3[0-1])\.|^172\.(6[4-9]|7[0-1])\.' all_ips.txt > non_cf_ips.txt
# Probe each for the target's content
for ip in $(cat non_cf_ips.txt); do
  curl --max-time 30 -sk --connect-timeout 5 "https://$ip" -H "Host: target.com" -o /dev/null -w "%{http_code} $ip\n"
done | grep -v "^403\|^000"
```

### 阶段 6 — 验证源站

```bash
# Check if IP serves the target's content
curl --max-time 30 --connect-timeout 10 -sk "https://ORIGIN_IP" -H "Host: target.com" | grep -o '<title>[^<]*</title>'

# Verify favicon matches
curl --max-time 30 --connect-timeout 10 -sk "https://ORIGIN_IP/favicon.ico" -H "Host: target.com" -o favicon_origin.ico
md5sum favicon_target.ico favicon_origin.ico  # should match

# Probe ports directly on origin
naabu -host ORIGIN_IP -p - -rate 2000
```

## Pitfalls

- **Cloudflare 可能在重复扫描时封禁你的 IP。** 轮换 user-agent 与代理。
- **Shodan 查询需要 API 密钥。** 免费套餐存在速率限制。
- **源站本身也可能受防火墙规则保护。** 即使找到了 IP，它可能只接受来自 Cloudflare IP 段的流量。
- **Google Analytics ID 可能在互不相关的站点间共享。** 在声称发现之前，应通过 favicon 或内容匹配进行验证。
- **子域名解析出的非 CDN IP 可能是负载均衡器，** 而非实际的 Web 服务器源站。使用 Host 头探测以确认。

## Verification

1. CDN 缓存站点与直接访问源站 IP 得到的 favicon 哈希一致。
2. 携带 `Host: target.com` 对源站 IP 发起 HTTPS 请求返回相同的页面内容。
3. 源站上开放的端口与经 CDN 代理的端口不同（源站暴露 SSH、MySQL 等）。
4. 源站 IP 上的 SSL 证书在 SAN 中列出了目标域名。

---

## 相关技能

- **`subdomain-enumeration`** — 生成 IP 去重所需的子域名列表。
- **`vhost-enumeration`** — 找到源站 IP 后，枚举虚拟主机。
- **`port-mass-scan`** — 扫描源站 IP 上暴露的服务。
