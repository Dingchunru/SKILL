---
name: subdomain-takeover-hunt
description: 通过指向未认领服务的悬空 CNAME 检测并验证子域名接管。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3, subfinder, dnsx
metadata:
  tags: [recon, subdomain, takeover, CNAME, DNS, cloud, Heroku, S3, Azure]
  category: recon
  related_skills:
    - subdomain-enumeration
    - origin-ip-discovery
    - port-service-discovery
---

# 子域名接管检测

检测指向未注册或未认领第三方云服务的子域名。当一条 CNAME 记录指向已不存在的服务时，攻击者可以注册该资源并在目标的子域名下提供任意内容——从而实现钓鱼、Cookie 窃取以及完整的源站冒充。

## When to Use

- 子域名枚举产出大量列表——扫描残留的 DNS 记录。
- 目标使用具有共享命名空间标识符的云服务（Heroku、S3、Azure、Zendesk、Shopify）。
- 子域名返回 NXDOMAIN、404 或 "no such app" 错误页。
- CNAME 目标是名称可由用户注册的服务。

## Prerequisites

- 具备 curl、dnsx、subfinder 的 `terminal`。
- 已安装 `subzy` 或 `subjack` 用于自动化检测。
- 来自 `subdomain-enumeration` 的存活子域名列表。

## How to Run

```bash
# DNS resolution with CNAME extraction
dnsx -retry 3 -a -cname -resp -silent -l alive_subs.txt | tee dns_records.txt

# Automated takeover scan
subzy run --targets alive_subs.txt --hide_fails --vuln
```

## 快速检测

```bash
# DNS resolution with CNAME extraction
dnsx -retry 3 -a -cname -resp -silent -l alive_subs.txt | tee dns_records.txt

# Automated takeover scan
subzy run --targets alive_subs.txt --hide_fails --vuln
```

## Procedure

### 阶段 1 — 提取 CNAME 记录

```bash
# Get all CNAME records
cat alive_subs.txt | dnsx -silent -cname -resp-only > cname_targets.txt

# Filter to suspicious services
grep -iE "heroku|s3\.amazonaws|azure|zendesk|shopify|github\.io|bitbucket|surge\.sh|netlify|vercel|ghost\.io|readme|statuspage|pantheon|desk\.com|campaignmonitor|intercom|unbounce|wordpress\.com|cargo\.collective" \
  cname_targets.txt > takeover_candidates.txt
```

### 阶段 2 — 自动化检测

```bash
# subzy — fast, shows vulnerable + fingerprint
subzy run --targets alive_subs.txt --hide_fails --vuln

# subjack — with custom fingerprints
subjack -w alive_subs.txt -t 100 -timeout 30 -o takeover_results.txt \
  -ssl -c ~/subjack/fingerprints.json -v

# nuclei — takeover templates
nuclei -l alive_subs.txt \
  -t nuclei-templates/takeovers/ \
  -o nuclei_takeover_results.txt
```

### 阶段 3 — 人工验证

```bash
# For each candidate, verify the service is claimable
CANDIDATE="api.target.com"

# Check what the CNAME points to
dig $CANDIDATE CNAME +short

# Check HTTP response
curl --max-time 30 --connect-timeout 10 -skI "https://$CANDIDATE" | head -10

# Key service-specific verification:

# Heroku: visit https://CANDIDATE — "no such app" = claimable
# S3: curl -s https://BUCKET_NAME.s3.amazonaws.com — 404 NoSuchBucket = claimable
# Zendesk: visit https://CANDIDATE — "account not found" = claimable
# GitHub Pages: dig CNAME returns user.github.io — 404 = claimable
# Azure: visit https://CANDIDATE — "tenant not found" = claimable
# Shopify: visit https://CANDIDATE — "Sorry, this shop is currently unavailable"
```

### 阶段 4 — S3 接管流水线

```bash
subfinder -d target.com -silent \
  | dnsx -silent -cname \
  | grep "s3.amazonaws" \
  | while read line; do
      sub=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
      curl --max-time 30 --connect-timeout 10 -sk "https://$sub" | grep -q "NoSuchBucket" && echo "CLAIMABLE: $sub"
    done
```

### 阶段 5 — 服务指纹参考

| 服务 | 错误信息或特征 | 可认领信号 |
|---|---|---|
| Heroku | "No such app" / "There's nothing here" | 是 |
| S3 | "NoSuchBucket" / "The specified bucket does not exist" | 是 |
| Azure | "tenant not found" / "This tenant is not found" | 是 |
| Zendesk | "account not found" / "Help Center Closed" | 是 |
| GitHub Pages | 404 "There isn't a GitHub Pages site here" | 是 |
| Shopify | "Sorry, this shop is currently unavailable" | 是 |
| Netlify | "Not Found" / "Site not found" | 是 |
| Vercel | 404 — "DEPLOYMENT_NOT_FOUND" | 是 |
| Bitbucket | "Repository not found" | 是 |
| Surge.sh | "project not found" | 是 |
| Readme.io | "Project not found" | 是 |
| Statuspage | 404 — status page not found | 是 |
| Desk.com | "This site is currently not available" | 是 |
| Campaign Monitor | "Trying to get your email from" | 是 |
| Intercom | "This page is reserved for Intercom customers" | 是 |
| Unbounce | "The requested URL was not found" | 是 |
| WordPress.com | "Do you want to register domain.wordpress.com?" | 是 |

## Pitfalls

- **CNAME 解析到 CDN 服务并不构成发现。** Cloudflare/CloudFront/Akamai 的子域名不可被认领。
- **CNAME 可能指向一个有效且正在使用的服务。** 在声称存在发现之前，务必验证错误页。
- **某些服务会阻断自动化扫描器。** 使用浏览器访问该 URL 以确认。
- **子域名接管需要注册目标资源。** 未经明确授权，绝不要注册资源。
- **通配符 DNS（`*.target.com` → IP）会产生误报。** 在扫描接管之前过滤掉通配符响应。

## Verification

1. `dig SUBDOMAIN CNAME +short` 返回一个名称可由用户注册的服务。
2. `curl --max-time 30 --connect-timeout 10 -sk https://SUBDOMAIN` 返回表明资源可用的服务专属错误页。
3. CNAME 目标不得解析到 CDN 或负载均衡器。
4. 在报告之前，记录确切的错误信息与服务类型。

---

## 相关技能

- **`subdomain-enumeration`** —— 生成用于接管扫描的子域名列表。
- **`origin-ip-discovery`** —— 若发现接管，检查同一 IP 是否托管其他服务。
- **`port-service-discovery`** —— 扫描 CNAME 解析出的 IP，寻找额外暴露的服务。
