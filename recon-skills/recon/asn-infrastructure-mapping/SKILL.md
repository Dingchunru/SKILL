---
name: asn-infrastructure-mapping
description: 通过 ASN、CIDR、TLD 扩展与反向 DNS 测绘组织的 IP 基础设施。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, dnsx, httpx
metadata:
  tags: [recon, ASN, CIDR, IP-range, TLD, reverse-DNS, infrastructure]
  category: recon
  related_skills:
    - subdomain-enumeration
    - origin-ip-discovery
    - vhost-enumeration
    - port-mass-scan
---

# ASN 基础设施测绘

通过从域名转向 ASN（自治系统号）、提取 CIDR 网段，并在所有归属 IP 段中发掘每个主机名与服务，来测绘组织的完整 IP 基础设施。包含 TLD 扩展，用于发现位于不同顶级域、拥有独立基础设施的兄弟域名。

## When to Use

- 你已掌握目标域名，希望发现该组织拥有的每一个 IP。
- 被动子域名枚举只找到少量主机——其余可能位于兄弟 TLD 或不同 IP 段。
- 目标有已知 ASN，可扩展为完整 CIDR 网段。
- 非标准端口上的服务对仅关注 Web 的侦察不可见。
- 被收购的子公司或国际域名可能位于安全防护更弱的不同 ASN 上。

## Prerequisites

- `terminal` 环境中的 whois、dnsx、mapcidr、httpx 与 asnmap。
- 目标域名和/或属于该组织的一个已知 IP。
- Shodan API 密钥（可选，用于更深入的 OSINT）。

## How to Run

```bash
# Start: domain → IP → ASN → CIDR ranges
IP=$(dig target.com +short | head -1)
ASN=$(whois $IP | grep -i "origin\|OriginAS" | awk '{print $NF}' | head -1)
echo "ASN: $ASN"
whois -h whois.radb.net -- "-i origin $ASN" | grep -Eo "([0-9.]+){4}/[0-9]+" | sort -u
```

## 快速检测

```bash
# Start: domain → IP → ASN → CIDR ranges
IP=$(dig target.com +short | head -1)
ASN=$(whois $IP | grep -i "origin\|OriginAS" | awk '{print $NF}' | head -1)
echo "ASN: $ASN"
whois -h whois.radb.net -- "-i origin $ASN" | grep -Eo "([0-9.]+){4}/[0-9]+" | sort -u
```

## Procedure

### 阶段 1 —— 从域名到 ASN 的发现

```bash
# asnmap — automated domain → ASN
asnmap -d target.com

# Manual whois approach
IP=$(dig target.com +short | head -1)
whois $IP | grep -iE "origin|OriginAS|route:|descr:" | head -10

# spk — finds all ASNs for a company by name (including subsidiaries)
spk -json -s "Company Name"

# Webtools
# https://bgp.he.net — search by company name
# https://asnlookup.com — search by org name, ASN, or CIDR
# https://bgp.tools — modern BGP explorer
```

### 阶段 2 —— 从 ASN 到 CIDR 网段

```bash
# asnmap — direct CIDR extraction
asnmap -a AS33905 -silent > cidr_ranges.txt

# RADB whois — full route objects
whois -h whois.radb.net -- "-i origin AS33905" \
  | grep -Eo "([0-9.]+){4}/[0-9]+" \
  | sort -u >> cidr_ranges.txt

# metabigor — multi-source IP intelligence
echo "Company Name" | metabigor net --org -o cidr_ranges.txt
echo "ASN33905" | metabigor net --asn -o cidr_ranges.txt
```

### 阶段 3 —— 从 CIDR 到单个 IP

```bash
# mapcidr — split CIDR into flat IP list
cat cidr_ranges.txt | mapcidr -silent > all_ips.txt
wc -l all_ips.txt

# prips — alternative IP generator
while read cidr; do prips "$cidr"; done < cidr_ranges.txt >> all_ips.txt

# Scan discovered IPs for live web services
cat all_ips.txt | httpx \
  -ports 80,443,8080,8443,3000,5000,8000,8888,9090,9443 \
  -status-code -title -web-server -silent \
  -o live_ip_services.txt
```

### 阶段 4 —— 对 IP 网段进行反向 DNS

```bash
# dnsx PTR — resolve hostnames from IP blocks
cat cidr_ranges.txt | dnsx -silent -resp-only -ptr > ptr_domains.txt

# Filter for target-related hosts
grep -i "target" ptr_domains.txt > ptr_target.txt

# hakrevdns — reverse DNS at scale
hakrevdns -d target.com -R resolvers.txt

# resolveDomains — check which IPs serve target content
resolveDomains -d all_subs.txt > resolved.txt
awk '{print $3}' resolved.txt | sort -u > unique_ips.txt
```

### 阶段 5 —— TLD 扩展

```bash
# tldbrute — discover all registered TLD variants
tldbrute -d target.com

# Manual IANA TLD list approach
wget -q https://data.iana.org/TLD/tlds-alpha-by-domain.txt
ROOT=$(echo "target.com" | cut -d. -f1)
cat tlds-alpha-by-domain.txt | tr '[:upper:]' '[:lower:]' \
  | while read tld; do echo "$ROOT.$tld"; done \
  | httpx -silent -mc 200 > tlds_alive.txt

# Apply to all known subdomains
cat all_subs.txt | while read sub; do
  cat tlds-alpha-by-domain.txt | tr '[:upper:]' '[:lower:]' \
    | sed "s/^/$sub./"
done | dnsx -silent > subs_tld_expanded.txt
```

### 阶段 6 —— 架构可视化

```bash
# Map which domains belong to which IP
cat unique_ips.txt | while read ip; do
  echo -n "$ip: "
  grep -l "$ip" resolved.txt 2>/dev/null | tr '\n' ' '
  echo
done > ip_to_domain_map.txt

# Identify shared infrastructure (one IP serving multiple domains — CDN or reverse proxy)
awk '{if (NF > 2) print}' ip_to_domain_map.txt > shared_infra.txt

# Scan non-web ports on ALL discovered IPs
naabu -l all_ips.txt -p - -rate 1000 -c 50 -exclude-ports 80,443 -o all_services.txt
```

### 阶段 7 —— 子组织发现

```bash
# Extract all company/organization names from whois
cat all_ips.txt | while read ip; do
  whois $ip 2>/dev/null | grep -iE "OrgName|org-name|descr:" | head -1
done | sort -u > subsidiary_names.txt

# For each subsidiary, repeat the ASN → CIDR pipeline
cat subsidiary_names.txt | while read org; do
  metabigor net --org "$org" >> expanded_cidr.txt
done
```

## Pitfalls

- **CIDR 网段可能非常庞大（例如 AWS）。** 只扫描确认属于目标的 IP 段，而非整个托管服务商。
- **RADB whois 数据可能过期。** 需与多个来源交叉核对（bgp.he.net、Censys、Shodan）。
- **TLD 扩展噪声很大。** 通常只有 .com/.org/.net/.io/.dev 能产生有用结果。
- **反向 DNS 可能暴露内部主机名。** 在外部侦察中需谨慎处理——这些泄露本身就是发现项。
- **子组织发现可能导致越界目标。** 扫描前务必核实归属关系。

## Verification

1. CIDR 网段至少通过两个来源确认（whois + bgp.he.net 或 asnmap）。
2. 对已发现 IP 进行反向 DNS 时返回了与目标相关的主机名。
3. TLD 扩展在兄弟 TLD 上发现了存活域名。
4. Web 服务扫描在非标准端口上识别出独有的应用。
5. 绘制完整基础设施图谱：域名 → IP → 服务 → 漏洞。

---

## 相关技能

- **`subdomain-enumeration`** —— 在扩展到 IP 基础设施之前生成初始子域名列表。
- **`origin-ip-discovery`** —— 在已知 CIDR 网段后，识别哪些 IP 是 CDN 背后的源站。
- **`vhost-enumeration`** —— 扫描已发现 IP 上的隐藏虚拟主机。
- **`port-mass-scan`** —— 扫描所有已发现 IP 上的暴露服务。
