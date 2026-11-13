---
name: vhost-enumeration
description: 通过 Host 头模糊测试和 SSL 证书解析发现隐藏的虚拟主机。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, ffuf, dnsx
metadata:
  tags: [recon, vhost, virtual-host, Host-header, fuzzing, SSL, PTR]
  category: recon
  related_skills:
    - subdomain-enumeration
    - origin-ip-discovery
    - source-leak-hunt
---

# 虚拟主机枚举

通过对 `Host` 头进行模糊测试，发现 IP 地址上隐藏的虚拟主机。许多服务器只对特定域名作出响应，而对标准的子域名枚举保持不可见。VHOST 模糊测试能够暴露共享同一 IP、却响应不同主机名的内部服务、开发环境和管理面板。

## When to Use

- 你从 `skill_view(name='origin-ip-discovery')` 或 `skill_view(name='port-service-discovery')` 获得了目标 IP 列表。
- 服务器对未知的 Host 头返回默认/空白页面。
- 子域名枚举可能遗漏了仅内部可用的主机名。
- IP 列表上的 SSL 证书在 SAN 字段中列出了多个域名。
- 你需要梳理反向代理后面的内部服务。

## Prerequisites

- 带有 curl、ffuf、dnsx 和 httpx 的 `terminal`。
- 用于主机名模糊测试的 DNS 字典。
- 目标 IP 地址列表。

## How to Run

```bash
# Basic VHOST fuzz on a single IP
ffuf -u http://TARGET_IP \
  -w /path/to/wordlist.txt \
  -H "Host: FUZZ.target.com" \
  -fs 0 -mc 200,301,302,401,403
```

## 快速检测

```bash
# Basic VHOST fuzz on a single IP
ffuf -u http://TARGET_IP \
  -w /path/to/wordlist.txt \
  -H "Host: FUZZ.target.com" \
  -fs 0 -mc 200,301,302,401,403
```

## Procedure

### 阶段 1 — Host 头模糊测试

```bash
# Fuzz for virtual hosts matching the target domain pattern
ffuf -u http://TARGET_IP \
  -w $DNS_WORDLIST \
  -H "Host: FUZZ.target.com" \
  -fs DEFAULT_RESPONSE_SIZE \
  -mc 200,301,302,401,403 \
  -o vhost_ffuf.json

# HTTPS variant
ffuf -u https://target.com \
  -w $DNS_WORDLIST \
  -H "Host: FUZZ.target.com" \
  -mc 200,301,302,401,403

# Fuzz multiple IPs with a wordlist
cat unique_ips.txt | while read ip; do
  ffuf -u "http://$ip" \
    -w $DNS_WORDLIST \
    -H "Host: FUZZ.target.com" \
    -fs 0 -mc 200,301,302 -o "vhost_$ip.json"
  sleep 0.5
done
```

### 阶段 2 — 响应过滤

```bash
# Auto-calibrate: ffuf detects default response size and filters it out
ffuf -u http://TARGET_IP \
  -w $DNS_WORDLIST \
  -H "Host: FUZZ.target.com" \
  -ac -sf -s \
  -mc 200

# Manual calibration: find the default response size first
curl --max-time 30 --connect-timeout 10 -s http://TARGET_IP -H "Host: nonexistentxxxxx12345.target.com" | wc -c
# Use that size as -fs filter
```

### 阶段 3 — 访问 VHOST 目标

```bash
# Method 1 — direct curl with Host header
curl --max-time 30 --connect-timeout 10 -H "Host: dev.target.com" http://TARGET_IP

# Method 2 — /etc/hosts injection for browser access
echo "TARGET_IP  dev.target.com internal.target.com admin.target.com" | sudo tee -a /etc/hosts
# Then open http://dev.target.com in browser

# Method 3 — httpx with custom host resolution
echo "http://dev.target.com" | httpx -silent
```

### 阶段 4 — SSL 证书 SAN 枚举

```bash
# Extract hostnames from SSL certificate
echo | openssl s_client -connect TARGET_IP:443 -servername target.com 2>/dev/null \
  | openssl x509 -noout -text \
  | grep -Po 'DNS:[^,\s]+' | cut -d: -f2 | sort -u

# Batch: extract hostnames from all discovered IPs
cat unique_ips.txt | while read ip; do
  echo | timeout 5 openssl s_client -connect $ip:443 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null \
    | grep -Po 'DNS:[^,\s]+' | cut -d: -f2 | sort -u >> ssl_hostnames.txt
  sleep 0.5
done

# Check which of those hostnames resolve to the target
cat ssl_hostnames.txt | dnsx -silent -a -resp-only | sort -u
```

### 阶段 5 — IP 段上的 PTR 反向 DNS

```bash
# If you have IP ranges, resolve PTR records to find hostnames
echo "10.0.0.0/23" | dnsx -silent -resp-only -ptr

# Batch on multiple CIDR ranges
cat cidr_ranges.txt | mapcidr -silent | dnsx -ptr -resp-only -silent > ptr_domains.txt
```

### 阶段 6 — 内容差异比对

```bash
# For each found VHOST, take a screenshot for visual triage
cat found_vhosts.txt | gowitness file -f - --no-http -P ./vhost_screenshots/

# Compare content across hosts — different content = different service
for host in $(cat found_vhosts.txt); do
  curl --max-time 30 --connect-timeout 10 -sk "http://TARGET_IP" -H "Host: $host" | md5sum
  sleep 0.3
done | sort
```

## Pitfalls

- **通配符 DNS 会对任意 Host 头返回有效的 HTTP 响应。** 使用自动校准（`-ac`）并手动验证。
- **默认虚拟主机可能对未知名称返回通用页面。** 使用一个已知不存在的主机名来校准 `-fs`。
- **SSL/TLS 在没有 SNI 的情况下会妨碍内容比对。** 对每个主机名使用 `openssl s_client -servername`。
- **有些服务器接受任意 Host 头。** 这会产生误报——请用人工 curl 验证每个发现。
- **仅内部可用的服务可能无法从你的 IP 访问。** 它们可能需要内部网络访问权限。

## Verification

1. ffuf 返回的状态码和响应大小与校准出的默认值不同。
2. 使用发现的主机名作为 Host 头进行人工 curl，返回有意义的内容（而非默认页面）。
3. 该主机名不在公开的子域名列表中（此前未知）。
4. SSL 证书的 SAN 字段确认该主机名属于此服务器。
5. 截图并确认它是一个独立的应用或服务。

---

## 相关技能

- **`subdomain-enumeration`** — 生成 DNS 字典和现有子域名。
- **`origin-ip-discovery`** — 找到需要进行 VHOST 扫描的源站 IP。
- **`source-leak-hunt`** — 找到 VHOST 后，对目录和端点进行模糊测试。
