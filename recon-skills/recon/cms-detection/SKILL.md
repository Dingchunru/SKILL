---
name: cms-detection
description: 识别存活主机上的 CMS、框架与服务器技术栈。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, httpx, nuclei
metadata:
  tags: [recon, CMS, fingerprinting, technology, WordPress, Drupal, Joomla, Magento]
  category: recon
  related_skills:
    - source-leak-hunt
    - wordpress-plugin-hunt
    - visual-recon
    - wp-mass-recon
---

# CMS 检测

识别每台存活主机所使用的内容管理系统、Web 框架、服务器软件与技术栈。在发起攻击之前先弄清你正在攻击的是哪种技术栈——WordPress 站点与 Laravel API 或 Spring Boot 微服务所需的测试方式各不相同。多 CMS 检测覆盖 WordPress、Drupal、Joomla、Magento、Shopify、Wix、Squarespace、Laravel、Django、Express、Spring Boot 等。

## When to Use

- 你有一份存活主机列表，需要按技术对其进行归类。
- WordPress 专项测试产生了误报（该站点实际使用的是 Drupal）。
- 需要识别正在运行的 CMS 版本，以便匹配已知 CVE。
- 某主机对所有路径都返回通用的 200——技术检测能告诉你它实际运行的是什么。
- 希望找出运行流行 CMS 平台过时版本的站点。

## Prerequisites

- 具备 httpx、whatweb、wappalyzer 与 curl 的 `terminal` 环境。
- 来自 `skill_view(name='visual-recon')` 或 `skill_view(name='subdomain-enumeration')` 的存活子域名列表。

## How to Run

```bash
# Fastest: httpx with built-in tech detection
cat alive_subs.txt | httpx -silent -tech-detect -o tech_detect.txt

# Deep: whatweb with aggressive checks
whatweb -i alive_subs.txt -a 3 -t 50 --log-brief=cms_results.txt
```

## 快速检测

```bash
# Fastest: httpx with built-in tech detection
cat alive_subs.txt | httpx -silent -tech-detect -o tech_detect.txt

# Deep: whatweb with aggressive checks
whatweb -i alive_subs.txt -a 3 -t 50 --log-brief=cms_results.txt
```

## Procedure

### 阶段 1 —— 批量技术指纹识别

```bash
# httpx — fast tech detection using Wappalyzer signatures
cat alive_subs.txt | httpx -silent -tech-detect -o tech_httpx.txt

# Parse results: extract unique technologies with counts
cat tech_httpx.txt | awk -F' [' '{print $2}' | tr -d ']' | tr ',' '\n' \
  | sed 's/^ *//' | sort | uniq -c | sort -rn > tech_summary.txt

# whatweb — deeper, identifies specific CMS versions
whatweb -i alive_subs.txt -a 3 -t 50 \
  --log-brief=cms_results.txt \
  --log-json=cms_results.json

# Parse whatweb JSON for versioned findings
cat cms_results.json | jq -r '.[] | select(.version != null) | "\(.target): \(.plugin) \(.version)"' \
  | sort -u > versioned_cms.txt
```

### 阶段 2 —— 针对特定 CMS 的版本检测

#### WordPress

```bash
# Generator meta tag
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Eo '<meta name="generator"[^>]*content="WordPress [^"]+' | head -1

# RSS feed
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/feed/" | grep -Eo '<generator>https://wordpress.org/\?v=[^<]+' | head -1

# readme.html (often left accessible)
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/readme.html" | grep -Eo "Version [0-9.]+" | head -1

# wp-json namespace
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/wp-json/" | jq -r '.namespaces[]' 2>/dev/null
```

#### Drupal

```bash
# CHANGELOG.txt (Drupal's canonical version leak)
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/CHANGELOG.txt" | head -5

# Drupal specific paths
curl --max-time 30 --connect-timeout 10 -skI "https://target.com/user/login" | grep -i "drupal\|x-generator"
curl --max-time 30 --connect-timeout 10 -skI "https://target.com/node/1"
```

#### Joomla

```bash
# Joomla version files
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/administrator/manifests/files/joomla.xml" | grep -Eo '<version>[^<]+' | head -1
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/language/en-GB/en-GB.xml" | grep -Eo '<version>[^<]+'

# Meta tag
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Eo '<meta name="generator"[^>]*content="Joomla[^"]+' | head -1
```

#### Magento

```bash
# Magento version file
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/magento_version" | head -1
# Composer lock
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/composer.lock" | jq -r '.packages[] | select(.name=="magento/magento2-base") | .version' 2>/dev/null
```

#### Laravel

```bash
# Laravel debug info
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Eo 'Laravel v[0-9.]+'
# Composer lock
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/composer.lock" | jq -r '.packages[] | select(.name=="laravel/framework") | .version' 2>/dev/null
```

### 阶段 3 —— 服务器与框架检测

```bash
# Server header — often removed but check anyway
for host in $(cat alive_subs.txt); do
  echo -n "$host: "
  curl --max-time 30 --connect-timeout 10 -skI "https://$host" | grep -i "server:\|x-powered-by:" | tr '\n' ' '
  echo
  sleep 0.3
done > server_headers.txt

# Common server signatures and what they mean
# nginx → likely PHP-FPM or Node.js proxy
# Apache → shared hosting, cPanel
# IIS → Windows, ASP.NET
# LiteSpeed → shared hosting, WordPress optimized
# cloudflare → CDN/WAF in front, need origin-ip-discovery
# Microsoft-IIS/10.0 → Windows Server 2016+

# Framework detection via specific paths
# Django admin: /admin/ → redirect to /admin/login/
# Rails: /assets/application-*.js pattern
# Express: X-Powered-By: Express
# Spring Boot: /actuator/health returns {"status":"UP"}
# Next.js: /_next/static/ chunks
```

### 阶段 4 —— 技术栈归类

```bash
# Categorize hosts by CMS for targeted testing
echo "=== WORDPRESS ==="
grep -i "wordpress" tech_detect.txt

echo "=== DRUPAL ==="
grep -i "drupal" tech_detect.txt

echo "=== OTHER CMS ==="
grep -iE "joomla|magento|shopify|wix|squarespace|ghost" tech_detect.txt

echo "=== FRAMEWORKS ==="
grep -iE "laravel|django|rails|express|spring|next\.js|nuxt" tech_detect.txt

echo "=== E-COMMERCE ==="
grep -iE "woocommerce|magento|shopify|prestashop|opencart" tech_detect.txt

echo "=== NO CMS (Static/Custom) ==="
cat alive_subs.txt | httpx -silent -td \
  | grep -v -iE "wordpress|drupal|joomla|magento|laravel|django|rails"
```

### 阶段 5 —— 版本 → CVE 映射

```bash
# Map detected versions to known CVEs
# WordPress: check https://wpscan.com/wordpress-security/vulnerability-database/
# Drupal: check https://www.drupal.org/security
# Magento: check https://magento.com/security/patches

# searchsploit — local ExploitDB search
searchsploit wordpress 6.5
searchsploit drupal 10.2
searchsploit joomla 5.1

# nuclei — automated CVE detection on detected CMS
nuclei -l wordpress_sites.txt -t nuclei-templates/http/cves/2024/
```

## Pitfalls

- **Generator 元标签可能被伪造。** 声称运行 "WordPress 7.0" 的站点实际可能是 6.5。请用 readme.html 或 RSS 源交叉验证。
- **技术检测基于特征签名。** 自定义主题可能剥离或修改这些签名。
- **CDN 缓存可能返回过期的版本信息。** 使用随机查询参数强制绕过缓存。
- **whatweb 在激进扫描时可能触发 WAF 拦截。** 对受保护目标使用 `-a 2`（降低激进度）。
- **无头 CMS（Strapi、Contentful）没有版本文件。** 转而查找 API 端点。

## Verification

1. 至少两种独立方法确认相同的 CMS/版本（元标签 + readme + wp-json）。
2. 存在与版本对应的特定路径（例如 WordPress 的 `/wp-admin/`、Drupal 的 `/user/login`）。
3. 框架专属端点响应正确（例如 Spring Boot 的 `/actuator/health`）。
4. 记录：主机名、CMS、版本、检测方法，以及该版本是否存在已知 CVE。

---

## 相关技能

- **`source-leak-hunt`** —— 一旦识别出 CMS，枚举其专属路径与端点。
- **`wordpress-plugin-hunt`** —— 针对 WordPress 目标的深度插件版本检测。
- **`wp-mass-recon`** —— 批量 WordPress 漏洞扫描。
- **`visual-recon`** —— 通过可视化截图验证确认 CMS 检测结果。
- **`deep-invade`** —— 针对已检测版本运行 nuclei CVE 扫描。
