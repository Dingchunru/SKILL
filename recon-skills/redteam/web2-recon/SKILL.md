---
name: web2-recon
description: Web2 侦察流水线 — 子域名枚举（subfinder、Chaos API、assetfinder）、存活主机发现（dnsx、httpx）、URL 爬取（katana、waybackurls、gau）、目录模糊测试（ffuf）、JS 分析（LinkFinder、SecretFinder）、持续监控（新子域名告警、JS 变更检测、GitHub 提交监控）。在开始对任何 web2 目标做侦察时使用，或被问及资产发现、子域名枚举、攻击面映射时使用。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux, macos]
metadata:
  tags: [web2, recon, redteam]
  category: redteam
---

# WEB2 RECON 侦察流水线

从零开始的完整资产发现，产出可直接用于狩猎的优先级 URL 列表。

---

## When to Use

- 开始对任何 web2 目标做侦察，或被问及资产发现、子域名枚举时。
- 攻击面映射。

## Prerequisites

- 针对目标取得明确授权、目标边界与速率限制。
- 工具：`censys`、`chaos`、`curl`、`dalfox`、`dig`、`dnsx`、`ffuf`、`gau`、`gf`、`gh`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对任何会改变状态的步骤（写入、上传、凭据尝试），在执行命令前立即取得明确确认。

## How to Run

```bash
# 1. Set your Chaos API key (get free key at chaos.projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"
# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 2. Update nuclei templates (run weekly)
nuclei -update-templates

# 3. Configure subfinder with API keys for more sources
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/config.yaml << 'EOF'
# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
EOF
```

## Procedure

以下各阶段即为操作流程。保持每个探测请求有界（`--max-time`），把证据记录到 `OUTPUT_DIR` 下，并在 Pitfalls 中列出的停止条件处停止。

## 环境准备（一次性）

```bash
# 1. Set your Chaos API key (get free key at chaos.projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"
# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 2. Update nuclei templates (run weekly)
nuclei -update-templates

# 3. Configure subfinder with API keys for more sources
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/config.yaml << 'EOF'
# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
censys_apiid: YOUR_CENSYS_ID
censys_secret: YOUR_CENSYS_SECRET
shodan: [YOUR_SHODAN_KEY]
EOF

# 4. Verify alltools installed
which subfinder httpx dnsx nuclei katana waybackurls gau dalfox ffuf anew gf interactsh-client
```

---

## 5 分钟法则

> 如果目标在 5 分钟侦察后仍无任何有价值的线索，就换下一个。不要在没有价值的攻击面上耗费数小时。

**5 分钟否决信号：**
- 所有子域名都返回 403 或静态营销页面
- URL 中看不到任何 API 端点
- 没有包含有价值端点路径的 JavaScript bundle
- nuclei 返回 0 个 medium/high 发现
- 没有表单、没有认证、没有用户数据

---

## 标准侦察流水线

### 狩猎前：始终先执行

```bash
TARGET="target.com"

# Step 0: Passive — crt.sh certificate transparency (no API key needed)
curl --max-time 30 --connect-timeout 10 -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > /tmp/subs.txt
echo "[+] crt.sh: $(wc -l < /tmp/subs.txt) subdomains"

# Step 1: Chaos API (ProjectDiscovery — most comprehensive source)
curl --max-time 30 --connect-timeout 10 -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/subs.txt

echo "[+] Chaos returned $(wc -l < /tmp/subs.txt) subdomains"

# Step 2: subfinder (passive multi-source)
subfinder -d $TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only $TARGET | anew /tmp/subs.txt

echo "[+] Total subdomains after all sources: $(wc -l < /tmp/subs.txt)"

# Step 3: DNS resolution + live host check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

echo "[+] Live hosts: $(wc -l < /tmp/live.txt)"

# Step 4: URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt

# Step 5: Historical URLs
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

echo "[+] Total URLs: $(wc -l < /tmp/urls.txt)"

# Step 6: Nuclei scan
nuclei -l /tmp/live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt
```

### 输出到整理好的目录

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# All outputs go here:
/tmp/subs.txt         → $RECON_DIR/subdomains.txt
/tmp/live.txt         → $RECON_DIR/live-hosts.txt
/tmp/urls.txt         → $RECON_DIR/urls.txt
/tmp/nuclei.txt       → $RECON_DIR/nuclei.txt
```

---

## 攻击面分诊

### 在 URL 列表中寻找值得关注的目标

```bash
# Parameters worth testing
cat /tmp/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/interesting-params.txt

# API endpoints
cat /tmp/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" | tee /tmp/api-endpoints.txt

# File upload endpoints
cat /tmp/urls.txt | grep -E "upload|file|attachment|document|image|avatar|photo|media" | tee /tmp/uploads.txt

# Admin/internal paths
cat /tmp/urls.txt | grep -E "/admin|/internal|/debug|/test|/staging|/dev|/management|/console" | tee /tmp/admin-paths.txt

# Authentication endpoints
cat /tmp/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/oidc|/callback|/token" | tee /tmp/auth-paths.txt
```

### gf 模式（快速分类）

```bash
# Install gf patterns: https://github.com/tomnomnom/gf
cat /tmp/urls.txt | gf xss | tee /tmp/xss-candidates.txt
cat /tmp/urls.txt | gf ssrf | tee /tmp/ssrf-candidates.txt
cat /tmp/urls.txt | gf idor | tee /tmp/idor-candidates.txt
cat /tmp/urls.txt | gf sqli | tee /tmp/sqli-candidates.txt
cat /tmp/urls.txt | gf redirect | tee /tmp/redirect-candidates.txt
cat /tmp/urls.txt | gf lfi | tee /tmp/lfi-candidates.txt
cat /tmp/urls.txt | gf rce | tee /tmp/rce-candidates.txt
```

---

## JS 分析

### SecretFinder（JS bundle 中的 API 密钥与令牌）

```bash
# Activate venv
source ~/tools/SecretFinder/.venv/bin/activate

# Scan a single JS file
python3 ~/tools/SecretFinder/SecretFinder.py -i "https://target.com/static/js/main.js" -o cli

# Scan all JS URLs found in recon
cat /tmp/urls.txt | grep "\.js$" | head -50 | while read url; do
  echo "=== $url ==="
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done

deactivate
```

### LinkFinder（隐藏在 JS 中的端点）

```bash
source ~/tools/LinkFinder/.venv/bin/activate

# Single JS file
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com/app.js" -o cli

# All pages (crawls JS from HTML)
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com" -d -o cli

deactivate
```

---

## 目录爆破

### ffuf — 标准模糊测试

```bash
# Directory discovery on a live host
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -mc 200,201,204,301,302,307,401,403 \
     -ac \
     -t 40 \
     -o /tmp/ffuf-dirs.json

# API endpoint discovery
ffuf -u "https://target.com/api/FUZZ" \
     -w ~/wordlists/api-endpoints.txt \
     -mc 200,201,204,301,302 \
     -ac \
     -t 20

# IDOR fuzzing with authenticated request
# Create req.txt with Authorization: Bearer TOKEN
ffuf -request /tmp/req.txt \
     -request-proto https \
     -w <(seq 1 10000) \
     -fc 404 \
     -ac \
     -t 10
```

---

## 目标评分 — GO / NO-GO

在投入时间之前先评分。评分 < 4 则跳过。

| 评分项 | 分值 |
|---|---|
| 最高赏金 >= $5K | +2 |
| 用户基数大（>100K）或涉及资金 | +2 |
| 项目启动 < 60 天 | +2 |
| 复杂功能：API、OAuth、文件上传、GraphQL | +1 |
| 近期代码/功能变更（GitHub、变更日志） | +1 |
| 私有项目（竞争更少） | +1 |
| 你熟悉的技术栈 | +1 |
| 有源代码可获取 | +1 |
| 有既往公开报告可研究 | +1 |

**< 4：** 跳过
**4-5：** 仅在别无更好选择时做
**6-8：** 良好 — 投入 1-3 天
**>= 9：** 优秀 — 最多投入 1 周

### 深入前的硬性否决信号

1. 最高赏金 < $500 → 不值得投入时间
2. 近期报告全是 N/A 或重复 → 已被狩猎者榨干
3. 范围只有一个静态营销页面 → 没有攻击面
4. 公司 < 5 名员工且无收入 → 不会付款
5. 规则中明确排除你计划测试的漏洞类别

---

## 技术栈识别（2 分钟）

```bash
# Response headers reveal backend
curl --max-time 30 --connect-timeout 10 -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"

# Common signals:
# Server: nginx + X-Powered-By: PHP/7.4 → PHP backend
# Server: gunicorn OR X-Powered-By: Express → Python/Node.js
# X-Powered-By: ASP.NET → .NET
# Server: Apache Tomcat → Java
# X-Runtime: Ruby → Ruby on Rails

# Framework from JS bundle paths:
# /_next/static/ → Next.js
# /static/js/main.chunk.js → CRA (React)
# /packs/ → Ruby on Rails + Webpacker
# /__nuxt/ → Nuxt.js (Vue)
```

### 技术栈 → 主要漏洞类别映射

| 技术栈 | 优先狩猎 | 次选狩猎 |
|---|---|---|
| Ruby on Rails | 批量赋值（Mass assignment） | IDOR（`:id` 路由） |
| Django | IDOR（ModelViewSet，无对象权限） | SSTI（mark_safe） |
| Flask | SSTI（render_template_string） | SSRF（requests 库） |
| Laravel | 批量赋值（`$fillable`） | IDOR（Eloquent，无归属校验） |
| Express (Node.js) | 原型链污染（Prototype pollution） | 路径穿越 |
| Spring Boot | Actuator 端点（/actuator/env） | SSTI（Thymeleaf） |
| ASP.NET | ViewState 反序列化 | 开放重定向（ReturnUrl） |
| Next.js | 经 Server Actions 的 SSRF | 经 redirect() 的开放重定向 |
| GraphQL | 通过 Introspection → 绕过 mutation 上的鉴权 | 通过 node(id:) 的 IDOR |
| WordPress | 插件 SQLi | REST API 鉴权绕过 | CORS 凭据反射 |

---

## 持续监控配置

每个目标配置一次。能让你比其他狩猎者更早收到告警。

### 新子域名告警（每日 cron）

```bash
#!/bin/bash
TARGET="target.com"
KNOWN="/tmp/$TARGET-subs-known.txt"

subfinder -d $TARGET -silent > /tmp/$TARGET-subs-fresh.txt
curl --max-time 30 --connect-timeout 10 -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/$TARGET-subs-fresh.txt

# Diff against known
NEW=$(comm -23 <(sort /tmp/$TARGET-subs-fresh.txt) <(sort $KNOWN 2>/dev/null))

if [ -n "$NEW" ]; then
  echo "NEW SUBDOMAINS: $NEW"
  echo "$NEW" >> $KNOWN
fi

# Schedule: crontab -e → 0 8 * * * /bin/bash ~/monitors/subs-watch.sh
```

### GitHub 提交监控

```bash
#!/bin/bash
REPO="TargetOrg/target-app"
LAST_SHA="/tmp/$REPO-last-sha.txt"

CURRENT=$(curl --max-time 30 --connect-timeout 10 -s "https://api.github.com/repos/$REPO/commits?per_page=1" | jq -r '.[0].sha')
KNOWN=$(cat $LAST_SHA 2>/dev/null)

if [ "$CURRENT" != "$KNOWN" ]; then
  echo "New commit on $REPO: $CURRENT"
  echo $CURRENT > $LAST_SHA
  # Get changed files
  curl --max-time 30 --connect-timeout 10 -s "https://api.github.com/repos/$REPO/commits/$CURRENT" \
    | jq -r '.files[].filename' | grep -E "auth|middleware|route|permission|role|admin"
fi

# Schedule: */30 * * * * /bin/bash ~/monitors/github-watch.sh
```

---

## 端口扫描（常被跳过 — 不要跳过）

```bash
# naabu - fast port scanner from ProjectDiscovery
# nmap often fails with "nse_main.lua not found" on minimal containers — naabu works.
# Finds non-standard ports: 8080, 8443, 3000, 8888, 9000, etc.
cat /tmp/live.txt | awk '{print $1}' | naabu -port 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379 -silent | tee /tmp/open-ports.txt

# Why this matters: admin panels, debug services, internal APIs often run on alt ports
# Example wins: :8080/actuator/env (Spring Boot), :9200/_cat/indices (Elasticsearch), :6379 (Redis)
```

### 原始端口连通性测试（naabu 不可用时）

```bash
# Quick single-port check via bash /dev/tcp — works anywhere bash is available
for port in 22 80 443 3306 5432 6379 8080 8081 8443 27017; do
  timeout 3 bash -c "echo >/dev/tcp/$TARGET/$port" 2>&1 && echo "PORT $port OPEN" || echo "PORT $port CLOSED/FILTERED"
done
```

## JS BUNDLE 中的密钥扫描

```bash
# trufflehog — high-signal secret detection with entropy analysis
# Scans JS files and git repos
pip install trufflehog3 2>/dev/null || true
trufflehog filesystem --only-verified recon/$TARGET/ 2>/dev/null

# SecretFinder — manual JS bundle scan (already intools/)
source ~/tools/SecretFinder/.venv/bin/activate
cat /tmp/urls.txt | grep "\\.js$" | head -100 | while read url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done
deactivate

# Quick grep for common patterns in downloaded JS
wget -q -r -l 1 -A "*.js" -P /tmp/js-files/ "https://$TARGET" 2>/dev/null
grep -rn "api_key\\|apiKey\\|client_secret\\|access_token\\|private_key\\|AWS_SECRET\\|AKIA" /tmp/js-files/ 2>/dev/null
```

### JS bundle API 密钥提取（兼容 BusyBox 的回退方案）

BusyBox 的 grep 不支持 `-P`（PCRE/Perl 正则）。在 Alpine 容器中对 JS bundle 做正则匹配时改用 Python3：

```bash
# Extract Firebase API keys from JS bundle
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/static/js/main.*.js" 2>/dev/null | python3 -c "
import sys, re
content = sys.stdin.read()
for k in re.findall(r'AIza[0-9A-Za-z_-]{35}', content):
    print(f'Firebase API Key: {k}')
for m in re.findall(r'(?:apiUrl|apiKey|authDomain|databaseURL|projectId)[\"\']?\s*[:=]\s*[\"]([^\"\']+)[\"]', content):
    print(f'Config: {m}')
for u in re.findall(r'https?://[a-zA-Z0-9._-]+\.(?:firebaseio|firestore|googleapis|herokuapp)\.com[^\"\\s,]*', content):
    print(f'URL: {u}')
for s in re.findall(r'(?:secret|jwt[_-]?secret|token)[\"\']?\s*[:=]\s*[\"]([a-zA-Z0-9_\-]{16,})[\"]', content):
    print(f'Potential secret: {s}')
" 2>/dev/null

# For React SPAs with chunked bundles — find the main bundle first
main_js=$(curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET:8080/" 2>/dev/null | grep -Eo 'src="([^"]+\.js)"' | sed 's/src="//;s/"//' | head -1)
[ -n "$main_js" ] && curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET:8080/$main_js" | python3 -c "
import sys, re
content = sys.stdin.read()
for m in re.findall(r'https?://[^\"\\s,;\\)]+', content):
    if '://' in m and not 'fonts.' in m:
        print(f'URL: {m}')
for m in re.findall(r'apiUrl[\"\\']?\s*[:=]\s*[\"\\']([^\"\\']+)[\"\\']', content):
    print(f'apiUrl: {m}')
" 2>/dev/null
```

该技术可以暴露运行在非标准端口上的 API 后端，而这些端口不会出现在导航链接和 DNS 命名约定中。

## 针对目标的 GITHUB DORKING

```bash
# Search GitHub for hardcoded secrets before hunting the app
TARGET_ORG="TargetOrgName"  # Check their GitHub org

# Useful dorks (search on github.com):
# org:TARGET_ORG password
# org:TARGET_ORG api_key
# org:TARGET_ORG "Authorization: Bearer"
# org:TARGET_ORG .env
# org:TARGET_ORG "BEGIN RSA PRIVATE KEY"

# CLI with gh (GitHub CLI):
gh search code "api_key" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | jq '.'
gh search code "password" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | head -20

# GitDorker (if installed):
python3 ~/tools/GitDorker/GitDorker.py -t GITHUB_TOKEN -d ~/tools/GitDorker/Dorks/alldorksv3 -q "$TARGET" -org
```

### 30 分钟侦察流程

## 双轨并行侦察（在多目标批量测试中已被证明有效）

当需要在多个行业中测试 15-20 个以上目标时，采用**双轨方法**：

**轨道 1 — 手动快速探测（在轨道 2 运行时由你来做）**
1. 用 `curl --max-time 10 --connect-timeout 5 -sI` 探测每个域名的存活状态与服务器头（每 5 个域名约 30 秒）
2. 立即检查有价值的信号：WordPress 链接头、CORS 源、可疑 Cookie
3. 对有价值的域名趁记忆新鲜时立即运行 subfinder
4. 立即追查存活的子域名（app.、dashboard.、staging. 等）

**轨道 2 — 自动化扫描器（后台）**
- 启动一个带有限速延迟和五个并行任务的 Python 扫描器。
- 扫描器负责系统性工作：WP 检测、CORS 测试、敏感文件检查、每个域名的子域名枚举
- 定期查看进度；等它完成时你已掌握高价值发现

**为什么有效：**
- 手动探测能在前 5 分钟内发现高价值目标（CRITICAL CORS、WP 用户枚举、暴露的 staging）
- 自动化扫描器校验其余部分，而不会把你的注意力浪费在死目标上
- 手动发现的子域名可以在扫描器仍在运行时立即探测
- 在第 5 波（20 个目标、4 个行业）中，该方法在 15 分钟的手动工作内发现了 3 个 CRITICAL CORS + 11 个暴露的 WP 用户 + 95 个子域名

### 第 0-5 分钟：阅读项目页面

```
Note:
- ALL in-scope assets (every domain listed)
- Out-of-scope list (read carefully — common trap)
- Safe harbor statement
- Impact types accepted (some exclude "low")
- Average bounty amount (signals program generosity)
```

### 第 5-15 分钟：资产发现

运行上面的标准流水线。重点关注 live.txt 的输出。

### 第 15-25 分钟：攻击面映射

运行 gf 模式和上面的 interesting-params grep。

### 第 25-30 分钟：手动探索

打开 Burp Suite。开启代理浏览应用：
1. 注册一个账号
2. 执行主要用户操作（创建/读取/更新/删除资源）
3. 记录 Burp 历史中的所有 API 调用
4. 寻找不在你 URL 列表中的端点

### 30 分钟后：排定优先级

```
Priority 1: API endpoints with ID parameters → IDOR candidates
Priority 2: File upload features → XSS/RCE candidates
Priority 3: OAuth/SSO flows → auth bypass candidates
Priority 4: Search/filter with user input → SQLi/SSRF/SSTI candidates
Priority 5: Admin/debug endpoints → auth bypass candidates
```

---

## 工具链回退（当 `dnsx` / `httpx` 崩溃时）

ProjectDiscovery 的 Go 二进制文件（`dnsx`、`httpx`、`naabu`）在 macOS arm64 上偶尔会因 cgo 与系统解析器的交互而 `SIGSEGV`。无论采用何种安装方式，崩溃特征都完全相同 — `brew install` 和 `go install github.com/projectdiscovery/<tool>@latest` 产出的二进制都会在同一地址发生段错误。在真实项目中依赖它们之前，先做一次快速验证：

```bash
dnsx -version   # if SIGSEGV: use the dig fallback below
httpx -version  # if SIGSEGV: use the curl fallback below
```

### `dnsx`（首选）或 `dig` 回退

```bash
# Preferred: dnsx (concurrent, 50-100x faster at scale)
dnsx -silent -l subs.txt -a -resp-only -o resolved.txt

# Fallback: dig (sequential, only if dnsx binary unavailable)
while read s; do
  ips=$(dig +short +tries=1 +time=3 "$s" \
    | grep -E '^[0-9.]+$' \
    | paste -sd, -)
  [ -n "$ips" ] && echo "$s|$ips"
done < subs.txt
```

### `httpx` → `curl` 回退

```bash
# Replaces: httpx -l subs.txt -silent -status-code -title -tech-detect
while read s; do
  resp=$(curl --max-time 30 --connect-timeout 10 -s -L -m 5 -o /tmp/body \
    -w "%{http_code}|%{url_effective}|%{header_server}" \
    "https://$s")
  code=$(echo "$resp" | cut -d'|' -f1)
  if [ "$code" != "000" ]; then
    title=$(grep -oE '<title[^>]*>[^<]*</title>' /tmp/body | head -1 | sed 's/<[^>]*>//g')
    echo "$s|$resp|$title"
  fi
done < subs.txt
```

**权衡：** 串行 vs. 并发。该回退方案在 14 秒内处理约 24 个子域名；同样的工作量在 `httpx` 上以默认 50 线程只需 2-3 秒完成。对 VDP 规模的侦察（< 100 个子域名）回退方案足够。对大规模侦察（1000+）先修复工具链。

（在技能开发过程中已针对 HackerOne 自身的 VDP 验证；验证日志为内部资料，不随仓库分发。）

---

## API 规范 / Swagger / OpenAPI 发现（2024-2026 攻击面）

API 规范端点是任何现代 .NET / Node / Python / Java 后端上杠杆率最高的侦察目标。规范文件会披露所有端点、HTTP 方法、参数名 + 类型 + 格式、模型、校验规则 — 一份 JSON 形式的完整攻击地图。默认路由在生产环境中常被遗留为启用状态。**把这份字典加入目录模糊测试阶段**（在标准的 `common.txt` 扫描之后）。

### 默认发现路径字典（粘贴到 `swagger-paths.txt`）

```
# NSwag / Swashbuckle (ASP.NET Core)
/swagger
/swagger/
/swagger/index.html
/swagger/ui/index.html
/swagger/v1/swagger.json
/swagger/v2/swagger.json
/swagger/v3/swagger.json
/swagger/docs/v1
/swagger/docs/v2
/swagger-ui
/swagger-ui/
/swagger-ui.html
/swagger-resources
/swagger-resources/configuration/ui
/nswag
/nswag/index.html
/api/swagger
/api/swagger.json
/api/swagger/v1/swagger.json
/api/openapi
/api/openapi.json
/api/v1/swagger.json
/api/v2/swagger.json
/api-docs
/api-docs/swagger.json

# OpenAPI generic
/openapi
/openapi.json
/openapi.yaml
/openapi.yml
/openapi/v1.json
/openapi/v2.json
/openapi/v3.json
/.well-known/openapi.json

# Java / Spring (Springfox / springdoc)
/v2/api-docs
/v3/api-docs
/v3/api-docs.yaml
/v3/api-docs/swagger-config
/swagger-ui/index.html

# Python (FastAPI / Flask-RESTPlus / Connexion / DRF)
/docs
/docs/
/redoc
/redoc/
/openapi.json
/swagger.json
/swagger/?format=openapi
/swagger.yaml

# Express / Node / Hapi
/api-docs
/api-docs.json
/swagger.json
/swagger-stats
/graphql-docs

# GraphQL adjacent (often co-located)
/graphql
/graphiql
/playground
/altair
/voyager
/graphql/console
/graphql-explorer

# ReDoc / RapiDoc / Stoplight / alt UIs
/redoc
/redoc.html
/redoc-ui.html
/rapidoc
/rapidoc.html
/stoplight
/elements

# Misc / dev-leftover
/actuator
/actuator/openapi
/actuator/mappings
/q/openapi
/q/swagger-ui
/docs/swagger.json
/api/v1/docs
/api/v2/docs
/internal/swagger
/admin/swagger
/management/swagger
```

### 与标准流水线集成

```bash
# After live-hosts.txt is built (Phase 1 / 2), run:
ffuf -w swagger-paths.txt -u "https://FUZZ.target.com" -mc 200,302 -fs 0 -t 50 -o swagger-hits.json
# Or with httpx for content-aware filtering:
httpx -l live-hosts.txt -path swagger-paths.txt -mc 200 -mr "swagger|openapi" -json | tee swagger-hits.jsonl
# For every hit:
jq '.paths | keys' swagger.json > endpoints.txt
jq '.components.schemas' swagger.json > schemas.json   # mass-assignment field candidates
```

### 为什么这对从侦察到狩猎的交接很重要

- **规范 → 批量 IDOR/BOLA** — `jq '.paths | keys' swagger.json` 成为逐用户 `Autorize`/`ffuf` 测试的输入列表。
- **规范 → 批量赋值 payload 构造** — `components.schemas.UserUpdateDto` 会列出 `isAdmin`、`emailVerified`、`tenantId`、`role`。
- **规范 → 隐藏端点发现** — `/internal/*`、`/debug/*`、`/v0/*`、`/legacy/*` 路由被文档化却从未做鉴权门控。
- **规范 → 注入类种子** — 每个参数的类型 + 格式 + 枚举 + 最大长度意味着 payload 在抵达汇聚点前就能通过校验。对 ASP.NET Core 尤其有价值，因为模型绑定器会在任何控制器逻辑之前拒绝畸形输入。

### 工具

- `kiterunner` — 原生解析 OpenAPI 规范，针对 API 生成请求。
- `sj`（Swagger Jacker）— 专为 Swagger 规范利用而构建。
- `apidetector`（brinhosa）— Swagger-UI 批量扫描器。
- `XSSwagger`（vavkamil）— 检测存在漏洞的 Swagger UI 版本（CVE-2018-25031 系列）。
- `nuclei -t http/exposures/apis/` — 针对默认规范路径的内置模板。

### 反模式提醒

`/swagger` 返回 404/403 并不意味着没有暴露规范。许多 .NET 项目把规范挂在 `/api/swagger/v1/swagger.json` 而不是 `/swagger`。始终测试完整路径列表，而不只是根路径。

完整的攻击链分析见 `hunt-api-misconfig` → `NSwag / Swagger / OpenAPI Spec Exposure`。

---

## Pitfalls
- **只做侦察不做分诊** — 收集 10,000 个子域名却不排定哪些该测的优先级，那只是数据收集，不是侦察。
- **只探测 HTTP 不探测 HTTPS** — 许多服务仅在 HTTPS 上响应。两个协议都要测。
- **只收集截图不做分析** — 自动化截图只有在你逐张查看时才有用。独特的登录页、错误信息、CMS 指纹才是价值所在。
- **只扫端口不识别服务** — 开放的 8443 端口可能是任何东西。抓取 banner 并识别实际服务。
- **过期的侦察数据** — 超过 30 天的子域名数据可靠性不断下降。每次项目都重新做侦察。

---

## Verification

1. **核心侦察工具** — 确认关键工具已安装：
   ```bash
   which subfinder httpx nuclei katana 2>/dev/null | wc -l | xargs -I{} echo "{} of 4 core tools found"
   ```
2. **HTTP 探测** — 确认 httpx 可用：
   ```bash
   echo "example.com" | httpx -silent -status-code 2>/dev/null && echo "PASS: httpx operational" || echo "NOTE: httpx not installed"
   ```
所有测试用于验证 web2 侦察的就绪状态。

---

## 相关技能与链路

- **`offensive-osint`** — 当侦察需要超出基础流水线的具体探测 / 字典 / 正则时。工作流原语：本技能产出 URL 集合；`offensive-osint` 提供你施加于该 URL 集合的密钥正则、GraphQL/Swagger 路径与身份体系探测。
- **`osint-methodology`** — 当你需要为所发现的内容给出严重性评分标准时。工作流原语：侦察输出 `subdomains.txt` / `live-hosts.txt` / `urls.txt` 后，对照 `osint-methodology` 的发现评分标准为每个资产打分，决定哪些构成 finding、哪些只留在资产图中。
- **`hunt-subdomain`** — 当侦察暴露出陈旧 CNAME / 悬空 DNS 时。工作流原语：`subdomains.txt` 中任何 CNAME 指向 S3 / GitHub Pages / Heroku / Shopify / Azure 的子域名都应自动路由到 `hunt-subdomain` 做接管验证。
- **`security-arsenal`** — 当 URL 集合已被 `gf` 分类、可进行主动测试时。工作流原语：`gf xss/ssrf/sqli/idor` 的输出名称成为针对 `security-arsenal` payload 库的 payload 类别查询。
- **`bb-methodology`** — 当侦察完成、阶段 1 转入阶段 2（Mapping）时。工作流原语：把存活主机 + URL 集合交回 `bb-methodology` 的阶段 2 做端点映射，并在阶段 3 做漏洞发现路由。

---

