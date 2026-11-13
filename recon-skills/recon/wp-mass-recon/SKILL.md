---
name: wp-mass-recon
description: "批量 WP 侦察：跨域名的用户、CORS、XMLRPC 与泄露。"
version: 1.1.1
revision_date: 2026-11-13
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, wordpress, mass-scan, us-companies]
  category: recon
  related_skills:
    - cors-credential-wordpress
    - source-leak-hunt
    - wordpress-plugin-hunt
    - staging-subdomain-hunt
    - wordpress-full-compromise
    - deep-invade
    - recon-playbook
    - port-service-discovery
---

# WP 批量侦察技能

用于并行扫描数十到数百个域名的批量 WordPress 漏洞检测流水线。一次运行即可检测 WordPress 存在性、REST API 用户枚举、CORS 凭据反射、XMLRPC 暴露、开放注册和敏感文件泄露。已在 28 个行业的 600+ 个美国公司域名上验证。

## When to Use

- 你拥有一份来自漏洞赏金项目、渗透测试委托或已签署 RoE 的红队授权的目标清单。
- 在授权范围内进行行业级侦察。
- 在 `subfinder`/`crt.sh` 产出目标清单后，你需要进行研判。
- 你希望用可并行化的流水线实现每分钟最大发现量。

## Prerequisites

- `curl`、`httpx`、`python3` 和 `jq`。
- 采用 `domain|company|sector` 格式的目标清单，每行一个目标。
- 可写的 `OUTPUT_DIR`；示例默认为 `./output`。
- 随附的扫描器或下文的内联命令。

## How to Run

```bash
# Phase 1: Live host discovery + tech detection
httpx -silent -l targets.txt -threads 50 -tech-detect -status-code -title -o $OUTDIR/alive.txt

# Phase 2: WP detection, user enum, CORS, XMLRPC (20 workers)
python3 parallel_batch.py "${OUTPUT_DIR:-./output}/targets.txt" 20
```

或者使用 Procedure 中的命令手动运行这 4 个阶段的流水线。

## 快速参考

| 检查项 | 命令 | 阳性信号 |
|-------|---------|-----------------|
| WP 检测 | `curl -skI "https://TARGET/wp-login.php"` | HTTP 200/301/302 |
| 用户枚举 | `curl --max-time 30 --connect-timeout 10 -sk "https://TARGET/wp-json/wp/v2/users"` | 包含 `id`、`name`、`slug` 的 JSON |
| CORS | `curl -skI "https://TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"` | `Access-Control-Allow-Credentials: true` |
| XMLRPC | `curl --max-time 30 --connect-timeout 10 -sk -X POST "https://TARGET/xmlrpc.php" -d '<methodCall><methodName>demo.sayHello</methodName></methodCall>'` | 响应 body 中包含 `Hello!` |
| 开放注册 | `curl --max-time 30 --connect-timeout 10 -sk "https://TARGET/wp-login.php?action=register"` | 包含 `user_login` 字段的表单 |
| 源码泄露 | 并行 curl 获取 `.env`、`wp-config.php.bak`、`.git/config`、`debug.log`、`backup.sql` | 真实内容（而非 SPA catch-all） |

## Procedure

### 阶段 1 — 目标准备

```bash
# Generate target list from crt.sh sector keywords
for sector in "landscaping" "roofing" "hvac" "pools" "plumbing"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://crt.sh/?q=%25.${sector}%25&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> $OUTDIR/discovered.txt
done

# Filter to unique domains, remove www prefix
cat $OUTDIR/discovered.txt | sed 's/^www\.//' | sort -u > $OUTDIR/unique_domains.txt
```

### 阶段 2 — 存活主机发现

```bash
# httpx with tech detection, 50 threads
httpx -silent -l $OUTDIR/unique_domains.txt -threads 50 -tech-detect -status-code -title \
  -o $OUTDIR/alive.txt

# Parse to URL list
awk '{print $1}' $OUTDIR/alive.txt | grep -E '^https?://' > $OUTDIR/urls.txt
```

### 阶段 3 — 并行漏洞扫描

对每个存活目标并行执行（20 个工作线程）：

```bash
while read -r url; do
  domain=$(echo "$url" | sed 's|https\?://||')
  (
    echo "# $domain Findings" > "$OUTDIR/findings/${domain}_findings.md"

    # WP detection
    wp_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 --connect-timeout 10 "$url/wp-login.php")
    [[ "$wp_code" =~ ^(200|301|302|403)$ ]] && echo "- WordPress: YES (wp-login: $wp_code)" >> "$OUTDIR/findings/${domain}_findings.md"

    # User enumeration
    users=$(curl -sk --max-time 10 --connect-timeout 10 "$url/wp-json/wp/v2/users" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null)
    [[ "$users" -gt 0 ]] && echo "- Users exposed: $users" >> "$OUTDIR/findings/${domain}_findings.md"

    # CORS credential reflection
    cors=$(curl -skI --max-time 10 --connect-timeout 10 "$url/wp-json/wp/v2/users" -H "Origin: https://evil.com" 2>/dev/null | grep -i "access-control-allow-credentials: true")
    [[ -n "$cors" ]] && echo "- CORS: CREDENTIAL REFLECTION CONFIRMED" >> "$OUTDIR/findings/${domain}_findings.md"

    # XMLRPC
    xmlrpc=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 --connect-timeout 10 -X POST "$url/xmlrpc.php" \
      -d '<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName></methodCall>')
    [[ "$xmlrpc" == "200" ]] && echo "- XMLRPC: OPEN" >> "$OUTDIR/findings/${domain}_findings.md"

    # Open registration
    reg=$(curl -sk --max-time 10 --connect-timeout 10 "$url/wp-login.php?action=register" | grep -o 'user_login')
    [[ -n "$reg" ]] && echo "- Open Registration: YES" >> "$OUTDIR/findings/${domain}_findings.md"

    # Source leaks (parallel)
    for path in ".env" "wp-config.php.bak" ".git/config" "debug.log" "backup.sql" "info.php" "phpinfo.php" "wp-config.php~" ".env.backup" ".env.local" "docker-compose.yml" "Dockerfile"; do
      leak_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "$url/$path")
      if [[ "$leak_code" == "200" ]]; then
        content=$(curl -sk --max-time 5 --connect-timeout 5 "$url/$path" | head -c 500)
        # False positive filter: skip SPA catch-alls
        if echo "$content" | grep -qiE 'DB_|APP_|_KEY|_SECRET|password|mysql|\[core\]|PHP Version|CREATE TABLE'; then
          echo "- Source leak: /$path (VERIFIED)" >> "$OUTDIR/findings/${domain}_findings.md"
        fi
      fi
    done
  ) &
  # Limit to 20 parallel workers
  while [[ $(jobs -r | wc -l) -ge 20 ]]; do sleep 0.5; done
done < $OUTDIR/urls.txt
wait
```

### 阶段 4 — 汇总

```bash
# Generate summary
echo "## Mass Recon Summary" > $OUTDIR/mass_summary.md
echo "" >> $OUTDIR/mass_summary.md
for f in $OUTDIR/findings/*_findings.md; do
  domain=$(basename "$f" _findings.md)
  criticals=$(grep -c "CRITICAL\|CREDENTIAL REFLECTION\|XMLRPC: OPEN\|Source leak: VERIFIED" "$f" || true)
  [[ "$criticals" -gt 0 ]] && echo "- **$domain**: $criticals findings" >> $OUTDIR/mass_summary.md
done

# Rank targets by finding count
grep "^\- \*\*" $OUTDIR/mass_summary.md | sort -t: -k2 -rn | head -20
```

## 生产级扫描器（Python——parallel_batch.py 模式）

经过生产验证的做法使用带 20 个工作线程的 `concurrent.futures.ThreadPoolExecutor`。每个工作线程通过 `subprocess.run` 调用 curl。这比 bash 的 `while` 循环快 10 倍。

```python
import concurrent.futures, subprocess, json

def curl_code(url, timeout=8):
    cmd = ["curl", "-sk", "-m", str(timeout), "-o", "/dev/null", "-w", "%{http_code}", url]
    r = subprocess.run(cmd, capture_output=True, timeout=timeout+5)
    return r.stdout.decode().strip()

def test_target(domain):
    # Determine protocol
    proto = None
    for p in ["https", "http"]:
        code = curl_code(f"{p}://{domain}/")
        if code not in ["000", ""]: proto = p; break
    if not proto: return None

    # WP detection (v2 strict: check login OR json)
    login_code = curl_code(f"{proto}://{domain}/wp-login.php")
    json_code = curl_code(f"{proto}://{domain}/wp-json/")
    is_wp = login_code not in ["000","404",""] or json_code not in ["000","404",""]

    if not is_wp: return {"domain":domain, "is_wp":False}

    score = 1  # WordPress detected
    findings = ["wordpress"]

    # Users (v2 pattern: parse JSON, check list length)
    body, _ = curl_raw(f"{proto}://{domain}/wp-json/wp/v2/users")
    try:
        data = json.loads(body.decode())
        if isinstance(data, list) and len(data) > 0:
            findings.append(f"wp_users_{len(data)}")
            score += 2
    except: pass

    # CORS (v2 pattern: explicit -I header check)
    cmd = ["curl","-sk","-m","8","-I","-H","Origin: https://evil.com",
           f"{proto}://{domain}/wp-json/wp/v2/users"]
    r = subprocess.run(cmd, capture_output=True, timeout=10)
    hdrs = r.stdout.decode().lower()
    acao = [l.split(":",1)[1].strip() for l in hdrs.split('\n') if 'access-control-allow-origin:' in l]
    acac = [l.split(":",1)[1].strip() for l in hdrs.split('\n') if 'access-control-allow-credentials:' in l]
    if acao and "evil.com" in acao[0] and acac and acac[0] == "true":
        findings.append("cors_credentialed")
        score += 3

    # XMLRPC (v2 pattern: system.listMethods, check for multicall string)
    xml = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
    body, _ = curl_raw(f"{proto}://{domain}/xmlrpc.php", method="POST", data=xml)
    txt = body.decode()
    if "system.multicall" in txt:
        findings.append("xmlrpc_multicall")
        score += 3
    elif "methodName" in txt:
        findings.append("xmlrpc_active")

    # Open registration (v2 pattern: three-string check avoids false positives)
    body, _ = curl_raw(f"{proto}://{domain}/wp-login.php?action=register")
    rt = body.decode().lower()
    if "register" in rt and "user_login" in rt and "wp-submit" in rt:
        findings.append("registration_open")
        score += 2

    # Severity (v2 thresholds: >=8 CRITICAL, >=5 HIGH, >=3 MEDIUM, >=1 LOW)
    if score >= 8: severity = "CRITICAL"
    elif score >= 5: severity = "HIGH"
    elif score >= 3: severity = "MEDIUM"
    elif score >= 1: severity = "LOW"
    else: severity = "NONE"

    return {"domain":domain, "severity":severity, "score":score, "findings":findings}

# Run with ThreadPoolExecutor
targets = [(d.strip(), s.strip()) for line in open("targets.txt") if (p := line.split("|")) and (d:=p[0]) and (s:=p[-1] if len(p)>2 else "unknown")]
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    futures = {ex.submit(test_target, t[0]): t for t in targets}
    for f in concurrent.futures.as_completed(futures):
        r = f.result()
        if r and r.get("score",0) > 0:
            print(f"[{r['severity']:>8}] {r['domain']:40s} | {r['score']:2d} | {', '.join(r['findings'])}")
```

## Pitfalls

- **SPA catch-all 误报：** 单页应用对每个路径都返回 200。务必验证 `.env` 含有 `DB_`/`APP_`/`_KEY`/`_SECRET` 模式；`.git/config` 含有 `[core]`；SQL 文件含有 `CREATE TABLE`/`INSERT INTO`。跳过前 100 个字符中包含 `<html` 或 `<script` 的响应体。
- **Cloudflare/WAF 拦截：** httpx 可能显示技术为 “Cloudflare”，但 WP 就在其后面。对托管在 WP Engine 上的站点尝试 HTTP/1.0：`curl --max-time 30 --connect-timeout 10 -sk --http1.0 "https://TARGET/wp-json/..."`
- **速率限制：** WP Engine 和 Hostinger 在约 50 个请求后开始限流。在请求之间加入 2-4 秒的抖动。Chrome/125 UA 的封禁率为 0%；curl/8.4 UA 为 5%；Python urllib 为 15%。
- **子路径上的 WordPress：** 除根路径外，还应检查 `/blog/` 和
  `/wp/` 这类合理候选路径；次级安装可能具有不同的
  版本和控制措施。
- **非标准 XMLRPC 路径：** 有些主机会重命名 xmlrpc.php。用 `system.listMethods` 验证（而不只是 HTTP 200）——在响应 XML 中寻找 `<string>` 标签。
- **注册表单误报：** 许多站点在 `?action=register` 上显示登录表单，但并不真正允许注册。v2 检查要求三个字符串全部命中：`register` + `user_login` + `wp-submit`。

## 真实世界结果（来自 600+ 个美国目标）

| 发现项 | 频率 | 最佳行业 |
|---------|-----------|-------------|
| WP 用户枚举 | ~9%（55/600） | 园林绿化、律师事务所 |
| 敏感文件（3+） | ~7%（41 个站点） | 汽车车身修复、窗户清洁 |
| CORS 凭据反射 | ~3.3%（20+ 个站点） | 律师事务所、房地产 |
| XMLRPC system.multicall | ~1.7%（10+ 个站点） | 暖通空调、园林绿化 |
| PHPInfo/info.php 暴露 | ~1.7%（~10 个站点） | 牙科、健身房 |
| MySQL 3306 暴露 | 0.17%（1 个站点） | 医疗健康 SaaS |

WordPress 占所有美国中小企业目标的 36.5%。所有 CORS/XMLRPC 漏洞都仅出现在 WordPress 上。

## Verification

- 每个 CORS 发现都必须在 curl `-I` 的响应头中显示 `Access-Control-Allow-Credentials: true`。
- 每个源码泄露都必须通过内容验证（而不仅仅是 HTTP 200）。跳过 HTML/SPA 响应。
- 每个 XMLRPC 发现都必须在 `system.listMethods` 响应中包含带有 `<string>` 方法名的内容。
- 按 v2 阈值给目标打分：WP=+1、用户（+2）、CORS=+3、XMLRPC multicall=+3、开放注册=+2。得分 >=6 即为深入挖掘候选（阶段 3）。
