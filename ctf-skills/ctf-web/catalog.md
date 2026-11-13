# ctf-web 文档索引

> 本文件由 `scripts/build_skill_catalog.py` 生成，请勿手工编辑。
>
> 用法：按「用途」定位候选文件，只加载命中的那一篇；同名 `catalog.json`
> 提供相同信息的机器可读版本（含路径、摘要、标签、章节、字节数）。

## 技术参考

| 文档 | 用途 | 关键章节 |
|---|---|---|
| [auth-and-access-2.md](auth-and-access-2.md) | 第 2 部分（2018 年代）：std::unordered_set 桶碰撞鉴权绕过、nodeprep.prepare Unicode 同形字符用户名碰撞、SRP A=0/A=N 鉴权绕过、ArangoDB AQL MERGE 提权 | std::unordered_set 哈希桶碰撞认证绕过（Hackover 2018）、nodeprep.prepare 同形用户名碰撞（HCTF 2018）、SRP A=0、A=N 认证绕过（OTW Advent 2018）、ArangoDB AQL MERGE 注入提权（P.W.N. CTF 2018） |
| [auth-and-access.md](auth-and-access.md) | 认证/授权绕过、隐藏端点、IDOR、重定向链、子域接管、AI 聊天机器人越狱 | 现代认证与访问控制模式（2025/2026）、从公开数据推断密码/密钥、登录表单爆破、弱签名/弱哈希校验绕过、客户端访问门禁绕过 |
| [auth-infra.md](auth-infra.md) | OAuth/OIDC、SAML、CORS、CI/CD 密钥、IdP 滥用、登录投毒 | 现代 OAuth/OIDC 与基础设施补充（2025/2026）、OAuth/OIDC 利用、CORS 配置错误、Git 历史凭据泄露（Barrier HTB）、CI/CD 变量凭据窃取（Barrier HTB） |
| [auth-jwt.md](auth-jwt.md) | JWT/JWE 篡改、弱密钥、头注入、密钥混淆、重放 | 现代 JWT/JWE 补充（2025/2026）、算法 None、算法混淆（RS256 转 HS256）、弱密钥爆破、不校验签名（Crypto-Cat） |
| [client-side-advanced.md](client-side-advanced.md) | CSP 绕过、Unicode 技巧、XSSI、CSS 窃取、浏览器规范化怪癖、postMessage null origin 绕过 | 现代浏览器信任边界补充（2025/2026）、Unicode 大小写折叠 XSS 绕过（UNbreakable 2026）、CSS 字体字形宽度 + 容器查询外带（UNbreakable 2026）、Hyperscript CDN CSP 绕过（UNbreakable 2026）、通过 postMessage 的 PBKDF2 前缀时序 oracle（UNbreakable 2026） |
| [client-side.md](client-side.md) | XSS、CSRF、缓存投毒、DOM 技巧、admin bot 滥用、请求走私、付费墙绕过 | 现代浏览器与客户端补充（2025/2026）、XSS Payload、借助可信后端路由绕过 DOMPurify、JavaScript String Replace 利用、客户端路径穿越（CSPT） |
| [cves.md](cves.md) | 可通过 banner、响应头、依赖泄露或版本文本匹配的 CVE 技术 | CVE-2025-29927：Next.js 中间件绕过、CVE-2025-0167：Curl .netrc 凭据泄露、Uvicorn CRLF 注入（未修复的 N-Day）、Python urllib 协议校验绕过（0-Day）、Chrome 通过 Link 头的 Referrer 泄露（2025） |
| [field-notes.md](field-notes.md) | 长篇利用笔记：SQLi、XSS、LFI、JWT、SSTI、SSRF、命令注入、XXE、反序列化、竞态、鉴权绕过的速查与多阶段链 | 侦察、SQL 注入速查、XSS 速查、借 JSONP 回调的 XSSI 外带、路径穿越 / LFI 速查 |
| [node-and-prototype.md](node-and-prototype.md) | 原型链污染、JS 沙箱逃逸、Node.js 攻击链 | 原型污染基础、flatnest 循环引用绕过（CVE-2023-26135）、Gadget：经原型链读取库配置、Node.js VM 沙箱逃逸、完整链条：原型污染到 VM 逃逸 RCE（4llD4y） |
| [pat-reference.md](pat-reference.md) | PayloadsAllTheThings 索引：XSS/SQLi/SSRF/SSTI/LFI/命令注入/上传的批量 payload（需要 PAT clone，见前置条件） | 如何使用本索引、分类映射——本地技巧 → PAT 路径、示例 payload（离线可用，带署名）、搜索配方（批量 PAT）、与本地技巧文件的关系 |
| [python-requests.md](python-requests.md) | Python requests 工具箱：session 脚手架、类 Burp Intruder 的 fuzzer（同步 + ThreadPoolExecutor + httpx 异步）、从 pat-reference.md 字典投放 payload、头/参数喷洒、cookie/JWT、代理 | 1. 何时使用 — Intruder 与 Repeater 的分工、2. 初始化 — Session 骨架、代理、校验、3. Intruder — 同步基线（先正确，再快速）、4. Intruder — ThreadPoolExecutor（30 worker，每线程独立 Session）、5. Intruder — httpx 异步（100 并发、Limits、Semaphore） |
| [server-side-2.md](server-side-2.md) | XXE（基础、OOB、DOCX 上传）、通过 X-Forwarded-For 的 XML 注入、PHP 可变变量、PHP uniqid 可预测文件名、连续正则替换绕过、命令注入（换行、黑名单、sendmail CGI、多条形码、git CLI）、GraphQL 注入（introspection、批处理、插值） | XXE（XML 外部实体）、经 X-Forwarded-For 头的 XML 注入（Pwn2Win 2016）、PHP 可变变量（$$var）滥用（bugs_bunny 2017）、PHP uniqid() 可预测文件名（EKOPARTY 2017）、顺序正则替换绕过（Tokyo Westerns 2017） |
| [server-side-advanced-2.md](server-side-advanced-2.md) | Docker API SSRF、Castor/XML、Apache expression 读取、解析器差异、Windows 路径技巧、恶意 MySQL 服务器读文件 | SSRF 打 Docker API 的 RCE 链（H7CTF 2025）、Castor XML 的 xsi:type 多态反序列化（Atlas HTB）、Apache ErrorDocument 表达式读文件（Zero HTB）、SQLite 文件路径穿越绕过字符串相等判断（Codegate 2013）、利用不间断空格做 HQL 注入（HackIM 2016） |
| [server-side-advanced-3.md](server-side-advanced-3.md) | 第 3 部分（CSAW/35C3/ASIS/PlaidCTF 2018）：WAV polyglot 上传、多斜杠 URL 绕过 path.startswith、Xalan XSLT math:random() 种子猜测、SoapClient _user_agent CRLF 方法走私、gopher:/// 无 host URL scheme 绕过、攻击者指定出站 URL 导致 SSRF 凭据泄露 | 经 .wave 扩展名的 WAV 多语言上传绕过（PlaidCTF 2018）、多斜杠 URL 解析器 path.startswith 绕过（CSAW 2018 Finals）、Xalan XSLT math:random() 种子猜测（35C3 2018）、SoapClient _user_agent CRLF 方法走私（35C3 2018）、gopher:// 无主机 URL scheme 绕过（35C3 2018） |
| [server-side-advanced-4.md](server-side-advanced-4.md) | 第 4 部分：WeasyPrint SSRF/文件读取（CVE-2024-28184）、MongoDB 正则/$where 盲注布尔预言、Pongo2 Go 模板注入、ZIP PHP webshell、basename() 绕过、wget CRLF SSRF→SMTP、Gopher SSRF 打 MySQL 盲注、React Server Components Flight RCE（CVE-2025-55182）、sslsplit+arpspoof 拦截… | WeasyPrint SSRF 与文件读取（CVE-2024-28184，Nullcon 2026）、MongoDB 正则注入 / $where 盲注 oracle（Nullcon 2026）、Pongo2 / Go 模板注入经路径穿越（Nullcon 2026）、上传 ZIP 携带 PHP Webshell（Nullcon 2026）、basename() 绕过读取隐藏文件（Nullcon 2026） |
| [server-side-advanced.md](server-side-advanced.md) | 进阶 SSRF、路径穿越、压缩包、解析器、框架与现代应用服务器问题、Nginx alias 穿越 | ExifTool CVE-2021-22204 —— DjVu Perl 注入（0xFun 2026）、Go rune/字节长度不匹配 + 命令注入（VuwCTF 2025）、Zip 符号链接路径穿越（UTCTF 2024）、路径穿越绕过技巧、Unicode 同形点路径穿越 U+2E2E（CSAW 2017） |
| [server-side-deser.md](server-side-deser.md) | Java/Python/PHP 反序列化与竞态条件 playbook、反序列化配合 PHP SoapClient CRLF SSRF | Java 反序列化（ysoserial）、Python Pickle 反序列化、条件竞争（Time-of-Check to Time-of-Use）、通过剥离 STOP 操作码实现 Pickle 链式执行（VolgaCTF 2013）、Java XMLDecoder 反序列化 RCE（HackIM 2016） |
| [server-side-exec-2.md](server-side-exec-2.md) | 更多执行链：SQLi 分片、路径解析器技巧、多语言 polyglot 上传、wrapper 滥用、文件名注入、文件名截断配合 BMP 像素 webshell | SQLi 关键字碎片化绕过（SecuInside 2013）、经 ORDER BY CASE 绕过 SQL WHERE（Sharif CTF 2016）、经 DNS 记录注入 SQL（PlaidCTF 2014）、Bash 花括号展开实现无空格命令注入（Insomnihack 2016）、Common Lisp 经 reader macro 注入（Insomnihack 2016） |
| [server-side-exec.md](server-side-exec.md) | 直接代码执行路径、上传转 RCE、反序列化相邻执行、LaTeX 注入、请求头与 API 滥用 | Ruby 代码注入、Ruby ObjectSpace 内存扫描提取 flag（Tokyo Westerns 2016）、Perl open() RCE、LaTeX 注入 RCE（Hack.lu CTF 2012）、服务端 JS eval 黑名单绕过 |
| [server-side.md](server-side.md) | PHP 类型混淆、php://filter LFI、Python str.format 路径穿越、SSTI（Jinja2、Twig、ERB、Mako、EJS、Vue.js、Smarty）、SSRF（Host 头、DNS rebinding、curl 重定向、未转义点号正则、SNI FTP 走私、mod_vhost_alias）、PHP hash_hmac NULL | PHP 类型混淆、PHP 文件包含 / php://filter、SQL 注入、Python str.format() 属性遍历（PlaidCTF 2017）、SSTI（服务端模板注入） |
| [sql-injection.md](sql-injection.md) | SQL 注入技术：鉴权绕过、UNION 提取、过滤绕过、二次注入、截断、竞态辅助泄露、INSERT ON DUPLICATE KEY UPDATE 覆盖密码、innodb_table_stats WAF 绕过 | 反斜杠转义引号绕过、十六进制编码绕过引号、二次注入、SQLi LIKE 逐字符爆破、MySQL 列截断（VolgaCTF 2014） |
| [tools-mcp.md](tools-mcp.md) | Web 方向的 MCP 服务集成：Playwright MCP（admin-bot DOM XSS 复现、实时 DOM/console/network 检查，browser_network_requests 只列端点，只有 browser_network_request part="response-body" 返回响应体）与 Burp Suite 官方 MCP（27 个工具、审批闸门会阻塞 agent、目标三元组把 socket 与 Host:… | Playwright MCP（浏览器自动化）、Burp Suite MCP（线路层利用）、何时用 Burp MCP、curl 还是 Playwright MCP |
| [web3.md](web3.md) | Solidity 与 Web3 挑战笔记 | 挑战基础设施模式、EIP-1967 代理模式利用、ABI Coder v1 与 v2 —— 脏地址绕过、剥离 Solidity CBOR 元数据以绕过 codehash 校验、非标准 ABI calldata 编码 |

## 辅助工具

| 脚本 | 用途 |
|---|---|
| `scripts/async_fuzz.py` |  |
