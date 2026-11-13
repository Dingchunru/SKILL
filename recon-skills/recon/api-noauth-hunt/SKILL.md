---
name: api-noauth-hunt
description: 当 API 可能在未认证的情况下暴露数据或特权操作时使用。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, API, no-auth, data-breach, CRUD]
  category: recon
  related_skills:
    - hunt-firebase
    - hunt-supabase
    - js-secrets-extraction
    - port-service-discovery
    - source-leak-hunt
---

# API 无认证访问验证

识别那些在缺少其数据和业务功能所需认证或授权的情况下仍可能被访问到的 API 操作。发现阶段默认只读。写入验证使用合成记录，并且必须在执行前立即获得明确授权。

## When to Use

- 端口扫描在非标准端口（3000、5000、8080-8085、9000）上发现 HTTP 服务。
- 目标拥有 API 子域名（api.target.com、backend.target.com）。
- JavaScript 打包文件引用了内部 API 端点。
- `port-service-discovery` 在意外端口上发现 HTTP 之后。
- `hunt-firebase` 或 `hunt-supabase` 识别出后端 API 之后。

## Prerequisites

- 已安装 curl、python3、jq。
- 疑似 API 的目标 URL 或 IP:port。
- 用于模糊测试的常见 API 路径列表。

## How to Run

```bash
# Quick API test — try common paths without auth
TARGET="https://api.target.com"
for path in "/" "/api" "/api/v1" "/api/users" "/api/health" "/docs" "/swagger.json"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "$TARGET$path")
  echo "HTTP $code: $TARGET$path"
done
```

## 快速参考

| 信号 | 含义 | 操作 |
|--------|---------------|--------|
| `/api/users` 或 `/api/clients` 返回 HTTP 200 | 可能存在未认证的数据访问 | 验证一个有界样本 |
| 未认证的 POST 返回 HTTP 2xx | 可能存在未认证的写入 | 停止操作并获取写入授权 |
| `/docs`、`/swagger.json` 暴露 OpenAPI/Swagger | 完整 API 映射被暴露 | 枚举全部端点 |
| 错误响应中出现堆栈跟踪 | 内部路径、框架版本 | 绘制基础设施拓扑 |
| 通过意外的方法触发状态变更 | 可能存在方法级授权缺口 | 使用合成记录复现 |
| 登录未校验密码 | 可能存在认证绕过 | 使用获批的测试账号验证 |

## Procedure

### 阶段 1 —— API 发现

```bash
TARGET="$1"      # URL or IP:port
OUTDIR="$OUTDIR/api_recon"
mkdir -p "$OUTDIR"

echo "[*] API discovery on $TARGET"

# Common API paths
API_PATHS=(
  "/" "/api" "/api/v1" "/api/v2" "/v1" "/v2"
  "/api/users" "/api/clients" "/api/admin" "/api/health"
  "/api/auth" "/api/login" "/api/register"
  "/api/products" "/api/orders" "/api/contracts"
  "/docs" "/swagger.json" "/swagger.yaml" "/openapi.json"
  "/api-docs" "/swagger-ui.html" "/graphql"
  "/health" "/status" "/version" "/info" "/ping"
  "/actuator" "/actuator/health" "/actuator/info" "/actuator/env"
)

for path in "${API_PATHS[@]}"; do
  code=$(curl -sk -o /tmp/api_probe_$$.tmp -w "%{http_code}" --max-time 5 --connect-timeout 5 "$TARGET$path" 2>/dev/null)

  if [[ "$code" == "200" ]]; then
    body=$(cat /tmp/api_probe_$$.tmp)
    content_type=$(file -b --mime-type /tmp/api_probe_$$.tmp 2>/dev/null)

    # Check if it's JSON (likely API)
    if echo "$body" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
      record_count=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 'object')" 2>/dev/null)
      echo "  [API] $path → HTTP 200 (JSON, ${record_count} records)"
    elif echo "$body" | grep -qi "swagger\|openapi"; then
      echo "  [SWAGGER] $path → HTTP 200 (API documentation)"
    elif echo "$body" | grep -qi "graphql"; then
      echo "  [GRAPHQL] $path → HTTP 200"
    else
      echo "  [HTTP] $path → HTTP 200 (${#body} bytes, $content_type)"
    fi
  elif [[ "$code" == "401" || "$code" == "403" ]]; then
    echo "  [AUTH] $path → HTTP $code (protected)"
  elif [[ "$code" == "500" ]]; then
    echo "  [ERROR] $path → HTTP 500 (potential injection point)"
    cat /tmp/api_probe_$$.tmp | head -5
  elif [[ "$code" != "404" && "$code" != "000" ]]; then
    echo "  [$code] $path"
  fi
done
rm -f /tmp/api_probe_$$.tmp
```

### 阶段 2 —— OpenAPI/Swagger 利用

```bash
TARGET="$1"

echo "[*] Extracting API schema..."

# Try multiple Swagger paths
for sw_path in "/swagger.json" "/swagger.yaml" "/openapi.json" "/api/swagger.json" \
  "/api-docs" "/v2/api-docs" "/v3/api-docs"; do
  schema=$(curl -sk --max-time 10 --connect-timeout 10 "$TARGET$sw_path" 2>/dev/null)

  if echo "$schema" | grep -q '"paths"'; then
    echo "[+] Found OpenAPI spec at $sw_path"

    # Extract all endpoints
    echo "$schema" | python3 -c "
import sys, json
spec = json.load(sys.stdin)
paths = spec.get('paths', {})
for path, methods in paths.items():
    for method in methods.keys():
        if method not in ('parameters',):
            print(f'  {method.upper():7s} {path}')
" 2>/dev/null

    # Save for later use
    echo "$schema" > /tmp/openapi_$$.json
    echo "[+] Schema saved to /tmp/openapi_$$.json"
    break
  fi
done
```

### 阶段 3 —— 经授权的合成数据 CRUD 验证

此阶段会改变服务器状态。仅当测试范围明确允许写入测试，且该端点用于存储一次性合成记录时才执行。下面的防护检查是有意设置的：不要移除它，也不要用既有对象 ID 替换。

```bash
TARGET="$1"
ENDPOINT="$2"  # approved test collection
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
PROBE_ID="noauth-test-$(date +%s)"

if [[ "${I_HAVE_EXPLICIT_WRITE_AUTHORIZATION:-no}" != "yes" ]]; then
  echo "Refusing state-changing validation without explicit authorization." >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR/api-validation"

create_body=$(curl -sk --max-time 10 --connect-timeout 5 \
  -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$PROBE_ID\",\"test_record\":true}")
printf '%s\n' "$create_body" \
  > "$OUTPUT_DIR/api-validation/create-response.json"

created_id=$(printf '%s' "$create_body" | jq -r '.id // .uuid // empty')
if [[ -z "$created_id" ]]; then
  echo "Create response did not expose a disposable object ID; stop here." >&2
  exit 1
fi

curl -sk --max-time 10 --connect-timeout 5 \
  "$TARGET$ENDPOINT/$created_id" \
  -o "$OUTPUT_DIR/api-validation/read-response.json"

curl -sk --max-time 10 --connect-timeout 5 \
  -X PATCH "$TARGET$ENDPOINT/$created_id" \
  -H "Content-Type: application/json" \
  -d '{"validation_state":"updated"}' \
  -o "$OUTPUT_DIR/api-validation/update-response.json"

curl -sk --max-time 10 --connect-timeout 5 \
  -X DELETE "$TARGET$ENDPOINT/$created_id" \
  -o "$OUTPUT_DIR/api-validation/delete-response.txt"
```

### 阶段 4 —— 有界读取验证

```bash
TARGET="$1"
ENDPOINT="$2"  # confirmed no-auth endpoint
OUTPUT_DIR="${OUTPUT_DIR:-./output}"

mkdir -p "$OUTPUT_DIR/api-validation"
curl --max-time 15 --connect-timeout 5 -sk \
  "$TARGET$ENDPOINT?page=1&limit=2" \
  -o "$OUTPUT_DIR/api-validation/bounded-sample.json"

jq 'if type == "array" then .[:2] else . end' \
  "$OUTPUT_DIR/api-validation/bounded-sample.json"
```

## Pitfalls

- **HTTP 200 ≠ API。** 某些服务在意外路径上返回 HTML。请验证内容类型是否为 JSON。
- **分页可能把验证变成全量采集。** 请求能够证明访问控制失效的最小页面即可。不要枚举整个数据集。
- **POST、PATCH、PUT 和 DELETE 会改变状态。** 需要明确授权，并且只对为测试而创建的合成对象进行操作。
- **认证测试可能锁定账号或触发告警。** 使用获批的测试身份，并遵守约定的请求速率。

## Verification

- 确认同一操作在未认证时成功，并且被预期的负向对照所拒绝。
- 对于读取，仅保留展示受保护数据类别所需的最小脱敏样本。
- 对于写入，记录同一合成对象的创建、读取、更新、删除与清理过程。
- 记录 URL、方法、预期策略、观察到的行为、身份、时间戳、对照结果以及测试限度。
