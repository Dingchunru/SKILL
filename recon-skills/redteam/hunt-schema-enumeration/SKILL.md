---
name: hunt-schema-enumeration
description: "通过 API 错误提示枚举隐藏的表、字段和端点。与 PostgREST、Zod、FastAPI、GraphQL 和 REST 无关。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [schema, enumeration, hunt, redteam]
  category: redteam
---

## When to Use

目标 API 返回结构化错误消息（JSON），其中暗示了有效的表名、字段名或端点路径。对于 REST/GraphQL API 而言，这是单次收益最高的黑盒侦察技术——一个模糊测试请求即可揭示整个数据库 schema。

最常见于：PostgREST（Supabase）、FastAPI（Python）、Zod（Next.js/Node）、tRPC、GraphQL，以及任何在生产环境中启用了校验错误详情的框架。

---

## Prerequisites

- 针对目标的明确授权、目标边界与速率限制。
- 工具：`curl`、`python3`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），必须在执行命令前立即获得明确确认。

## How to Run

```bash
SUPABASE_URL="https://PROJECT.supabase.co"
ANON_KEY="eyJ..."

# Fuzz with common table names — read the hints
for table in users profiles posts products orders data config settings; do
  echo "=== $table ==="
  curl --max-time 30 --connect-timeout 10 -sk "${SUPABASE_URL}/rest/v1/${table}?select=*&limit=1" \
    -H "apikey: ${ANON_KEY}" \
    -H "Authorization: Bearer ${ANON_KEY}" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
hint=d.get('hint','')
if hint: print(f'  -> {hint}')
"
done
```

## Procedure

下述阶段即为操作流程。保持每个探测请求有界（`--max-time`），将证据记录在 `OUTPUT_DIR` 之下，并在 Pitfalls 中列出的停止条件处停止。

## 阶段 1——PostgREST 错误提示枚举

PostgREST 是 Supabase/PostgreSQL 的 REST API 层。当你查询一个不存在的表时，它会返回一个包含真实表名的提示。

```bash
SUPABASE_URL="https://PROJECT.supabase.co"
ANON_KEY="eyJ..."

# Fuzz with common table names — read the hints
for table in users profiles posts products orders data config settings; do
  echo "=== $table ==="
  curl --max-time 30 --connect-timeout 10 -sk "${SUPABASE_URL}/rest/v1/${table}?select=*&limit=1" \
    -H "apikey: ${ANON_KEY}" \
    -H "Authorization: Bearer ${ANON_KEY}" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
hint=d.get('hint','')
if hint: print(f'  -> {hint}')
"
done

# The response pattern:
# {"hint":"Perhaps you meant the table 'public.real_table_name'"}
# {"hint":"Perhaps you meant the table 'public.user_sessions'"}
```

**构建用于定向模糊测试的字典：**
```bash
# Common patterns found in field:
# - Game apps: hands, scores, sessions, players, items, inventory
# - SaaS: subscriptions, subscribers, billing, invoices, teams, api_keys
# - Health: patients, appointments, assessments, prescriptions
# - Gov: citizens, certificates, documents, protocols
# - Finance: transactions, accounts, wallets, withdrawals, deposits
```

---

## 阶段 2——Zod/FastAPI 校验错误挖掘

现代框架会返回详细的校验错误，暴露所有预期字段。

### FastAPI（Python）
```bash
# POST with empty body or wrong fields
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://api.target.com/endpoint" \
  -H "Content-Type: application/json" -d '{}' 2>/dev/null
# Response reveals ALL required fields:
# {"errors":{"usuario":["required"],"senha":["required"]}}
```

### Zod（Next.js/Node）
```bash
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/workspaces" \
  -H "Content-Type: application/json" -d '{}' 2>/dev/null
# Response: {"error":{"name":"ZodError","message":"[\n  {\"expected\":\"string\",\"path\":[\"name\"]}\n]"}}
```

---

## 阶段 3——GraphQL 内省

```bash
# Standard introspection query
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}' 2>/dev/null

# Even if introspection is disabled, error messages reveal type names:
# "Cannot query field 'x' on type 'User'. Did you mean 'users'?"
```

---

## 阶段 4——激进表名模糊测试

生成一份综合字典，组合以下内容：

```bash
# 1. From JS bundle analysis
grep -Eo 'from\(["\x60][a-zA-Z_]+["\x60]\)' /tmp/target.js | sort -u

# 2. From common patterns
# Singular/plural: user/users, post/posts, product/products
# Snake/camel: user_sessions, userSessions, UserSessions
# Domain-specific: appointments, patients, assessments, certificates

# 3. Systematic fuzz
for table in $(cat /tmp/wordlist.txt); do
  curl --max-time 30 --connect-timeout 10 -sk -w "%{http_code}" "${BASE}/rest/v1/${table}?select=count" \
    -H "apikey: ${KEY}" 2>/dev/null | tee -a /tmp/fuzz_results.txt
done
```

---

## Pitfalls
- **枚举 schema 而无敏感字段**——了解 API schema 只是侦察。需要证明存在可利用的字段/变更操作。
- **通过内省获取 GraphQL schema**——内省是一项功能，不是缺陷（除非在生产环境中被显式禁用）。
- **通过错误消息获取数据库 schema**——泄露表名的 SQL 错误属于信息泄露，而非 schema 专有问题。根据所披露的内容评级。
- **OpenAPI 规范可公开访问**——`/swagger.json` 或 `/openapi.json` 是有意为 API 消费者公开的。根据所暴露的管理/内部端点评级。

---

## Verification

- **确认 PostgREST 命中**：响应为 `[]`（空数组 = 表存在，RLS 阻止读取）或返回了数据
- **确认 Zod 命中**：错误列出了确切的字段名和期望类型
- **确认 FastAPI 命中**：422 且 `detail` 数组列出了缺失字段
- **误报**：通用 404 HTML 页面（不是 JSON 错误）

---

## 后续步骤

- 如果 PostgREST 提示揭示了表 → 继续 `hunt-write-gap`（测试 PATCH/POST/DELETE）
- 如果 Zod 错误揭示了字段 → 测试 `hunt-business-logic`（批量赋值、价格篡改）
- 如果 FastAPI 揭示了认证 schema → 测试 `jwt-attack` 或 `api-noauth-hunt`
- schema 枚举总是通向下一步攻击——绝不是最终步骤

---
