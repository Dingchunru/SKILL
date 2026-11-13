---
name: hunt-metrics-exposure
description: "狩猎泄露 AI 使用情况、数据库连接池和运营情报的公开 /metrics、/health 和 actuator 端点。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [metrics, exposure, hunt, redteam]
  category: redteam
---

## When to Use

目标使用现代可观测性工具（Go、.NET、Java、Node.js）。这些框架经常会暴露 `/metrics`、`/health` 和 `/status` 端点，而它们被遗忘在认证之后。与应用数据泄露不同，metrics 泄露揭示的是**完整的**运营画像：使用了哪些 AI 模型、有多少活跃用户、数据库连接耗尽情况，以及第三方服务依赖。

---

## Prerequisites

- 针对目标的明确授权、目标边界和速率限制。
- 工具：`curl`、`python3`。
- 可写证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何会改变状态的步骤（写入、上传、凭据尝试），在命令执行前立即获得明确确认。

## How to Run

```bash
TARGET="https://target.com"

# Common observability paths
for ep in metrics health status ready live readyz healthz \
  actuator/health actuator/metrics actuator/prometheus \
  Telescope telescope horizon debug; do
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /tmp/metrics_${ep}.txt -w "%{http_code}" \
    "${TARGET}/${ep}" 2>/dev/null)
  if [ "$code" = "200" ]; then
    size=$(wc -c < /tmp/metrics_${ep}.txt)
    echo "  /${ep}: HTTP 200 (${size} bytes)"
  fi
done
```

## Procedure

下文各阶段即为操作流程。保持每个探测请求有界（`--max-time`），将证据记录到 `OUTPUT_DIR` 下，并在 Pitfalls 中列出的停止条件处停止。

## 阶段 1 — 发现 Metrics 端点

```bash
TARGET="https://target.com"

# Common observability paths
for ep in metrics health status ready live readyz healthz \
  actuator/health actuator/metrics actuator/prometheus \
  Telescope telescope horizon debug; do
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /tmp/metrics_${ep}.txt -w "%{http_code}" \
    "${TARGET}/${ep}" 2>/dev/null)
  if [ "$code" = "200" ]; then
    size=$(wc -c < /tmp/metrics_${ep}.txt)
    echo "  /${ep}: HTTP 200 (${size} bytes)"
  fi
done
```

---

## 阶段 2 — 分析 Prometheus Metrics

```bash
# Count unique metric families (each reveals a subsystem)
grep -c '^# HELP' /tmp/metrics_metrics.txt

# Extract AI/ML model usage
grep -i 'ai_\|model\|llm\|openai\|gemini\|copilot' /tmp/metrics_metrics.txt

# Extract database pool states
grep -i 'db_pool\|database\|connection' /tmp/metrics_metrics.txt

# Extract third-party dependencies
grep -i 'stripe\|openai\|sendgrid\|twilio\|email' /tmp/metrics_metrics.txt

# Extract request volumes (user activity)
grep -i 'http_request\|api_request\|grpc_request' /tmp/metrics_metrics.txt

# Extract circuit breaker states (service health)
grep -i 'circuit_breaker' /tmp/metrics_metrics.txt
```

---

## 阶段 3 — 分析 Health/Status 端点

```bash
# Spring Boot Actuator
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/actuator/health" | python3 -m json.tool
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/actuator/metrics" | python3 -m json.tool
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/actuator/env" | python3 -m json.tool  # May leak env vars

# Custom health endpoints
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/health" | python3 -m json.tool
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/api/health" | python3 -m json.tool

# Laravel Telescope (if exposed)
curl --max-time 30 --connect-timeout 10 -sk "${TARGET}/telescope/requests" | head -c 500
```

---

## Metrics 揭示的内容

| Metric | 获得的情报 |
|--------|-------------------|
| `ai_analyzer_output_total{model="gpt-5-mini"}` | 使用了哪些 AI 模型、使用量 |
| `db_pool_idle_connections{pool="api"}` | 数据库连接池规模、连接耗尽风险 |
| `circuit_breaker_state{client="stripe"}` | 第三方依赖及其健康状况 |
| `clinical_copilot_sse_active` | 特定功能的实时用户数 |
| `http_requests_total` | 请求量、高峰时段、用户活动 |
| `app_version` / `build_info` | 已部署版本、构建时间戳 |

---

## Pitfalls
- **不含秘密的 Prometheus /metrics** — 暴露请求计数的 metrics 端点只是信息性的。需要包含 PII、内部主机名或凭据的标签。
- **Spring Boot Actuator /actuator/metrics** — metrics 是有意为监控而暴露的。只有当它们泄露敏感数据（标签中的用户名、内部 IP）时才报告。
- **未认证的 JMX** — 未认证的 JMX 暴露只有在可以进行写操作（调用 MBean）时才是严重的。只读 JMX 只是信息性的。
- **不含敏感数据的健康端点** — `/health`、`/status`、`/ready` 端点本就是设计为公开的。需要泄露的内部数据。

---

## Verification

- **确认暴露**：`/metrics` 返回 Prometheus 文本格式（以 `# HELP` 或 `# TYPE` 开头的行）
- **Actuator 暴露**：`/actuator/health` 返回带组件状态的 JSON
- **误报**：端点仅返回 `{"status":"ok"}`（最小健康检查，而非 metrics 泄露）
- **严重性升级**：`/actuator/env` 或 `/actuator/configprops` 暴露 → 仅当响应包含未脱敏的秘密时才为 HIGH/CRITICAL（Spring Boot 2.2+ 默认会脱敏 `password`/`secret`/`key` 的值 — 评分前先检查响应体）

---

## 后续步骤

- AI 模型使用指标 → 转向 `hunt-llm-ai`（对所发现的模型进行提示注入）
- 显示过载的数据库连接池指标 → 已识别 DoS 攻击面
- Stripe/邮件服务的熔断器状态 → 用于链式攻击的基础设施依赖图
- 与 `hunt-schema-enumeration` 结合以完成完整的目标画像

---
