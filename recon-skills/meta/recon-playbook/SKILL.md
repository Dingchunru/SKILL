---
name: recon-playbook
description: 在启动或重构已授权的外部 Web 与 API 评估时使用。
version: 2.0.0
license: MIT
platforms: [linux, macos]
compatibility: Requires curl, jq, subfinder, dnsx, httpx, katana, and optional nmap
metadata:
  tags: [meta, recon, web, api, workflow]
  category: meta
  related_skills:
    - attack-patterns-reference
    - evidence-hygiene
    - offensive-osint
    - port-service-discovery
    - report-writing
    - subdomain-enumeration
    - triage-validation
    - source-leak-hunt
    - web2-recon
---

# 外部 Web 侦察剧本

使用本剧本，将已授权的根域名或资产列表转化为一份按优先级排序的地图，涵盖 Web 应用、API、认证边界和可测试的安全假设。

```text
scope
  -> assets
  -> DNS and services
  -> routes and client code
  -> APIs and identities
  -> hypotheses
  -> focused validation
  -> evidence and reporting
```

## When to Use

- 开始外部 Web、API 或漏洞赏金评估时。
- 已有侦察输出，但缺乏规范化、来源追踪或优先级排序。
- 目标横跨多个应用、子域或身份边界。
- 需要将大范围扫描转化为聚焦的人工验证。

不要使用本剧本为超出约定范围的活动提供理由，也不要对每个资产运行所有可用工具。

## Prerequisites

- 明确的授权、目标边界、排除项、速率限制和停止条件。
- `curl`、`jq`、`subfinder`、`dnsx`、`httpx` 和 `katana`。
- 仅当 IP 或端口发现属于范围时才使用 `nmap`。
- 用于授权测试和会话测试的已批准测试身份。
- 可写入的证据目录。

## How to Run

```bash
export TARGET="example.test"
export OUTPUT_DIR="${OUTPUT_DIR:-./output/$TARGET}"

mkdir -p \
  "$OUTPUT_DIR/assets" \
  "$OUTPUT_DIR/http" \
  "$OUTPUT_DIR/urls" \
  "$OUTPUT_DIR/evidence"
```

只有在审阅上一阶段的输出后，才运行每个阶段。保留原始源文件，使每个主机名、URL 和假设都有来源可溯。

## Procedure

### 1. 记录范围

在输出目录旁保留一份简短、便于操作人员阅读的范围记录：

```text
allowed: *.example.test
excluded: status.example.test
identities: anonymous, test-user-a, test-user-b
request rate: 2 requests/second/host
state changes: synthetic records only
```

范围必须回答：可以测试什么、可以使用哪些身份、多少流量是可接受的，以及是否允许执行改变状态的测试。

### 2. 发现并规范化资产

```bash
subfinder -d "$TARGET" -silent \
  > "$OUTPUT_DIR/assets/subfinder.txt"

curl -sS --max-time 30 \
  "https://crt.sh/?q=%25.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/^\*\.//' \
  > "$OUTPUT_DIR/assets/crtsh.txt"

cat "$OUTPUT_DIR/assets/subfinder.txt" \
    "$OUTPUT_DIR/assets/crtsh.txt" \
  | tr '[:upper:]' '[:lower:]' \
  | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' \
  | sort -u \
  > "$OUTPUT_DIR/assets/hostnames.txt"
```

在开始主动探测之前，审阅通配符结果、证书 SAN、第三方 CNAME 以及被排除的资产。

### 3. 解析并识别 HTTP 服务

```bash
dnsx \
  -l "$OUTPUT_DIR/assets/hostnames.txt" \
  -silent -a -aaaa -cname -json \
  -o "$OUTPUT_DIR/assets/dns.jsonl"

httpx \
  -l "$OUTPUT_DIR/assets/hostnames.txt" \
  -threads 10 \
  -rate-limit 2 \
  -status-code -title -tech-detect -server -ip -cname \
  -json \
  -o "$OUTPUT_DIR/http/services.jsonl"

jq -r '.url // empty' "$OUTPUT_DIR/http/services.jsonl" \
  | sort -u \
  > "$OUTPUT_DIR/http/live-urls.txt"
```

把技术标签和 banner 当作路由线索。在将某个漏洞与组件关联之前，先通过多个来源确认重要组件。

### 4. 映射路由、参数与客户端代码

```bash
katana \
  -list "$OUTPUT_DIR/http/live-urls.txt" \
  -silent -jc -kf all \
  -c 2 -p 2 -rl 2 \
  -o "$OUTPUT_DIR/urls/katana.txt"

grep -Ei '/api/|/graphql|swagger|openapi|/rest/' \
  "$OUTPUT_DIR/urls/katana.txt" \
  > "$OUTPUT_DIR/urls/api-candidates.txt"

grep -Ei 'login|logout|register|reset|oauth|saml|callback|session|token' \
  "$OUTPUT_DIR/urls/katana.txt" \
  > "$OUTPUT_DIR/urls/auth-candidates.txt"

grep -Ei '\.js([?#].*)?$' "$OUTPUT_DIR/urls/katana.txt" \
  > "$OUTPUT_DIR/urls/javascript.txt"
```

在加入存档来源之前，先映射当前路由。历史 URL 对发现有用，但它们不能证明某个端点仍然可达。

### 5. 映射 API 与身份边界

对每个应用记录：

- API 基础 URL、描述、版本、操作和对象标识符；
- 匿名、用户、租户、管理者和管理员边界；
- 登录、登出、刷新、密码重置、MFA、OAuth 和 SAML 流程；
- cookie、token、CORS、CSRF 和 WebSocket 行为；
- 改变状态的方法以及已批准用于测试的合成对象。

当某项断言依赖于跨用户或跨租户访问时，授权测试至少需要两个已批准的身份。

### 6. 选择聚焦技能

使用 `attack-patterns-reference` 对观察结果进行分类，然后只打开有当前证据支持的技能。常见路径包括：

| 观察结果 | 后续技能 |
|---|---|
| JavaScript bundle 或 source map | `js-secrets-extraction`、`source-leak-hunt` |
| REST 对象与标识符 | `hunt-api-misconfig`、`hunt-idor` |
| GraphQL 端点 | `hunt-graphql` |
| OAuth 或 SAML 流程 | `hunt-oauth`、`hunt-saml` |
| WordPress 攻击面 | `hunt-wordpress`、`wordpress-plugin-hunt` |
| 公开服务端口 | `port-service-discovery` |
| 候选多步路径 | `cross-attack-chains` |

### 7. 每次只验证一个假设

在探测之前先写下假设：

```text
Expected: user A cannot read user B's synthetic object.
Test: repeat the same object request with both approved sessions.
Positive evidence: user A receives user B's object and its non-public fields.
Negative control: an unknown object returns the documented not-found response.
Stop condition: any access to non-synthetic or out-of-scope data.
```

在报告之前使用 `triage-validation`。状态码、扫描器标签、版本字符串或看起来宽松的响应头，本身都不足以作为证据。

### 8. 保存证据

对每个实质性结果，保留：

- 目标、身份、UTC 时间戳和范围上下文；
- 已脱敏的请求和响应；
- 预期行为与观察到的行为；
- 阴性对照；
- 副作用、清理和测试限制；
- 工具及相关的版本。

测试过程中使用 `evidence-hygiene`，验证完成后使用 `report-writing`。

## Pitfalls

- 泛匹配（catch-all）应用会对不存在的敏感路径返回 `200`。
- CDN IP 和响应头本身无法确定源站或应用版本。
- 存档端点可能已失效、被重定向或已重新分配给其他用途。
- 公开的客户端标识符并不自动等同于密钥。
- 大范围爬取可能越界进入第三方或被排除的域名。
- 分页可能把有边界的证明变成不必要的数据收集。
- 改变状态的验证需要在该命令执行前立即获得明确授权，并且必须使用合成记录。

## Verification

- 每个活跃资产都可追溯到一条被允许的范围条目和一个发现来源。
- 活跃服务具有规范化的 URL 和 DNS 上下文。
- 应用地图包含路由、API、认证和身份角色。
- 每个被提升的发现都包含语义证据和阴性对照。
- 候选攻击路径将未验证的步骤标注为推断或未测试。
- 证据已脱敏、可复现，并保存在 `OUTPUT_DIR` 之下。
