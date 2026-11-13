---
name: github-secret-hunting
description: 在公开 GitHub 仓库中寻找泄露的 API 密钥、令牌和凭据。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, httpx, python3
metadata:
  tags: [recon, github, secret, API-key, token, dork, OSINT, trufflehog, credential]
  category: recon
  related_skills:
    - js-secrets-extraction
    - hardcoded-credential-hunt
    - source-leak-hunt
---

# GitHub 密钥挖掘

扫描公开的 GitHub 仓库，寻找泄露的 API 密钥、令牌、口令以及内部基础设施信息。开发者会不断意外推送密钥 —— 本技能使用定向 dork 查询、自动化扫描工具和实时监控，在开发者察觉并吊销凭据之前发现它们。

## When to Use

- 目标在某个组织账号下拥有公开仓库。
- JS 打包文件分析揭示内部服务名称 —— 在 GitHub 上搜索相关的配置文件。
- 需要找到可用于云服务、支付网关或第三方集成的有效 API 密钥。
- 目标使用的 CI/CD 系统可能在构建日志或工作流文件中泄露令牌。
- 希望对目标组织新出现的密钥泄露进行实时监控。

## Prerequisites

- 具备 python3、curl、git 的 `terminal`。
- GitHub 个人访问令牌（仅需 `public_repo` 权限范围）。
- 工具依赖：TruffleHog、GitDorker、gitleaks。

## How to Run

```bash
# Basic GitHub code search for sensitive patterns in target repos
echo "target.com" | while read domain; do
  curl --max-time 30 --connect-timeout 10 -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/code?q=$domain+filename:.env" \
    | jq '.items[]?.html_url'
done
```

## 快速检测

```bash
# Basic GitHub code search for sensitive patterns in target repos
echo "target.com" | while read domain; do
  curl --max-time 30 --connect-timeout 10 -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/code?q=$domain+filename:.env" \
    | jq '.items[]?.html_url'
done
```

## Procedure

### 阶段 1 — 使用 GitDorker 进行定向 Dork 查询

```bash
# Clone the dork collection and run against target
git clone https://github.com/Proviesec/github-dorks
python3 GitDorker.py \
  -tf $GITHUB_TOKEN \
  -q target.com \
  -d dorks/medium_dorks.txt \
  -o gitdorker_target.txt

# Also search by employee emails found in LinkedIn or metadata
python3 GitDorker.py \
  -tf $GITHUB_TOKEN \
  -q "john.doe@target.com" \
  -d dorks/medium_dorks.txt

# Custom dork: find env files
python3 GitDorker.py -tf $GITHUB_TOKEN \
  -q "org:target filename:.env DB_PASSWORD" -d dorks/medium_dorks.txt
```

### 阶段 2 — TruffleHog 深度扫描

```bash
# Scan a specific repo (finds secrets even in deleted commits)
trufflehog git https://github.com/target/repo --results=verified

# Scan entire GitHub org
trufflehog github --org=target --token=$GITHUB_TOKEN \
  --only-verified --threads=20 --json > trufflehog_org.json

# Docker variant
docker run --rm -it trufflesecurity/trufflehog:latest \
  github --only-verified --org=target

# Parse verified secrets
cat trufflehog_org.json | jq -r 'select(.Verified == true) | "\(.DetectorName): \(.RawV2)"'
```

### 阶段 3 — 使用 shhgit 进行实时监控

```bash
# Monitor globally for secrets being pushed right now
shhgit --search-query \
  'path:*.env OR "DB_PASSWORD=" OR "AWS_ACCESS_KEY_ID=" OR "-----BEGIN RSA PRIVATE KEY-----"'

# Monitor specific org
shhgit --search-query \
  'target.com (path:*.env OR "DB_PASSWORD=" OR "api_key=")'
```

### 阶段 4 — 文件类型与扩展名搜索

```bash
# git-wild-hunt: find specific file types
python3 git-wild-hunt.py \
  -s "org:Target extension:json filename:creds language:JSON"
python3 git-wild-hunt.py \
  -s "org:Target extension:sql filename:backup"
python3 git-wild-hunt.py \
  -s "target.com gitlab_token"

# Manual search patterns via GitHub API
for pattern in "filename:.env DB_PASSWORD" "filename:credentials.json" \
               "filename:config.json api_key" "filename:id_rsa" \
               "filename:.npmrc" "extension:pem BEGIN RSA" \
               "filename:service-account.json"; do
  curl --max-time 30 --connect-timeout 10 -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/code?q=target.com+$pattern" \
    | jq '.total_count, (.items[:3][].html_url)'
done
```

### 阶段 5 — 硬编码凭据验证

```bash
# Pipeline: find → extract → verify
echo "target.com" | gau | grep -E '\.js$|\.json$|\.env$|\.config$' \
  | httpx -silent -mc 200 \
  | parallel -j 10 "curl --max-time 30 --connect-timeout 10 -s {} | grep -Eo \
    '(?:api[_-]?key|secret|token)[\"'\''']?\s*[:=]\s*[\"'\''']?([A-Za-z0-9_\-]{20,})' \
    | tee -a api_keys.txt"

# Verify found keys
for key in $(cat api_keys.txt | awk -F':' '{print $2}' | tr -d '"'\'' ' | sort -u); do
  # OpenAI
  curl --max-time 30 --connect-timeout 10 -s "https://api.openai.com/v1/models" -H "Authorization: Bearer $key" | jq '.data[].id' 2>/dev/null && echo "VALID OPENAI: $key"
  # GitHub
  curl --max-time 30 --connect-timeout 10 -s "https://api.github.com/user" -H "Authorization: token $key" | jq '.login' 2>/dev/null && echo "VALID GITHUB: $key"
done
```

### 阶段 6 — GitLab 私有实例

```bash
# Discover self-hosted GitLab
# Check: gitlab.target.com, git.target.com, code.target.com
curl --max-time 30 --connect-timeout 10 -sk "https://gitlab.target.com/api/v4/projects?visibility=public"

# With a found token
curl --max-time 30 --connect-timeout 10 --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.target.com/api/v4/user"
curl --max-time 30 --connect-timeout 10 --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.target.com/api/v4/projects?membership=true&simple=true"

# Deep scan for secrets across accessible repos
gitleaks detect \
  --source https://gitlab.target.com \
  --access-token $GITLAB_TOKEN -v
```

### 阶段 7 — 从公开文档中提取元数据

```bash
# metafinder: downloads public documents and extracts metadata
# Reveals usernames, software versions, internal file paths, email patterns
metafinder -d "target.com" -l 10 -go -bi -ba -o metadata_target.txt
metafinder -d "dev.target.com" -l 10 -go -bi -ba -o metadata_dev.txt

# Manual: check PDF metadata
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/document.pdf" -o doc.pdf
exiftool doc.pdf | grep -i "author\|creator\|producer"
```

## Pitfalls

- **大多数搜索结果都是文档和示例，而非真实泄露。** 重点关注 `.env`、`.config`、`.npmrc` 以及 CI/CD 工作流文件。
- **GitHub API 的速率限制很严格。** 使用多个令牌或轮换 IP。
- **已验证的密钥可能已被吊销。** 报告前务必再次验证。
- **自建 GitLab 实例可能阻断外部扫描。** 先测试连通性。
- **绝不要用发现的凭据进行未授权访问。** 仅做最小化验证，记录并报告。

## Verification

1. TruffleHog 或 GitDorker 识别出带有上下文的潜在密钥。
2. 通过最小化 API 调用验证该密钥（例如对 GitHub 令牌调用 `GET /user`）。
3. 确认该密钥是最近提交的（检查提交日期）—— 陈旧密钥优先级较低。
4. 检查仓库是否为公开，以及该密钥是否授予有意义的访问权限（管理员权限还是只读）。
5. 为报告记录确切的文件路径、提交哈希和行号。

---

## 相关技能

- **`js-secrets-extraction`** —— 在 JavaScript 打包文件中查找可能指向 GitHub 仓库的 API 密钥和端点。
- **`hardcoded-credential-hunt`** —— 检测 HTML、JS 和 API 响应中硬编码的口令。
- **`source-leak-hunt`** —— 在在线 Web 服务器上寻找暴露的配置文件（.env、.git）。
