---
name: google-dorks-catalog
description: "用于发现暴露配置、密钥与凭据的高精度 Google dork —— 经真实环境验证"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: N/A (reference catalog)
metadata:
  tags: [meta, google-dorks, secrets, passive-recon, osint]
  category: meta
---

# Google Dorks 目录 —— 暴露的配置与密钥

## When to Use

- 在对每个目标执行**被动侦察**（阶段 1）期间
- 在 crt.sh 子域枚举之后
- 在任何主动扫描之前
- 已针对 100 多个真实目标验证

## Prerequisites

- 针对目标的明确授权、目标边界和速率限制。
- 工具：`curl`、`openssl`、`python3`。
- 可写入的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），须在该命令执行前立即获得明确确认。

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

# Test dork results manually
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/.env" | head -5
# Verify GitHub found secrets
python3 -c "import json; print(json.loads(open('result.json').read()))"
```

## Procedure

以下各阶段就是本流程。让每次探测都有边界（`--max-time`），在 `OUTPUT_DIR` 下记录证据，并在 Pitfalls 中列出的停止条件处停止。

## 高精度 Dork

### 关键暴露文件

```
site:$target "APP_KEY"
site:$target "DB_PASSWORD"
site:$target "-----BEGIN RSA PRIVATE KEY-----"
site:$target filetype:env
site:$target inurl:git/config
site:$target intitle:"index of" ".env"
site:$target "api_key" OR "apikey" OR "secret_key"
site:$target "firebase" "apiKey"
site:$target "supabase" "anon" "key"
site:$target inurl:"/.env" "DB_PASSWORD"
site:$target "client_secret" "redirect_uris" extension:json
site:$target "private_key" "client_email" extension:json
```

### 暴露的配置文件（所有扩展名）

```
site:$target ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json
```

这覆盖了：
- **log** —— 明文形式的 token、SQL 查询、邮箱
- **txt/conf/cnf/ini** —— 服务器配置、数据库主机
- **env** —— 含凭据的环境变量
- **sh** —— 硬编码口令的脚本
- **bak/backup/swp/old/~** —— 含旧版本的备份文件
- **git/svn** —— 暴露的版本库
- **htpasswd/htaccess** —— 含哈希的访问控制
- **json** —— 服务账号、Firebase 配置、Supabase 配置

### 特定服务的 Dork

#### Supabase
```
site:$target "supabase.co" "anon_key" OR "SUPABASE_ANON_KEY"
```

#### Firebase
```
site:$target "firebase-adminsdk" "private_key_id" extension:json
```

#### AWS
```
site:$target "AKIA" filetype:env NOT example NOT test
```

#### SendGrid
```
site:$target "SG." filetype:env NOT example
```

#### MongoDB
```
site:$target "mongodb+srv://" "password"
```

#### PostgreSQL
```
site:$target "postgresql://" "password" ext:env
```

#### JWT 密钥
```
site:$target "JWT_SECRET" OR "jwt_secret" filetype:env
```

#### OpenAI API 密钥
```
site:$target "sk-" filetype:env OR filetype:txt
```

#### GitHub Token
```
site:$target "ghp_" OR "gho_" OR "ghu_"
```

## GitHub 代码搜索模式

使用 GitHub 个人 token（结果要好得多）：

```python
headers = {"Authorization": "token GH_TOKEN"}
base = "https://api.github.com/search/code"

# SA Keys (Firebase/GCP) -- ~1 in 30 is valid
params = {"q": '"type": "service_account" "private_key" "project_id"'}

# .env with real credentials
params = {"q": 'DB_PASSWORD+DB_HOST+APP_KEY+filename:.env+NOT+example+NOT+your+NOT+test'}

# Supabase URLs + keys
params = {"q": 'supabase.co+SUPABASE_URL+SUPABASE_ANON_KEY+NOT+example+NOT+your'}

# AWS Keys
params = {"q": 'AKIA+filename:.env+NOT+example+NOT+your'}

# SendGrid keys
params = {"q": 'SG.+filename:.env+NOT+example'}

# MongoDB connection strings
params = {"q": 'mongodb+srv://+password+filename:.env'}
```

## 证书 SAN 发现

```bash
# Extract SANs directly from the certificate
openssl s_client -connect $TARGET:443 -servername $TARGET </dev/null 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName | grep -Eo 'DNS:[^,]+' | cut -d: -f2 | sort -u
```

## 真实案例

**真实案例（已脱敏）**：SSO 证书暴露了 ORG_DOMAIN_1、ORG_DOMAIN_2、ORG_DOMAIN_3，这些域名未出现在常规的 CT 搜索中。

## Pitfalls

| 问题 | 解决方案 |
|-------|----------|
| Google 速率限制 | 拉开搜索间隔，使用无痕模式，轮换 IP |
| GitHub API 限制 | 使用个人 token（5000 req/hr） |
| example 仓库造成的误报 | 追加 NOT example NOT test NOT your |

## Verification

```bash
# Test dork results manually
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/.env" | head -5
# Verify GitHub found secrets
python3 -c "import json; print(json.loads(open('result.json').read()))"
```
