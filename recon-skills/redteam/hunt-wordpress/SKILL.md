---
name: hunt-wordpress
description: 当授权目标暴露 WordPress 核心、插件、主题、REST 或 XML-RPC 行为时使用。
version: 3.0.0
license: MIT
platforms: [linux, macos]
compatibility: Requires curl, jq, and optional wpscan
metadata:
  tags: [redteam, wordpress, web, api, plugins]
  category: redteam
  related_skills:
    - cors-credential-wordpress
    - error-log-mining
    - source-leak-hunt
    - staging-subdomain-hunt
    - wordpress-plugin-hunt
    - wp-plugin-rest-auth-bypass
    - xmlrpc-exploitation
---

# WordPress 安全评估

在选择具体的漏洞测试之前，先梳理 WordPress 核心、REST、XML-RPC、插件、主题、认证边界以及相邻安装。WordPress 的存在、一条公开路由或一个版本匹配本身都不是发现。

## When to Use

- HTML、响应头、静态资源、cookie 或路由表明存在 WordPress。
- `/wp-json/`、`/wp-login.php`、`/xmlrpc.php` 或 `/wp-content/` 可达。
- JavaScript 或源代码引用了 WordPress 后端。
- staging 或子目录安装可能与主站不同。

## Prerequisites

- 明确的授权与当前目标边界。
- `curl` 和 `jq`；`wpscan` 为可选。
- 用于角色或授权检查的已批准测试身份。
- 仅在盲 SSRF 测试获得授权时，才使用受控回调服务。
- 在注册、上传、密码、插件或其他改变状态的测试前，立即获取明确批准。

## How to Run

以有界的只读映射开始：

```bash
TARGET="https://www.example.test"
OUTPUT_DIR="${OUTPUT_DIR:-./output/wordpress}"
mkdir -p "$OUTPUT_DIR"

for path in \
  / \
  /wp-json/ \
  /wp-login.php \
  /xmlrpc.php \
  /readme.html \
  /author-sitemap.xml; do
  curl -sS --max-time 10 \
    -o /dev/null \
    -w '%{http_code} %{content_type} %{size_download} %{url_effective}\n' \
    "$TARGET$path"
  sleep 1
done
```

## Procedure

### 1. 确认 WordPress

使用多个信号：

```bash
curl -sS --max-time 10 "$TARGET/" \
  | grep -Eio 'wp-content|wp-includes|wp-json|wordpress' \
  | sort -u

curl -sS --max-time 10 "$TARGET/wp-json/" \
  -o "$OUTPUT_DIR/rest-index.json"

jq -r '.namespaces[]? // empty' "$OUTPUT_DIR/rest-index.json" \
  | sort -u \
  > "$OUTPUT_DIR/rest-namespaces.txt"
```

仅有通用的 `200` 响应并不充分。将可疑路径与一个随机不存在的路径作对比，以识别通配路由（catch-all）。

### 2. 梳理核心、主题与插件资产

```bash
curl -sS --max-time 10 "$TARGET/" \
  | grep -Eo "wp-content/(plugins|themes)/[^/?\"']+" \
  | sort -u \
  > "$OUTPUT_DIR/components.txt"
```

在可行时，至少用两个信号确认某个组件：静态资源路径、REST 命名空间、readme 或 changelog、HTML 标记，或带版本的文件。只有在确定了确切受影响版本和前提条件之后，才匹配 CVE。

使用 `wordpress-plugin-hunt` 进行插件发现和版本验证。

### 3. 梳理 REST 数据与授权

```bash
for path in \
  /wp-json/ \
  /wp-json/wp/v2/types \
  /wp-json/wp/v2/posts?per_page=2 \
  /wp-json/wp/v2/pages?per_page=2 \
  /wp-json/wp/v2/users?per_page=2; do
  curl -sS --max-time 10 \
    -D "$OUTPUT_DIR/headers.tmp" \
    -o "$OUTPUT_DIR/body.tmp" \
    "$TARGET$path"
  printf '%s %s\n' "$path" "$(wc -c < "$OUTPUT_DIR/body.tmp")"
  sleep 1
done
```

在判定影响之前先对响应分类：

- 已发布的文章和页面通常按设计就是公开的；
- 用户名可能增加钓鱼或认证风险，但不等于账号接管；
- 邮箱地址、角色、草稿、设置、表单条目、订单和日志需要单独的访问控制审查；
- 插件命名空间可能存在，但所有操作仍受保护。

对于授权类的结论，要将匿名、用户 A、用户 B 以及一个已批准的特权身份针对同一合成对象进行比较。

### 4. 在浏览器中验证 CORS

```bash
curl -sS --max-time 10 \
  -D "$OUTPUT_DIR/cors-headers.txt" \
  -o "$OUTPUT_DIR/cors-body.txt" \
  -H 'Origin: https://attacker.example' \
  "$TARGET/wp-json/wp/v2/users?per_page=2"
```

响应头反射只是一个线索。带凭据的 CORS 影响需要满足：

1. 响应接受了不受信任的 origin；
2. 当需要 cookie 时返回 `Access-Control-Allow-Credentials: true`；
3. 一个已批准的已认证浏览器会话；
4. 浏览器 JavaScript 能够读取非公开数据；
5. 一个匿名或公开数据的负向对照。

使用 `cors-credential-wordpress` 获取完整的浏览器工作流。

### 5. 对 XML-RPC 分类

```bash
curl -sS --max-time 15 \
  -X POST "$TARGET/xmlrpc.php" \
  -H 'Content-Type: text/xml' \
  --data-binary \
  '<methodCall><methodName>system.listMethods</methodName></methodCall>' \
  -o "$OUTPUT_DIR/xmlrpc-methods.xml"

grep -Eo '<string>[^<]+</string>' "$OUTPUT_DIR/xmlrpc-methods.xml" \
  | sed -E 's#</?string>##g' \
  | sort -u
```

在协议分类期间不要跟随重定向。有效的 `methodResponse` 才能证明 XML-RPC 行为；仅凭状态码不能证明。凭据测试、multicall 放大、上传和 SSRF 绕过都需要各自的授权与安全限制。只有在已确认相关方法和前提条件后，才使用 `xmlrpc-exploitation`。

### 6. 检查 staging 与次级安装

证书透明度日志、归档和静态资源路径可能暴露 staging 主机或子目录安装。比较：

- WordPress 与插件版本；
- 认证与 WAF 行为；
- REST 与 XML-RPC 暴露情况；
- 调试配置与源文件；
- 共享的 cookie、凭据、存储和部署路径。

较弱的 staging 控制只有在环境处于范围内且其影响得到证明时才重要。使用 `staging-subdomain-hunt` 进行有界比较。

### 7. 检查源码与错误信息暴露

只探测由观测到的技术栈所支持的路径。验证内容而非状态码：

| 候选路径 | 所需内容 |
|---|---|
| `.git/HEAD` | 形如 `ref: refs/heads/...` 的 Git 引用 |
| `.env` | 配置赋值，而非通用 HTML |
| `debug.log` 或 `error_log` | 真实的应用错误或敏感运行时数据 |
| 备份归档 | 正确的文件签名和有意义的内容 |
| 目录列表 | 目录索引标记和实际条目 |

使用 `source-leak-hunt` 和 `error-log-mining`；仅保留演示暴露所需的最小化、已脱敏样本。

### 8. 构建候选攻击路径

只连接已验证的前提条件：

```text
observed component
  -> exact version and configuration
  -> reachable vulnerable operation
  -> approved identity or synthetic object
  -> reproduced security impact
```

注册、XML-RPC、上传路由和可执行的 PHP 配置并不会自动构成 RCE 链路。要独立确认角色能力、上传校验、存储路径和执行行为。

## Pitfalls

- WordPress 路由常常位于 CDN、缓存或通配行为之后。
- `GET /xmlrpc.php` 返回 `405` 不能用来判定一次有效的 POST 方法调用。
- 存在 REST 命名空间并不证明某个插件操作未认证。
- 公开的作者元数据并不自动就是敏感的。
- 插件版本可能被隐藏、回移（backport），或由过期的静态资源报告。
- 大型日志、站点地图和 REST 集合可能导致不必要的数据收集；请求有界样本。
- 默认凭据尝试、密码喷洒、注册、上传和写入都需要明确授权和约定的锁定限制。

## Verification

- WordPress 的存在由内容确认，而不只是状态码。
- 每个组件发现都包含第二个信号，或说明为何无法获得第二个信号。
- 每个 CVE 关联都包含确切版本和前提条件证据。
- REST 授权使用已批准身份和负向对照。
- CORS 影响在浏览器中以非公开数据复现。
- XML-RPC 行为以协议有效响应或受控回调为依据。
- 改变状态的测试使用合成记录，保留清理证据，并保持在范围内。
