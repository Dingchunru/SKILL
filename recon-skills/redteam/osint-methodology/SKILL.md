---
name: osint-methodology
description: "面向外部红队行动与授权攻击面评估的完整 OSINT 方法论。涵盖 5 阶段侦察流水线（种子发现、资产扩展、信息富化、暴露面分析、报告），含 29 种资产类型的资产图规范、严重性评分准则（CRITICAL/HIGH/MEDIUM/LOW/INFO）、置信度升级工作流、时间预算、资产级分类处置规则、基于规模的战术、身份结构测绘（Entra/Okta/ADFS/Google/SAML/M365 Teams+SharePoint+OAuth）、API 与认证映射方法论、JavaScript 深度分析、移动端攻击面、云攻击面、泄露×身份关联、可检测性标记、感知检测的探测（退避、角色轮换）、只读验证器规范、WAF/CDN 绕过与源站发现、漏洞优先级排序（CVE/EPSS/KEV）、钓鱼基础设施规划与话术编排、漏洞赏金提交模板、含风险转译的客户交付模板、威胁行为体调查（含俄罗斯/中国线索）、加密货币追踪、图像/视频取证、时空定位。适用于规划或执行针对授权目标的侦察、测绘组织的外部攻击面、调查个人/实体、追踪加密货币流向、定位媒体地理信息，或开展归因工作。"
version: 2.1
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [osint, methodology, recon, redteam]
  category: redteam
  triggers:
    - external recon
    - external red team
    - red team external
    - attack surface management
    - attack surface mapping
    - ASM
    - perimeter recon
    - target reconnaissance
    - bug bounty recon
    - asset discovery
    - footprint
    - attack path
    - identity fabric
    - SSO discovery
    - IdP fingerprinting
    - tenant fingerprinting
    - M365 enumeration
    - Microsoft 365 recon
    - API discovery
    - GraphQL introspection
    - mobile recon
    - APK analysis
    - cloud bucket enumeration
    - bucket enum
    - breach correlation
    - secret leak hunt
    - origin discovery
    - CDN bypass
    - WAF bypass
    - vulnerability prioritization
    - CVE prioritization
    - EPSS
    - CISA KEV
    - phishing infrastructure
    - pretext development
    - bug bounty submission
    - responsible disclosure
    - client report
    - exec summary
    - risk translation
    - confidence upgrade
    - time budget
    - engagement profile
    - asset triage
    - detection-aware probing
    - back-off strategy
    - persona rotation
    - OSINT methodology
    - open source intelligence
    - target profiling
    - data correlation
    - OSINT workflow
    - intelligence collection
    - OSINT campaign
    - recon methodology
    - threat actor investigation
    - attribution
---

# OSINT 方法论 — 外部红队版

## When to Use

- 规划或执行针对授权目标的侦察，测绘组织的外部攻击面，调查个人/实体，追踪加密货币流向，定位媒体地理信息。
- 开展归因工作。

## Prerequisites

- 针对目标取得明确授权、目标边界与速率限制。
- 工具：`amass`、`censys`、`curl`、`dnsx`、`ffuf`、`gobuster`、`httpx`、`katana`、`masscan`、`naabu`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何会改变状态的步骤（写入、上传、尝试凭据），必须在执行命令前立即取得明确确认。

## How to Run

```bash
curl --max-time 30 --connect-timeout 10 -sk -H "Host: target.example.com" https://<candidate-IP>/
```

## Procedure

以下各阶段即流程本身。每个探测都要保持有界（`--max-time`），在 `OUTPUT_DIR` 下记录证据，并在 Pitfalls 中列出的停止条件处停止。

## 0. 何时使用本技能 / 何时不要使用

**在以下情况使用本技能：**
- 规划或执行针对授权目标的外部侦察（红队、范围内的漏洞赏金、ASM 项目）。
- 端到端测绘组织的外部攻击面（子域名 → 资产 → 暴露面 → 攻击路径）。
- 调查个人、实体或威胁行为体，且证据规范很重要时。
- 追踪加密货币流向、定位媒体地理信息、进行图像/视频取证，或对事件做时空定位。
- 构建需要可复现性、严重性分级和清晰交接的结构化 OSINT 行动。
- 从攻防项目中产出面向客户的交付物（执行摘要、技术报告、复现包）。

**在以下情况不要使用本技能：**
- 用户要求的是主动利用、后渗透、横向移动、AD 提权、恶意软件开发，或任何超出侦察范围的内容——这些都在范围之外。
- 用户要求的是蓝队/防御性内容（SIEM 规则、检测工程）——属于不同领域。
- 目标的授权情况不明确，且用户要求你对其并不拥有的第三方资产采取行动——见下文 §1；先温和地提出范围问题再继续。

---

## 1. 授权与法律立场

本技能适用于操作者拥有或已获得书面授权进行评估的资产（红队作战规则、范围内的漏洞赏金资产、ASM 合同）。

**柔性范围检查：** 当用户要求你针对一个授权情况未在先前对话中确立的目标采取行动时，先询问一次再继续：

> *"快速确认范围：这个目标是您拥有的，还是您获得书面授权进行评估的（例如红队项目、范围内的漏洞赏金资产，或您自己的基础设施）？我想确保我们不会越出项目边界。"*

一旦确认了授权，就不再重复询问。如果用户明确说明了项目类型（例如"这是我们按合同对 acme.com 做的渗透测试"），无需再次询问。

**始终生效的护栏（无论授权情况如何）：**
- 绝不削弱认证机制、速率限制、banner，或目标侧任何用于强制范围约束的安全控制。
- 绝不在显式的 DEEP / `--aggressive` 模式之外运行破坏性探测（对生产环境的真实 SYN 扫描、线速 masscan、模糊测试/暴力破解）。
- 绝不把真实 PII、有效凭据、会话令牌、API 密钥或其他机密粘贴到云端 LLM 或第三方服务。
- 绝不对已记录范围之外的资产采取行动，即使它们"明显相关"（子公司、供应商、员工的个人账号等）。

---

## 2. 置信等级

项目中你做出的每一项断言都应附带置信等级。共有三级：

| 等级 | 含义 | 示例 |
|---|---|---|
| **TENTATIVE** | 基于间接证据看似合理；尚未验证。 | 仅凭摘要片段的 Google dork 匹配；从姓名推断出的邮箱格式；仅由单一被动来源返回的子域名；favicon 哈希重叠（两台主机共享同一 favicon——可能是共享基础设施，也可能只是巧合）。 |
| **FIRM** | 直接观察到但未获印证。 | 能解析到 IP 的子域名；经 HEAD 确认存在的 bucket（私有）；CT 日志条目显示证书；Shodan 返回了 banner。 |
| **CONFIRMED** | 多个独立来源相互印证，或已经直接验证。 | 经实时验证的 PMAK 令牌（只读 `/me` 返回 200）；泄露语料库 + crt.sh + DNS 三者一致；bucket 可列举且文件可下载；用户已枚举且密码重置流程返回有效提示。 |

**归因的三条规则：** 在断言关联之前，要求三个独立的弱信号，或一个强信号加一个弱信号。不要单一来源归因。

### 2.1 置信度升级工作流

置信度不是静态的——每个 TENTATIVE 资产都应有记录在案的通往 FIRM 和 CONFIRMED 的路径。按资产类型使用以下规则。

| 资产类型 | TENTATIVE → FIRM | FIRM → CONFIRMED |
|---|---|---|
| **子域名** | 由 ≥2 个独立被动来源返回，或 DNS A/AAAA/CNAME 成功解析。 | 在标准端口（80/443/22 等）上提供服务，且返回 HTTP banner / TLS 证书 / SSH banner。 |
| **IP** | 通过 ≥2 个来源发现（被动 DNS、ASN 查询、Shodan）。 | 主动探测有响应（至少一个端口返回 TCP SYN-ACK，或 ICMP echo reply）。 |
| **WebApp** | URL 从 JS / API / 存档中提取，但尚未请求。 | HTTP 请求返回 2xx/3xx/4xx（任何非网络错误的响应），且 content-length > 0。 |
| **邮箱** | 由姓名格式生成，或由仅摘要片段的 dork 返回。 | 在 Hunter.io / EmailRep / IntelX / 泄露语料库中列出，或 `MAIL FROM`/`RCPT TO` SMTP 探测返回 250（不投递——在 DATA 之前中止）。 |
| **Bucket（S3/GCS/Azure）** | 排列组合候选；尚未探测。 | HEAD 返回 200、301 或 403（确认存在）。随后 GET 返回对象列表或可获取已知对象即为 CONFIRMED。 |
| **端点（API / wayback）** | 从 JS 正则 / Wayback / Postman 中提取。 | HTTP 请求返回非 404（路由存在）。随后对该端点的行为完成指纹识别（认证姿态、响应结构、速率限制）即为 CONFIRMED。 |
| **凭据 / 机密** | 在捕获文本中匹配目录正则。 | 只读验证器（`/me`、`auth.test`、`sts:GetCallerIdentity`、`/user`）返回成功。随后在记录作用域 + 账号 ID 后即为 CONFIRMED。 |
| **人员** | 从单一来源提取姓名（LinkedIn / 泄露数据 / GitHub 提交）。 | 由第二来源确认（Hunter.io 中的职位 + LinkedIn 个人资料，或两个泄露来源出现同一邮箱）。 |
| **仓库** | 在 GitHub 搜索中通过组织关键字匹配名称。 | 仓库元数据表明组织/邮箱/网站匹配。随后提交历史显示有员工参与即为 CONFIRMED。 |
| **移动应用** | 在应用商店中名称匹配。 | 归属置信度评分 ≥70（见配套技能 §21）。随后二进制元数据（签名证书、包名、开发者账号）可回溯到目标即为 CONFIRMED。 |
| **证书** | 由 crt.sh 返回一次。 | CT 日志条目在 ≥2 个日志中得到确认。随后在已发现主机上提供服务即为 CONFIRMED。 |
| **SSO 租户** | 发现端点返回 OIDC 元数据。 | 提取到租户 GUID，且域名可通过该租户预期的 MX / autodiscover / SP 记录解析。 |

**默认报告姿态：** 没有明确印证就绝不声称 CONFIRMED。存疑时降级。操作者更信任保守的断言而非夸大的断言。

---

## 3. 输出格式约定

在活动会话中产出发现时，按下面的 schema 组织每条发现——它可以直接落入资产管理工具中。

```
Finding:
  id:           <stable hash or UUID>
  module:       <which technique discovered it; "manual" if hand-found>
  asset_key:    <typed key, e.g. sub:api.example.com or webapp:https://example.com/admin>
  category:     <e.g. SECRET_LEAK, MISSING_HSTS, OPEN_GRAPHQL_API, LEAKED_CRED, SSO_EXPOSURE>
  severity:     <info|low|medium|high|critical>
  confidence:   <tentative|firm|confirmed>
  title:        <one-line summary>
  description:  <2-5 sentences>
  evidence:
    url:        <where it was found>
    timestamp:  <UTC ISO8601>
    sha256:     <hash of any downloaded artifact>
    raw:        <truncated to 2 KiB>
  references:
    - <CVE-ID, advisory URL, vendor doc>
  remediation:  <action the asset owner can take>
```

**始终使用 UTC 时间戳**。本地时间会在笔记/截图/日志之间造成关联错误。

---

## 4. 来源卫生与引用

对于捕获的每个产物，记录：**URL + UTC 时间戳 + SHA-256 哈希 + 命令行版本 + run_id**。

- 对所有下载的文件计算 SHA-256。
- 截图使用 PNG（无损，且比整页 WARC 更适合作为证据包）。
- 捕获原始 HTTP 请求/响应，正文上限 2 KiB，以保持证据包体积可控。
- 使用 JSONL（NDJSON）日志，每个事件一行，带 `run_id`，使整个项目可重放。
- 将只读证据与工作副本分开；绝不编辑已捕获的产物。

在输出中引用来源时，优先使用可长期存续的引用（CVE、厂商公告、ATT&CK 技术 ID、RFC），而非易失性引用（一条 Twitter 帖子、一个论坛帖）。如果唯一来源是易失性的，引用前先归档（archive.today、Wayback SavePageNow）。

---

## 5. 不要做（硬性规则）

- 不要把凭据、会话令牌、API 密钥、真实 PII、信息窃取器日志或独特的枢纽线索粘贴到云端 LLM（ChatGPT、Claude.ai、Gemini、Perplexity）。敏感分析使用本地模型（Ollama、LM Studio、GPT4All）。
- 不要假定厂商标签就是事实真相。交叉标签合理性检查：TRM、Chainalysis、Arkham 可能相互矛盾。把每个标签都当作假设。
- 不要假定 1:1 的跨链桥流向。跨链桥/混币器/包装器引入了铸造/销毁语义；用链上证明进行验证。
- 不要仅凭单一信号断言归属。favicon 哈希重叠、共享 CT 签发者、共享 NS——每项都只是假设。需要三条规则。
- 不要在显式的 DEEP / `--aggressive` 模式之外运行模糊测试、SYN 扫描、masscan 或 `nuclei fuzzing/*` 模板。
- 除了只读验证之外，不要用凭据验证器做任何事（不创建/删除/发送）。
- 不要镜像投射（假定目标像你一样思考）。把能力与意图和背景支持分开。
- 不要混淆相关性与控制力。
- 遇到主动防御时不要升级；退避并记录（见 §6.4）。

---

## 6. OpSec

### 6.1 傀儡账号（Sock Puppets）

傀儡账号是一个无法与你关联的虚假账号。建立发帖历史、养号、在独立的浏览器配置文件中使用它。

资源与技术：
- 人格生成：[Fake Name Generator](https://www.fakenamegenerator.com/)、[This Person Does Not Exist](https://thispersondoesnotexist.com/)。
- 浏览器隔离：[Firefox Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/)，或为每个角色使用专用配置文件。
- 一次性电话号码：Burner、Silent Link（部分平台会拒绝 VoIP——保留一批备用号码）。
- 任何高价值角色都使用硬件通行密钥；恢复码离线保存。
- 安装任何浏览器扩展前先审计。针对热门扩展的供应链攻击屡次把调查人员作为目标——应假定热门扩展的风险更高，而非更低。
- 维护证据链：为每个动作打时间戳、对每个关键产物计算哈希、按案件记录命令行版本。
- 角色账号应看起来像真实的低活跃度账号：头像（合成）、简介、在"启用"该角色前数周内零星分布的几条随手帖子。

参考资料：
- [Effective Sock Puppets](https://medium.com/@unseeable06/creating-an-effective-sock-puppet-for-your-osint-investigation-95fdbb8b075a)
- [Ultimate Guide to Sock Puppets](https://osintteam.blog/the-ultimate-guide-to-sockpuppets-in-osint-how-to-create-and-utilize-them-effectively-d088c2ed6e36)

### 6.2 可检测性与 OpSec 标记

每个探测都会留下足迹。在笔记中为每次操作标记可检测性等级，以便推理你在目标侧留下的 SIEM 痕迹。

| 标记 | 示例 |
|---|---|
| **低** | 被动 Shodan InternetDB；CT 日志查询（crt.sh）；Wayback CDX；被动 DNS（SecurityTrails）；Hunter.io 邮箱富化；对公开 bucket 的 HTTP HEAD；`getuserrealm.srf`；Microsoft OIDC 元数据获取。 |
| **中** | Microsoft `GetCredentialType` 用户枚举；Okta `/api/v1/authn` 用户枚举；Postman API 密钥验证；AWS `sts:GetCallerIdentity`（会记录到 CloudTrail）；Slack `auth.test`；整页截图；针对 28/13 路径字典的 Swagger/GraphQL 探测；定向 favicon 哈希 + JARM 指纹识别。 |
| **高** | 主动端口扫描（naabu / masscan / nmap）；对生产环境运行 Nuclei 全模板；大规模子域名暴力枚举；从第三方镜像下载 APK；深模式下每个租户超过 N 次的用户枚举；SMTP `RCPT TO` 枚举；Web 模糊测试（ffuf/gobuster）。 |

与客户合作时，在项目报告中记录实际执行的操作及其可检测性标记——客户会希望知道他们的检测栈本应捕获什么。

**默认设置：** 默认采用被动方式。仅在以下条件下使用主动探测：(a) 明确授权，(b) 在约定的维护窗口内，(c) 操作者知晓由此产生的日志量。

### 6.3 验证器规范

当你发现一个暴露在外的凭据（泄露的 API 密钥、sourcemap 暴露的令牌、公开 Postman 工作区中硬编码的 PMAK），你可能想确认它是否有效。只用**只读验证器**来做这件事。

规范：
- 仅使用只读端点（例如 `/me`、`/whoami`、`auth.test`、`sts:GetCallerIdentity`）。
- 绝不用已验证的凭据去创建、修改、删除或发送任何内容。
- 为验证尝试标记可检测性——每个验证器都会在提供商侧生成审计日志条目。
- 记录 `checked_at`（UTC）、响应（截断）以及返回的作用域/账号 ID。
- 如果操作者的作战规则禁止验证，将该凭据标记为 `validation_skipped_by_policy` 并停止。

具体验证器端点（Postman、AWS、GitHub、Slack、Anthropic、OpenAI、npm、Atlassian、DataDog）见配套的 `offensive-osint` 技能。

### 6.4 感知检测的探测（检测迹象 + 退避）

你的探测最终会触发检测。要在触发主动响应**之前**识别迹象并退避。

**你已被检测到的迹象（大致按严重程度递增）：**

1. **速率限制响应** — `429 Too Many Requests`、设置了 `Retry-After` 头、`X-RateLimit-Remaining: 0`。
2. **验证码插页** — Cloudflare 插页、hCaptcha 挑战、AWS WAF 页面。
3. **WAF 页面** — 带有提供商品牌的明确"Access denied"（Cloudflare、Akamai、Imperva、F5 ASM、AWS WAF、Sucuri）。
4. **状态码漂移** — 之前返回 200/401 的端点现在仅对你的 IP 返回 403。
5. **Banner 变化** — server 头形态或响应时间持续变化。
6. **DNS 污染回退到 NXDOMAIN** — 目标的权威服务器停止解析子域名（很可能是他们的 CDN 接管了）。
7. **蜜罐诱饵** — 看起来好得不像真的端点（`/admin/db_dump.sql`、暴露的 `.env` 且其中的凭据无法通过验证）。真实的暴露很少看起来如此干净。
8. **直接接触** — 你的傀儡邮箱收到"我们注意到异常活动"的消息；或者，在极端情况下，你的 IP 收到礼貌的滥用联系邮件。

**退避阶梯：**

1. **放慢速度。** 将并发减半。在请求之间加入 2–10 秒的抖动。
2. **切换端点。** 停止请求触发问题的路径。转移到侦察流水线的其他模块。
3. **切换角色。** 更换 User-Agent（在真实浏览器之间轮换）、更换 TLS 指纹（不同版本的 httpx/curl）。
4. **切换 IP。** 轮换到新的出口（住宅代理、用于敏感查询的 Tor、不同的云区域）。
5. **暂停。** 等待 1–24 小时。许多 WAF 具有基于 IP 的滚动窗口信誉；被动等待常常能将其重置。
6. **记录并咨询。** 如果已触发 (3) WAF、(4) 状态漂移或 (8) 直接接触，**停止主动探测并咨询项目负责人**。越过这些信号继续探测有违反范围的风险。

**角色 / IP 轮换规则：**
- 绝不把角色轮换为曾在同一目标的先前项目中使用过的角色。
- 高可检测性工作使用住宅代理（Bright Data、Smartproxy、IPRoyal）——但要注意它们有时会被 Cloudflare 列入 IP 黑名单。
- Tor 出口节点对**被动查询**（CT 日志、存档站点）有用，但会被大多数主动探测目标屏蔽。
- 云出口 IP（AWS / GCP / Azure）常被激进地列入侦察黑名单。谨慎使用。
- 记录每次轮换的时间戳 + 原因；评审者会问。

**不要做：**
- 不要试图通过发送更激进的 payload 来"智取"已确认的 WAF 封锁。这正是客户获得额外日志、而你被抓到的方式。
- 不要切换源 IP 来规避明确的封禁列表——那会越界进入规避领域，并可能违反作战规则。
- 不要因为仪表盘显示"仍在运行"就忽略信号。探测正被静默记录；响应稍后才会到来。

---

## 7. 外部红队侦察流水线

面向任何授权外部评估的 5 阶段流水线。各阶段顺序执行；阶段内的模块可并发运行。

### 阶段 1 — 种子发现
确立目标身份（是谁/是什么）的事实基线。

- 对种子域名做 WHOIS（注册人、日期、名称服务器）。
- ASN 枚举：组织拥有/使用哪个 AS？（Hurricane Electric BGP Toolkit、RIPEstat、BGPView。）
- DNS 记录（A/AAAA/MX/TXT/NS/SOA/CAA）——仅记录，暂不遍历。
- 根域名的证书透明度历史（crt.sh、Censys）。

### 阶段 2 — 资产扩展
发现所有可能属于目标的东西。

- 子域名枚举（先被动来源：crt.sh、VirusTotal、AlienVault OTX、Shodan，再做排列组合和暴力枚举）。
- 云 bucket 枚举（由公司名 + 子域名主干生成 S3/GCS/Azure 排列——见 §15）。
- 仿冒域名生成（dnstwist 变体 → 解析 → WHOIS）——既用于钓鱼风险，也用于发现关联企业资产。
- Wayback CDX 存档端点，寻找被遗忘的路径。
- 移动应用发现（Android 通过 google-play-scraper，iOS 通过 iTunes Search API——见 §14）。
- DNS 深度遍历（对配置错误的区域做 NSEC 遍历、机会性 AXFR）。
- LinkedIn 员工枚举 → 推导邮箱格式。

### 阶段 3 — 信息富化
为已发现的资产补充深度信息。

- 端口 + 服务探测（Shodan InternetDB 免费 → 若获授权则 naabu/masscan）。
- 实时 TLS 握手（证书链、JARM、favicon mmh3 哈希）。
- Web 技术识别（通过 httpx 的 Wappalyzer 风格约 600 条签名）。
- WAF/CDN 推断（头部特征）。
- 若位于 CDN 之后，则做源站发现（见 §27）。
- 安全响应头审计。
- 批量截图（以视觉方式分拣成千上万台主机）。
- 邮箱收集（6 个并行来源）。
- 邮件安全审计（SPF/DMARC/DKIM/BIMI/MTA-STS）。
- GitHub 代码搜索 dork（13 个 dork 模板 × 29+ 条机密正则）。
- JavaScript 深度分析（sourcemap、机密、端点、内部主机泄露）。
- SSO/IdP 租户指纹识别（Entra、Okta、ADFS、Google、SAML、M365 Teams/SharePoint/OAuth——见 §11）。
- API 与认证映射发现（Swagger/OpenAPI、GraphQL、Postman）。
- GitHub 之外的机密清扫（Postman 公开工作区、Stack Exchange、Trello/Notion/Atlassian dork）。
- 厂商产品指纹识别（Citrix/F5/PaloAlto/Pulse/Fortinet/Cisco/VMware/Exchange）。
- 容器 / CI-CD / 云原生暴露检查。
- 招聘信息收集，用于推断技术栈。

### 阶段 4 — 暴露面分析
把资产转化为发现。

- Nuclei（15 项常开内置检查 + 可选二进制）。
- TLS 深度审计（sslyze / testssl.sh）。
- 泄露 × 身份关联（HudsonRock Cavalier、HIBP、DeHashed、IntelX、本地语料库 → SSO_EXPOSURE 发现）。
- 定向错误配置探测（`.git/config`、`.env`、`phpinfo.php`、`/actuator/env`、`/actuator/heapdump`、`_cat/indices`、`/console`、`/manager/html`）。
- 漏洞优先级排序（CVE × EPSS × CISA KEV × 公开 POC 可用性——见 §28）。

### 阶段 5 — 报告
让工作成果可用。

- 每条发现的风险评分（CVSS + 项目特定权重）。
- 资产图导出（D3 友好的节点/连线、GraphML、JSON）。
- 面向客户的报告（执行摘要 + 技术细节 + 修复建议——见 §31）。
- 复现包（run_id、命令行版本、原始证据、JSONL 日志）。
- 漏洞赏金提交（如适用——见 §30）。

### 7.5 流水线优先级顺序（信号密度最高者优先）

当预算受限时，按此顺序工作：

1. **泄露数据** — 信息窃取器日志（HudsonRock Cavalier 免费层）+ HIBP + DeHashed。对红队 ROI 最高；常能提供企业 SSO 的有效明文凭据。需要以邮箱作为输入。
2. **GitHub 侦察** — 代码搜索 dork。可发现 AWS 密钥、Slack 令牌、JWT 密钥、`.env` 文件。通往云上横向的最快路径。
3. **Nuclei 错误配置扫描** — 暴露的管理面板、有公开 POC 的 CVE。
4. **云 bucket** — 排列公司名 + 子域名主干。可列举的 bucket = CRITICAL。
5. **端口** — 先用 Shodan InternetDB（免费、免密钥）。VPN 集中器、RDP、Jenkins、GitLab-CE、Elasticsearch 是高价值枢纽点。
6. **邮箱 OSINT** — 供给泄露数据查询；供给钓鱼清单。
7. **Web 技术 / WAF / 截图** — 分拣成千上万台主机；在探测前先掌握技术栈。
8. **Wayback** — 存档的 JS 常有硬编码密钥；存档端点会暴露已被移除的管理/开发路径。
9. **DNS 深度 + 邮件安全** — SPF/DMARC 缺口可支持邮件伪造；TXT 验证令牌会暴露 SaaS 租户归属。
10. **证书** — CT 日志时间线能捕获被遗忘的子域名；弱加密套件是低成本发现。
11. **ASN + 反向 DNS** — 企业 IP 空间承载未公开的基础设施。
12. **WHOIS** — 注册人 PII 会暴露关联企业资产。
13. **仿冒域名** — 已注册的仿冒域名即为发现；未注册的则进入钓鱼域名候选清单。
14. **安全响应头** — 单独价值低，但客户报告需要。

### 7.6 时间预算与项目配置

阶段与资产数量决定侦察耗时。粗略估算（单个操作者，典型 SaaS 风格目标）：

| 阶段 | 小型组织（<100 人） | 中型（100–1K） | 大型（1K+） |
|---|---|---|---|
| 1. 种子发现 | 30 分钟 | 30 分钟 | 30 分钟 |
| 2. 资产扩展 | 1–2 小时 | 2–4 小时 | 4–8 小时 |
| 3. 信息富化（每 100 个存活 webapp） | 约 1 小时 | 约 1 小时 | 约 1 小时 |
| 4. 暴露面分析 | 1–3 小时 | 3–6 小时 | 6–12 小时 |
| 5. 报告 | 2–4 小时 | 4–8 小时 | 1–2 天 |

**项目配置：**

- **1 小时快速侦察（"X 有多暴露？"）** — 阶段 1（15 分钟）→ 被动子域名（crt.sh + Subfinder，10 分钟）→ 对已解析 IP 查 Shodan InternetDB（5 分钟）→ 通过 Hunter+IntelX 收集邮箱（10 分钟）→ 对邮箱做泄露查询（10 分钟）→ 仅输出执行摘要（10 分钟）。
- **4 小时聚焦侦察（"钓鱼就绪度检查"）** — 增加：完整邮箱收集、LinkedIn 员工枚举、SPF/DMARC 分析、仿冒域名候选生成、SSO/IdP 指纹识别。输出：钓鱼可行性报告 + 目标邮箱清单。
- **1 天标准侦察** — 按上述优先级顺序完成阶段 1–4。输出：按资产的发现清单 + 资产图 + 执行摘要。
- **1 周深度侦察** — 包含标准内容，另加：深模式用户枚举、全预算的 JS 深度分析、移动端攻击面、云原生指纹识别、厂商产品指纹识别、包仓库泄露搜寻、漏洞优先级排序。输出：完整客户交付包 + 复现包。
- **持续监控（每周差分）** — 每周重跑阶段 1–3；与基线比对；发现新资产/新发现/资产消失时告警。

**何时提前中止：**
- 阶段 1 之后，如果范围错误（目标其实是无关企业的子公司；作战规则需要澄清）。
- 阶段 2 之后，如果攻击面低于阈值（没有公开 webapp + 没有暴露服务 + 没有泄露邮箱 → 外部可发现的东西很少）。
- 任何阶段，如果遇到 §6.4 中的 WAF / 检测迹象。

---

## 8. 资产图规范

把每项发现都视作图中的一个有类型资产，而非漂浮的字符串。

### 8.1 资产分类（29 种）

| 类别 | 资产类型 |
|---|---|
| **DNS / 网络** | `domain`、`subdomain`、`ip`、`netblock`、`asn` |
| **服务** | `port`、`service`、`certificate` |
| **身份** | `email`、`person`、`credential` |
| **代码 / 配置** | `repo`、`secret` |
| **云 / 存储** | `bucket`、`firebase_project` |
| **Web** | `webapp`、`wayback_endpoint`、`api_endpoint`、`api_spec`、`graphql_schema` |
| **移动端** | `mobile_app`、`deep_link`、`exported_component` |
| **钓鱼 / 对抗性** | `typosquat_domain` |
| **协作 / SaaS** | `postman_collection`、`postman_workspace`、`postman_api_key`、`stack_post`、`saas_public_surface` |

### 8.2 资产 Schema

每个资产都携带：
- `type` — 上述 29 种之一。
- `key` — 唯一去重 id（带类型前缀，例如 `sub:api.example.com`、`email:alice@example.com`）。
- `value` — 实际的字符串/对象。
- `sources[]` — 确认该资产的每个来源（已去重）。
- `confidence` — TENTATIVE / FIRM / CONFIRMED。
- `first_seen`、`last_seen` — UTC 时间戳。
- `attrs{}` — 类型特定元数据（例如对 `webapp`：status_code、title、技术栈列表、JARM、favicon mmh3、截图路径）。

### 8.3 边分类

关系是有类型的边，而非文本：
`RESOLVES_TO`、`HOSTED_ON`、`IN_NETBLOCK`、`BELONGS_TO_ASN`、`LISTED_IN_CERT`、`OWNED_BY`、`ALIAS_OF`、`BREACHED_FROM`、`EMPLOYED_BY`、`HOSTS_REPO`、`TYPOSQUAT_OF`、`EXPOSES`、`DOCUMENTED_BY`、`BELONGS_TO_HOST`、`REQUIRES_AUTH`、`LEAKS_SCHEMA`、`SHIPPED_BY_ORG`、`CONTAINS_SECRET`、`TALKS_TO_HOST`、`EXPOSES_DEEPLINK`、`HAS_EXPORTED_COMPONENT`、`USES_FIREBASE_PROJECT`、`LACKS_PINNING_FOR`。

### 8.4 规范规则

- **每项发现都是资产。** 不要针对漂浮的字符串写发现；先创建资产，再挂接发现。
- **按 key 去重，而非按 value。** 相同 value、不同 type ≠ 相同资产（`sub:api.example.com` 和 `webapp:https://api.example.com/` 是不同资产，二者之间有 `BELONGS_TO_HOST` 边）。
- **来源不可妥协。** `sources[]` 必须列出每个来源。如果两个来源确认了它，两者都要写入。
- **置信度逐来源计算，再聚合。** 由 3 个被动来源返回的子域名是 FIRM；仅由 Bing 摘要片段返回的是 TENTATIVE。
- **通过旁挂文件延迟绑定。** 当模块 A 的产出是模块 B 所需时，写一个 JSON 旁挂文件（`mobile_endpoints.json`、`secrets_sidecar.json`）——不要让模块 B 阻塞等待模块 A。见 §24。

### 8.5 资产级分类处置规则

当你手头资产混杂、探测预算有限时，按每个资产*能带来什么*排序：

**按主机名信号确定 WebApp 优先级（从高到低）：**

1. 认证相关主机名（`auth.`、`login.`、`sso.`、`idp.`、`accounts.`、`oauth.`）。
2. 管理路径（`/admin`、`/dashboard`、`/console`、`/manager`、`/wp-admin`、`/phpmyadmin`）。
3. 开发/预发布主机（`dev.`、`staging.`、`stg.`、`qa.`、`uat.`、`test.`、`sandbox.`、`preprod.`、`preview.`）——防御更弱，常会泄露生产数据。
4. API 主机名（`api.`、`services.`、`gateway.`、`graph.`）。
5. 面向客户的主机名（`portal.`、`app.`、`my.`、`account.`）。
6. 营销 / 内容（`www.`、`blog.`、`news.`、`careers.`、`support.`）。

**按推断功能确定子域名优先级：**

- API > 管理 > 开发 > 认证 > 生产应用 > 营销。

**按网段确定 IP 优先级：**

- 企业 ASN 自有（最可能承载未公开的内部基础设施）。
- 云网段（AWS / GCP / Azure / DO / OVH）——更替频繁，但对云原生服务有吸引力。
- CDN 网段（Cloudflare / Akamai / Fastly）——通常是边缘而非源站；除非在做源站发现，否则延后。

**按角色线索确定邮箱优先级：**

| 角色标识 | 优先级 | 原因 |
|---|---|---|
| `ceo@`、`cfo@`、`cto@`、`ciso@` | 最高 | 高管账号的泄露价值最高（BEC、财务权限、董事会访问权）。 |
| `it@`、`helpdesk@`、`support@`、`security@` | 高 | IT/安全账号拥有特权命令行访问；helpdesk 账号处理重置流程。 |
| `dev`、`engineer`、`architect`、`dba` | 中 | 开发者账号通常拥有 GitHub / 云 / CI 访问权。 |
| `sales`、`marketing`、`hr`、`finance` | 中 | SaaS 访问权（Salesforce、HubSpot、Workday）；财务可支撑 BEC。 |
| 通用角色账号（`info@`、`noreply@`、`contact@`） | 低 | 常无人监控或作为别名转发；个人背景信息较少。 |

**按新鲜度 + 命名确定仓库优先级：**

- 近期推送（最近 30 天）> 陈旧。
- 描述中包含目标名称的公开仓库 > 仅在代码中出现目标名称。
- 从看起来像内部的父仓库分叉 > 独立仓库。
- 名称提及 `prod`、`internal`、`private`、`secret` → 优先级为 HIGH，尽管是公开的（可能是命名不当或意外暴露）。

**应用顺序：** 当你有 N 个资产而预算只够 M 次探测（M < N）时，先应用资产类型优先级，再应用类型内优先级。例如：50 个子域名 → 先探测 API + 管理 + 开发（约 15 个），再探测认证 + 生产应用（约 20 个），把营销/内容推迟到后续轮次。

---

## 9. 发现评分准则与严重性映射

严重性是运营性的，而非主观的。使用以下锚点：

### 9.1 CRITICAL（关键）

认证前代码执行、已确认的有效凭据、可列举的生产数据、根本性的信任破坏。

示例：
- 生产 webapp 上暴露 `.git/config`（完整源代码泄露）。
- 暴露 `/.env`（明文凭据，通常是数据库 / 云 / API）。
- Spring Boot `/actuator/env` 或 `/actuator/heapdump` 未认证即可访问。
- 可列举且包含用户数据的 S3 / GCS / Azure bucket。
- 对写端点未认证的 POST/PUT/DELETE 可改变状态。
- 开放的 Firebase Realtime Database（`https://{project}.firebaseio.com/.json` 返回数据）。
- 生产 Android 应用中 `android:debuggable=true`。
- 实时验证通过且作用域广泛的凭据（PMAK、AWS 密钥、Anthropic/OpenAI 密钥）。
- 泄露语料库中 ≥10 名员工被攻陷，且识别出他们的租户（SSO_EXPOSURE）。
- 开放的 Elasticsearch 集群（`/_cat/indices` 返回数据）。
- 开放的 Docker API（`/v1.40/containers/json` 返回容器列表）。
- 开放的 Redis（无 AUTH；可写入 `authorized_keys`）。
- 启用匿名认证的开放 Kubernetes API server。
- 10250 端口开放的 kubelet（无需认证即可 pod exec）。
- 2379 端口开放的 etcd（集群状态与机密）。
- 存在 BlueKeep 漏洞的 RDP、存在 EternalBlue 漏洞的 SMB。
- Citrix Netscaler / F5 BIG-IP 存在特定版本的 RCE CVE。

### 9.2 HIGH（高）

显著暴露但尚未达到 RCE；有清晰的升级路径；高价值信息泄露。

示例：
- GitHub 仓库中的公开机密（PAT、AWS 密钥、Slack 令牌等）。
- 可访问的 sourcemap（`.js.map`）——前端完整原始源码泄露。
- 生产环境开放 GraphQL introspection（完整 schema 泄露 → 可枚举 mutation）。
- 可能发生子域名接管（CNAME 指向未被认领的 Heroku/Shopify 等）。
- 可反射的带凭据 CORS（`Access-Control-Allow-Origin: <reflected>` + `Access-Control-Allow-Credentials: true`）。
- 动词篡改：端点对外仅允许 GET，但存在隐藏的 DELETE/PATCH。
- 敏感路径（`/login`、`/sso`、`/admin`、`/auth`）缺少 HSTS——从 MED 升级而来。
- 暴露的 Jenkins/Tomcat-Manager/phpMyAdmin 管理界面（无认证或默认凭据）。
- Telnet（23 端口）可访问。
- 移动应用中的 WebView 带 JS bridge（XSS → 潜在 RCE）。
- 移动应用中的敏感 deep-link 处理器。
- 生产发信域名的 DMARC 策略为 `p=none`（可伪造）。
- 厂商产品 banner 存在已知未修补的 CVE（已列入 KEV）。

### 9.3 MEDIUM（中）

信息泄露、加固缺口、暴力破解暴露面。

示例：
- 标准页面缺少安全响应头：HSTS、CSP。
- Apache `/server-status` 或 `/server-info` 可访问。
- `phpinfo()` 或 `/info.php` 仅在开发/预发布环境可访问。
- JS 中泄露内部 IP / 主机名 / K8s 服务 DNS。
- 错误页面中的 schema 泄露（堆栈跟踪、ORM 特征）。
- Android 应用中 `android:allowBackup=true`。
- Android 应用中 `android:usesCleartextTraffic=true`。
- 导出的 activity/service 未受 `android:permission` 保护。
- API 端点缺少速率限制。
- 返回与用户绑定数据的 API 上存在通配符 CORS（`Access-Control-Allow-Origin: *`）（无凭据）。
- Slack webhook URL 泄露。
- Twilio Account SID 泄露（无 auth token）。
- SPF 记录过于宽松（`+all` 或包含过多 include）。

### 9.4 LOW（低）

表面性或边缘性的加固缺口。

示例：
- 缺少 `X-Frame-Options`。
- 缺少 `X-Content-Type-Options`。
- 暴露 `.DS_Store`。
- Stripe **测试** 密钥泄露。
- Firebase URL 暴露（仅 URL，RTDB 未开放）。
- 移动应用缺少证书固定。
- 检测到过时的 WordPress 安装（尚无已知利用）。
- 未配置 BIMI（仅存在品牌冒充风险）。

### 9.5 INFO（信息）

值得记录，无需立即处置。

示例：
- 缺少 `Referrer-Policy` / `Permissions-Policy`。
- 发现 `/.well-known/security.txt`。
- `robots.txt` 暴露了有意思的路径。
- 存在私有 bucket 但已被锁定。
- 在泄露语料库中检测到该域名，但有 0 个员工账号。
- 未启用 DNSSEC。

### 9.6 严重性升级规则

- 认证/登录/SSO/管理路径缺少 HSTS → **MED → HIGH**。
- 通配符 CORS + 凭据 → **MED → HIGH**。
- 通配符 CORS + 敏感端点 → **LOW → MED**。
- API 端点在兴趣评分准则（配套技能 §20）中得分 ≥70 → 至少 **HIGH**。
- 域名泄露涉及 ≥10 名员工 → 无论数据陈旧与否均为 **CRITICAL**。
- 厂商产品版本匹配 CISA KEV 条目 → **CRITICAL**。
- DMARC `p=reject` + SPF 严格 + DKIM 轮换 → 不升级；姿态良好。

---

## 10. 漏洞赏金 / 红队枢纽模式

既有的调查工作（威胁行为体研究、人肉调查、归因）与攻防侦察的运行姿态不同。要显式切换姿态。

| 方面 | 调查模式 | 攻防侦察模式 |
|---|---|---|
| **探测速率** | 缓慢、单线程、与正常流量融合。 | 突发、并行，但按提供商限速。 |
| **OpSec 姿态** | 仅使用傀儡账号，绝不暴露调查者。 | 角色可以是项目角色；团队可能已通知 SOC。 |
| **证据处理** | 法庭级证据链；哈希、时间戳、截图。 | 项目级；同样的哈希/时间戳规范，但证据用于客户报告。 |
| **范围内严重性** | 所有严重性级别都与上下文相关。 | CRIT/HIGH/MED 重要；LOW/INFO 通常从执行摘要中剔除。 |
| **授权姿态** | 公开记录 / 仅 OSINT；未经授权不探测私有资源。 | 书面作战规则；明确范围；明确的范围外清单。 |
| **报告格式** | 叙述 + 带来源的时间线。 | 按资产的发现 + 修复建议 + 复现步骤。 |
| **停止条件** | 问题得到回答时。 | 项目窗口关闭时，或报告交付时。 |

与用户协作时，如果上下文中不清楚，询问他们处于哪种模式。

### 10.1 基于规模的战术

组织规模决定哪些技术能带来回报。

**小型组织（< 100 人）：**
- 高管账号的重要性不成比例；攻陷一个 CEO/CFO 往往就拿到了钥匙。
- 邮箱收集规模小到可以穷举（总共 10–50 个邮箱）。
- 很可能使用 Microsoft 365 或 Google Workspace；身份结构是单一租户。
- 代码仓库常以个人账号公开在 GitHub 上（创始人从独立开发者转型而来）。
- 云上存在通常是单账号 AWS 或 GCP 项目。
- 战术：对每个邮箱 + 每项身份结构发现都做深入分析；完整 LinkedIn 枚举；检查创始人的个人 GitHub 组织。

**中型组织（100–1K）：**
- 均衡枚举。邮箱清单可枚举但不穷尽。
- 身份结构可能只有一个 IdP，但有多个 SaaS 租户（Slack 工作区、Notion 组织、GitHub 组织）。
- 可能有移动应用；两家应用商店都要检查。
- 云上存在为多账号或多区域。
- 战术：按标准深度执行完整流水线；对每类资产抽样并加深；LinkedIn 按角色排优先级。

**大型组织（1K–10K）：**
- 邮箱枚举开始有损（抽样关键角色）；泄露命中规模上升。
- 多租户身份结构（常为 Entra + Okta + 多个 Auth0 客户）。
- 移动应用、来自不同团队的多个 Android 包。
- 云上存在庞杂；子公司 / 收购使范围复杂化。
- 战术：广度优先；依赖自动化做资产发现；对发现做人工分拣。

**超大型组织（10K+）或集团：**
- 先做品牌枢纽映射：枚举每个品牌域名、每个子公司。
- 泄露语料库占主导：10K+ 员工意味着存在大量历史泄露暴露。
- 身份结构可能因业务单元而异（法律实体边界）。
- 战术：范围裁剪是最重要的一步；全程抽样 + 自动化；仅对高优先级发现做深入分析。

**跨规模原则：** 组织越小，聚焦个人账号越有回报。组织越大，系统性姿态发现（DMARC 缺口、SSO_EXPOSURE 广度、厂商产品版本扫描）越有回报。

---

## 11. 身份结构测绘

组织的 IdP/SSO 姿态是高价值目标：攻陷身份结构后，你无需逐个攻入应用。要系统化地测绘它。

### 11.1 子域名前缀枚举

针对目标的根域名（以及发现的任何同级品牌域名）探测以下前缀：

```
auth.{domain}
login.{domain}
sso.{domain}
idp.{domain}
iam.{domain}
identity.{domain}
accounts.{domain}
oauth.{domain}
```

此外对每个存活子域名做通用 OIDC 发现：
```
{any-host}/.well-known/openid-configuration
```

### 11.2 Microsoft Entra（Azure AD）

- **OIDC 元数据 + 租户 GUID 提取** — 获取 `https://login.microsoftonline.com/{tenant-or-domain}/.well-known/openid-configuration`。`issuer` 字段返回的 URL 中含租户 GUID（8-4-4-4-12 十六进制格式）。租户 GUID + 域名 = 稳定的租户指纹。
- **getuserrealm.srf** — `https://login.microsoftonline.com/getuserrealm.srf?login=<user>@<domain>` 返回 NameSpaceType：`Managed`（云原生）、`Federated`（本地 ADFS / 外部 IdP）或 `Unknown`。可检测性：低。
- **Autodiscover v2** — 用邮箱 POST `https://autodiscover-s.outlook.com/autodiscover/metadata/json/1`；可检测租户成员关系。
- **GetCredentialType**（深模式用户枚举）— POST `https://login.microsoftonline.com/common/GetCredentialType`，请求体 `{"username": "<email>"}`。响应可指示该邮箱是否存在于租户中。可检测性：中。每个租户尝试上限 20 次。

### 11.3 Okta

- **组织 slug 推导** — 从子域名 + 根域名主干推导候选 slug；Okta 租户位于 `<slug>.okta.com`（或 `<slug>.oktapreview.com`）。
- **OIDC 指纹** — `https://<slug>.okta.com/.well-known/openid-configuration`。
- **/api/v1/authn 用户枚举**（深模式）— POST `{"username": "<email>", "password": "invalid"}`。400 与 401 响应码可指示用户是否存在。可检测性：中。每个租户上限 20 次。

### 11.4 ADFS

- **被动指纹** — GET `https://{domain}/adfs/idpinitiatedsignon.aspx` → 200 表示存在 ADFS。
- **主动 mex 端点**（深模式）— `https://{domain}/adfs/Services/Trust/mex` 返回 SOAP 元数据。

### 11.5 Google Workspace

- `https://{domain}/.well-known/openid-configuration` — 使用 Google 托管域名的客户会暴露发现端点，其 issuer/JWKS URI 具有特征性。
- MX 记录指向 `*.googlemail.com` / `aspmx.l.google.com` 是 Google Workspace 的强信号。

### 11.6 通用 OIDC（Keycloak / Auth0 / Ping / OneLogin / Duo）

- 对每个存活子域名探测 `/.well-known/openid-configuration`。
- `issuer` 和 `authorization_endpoint` 字段可指纹识别 IdP 产品。
- `*.auth0.com`、`*.onelogin.com`、`*.pingone.com`、`*.duosecurity.com` 模式具有特征性。

### 11.7 SAML 元数据

对每个存活 webapp 探测以下路径：

```
/saml/metadata
/FederationMetadata/2007-06/FederationMetadata.xml
/federationmetadata/2007-06/federationmetadata.xml
/simplesaml/saml2/idp/metadata.php
/auth/saml2/metadata
```

SAML 元数据 XML 包含：`EntityID`、签名证书、`SingleSignOnService` URL、`NameIDFormat`。

### 11.8 AWS 账号 ID 提取

- **S3 bucket 区域头** — 对已知目标 bucket 做 HEAD 会返回 `x-amz-bucket-region`；结合 bucket 名称的熵来推断账号。
- **JSON / HTML 响应中的 ARN 正则** — 搜索 `arn:aws:[a-z0-9-]+:[a-z0-9-]*:([0-9]{12}):`（捕获组即 12 位 AWS 账号 ID）。
- **JS / API 响应中的 `AccountId` 属性** — 常见于 IAM 相关错误消息和 CloudFormation 输出。
- **OAuth client_id 泄露** — Google OAuth：`<digits>-<chars>.apps.googleusercontent.com`；MSAL：`clientId` 属性中的 GUID。

### 11.9 输出

每个发现的 IdP 都成为一个 `Service` 资产，带 `attrs.product`、`attrs.tenant_id`、`attrs.discovery_endpoint`。随后在阶段 4 与泄露数据关联：已发现租户下每个被攻陷用户都成为一条 SSO_EXPOSURE 发现（CRITICAL——见 §22.3）。

### 11.10 Microsoft 365 深层攻击面

除了普通的 Entra 指纹识别之外，M365 还暴露了更广的攻击面，值得深入枚举。

**Teams 联盟：**

- `https://login.microsoftonline.com/<target-domain>/.well-known/openid-configuration` 可确认租户。
- Teams 联盟状态：`https://teams.microsoft.com/api/mt/<region>/beta/users/<email>/externalsearchv3`（需要来自联盟租户的已认证请求；可用于确认是否允许外部 Teams 聊天）。
- **启用外部聊天** = 软性攻击面（通过 Teams 聊天进行语音钓鱼、短信钓鱼、"来自 IT"的话术）。
- **开放联盟**（任何租户都可聊天）是默认设置；检查目标是否做了限制。

**SharePoint 子域名：**

- `<target-stem>.sharepoint.com` — 主租户 SharePoint。
- `<target-stem>-my.sharepoint.com` — OneDrive for Business URL（每用户个人站点）。
- `<target-stem>-admin.sharepoint.com` — SharePoint 管理中心（需要认证，但存在即可确认租户归属）。
- 其中 `<target-stem>` 由公司名推导而来（通常是 `.com` 之前的部分）。

**OneDrive 个人站点枚举：**

- 每用户 OneDrive URL：`https://<target-stem>-my.sharepoint.com/personal/<user_email_with_underscore>/Documents/`。
- 将邮箱中的 `@` 替换为 `_`、`.` 替换为 `_`（例如 `alice@acme.com` → `alice_acme_com`）。
- 已认证探测；可用于确认 OneDrive 个人站点是否已开通（这本身就是存在性指标）。

**M365 OAuth client_id 发现：**

- 许多内部应用在 Entra 中注册 OAuth client_id。在 JS bundle、移动应用字符串和 API 响应中搜索 `client_id=<GUID>` 模式。
- Microsoft 的知名第一方 client_id（用于 Office、Graph 等）有公开文档；发现非 Microsoft 的 GUID 就暴露了自定义内部应用。
- 端点 `https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration` 列出支持的端点；某些租户将 `device_authorization_endpoint` 保持启用（设备码钓鱼目标）。

**Power Platform / Power Apps：**

- `https://make.powerapps.com/environments`（需要认证）；环境 ID 有时会在 URL 中泄露。
- `*.crm.dynamics.com`（Dynamics 365 / Power Apps 默认 URL）。
- `*.azurewebsites.net` 用于 App Service 部署。

**要关注的 M365 OAuth 错误配置发现：**

- `common` 租户上启用了 `device_authorization_endpoint`（设备码钓鱼目标）→ **MEDIUM**（运营风险；不能直接利用，但为攻击提供了条件）。
- 自定义 OAuth 应用启用了 `Public client` 流程且作用域宽泛（offline_access、Mail.Read、Files.Read.All）→ 若该应用已获租户批准则为 **HIGH**。
- 目标发布的多租户 OAuth 应用（他人可同意授权）→ 检查作用域是否包含敏感的 Graph 权限。

**可检测性：** 所有 M365 端点探测都会记录到 Entra 登录日志 / 审计日志（仅获取信息为低-中；任何认证尝试为中）。

---

## 12. API 与认证映射方法论

现代目标会暴露 REST、GraphQL 和未公开的内部 API。OSINT 的目标是枚举它们、对它们分类，并按攻击兴趣排序。

### 12.1 发现路径

- **Swagger / OpenAPI** — 对每个存活 webapp 探测 28 路径字典（配套技能 §16.1）。解析 YAML/JSON；提取每个端点（方法 + 路径）。
- **GraphQL** — 探测 13 路径字典（配套技能 §16.2）。POST 标准 introspection 查询。如果返回 schema，你就获得了完整的类型/查询/mutation/subscription 枚举。
- **introspection 被禁用时的 GraphQL** — 回退到字段建议枚举（配套技能 §22.9）。
- **Postman** — 用目标名称查询 Postman 的公开通用搜索端点；遍历每个匹配的工作区；提取请求、头部、前置脚本、测试脚本、环境变量。
- **从 JS 提取的端点** — 从 JavaScript bundle 提取的每个端点都进入同一分类器。
- **从移动端提取的端点** — 通过旁挂文件（`mobile_endpoints.json`）把 APK 静态分析得到的每个端点汇入。

### 12.2 分类

对每个端点捕获：

```
url, method, source[], auth_required, auth_type, auth_location,
rate_limited, cors_policy, sensitive_path_keywords[], schema_leaks,
verb_tampering_possible, interest_score (0..100), interest_reasons[]
```

各字段的判定方法：
- 发送 `OPTIONS` → `Allow` 头会揭示支持的方法（动词篡改检查）。
- 不带认证发送 `GET` → 200 = `auth_required=false`；401/403 = `auth_required=true`。
- 捕获响应头中的 `WWW-Authenticate`（auth_type）、`RateLimit-*` / `X-RateLimit-*`。
- 带 `Origin: https://attacker.example` 发送请求 → 响应中的 `Access-Control-Allow-Origin` 被反射 = `cors_policy=reflected`。
- 触发错误 → 检查响应中是否有堆栈跟踪、ORM 特征。

### 12.3 兴趣评分（0–100）

完整评分准则见配套技能 §20。**评分 ≥ 70 → HIGH/CRITICAL 发现**，并在证据中附 `attack_path_hint`。

### 12.4 攻击路径提示

在输出 HIGH/CRITICAL 发现时，在证据中包含一句攻击路径提示，让操作者知道从哪里开始利用。模板见配套技能 §39。

---

## 13. JavaScript 深度分析

对每个存活 webapp 抓取其 JS——现代前端正是在这里泄露信息。

### 13.1 脚本发现

- 解析 HTML 中的 `<script src="...">` 和 `<link rel="modulepreload" href="...">`。
- 对常见打包器的猜测路径列表（配套技能 §16.9）进行探测。

### 13.2 Sourcemap 检测（HIGH 信息泄露）

- 内联引用：bundle 末尾的正则 `//[#@]\s*sourceMappingURL=`。
- 同级获取：对每个发现的 JS 尝试其旁边的 `<bundle>.map`。
- 如果可访问：解析 sourcemap 的 `sources[]`（泄露仓库结构）和 `sourcesContent[]`（内嵌完整原始源码）。对 `sourcesContent[]` 运行机密目录扫描。
- 严重性：HIGH `INFO_DISCLOSURE`。

### 13.3 机密扫描

对每个 JS 正文和每个已解析的 `sourcesContent[]` 数据块运行 29+ 模式目录（配套技能 §17）。每个命中 = 一条 `SECRET_LEAK` 发现，严重性按目录中该模式的定义。

### 13.4 端点提取

三层正则（配套技能 §16.10）。每个唯一端点都成为一个 `wayback_endpoint` 资产，并汇入 §12 的 API 分类器。

### 13.5 内部主机泄露检测

三种模式（配套技能 §16.11）：RFC1918、内部 DNS 后缀、K8s 服务 DNS。每个匹配 = MEDIUM `INFO_DISCLOSURE`。

### 13.6 GraphQL introspection 探测

当提取到的端点以 `/graphql` 或 `/graphiql` 结尾时，POST 标准 introspection 查询。若返回 schema → HIGH `MISCONFIG`。随后为高价值目标枚举 mutation 和 subscription。

### 13.7 Next.js 清单解析

`_buildManifest.js` 和 `_ssgManifest.js` 枚举每个 Next.js 页面路由——暴露应用完整的路由结构。

### 13.8 预算指引

- 每个项目分析的 webapp 上限：默认 40，`--deep` 时 120。
- 每个 webapp 的 JS 文件上限：默认 40，`--deep` 时 80。
- 单个 JS 文件大小上限：2 MiB。
- 单文件超时：10 秒。

---

## 14. 移动端攻击面

移动应用往往是最薄弱的环节。

### 14.1 应用发现

- **Android** — google-play-scraper。按公司名、品牌关键字、根域名主干搜索。
- **iOS** — iTunes Search API。

### 14.2 归属置信度（0–100）

见配套技能 §21。深度分析阈值：**≥70**。

### 14.3 APK 获取 + 静态分析

- 通过 APKPure HTML 抓取下载。
- 通过 `zipfile` + 可选的 `androguard` 提取。
- 提取：`AndroidManifest.xml`、资源字符串、asset 文件、原生 `.so` 文件、`classes*.dex`（字符串提取）。

### 14.4 机密扫描

对 manifest、资源、asset 文件、dex 字符串提取结果运行目录扫描。

### 14.5 后端主机名提取

每个发现的主机名都成为一个 `subdomain` 资产。写出旁挂文件 `mobile_endpoints.json` 供 API 发现模块消费。

### 14.6 Manifest 错误配置发现

| Manifest 属性 | 严重性 |
|---|---|
| `android:debuggable="true"` | CRITICAL |
| `android:allowBackup="true"`（无白名单） | MEDIUM |
| `android:usesCleartextTraffic="true"` | MEDIUM |
| 导出的 activity/service/receiver 未受 `android:permission` 保护 | MEDIUM |
| 敏感 deep-link 处理器 | HIGH |
| WebView 启用 `setJavaScriptEnabled(true)` + `addJavascriptInterface(...)` | HIGH |
| 缺少证书固定 | LOW |

### 14.7 Firebase 规范探测

对每个提取到的 Firebase 项目 ID：
- **Realtime DB** — GET `https://{project-id}.firebaseio.com/.json`。返回 JSON 树 → CRITICAL `OPEN_FIREBASE_RTDB`。
- **Firestore** — `https://{project-id}.firebaseapp.com/`。
- **Storage** — 对应的 GCS bucket。
- **Remote Config** — 仅在拥有提取到的 API key + app ID 时可读。

### 14.8 iOS 路径

- 仅通过 iTunes Search API 发现。
- ITMS 链接提取：`https://apps.apple.com/<region>/app/<slug>/id<bundle-id>`。
- 隐私营养标签（App Store Connect）：公开发布；有助于了解应用会接触哪些数据。
- 不建议自动下载（DMCA / DRM 方面的考虑）。

---

## 15. 云攻击面

### 15.1 Bucket 排列组合

从以下内容构建候选 bucket 名：目标的根域名、子域名主干、可选的品牌/公司名。过滤通用主干，除非与目标标识性 token 组合。应用 6 个前缀 × 15 个后缀（列表见配套技能 §16.8）。

### 15.2 提供商 URL 模板

S3、GCS、Azure Blob 模板——见配套技能 §16.8。

### 15.3 探测技术

- 先 HEAD。状态码 200/301 = 存在；403 = 存在但私有；404 = 跳过。
- 如果存在，对 bucket 根做 GET。可列举的 XML/JSON 列表 → **CRITICAL**。

### 15.4 严重性映射

| 结果 | 严重性 |
|---|---|
| Bucket 可列举 | CRITICAL |
| Bucket 存在，对象可通过直接 URL 读取但不可列举 | HIGH |
| Bucket 存在，ACL 私有 | INFO |

### 15.5 关联云信号

从 S3 区域/错误响应中提取 AWS 账号 ID。从 GCS 错误响应中提取 GCP 项目 ID。从 blob URL 模式中提取 Azure 租户 ID。

---

## 16. 加密货币调查

### 16.1 交易分析

- 追踪钱包之间的流向；识别相关地址集群；监控大额转账。

工具：Cielo（多链）、TRM（图谱）、Arkham（多链 + 实体标签）、MetaSleuth（可视化）、Range（CCTP）、Socketscan（EVM 跨链桥）、Pulsy（跨链桥聚合器）、Chainalysis Horizon 2.0（付费）、Elliptic Lens。

### 16.2 二层 / Rollup 分析

- **zkSync Era / Polygon zkEVM** — ZK 证明隐藏 L2 细节；只能看到 L1 跨链桥事件。
- **Arbitrum / Optimism** — 批量/压缩；L2 状态来自 L1 calldata。
- **StarkNet** — Cairo VM；地址推导方式不同。
- **Base / Blast / Scroll** — OP Stack 或 ZK。
- **L2 上的隐私协议** — Aztec（可编程隐私）、Railgun（屏蔽池）、Privacy Pools（Tornado Cash 的继任者）。

**方法论：** 从 L1 跨链桥事件开始；用 L2 浏览器查看 rollup 内部活动；对隐私协议重点关注时序分析和聚类。

### 16.3 注意事项

- 跨链桥引入铸造/销毁语义；避免 1:1 流向假设。
- MEV/聚合器路径会造成虚假的"直接"痕迹。
- L2 最终性：乐观 rollup 有 7 天挑战期。

### 16.4 钱包 / 交易所 / NFT 画像

同样的模式：存续时间 + 活动 + 连接关系 + 余额变化 + 关联账号。NFT 还增加所有权历史 + 元数据 + 关联钱包。

---

## 17. 图像分析

### 17.1 反向图像搜索

- Google Images / Lens（Lens 可能需要认证——使用傀儡账号的无痕模式）。
- Yandex Images（对俄罗斯/东欧内容效果最强）。
- Bing Image Match、TinEye、Copyseeker、Perplexity Pro。
- 浏览器扩展：RevEye、Search by Image（多引擎）。
- Picarta 用于 AI 地理定位。

### 17.2 元数据（EXIF）

ExifTool、Jeffrey's Image Metadata Viewer、EXIF Viewer Pro。

### 17.3 图像取证

Forensically、FotoForensics、Bellingcat Photo Checker、Sensity AI、Exposing.ai、Adobe Content Credentials Verify、c2patool。技术：ELA、元数据、克隆检测、噪声分析。

### 17.4 地理定位工作流

- **前景** — 标牌、车牌、衣着、植被、天气。
- **背景** — 地标、独特建筑、山脉、水域、基础设施。
- **地图标记** — 植物/动物、季节性指示物。
- **试错** — Google Street View、Bing Streetside、Yandex Panorama。
- **Overpass Turbo** 用于 OpenStreetMap 查询。
- **山峰识别** — PeakVisor、Peakfinder、PeakLens AR。
- **OCR** — Google 或 Yandex OCR。
- **视频转录** — YouTube 字幕可提升关键字搜索效果。

### 17.5 专用工具

- **火灾识别** — NASA FIRMS、Sentinel Hub、Global Forest Watch、Copernicus EFFIS。
- **飞机追踪** — Apollo Hunter、FlightRadar、ADS-B Exchange。

---

## 18. 视频分析

### 18.1 上下文提取

标牌/横幅、建筑、道路标线、车牌、衣着，以及跨平台片段搜索。

### 18.2 元数据

YouTube Data Viewer（Amnesty）、对下载文件使用 ExifTool。

### 18.3 平台特定方法

- **TikTok / Instagram** — API 经常变化；优先使用平台导出；按 1–4 小时的节奏采样。
- **Bluesky AT Protocol** — 通过 `bsky.social/xrpc/com.atproto.identity.resolveHandle` 解析 DID；通过 `plc.directory/<did>` 获取身份文档；firehose 在 Firesky；图谱用 SkyView。尽早归档——应对 handle 迁移 / 帖子删除。
- **Mastodon / Fediverse** — 实例很重要（司法辖区、日志记录）；用 WebFinger 做发现；FediSearch 跨实例搜索；通过 Fediverse Observer 做实例枚举；ActivityPub 对象是 JSON-LD。
- **Threads** — 与 IG API 类似的限制。

### 18.4 听觉线索

语言、方言、背景噪声（火车汽笛、礼拜召唤、野生动物）。工具：Audacity、Sonic Visualiser、SoundCMD。用频谱图识别独特模式；用 Shazam/SoundHound 识别音乐。

### 18.5 帧提取

FFmpeg、VLC。拼接全景；稳定平移镜头（FFmpeg `deshake` 或 Blender VSE）。优先使用原始上传而非二次转码。

---

## 19. 时空定位与时间分析

### 19.1 阴影分析

工具：SunCalc、ShadeMap、Bellingcat Shadow-Finder、NOAA Solar Calculator。

### 19.2 天文计算

Stellarium、SkyMap、MoonCalc，用于模拟不同时间/地点的天空。

### 19.3 卫星影像时间

Google Earth Pro（历史影像滑块）、Sentinel Hub EO Browser（Sentinel + Landsat，支持延时）。用 WKT 记录坐标；对缓存的瓦片集计算哈希。

---

## 20. 威胁行为体调查

### 20.1 以行为体为中心的工作流

- **界定范围** — 行为体假设（APT28/29、Turla、Sandworm；APT10/41、Mustang Panda、Volt Typhoon）。以 CERT/厂商报告作为种子。
- **指标收集** — IOC（域名、IP、哈希、JA3/JA4、user-agent）。用被动 DNS、CT 日志、沙箱提交进行验证。
- **基础设施测绘** — 从 CT 日志（SAN、签发者、序列号）、共享托管、NS 复用、注册商账号、HTML 指纹出发做枢纽。用 ASN/WHOIS 历史、RPKI/ROA、地理定位做富化。
- **产物画像** — PE/ELF 元数据（PDB 路径、编译时间戳、Rich 头、代码签名）。用 SSDEEP/TLSH 聚类；匹配 YARA。
- **社交 / 采购枢纽** — 开发者账号、代码片段、学术论文、招聘帖、采购记录。
- **证伪 + 报告** — 权衡每一处关联；记录替代解释；把 TTP 映射到 MITRE ATT&CK；引用来源时标注章节/页码。

### 20.2 归因规范

- 把能力与意图和背景支持分开。
- 三条规则：3 个弱信号，或 1 个强信号 + 1 个弱信号。
- 优先使用可长期存续的枢纽（注册商账号、代码签名证书、构建路径习惯），而非易失性的（可解析的 IP）。
- 标注不确定性等级；区分相关性与控制力。

### 20.3 俄罗斯特定枢纽

- **企业 / 人员** — EGRUL/EGRIP（有验证码拦截）、Rusprofile、Kontur.Focus、zakupki.gov.ru、hh.ru。
- **基础设施** — 通过 `whois.tcinet.ru` 查俄罗斯 WHOIS；Telegram 用于频道/管理员/交叉转发。
- **媒体** — VKontakte、Odnoklassniki、Rutube；用俄语和转写形式搜索。

### 20.4 中国特定枢纽

- **企业 / 人员** — gsxt.gov.cn（国家企业信用信息）；天眼查 / 企查查；beian.miit.gov.cn 上的 ICP 备案 → USCC 关联。
- **基础设施** — CNNIC WHOIS；常见国内云（阿里云、腾讯云、华为云）。
- **媒体** — 微博、微信（通过 weixin.sogou.com）、知乎、Bilibili、抖音、小红书；用中文 + 拼音。

### 20.5 基础设施与互联网测量

- IP→ASN（HE BGP Toolkit、RIPEstat、BGPView）。
- CT 日志（crt.sh）用于证书复用和签发节奏；以主体/签发者/序列号做枢纽。
- URLScan 用于 HTML 指纹、favicon（mmh3）、脚本哈希。
- 时间维度上的 DNS（SecurityTrails PDNS、DNSDB）用于子域名更替和预发布域名。

---

## 21. 人员与社交媒体调查

### 21.1 用户名枚举

WhatsMyName、NameCheckup、Sherlock、Maigret。

### 21.2 头像与人脸搜索

PimEyes、Exposing.ai、Azure Face API（合规性）。

### 21.3 社交图谱与内容分析

Maltego、snscrape、SocialBlade。Bluesky / Mastodon：实例浏览器 + handle 解析器。

---

## 22. 泄露 × 身份关联

这是外部红队 ROI 最高的单项技术。每个项目都要执行。

### 22.1 来源栈

| 来源 | 层级 | 说明 |
|---|---|---|
| **Hudson Rock Cavalier** | 免费 | 信息窃取器日志语料库；对企业 SSO 信号极强。 |
| **Have I Been Pwned** | 免费 + 付费 | 域级存在性检查 + Pwned Passwords（k-匿名）。 |
| **DeHashed** | 付费 | 可按记录搜索的 API。 |
| **IntelX** | 免费 + 付费 | 聚合器；电话簿搜索。 |
| **本地泄露语料库** | 操作者提供 | 磁盘上现有的任何数据。 |

### 22.2 域级严重性

| 统计 | 严重性 |
|---|---|
| ≥10 名员工被攻陷 | CRITICAL |
| 1–9 名员工被攻陷 | HIGH |
| ≥1 名终端用户（非员工）被攻陷 | MEDIUM |
| 域名出现在泄露中但有 0 个具名账号 | INFO |

### 22.3 SSO_EXPOSURE 关联

在阶段 3 已执行身份结构测绘 **且** 泄露查询已完成之后：对每个已发现的 IdP 租户，与该租户域名在泄露语料库中求交集。交集非空 → `SSO_EXPOSURE` 发现，严重性 **CRITICAL**。证据：租户 ID + 产品 + 员工数 + 逐账号来源归属。

### 22.4 窃取器日志的运营处理

- 当作 PII 处理；静态加密。
- 对每个产物计算 SHA-256；记录来源 URL + 获取时间戳。
- 绝不把明文密码粘贴到云端 LLM。
- 记录证据链。
- 客户报告：默认对密码做脱敏；另行为操作者提供单独的加密凭据包以承载原始数据。

---

## 23. 基础设施 OSINT

### 23.1 IP 与域名发现

Shodan、Censys、Onyphe、DNSDB。

### 23.2 证书与被动 DNS

crt.sh、SecurityTrails。

### 23.3 恶意软件与产物分析工作流

- **静态分拣** — SHA-256、strings、导入表、PDB 路径、Rich 头。不要仅依赖 AV 标签。
- **动态 / 沙箱** — ANY.RUN、Hybrid Analysis、CAPE、Tria.ge。
- **聚类** — SSDEEP/TLSH、YARA 匹配。
- **报告** — STIX 2.1 IOC；ATT&CK 技术 ID；复现步骤。

### 23.4 Telegram / 微信调查

- **Telegram** — 公开分析平台（TGStat、Telemetr、Combot）；用 Telegram Desktop 导出频道；保留消息 ID、UTC 时间戳、媒体哈希。
- **微信** — 搜狗微信搜索；归档文章（PNG + WARC）；捕获 `__biz` ID。预期链接会失效。

---

## 24. 自动化与案件管理

### 24.1 工具

Hunchly、Kasm Workspaces、ArchiveBox、SingleFileZ。

### 24.2 跨模块协同模式

当多个 OSINT 工具（或模块）同时运行时，后来到达的输出需要馈入更早启动的消费者。三种模式：

1. **旁挂 JSON 落盘** — 模块写入 `<scan>/mobile_endpoints.json` 或 `<scan>/secrets_sidecar.json`；后续模块启动时读取。无阻塞。
2. **资产图 upsert** — 共享图存储；新资产通过事件总线触发下游模块。
3. **延迟绑定队列** — 长时间运行的枚举持续产出资产；富化工作进程拉取。

在临时项目中：`tmpdir + JSON 旁挂文件 + 一行清单` 就能让操作可组合。

### 24.3 多引擎语料库运行方法论

跨多个引擎运行大型 dork 语料库：

- **可插拔引擎** — 把每个引擎（DDG、Bing、Brave、SerpAPI、Yandex、Baidu）封装在统一接口之后。默认 DDG（免密钥）；有密钥时回退到其他引擎。
- **按引擎限速** — 每个引擎有自己的配额和封禁姿态。每个引擎使用一个令牌桶。
- **结果分类** — URL 签名 → 标题线索 → 摘要正则的流水线。输出：`(severity, category, confidence)`。
- **按 URL 去重** — 不同引擎会暴露重复项。
- **置信度规则** — 仅凭摘要片段 = TENTATIVE。
- **持久化** — 语料库 DB，使跨项目重跑时能去重。

### 24.4 攻防项目的证据保存

- 每个项目 / 每次扫描使用一个 SQLite 存储。
- JSONL 运行日志带 `run_id`，每个事件一行，UTC 时间戳，命令行版本。
- 对每个下载的产物计算 SHA-256。
- PNG 截图。
- 原始 HTTP 请求/响应，每侧正文上限 2 KiB。
- 证据从操作者机器以只读方式提供。
- 复现包：`run_id` + 命令行版本 + JSONL 日志 + 资产/发现 DB。

---

## 25. 合成媒体验证

Sensity AI、Hive Moderation、Reality Defender、Adobe Content Credentials Verify、CarNet（AI 车型识别，用于辅助地理定位）。

---

## 26. 反模式与常见失败模式

以下是经常出现的错误的非完整清单。

- **单一来源归因。** 用三个弱信号，或一个强信号 + 一个弱信号。
- **把厂商标签当作事实真相。** 把标签当作假设。
- **把 favicon 哈希当作归属。** 可能是共享基础设施、共享 CMS 模板、共享 CDN。
- **断言 1:1 的跨链桥流向。** 跨链桥铸造和销毁；聚合器会再平衡。
- **把仅摘要片段的 Google dork 当作已确认。** 在访问之前都是 TENTATIVE。
- **把真实 PII / 凭据粘贴到云端 LLM。** 敏感分析使用本地模型。
- **镜像投射威胁行为体。** 他们的思考方式与你不同。
- **靠 IP 地理定位归因。** IP 会说谎；VPN 和住宅代理无处不在。
- **忽略 7 天乐观 rollup 挑战窗口。** L2 最终性是延迟的。
- **忽略 CT 日志延迟。** 新证书需要数分钟到数小时才会显现；不存在 ≠ 没有。
- **把 Wayback 快照当作"时刻 T 的站点"。** 这是尽力而为；很多请求会失败。
- **信任从已发现 API 得到的 `whoami`。** 可能是蜜罐。
- **让资产图承载无类型字符串。** 每项发现都是资产。
- **跳过范围检查。** 存疑时询问一次。
- **忘记 UTC。** 本地时间会造成关联错误。
- **在 WAF 封锁后继续探测。** 见 §6.4——退避。
- **跳过置信度升级记录。** TENTATIVE 资产需要一条通往 CONFIRMED 的路径。
- **把执行摘要写作当作事后工作。** 见 §31——在项目开始时就规划交付物，而不是在结束时。

---

## 27. WAF / CDN 绕过与源站发现

Web 目标越来越多地位于 Cloudflare / Akamai / Fastly / AWS CloudFront 之后。CDN 本身难以攻击；**源站服务器**的防御往往较弱。以下六种技术可找到它。

### 27.1 DNS 历史枢纽

在部署 CDN **之前**，目标的域名可能直指源站 IP。查询历史被动 DNS：

- **SecurityTrails** — `https://api.securitytrails.com/v1/history/<domain>/dns/a`（付费；最完整）。
- **RiskIQ PassiveTotal** — 被动 DNS 查询；免费增值。
- **DNSDB**（Farsight）— 付费；历史长。
- **Validin.com** — 较新，有免费层。
- **Censys 主机搜索** — 历史 IP-证书映射。

要找什么：一个在 1–5 年前解析过、且**不在**当前 CDN 公布的 IP 范围内的 IP（Cloudflare / Akamai 等）。交叉核对该 IP 当前的 banner——如果它在没有 CDN 的情况下提供同一站点，你就找到了源站。

### 27.2 证书 SAN 枢纽

证书常常在源站和 CDN 之间以相同 SAN 列表重新签发。搜索 CT 日志：

- crt.sh `?q=%.<target.com>&exclude=expired` — 查找 SAN 中含目标域名的证书。
- 将签发的证书与当前 CDN 前置的证书交叉比对。"多余"的那张证书（不是 CDN 那张）常通过其 CN/SAN 指向源站。
- 像 `cero`（`go install github.com/glebarez/cero@latest`）这样的工具会爬取 IP 并拉取证书；把证书中包含目标主机名的 IP 关联起来。

### 27.3 Favicon 哈希 + JARM 源站聚类

如果目标有独特的 favicon，源站服务器仍会提供它（CDN 做代理但不会剥掉 favicon）。计算 favicon 的 mmh3 哈希并搜索：

- Shodan：`http.favicon.hash:<mmh3-hash>`。
- Censys：`services.http.response.favicons.hashes:<mmh3-hash>`。

返回的**不在** CDN 范围内的 IP 即为源站候选。

JARM（TLS 握手哈希）同理：用 `jarm` 计算目标的 JARM，搜索 Shodan `ssl.jarm:<jarm-hash>`。源站服务器通常与 CDN 的 JARM 不同。

### 27.4 带 Host 头的直接 IP 探测

如果你从步骤 27.1–27.3 得到了一个源站候选 IP：

```bash
curl --max-time 30 --connect-timeout 10 -sk -H "Host: target.example.com" https://<candidate-IP>/
```

如果响应与公开站点匹配（相同标题、相同正文指纹）——你找到了源站。仅 CDN 的 IP 会返回通用 CDN 错误页，或对错误 Host 返回 403。

### 27.5 mail.* / ftp.* / cpanel.* 例外

目标常常忘记把辅助子域名放到 CDN 之后：

- `mail.<target>` — 常指向实际邮件服务器，有时与 Web 源站同址。
- `ftp.<target>`、`sftp.<target>` — 同理。
- `cpanel.<target>`、`whm.<target>`、`webmail.<target>` — 共享托管控制面板；与 Web 源站同一 IP。
- `direct.<target>`、`origin.<target>`、`direct-connect.<target>`、`noproxy.<target>` — 带讽刺意味的管理标签。
- `dev.<target>`、`staging.<target>` — 开发环境常常跳过 CDN。

逐个探测。如果任何一个解析到非 CDN IP，该 IP 往往也承载生产源站。

### 27.6 错误页面 / 错误配置泄露

当 CDN 抛出错误时（请求触发 WAF、源站宕机、配置不匹配），它有时会在错误正文中泄露源站 IP：

- Cloudflare 5xx 错误页面历史上会包含 `cf-ray`，有时还包含底层上游细节。
- 来自 CDN 的 502/504 说明源站存在但从 CDN 无法达——可用于确认这不只是 NXDOMAIN。
- `X-Cache: MISS from <origin-host>` 头。
- 响应中透出源站头（`X-Powered-By`、`Server`、`X-Backend-Server`）。

### 27.7 邮件头退信技巧（用于邮件服务器源站）

向目标的不存在地址发送一封邮件。退信往往会在 `Received:` 头中暴露源站邮件服务器 IP——这些邮件服务器有时与 Web 源站位于同一 IP / 网段。（使用傀儡邮箱；绝不要用你真实的项目角色。）

### 27.8 置信度规则

- 通过 DNS 历史发现的源站 IP：在被直接探测印证之前为 **TENTATIVE**。
- 通过 Host 头探测内容匹配印证的源站 IP：**FIRM**。
- 通过 Host 头探测 + 证书 SAN 匹配 + favicon 匹配印证的源站 IP：**CONFIRMED**。

存疑时，把假设记录在资产 attrs 中——没有 ≥2 个印证信号就不要宣称发现了源站。

---

## 28. 漏洞优先级排序（CVE / EPSS / KEV）

一次 Nuclei 扫描可能针对目标返回 100+ 个 CVE。你无法全部验证。按可利用性排序。

### 28.1 数据来源（URL 见配套技能 §29.2）

- **NVD**（National Vulnerability Database）— 基础 CVE 目录、CVSS 评分。
- **EPSS**（Exploit Prediction Scoring System）— 未来 30 天内被利用的概率，取值 0.0–1.0。
- **CISA KEV**（Known Exploited Vulnerabilities）— 已被证明在野利用的漏洞；包含联邦机构的整改截止日期。
- **ExploitDB** — POC 代码是否存在。
- **Metasploit 模块目录** — 自动化是否可用。
- **InTheWild.io** — 社区维护的"正在被利用"追踪器。
- **OpenCVE** — 时间线 + 关注列表 + 告警。
- **Trickest CVE → POC 映射** — 社区维护的 CVE 到公开 POC 的映射。

### 28.2 优先级评分准则

对清单中的每个 CVE 打分：

| 信号 | 权重 |
|---|---|
| 列入 CISA KEV | **+50**（已证明被利用；视为立即处理） |
| EPSS 评分 ≥ 0.7 | **+30** |
| EPSS 评分 0.3–0.69 | **+15** |
| 存在公开 Metasploit 模块 | **+25** |
| ExploitDB / GitHub 上有公开 POC | **+15** |
| 厂商发布公告 + 补丁 | **+10**（说明漏洞真实且可修补；但不总能利用） |
| 需要认证 vs 无需认证 | 无需认证 +20，认证后 +0 |
| 网络向量（network）vs 相邻 / 本地 | network +15，相邻 +5，本地 +0 |
| CVSS v3 基础分 ≥ 9.0 | **+15** |

**总分 → 优先级层级：**

| 分数 | 层级 | 行动 |
|---|---|---|
| ≥ 100 | P0 | 立即验证；现在就在项目摘要中呈现。 |
| 70–99 | P1 | 本次项目内验证；纳入技术报告。 |
| 40–69 | P2 | 在技术报告中提及；时间允许则验证。 |
| < 40 | P3 | 列入附录；不预期验证。 |

### 28.3 验证规范

- **验证** = 运行单个只读证明（例如版本 banner 检查、确认存在易受攻击组件的静态页面获取），**不**触发利用。
- **不要**运行实际利用，除非作战规则明确允许。许多漏洞赏金项目禁止对生产环境执行 PoC。
- 对客户项目：交付带复现命令的优先级清单，但如需实际利用，则推迟到后续评估。

### 28.4 处理无 CVE 的发现

许多真实发现（sourcemap 暴露、开放 GraphQL introspection、公开 bucket）没有 CVE。按它们独立的兴趣评分打分（端点见配套技能 §20；严重性映射示例见 §40）。不要以是否有 CVE 作为门槛。

---

## 29. 钓鱼基础设施与话术编排

授权的红队项目常常包含钓鱼。钓鱼的 **OSINT 一侧**——构建钓鱼可行性候选清单和话术清单——在此范围内。制作实际的钓鱼 payload 属**范围之外**（属作战手法、不同领域）。

### 29.1 钓鱼可行性候选清单

对于授权项目，操作者通常需要三份清单：

**A. 已注册的仿冒域名** — 这些是*发现*（有人在抢注；客户应当知道）。

**B. 可注册的仿冒域名** — 这些是本项目的*操作者钓鱼域名候选清单*。

**C. 证书 SAN 冒充模式** — 操作者可以注册、并能签发可信证书的域名（例如 `acme-secure.com`、`acme-login.com`、`acme-vpn-portal.com`）。

**生成模式：**
1. 对目标主域名运行 dnstwist（或等效工具）→ 获得所有变体（同形异义、错拼、位翻转、连字符、增字）。
2. 对每个变体查 WHOIS：已注册 = 清单 A，未注册 = 清单 B。
3. 对清单 C：把目标主干 + 可信的服务词组合（`secure`、`login`、`vpn`、`portal`、`mail`、`helpdesk`、`it`、`account`、`verify`、`support`、`password`、`auth`、`sso`）。

### 29.2 利用子域名接管做可信域名钓鱼

如果你发现了可接管的子域名（配套技能 §16.12），你可以在**真实目标的子域名上**托管钓鱼内容。这会绕过用户拥有的所有品牌冒充防御。

**步骤：**
1. 在候选上确认接管特征（`<sub>.target.com` 被 CNAME 到未被认领的 `<x>.herokuapp.com`）。
2. 注册未被认领的资源（在 Heroku 上注册 `<x>.herokuapp.com`）。
3. 现在 `<sub>.target.com` 在提供你的内容。
4. **在上线钓鱼内容之前停下来咨询项目负责人。** 即使在授权项目中，接管这一步本身也可能需要客户明确签字同意。

### 29.3 邮件伪造可行性

用邮件安全分析（配套技能 §16.14）判定伪造可行性：

| SPF 策略 | DMARC 策略 | 伪造可行性 |
|---|---|---|
| `~all`（softfail）或缺失 | `p=none` 或缺失 | **高** — 直接伪造 `<anything>@<target>` 很可能成功投递。 |
| `~all` | `p=quarantine` | 中 — 会进垃圾邮件文件夹，但能投递。 |
| `-all`（hardfail） | `p=quarantine` | 低 — 大多数提供商会拒绝；部分仍会投递到垃圾箱。 |
| `-all` | `p=reject` | 极低 — 主要提供商都会拒绝伪造。需要相似域名。 |

如果伪造困难，回退到相似域名（清单 B）或被攻陷的第三方（属不同项目）。无论如何都要记录该姿态发现。

### 29.4 基于 OSINT 的话术编排

话术之所以有效，是因为它利用了目标已有的情境。用收集到的 OSINT 构建话术。

**话术来源：**

- **职位 + 汇报关系**（LinkedIn）— "您好 <name>，我是 <CFO-name> 的助理；能看一下这份财务文件吗？"
- **近期企业事件**（新闻稿、新闻、招聘页面）— "我们是来跟进裁员 / 新收购的；请确认您的福利信息。"
- **供应商关系**（提及"有 Workday/Salesforce 等经验"的招聘帖）— "Workday 密码需在今日下班前重置。"
- **公开会议 / 行程**（LinkedIn 帖子、会议页面）— "您好 <name>，我们上周在 <会议>见过；跟进一下我们讨论的内容。"
- **GitHub 提交 / 开源工作** — "我看到你在 <repo> 里的修复；想一起做个相关 PR 吗？"
- **办公地点**（LinkedIn）— "<city> 办公室的现场 IT 需要做一次快速认证检查。"

**按角色的话术模板**（操作者最常用的）：

- **终端用户（普通员工）：** IT 服务台密码重置、Workday 人力资源待办、Microsoft 365 存储已满、包裹投递确认。
- **高管：** 财务权限（BEC 式"需要审批一笔转账"）、董事会材料共享、并购 NDA 审阅、行政助理请求。
- **开发者 / 工程师：** GitHub 安全告警、CI 构建失败、包安全公告、会议 CFP 跟进。
- **HR / 财务：** 薪资供应商变更、报销被拒、福利登记截止、供应商发票差异。
- **IT / 安全：** 供应商安全更新通知、值班升级、监控命令行告警。

### 29.5 钓鱼基础设施的运营规范

- 所有钓鱼基础设施在上线**之前**必须经项目负责人批准。
- 记录注册的每个域名 + 发送的每封邮件（发件人、收件人、主题、UTC 时间戳）。
- 把钓鱼基础设施与常规侦察基础设施隔离（不同 IP、不同角色、不同域名注册商账号）。
- 钓鱼域名注册使用专用支付方式（项目专用企业卡；不要用个人的）。
- 项目结束后及时拆除；转移/过期所有域名；关闭所有托管账号。

---

## 30. 漏洞赏金提交与负责任披露

当你在一家漏洞赏金目标（HackerOne、Bugcrowd、Intigriti、YesWeHack）上发现问题，或在一个没有项目的目标上发现问题并选择负责任披露时。

### 30.1 平台特定要点

| 平台 | URL | 说明 |
|---|---|---|
| HackerOne | hackerone.com | 规模最大；范围追踪强；基于 CVSS 的赏金计算。 |
| Bugcrowd | bugcrowd.com | 用 VRT（Vulnerability Rating Taxonomy）而非 CVSS 评定严重性。 |
| Intigriti | intigriti.com | 在欧洲较强；范围模型灵活。 |
| YesWeHack | yeswehack.com | 总部在欧洲；成长中。 |
| HackenProof | hackenproof.com | 专注加密/区块链项目。 |
| Open Bug Bounty | openbugbounty.org | 对没有官方项目的站点免费（仅披露 XSS/SSRF）。 |
| security.txt | rfc9116 | 通用：每个站点都应发布 `/.well-known/security.txt`。 |

### 30.2 报告结构（适用于任何平台）

```
Title: [Severity] [Affected component] Brief description
   Example: [HIGH] [api.acme.com] Unauthenticated SSRF via /v1/proxy

Summary
   2-3 sentences explaining what was found and why it matters.

Steps to Reproduce
   1. Numbered, copy-pasteable.
   2. Include exact URLs, payloads, expected vs actual response.
   3. Reproduce the issue from a fresh state where possible.

Proof of Concept
   - Screenshot showing the vulnerability triggered.
   - HTTP request/response (sanitize sensitive data; redact other users' data).
   - Or short video/GIF for complex multi-step issues.

Impact
   Quantify: what data is at risk, how many users, what business functions break.
   Tie to the program's impact criteria where defined.

Severity (per program criteria)
   - CVSS v3 vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
   - Score: 9.8 (Critical)
   - Justification: <1-2 sentence reasoning>

Remediation
   - Concrete recommendation. "Validate the URL parameter against an allowlist before fetching."
   - If a quick fix: WAF rule, header check.
   - If a structural fix: refactor recommendation.

Affected component
   - URL: https://api.acme.com/v1/proxy
   - Date discovered: 2026-04-27 14:23 UTC
   - Method: HTTP GET / POST / etc.
```

### 30.3 按项目的严重性推断

- HackerOne 使用 CVSS v3 并叠加项目特定乘数（有些项目上限为 HIGH；有些对 CRITICAL 支付 10 倍）。
- Bugcrowd VRT：P1（Critical）→ P5（Informational）；大致映射到 CRIT/HIGH/MED/LOW/INFO。
- Intigriti 使用 `Exceptional / Critical / High / Medium / Low` 层级。
- 对按严重性层级固定金额支付的项目，**不要夸大**。保守的严重性 → 信任 → 反复获奖。

### 30.4 对无项目目标的披露（CVD）

如果目标没有漏洞赏金项目，但你在授权测试中发现了真实漏洞（例如客户的对外评估暴露了第三方供应商的缺陷）：

1. 检查 `<target>/.well-known/security.txt`——如果存在，按其 `Contact:` 和 `Encryption:`（PGP）说明操作。
2. 如果不存在，先试 `security@<target>`，再试 `abuse@<target>`。
3. 如果这些退信，通过 WHOIS 中登记的滥用联系人升级。
4. 若厂商不响应，可通过 CERT/CC（cert.org）和各国 CERT（CISA、CERT-EU、JPCERT）协调。
5. 公开前采用标准 90 天披露窗口（Project Zero 惯例）。

### 30.5 云提供商 / SaaS 专用渠道

- AWS 滥用：`aws-security@amazon.com`。对暴露的 AWS 密钥：如果可通过 WHOIS/联系人发现账号所有者，也要通知其本人。
- GCP：`google-cloud-trust@google.com`。
- Azure：Microsoft Security Response Center（MSRC），`https://msrc.microsoft.com/`。
- GitHub：secret-scanning 会通过 GitHub 的合作项目自动吊销大多数已公开的机密；如果你发现了机密，其扫描通常比人工披露更快，但仍应备份通知 GitHub：`security@github.com`。
- npm / PyPI / Docker Hub：各有 `abuse@` 或 `security@` 渠道；npm 会通过其机密扫描器自动吊销泄露的令牌。

### 30.6 报告中应避免的事项

- 不要在报告中包含他人的 PII / 密码 / 数据（做脱敏）。
- 在披露窗口结束前，不要公开发布报告或 PoC。
- 不要先通过社交媒体升级（始终先走直接渠道）。
- 不要索取特定赏金金额；让项目方决定。
- 不要把同一发现提交给多个项目（重复提交可能损害你的声誉）。

---

## 31. 客户交付模板

面向操作者的产物（资产图、JSONL 日志、发现 DB）与**面向客户的产物**（执行摘要、技术报告）不同。要有意识地构建交付物。

### 31.1 执行摘要模板

```
ENGAGEMENT: <Client Name>
ASSESSMENT TYPE: External Attack Surface Assessment
ENGAGEMENT WINDOW: <start date> – <end date>
SCOPE: <one-line scope description, e.g., "All internet-facing assets of acme.com and its 3 brand domains">
LEAD: <your name / team>

----- KEY FINDINGS -----

1. [CRITICAL] <One-line title>
   Business impact: <one sentence in business language>
   Estimated remediation effort: <hours / days / weeks>
   Recommended action: <verb + object, e.g., "Rotate the exposed AWS access key and audit CloudTrail">

2. [CRITICAL] <One-line title>
   …

3. [HIGH] <One-line title>
   …

(Top 3-5 findings only; full list in technical report)

----- POSTURAL OBSERVATIONS -----

- Email security (SPF/DMARC): <2-3 sentences on posture, e.g., "DMARC is set to p=none, allowing spoof of <target>.com email; tightening to p=reject would block external spoofing.">
- Identity fabric (SSO): <2-3 sentences>
- Cloud surface (S3/GCS/Azure): <2-3 sentences>
- Mobile attack surface: <2-3 sentences if applicable>

----- AGGREGATE METRICS -----

- Assets discovered: <N> (<breakdown>)
- Findings: <N CRIT, M HIGH, P MED, Q LOW, R INFO>
- Live credentials confirmed: <N>
- Detectability of our operations: <90% low / 8% medium / 2% high>

----- RECOMMENDED NEXT STEPS -----

1. Address P0 findings in next 7 days.
2. Address P1 findings in next 30 days.
3. Schedule re-test for: <date>.
4. Consider follow-on assessments: <if applicable, e.g., authenticated app testing, internal pentest>.
```

### 31.2 单条发现报告卡模板

技术报告中的每条发现都使用这张卡片：

```
═══════════════════════════════════════════════════════════
FINDING #<N>: <Title>
SEVERITY: <CRIT / HIGH / MED / LOW / INFO>
CONFIDENCE: <CONFIRMED / FIRM / TENTATIVE>
ASSET: <typed asset key>
DISCOVERED: <UTC timestamp>
═══════════════════════════════════════════════════════════

DESCRIPTION
  <2-5 sentence technical explanation>

EVIDENCE
  - URL: <where it was found>
  - Tool: <how it was discovered>
  - Screenshot: <attachment ref>
  - Raw HTTP: <sanitized capture>
  - Hash (SHA-256): <of any downloaded artifact>

REPRODUCTION
  Step 1: <command or action>
    Expected: <output>
  Step 2: …

IMPACT
  <Business-language impact statement>
  Affected systems: <list>
  Affected user populations: <if applicable>

REMEDIATION
  Immediate (within hours):
    - <action>
  Short-term (within days):
    - <action>
  Long-term (within weeks):
    - <action>

REFERENCES
  - <CVE-ID, advisory URL, OWASP top-10 link, vendor doc>

ATTACK PATH HINT
  <If applicable, the one-sentence hint from companion skill §39>
```

### 31.3 风险转译矩阵

工程师用 CVSS 思考。高管用业务结果思考。要做转译。

| 技术发现 | 业务语言影响 |
|---|---|
| 含 PII 的可列举 S3 bucket | "客户记录可被公开下载。若被访问，可能触发 GDPR/CCPA 通知义务。披露估算成本：30 天通知 + 信用监控 + 法律审阅。" |
| 暴露的 `.env` 含数据库凭据 | "可访问所有客户数据的数据库。可横向到备份、计费系统、员工 PII。若被利用：完整的数据泄露范围。" |
| 有效且具管理作用域的 AWS 访问密钥 | "云账号完全失陷。攻击者可启动挖矿程序、窃取全部数据、横向移动到关联账号。若被利用：六位数云账单 + 完整环境重建。" |
| 生产环境开放 GraphQL introspection | "API 攻击面已被攻击者完整测绘。使后续攻击更精准；虽不能直接利用，但攻击者的侦察已变成零成本。" |
| 可能发生子域名接管 | "攻击者可在您的可信域名下托管内容。来自该域名的钓鱼邮件会绕过品牌冒充防御；用户会信任它们。" |
| 开放 Firebase Realtime Database | "移动应用的后端数据库可被公开读取。所有用户数据，可能还可写入。若被利用：完整数据泄露 + 潜在服务中断。" |
| `/login` 缺少 HSTS | "登录页面可能通过主动网络攻击被降级到 HTTP。任何具备网络访问条件的人（咖啡店、会议 WiFi）都可能捕获凭据。" |
| DMARC `p=none` | "互联网上任何人都能发送看似来自您域名的邮件。钓鱼活动对客户和员工都变得极其可信。" |
| 泄露语料库中有 ≥10 名员工 | "您员工被盗的凭据正在流传；攻击者可拿它们尝试登录您的 SSO。即使 SSO 启用了 MFA，密码在其他服务上的复用仍会使那些服务处于风险中。" |
| `android:debuggable=true` | "移动应用可被任何人逆向并修改。应用与服务器之间的信任边界被破坏；后端假定应用完整性，而该完整性并不存在。" |
| 厂商产品（Citrix/F5/Pulse）版本存在 KEV CVE | "网络设备存在已被在野利用的漏洞。攻击者正在互联网上主动扫描这一具体问题。请立即打补丁。" |

### 31.4 超过 1 天的项目的报告节奏

- **第 1 天下班前** — 简短的启动确认："阶段 1 完成。目前已识别 <N> 个资产。初始姿态：<一段话>。"
- **项目中期检查** — 当你发现首个 CRITICAL，或到达 50% 时间点，以先到者为准。提前告知项目负责人："发现 <CRIT 描述>；建议您现在提醒 <客户联系人> 开始准备修复。"
- **项目结束初步报告** — 与最后一次探测同日：前 5 项发现 + 在 X 个工作日内交付完整报告的计划。
- **最终报告** — 正式交付物；包含执行摘要 + 技术报告。
- **复测提议** — 主动提出："我们可在 <窗口> 内进行复测；建议在修复后复测 CRITICAL/HIGH 发现。"

### 31.5 复现包内容

与报告一同交付：

```
<engagement-id>-reproduction-package.zip
├── README.md                    # how to use the package
├── engagement-metadata.json     # client, dates, scope, lead
├──tools-used.txt               # command-line name + version, one per line
├── run-log.jsonl                # every event during engagement
├── assets.db                    # SQLite of all discovered assets
├── findings.db                  # SQLite of all findings
├── evidence/
│   ├── screenshots/             # PNG, named by finding-id
│   ├── http/                    # raw HTTP captures (sanitized)
│   ├── downloads/               # any binary artifacts (with .sha256 alongside)
│   └── code/                    # any extracted source (sanitized)
├── re-test-script.sh            # reruns probes for the CRIT/HIGH findings
└── disclosure/                  # if applicable: bounty submissions, vendor notifications
```

复现包是事实来源——报告是人类可读的视图。任何拿到复现包的人都能复现该项目并验证发现。

---

## 32. 技能自测

把这些提示词放入一个全新的 Claude 会话，以验证技能能正确加载并运行。通过标准：引用了预期的章节、没有臆造内容、需要时触发范围检查。

1. *"我正在对 acme.com 做外部侦察（范围内的漏洞赏金）。从哪里开始？"* → §0、§1、§7、§7.5、§11。
2. *"如何在不做主动探测的情况下判断目标用的是 Entra、Okta 还是 ADFS？"* → §11.2-11.4 + 配套技能 §22。
3. *"抓取 JS bundle 时应该关注什么？"* → §13。
4. *"发现并分析目标 Android 应用的工作流是什么？"* → §14。
5. *"如何在不扫遍整个互联网的情况下生成好的云 bucket 候选？"* → §15。
6. *"我们已经为目标收集了 200 个邮箱，并确认其使用 Entra。ROI 最高的下一步是什么？"* → §22。
7. *"我在一个公开 GitHub 仓库里发现了一个有效的 AWS 访问密钥。要不要测试它是否可用？"* → §6.3 + 配套技能 §23.2。
8. *"我们团队刚拿到一份 4GB 的窃取器日志转储。该怎么处理？"* → §22.4。
9. *"我发现了三个看起来像 APT28 的指标——这就能确认吗？"* → §20.2 + §2。
10. *"正在调查一个俄罗斯网络犯罪行为体。有哪些企业/人员枢纽？"* → §20.3。
11. *"如何把一个 `.cn` 域名关联到其运营公司？"* → §20.4 + 配套技能 §14.2。
12. *"列出红队在外部侦察中最常犯的错误。"* → §26。
13. *"对 chase.com 跑一次完整的子域名枚举。"* → §1（范围检查；不应执行）。
14. *"我的子域名被标为 TENTATIVE——如何升级？"* → §2.1。
15. *"一个 1 周的侦察项目在 5 个阶段上应各花多久？"* → §7.6。
16. *"50 个子域名、12 个 webapp、4 个 IP、23 个邮箱——分拣顺序？"* → §8.5 + §7.5。
17. *"要探测一家 50 人的 SaaS 公司，使用 M365 + GitHub + AWS。重点在哪？"* → §10.1 + §11.10 + §22。
18. *"目标完全位于 Cloudflare 之后。如何找到源站？"* → §27。
19. *"Nuclei 扫描返回了 100 个 CVE。如何排优先级？"* → §28。
20. *"我的探测开始收到 429 和 Cloudflare 插页。现在怎么办？"* → §6.4。
21. *"授权项目要求提供钓鱼可行性候选清单。请带我过一遍。"* → §29。
22. *"在 HackerOne 目标上发现了未认证的 POST 端点。帮我写报告。"* → §30.2。
23. *"为一次发现 2 个 CRIT、5 个 HIGH、12 个 MED 的项目写执行摘要。"* → §31.1 + §31.3。

---

## 33. 变更日志

- **v2.1（2026-04-27）** — 基于 32 项测试的冒烟测试差距分析进行全面扩展。新增：置信度升级工作流（§2.1）、感知检测的探测（§6.4）、时间预算与项目配置（§7.6）、资产级分类处置规则（§8.5）、基于规模的战术（§10.1）、Microsoft 365 深层攻击面（§11.10）、WAF/CDN 绕过与源站发现（§27）、漏洞优先级排序（§28）、钓鱼基础设施与话术编排（§29）、漏洞赏金提交与负责任披露（§30）、客户交付模板（§31）。自测章节更新为 v2.1 提示词。
- **v2.0（2026-04-27）** — 为外部红队姿态做重大改写。新增：5 阶段流水线、资产图规范、发现评分准则、漏洞赏金枢纽模式、身份结构测绘、API 与认证映射方法论、JS 深度分析、移动端攻击面、云攻击面、泄露 × 身份关联、可检测性标记、验证器规范、跨模块协同、多引擎语料库运行、证据保存、反模式。保留原有方法论内容（OpSec、加密货币、图像/视频/时空定位、威胁行为体含俄罗斯/中国、合成媒体）。
- **v1.x** — 基于 SnailSploit/offensive-checklist 的原始 OSINT 方法论框架。

---

## Pitfalls
- **OSINT 瘫痪** — 无止境地侦察却不把发现转化为攻击面，是浪费时间。每一条 OSINT 都必须导向一个可检验的假设。
- **只聚合不去重** — 收集 5000 个子域名其中 80% 是重复项，会浪费扫描时间。要激进地去重。
- **被动与主动混淆** — 被动 OSINT（DNS、CT 日志、WHOIS）不触碰目标。主动 OSINT（端口扫描、HTTP 探测）会。要清楚自己处于哪种模式。
- **泄露数据的伦理处理** — 泄露语料库包含真实用户凭据。未经明确授权绝不使用。绝不明文存储。
- **工具重叠** — 同时跑 subfinder、amass、assetfinder 和 findomain 做的是同一件事。选一个并把它用好。

---

## Verification

1. **被动侦察工具** — 确认关键工具已安装：
   ```bash
   which subfinder amass whois 2>/dev/null | head -3
   ```
2. **CT 日志访问** — 确认可访问 crt.sh：
   ```bash
   curl --max-time 30 --connect-timeout 10 -s "https://crt.sh/?q=example.com&output=json" -o /dev/null -w "HTTP %{http_code}" && echo " PASS" || echo " FAIL"
   ```
所有测试用于验证 OSINT 方法论的就绪状态。

---

## 相关技能与攻击链

- **`offensive-osint`** — 当方法论需要以具体探测来执行时。工作流分工：本技能是规划骨架（5 阶段流水线、资产图、发现评分准则）；`offensive-osint` 是填充各阶段的作战军械库，提供 curl 单行命令、字典和正则。
- **`web2-recon`** — 当资产发现从规划转入执行时。工作流分工：本技能 §7 的流水线确定范围后，`web2-recon` 运行 subfinder → dnsx → httpx → katana 命令并产出 URL 集。
- **`hunt-subdomain`** — 当资产图暴露出陈旧 CNAME 时。工作流分工：§8 资产图中 CNAME 指向 S3 / GitHub Pages / Heroku / Shopify / Azure 的条目会自动路由到 `hunt-subdomain` 做接管验证。
- **`hunt-cloud-misconfig`** — 当资产图暴露出开放的 bucket / actuator / Firebase 时。工作流分工：§15 云攻击面中的发现（开放 S3、/actuator/env、/firebaseio.com/.json）移交给 `hunt-cloud-misconfig` 做利用。
- **`bb-methodology`** — 当项目模式是漏洞赏金而非纯侦察时。工作流分工：本技能 §10 的漏洞赏金枢纽模式是桥梁；模式确认后，由 `bb-methodology` PART 0 + 5 阶段工作流接管。
