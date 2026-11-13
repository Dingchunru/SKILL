---
name: attack-patterns-reference
description: 当需要归类已验证的 Web 或 WordPress 行为，并选择相关的验证技能时使用。
version: 1.2.1
revision_date: 2026-11-13
license: MIT
platforms: [linux]
compatibility: N/A (reference catalog)
metadata:
  tags: [meta, reference, patterns, validation]
  category: meta
  related_skills:
    - cors-credential-wordpress
    - cross-attack-chains
    - error-log-mining
    - js-secrets-extraction
    - phpinfo-to-rce
    - port-service-discovery
    - source-leak-hunt
    - staging-subdomain-hunt
    - wordpress-plugin-hunt
    - wp-mass-recon
---

# 攻击模式参考

本目录将观察到的 Web 与 WordPress 行为映射到负责其验证的技能。模式 ID 仅
用作导航标签。它们并不能确立可利用性、严重性、普遍性或已确认的攻击路径。

## When to Use

- 在某项侦察结果进入专项测试之前，需要对其进行归类。
- 多个已验证的行为可能构成一条候选攻击路径。
- WordPress、CORS、XML-RPC、源码泄漏或暴露服务信号需要一个负责的验证流程。

不要将该目录用作扫描器漏洞列表，也不要用它替代所属技能的验证章节。

## Prerequisites

- 一个已获授权的目标及当前的范围限制。
- 针对待归类观察结果已捕获的证据。
- 所选后续技能所需的工具与身份。

## How to Run

1. 将观察到的行为匹配到最接近的模式。
2. 打开表格中列出的所属技能。
3. 检查其前置条件与副作用。
4. 运行能够证伪该假设的最小验证与负向对照。
5. 将结果记录为已观察、推断、已确认或未测试。

## Procedure

### 通用 Web 模式

| 模式 | 初始信号 | 所属技能 |
|---|---|---|
| WordPress 用户暴露 | REST 或作者路由返回用户元数据 | `wp-mass-recon` |
| 带凭据的 CORS | 不受信任的来源被反射且携带凭据 | `cors-credential-wordpress` |
| XML-RPC 方法 | 协议有效的 `system.listMethods` 响应 | `xmlrpc-exploitation` |
| XML-RPC SSRF | `pingback.ping` 到达受控回调 | `xmlrpc-exploitation` |
| 公开注册 | 注册功能已启用 | `wp-mass-recon` |
| 插件攻击面 | REST 命名空间、资源或版本标记 | `wordpress-plugin-hunt` |
| 预发环境差异 | 非生产主机存在更弱的控制 | `staging-subdomain-hunt` |
| 暴露的错误日志 | 响应包含真实的应用错误 | `error-log-mining` |
| PHPInfo 暴露 | PHP 配置页面可访问 | `phpinfo-to-rce` |
| 源码或备份泄漏 | 响应包含代码仓库、配置或数据库内容 | `source-leak-hunt` |
| JavaScript 密钥候选 | 打包文件包含凭据形态的值 | `js-secrets-extraction` |
| 公开服务 | 非 HTTP 或管理类服务可从互联网访问 | `port-service-discovery` |

关于扩展的模式说明，参见 [`references/p-patterns.md`](references/p-patterns.md)。

### CORS 变体

| 变体 | 初始信号 | 必需的验证 |
|---|---|---|
| 带凭据的来源反射 | 不受信任的来源加 `ACAC: true` | 带凭据的浏览器可读取非公开数据 |
| 空来源信任 | `ACAO: null` 加 `ACAC: true` | 沙箱化浏览器可读取非公开数据 |
| 无凭据的通配符 | `ACAO: *` | 判断该响应是否本就公开 |
| 带凭据的预检 | OPTIONS 接受来源、方法与头部 | 实际请求成功且浏览器可读取响应 |
| 认证路由 CORS | 受保护路由上出现 CORS 头部 | 已批准的会话返回可读的受保护数据 |
| 插件特定 CORS | 仅某个插件命名空间接受该来源 | 响应包含受保护数据或执行经授权的测试动作 |
| 环境特定 CORS | 预发与生产策略不同 | 在已授权环境中证明影响 |
| 第三方白名单 | 某个外部服务来源被信任 | 确立对该来源的控制及受保护数据访问 |

### 候选攻击路径

以下为组合模板，而非已确认的发现：

| 路径 | 必须验证的前置条件 |
|---|---|
| CORS 到受保护数据读取 | 已批准会话、不受信任来源、可被浏览器读取的非公开响应 |
| XML-RPC SSRF 到云元数据 | 受控回调、可达的元数据服务、可用的二次影响 |
| 开放注册到上传 | 已批准的合成账号、具备上传能力的角色、可执行文件路径 |
| 暴露日志到账号访问 | 当前可用的凭据材料、已批准身份、有效的认证控制 |
| 预发暴露到生产影响 | 共享的信任边界、可复用的密钥或部署路径、明确的范围 |

只有在每一个前置条件都被独立验证之后，才使用 `cross-attack-chains`。

## Pitfalls

- 历史频率并不是关于当前目标的证据。
- 产品名称、版本、状态码或头部不能证明影响。
- 兜底路由可能让敏感路径看起来可访问。
- 公开的客户端标识符与有意公开的 API 并不自动构成凭据或授权失效。
- 模式的前置条件会随产品与插件版本而变化。
- 攻击路径会继承其最薄弱环节的不确定性。

## Verification

- 将每个模式对应到已捕获的请求与响应证据。
- 运行负向对照，以区分该结果与公开或通用行为。
- CORS 影响需使用浏览器验证；仅有头部不足。
- 盲 SSRF 需使用受控回调；仅有协议状态不足。
- 在关联某个 CVE 之前，先做确切的组件与前置条件检查。
- 仅报告在范围内复现的影响。
