---
name: wordpress-full-compromise
description: 当已验证的 WordPress 发现可能组合成通往管理控制或服务器控制的经授权路径时使用。
version: 2.0.0
license: MIT
platforms: [linux, macos]
compatibility: Requires curl, a browser, approved test identities, and WordPress component evidence
metadata:
  tags: [chains, wordpress, validation, attack-path]
  category: chains
  related_skills:
    - cross-attack-chains
    - hunt-wordpress
    - triage-validation
    - wordpress-cors-xmlrpc-rce-chain
    - wordpress-plugin-hunt
    - xmlrpc-exploitation
---

# WordPress 失陷路径分析

使用本技能判断已验证的 WordPress 原语是否真正组合成管理控制或无害的代码执行证明。
它是一道攻击链闸门，而不是在前置条件失败后强行升级的检查清单。

## When to Use

- 某个插件漏洞已有确切的版本与路由证据。
- 某个已批准的身份可能拥有意外的 WordPress 能力。
- 某次上传或配置写入可能到达可执行的解析处理。
- CORS、XML-RPC、预发环境或源码暴露可能提供缺失的前置条件。

## Prerequisites

- 对注册、认证、上传、写入与执行测试的明确授权。
- 一个已批准的合成账号与可丢弃的内容。
- 确切的 WordPress、插件、主题与主机行为。
- 用于任何执行测试的无害标记。
- 清理与停止条件。

## How to Run

构建前置条件表：

```text
Step                         State       Required evidence
Component vulnerability      observed    exact version and affected operation
Authorized identity          confirmed   approved account and current role
Write or upload capability   unverified  synthetic artifact accepted
Executable handling          unverified  benign marker executed
Administrative control       not tested  approved admin-only action
Cleanup                      planned     artifact and account removal
```

不要越过尚未验证的前置条件继续推进。

## Procedure

### 1. 确认组件

使用 `hunt-wordpress` 与 `wordpress-plugin-hunt` 来确定：

- 来自不止一个信号的组件身份；
- 确切的版本或提交；
- 易受攻击的路由或处理器；
- 认证与角色前置条件；
- 受影响的配置与文件类型。

仅凭公开的 readme 或过期的静态资源并不充分。

### 2. 确认身份与能力

仅使用已批准的测试身份。记录当前角色以及该操作所检查的确切能力。订阅者、客户、
作者、编辑与管理员角色不可互换。

不要用密码喷洒、撞库或无关的泄漏凭据来弥合缺失的授权。

### 3. 用合成数据验证状态变更

使用唯一命名的合成文章、客体或无作用的文件。记录：

- 请求与身份；
- 响应与生成的客体 ID；
- 位置与内容；
- 预期的授权策略；
- 清理结果。

如果该客体无法被安全移除，请在创建之前停止。

### 4. 将上传与执行分离

上传被接受只证明存在上传边界。应单独确立可执行的解析处理：

- 服务器将存储的扩展名映射到某个解释器；
- MIME 与扩展名校验允许被测类型；
- 存储路径可通过 Web 访问；
- 插件处理过程不会重命名或清洗该文件；
- 无害标记能在已批准环境中执行。

绝不要部署命令 shell 作为通用证明。

### 5. 评估管理影响

管理控制需要一个已批准的管理员专属效果，例如读取某个合成的私有设置，或更改某个
可丢弃的配置值随后再恢复。用户枚举、REST 元数据或存在可用的登录页面并不能确立
账号接管。

### 6. 组装路径

使用 `cross-attack-chains` 仅连接已确认的衔接环节。当 CORS 与 XML-RPC 是真正的前置
条件——而不仅仅是同一套安装上的额外发现——时，使用 `wordpress-cors-xmlrpc-rce-chain`。

## Pitfalls

- 开放注册通常只会创建低权限角色。
- XML-RPC 方法存在并不等于有权调用该方法。
- PHP 进程函数被启用并不会创造上传原语。
- 插件版本证据可能过期或是向后移植的。
- 预发站点可能使用独立的数据库，且不存在通往生产的信任路径。
- 某个前置条件失败，即是所提议攻击链在此终止的证据。

## Verification

- 组件身份、版本、路由与前置条件均已确认。
- 已批准的身份具备确切所需的能力。
- 状态变更使用合成资源并已被回滚。
- 上传与执行作为独立步骤得到证明。
- 管理影响使用已批准的可丢弃动作。
- 每一个缺失的步骤仍标记为推断或未测试。
