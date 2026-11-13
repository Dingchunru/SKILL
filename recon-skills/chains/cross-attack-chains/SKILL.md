---
name: cross-attack-chains
description: 当两个或更多已验证的发现可能组合成影响更高的经授权攻击路径时使用。
version: 2.0.0
license: MIT
platforms: [any]
compatibility: Requires evidence from the owning validation skills
metadata:
  tags: [chains, attack-path, validation, reporting]
  category: chains
  related_skills:
    - attack-patterns-reference
    - evidence-hygiene
    - report-writing
    - triage-validation
    - wordpress-full-compromise
---

# 跨组件攻击链

攻击链是一系列已验证的安全行为，其中每一步都为下一步提供前置条件。同一目标上的
若干发现并不能构成攻击链，除非它们之间的依赖关系得到证明。

## When to Use

- 两个或更多已验证的发现影响同一个信任边界。
- 某个发现暴露了另一个发现所需的身份、令牌、路由、主机或能力。
- 报告需要区分独立影响与复合影响。
- 攻击链的下一步无法安全测试，必须标记为推断。

## Prerequisites

- 针对每个组成部分发现已捕获的证据与负向对照。
- 对复合测试及任何增加的副作用具备当前授权。
- 已批准的身份、合成记录、回调以及清理流程。
- 针对敏感数据、可用性或范围变更的明确停止条件。

## How to Run

在目标输出目录下创建攻击链记录：

```bash
TARGET_ID="example-test"
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
CHAIN_DIR="$OUTPUT_DIR/$TARGET_ID/chains"

mkdir -p "$CHAIN_DIR"
touch "$CHAIN_DIR/EXPLOIT_CHAINS.md"
```

一致地使用以下证据状态：

| 状态 | 含义 |
|---|---|
| Observed | 出现在已捕获输出中 |
| Confirmed | 安全影响已通过对照复现 |
| Inferred | 合理但尚未测试的依赖关系 |
| Not tested | 因范围、安全性或缺少前置条件而排除 |

## Procedure

### 1. 归一化组成部分发现

对每个组成部分记录：

- 预期行为与实际观察到的行为；
- 目标、身份与时间戳；
- 正向证据与负向对照；
- 副作用与清理情况；
- 已证明的影响；
- 假设与测试限制。

丢弃尚未通过其所属技能验证的扫描器标签与仅基于版本的线索。

### 2. 绘制依赖关系

```text
Finding A
  output: approved user identifier
  enables: object lookup in Finding B

Finding B
  output: unauthorized synthetic object read
  enables: none
```

如果 A 与 B 只是恰好位于同一目标，请分别记录它们。

### 3. 测试衔接环节

衔接环节是攻击链的核心。要证明某一步的确切输出在同等的已授权条件下被下一步接受。

示例：

| 候选路径 | 需要证明的衔接 |
|---|---|
| 源码映射到隐藏 API | 提取出的 base URL 能解析到被测 API |
| 用户枚举到 IDOR | 枚举得到的标识符可访问另一个已批准身份的客体 |
| CORS 到受保护数据读取 | 已批准的浏览器会话向受控来源返回非公开响应 |
| SSRF 到内部服务 | 受控回调或响应识别出该内部服务 |
| 暴露凭据到代码仓库访问 | 受范围限定的凭据对已批准的测试资源有效 |

不要使用真实用户数据、大范围凭据测试或破坏性操作来弥合缺失的衔接环节。

### 4. 重新计算复合影响

说明：

1. 每个组成部分单独证明了什么；
2. 已验证的衔接创造了什么额外能力；
3. 哪种最终影响已被复现；
4. 哪些下游后果仍属推断。

攻击链的严重性不能超出证据。前序步骤成功并不意味着理论上的最后一步得到确认。

### 5. 保留清理与限制

记录合成用户、客体、上传文件、回调与临时令牌的移除情况。如果测试在最后一步之前
停止，请说明原因并保留最后确认的状态。

## Pitfalls

- 同时出现不等于存在依赖关系。
- 用户名不是凭据。
- 有效凭据并不意味着可访问所有服务。
- 文件上传并不意味着代码执行。
- 内部可达并不意味着能控制内部服务。
- 多个低置信度的步骤会累积不确定性，而不是置信度。
- 复合测试可能需要超出单项发现的授权。

## Verification

- 每个组成部分都通过了其所属技能的验证。
- 每一个箭头都有证据表明前序输出使后续输入成为可能。
- 负向对照能将该路径与公开或预期行为区分开。
- 变更状态的步骤使用合成资源，并包含清理。
- 推断与未测试的步骤保持可见的标记。
- 最终报告将已证明的影响与可能后果分开。
