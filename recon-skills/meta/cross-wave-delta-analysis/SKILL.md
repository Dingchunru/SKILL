---
name: cross-wave-delta-analysis
description: 对比多轮侦察结果，找出新增（NEW）、回归（REGRESSED）与持续存在（PERSISTENT）的发现。
version: 1.1.1
revision_date: 2026-11-13
license: MIT
platforms: [linux]
compatibility: N/A (analysis methodology)
metadata:
  tags: [meta, wave, delta, comparison, analysis]
  category: meta
  related_skills:
    - recon-playbook
    - cross-attack-chains
    - cors-credential-wordpress
    - attack-patterns-reference
---

# 跨轮次差异分析技能

用于在同一组目标的多轮侦察之间对比发现的方法论。可检测新增（NEW）发现、
回归（REGRESSION，此前开放而现已阻断）、持续存在（PERSISTENT）的漏洞
以及随时间发生的变化（CHANGES）。该方法论提炼自 7 个深度目标上的 9 轮侦察，
其中揭示了被遗漏的 CORS 发现、新增的端口暴露以及基础设施漂移。

## When to Use

- 对同一组目标重复执行侦察（第 N 轮之后的第 N+1 轮）。
- 你想知道某个漏洞自上一轮以来是否已被修补。
- 你想知道是否出现了新的攻击面（新端口、新子域、新端点）。
- 完成一轮深度侦察之后——在进入下一轮之前产出差异报告。
- 在提交报告之前——确认发现仍然有效（未发生回归）。

## Prerequisites

- 此前评估的输出位于 `${OUTPUT_DIR:-./output}/baseline/` 之下。
- 当前评估的输出位于 `${OUTPUT_DIR:-./output}/current/` 之下。
- 每个目标的结构化发现（至少包含：端口、CORS 状态、WP 用户、XMLRPC 状态、敏感路径）。

## How to Run

```bash
# Produce a delta report comparing WaveN to WaveN+1
# Read wave outputs, compare per-target, classify findings
```

## 快速参考

### 差异类别

| 类别 | 标签 | 含义 | 示例 |
|----------|-------|---------|---------|
| NEW | ++ | 在此前任何一轮中都不存在的发现 | `Port 3306 (MySQL) now OPEN` |
| REGRESSION | -- | 此前可访问而现已被阻断的服务 | `XMLRPC 200 -> 405 (hardened)` |
| PERSISTENT | == | 在所有轮次中均未变化的漏洞 | `CORS still reflecting since wave6` |
| CHANGE | ~ | 配置发生变化但不属于回归 | `WP users: 10 in wave7, 9 in wave9` |
| REVERSED | -> | 后续被撤销的回归（缓解措施被移除） | `XMLRPC 405 (W9) -> 200 active (W10)` |

### REVERSED —— 特殊类别

反转（Reversed）发现是指后续又回退到原始易受攻击状态的回归。出现情形包括：
- 某条 WAF 规则被临时应用随后又被移除（在 GoDaddy/Cloudflare 共享主机上很常见）
- 某插件的安全更新被回滚
- 基础设施在未包含加固措施的情况下被重新部署

**将 REVERSED 视为可操作项**：安全团队要么不知道，要么不在意。这类目标是高优先级，
因为它们的防护并不可靠。

### 每个目标需要对比的字段

| 字段 | 检查方式 | 差异的含义 |
|-------|-------------|------------------|
| XMLRPC 状态 | POST /xmlrpc.php 的 HTTP 状态 | 200 -> 405 = REGRESSION (hardened) |
| CORS 头部 | /wp/v2/users 上的 ACAO + ACAC | Reflecting -> No headers = REGRESSION |
| WP 用户 | 来自 /wp/v2/users 的数量 | Count change = CHANGE |
| 开放端口 | nmap 或 naabu 输出 | New port = NEW (surface expanded) |
| 子域 | subfinder 输出 | New subs = NEW |
| 敏感路径 | .env、info.php 等的 HTTP 状态 | Previously 200 -> 403 = REGRESSION |

## Procedure

### 第 1 步 —— 收集两轮的数据

```bash
WAVE_OLD="${OUTPUT_DIR:-./output}/baseline"
WAVE_NEW="${OUTPUT_DIR:-./output}/current"
echo "=== Comparing $WAVE_OLD vs $WAVE_NEW ==="
```

### 第 2 步 —— 产出每个目标的差异表

对于同时出现在两轮中的每个目标，对比 XMLRPC 状态、CORS 头部、开放端口、WP 用户
与子域。将发现标记为 NEW（此前轮次中没有）、REGRESSION（此前可用、现被阻断）、
PERSISTENT（未变化）或 CHANGE（有所不同但未被阻断）。

### 第 3 步 —— 归类并标记关键差异

以下情况视为关键差异信号：新开放的 3306 端口（MySQL）、新的 CORS 凭据反射、
新的 WP 安装页面、带有 admin/staging 模式的新子域。

## Pitfalls

- **假性 REGRESSION。** 403 可能是限流而非修补。用不同的 IP/时延重试 3 次。
- **假性 PERSISTENT。** 某个 200 端点可能仍然存活，但底层漏洞（例如 multicall）可能已被禁用。
- **时序很重要。** 各轮必须使用相同的方法论，否则差异毫无意义。
- **不要把"未被记录"混淆为"不存在"。** 某个发现可能曾经存在，但只是被遗漏了。

## Verification

- 每个差异都必须能用完全相同的命令在两轮的输出上复现。
- 新增发现应立即重新测试——它们可能是暂时性的。
- 跨 3 轮及以上持续存在的发现最为可靠（没有安全团队、没有修补节奏）。

---

## 相关技能

- `attack-patterns-reference` —— 将发现匹配到模式 ID（P-01 至 P-25）
- `recon-playbook` —— 产出各轮数据的四阶段流水线
- `cross-attack-chains` —— 将新增发现串联为关键影响
- `cors-credential-wordpress` —— 验证 CORS 发现的归类
- `xmlrpc-exploitation` —— 验证 XMLRPC 的回归状态
