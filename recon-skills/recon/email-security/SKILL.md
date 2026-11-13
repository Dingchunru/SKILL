---
name: email-security
description: "DMARC/SPF/DKIM 检查、邮件伪造、SMTP 测试与安全响应头分析"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [email, SPF, DKIM, DMARC, spoofing, SMTP, recon]
  category: recon
---

# 邮件安全 -- DMARC、SPF、DKIM

## When to Use

- 被动侦察阶段（阶段 1）
- 初始 DNS 枚举之后
- DMARC p=none 意味着 DMARC 强制未开启；实际是否可伪造仍取决于 SPF/DKIM 与接收方的本地策略
- 识别钓鱼/商业邮件诈骗风险的关键

## Prerequisites

- 针对目标的明确授权、目标边界与速率限制。
- 工具：`dig`、`swaks`。
- 一个可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何会改变状态的步骤（写入、上传、凭据尝试），必须在执行命令前立即获得明确确认。

## How to Run

```bash
# SPF
dig +short TXT $target | grep "v=spf1"

# DMARC
dig +short TXT _dmarc.$target

# DKIM (common selector: google)
dig +short TXT google._domainkey.$target

# MX
dig +short MX $target
```

## Procedure

以下各阶段即为流程。保持每次探测有界（`--max-time`），在 `OUTPUT_DIR` 下记录证据，并在 Pitfalls 中列出的停止条件处停止。

## DMARC/SPF/DKIM 检查命令

```bash
# SPF
dig +short TXT $target | grep "v=spf1"

# DMARC
dig +short TXT _dmarc.$target

# DKIM (common selector: google)
dig +short TXT google._domainkey.$target

# MX
dig +short MX $target
```

## 结果解读

| 配置 | 含义 | 风险 |
|--------|---------|------|
| v=spf1 ~all (softfail) | SPF 建议拦截但未强制执行 | 伪造邮件可能通过 |
| v=spf1 ?all (neutral) | SPF 不起作用 | 完全放行 |
| v=spf1 include:amazonses.com ~all | SES 可以该域名义发信 | 任何 AWS SES 账户都可伪造 |
| v=DMARC1; p=none | DMARC 已禁用 | 零伪造防护 |
| v=DMARC1; p=quarantine | 未通过校验的邮件进入垃圾箱 | 部分防护 |
| v=DMARC1; p=reject | 未通过校验的邮件被拒绝 | 完整防护 |
| 缺少 DKIM | 无加密签名 | 邮件可被伪造 |

## 通过 SMTP 进行邮件伪造

```bash
# Test SMTP relay
timeout 3 bash -c 'exec 3<>/dev/tcp/TARGET/25; head -1 <&3'

# Send spoofed email via open relay (swaks)
swaks --to victim@target.com --from admin@target.com   --server TARGET --body "Spoofed email"
```

## 指示安全级别的响应头

| 响应头 | 取值 | 含义 |
|--------|-------|---------|
| Authentication-Results | spf=pass | SPF 通过 |
| Authentication-Results | spf=fail | SPF 未通过 |
| Authentication-Results | dmarc=pass | DMARC 通过 |
| Authentication-Results | dmarc=fail | DMARC 未通过 |
| Authentication-Results | dkim=pass | DKIM 通过 |
| Received-SPF | Pass | 发件方已获授权 |
| Received-SPF | Softfail | 发件方未完全获授权 |
| Received-SPF | Fail | 发件方未获授权 |
| ARC-Authentication-Results | | 认证链 |

## AWS SES 伪造（当 SPF 包含 amazonses.com 时）

在 `v=spf1 include:amazonses.com ~all` 的情况下：
1. 创建 AWS 账户
2. 用你自己的（已验证的）域名配置 SES
3. 发送邮件，From: admin@target.com
4. SPF 通过（因为 include:amazonses.com）
5. DMARC p=none -- 接收方不应用任何 DMARC 策略；投递结果取决于 SPF/DKIM 与本地过滤规则

## 真实案例

**实地观察（在取得投递证据后报告为严重）**：某组织两个域名均为 DMARC p=none，且 SPF 为 `include:amazonses.com`，通过另一个 SES 账户伪造的邮件被成功投递到一个受控收件箱。支撑该严重级别的是收件箱投递证据，而非单独的 p=none 记录。

## Pitfalls

| 问题 | 解决方案 |
|-------|----------|
| SPF 查询次数限制 | DNS 对 SPF include 有 10 次查询限制 |
| DKIM 选择器未知 | 尝试常见选择器：google、selector1、selector2、2022、2023 |
| DMARC 报告 | rua=mailto: 可能将认证结果泄露给第三方 |

## Verification

```bash
# Check the DMARC policy first
dig +short TXT _dmarc.target.com
# p=none means no DMARC enforcement — it does NOT by itself prove spoofing.
# Proof = a spoofed message actually delivered to an inbox you control:
swaks --to you@your-inbox.example --from ceo@target.com \
  --server <an-smtp-relay-you-control-or-localhost> --header-From "ceo@target.com"
# Then inspect the delivered message's Authentication-Results header:
# dmarc=none or dmarc=pass with an attacker-controlled source = confirmed.
# Reject/quarantine or spam-folder delivery = not demonstrated.
```
