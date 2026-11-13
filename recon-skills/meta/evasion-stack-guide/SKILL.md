---
name: evasion-stack-guide
description: 当需要判断某个被阻断的探测请求适用哪一层浏览器、TLS、HTTP/2 或行为模拟时使用。
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
  tags: [meta, evasion, anti-bot, fingerprint, decision-guide]
  category: meta
  related_skills:
    - tls-fingerprint-impersonation
    - http2-header-impersonation
    - stealth-browser-launch
    - humanize-automation
    - ops-proxyns
---

# 规避技术栈指南

四个技能分别覆盖客户端模拟的四个不同层次。它们互为补充，不可互换。应选择
能够解释阻断的最低层次，验证它确实修复了响应，然后才添加下一层。

## When to Use

- 尽管 URL 与方法都正确，请求仍被阻断或被质询。
- WAF/CDN 返回质询页面、无响应体的 403，或机器人评分墙。
- 你不确定阻断是基于 IP、基于 TLS、基于 HTTP/2 还是基于行为的。

## Prerequisites

- 对目标的授权，以及对其速率限制的了解。
- 一个能显示阻断*具体表现*（状态码、响应体、头部）的对照请求。

## How to Run

先诊断层次，然后加载所属技能：

| 症状 | 层次 | 技能 |
|---|---|---|
| 阻断跟随你的 IP；更换出口后结果变化 | 网络 | `ops-proxyns` |
| `curl` 被阻断但真实浏览器可通过；阻断与头部无关 | TLS (JA3/JA4) | `tls-fingerprint-impersonation` |
| TLS 一致但 H2 帧/头部暴露了你（Akamai、部分 CF 配置） | HTTP/2 | `http2-header-impersonation` |
| 请求通过，但 JS 质询/指纹将自动化标记出来 | 浏览器二进制 | `stealth-browser-launch` |
| 页面加载正常，但交互被评为机器人（reCAPTCHA v3、Turnstile） | 行为 | `humanize-automation` |

## Procedure

1. **建立基线。** 用 `curl`、用模拟技术栈、以及（如可能）用真实浏览器发送
   同一请求。对比状态码、响应体与 `Set-Cookie`/质询标记。
2. **先轮换出口**（`ops-proxyns`）。如果阻断消失，说明是 IP 信誉问题；到此为止。
3. **匹配 TLS**（`tls-fingerprint-impersonation`）。如果 `curl` 失败但浏览器在
   头部完全相同的情况下通过，那么 TLS ClientHello 就是暴露点。
4. **匹配 HTTP/2**（`http2-header-impersonation`）。伪头部顺序与 SETTINGS 帧
   是与 TLS 相互独立的另一种指纹。
5. **匹配浏览器二进制**（`stealth-browser-launch`），当 JS 质询必须被执行时：
   指纹标记、WebGL、WebRTC、时区。
6. **最后匹配行为**（`humanize-automation`）：鼠标轨迹、输入节奏、滚动。
   只有在更低层次通过之后，行为评分才重要。

## Pitfalls

- **层次混淆。** 当阻断处于 TLS 层时却添加浏览器隐身，会浪费数小时；始终通过
  基线对比来识别出问题的层次。
- **默认叠加所有手段。** 每增加一层都会带来脆弱性和可检测面。只有在上一层
  验证干净后才添加新层。
- **规避不等于授权。** 突破机器人防护墙并不改变范围；速率限制与授权规则依然适用。

## Verification

- 模拟请求返回的状态码/响应体类别与真实浏览器对照相同，而不仅仅是换了一种错误。
- 每增加的一层都应由其下一层测试失败来证明其必要性。
