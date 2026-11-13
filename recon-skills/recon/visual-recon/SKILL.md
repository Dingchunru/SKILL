---
name: visual-recon
description: 对所有存活主机截图，用于快速可视化研判和技术指纹识别。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, httpx, python3
metadata:
  tags: [recon, screenshot, visual, triage, fingerprinting, technology]
  category: recon
  related_skills:
    - subdomain-enumeration
    - source-leak-hunt
    - cms-detection
    - port-service-discovery
---

# 可视化侦察

自动对每台存活主机截图，从而以可视化方式研判数百个子域名，而不必逐个手动打开。结合技术指纹识别，可一眼看出技术栈、默认 CMS 安装页面、管理面板和配置不当的服务。几分钟内即可处理 500 台以上主机，并通过目视检查识别高价值目标。

## When to Use

- 你有 100 个以上存活子域名，需要快速确定目标优先级。
- 人工浏览对于批量侦察来说太慢。
- 需要识别默认安装页面（WordPress 安装向导、phpMyAdmin 登录页、Jenkins 仪表盘）。
- 希望跨子域名比对视觉指纹（共享基础设施）。
- 目标会根据 User-Agent 或地理位置返回不同内容。

## Prerequisites

- 带有 gowitness、httpx 和 curl 的 `terminal`。
- 已安装 `gowitness`：`go install github.com/sensepost/gowitness@latest`。
- 来自 `subdomain-enumeration` 的存活子域名列表。

## How to Run

```bash
# gowitness — fast, Go-based screenshot tool
gowitness file -f alive_subs.txt \
  -P ./screenshots/ \
  --no-http \
  --timeout 15 \
  --resolution-x 1440 \
  --resolution-y 900

# With database for searchable results
gowitness file -f alive_subs.txt -P ./screenshots/ --no-http \
  --db gowitness.db --chrome-window-x 1440 --chrome-window-y 900

# Query results
gowitness report list --db gowitness.db
```

## 快速开始

```bash
gowitness file -f alive_subs.txt -P ./screenshots/ --no-http
```

## Procedure

### 阶段 1 — 批量截图

```bash
# gowitness — fast, Go-based screenshot tool
gowitness file -f alive_subs.txt \
  -P ./screenshots/ \
  --no-http \
  --timeout 15 \
  --resolution-x 1440 \
  --resolution-y 900

# With database for searchable results
gowitness file -f alive_subs.txt -P ./screenshots/ --no-http \
  --db gowitness.db --chrome-window-x 1440 --chrome-window-y 900

# Query results
gowitness report list --db gowitness.db
gowitness report generate --db gowitness.db

# eyewitness — with HTML report generation
python3 EyeWitness.py \
  -f alive_subs.txt \
  --web \
  -d ./eyewitness_output/ \
  --timeout 15 \
  --no-prompt
```

### 阶段 2 — 针对 JS 渲染站点的无头模式

```bash
# Single-page applications need JS execution
gowitness single -u https://[SPA_COMPANY] \
  -P ./screenshots/ \
  --chrome-window-x 1440 --chrome-window-y 900

# Batch headless capture
cat spa_urls.txt | while read url; do
  gowitness single -u "$url" -P ./screenshots/
done
```

### 阶段 3 — 可视化分析模式

查看截图以寻找高价值特征：

```bash
# Extract all titles from screenshots for quick filtering
gowitness report list --db gowitness.db \
  | grep -iE "login|admin|dashboard|setup|install|phpmyadmin|jenkins|grafana|api|dev|staging|test"

# Look for default error pages (identifies specific web servers)
gowitness report list --db gowitness.db \
  | grep -iE "404|403|502|503|default|maintenance|under construction"
```

**应关注的内容：**

| 截图显示 | 含义 |
|---|---|
| WordPress 安装页面 | 全新的 WordPress — 在 /wp-admin/install.php 上测试注册 |
| phpMyAdmin 登录页 | 数据库访问面板 — 尝试默认凭据 |
| Jenkins 登录页 | CI/CD 服务器 — 检查是否存在未认证访问 |
| Grafana/Prometheus | 监控仪表盘 — 检查是否有公开数据 |
| IIS 默认页面 | Windows 服务器 — 检查 ASP.NET 端点 |
| Apache 默认页面 | 标准 Linux 服务器 — 检查 server-status |
| 错误堆栈跟踪 | 调试模式已开启 — 提取服务器路径和版本 |
| 目录列表 | 可读的文件树 — 检查配置文件 |
| 自定义端口上的登录表单 | 内部管理面板 — 最高优先级目标 |

### 阶段 4 — 可视化差异比对（多环境）

```bash
# Compare screenshots across subdomains to find shared infrastructure
# Same visual = shared server = if one is vulnerable, all are

ls screenshots/ | cut -d'-' -f1 | sort | uniq -c | sort -rn
# High count of identical-looking sites = mass vulnerability potential
```

### 阶段 5 — 基于截图的技术指纹识别

```bash
# whatweb — identifies CMS, frameworks, servers
whatweb -i alive_subs.txt -a 3 -t 50 --log-brief=cms_results.txt

# wappalyzer CLI — detailed tech stack
wappalyzer https://target.com

# httpx with tech detection built-in
cat alive_subs.txt | httpx -silent -tech-detect -o tech_detected.txt

# Extract unique technologies
cat tech_detected.txt | awk -F'[' '{print $2}' | tr -d ']' | tr ',' '\n' \
  | sort | uniq -c | sort -rn
```

### 阶段 6 — 基于截图的研判流水线

```bash
# Full pipeline: subdomains → alive → screenshot → filter → prioritize
cat all_subs.txt \
  | httpx -silent -mc 200 -o alive_200.txt

gowitness file -f alive_200.txt -P ./screenshots/ --no-http

# Generate report for manual review
gowitness report generate --db gowitness.db -o ./report/

# Extract login/admin pages for priority testing
gowitness report list --db gowitness.db \
  | grep -iE "login|admin|sign.?in|dashboard|panel|manage" \
  > priority_targets.txt
```

## Pitfalls

- **大批量截图可能撑爆磁盘。** 500 张 1440x900 的截图约 300MB。
- **JS 密集型 SPA 可能渲染为空白。** 使用无头模式并延长超时时间。
- **重定向链会截取重定向目标的图。** 这是正确的——你需要的是最终落点。
- **CAPTCHA 页面会浪费截图。** 在截图前过滤掉 CAPTCHA 主机。
- **慢速服务器会超时。** `--timeout 15` 通常足够；连接较慢时请延长。

## Verification

1. `alive_subs.txt` 中所有主机都有对应截图。
2. 目视检查确认每张截图都显示了有意义的内容（不是空白，也不是错误页）。
3. 技术识别结果与视觉指纹一致（WordPress favicon = WordPress CMS）。
4. 优先目标（登录面板、管理仪表盘、开发环境）已被识别并转入下一阶段。

---

## 相关技能

- **`subdomain-enumeration`** — 生成存活子域名列表。
- **`source-leak-hunt`** — 深入挖掘通过截图发现的单个主机。
- **`cms-detection`** — 对发现的主机进行自动化 CMS 和框架识别。
