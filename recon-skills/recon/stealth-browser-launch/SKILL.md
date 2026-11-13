---
name: stealth-browser-launch
description: 启动带 C++ 指纹补丁的隐蔽 Chromium 以绕过反机器人检测。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, httpx, nuclei, python3
metadata:
  tags: [recon, stealth, browser, anti-bot, fingerprint, chromium, playwright]
  category: recon
  related_skills:
    - humanize-automation
    - tls-fingerprint-impersonation
    - http2-header-impersonation
    - ops-proxyns
    - evasion-stack-guide
---

# 隐蔽浏览器启动

启动一个经过修改的 Chromium 二进制文件，其在 C++ 源码层面做了指纹修改，可绕过反机器人检测。该二进制在二进制层面伪造 canvas、WebGL、audio、GPU、屏幕、WebRTC、网络时序和自动化信号——而不是通过 JavaScript 注入或会在 Chrome 更新后失效的配置补丁。可通过 Cloudflare Turnstile、reCAPTCHA v3（0.9 分）、FingerprintJS、BrowserScan 以及 30 多个检测站点。

## When to Use

- 目标使用 Cloudflare、Akamai、DataDome 或 Kasada 封堵 curl/httpx/nuclei。
- 需要完整的浏览器 JavaScript 执行能力，用于提交表单、登录或 XSS 测试。
- 即使请求头正确，目标对所有未认证请求仍返回 403。
- 需要访问受 reCAPTCHA 保护的端点而不解决验证码。
- 在住宅代理之后运行自动化侦察——隐蔽浏览器可防止 IP 与 UA 关联。

## Prerequisites

- 具备 python3 和 pip 的 `terminal`。
- 已安装 `playwright`：`pip install playwright && playwright install-deps chromium`。
- 住宅代理（无论浏览器指纹如何，数据中心 IP 都会因信誉被封锁）。
- 可选：`cloakbrowser[geoip]`，用于根据代理出口 IP 自动解析时区/区域设置。

## How to Run

```bash
pip install cloakbrowser
python3 -c "
from cloakbrowser import launch
browser = launch()
page = browser.new_page()
page.goto('https://target.com')
print(page.title())
browser.close()
"
```

## 快速开始

```bash
pip install cloakbrowser
python3 -c "
from cloakbrowser import launch
browser = launch()
page = browser.new_page()
page.goto('https://target.com')
print(page.title())
browser.close()
"
```

## Procedure

### 阶段 1 — 基础隐蔽启动

该二进制在每次启动时自动生成随机指纹种子。基础隐蔽无需任何参数：

```python
from cloakbrowser import launch

browser = launch(
    headless=True,
    proxy="http://user:pass@residential-proxy:port",
    geoip=True,    # auto-detect timezone/locale from proxy exit IP
)
page = browser.new_page()
page.goto("https://target.com")
# Standard Playwright API from here
page.locator("input[name='username']").fill("test")
page.locator("button[type='submit']").click()
browser.close()
```

### 阶段 2 — 持久身份

在重复访问同一目标时使用固定指纹种子，以表现为回访访客：

```python
browser = launch(
    proxy="http://user:pass@residential-proxy:port",
    geoip=True,
    args=["--fingerprint=42069"],  # fixed seed = same fingerprint every launch
)
```

### 阶段 3 — 有头模式以获得最大隐蔽性

有些站点即使面对 C++ 补丁也能检测出无头模式。此时配合虚拟显示以有头模式运行：

```bash
# Start virtual display
Xvfb :99 -screen 0 1920x1080x24 &
export DISPLAY=:99
```

```python
browser = launch(
    headless=False,  # real rendering
    proxy="http://residential-proxy:port",
    geoip=True,
    humanize=True,   # human-like mouse/keyboard/scroll
)
```

### 阶段 4 — 指纹定制

覆盖特定指纹值以匹配目标环境：

```python
browser = launch(stealth_args=False, args=[
    "--fingerprint=42069",
    "--fingerprint-platform=windows",
    "--fingerprint-gpu-vendor=NVIDIA Corporation",
    "--fingerprint-gpu-renderer=NVIDIA GeForce RTX 3060/PCIe/SSE2",
    "--fingerprint-hardware-concurrency=16",
    "--fingerprint-device-memory=16",
    "--fingerprint-screen-width=2560",
    "--fingerprint-screen-height=1440",
    "--fingerprint-timezone=America/Sao_Paulo",
    "--fingerprint-locale=pt-BR",
    "--fingerprint-webrtc-ip=auto",
    "--fingerprint-noise=false",  # disable noise for FingerprintJS ML bypass
])
```

### 阶段 5 — 持久化配置文件

跨会话保留 cookie 和 localStorage，以绕过“首次访问”类挑战：

```python
from cloakbrowser import launch_persistent_context

ctx = launch_persistent_context(
    "./target-profile",
    headless=False,
    proxy="http://residential-proxy:port",
    geoip=True,
)
page = ctx.new_page()
page.goto("https://target.com")
# Session persists across restarts
ctx.close()
```

### 阶段 6 — 通过 CDP 多路复用器实现多身份

使用 cloakserve 在单个容器中运行多个浏览器身份：

```bash
docker run -d --name cloak -p 127.0.0.1:9222:9222 cloakhq/cloakbrowser cloakserve
```

```python
from playwright.sync_api import sync_playwright

pw = sync_playwright().start()

# Each unique fingerprint seed spawns separate Chrome process with independent identity
b1 = pw.chromium.connect_over_cdp("http://localhost:9222?fingerprint=11111")
b2 = pw.chromium.connect_over_cdp("http://localhost:9222?fingerprint=22222")

# Full identity control via query params
b3 = pw.chromium.connect_over_cdp(
    "http://localhost:9222?fingerprint=33333"
    "&timezone=America/New_York&locale=en-US&platform=windows"
    "&hardware-concurrency=4&device-memory=8"
)

# Each browser has independent cookies, localStorage, canvas noise
```

### 阶段 7 — 反机器人字体配置

针对会检查 canvas emoji 渲染的激进站点（Kasada、Akamai）：

```bash
apt install -y fonts-noto-color-emoji fonts-freefont-ttf fonts-unifont \
    fonts-ipafont-gothic fonts-wqy-zenhei fonts-tlwg-loma-otf
```

为规避 CreepJS 的字体枚举，安装 Windows 字体：

```bash
# Copy from Windows machine: C:\Windows\Fonts\
mkdir -p ~/.local/share/fonts/windows
cp /path/to/windows/fonts/SegoeUI*.ttf ~/.local/share/fonts/windows/
fc-cache -f

# Then launch with:
# browser = launch(args=["--fingerprint-fonts-dir=/home/user/.local/share/fonts/windows"])
```

## 指纹参数参考

| 参数 | 默认值 | 控制内容 |
|---|---|---|
| `--fingerprint=SEED` | 随机 5 位数字 | canvas/WebGL/audio/字体 的主种子 |
| `--fingerprint-platform` | `windows`/`macos` | `navigator.platform`、UA 操作系统、GPU 池 |
| `--fingerprint-gpu-vendor` | 自动 | WebGL UNMASKED_VENDOR_WEBGL |
| `--fingerprint-gpu-renderer` | 自动 | WebGL UNMASKED_RENDERER_WEBGL |
| `--fingerprint-hardware-concurrency` | 8 | `navigator.hardwareConcurrency` |
| `--fingerprint-device-memory` | 8 | `navigator.deviceMemory` |
| `--fingerprint-screen-width` | 1920/1440 | 屏幕宽度 |
| `--fingerprint-screen-height` | 1080/900 | 屏幕高度 |
| `--fingerprint-timezone` | — | IANA 时区 |
| `--fingerprint-locale` | — | BCP 47 区域设置 |
| `--fingerprint-webrtc-ip` | — | WebRTC ICE IP（`auto` 表示使用代理出口 IP） |
| `--fingerprint-noise=false` | true | 禁用 canvas/WebGL/audio 噪声 |
| `--fingerprint-fonts-dir` | — | 目标平台的字体路径 |
| `--fingerprint-windows-font-metrics` | — | 将字体度量对齐到 Windows（v148+） |
| `--fingerprint-storage-quota` | 自动 | 存储配额，单位 MB |
| `--fingerprint-taskbar-height` | 48/95/0 | 任务栏高度伪装 |

## Pitfalls

- **数据中心 IP 无论浏览器指纹如何都会被封锁。** 始终使用住宅代理。
- **`page.wait_for_timeout()` 会泄漏 CDP 流量，从而被 reCAPTCHA 检测到。** 请改用 `time.sleep()`。
- **Puppeteer 发出的 CDP 流量比 Playwright 更多。** 对 reCAPTCHA 密集的目标请使用 Playwright。
- **缺少字体会导致在 Kasada/Akamai 上 canvas 哈希不匹配。** 请安装阶段 7 中列出的字体包。
- **`--fingerprint-noise=false` 可能在 FingerprintJS 上触发基于 ML 的检测。** 仅在确实被其阻断时才禁用噪声。
- **即使有 C++ 补丁，无头模式仍可能被检测到。** 在激进站点上使用有头模式（`headless=False`）以获得最大隐蔽性。
- **二进制自动更新会被缓存约 24 小时。** 若需要可复现性，请用 `browser_version=` 固定版本。

## Verification

1. 针对 `https://browserscan.net` 测试——全部 4 项机器人检测应显示 NORMAL。
2. 针对 `https://demo.fingerprint.com/playground` 测试——不应显示 “nodriver” 或 “bot” 检测。
3. 针对 reCAPTCHA v3 测试：`https://antcpt.com/eng/information/demo-form/recaptcha-3-test-score.html`——分数应 ≥ 0.7。
4. 针对 `https://deviceandbrowserinfo.com` 测试——`isBot` 应为 false，且真值标记数为 0。
5. 用 `page.evaluate("navigator.webdriver")` 验证 `navigator.webdriver` 为 `false`。

---

## 相关技能

- **`humanize-automation`** — 类人鼠标/键盘/滚动操作，用于行为层面绕过。
- **`tls-fingerprint-impersonation`** — 在 HTTP 客户端层面伪造 TLS/JA4 指纹。
- **`http2-header-impersonation`** — 浏览器特有的 HTTP/2 伪首部顺序与 SETTINGS 帧。
