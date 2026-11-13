---
name: humanize-automation
description: 用于绕过行为型机器人检测的类人鼠标、键盘与滚动行为。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires python3
metadata:
  tags: [recon, humanize, behavioral, anti-bot, mouse, keyboard, automation]
  category: recon
  related_skills:
    - stealth-browser-launch
    - tls-fingerprint-impersonation
    - evasion-stack-guide
---

# 人性化自动化

将瞬时完成的程序化交互替换为类人的鼠标移动、键盘输入与滚动模式。在类级别对 Playwright 的 API 打补丁 —— `page.click()`、`page.type()`、`page.fill()` 以及 Locator 方法都会被自动替换为贝塞尔曲线鼠标轨迹、带误输入的逐字符输入，以及多阶段滚动加速。一个标志位（`humanize=True`）即可启用全部行为补丁，无需修改代码。

## When to Use

- 目标使用行为型机器人检测（鼠标轨迹分析、输入速度画像）。
- 在浏览器指纹正确的情况下，reCAPTCHA v3 评分仍然偏低（<0.3）。
- 目标在快速提交表单后超时或弹出质询。
- 需要模拟真实用户浏览会话以完成登录或账号注册。
- 目标使用基于 `requestAnimationFrame` 的鼠标移动追踪。

## Prerequisites

- 具备 python3 的 `terminal`。
- 已安装 `cloakbrowser`：`pip install cloakbrowser`。
- 或者使用带自定义补丁的独立 Playwright：从 humanize 模块导入 `patch_page`。

## How to Run

```bash
export TARGET="https://target.com/login"
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

python3 - "$TARGET" <<'PY'
import sys
from cloakbrowser import launch

browser = launch(humanize=True)
page = browser.new_page()
page.goto(sys.argv[1])
print(page.title())
browser.close()
PY
```

## 快速开始

```python
from cloakbrowser import launch

browser = launch(humanize=True)
page = browser.new_page()
page.goto("https://target.com/login")

# All interactions are automatically humanized
page.locator("#email").fill("user@example.com")     # per-character timing
page.locator("#password").fill("password123")       # with thinking pauses
page.locator("button[type=submit]").click()         # Bézier curve movement
browser.close()
```

## Procedure

### 阶段 1 — 默认人性化

一个标志位即可启用全部行为补丁：

```python
browser = launch(
    headless=False,
    proxy="http://residential-proxy:port",
    geoip=True,
    humanize=True,  # enables all behavioral patches
)
page = browser.new_page()
page.goto("https://target.com")

# All Playwright interactions are replaced with human-like equivalents
page.locator("input[name='search']").fill("restricted query")
page.locator("button[type='submit']").click()
```

### 阶段 2 — 谨慎模式（更慢、更从容）

适用于会对交互速度进行画像的站点：

```python
browser = launch(
    humanize=True,
    human_preset="careful",  # slower typing, more idle pauses
)
```

谨慎预设变更：输入 100±50ms（对比 70±40ms）、点击瞄准 80-180ms（对比 60-140ms）、启用带 0.4-1.0s 停顿的 `idle_between_actions`。

### 阶段 3 — 自定义行为配置档

针对特定站点微调，覆盖单个参数：

```python
from cloakbrowser import HumanConfig

custom = HumanConfig(
    typing_delay=150,
    typing_delay_spread=60,
    typing_pause_chance=0.15,
    mistype_chance=0.03,
    mouse_wobble_max=2.0,
    click_aim_delay_input=(100, 200),
    scroll_delta_base=(60, 100),
    idle_between_actions=True,
    idle_between_duration=(0.5, 1.5),
)

browser = launch(humanize=True, human_config=custom)
```

### 阶段 4 — 单次调用覆盖

针对单次交互覆盖行为参数：

```python
# Slow, careful typing for password field
page.locator("#password").fill("secret", human_config={"typing_delay": 200})

# Fast click (bypass aim delay)
page.locator("#submit").click(human_config={"click_aim_delay_input": (0, 0)})
```

### 阶段 5 — 独立人性化（不依赖 CloakBrowser）

对已有的 Playwright page 打补丁：

```python
from playwright.sync_api import sync_playwright
from cloakbrowser.human import patch_page, resolve_config

pw = sync_playwright().start()
browser = pw.chromium.launch()
page = browser.new_page()

# Apply humanization to an existing page
config = resolve_config("default")
patch_page(page, config)

# All interactions now humanized
page.locator("#email").fill("user@example.com")
```

## 行为参数参考

### 鼠标移动

| 参数 | 默认值 | 效果 |
|---|---|---|
| `mouse_steps_divisor` | 8 | 控制平滑度（越小越平滑、步数越多） |
| `mouse_min_steps` | 25 | 每次移动的最小步数 |
| `mouse_max_steps` | 80 | 每次移动的最大步数 |
| `mouse_wobble_max` | 1.5 px | 横向正弦抖动幅度 |
| `mouse_overshoot_chance` | 0.15 | 冲过目标的概率 |
| `mouse_overshoot_px` | (3, 6) px | 冲过目标的距离 |

**移动算法：** 三次贝塞尔曲线，带 2 个随机垂直控制点 → 三次缓入缓出 → 正弦抖动 → 15% 概率冲过目标并回正。

### 键盘输入

| 参数 | 默认值 | 效果 |
|---|---|---|
| `typing_delay` | 70 ms | 每个字符的平均延迟 |
| `typing_delay_spread` | 40 ms | 围绕延迟的随机浮动范围 |
| `typing_pause_chance` | 0.10 | 每个字符出现思考停顿的概率 |
| `typing_pause_range` | (400, 1000) ms | 思考停顿持续时间 |
| `mistype_chance` | 0.02 | 每个字符打错的概率 |
| `mistype_delay_notice` | (100, 300) ms | 意识到打错所需时间 |
| `mistype_delay_correct` | (50, 150) ms | 纠正错误所需时间 |
| `field_switch_delay` | (800, 1500) ms | 在表单字段之间切换时的延迟 |

**输入算法：** 带随机浮动的逐字符延迟 → 10% 概率停顿 → 2% 概率打错（邻近键 → 察觉 → 退格 → 重打）→ Shift 符号通过 CDP `Input.dispatchKeyEvent` 发送以使 `isTrusted=true`。

### 滚动

| 参数 | 默认值 | 效果 |
|---|---|---|
| `scroll_delta_base` | (80, 130) px | 每步滚动距离 |
| `scroll_accel_steps` | (2, 3) | 加速阶段的步数 |
| `scroll_decel_steps` | (2, 3) | 减速阶段的步数 |
| `scroll_overshoot_chance` | 0.10 | 冲过目标的概率 |
| `scroll_overshoot_px` | (50, 150) px | 冲过目标的距离 |
| `scroll_target_zone` | (0.20, 0.80) | 视口中的目标区域 |
| `scroll_settle_delay` | (300, 600) ms | 到达目标后的延迟 |

**滚动算法：** 加速（2-3 步，80-100px）→ 巡航（80-130px，拆分为 20-40px 的滚轮小块，间隔 8-20ms）→ 减速（2-3 步，60-90px）→ 10% 概率冲过目标并回正。

### 点击行为

| 参数 | 默认值 | 效果 |
|---|---|---|
| `click_aim_delay_input` | (60, 140) ms | 点击输入元素前的延迟 |
| `click_aim_delay_button` | (80, 200) ms | 点击按钮前的延迟 |
| `click_hold_input` | (40, 100) ms | 在输入元素上的按住时长 |
| `click_hold_button` | (60, 150) ms | 在按钮上的按住时长 |
| `click_input_x_range` | (0.05, 0.30) | 输入框内的点击位置（偏左侧） |

### 空闲行为

| 参数 | 默认值 | 效果 |
|---|---|---|
| `idle_between_actions` | False | 是否在动作之间启用微小移动 |
| `idle_between_duration` | (0.3, 0.8) sec | 动作之间的空闲时长 |
| `idle_drift_px` | 3 px | 空闲期间光标的随机漂移 |
| `idle_pause_range` | (300, 1000) ms | 空闲停顿持续时间 |
| `initial_cursor_x` | (400, 700) px | 光标起始 X 坐标（地址栏区域） |
| `initial_cursor_y` | (45, 60) px | 光标起始 Y 坐标（地址栏区域） |

### 预设

| 预设 | 输入 | 瞄准延迟 | 动作间空闲 | 适用场景 |
|---|---|---|---|---|
| `default` | 70±40ms | 60-140ms | 否 | 正常人类速度 |
| `careful` | 100±50ms | 80-180ms | 是（0.4-1.0s） | 更慢、更从容 |

## Pitfalls

- **人性化依赖封装层。** 不经封装层直接通过 CDP 连接会丢失人性化 —— 裸 CDP 上只有指纹补丁生效。
- **在 Playwright 中 ElementHandle 对象会绕过人性化。** 使用 `page.click(selector)` 或 `page.locator(selector).*` —— 避免 `query_selector()` 返回的句柄。
- **启用人性化时 `page.fill()` 会先清空原有内容，再逐字符输入。** 这是有意为之，但比原生 `fill()` 慢。
- **存在输入速度画像。** 部分站点会测量每次击键之间的毫秒间隔。对可疑目标使用 `careful` 预设或增大 `typing_delay`。
- **滚动到元素是自动完成的。** 点击/悬停时，会先用人类化滚动将元素滚入视野再交互。
- **CDP 隔离世界用于隐蔽的 DOM 查询。** 这可以防止在主 JavaScript 上下文中被检测到 monkey-patch。

## Verification

1. 针对 `https://deviceandbrowserinfo.com` 测试 —— 应显示 24/24 项行为信号通过。
2. 对比开启与不开启 `humanize=True` 时的 reCAPTCHA v3 评分 —— 人性化应使评分提升 0.2-0.4。
3. 使用浏览器 DevTools 的 Performance 面板录制一次会话 —— 鼠标事件应呈现真实的时序曲线，而不是瞬时跳变。
4. 在事件监听器中确认 `Input.dispatchKeyEvent` 事件的 `isTrusted: true`。

---

## 相关技能

- **`stealth-browser-launch`** —— 启动带有 C++ 指纹修改的补丁版 Chromium 二进制。
- **`tls-fingerprint-impersonation`** —— 用于 HTTP 层规避的 TLS/JA4 指纹仿冒。
