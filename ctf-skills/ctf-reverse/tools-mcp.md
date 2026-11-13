# CTF Reverse - MCP 服务器集成

模型上下文协议（Model Context Protocol，MCP）服务器让智能体直接驱动反汇编器/反编译器，而不必在 GUI 里复制粘贴。逆向工程中真正重要的三个是 **IDA Pro MCP**、**Ghidra MCP** 和 **JADX MCP**（Android）。本文件是 MCP 的权威参考 —— `ctf-pwn` 交叉链接到这里共享工具链，只记录各自的用例。

## 目录
- [黄金法则：先看伪代码，失败再看汇编](#黄金法则先看伪代码失败再看汇编)
- [IDA Pro MCP（智能体驱动的反编译）](#ida-pro-mcp智能体驱动的反编译)
- [Ghidra MCP（免费反编译器，自主 RE）](#ghidra-mcp免费反编译器自主-re)
  - [无头服务器陷阱](#无头服务器陷阱全部在真实运行中踩过)
  - [反编译器有体积墙](#反编译器有体积墙--调用前先查函数大小)
  - [最要命的一条：默认分析会静默丢弃调用参数](#最要命的一条默认分析会静默丢弃调用参数)
- [JADX MCP（Android APK / DEX）](#jadx-mcpandroid-apk--dex)
  - [跨越 JNI 边界：直接运行 `.so`，别去逆向它](#跨越-jni-边界直接运行-so别去逆向它)
    - [当 harness 失败时 —— 而它一定会失败](#当-harness-失败时--而它一定会失败)
- [何时用 MCP，何时用 CLI](#何时用-mcp何时用-cli)

WinDbg MCP（Windows 崩溃转储、用户态实时调试、内核调试）见 [../ctf-pwn/tools-mcp.md](../ctf-pwn/tools-mcp.md#windbg-mcpwindows-崩溃转储实时与内核调试)。较早的 Ghidra `MCP Commands` 速查见 [tools.md](tools.md#mcp-命令)。

---

<a id="golden-rule-pseudocode-first-assembly-only-when-it-fails"></a>
## 黄金法则：先看伪代码，失败再看汇编

**在碰汇编之前，永远先调用反编译器。** IDA（Hex-Rays）和 Ghidra 都提供 `decompile`/`decompile_function` 工具，返回可读的伪 C 代码。先读它 —— 它能把几百条指令压缩成几行逻辑，让你一遍就能想清楚，而且比逐条看汇编在 agent token 消耗上便宜得多。

```text
# Preferred order for any function of interest
1. decompile <func>        # read the logic as pseudo-C   ← default
2. xrefs_to <target>       # follow data/call relationships
3. rename / set_comment    # persist understanding in the database
4. disassemble <func>      # ONLY if decompiler output is wrong/missing
```

**只有**当反编译器放弃或说谎时，才下探到汇编（`disassemble_function` / `disasm`）：

- 重度混淆、不透明谓词，或控制流平坦化
- 手写汇编 / shellcode，没有干净的 C 表示
- 函数边界缺失或损坏（先定义函数，再重试）
- 反编译器隐藏的指令级细节（具体 SIMD 操作、对齐、计时 gadget、系统调用号）

**关键洞见：** 反编译结果是地图，汇编是地形。先看地图。一次 `decompile` 调用往往就能揭示整个 flag 校验算法（异或循环、比较目标、自定义哈希），让你省掉 90% 的人工读汇编。只有当地图空白或错误时，才放大看指令。

---

<a id="ida-pro-mcp-agent-driven-decompilation"></a>
## IDA Pro MCP（智能体驱动的反编译）

仓库：`https://github.com/mrexodia/ida-pro-mcp`（MIT）。作者是 x64dbg 的维护者 —— 这个 IDA MCP 服务器是事实标准。它有**两种模式**，两种模式下工具名不同：

- **GUI 插件** —— `ida-pro-mcp --install` 安装插件，目标在 IDA GUI 中打开时提供 HTTP MCP 端点（默认 `http://127.0.0.1:13337/mcp`）。经典短名：`list_functions`、`decompile_function`、`get_xrefs_to`、`rename_function`、`set_comment`。
- **idalib 无头模式** —— 独立的 `idalib-mcp` 服务器在无 GUI 的情况下驱动 IDA，暴露**更丰富、基于会话的**工具集（`survey_binary`、`analyze_function`、`trace_data_flow`、查询 DSL、`make_signature`、`patch`）。这是自主解题时杠杆更高的模式；配置好后优先用它。

**安装：**

```bash
pip install ida-pro-mcp
ida-pro-mcp --install          # GUI mode: open target in IDA, client connects to :13337
# Headless (no GUI) is the idalib-mcp server; it manages IDA sessions itself. Verify:
#   claude mcp list            # the idalib server should read "Connected"
```

**会话模型（idalib 无头）：** 每次调用都要带 `idb_open` 返回的 `database` 会话 id —— 先打开二进制，然后把该 id 贯穿到后续所有调用。

```text
idb_open input_path=/path/to/chall   # opens + auto-analyzes + warms Hex-Rays
# -> {"success":true,"session":{"session_id":"f0bbe3af",...}}
#    the id you need is session.session_id, NOT a top-level "session" string
idb_list                             # enumerate open sessions (server_health probes one)
# pass database="f0bbe3af" to EVERY subsequent tool call
idb_save database=f0bbe3af           # persist annotations back to the .i64
```

`idb_open` 有两个选项值得了解：

- **`idle_ttl_sec`（默认 600）** —— 无头 worker 空闲 10 分钟后自行退出，会话随之消失。长时间挑战中要调大它，否则思考间隙之后 `database=<id>` 就会开始失败。worker 退出前还会在二进制旁边持有 `.id0/.id1/.nam` 锁文件。
- **`mode`** —— `prefer_headless`（默认）、`force_headless`、`prefer_gui`（若存在运行中的 IDA GUI 则接管）、`force_gui`。若希望你的注释出现在已经打开的 GUI 里，用 `prefer_gui`。

**核心工具（idalib 名称；括号内为 GUI 插件等价物）：**

- 摸底：`survey_binary`（一次调用完成整二进制概览）、`list_funcs`（`list_functions`）、`list_strings`、`list_imports`、`list_globals`、`list_segments`
- 查询 DSL：`func_query`、`insn_query`、`xref_query`、`type_query`、`imports_query` —— 按名称正则 / 大小 / 类型信息过滤，支持分页
- 分析：`decompile`（`decompile_function`）、`analyze_function`（一次调用返回伪代码 + 字符串 + 常量 + 调用者 + 被调用者 + 交叉引用 + 基本块）、`disasm`（`disassemble_function`）、`basic_blocks`、`callgraph`、`callees`
- 交叉引用与数据流：`xrefs_to`（`get_xrefs_to`）、`xrefs_to_field`、`trace_data_flow`（自动多跳，`direction=forward|backward`，`max_depth`）
- 搜索：`find`（一次调用、多个目标；`type` = `string` | `immediate` | `data_ref` | `code_ref`）、`search_text`（渲染列表，`regex=true`、`code_only`、`start`/`end` 限定范围、`limit` 默认 30）、`find_bytes`、`find_regex`、`get_string`、`get_bytes`
- 标注：`rename`（`rename_function`）、`set_comments`（`set_comment`）、`append_comments`、`add_bookmark`、`set_type`、`declare_type`、`set_function_prototype`、`infer_types`
- 签名与打补丁：`make_signature`（最短唯一字节签名，可跨重编译存活 —— 非常适合识别库函数）、`patch` / `patch_asm`（击败反调试、强制某个分支）、`make_data`、`define_func`

**`xrefs_to` 不接受字符串内容。** 它只解析**地址或符号/函数名** —— 传字符串文本会返回 `{"error":"Not found: '<text>'"}`。永远先用 `find` 把字符串解析成地址。这个两步操作是这里最常见的浪费调用方式：

```text
find type=string targets=["Correct!","Wrong"] database=<sid>   # -> match addresses
xrefs_to addrs=["0x140009640"] database=<sid>                  # -> the checker
```

**直达 flag 校验器的最快路径（idalib）：**

```text
idb_open input_path=./chall                  # -> session.session_id, use as database=
survey_binary database=<sid>                 # ONE call: entry, top strings, top funcs by xref, imports
find type=string targets=["Correct","flag{"] database=<sid>    # string -> address
xrefs_to addrs=[<string_addr>] database=<sid>                  # address -> the checker
analyze_function addr=<check_fn> database=<sid>  # pseudo-C + constants + callers, one call
trace_data_flow addr=<input_buf> direction=forward database=<sid>  # input -> the compare
rename addr=<check_fn> name=verify database=<sid>
set_comments database=<sid> ...              # breadcrumbs; then idb_save
```

`survey_binary` 把导入按 `crypto` / `network` / `file_io` / `process` / `registry` / `other` 分桶 —— `crypto` 桶非空，就能在你读一行伪代码之前判断出算法家族。当字符串搜索一无所获时，`find type=immediate` 是常量猎手（TEA 的 delta `0x9E3779B9`、MD5/SHA 初始字、自定义异或密钥）；它匹配的是 IDA 记录的立即数操作数，所以未命中意味着"不是立即数操作数"，而不是"不在二进制里"。

**Token 纪律** —— 这些默认值在大目标上很关键：函数超过 1 万个时用 `survey_binary detail_level="minimal"`，保持 `analyze_function include_asm=false`（本来就是默认值 —— 别打开），用 `decompile include_addresses=false` 去掉每行的 `/*0xNNNN*/` 标记。`find` 通过返回的 `cursor` 分页（`limit` 默认 1000，最大 10000）。

**关键洞见：** `survey_binary` 把整个摸底阶段（元数据、段、入口点、按交叉引用数排序的字符串和函数、按类别分桶的导入、调用图摘要）压缩成**一次**调用 —— 每次开启无头 IDA 会话都用它，而不是分别调用 `list_*`。然后 `analyze_function` 一次性返回伪代码以及所有卫星事实（调用者、被调用者、常量、交叉引用、基本块数量和圈复杂度），`trace_data_flow` 自动从输入缓冲区追到比较处。这三者替代了十几次 GUI 往返，正是 idalib 工具集相对经典 GUI 插件名带来的真正提速 —— 只要记住 `find` → `xrefs_to` 这一跳，因为字符串是常见的入口，而 `xrefs_to` 无法从字符串起步。

---

<a id="ghidra-mcp-free-decompiler-autonomous-re"></a>
## Ghidra MCP（免费反编译器，自主 RE）

仓库：`https://github.com/bethington/ghidra-mcp`（Apache-2.0）。没有 IDA 许可证时用它。它的标志性特性是**独立的无头服务器**：这里的 Ghidra MCP *不*需要 GUI，因此智能体可以直接从 shell 把整套栈拉起来。

它在一个 Ghidra 内核上提供两个独立前端：

| 模式 | 需要 GUI？ | 运行方式 |
|---|---|---|
| **无头服务器**（`GhidraMCPHeadlessServer`） | 否 | 纯 `java -cp ...`，HTTP 监听 **:8089** |
| GUI 插件 | 是 | CodeBrowser 扩展，**同样 :8089**，并且必须点击 *Tools > GhidraMCP > Start MCP Server* |

两者都由同一个 `bridge-mcp-ghidra` Python 桥接器前置，它是一个 MCP↔HTTP 多路复用器，暴露 **222 个 MCP 工具**。优先选无头：不需要显示器，几秒启动，目标从命令行传入。

**两种模式默认使用同一个端口**，所以它们相互冲突，而不是与其他东西冲突 —— `GhidraMCPHeadlessServer` 和 `GhidraMCPPlugin` *两者*中都是 `DEFAULT_PORT = 8089`。端口被占用时 GUI 插件会依次尝试 `8089, 8090, …`，所以如果你留着无头服务器在跑，GUI 会静默落到另一个端口，而 `GHIDRA_MCP_URL` 指向错误那个。一次只跑一个。（LaurieWired 时代的旧笔记写 `:8080` —— 那个数字在这里不适用。）

**版本下限是硬门槛。** `tools/setup/versioning.py` 对 **major.minor 精确比较**（`is_ghidra_version_compatible`），而 pom 固定了 `12.1.2` —— 因此需要 Ghidra **12.1.x** 安装，11.x 并不"差不多"。用 `cat $GHIDRA_HOME/Ghidra/application.properties` 检查。

**安装 —— 不需要 Maven，不需要 Docker。** 从仓库的 [Releases 页面](https://github.com/bethington/ghidra-mcp/releases) 拿预构建产物（作者版本更新频繁 —— 总取最新；无需 `mvn`/Docker 构建）：`GhidraMCP-<ver>.zip` 扩展（包含无头类）和 `ghidra_mcp_bridge-<ver>-py3-none-any.whl` 桥接器。用 `uv tool install` 安装 wheel（→ `~/.local/bin/bridge-mcp-ghidra`），`unzip` 扩展得到 `GhidraMCP/lib/GhidraMCP-<ver>.jar`。

**原生启动无头服务器**（仓库只记录了 Docker 方式；这里用的 classpath 与其 `docker/entrypoint.sh` 构建的相同）：

```bash
GHIDRA_HOME=~/ghidra_12.1.x_PUBLIC        # major.minor must match the release's pin
CP=/path/to/GhidraMCP.jar                 # the unzipped GhidraMCP-<ver>.jar
for d in Framework Features Processors; do
  for j in "$GHIDRA_HOME"/Ghidra/$d/*/lib/*.jar; do CP="$CP:$j"; done
done
java -Xmx4G -Dghidra.home="$GHIDRA_HOME" -Dapplication.name=GhidraMCP \
     -cp "$CP" com.xebyte.headless.GhidraMCPHeadlessServer \
     --port 8089 --bind 127.0.0.1 --file /path/to/target.bin &

curl -s http://127.0.0.1:8089/check_connection   # "Connection OK - GhidraMCP Headless Server ..."
```

然后把 MCP 客户端指向桥接器（`GHIDRA_MCP_URL` 是它找到 HTTP 服务器的方式，无论哪个模式在跑）：

```jsonc
"ghidra-mcp": {
  "command": "/home/<you>/.local/bin/bridge-mcp-ghidra",
  "args": ["--transport", "stdio", "--no-lazy"],
  "env": { "GHIDRA_MCP_URL": "http://127.0.0.1:8089/" }
}
```

用 `--no-lazy`：实测 `--lazy` 只暴露 **96** 个工具（默认的 `listing,function,program` 分组），而 `--no-lazy` 有 **222** 个。缺的 126 个需要一次 `tools/list_changed` 往返，客户端可能永远不做，症状是工具"不存在"而不是报错。

**分析不是自动的。** 刚用 `--file` 载入的程序会报告 `Function Count: 0`，直到你 `POST /run_analysis`（小二进制约 3-12 秒）。在那之前反编译得不到有用内容。

<a id="headless-server-traps-all-hit-on-a-real-run"></a>
### 无头服务器陷阱（全部在真实运行中踩过）

- **`/load_program` 需要 JSON 请求体 —— README 里表单编码的例子是错的。** `-d "file=/path"` 返回 `{"error":"file path required"}`；只有 `-H 'Content-Type: application/json' -d '{"file":"/path"}'` 有效。
- **`/load_program` 会添加程序，但不会把它设为默认目标。** 它返回 `{"success":true,"program":"hello"}`，然而 `/get_metadata` 和 `/run_analysis` 仍然在回答服务器启动时那个二进制。解决办法不是重启：**每个工具都接受可选的 `program=<name>`** 选择器，靠它来区分。

  ```bash
  curl -s -X POST -H 'Content-Type: application/json' \
       -d '{"file":"/bin/true"}' :8089/load_program      # -> {"program":"true"}
  curl -s ":8089/get_metadata"                           # -> Program Name: hello   (the original)
  curl -s ":8089/get_metadata?program=true"              # -> Program Name: true    (selected)
  ```

  传一个不存在的名字来枚举已加载的程序 —— 错误信息会列出来：`{"error":"Program not found: __nope__ Available programs: true, hello"}`。**一旦载入第二个程序，每次调用都要传 `program=`**，否则你会静默分析错误的二进制。
- **`list_functions` 不接受 `limit`/`offset`** —— 它的签名是 `list_functions(program)`，传了会被静默忽略（`limit=10` 和 `limit=500` 返回相同输出）。不过它**没有**被截断：它返回每一个真实函数，在一个静态链接二进制上验证为 2417/2417。需要分页时，`list_functions_enhanced(offset, limit, program)` 和 `search_functions(name_pattern, offset, limit, program)` 都有。
- **`/get_metadata` 里的 `Function Count` 比 `list_functions` 大 —— 这个差额是 EXTERNAL 导入，不是缺失的函数。** 不要据此去翻找"隐藏"函数：

  ```text
  hello  (dynamic ELF): Function Count 32, list_functions 23  -> 9 = the 9 EXTERNAL imports
  chall  (static ELF):  Function Count 2417, list_functions 2417 -> no externals, no gap
  ```

  先用 `list_imports` 交叉验证（条目显示为 `EXTERNAL:0000000N`），再下"有东西被藏起来"的结论。
- **`program=` 只能作为查询参数生效 —— 放在 JSON 请求体里会被静默忽略。** 这一条会*悄悄分析错误的二进制*：

  ```bash
  curl -X POST -H 'Content-Type: application/json' -d '{"program":"chall"}' \
       :8089/run_analysis          # -> {"success":true,...,"program":"hello"}   ← WRONG TARGET
  curl -X POST ":8089/run_analysis?program=chall"
                                   # -> {"success":true,"total_functions":2417,"program":"chall"}
  ```

  注意这与 `/load_program` 正好相反，后者*要求* `file` 放在 JSON 请求体里。API 不一致，所以**永远要读响应中的 `"program"` 字段**，确认自己到底动的是哪个二进制。
- **MCP 工具 schema 与原始 HTTP 端点并不总是一致 —— 相信 MCP 一侧。** `disassemble_bytes` 通过 MCP 声明 `start_address`（必填），但 HTTP 端点拒绝 `?start_address=...`，报 `start_address parameter required`。通过 MCP 客户端传*同样的*参数却可以工作，并返回结构化 JSON：

  ```text
  disassemble_bytes program="hello" start_address="0x001011a9" length=48
  # -> {"success":true,"bytes_disassembled":48,"instructions":[
  #      {"address":"001011a9","mnemonic":"ENDBR64",...}, ...],"truncated":false}
  ```

  所以 curl 适合摸底，但当某个端点对你 schema 明明声明的参数提出异议时，先走 MCP，再断定工具坏了。
- **`search_functions` 是子串匹配，而且诱饵排在最前。** `name_pattern="main"` 会返回 `__libc_start_main @ 00105000`，*先于* `main @ 001011a9`。取了第一个命中，你反编译的就是一个 PLT 桩 —— `void __libc_start_main(void) { halt_baddata(); }` —— 看起来像反编译器坏了，其实是你自己的错误。知道确切名字时**锚定精确名称**。
- **MinGW/PE 会给符号加 `_` 前缀** —— 这是上一条的镜像情况：用 `\bmain\b` grep 会*漏掉* `_main at 00401460`。所以先宽松匹配找候选，再有意识地选精确符号。

<a id="the-decompiler-has-a-size-wall--check-function-size-before-calling-it"></a>
### 反编译器有体积墙 —— 调用前先查函数大小

`decompile_function` 在大函数上返回 `{"error":"Decompilation did not complete. Reason: Exception while decompiling <addr>: process: timeout"}`。Ghidra 是**一次反编译整个函数**（SSA 构建、数据流、类型传播、控制流结构化），开销随体积超线性增长 —— 这里一个 CTF 二进制的 `main` 函数体是 `00401110 - 004092db`，即 **33 KB ≈ 8300 条 AArch64 指令**，直接超出默认超时。

在花掉这次调用*之前*先查大小：

```text
get_function_by_address address=0x00401110
# -> Body: 00401110 - 004092db      ← 0x81CB bytes; do not expect a fast decompile
```

静态链接、strip 过、重度内联的二进制经常产生这种函数。**不要**先假定这是 Ghidra 的边界错误并试图"拆分"函数 —— 先验证，因为它往往是真正巨大的函数（这里它以真正的 `ret` 结束，紧跟着就是下一个 prologue）。

三条出路，从最便宜的开始：

1. **只读你需要的窗口。** 有意思的代码通常在字符串交叉引用附近。`get_xrefs_to` 给出确切地址；反汇编它周围几百字节，而不是反编译 33 KB。
2. **调大 `timeout`**（`decompile_function(address, program, timeout)`）并放到后台跑 —— 这*确实*有效：对那个 33 KB 函数用 `timeout=1200` 跑完了并返回**约 1 MB 的 C 代码**。预留 10-20 分钟，不要让它阻塞会话。准备好面对满屏 `undefined1 auVar[16]` SIMD 临时变量（来自完全展开的内联加密），对你真正关心的那几百字节来说，它往往比汇编更难读。
3. **单个窗口的 CLI 兜底** —— `radare2`（`r2 -q -c "s <addr>; pd 50" bin`）是瞬时的。注意发行版主机上的原生 `objdump` 对跨架构目标常常失败（AArch64 上 `can't disassemble for architecture UNKNOWN!`）；`r2` 不需要额外 binutils 包就能处理。

<a id="the-big-one-default-analysis-silently-drops-call-arguments"></a>
### 最要命的一条：默认分析会静默丢弃调用参数

在 32 位 PE 上，开箱即用的分析器集合会把函数反编译成没有参数的调用 —— 每个字符串常量，*包括 flag*，都会消失：

```c
___main();  puts();  printf();  scanf();  printf();   // ← useless
```

默认有两个分析器是关的（用 `GET /list_analyzers` 确认）：`Stack.Create Param Variables` 和 `WindowsPE x86 Propagate External Parameters`。打开它们并重新分析：

```bash
for a in "WindowsPE x86 Propagate External Parameters" "Stack.Create Param Variables"; do
  curl -s -X POST --data-urlencode "name=$a" --data-urlencode "enabled=true" \
       http://127.0.0.1:8089/configure_analyzer
done
curl -s -X POST http://127.0.0.1:8089/run_analysis
```

```c
puts("Hello, World!");                    // ← same function, after the fix
printf("Input: ");
scanf(&DAT_0040507a,local_14);
printf("You entered: %d\n",local_14[0]);
```

**在断定一个二进制没有有趣的字符串之前，先做这件事。** 无参数的反编译结果不是"程序是空的"的证据 —— 那是分析器配置错误，而且它会把 flag 藏起来不给你看。

**如果无头服务器不可用**，退回到带 post-script 的 `analyzeHeadless` 做批量反编译（导入 + 完整分析一个小 PE 约 13 秒），或退回到 `objdump -d` / `radare2` 处理单个函数 —— 两者都比干等 GUI 强。

**这里没有 Burp 冲突。** [ctf-web](../ctf-web/tools-mcp.md) 把 Burp 代理放在 8080；这个服务器用 8089，所以 web 和逆向挑战可以在同一会话中运行。如果确实需要挪端口，在 *CodeBrowser > Edit > Tool Options > GhidraMCP HTTP Server* 下修改 GUI 插件端口，并同步设置 `GHIDRA_MCP_URL`。

**核心工具**（`--no-lazy` 下暴露 222 个；下面这些是真正撑起一道题的）：

- 侦察：`list_functions`、`list_methods`、`list_classes`、`list_imports`、`list_exports`、`list_segments`、`list_strings`、`list_data_items`、`list_namespaces`、`get_metadata`、`get_current_program_info`
- 搜索：`search_functions`（**`name_pattern`**、`offset`、`limit`）、`search_functions_enhanced`、`search_byte_patterns`、`find_similar_functions`
- 分析：`decompile_function`、`batch_decompile`、`force_decompile`、`disassemble_function`、`get_function_by_address`
- 交叉引用：`get_xrefs_to`、`get_xrefs_from`、`get_function_xrefs`
- 标注：`rename_function`、`rename_function_by_address`、`rename_variable`、`rename_data`、`set_decompiler_comment`、`set_disassembly_comment`、`set_function_prototype`、`set_local_variable_type`
- 生命周期：`load_program`、`run_analysis`、`configure_analyzer`、`list_analyzers`

**一切都以地址为目标，而不是名字。** `decompile_function` 的签名是 `decompile_function(address, program, timeout)`，**`address` 必填** —— 没有按名字的形式，`?name=main` / `?function=main` 都返回 `{"error":"Address or function name is required"}`。先把名字解析成地址：

```text
search_functions name_pattern="main" limit=20      # NOT query=/name= — the param is name_pattern
# -> main at 001011a9
decompile_function address="0x001011a9"
```

读 schema，别猜参数名 —— 这个服务器会拒绝那些显而易见的猜法（`query`、`name`、`term`、`q` 在 `search_functions` 上全部失败）。

**旧版 GhidraMCP 构建里的四个工具名已经不存在了**，调用它们只是浪费回合：`decompile_function_by_address`（已并入 `decompile_function`）、`search_functions_by_name`（现为 `search_functions`），以及 `get_current_function` / `get_current_address`（无头模式下没有 GUI 光标 —— 用 `get_current_program_info`）。

**分页是按工具的，不是通用的。** `list_strings(offset, limit, filter, program)` 能分页也能过滤；`list_functions(program)` 两者都不能（见上面的陷阱）。在假定列表完整之前先查 schema，并且优先用 `list_strings filter=` 而不是把全部内容倒出来。

**直达 flag 校验器的最快路径：**

```text
run_analysis                        # MUST run first — a fresh load has 0 functions
list_strings filter="flag"          # ← START HERE: filter is server-side, one call
list_strings filter="Correct"       # success/failure messages are the usual anchor
get_xrefs_to address=<string_addr>  # who reads that string -> the validator
decompile_function address=<caller_addr>      # pseudo-C first (golden rule)
search_functions name_pattern="check" limit=50  # if strings gave nothing; note: name_pattern
decompile_function address=<candidate>
rename_function FUN_00101xxx validate_flag
set_decompiler_comment <addr> "input[i] ^ 0x2a compared here"
```

**关键洞见：** `list_strings` 的 `filter` 参数是整个 Ghidra 工具集中杠杆最高、也最常被漏掉的一次调用 —— 它在服务端完成 `strings | grep` 这一步，得到的地址可以直接喂给 `get_xrefs_to`，两次调用就落到 flag 校验器上。在枚举函数之前，先走"字符串→交叉引用→反编译"这条链。除此之外，Ghidra MCP 免费提供与 IDA MCP 相同的智能体驱动工作流，而且 Ghidra 的反编译器偶尔比 Hex-Rays 更清楚地读出某种构造（反之亦然）—— 如果一个 MCP 服务器产出的伪代码令人困惑，用另一个交叉验证，这与 [tools.md](tools.md#用-dogboltorg-对比反编译器) 中 dogbolt.org 的思路一致。

---

<a id="jadx-mcp-android-apk--dex"></a>
## JADX MCP（Android APK / DEX）

仓库：`https://github.com/zinja-coder/jadx-ai-mcp`（Apache-2.0，测试过 v6.4.0+）。以 JADX-GUI 插件（`jadx-ai-mcp`）加配套的 `jadx-mcp-server` 形式发布；两个都要装。

**安装：**

```bash
# 1. Drop the jadx-ai-mcp plugin jar into JADX-GUI (Plugins > install), open the APK
# 2. Run the companion server (uses uv / fastmcp) and point your MCP client at it:
uvx jadx-mcp-server        # or follow the repo README for manual launch
```

**两个进程，必须都在跑。** `jadx-mcp-server` 只是个代理 —— 它把请求转发到 JADX-GUI 内部 **`127.0.0.1:8650`** 的插件 HTTP 端点。如果 JADX-GUI 关了（或插件未激活），每个工具都会返回 `Cannot connect to JADX plugin at http://127.0.0.1:8650. Ensure JADX-GUI is running and the AI MCP plugin is active.` —— 一个在跑的 `jadx_mcp_server` 进程什么也证明不了。开始工作前先做一次廉价的 `get_cache_stats` 调用探测。

**自己解除阻塞 —— 不要让用户去点 GUI。** 这个插件是持久安装（`jadx plugins --list` 能看到 `jadx-ai-mcp`），所以通常唯一缺的就是一个载入了 APK 的 GUI 进程。从 shell 以无头风格启动它，等端口起来，然后重新探测：

```bash
jadx plugins --list                                   # confirm jadx-ai-mcp is installed
nohup jadx-gui /path/to/app.apk >/tmp/jadx.log 2>&1 & # opens the APK directly
until curl -s --max-time 2 http://127.0.0.1:8650 >/dev/null; do sleep 2; done
echo "plugin endpoint up"                             # ~2-10s; then call get_cache_stats
```

`jadx-gui <file>` 把目标作为参数，所以 APK 在启动时就完成分析，无需点击。会出现一个 GUI 窗口（需要 `$DISPLAY`），但你永远不必碰它。在命令行传入 APK 也正是让 `get_android_manifest` 之类工具返回数据而非空项目的原因。

**核心工具（对 jadx-ai-mcp v6.4.0 核实 —— 早期的短名如 `get_manifest`/`get_method_code`/`get_main_activity` 并不存在）：**

- 侦察：`get_all_classes`、`get_package_tree`、`search_classes_by_keyword`、`search_method_by_name`、`get_main_activity_class`、`get_android_manifest`、`get_manifest_component`
- 源码：`get_class_source`、`get_method_by_name`、`get_methods_of_class`、`get_fields_of_class`、`get_main_application_classes_names`、`get_main_application_classes_code`（导出全部应用类 —— 调用前先看下面的 R 类警告）
- Smali/资源/字符串：`get_smali_of_class`、`get_strings`、`get_all_resource_file_names`、`get_resource_file`
- 交叉引用：`get_xrefs_to_method`、`get_xrefs_to_field`、`get_xrefs_to_class`
- 重构：`rename_class`、`rename_method`、`rename_field`、`rename_variable`、`rename_package`
- JADX-GUI 实时上下文：`fetch_current_class`、`get_selected_text`
- 缓存：`get_cache_stats`（也是廉价的存活探测）、`clear_cache`（重命名后若返回陈旧的反编译源码就用它）
- 动态调试器（JADX 调试会话）：`debug_get_threads`、`debug_get_stack_frames`、`debug_get_variables`

**三个会直接赔掉一道题的陷阱：**

- **`get_main_application_classes_code` 不是廉价的摸底 —— 从 `get_main_application_classes_names` 开始。** "主应用类"集合包含自动生成的 `R` 和 `R.styleable` 类，那是成千上万个资源 ID 常量。在一个*只有 3 个类*的 CTF 应用上，这次调用返回了 **161 KB**，直接冲爆工具结果上限。取名字的调用只有几百字节，立刻显示真正的目标：

  ```text
  get_main_application_classes_names
  # -> BuildConfig, FlagstaffHill, MainActivity, R, R.anim, R.attr, R.bool, ...
  #    Ignore R.* and BuildConfig. Two classes carry all the logic.
  get_class_source class_name="com.x.MainActivity"    # then fetch those by name
  ```

  规则：**过滤掉 `R`/`R.*`/`BuildConfig`，然后对剩下的每个类调 `get_class_source`。** 只有当应用确实有很多真实类*并且*你用 `count`/`offset` 分页时，才去用批量导出。

- **`get_strings` 读的是 `strings.xml` 资源 —— 不是代码里的字符串常量。** 硬编码在 Java 方法里的 flag 或密钥*永远不会*出现在那里。要找到它们，搜索代码范围（见下）。

  反过来同样重要：**当反编译出的 Java 读的是 `ctx.getString(R.string.foo)` 时，`get_strings` 恰恰是正确工具，代码搜索什么也找不到。** 比较值经常被停在 `strings.xml` 里以免进入 DEX：

  ```java
  String password = ctx.getString(R.string.password);
  return input.equals(password) ? nativeCheck(input) : "NOPE";
  ```

  ```text
  get_strings count=400     # -> <string name="password">opossum</string>
  ```

  注意 `get_strings` 按*文件*分页，而不是按字符串，每一项都是整个 `strings.xml`。诱饵条目（在真正的 `password` 周围堆一圈看着像动物名的东西）是常见伎俩 —— 匹配 Java 代码请求的**资源名**，而不是某个只是看起来像 flag 的字符串。

- **`get_smali_of_class` 是 JADX MCP 能到的最深处 —— 它看不到原生代码。** 当反编译 Java 显示 `public static native String foo(...)` 加 `System.loadLibrary("bar")` 时，flag 逻辑在 `lib/*/libbar.so` 里，**任何 JADX 工具都不会显示它**。别在 DEX 里继续搜，切换到下面的原生工作流。

- **`get_method_by_name` 需要 `class_name` 和 `method_name`**（外加可选的 `method_signature` 消歧重载）。不能只传方法名调用 —— 先用 `search_method_by_name` 找出所属类，再两个都传。

`search_classes_by_keyword` 是主力，能力远超普通关键词匹配 —— `search_in` 接受 `class`、`method`、`field`、`code`、`comment`，可逗号组合，`package` 缩小范围：

```text
search_classes_by_keyword search_term="flag{" search_in="code"
search_classes_by_keyword search_term="decrypt" search_in="method,code" package="com.ctf.app"
```

分页在这里生效（`count` 默认 20），`get_all_classes`、`get_strings`、`get_main_application_classes_code`（`count`/`offset`）同样 —— 调大 `count` 或翻页，否则你只会静默分析应用的第一片。

**Android flag 猎取循环：**

```text
get_cache_stats                                       # liveness probe (see setup)
get_android_manifest                                  # entry activity, exported components, package name
get_main_application_classes_names                    # cheap: the real classes (ignore R.*, BuildConfig)
get_class_source <MainActivity>                       # entry logic + System.loadLibrary calls
get_class_source <Validator>                          # the class the button handler calls
search_classes_by_keyword search_term="flag{" search_in="code"   # direct hit when the flag is in the DEX
search_method_by_name check                           # -> tells you the owning class
get_method_by_name class_name=<Cls> method_name=check # read decompiled Java (both args!)
get_xrefs_to_method <check>                           # every caller / trigger path
get_strings count=400                                 # strings.xml — where R.string.* values live
get_smali_of_class <Crypto>                           # smali only if Java decompile breaks
# if you hit `native` methods -> leave JADX, go to "Crossing the JNI boundary"
```

**关键洞见：** APK 的 Java 层通常只是一个*路由器* —— 它命名了校验函数，并告诉你真正的比较值在哪里。把两三个非 `R` 的类从头读到尾（它们很小），反编译源码会把你精确指向三种位置之一：DEX 里的常量（`search_classes_by_keyword ... search_in="code"`）、资源（`get_strings`），或原生库（`native` + `System.loadLibrary` → 下一节）。在读这些类之前就猜是哪种，只会浪费调用。之后就是通常的伪代码优先原则：先 `get_class_source` / `get_method_by_name`（反编译 Java），再 `get_smali_of_class`（字节码）。JADX MCP 与 Frida 配合得很好，用于动态那一半 —— 静态找到方法，然后 hook 它 dump 运行时值（见 [tools-dynamic.md](tools-dynamic.md#androidios-上的-frida)），或在 JADX 调试会话附着时用内置的 `debug_get_variables`。

<a id="crossing-the-jni-boundary-run-the-so-dont-reverse-it"></a>
### 跨越 JNI 边界：直接运行 `.so`，别去逆向它

`public static native String fenugreek(String s)` + `System.loadLibrary("hellojni")` 意味着答案在 `lib/<abi>/libhellojni.so` 里。本能反应是把这个 `.so` 载入 Ghidra/IDA MCP 去反编译 —— 但对于一个*产出* flag 的函数，那是慢路径。**Android JNI 的 `.so` 就是普通 ELF 共享对象；你可以在主机上 `dlopen` 它并直接调用导出函数**，不需要模拟器、不需要设备、完全不需要 Android。几分钟，而不是花一小时反编译一段自定义字符串打乱逻辑。

用 JNI 名称改编 `Java_<package with . -> _>_<Class>_<method>` 把 Java 方法映射到符号，再确认它真的被导出（如果缺失，说明应用用了 `RegisterNatives` —— 见 [languages-platforms.md](languages-platforms.md#android-jni-registernatives-混淆-htb-wondersms)）：

```bash
unzip -q app.apk 'lib/*'                    # x86_64 first: it runs natively on a normal host
objdump -T lib/x86_64/libfoo.so | grep Java_
objdump -p lib/x86_64/libfoo.so | grep NEEDED     # bionic libs you must stub
```

harness 只伪造 `JNIEnv` 的足够部分 —— CTF 的 JNI 函数很少碰字符串调用之外的东西。对着真实 JDK 的 `jni.h` 编译它：

```c
/* jni_harness.c — gcc -o harness jni_harness.c -ldl \
     -I$JAVA_HOME/include -I$JAVA_HOME/include/linux
   ./harness ./libfoo.so Java_com_x_Y_method "input"                         */
#include <jni.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A jstring is an opaque pointer, so just use raw char*. Hand back a heap copy:
   native code often free()s this pointer instead of calling Release, which
   aborts on non-malloc'd memory. */
static const char *h_GetStringUTFChars(JNIEnv *e, jstring s, jboolean *copy) {
    if (copy) *copy = JNI_TRUE;
    return s ? strdup((const char *)s) : NULL;
}
static void    h_ReleaseStringUTFChars(JNIEnv *e, jstring s, const char *c) {}
static jstring h_NewStringUTF(JNIEnv *e, const char *b) { return (jstring)(b ? strdup(b) : NULL); }
static jsize   h_GetStringUTFLength(JNIEnv *e, jstring s) { return s ? (jsize)strlen((const char *)s) : 0; }
static jclass  h_FindClass(JNIEnv *e, const char *n) { return (jclass)0xdeadbeef; }
static jint    h_GetVersion(JNIEnv *e) { return JNI_VERSION_1_6; }

typedef jstring (*fn_t)(JNIEnv *, jclass, jstring);

int main(int argc, char **argv) {
    struct JNINativeInterface_ nif;              /* designated init: no slot counting */
    memset(&nif, 0, sizeof(nif));
    nif.GetVersion = h_GetVersion;               nif.FindClass = h_FindClass;
    nif.GetStringUTFChars = h_GetStringUTFChars; nif.NewStringUTF = h_NewStringUTF;
    nif.ReleaseStringUTFChars = h_ReleaseStringUTFChars;
    nif.GetStringUTFLength = h_GetStringUTFLength;
    nif.GetStringLength = h_GetStringUTFLength;

    struct JNIEnv_ env; env.functions = &nif;
    void *lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    fn_t fn = (fn_t)dlsym(lib, argv[2]);
    if (!fn) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    jstring out = fn((JNIEnv *)&env, (jclass)0, (jstring)argv[3]);
    printf("%s\n", out ? (const char *)out : "(null)");
    return 0;
}
```

**按 C 编译，不要按 C++。** 在 C 里，`JNIEnv` 是 `struct JNIEnv_`，内含指向普通结构体函数表的指针，你可以*按字段名*填充；C++ 头文件把它变成一个带内联方法的类，这个技巧就编不过了。

**你会依次撞上两个错误：**

1. `dlopen: libandroid.so: cannot open shared object file` —— 主机缺少 bionic 库。为除 libc 之外的每个 `NEEDED` 条目生成空桩：
   ```bash
   printf 'int __android_log_write(int p,const char*t,const char*m){return 0;}\n' > stub.c
   for l in liblog libandroid libm libdl; do gcc -shared -fPIC -o stubs/$l.so stub.c; done
   ```
2. `undefined symbol: __cxa_finalize, version LIBC` —— 真正的陷阱。bionic 把它的 libc 符号导出在一个**字面名为 `LIBC` 的版本节点**下，所以朴素的桩 `libc.so` 满足不了 `Version References` 条目（`objdump -p lib.so` 显示 `required from libc.so: LIBC`）。构建一个既*转发到 glibc* 又*声明该版本节点*的桩：
   ```bash
   printf 'LIBC { global: *; };\n' > libc.ver
   gcc -shared -fPIC -o stubs/libc.so bionic_libc.c -Wl,--version-script=libc.ver -ldl
   ```
   在 `bionic_libc.c` 里实现 `objdump -T ... | grep UND` 列出的那一小撮符号：no-op 的 `__cxa_finalize`/`__cxa_atexit`、会 `abort()` 的 `__stack_chk_fail`、手写的 `strlen`/`strcmp`/`strdup`、经 `vsprintf` 实现的 `sprintf`，以及用 `dlsym(RTLD_NEXT, "calloc")` 转发的 `calloc`/`free`，保证堆指针仍归 glibc 管。

```bash
LD_LIBRARY_PATH=$PWD/stubs ./harness ./lib/x86_64/libfoo.so \
    Java_com_hellocmu_picoctf_FlagstaffHill_fenugreek "opossum"
# picoCTF{pining.for.the.fjords}
```

**然后验证它是真正的变换，而不是内嵌常量** —— 用错误输入重跑。如果输出变了（或函数退出），说明 flag 确实由你的输入推导而来，你恢复出的密码是对的。一个导出多个香料命名函数的库，通常服务于同一系列的多道题；用一个循环把它们全部扫一遍。在*错误输入*路径里的 abort 是 harness 的产物（失败分支释放了一个静态字符串），不是答案错误 —— 只要正确输入能干净打印，就忽略它。

<a id="when-the-harness-fails--and-it-will"></a>
#### 当 harness 失败时 —— 而它一定会失败

**harness 是五分钟的赌注，不是逆向的替代品。** 它只在一种形态下获胜：*你已经拿到正确输入，只想要输出。* 给它设时间盒。下面任一症状出现，就停止修补 harness 并切换 —— 兜底通常比把 harness 修好更便宜。

正确的兜底不总是"反编译"。有三档，成本递增、保真度递增：

1. **主机 harness** —— 完全没有 Android 上下文。最快，也最脆弱。
2. **设备/模拟器上的 Frida** —— *真正的* `JNIEnv`、真实应用状态、真实包身份。修复下面所有"需要 Android 上下文"的失败，而且你依然不必逆向算法。见 [tools-dynamic.md](tools-dynamic.md#androidios-上的-frida)。
3. **静态反编译**（Ghidra/IDA MCP）或 angr —— 当你必须*恢复输入*而不是观察输出时，这是唯一选项。

| 症状 | 原因 | 转去 |
|---|---|---|
| `dlsym: undefined symbol: Java_...` | `RegisterNatives`，不是标准改编 | 反编译 `JNI_OnLoad` 找方法表（[详情](languages-platforms.md#android-jni-registernatives-混淆-htb-wondersms)） |
| APK 只带 `lib/armeabi-v7a` + `lib/arm64-v8a` | 没有主机可执行的 ABI | `qemu-arm64 -L <arm sysroot>`，或反编译 |
| 在 `mov 0x<N>(%rdx),%rdx` 之后立刻 `call *%rcx` 处 SIGSEGV | 原生代码用了你留空的某个 `JNIEnv` 槽位 | 实现槽位 `N/8`（见下） |
| 那个槽位是 `GetObjectClass`/`GetFieldID`/`Call*Method` | 它在**回调 Java** —— 主机上无法伪造 | Frida（第 2 档） |
| 读 `/proc/self/maps`、系统属性、包名、APK 签名 | 需要真实应用身份 | Frida（第 2 档） |
| 无论输入如何输出都是固定字符串 | 逻辑被 `dlopen` 从未运行的 `JNI_OnLoad` 状态门控 | Frida，或用手工伪造的 `JavaVM` 手动调用 `JNI_OnLoad` |
| 对你试的**每个**输入都返回 `"try again"` / abort | 函数是**校验器**；你没有输入 | 反编译（第 3 档）—— harness 永远无法告诉你 |

**把段错误解码成槽位号。** JNI 派发会编译成固定模式：先解引用 `JNIEnv*` 得到函数表，再索引它。这道题的库里：

```asm
mov  (%rdx),%rdx          ; rdx = *env  -> function table
mov  0x548(%rdx),%rdx     ; 0x548 / 8 = 169  -> GetStringUTFChars
call *%rcx
```

所以 **`offset / 8` 就是 JNI 槽位号** —— 在 `jni.h` 的 `JNINativeInterface_` 布局里查它，然后把那个字段精确加进 harness。你最常撞上的字符串簇：`167` `NewStringUTF`、`168` `GetStringUTFLength`、`169` `GetStringUTFChars`、`170` `ReleaseStringUTFChars`。事先对目标函数 grep `mov 0x...(%rdx)`，就能在第一次崩溃*之前*知道该实现哪些槽位。

**具体的校验器墙。** 同一个库里的 `sesame()` 根据辅助函数 `basil(input)` 分支，false 分支是死路。反汇编 `basil` 会看到一张六个静态单词的表（`weatherwax, ogg, garlick, nitt, aching, dismass`）、一次索引计算，以及一个 `"%s.%s.%s..."` 的 `sprintf` —— 也就是说密码是一个*计算出的点连接短语*。反复重跑 harness 不可能恢复它；你必须读代码。而同一个库里的 `fenugreek()` 是纯生产者，一次调用就拿下。**同一个 `.so`，两个函数，两种不同的正确策略** —— 所以选工具之前先给函数分类，别让一个曾经奏效的 harness 说服你放弃反编译下一个。

---

<a id="when-to-use-mcp-vs-cli"></a>
## 何时用 MCP，何时用 CLI

| 情形 | 用 |
|-----------|-----|
| 大型二进制，需要把许多函数当伪 C 读 | MCP（IDA/Ghidra） |
| 追交叉引用、重命名、迭代式建立理解 | MCP |
| 快速的明文 flag / 字符串摸底 | CLI（`strings`、`rabin2 -z`）—— 更快 |
| 单个函数的一次性反汇编 | CLI（`objdump -d`）够用 |
| Android：理解类结构和 Java 逻辑 | MCP（JADX） |
| Android：flag 由 `lib/*.so` 中的 `native` 方法产出 | CLI JNI harness（[见上](#跨越-jni-边界直接运行-so别去逆向它)）—— 运行它，别反编译 |
| 对 flag 校验器做符号求解 | angr（见 [tools-dynamic.md](tools-dynamic.md#angr符号执行)） |
| 从混淆代码中提取运行时值 | Frida（见 [tools-dynamic.md](tools-dynamic.md)） |

**关键洞见：** MCP 在迭代式、重理解的分析中大放异彩 —— 智能体需要读反编译输出并追踪关系。对于一次性侦察（`file`、`strings`、`checksec`），[SKILL.md](SKILL.md#快速收益先试这些) 里的 CLI 快赢仍然更快 —— 过了摸底、真正开始逆逻辑时再上 MCP。
