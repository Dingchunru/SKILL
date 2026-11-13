# CTF Pwn - MCP 服务器集成

MCP 服务器能加速 pwn 工作流的两个半边：**理解**二进制（反编译有漏洞的函数）和**调试**利用（检查崩溃状态、堆、寄存器）。通过 IDA/Ghidra MCP 做静态反编译的权威参考是 [../ctf-reverse/tools-mcp.md](../ctf-reverse/tools-mcp.md)；本文件讲 pwn 特有的角度，外加 Windows 目标的 **WinDbg MCP**。

## 目录
- [WinDbg MCP（Windows 崩溃转储、实时与内核调试）](#windbg-mcpwindows-崩溃转储实时与内核调试)
- [用 IDA / Ghidra MCP 开发利用](#用-ida--ghidra-mcp-开发利用)

---

<a id="windbg-mcp-windows-crash-dumps-live--kernel-debugging"></a>
## WinDbg MCP（Windows 崩溃转储、实时与内核调试）

仓库：`https://github.com/svnscha/mcp-windbg`（MIT）。它把 WinDbg 的 `cdb.exe`（用户态）和 `kd.exe`（内核态）桥接给智能体，因此转储分诊、带断点的实时利用以及内核调试都能以工具调用的形式跑。

**安装：**

```bash
# Needs the Windows SDK "Debugging Tools for Windows" (provides cdb.exe + kd.exe),
# usually C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\
uv tool install mcp-server-windbg     # or: pip install mcp-server-windbg
claude mcp add mcp-windbg -- mcp-windbg
```

### 会话模型 —— 先读这一节

除 `list_dumps` 外，**每个工具都以会话寻址**。`open_*` 返回 `session_id`；之后每条命令都必须把它传回来。打开一次，整道题复用，结束时关闭。这是最常见的失败模式：从一个还没 `open_*` 的会话里调用 `run_cdb_command`。

**用户态（cdb.exe）** —— 转储，以及通过调试服务器连接实时目标：

| 工具 | 用途 |
|---|---|
| `list_dumps(directory_path?, recursive?)` | 枚举 `.dmp` 文件；不需要会话 |
| `open_cdb_dump(dump_path, symbols_path?, include_stack_trace?, include_modules?, include_threads?, timeout_seconds?)` | 加载转储 → `session_id`。自动执行 `.lastevent` + `!analyze -v` |
| `open_cdb_remote(connection_string, ...)` | 连接到 `cdb -server tcp:port=5005 <prog>` → `session_id` |
| `run_cdb_command(session_id, command, timeout_seconds?)` | 任意 cdb 命令 |
| `send_ctrl_break(session_id)` | 打断*正在运行*的实时目标 |
| `close_cdb_session(session_id)` | 释放 |

**内核态（kd.exe）** —— Windows 内核/驱动 pwn：

| 工具 | 用途 |
|---|---|
| `open_kd_session(connection_string, symbols_path?, ...)` | 连接 + 中断 → `session_id` |
| `run_kd_command(session_id, command, timeout_seconds?)` | 任意 kd 命令 |
| `send_ctrl_break(session_id)` | 打断正在运行的内核 |
| `close_kd_session(session_id, resume=true)` | 释放。**`resume=false` 会把整台目标机冻结** |

内核连接串：KDNET `net:port=50000,key=1.2.3.4`、命名管道 `com:pipe,port=\\.\pipe\com_1,baud=115200,reconnect,resets=0`、串口 `com:port=COM1,baud=115200`。

**符号是正确性问题，不是便利性问题。** 在 `open_*` 上传 `symbols_path="srv*C:\symbols*https://msdl.microsoft.com/download/symbols"`。符号错了时 `!analyze -v` 不会大声失败 —— 它会编出一个**看似合理但错误**的答案。在真实转储上验证过：符号错误时 `!analyze -v` 报告 `PROCESS_NAME: ntdll.wrong.symbols.dll` 和一个假的 bugcheck 码，`k` 给出 `combase!CoTaskMemRealloc+0x31a7` / `notepad+0xaf59`。执行 `.symfix; .reload` 之后，同一个栈读出来是 `combase!InitMainThreadWnd+0x57` / `notepad!wWinMain+0x11d` —— 完全是另外两个函数。

**在信任任何一帧之前，先对自动分析做常识校验：** 如果输出里出现 `WRONG_SYMBOLS`、`MISSING_CRITICAL_SYMBOLS` 或 `***** OS symbols are WRONG`，就先 `.symfix; .reload` 再重新执行 `k`，然后才去推理崩溃原因。

### 崩溃转储分诊循环

`open_cdb_dump` 已经替你跑过 `.lastevent` + `!analyze -v`。设 `include_stack_trace=true, include_modules=true`，把 `kb` 和 `lm` 折进同一次首调，省下两次往返。

```text
open_cdb_dump crash.dmp  include_stack_trace=true include_modules=true
run_cdb_command <sid> ".symfix; .reload"     # FIRST — see the symbol warning above
run_cdb_command <sid> "r"                    # registers — did we control rip?
run_cdb_command <sid> "!exchain"             # SEH chain (SEH-overwrite target)
run_cdb_command <sid> "dds esp L40"          # stack — locate the cyclic pattern
run_cdb_command <sid> "!heap -p -a <addr>"   # heap block owner for UAF/overflow
run_cdb_command <sid> "~*k"                  # all thread stacks, not just the faulting one
run_cdb_command <sid> "!teb"                 # TEB: stack limits, last error, SEH head
```

`list_dumps` 需要显式的 `directory_path`，除非机器上配置了 `LocalDumps` 注册表路径 —— 否则它只会报错。

**直接从转储里拿 flag。** 在任何利用之前先扫内存 —— 很多 Windows 取证/pwn 混合题给出的转储里已经含 flag。**在 x64 上不要按原始地址范围扫描。** 32 位范围永远到不了堆（堆在 4 GB 以上，例如 `0x246ab1a1720`），而完整的 47 位用户空间范围 `L?0x7fffffffffff` 会让会话直接挂死。枚举已提交区域，只在这些区域里搜：

```text
run_cdb_command <sid> "!address -f:Heap -c:\"s -u %1 %2 \\\"flag{\\\"\""    # UTF-16
run_cdb_command <sid> "!address -f:Heap -c:\"s -a %1 %2 \\\"flag{\\\"\""    # ASCII
run_cdb_command <sid> "du <hit_addr>"                       # print the whole flag
run_cdb_command <sid> ".writemem C:\\out\\heap.bin <start> L<len>"  # carve for offline analysis
```

先试 **`s -u`**：Win32 把命令行、环境块和大多数字符串数据存为 UTF-16，所以 `s -a` 常常一无所获，而 `s -u` 立刻命中。把 `-f:Heap` 换成 `-f:Stack`、`-f:Image` 或 `-f:MEM_PRIVATE` 可以扩大清扫范围。在 `-c:` 里占位符是 `%1` 起始、`%2` 结束+1、`%3` 大小；引号需要转义，而且**不支持用分号分隔多条命令**。

### 实时利用循环（大多数人漏掉的部分）

`open_cdb_remote` 把 MCP 变成完整的交互式调试器。在调试服务器下启动目标，然后用断点、打内存补丁、读 flag —— 无 GUI，无需手工单步。

```bash
cdb -server tcp:port=5005 chall.exe      # on the target box
```

```text
open_cdb_remote "tcp:Port=5005,Server=127.0.0.1"
run_cdb_command <sid> "bp chall!check_password"        # break on the gate
run_cdb_command <sid> "ba r4 <flag_buf>"               # HW watchpoint: who READS the flag?
run_cdb_command <sid> "bp chall!cmp \"du poi(esp+4); g\""  # scripted bp, auto-continues
run_cdb_command <sid> "g"  timeout_seconds=30          # run; bounded so it can't hang you
run_cdb_command <sid> "r rip=chall!print_flag"         # skip the check entirely
run_cdb_command <sid> "eb <addr> 90 90"                # NOP out a jz — patch, don't solve
run_cdb_command <sid> "!gflag +hpa"                    # page heap: overflow faults immediately
```

如果目标在跑而命令没响应，先 `send_ctrl_break` —— 调试对象自由运行时，实时会话无法执行命令。

### Windows 缓解检查（`checksec` 的等价物）

Windows 上没有 `checksec`；`!dh` 就是。选策略之前先做这一步 —— 它决定走 ROP、ret2win 还是 SEH 覆写：

```text
run_cdb_command <sid> "lm"                  # module list + base addresses
run_cdb_command <sid> "!dh -f chall"        # read the "DLL characteristics" block
run_cdb_command <sid> "!address -f:PAGE_EXECUTE_READWRITE"   # RWX — where shellcode can live
```

`!dh -f` 按名称打印标志位；下面这些才是要紧的：

| `!dh -f` 行 | 含义 |
|---|---|
| `Dynamic base` | ASLR 开启 |
| `High entropy VA supported` | 64 位 ASLR 熵 |
| `NX compatible` | DEP 开启 |
| `Guard` | **CFG** —— 间接调用会被校验 |

`/GS`（栈 cookie）**不是** DLL characteristics 标志位，永远不会出现在这里 —— 它在 Load Configuration Directory 的 `SecurityCookie` 字段里。用 `dt ntdll!_IMAGE_LOAD_CONFIG_DIRECTORY64 <imgbase>+<lcd_rva>` 单独确认，或者直接在函数尾声找 `__security_cookie` 的异或/比较。

CFG 存在会把你推向*合法的调用目标*（比如 `system()`），而不是任意 gadget —— 见 [advanced-exploits-4.md](advanced-exploits-4.md) 里的 CFG 绕过技巧。

### 内核态循环（HEVD 风格驱动题）

Windows 内核 pwn 是反复出现的 CTF 类别，而 `open_kd_session` 是触达它的唯一方式。目标几乎总是窃取 token：

```text
open_kd_session "net:port=50000,key=1.2.3.4" symbols_path="srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
run_kd_command <sid> "lm m HEVD"                    # driver base → offsets for the ROP chain
run_kd_command <sid> "!drvobj HEVD 2"               # IOCTL dispatch routines = attack surface
run_kd_command <sid> "bp HEVD!TriggerStackOverflow"
run_kd_command <sid> "r cr4"                        # bit 20 set = SMEP on → must ROP in kernel
run_kd_command <sid> "!process 0 0 System"          # System EPROCESS (token source)
run_kd_command <sid> "dt nt!_EPROCESS <addr> Token ActiveProcessLinks UniqueProcessId"
run_kd_command <sid> "!pool <addr>"                 # pool chunk metadata for grooming
run_kd_command <sid> "!analyze -v"                  # after a BSOD: bugcheck code + faulting driver
close_kd_session <sid> resume=true
```

`dt nt!_EPROCESS ... Token` 既给出利用所需的精确 token 偏移，*又*能验证窃取是否落地。内核内存读取很慢 —— 把 `timeout_seconds` 调大，而不是假定它挂死了。

**关键洞见：** MCP 的价值不是"没有 GUI 的 WinDbg"，而是断点、内存补丁和内存扫描都变成*智能体可驱动*的。最快的 Windows CTF 路径通常压根不是干净的利用：在已提交区域扫 `flag{`、在 flag 缓冲区上设硬件读监视点，或者用 `eb`/`r rip=` 直接跨过检查。写 ROP 链之前先试这些 —— 但要先修好符号，因为符号错乱的 `!analyze -v` 会信心十足地把你指向错误的函数。交互式本地工作仍然用 x64dbg 作为 GUI 替代（见 [../ctf-reverse/tools-dynamic.md](../ctf-reverse/tools-dynamic.md#x64dbgwindows-调试器)）。

---

<a id="ida--ghidra-mcp-for-exploit-development"></a>
## 用 IDA / Ghidra MCP 开发利用

写利用之前，先用 [../ctf-reverse/tools-mcp.md](../ctf-reverse/tools-mcp.md) 里的反编译 MCP 服务器找到并理解漏洞 —— **先伪代码，失败再看汇编**（同一条黄金法则）。

**pwn 专用查询：**

```text
list_strings filter="flag"          # free win: the flag or its file path, in one call
decompile_function <handler>        # spot the unchecked memcpy/gets/scanf("%s")
get_function_xrefs name=read_input  # every path that reaches the vulnerable buffer (by name)
get_xrefs_to address=<buf_addr>     # ...or by hex address for a data buffer
decompile_function <win/backdoor>   # confirm a ret2win target + required args
list_methods offset=0 limit=100     # locate system/execve wrappers — page past 100!
disassemble_function address=<gadget_addr>  # ONLY when hunting exact bytes for gadgets
```

**MCP 在 pwn 里帮助最大的地方：**

- 定位 bug：把处理函数当伪 C 读，直接看到缺失的边界检查，而不是用肉眼看汇编。
- 找 ret2win / 魔法值函数以及它们精确的参数要求。
- 还原结构体布局（IDA 的 `set_function_prototype`、`declare_c_type`），让堆溢出偏移分毫不差。
- 在确定利用策略之前，确认 canary/flag 校验的比较方向（见 [SKILL.md](SKILL.md#保护机制对利用策略的影响)）。

**关键洞见：** pwn 里最终一定要精确字节（gadget、偏移），所以你*必然*会下探到汇编 —— 但要在反编译器已经告诉你*攻哪个*函数、*哪个*检查之后。每个 pwn 目标都从反编译输入处理函数开始；等你知道了目标、需要指令级精度时，再转到 `disassemble_function` / ROPgadget。
