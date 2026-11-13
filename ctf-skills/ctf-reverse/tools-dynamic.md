# CTF Reverse - 动态分析工具

## 目录
- [Frida（动态插桩）](#frida动态插桩)
  - [安装](#安装)
  - [基础函数挂钩](#基础函数挂钩)
  - [绕过反调试](#绕过反调试)
  - [内存扫描与打补丁](#内存扫描与打补丁)
  - [函数替换](#函数替换)
  - [跟踪与 Stalker](#跟踪与-stalker)
  - [r2frida（Radare2 + Frida 集成）](#r2fridaradare2--frida-集成)
  - [Android/iOS 上的 Frida](#androidios-上的-frida)
  - [用 Frida 记忆化加速递归函数（hxp CTF 2017）](#用-frida-记忆化加速递归函数hxp-ctf-2017)
- [angr（符号执行）](#angr符号执行)
  - [安装 angr](#安装-angr)
  - [基础路径探索](#基础路径探索)
  - [带约束的符号输入](#带约束的符号输入)
  - [Hook 函数以简化分析](#hook-函数以简化分析)
  - [从指定地址开始探索](#从指定地址开始探索)
  - [常见模式与技巧](#常见模式与技巧)
  - [应对路径爆炸](#应对路径爆炸)
  - [angr CFG 恢复](#angr-cfg-恢复)
- [lldb（LLVM 调试器）](#lldbllvm-调试器)
  - [基础命令](#基础命令)
  - [脚本化（Python）](#脚本化python)
- [x64dbg（Windows 调试器）](#x64dbgwindows-调试器)
  - [主要特性](#主要特性)
  - [脚本](#脚本)
  - [常见 CTF 工作流](#常见-ctf-工作流)
- [在 putchar() 上做 GDB 寄存器侧信道（picoCTF 2018）](#在-putchar-上做-gdb-寄存器侧信道picoctf-2018)
- [用 radare2 可视化面板跟踪自定义 VM（OTW Advent 2018）](#用-radare2-可视化面板跟踪自定义-vmotw-advent-2018)
- [崩溃时用 libSegFault.so 转储寄存器（OTW Advent 2018）](#崩溃时用-libsegfaultso-转储寄存器otw-advent-2018)
- [r2pipe 遍历二进制 + DP 约束求解（OTW Advent 2018）](#r2pipe-遍历二进制--dp-约束求解otw-advent-2018)
- [在 strcmp 处用 GDB 命令恢复动态 XOR 密钥（TAMUctf 2019）](#在-strcmp-处用-gdb-命令恢复动态-xor-密钥tamuctf-2019)

Qiling/Triton 模拟与 Intel Pin / LD_PRELOAD 侧信道技巧见 [tools-emulation.md](tools-emulation.md)。

---

<a id="frida-dynamic-instrumentation"></a>
## Frida（动态插桩）

Frida 把 JavaScript 注入运行中的进程，实现实时挂钩、跟踪与修改。反调试绕过、运行时检查和移动端逆向的必备工具。

<a id="installation"></a>
### 安装

```bash
pip install frida-tools frida
# Verify
frida --version
```

<a id="basic-function-hooking"></a>
### 基础函数挂钩

```javascript
// hook.js — intercept a function and log arguments/return value
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        this.arg0 = Memory.readUtf8String(args[0]);
        this.arg1 = Memory.readUtf8String(args[1]);
        console.log(`strcmp("${this.arg0}", "${this.arg1}")`);
    },
    onLeave: function(retval) {
        console.log(`  → ${retval}`);
    }
});
```

```bash
# Attach to running process
frida -p $(pidof binary) -l hook.js

# Spawn and instrument from start
frida -f ./binary -l hook.js --no-pause

# One-liner: hook strcmp and dump comparisons
frida -f ./binary --no-pause -e '
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        console.log("strcmp:", Memory.readUtf8String(args[0]), Memory.readUtf8String(args[1]));
    }
});
'
```

<a id="anti-debug-bypass"></a>
### 绕过反调试

```javascript
// Bypass ptrace(PTRACE_TRACEME) — returns 0 (success) without calling
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        this.request = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (this.request === 0) { // PTRACE_TRACEME
            retval.replace(ptr(0));
            console.log("[*] ptrace(TRACEME) bypassed");
        }
    }
});

// Bypass IsDebuggerPresent (Windows)
var isDbg = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
Interceptor.attach(isDbg, {
    onLeave: function(retval) {
        retval.replace(ptr(0));
    }
});

// Bypass timing checks — hook clock_gettime to return constant
Interceptor.attach(Module.findExportByName(null, "clock_gettime"), {
    onLeave: function(retval) {
        // Force constant timestamp to defeat timing checks
        var ts = this.context.rsi || this.context.x1; // x86 or ARM
        Memory.writeU64(ts, 0);        // tv_sec
        Memory.writeU64(ts.add(8), 0); // tv_nsec
    }
});
```

<a id="memory-scanning-and-patching"></a>
### 内存扫描与打补丁

```javascript
// Scan for flag pattern in memory
Process.enumerateRanges('r--').forEach(function(range) {
    Memory.scan(range.base, range.size, "66 6c 61 67 7b", { // "flag{"
        onMatch: function(address, size) {
            console.log("[FLAG] Found at:", address, Memory.readUtf8String(address, 64));
        },
        onComplete: function() {}
    });
});

// Patch instruction (NOP out a check)
var addr = Module.findBaseAddress("binary").add(0x1234);
Memory.patchCode(addr, 2, function(code) {
    var writer = new X86Writer(code, { pc: addr });
    writer.putNop();
    writer.putNop();
    writer.flush();
});
```

<a id="function-replacement"></a>
### 函数替换

```javascript
// Replace a validation function to always return true
var checkFlag = Module.findExportByName(null, "check_flag");
Interceptor.replace(checkFlag, new NativeCallback(function(input) {
    console.log("[*] check_flag called with:", Memory.readUtf8String(input));
    return 1; // always valid
}, 'int', ['pointer']));
```

<a id="tracing-and-stalker"></a>
### 跟踪与 Stalker

```javascript
// Trace all calls in a function (Stalker — instruction-level tracing)
var targetAddr = Module.findExportByName(null, "main");
Stalker.follow(Process.getCurrentThreadId(), {
    transform: function(iterator) {
        var instruction;
        while ((instruction = iterator.next()) !== null) {
            if (instruction.mnemonic === "call") {
                iterator.putCallout(function(context) {
                    console.log("CALL at", context.pc, "→", ptr(context.pc).readPointer());
                });
            }
            iterator.keep();
        }
    }
});
```

<a id="r2frida-radare2--frida-integration"></a>
### r2frida（Radare2 + Frida 集成）

r2frida 通过 Frida 操控活进程，但以 r2 IO 插件的形式暴露，因此反汇编、seek 和原生钩子都能在 r2 内使用。这是对运行中进程的动态插桩——可与 r2ghidra（静态反编译器）和 ESIL（静态单函数模拟）对照。

核心 r2 自身并不会注册 `frida://`：`r2 -L` 列出的 40+ 个 IO 插件中没有 frida 项，`r2 -q frida://0` 会报 `ERROR: Cannot open`。需要安装与 r2 版本匹配的插件构建（在 r2 6.2.2 上实测，用 nowsecure/r2frida 6.2.2 的 `.deb`，`io_frida.so` 为 184 MB）：

```bash
# r2pm has no binstall dispatch on this build — extract the .deb manually
# (same ar x + tar xzf route as the r2ghidra .deb)
ar x r2frida_6.2.2_amd64.deb && tar xzf data.tar.gz
mkdir -p ~/.local/share/radare2/plugins
cp usr/local/share/radare2/plugins/io_frida.so ~/.local/share/radare2/plugins/
r2 -L | grep frida   # rw_  frida    io plugin for Frida ... frida://
```

对 CTF 目标，通过插件启动二进制（宿主架构），并对活内存反汇编。`ptrace_scope=1` 时附加到无关 pid 会失败；`frida://0` 是附加到 r2 自身，所以不要拿它当示例：

```bash
r2 -q -c 's sym.compute; pd 5' 'frida:///abs/path/to/binary'
```

原生返回值钩子使用 `:di*` 系列（下面验证了 `dif-1` 和 `dif0`；`difi` 需要显式参数，`dbc` 设置断点/继续钩子，`:dm` 列出内存映射）。挂钩 `compute`，让其调用方打印 `-1` 而不是真实结果：

```bash
r2 -q -c 's sym.compute; :dif-1 $$; :dc; :dc' 'frida:///abs/path/to/binary'
# Target: $$ was called, intercepting return value.
# -1
```

内存映射用 `:dm`——直接 `dm` 会报 `dm requires the debugger or use om instead`。`:.` 命令把 `.ts`/`.js`/`.c` 文件加载进 agent；它不是完整的 Frida REPL（实测：`Ptr` 未定义，需用 `NativePointer`，`Module.findBaseAddress` 会抛 `TypeError: not a function`）——所以 JS 逻辑放在真正的 Frida 脚本里，r2frida 只用来反汇编和跑 `:di*` 钩子。

<a id="frida-for-androidios"></a>
### Android/iOS 上的 Frida

```bash
# Android (requires rooted device or Frida server)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# Hook Android Java methods
frida -U -f com.example.app -l hook_android.js --no-pause
```

```javascript
// hook_android.js — hook Java method
Java.perform(function() {
    var MainActivity = Java.use("com.example.app.MainActivity");
    MainActivity.checkPassword.implementation = function(input) {
        console.log("[*] checkPassword called with:", input);
        var result = this.checkPassword(input);
        console.log("[*] Result:", result);
        return result;
    };
});
```

**关键点：** 静态分析失效的场景正是 Frida 的强项——混淆代码、加壳二进制、运行时生成的数据。钩住比较函数（`strcmp`、`memcmp`、自定义校验器）即可在不逆向算法的前提下拿到期望值。`Interceptor.attach` 用于观察，`Interceptor.replace` 用于修改。

**适用场景：** 绕过反调试、提取运行时计算的密钥、钩住加密函数导出明文、移动应用分析、加壳二进制检查。

<a id="frida-memoization-for-recursive-function-speedup-hxp-ctf-2017"></a>
### 用 Frida 记忆化加速递归函数（hxp CTF 2017）

用 Frida 挂钩递归函数，缓存结果，命中缓存时直接回放以跳过重复计算。指数复杂度的斐波那契类递归题，加上记忆化后瞬间完成。

```javascript
// memo_hook.js — memoize a recursive function to skip redundant calls
var memo = {};
var funcAddr = ptr("0x400abc");    // Address of the recursive function
var retAddr = ptr("0x400def");     // Address of the function's ret instruction

Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        this.key = args[0].toInt32();
        if (memo[this.key] !== undefined) {
            // Skip computation entirely: set return value and jump to ret
            this.context.rax = memo[this.key];
            this.context.rip = retAddr;
        }
    },
    onLeave: function(retval) {
        // Cache the result for future calls with the same argument
        memo[this.key] = retval.toInt32();
    }
});
```

```bash
# Usage
frida -f ./binary -l memo_hook.js --no-pause
```

多参数函数则构造组合键：
```javascript
Interceptor.attach(funcAddr, {
    onEnter: function(args) {
        this.key = args[0].toInt32() + "," + args[1].toInt32();
        if (memo[this.key] !== undefined) {
            this.context.rax = memo[this.key];
            this.context.rip = retAddr;
        }
    },
    onLeave: function(retval) {
        memo[this.key] = retval.toInt32();
    }
});
```

**关键点：** Frida 的 `Interceptor` 既能读也能改寄存器状态，因此通过设置 `rax`（返回值）和 `rip`（指向 `ret` 指令）就能完全跳过函数执行。凡是“相同参数产生相同结果”的递归函数都适用。指数时间的递归计算（斐波那契、Ackermann、树遍历）加记忆化后变为线性。

**参考：** hxp CTF 2017

---

<a id="angr-symbolic-execution"></a>
## angr（符号执行）

angr 自动探索程序路径，寻找满足约束的输入。许多 flag 校验二进制它能几分钟解出，而手工分析要花数小时。

<a id="angr-installation"></a>
### 安装 angr

```bash
pip install angr
```

<a id="basic-path-exploration"></a>
### 基础路径探索

```python
import angr
from angr import claripy

# Load binary
proj = angr.Project('./binary', auto_load_libs=False)

# Find address of "Correct!" print, avoid "Wrong!" print
# Get these from disassembly (objdump -d or Ghidra)
FIND_ADDR = 0x401234    # Address of success path
AVOID_ADDR = 0x401256   # Address of failure path

# Create simulation manager and explore
simgr = proj.factory.simgr()
simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    found = simgr.found[0]
    # Get stdin that reaches the target
    print("Flag:", found.posix.dumps(0))  # fd 0 = stdin
```

<a id="symbolic-input-with-constraints"></a>
### 带约束的符号输入

```python
import angr
from angr import claripy

proj = angr.Project('./binary', auto_load_libs=False)

# Create symbolic input (e.g., 32-byte flag)
flag_len = 32
flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

# Constrain to printable ASCII
state = proj.factory.entry_state(stdin=flag)
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

# Constrain known prefix: "flag{"
state.solver.add(flag_chars[0] == ord('f'))
state.solver.add(flag_chars[1] == ord('l'))
state.solver.add(flag_chars[2] == ord('a'))
state.solver.add(flag_chars[3] == ord('g'))
state.solver.add(flag_chars[4] == ord('{'))
state.solver.add(flag_chars[flag_len-1] == ord('}'))

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=0x401256)

if simgr.found:
    found = simgr.found[0]
    result = found.solver.eval(flag, cast_to=bytes)
    print("Flag:", result.decode())
```

<a id="hook-functions-to-simplify-analysis"></a>
### Hook 函数以简化分析

```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)

# Hook printf to avoid path explosion in I/O
@proj.hook(0x401100, length=5)  # Address of call to printf
def skip_printf(state):
    pass  # Do nothing, just skip

# Hook sleep/anti-debug functions
@proj.hook(0x401050, length=5)  # Address of call to sleep
def skip_sleep(state):
    pass

# Replace a function with a summary
class AlwaysSucceed(angr.SimProcedure):
    def run(self):
        return 1

proj.hook_symbol('check_license', AlwaysSucceed())
```

<a id="exploring-from-specific-address"></a>
### 从指定地址开始探索

```python
# Start from middle of function (skip initialization)
state = proj.factory.blank_state(addr=0x401200)

# Set up registers/memory manually
state.regs.rdi = 0x600000  # Pointer to input buffer
state.memory.store(0x600000, b"AAAA" + b"\x00" * 28)

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401300, avoid=0x401350)
```

<a id="common-patterns-and-tips"></a>
### 常见模式与技巧

```python
# Pattern 1: argv-based input
state = proj.factory.entry_state(args=['./binary', flag_sym])

# Pattern 2: Multiple find/avoid addresses
simgr.explore(
    find=[0x401234, 0x401300],     # Any success path
    avoid=[0x401256, 0x401400]     # All failure paths
)

# Pattern 3: Find by output string (no address needed)
def is_successful(state):
    stdout = state.posix.dumps(1)  # fd 1 = stdout
    return b"Correct" in stdout

def should_avoid(state):
    stdout = state.posix.dumps(1)
    return b"Wrong" in stdout

simgr.explore(find=is_successful, avoid=should_avoid)

# Pattern 4: Timeout protection
simgr.explore(find=0x401234, avoid=0x401256, num_find=1)
# Or use exploration techniques:
simgr.use_technique(angr.exploration_techniques.DFS())  # Depth-first
simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=500))
```

<a id="dealing-with-path-explosion"></a>
### 应对路径爆炸

```python
# Use DFS instead of BFS (default) for flag checkers
simgr.use_technique(angr.exploration_techniques.DFS())

# Limit symbolic memory operations
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

# Hook expensive functions (crypto, hashing) to avoid explosion
import hashlib
class SHA256Hook(angr.SimProcedure):
    def run(self, data, length, output):
        # Concretize input and compute hash
        concrete_data = self.state.solver.eval(
            self.state.memory.load(data, self.state.solver.eval(length)),
            cast_to=bytes
        )
        h = hashlib.sha256(concrete_data).digest()
        self.state.memory.store(output, h)

proj.hook_symbol('SHA256', SHA256Hook())
```

<a id="angr-cfg-recovery"></a>
### angr CFG 恢复

```python
# Control flow graph for understanding structure
cfg = proj.analyses.CFGFast()
print(f"Functions found: {len(cfg.functions)}")

# Find main
for addr, func in cfg.functions.items():
    if func.name == 'main':
        print(f"main at {addr:#x}")
        break

# Cross-references
node = cfg.model.get_any_node(0x401234)
print("Predecessors:", [hex(p.addr) for p in cfg.model.get_predecessors(node)])
```

**关键点：** angr 在成功/失败路径清晰的 flag 校验二进制上效果最好。对复杂二进制，钩掉昂贵函数（加密、I/O）并使用 DFS 探索。先用最简单的方式（只给 find/avoid 地址），再逐步加约束。如果 angr 太慢，把输入约束为可打印 ASCII 并加上已知前缀。

**适用场景：** 带分支逻辑的 flag 校验器、迷宫/寻路类二进制、约束密集的检查、自动化二进制分析。效果较差的场景：重型加密、浮点运算、复杂堆操作。

---

<a id="lldb-llvm-debugger"></a>
## lldb（LLVM 调试器）

macOS/iOS 的主力调试器，也能在 Linux 上使用。Swift/Objective-C 以及 Apple 平台二进制首选。

<a id="basic-commands"></a>
### 基础命令

```bash
lldb ./binary
(lldb) run                          # Run program
(lldb) b main                       # Breakpoint on main
(lldb) b 0x401234                   # Breakpoint at address
(lldb) breakpoint set -r "check.*"  # Regex breakpoint
(lldb) c                            # Continue
(lldb) si                           # Step instruction
(lldb) ni                           # Next instruction
(lldb) register read                # Show all registers
(lldb) register write rax 0         # Modify register
(lldb) memory read 0x401000 -c 32   # Read 32 bytes
(lldb) x/s $rsi                     # Examine string (GDB-style)
(lldb) dis -n main                  # Disassemble function
(lldb) image list                   # Loaded modules + base addresses
```

<a id="scripting-python"></a>
### 脚本化（Python）

```python
# lldb Python scripting
import lldb

def hook_strcmp(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    arg0 = frame.FindRegister("rdi").GetValueAsUnsigned()
    arg1 = frame.FindRegister("rsi").GetValueAsUnsigned()
    s0 = process.ReadCStringFromMemory(arg0, 256, lldb.SBError())
    s1 = process.ReadCStringFromMemory(arg1, 256, lldb.SBError())
    print(f'strcmp("{s0}", "{s1}")')

# Register in lldb: command script add -f script.hook_strcmp hook_strcmp
```

**关键点：** macOS 二进制（Mach-O）、iOS 应用以及没有 GDB 时用 lldb。`image list` 给出 PIE 二进制的 ASLR 偏移。其脚本 API 比 GDB 更结构化。

---

<a id="x64dbg-windows-debugger"></a>
## x64dbg（Windows 调试器）

开源 Windows 调试器，界面现代。Windows 逆向题目中可替代 OllyDbg/WinDbg。

<a id="key-features"></a>
### 主要特性

```bash
# Launch
x64dbg.exe binary.exe         # 64-bit
x32dbg.exe binary.exe         # 32-bit

# Essential shortcuts
F2      → Toggle breakpoint
F7      → Step into
F8      → Step over
F9      → Run
Ctrl+G  → Go to address
Ctrl+F  → Find pattern in memory
```

<a id="scripting"></a>
### 脚本

```bash
# x64dbg command line
bp 0x401234                    # Breakpoint
SetBPX 0x401234, 0, "log {s:utf8@[esp+4]}"  # Log string arg on hit
run                            # Continue
StepOver                       # Step over
```

<a id="common-ctf-workflow"></a>
### 常见 CTF 工作流

1. 对 GUI 破解题在 `GetWindowTextA`/`MessageBoxA` 下断
2. 从成功/失败提示反推校验点
3. 加壳二进制用 **Scylla** 插件重建 IAT
4. 需要快速看伪 C 时用 **Snowman** 反编译插件

**关键点：** x64dbg 内置模式扫描、硬件断点和条件日志。对 Windows CTF 二进制，动态分析往往比 IDA/Ghidra 更快。自动标注函数参数可用 **xAnalyzer** 插件。

---

<a id="gdb-register-side-channel-on-putchar-picoctf-2018"></a>
## 在 putchar() 上做 GDB 寄存器侧信道（picoCTF 2018）

**模式：** 二进制逐字符解密 flag，每次打印之间调用 `usleep()`。不必真的等这些 sleep，在 `putchar@plt` 下断，每次命中记录 `$rdi`（glibc x86-64 上字符就在该寄存器）。一个 GDB 日志循环可在毫秒级导出完整 flag，无论人为延迟多长。

```gdb
# ~/.gdbinit for this challenge
set pagination off
set logging file flag.log
set logging overwrite on
set logging on

break putchar
commands
  silent
  printf "%c", $rdi
  continue
end

run
```

```bash
gdb -batch -x script.gdb ./crackme
cat flag.log
```

**关键点：** 只要程序用 `usleep`、`nanosleep` 或忙循环人为放慢输出，待打印的字符在 sleep 执行前就已经在寄存器里了。在输出函数（`putchar`、`fputc`、`fd=1` 的 `write`）下断，打印第一个参数寄存器（x86-64 是 `$rdi`，ARM 是 `$r0`，RISC-V/MIPS 是 `$a0`），用 GDB 脚本批量提取数据。有硬件断点时，对反调试二进制同样有效。

**参考：** picoCTF 2018 — learn gdb，writeup 11784

---

<a id="radare2-visual-panels-for-custom-vm-tracing-otw-advent-2018"></a>
## 用 radare2 可视化面板跟踪自定义 VM（OTW Advent 2018）

**模式：** 自定义 VM 二进制本来难以看清，直到能同时看到程序计数器、下一条操作码、栈和堆。radare2 的面板模式（`V!`）允许在一屏内固定这四个视图，逐条执行宿主指令的同时观察 VM 状态变化。

```text
f sp @ rbp-0x160       # flag VM sp
f ip @ rbp-0x158       # flag VM ip
f stack @ rbp-0x150
f heap @ rbp-0x148

V!                       # enter panels
# panel 1: ?v [ip]; pd 1 @ [ip]    (next VM instruction)
# panel 2: pxQ 0x60 @ sp             (stack)
# panel 3: pxQ 0x60 @ heap           (heap)
# panel 4: afvd                      (local vars / registers)
```

在对应 VM 操作码分发的宿主级分支上设置条件断点，用 `ds` 单步。配合 `e io.cache=true` 可在分析期间对 VM 操作码做非破坏性修改。

**关键点：** 一旦能实时观察状态，自定义 VM 几分钟就能逆向。面板模式胜过静态反编译，因为宿主二进制往往缺少适合反编译的结构；而当每个寄存器的跳动都实时可见时，VM 就变得不言自明。

**参考：** OverTheWire Advent 2018 — Jackinthebox，writeup 12789

---

<a id="libsegfaultso-register-dump-at-crash-otw-advent-2018"></a>
## 崩溃时用 libSegFault.so 转储寄存器（OTW Advent 2018）

**模式：** 需要 shellcode 入口处的精确寄存器状态，但 gdb 不可用或被挂钩。预加载 `libSegFault.so`（glibc 自带）并让程序崩溃：它会向 stderr 打印完整寄存器转储、回溯和内存映射。

```bash
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libSegFault.so ./target
# or 32-bit:
LD_PRELOAD=/lib32/libSegFault.so ./target

# Force the crash:
# segfault_handler dumps: RIP, RSP, RAX..R15, stack backtrace
```

读取打印出的寄存器，看哪些已经指向你的 shellcode（常见：`RAX` → 缓冲区，`RDI` → 0），据此设计最小 shellcode。

**关键点：** libSegFault 是标准调试基础设施的一部分，每个 glibc 系统都装了。它能把任意段错误变成免费的寄存器快照，即使在没权限用 `strace`/`gdb` 的加固机器上也有效。

**参考：** OverTheWire Advent Bonanza 2018 — Day 22，writeup 12757

---

<a id="r2pipe-binary-walking--dp-constraint-solver-otw-advent-2018"></a>
## r2pipe 遍历二进制 + DP 约束求解（OTW Advent 2018）

**模式：** 12 MB 二进制、30 万+ 基本块，对 `argv[1]` 做链式哈希校验。用 `r2pipe` 遍历每个块，把指令分类为 hash/cmp/jmp/print，构建约束图，再用动态规划 + 对输入位置的回溯求解。

```python
import r2pipe
r = r2pipe.open('./huge_binary')
r.cmd('aaa')
for fn in r.cmdj('aflj'):
    for block in r.cmdj(f"pdfj @ {fn['offset']}")['ops']:
        op = block['type']
        if op == 'cmp':  constraints.append(parse_cmp(block))
        if op == 'call': targets.append(block['jump'])
# DP: memoize (position, accepted_set) -> char
```

**关键点：** 带哈希链的大二进制，只要把每个分支视为输入字节上的不等式就可解。r2pipe 的 JSON 输出机器可读；以 (位置, 取值) 元组做 DP 能在运行前剪掉大部分分支。

**参考：** OverTheWire Advent Bonanza 2018 — Day 8，writeup 12771

---

<a id="gdb-commands-at-strcmp-to-recover-dynamic-xor-key-tamuctf-2019"></a>
## 在 strcmp 处用 GDB 命令恢复动态 XOR 密钥（TAMUctf 2019）

**模式（Obfuscaxor）：** 二进制用 [obfy](https://github.com/fritzone/obfy) C++ 模板混淆器，把简单的 `enc(input)` XOR 循环埋在数千个不透明谓词之下。但最终校验仍是 `strcmp(expected_ciphertext, enc(input))`——所以不必拆解 obfy，直接在 `strcmp` 调用处下断，导出两个操作数：

```gdb
disassemble verify_key
# ... 0x5555555560b9 <+96>: call   strcmp@plt
break *verify_key+96
commands
  silent
  printf "RDI (expected): "
  x/4xg $rdi
  printf "RSI (computed): "
  x/4xg $rsi
  continue
end
run
```

喂入已知明文（`AAAAAAAAA`），记录 `computed_A[i]`。由于 `enc` 是逐字节 XOR 密钥流，密钥字节可直接由它与目标值的差恢复：

```python
# input_char ^ key = computed_char, and we want: target_char ^ key = target_input
def to_ans(got_A, expected):
    return chr(got_A ^ ord('A') ^ expected)

# Sanity: flip just one byte of input and confirm only one computed byte moves.
```

对完整的 16 字节目标逐字节套用恢复流程，重建正确密钥（本题为 `p3Asujmn9CEeCB3A`）。

**关键点：** 当 `strcmp` 是最后一道关卡时，混淆器就无关紧要了——它的输出在某个已知调用点仍必须等于固定字符串。GDB 的 `commands` 块把断点变成自动 oracle：跑一次 `AAAA...` 泄露密钥流，再用任意目标字符串跑第二遍即可得到合法输入。凡是在固定密钥下等价于输入置换的键控变换都适用。

**参考：** TAMUctf 2019 — Obfuscaxor，writeup 13574
