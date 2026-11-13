# CTF Reverse - 反分析技术与绕过

CTF 题目中常见的反调试、反虚拟机、反 DBI 和完整性校验技术的综合参考，附实用绕过方法。

## 目录
- [Linux 反调试（进阶）](#linux-反调试进阶)
  - [基于 ptrace](#基于-ptrace)
  - [/proc 文件系统检查](#proc-文件系统检查)
  - [基于时序的检测](#基于时序的检测)
  - [基于信号的反调试](#基于信号的反调试)
  - [系统调用层规避](#系统调用层规避)
  - [Trap Flag 自检与 cmovz 补丁（Hack.lu 2018）](#trap-flag-自检与-cmovz-补丁hacklu-2018)
  - [SIGFPE 处理器改写代码（Hack.lu 2018）](#sigfpe-处理器改写代码hacklu-2018)
- [Windows 反调试（进阶）](#windows-反调试进阶)
  - [PEB（进程环境块）检查](#peb进程环境块检查)
  - [NtQueryInformationProcess](#ntqueryinformationprocess)
  - [堆标志](#堆标志)
  - [TLS 回调](#tls-回调)
  - [硬件断点检测](#硬件断点检测)
  - [软件断点检测（INT3 扫描）](#软件断点检测int3-扫描)
  - [基于异常的反调试](#基于异常的反调试)
  - [NtSetInformationThread（隐藏线程）](#ntsetinformationthread隐藏线程)
- [反虚拟机 / 反沙箱](#反虚拟机--反沙箱)
  - [CPUID 的 hypervisor 位](#cpuid-的-hypervisor-位)
  - [MAC 地址 / 硬件指纹](#mac-地址--硬件指纹)
  - [基于时序的虚拟机检测](#基于时序的虚拟机检测)
  - [文件 / 注册表痕迹](#文件--注册表痕迹)
  - [资源检查（CPU 核数、内存、磁盘）](#资源检查cpu-核数内存磁盘)
- [反 DBI（动态二进制插桩）](#反-dbi动态二进制插桩)
  - [Frida 检测](#frida-检测)
  - [Pin/DynamoRIO 检测](#pindynamorio-检测)
- [代码完整性 / 自哈希](#代码完整性--自哈希)
- [反反汇编技巧](#反反汇编技巧)
  - [不透明谓词](#不透明谓词)
  - [垃圾字节 / 指令重叠](#垃圾字节--指令重叠)
  - [跳进指令中间](#跳进指令中间)
  - [函数分块 / 代码离散](#函数分块--代码离散)
  - [控制流平坦化（进阶）](#控制流平坦化进阶)
  - [混合布尔算术（MBA）的识别与化简](#混合布尔算术mba的识别与化简)
- [综合绕过策略](#综合绕过策略)
  - [通用绕过检查清单](#通用绕过检查清单)
  - [分层反调试（真实场景模式）](#分层反调试真实场景模式)
  - [速查：检查项到绕过手法](#速查检查项到绕过手法)

CTF writeup 中的技巧（SIGILL 处理器切换模式、SIGFPE strace 侧信道、指令轨迹求逆、无调用函数链、父进程修补子进程二进制转储）见 [anti-analysis-ctf.md](anti-analysis-ctf.md)。

---

<a id="linux-anti-debug-advanced"></a>
## Linux 反调试（进阶）

<a id="ptrace-based"></a>
### 基于 ptrace

**自我 ptrace（最常见）：**
```c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) exit(1); // Already traced = debugger attached
```

**绕过：**
```bash
# 1. LD_PRELOAD (see patterns.md for full hook)
LD_PRELOAD=./hook.so ./binary

# 2. Patch with pwntools
python3 -c "
from pwn import *
elf = ELF('./binary', checksec=False)
elf.asm(elf.symbols.ptrace, 'xor eax, eax; ret')
elf.save('patched')
"

# 3. GDB: catch the syscall
gdb ./binary
(gdb) catch syscall ptrace
(gdb) run
# When it stops at ptrace:
(gdb) set $rax = 0
(gdb) continue

# 4. Kernel config (requires root)
echo 0 > /proc/sys/kernel/yama/ptrace_scope
```

**双重 ptrace 模式：**
```c
// Fork child to ptrace parent — blocks all other debuggers
pid_t child = fork();
if (child == 0) {
    ptrace(PTRACE_ATTACH, getppid(), 0, 0);
    // Child sits in waitpid loop, keeping parent traced
} else {
    // Parent continues with real logic
}
```
**绕过：** 先杀掉这个看门狗子进程，再挂调试器。

<a id="proc-filesystem-checks"></a>
### /proc 文件系统检查

```c
// TracerPid check
FILE *f = fopen("/proc/self/status", "r");
// Looks for "TracerPid:\t0" — non-zero means debugger

// /proc/self/exe link check (some debuggers change this)
readlink("/proc/self/exe", buf, sizeof(buf));

// /proc/self/maps — check for debugger libraries
grep("frida", "/proc/self/maps");
```

**绕过：**
```bash
# 1. LD_PRELOAD fopen/fread to fake /proc contents
# 2. Mount namespace isolation
unshare -m bash -c 'mount --bind /dev/null /proc/self/status && ./binary'

# 3. GDB: set breakpoint at fopen, change filename argument
(gdb) b fopen
(gdb) run
(gdb) set {char[20]} $rdi = "/dev/null"
(gdb) continue
```

<a id="timing-based-detection"></a>
### 基于时序的检测

```c
// rdtsc (CPU timestamp counter)
uint64_t start = __rdtsc();
// ... code ...
uint64_t delta = __rdtsc() - start;
if (delta > THRESHOLD) exit(1);  // too slow = debugger

// clock_gettime
struct timespec ts1, ts2;
clock_gettime(CLOCK_MONOTONIC, &ts1);
// ... code ...
clock_gettime(CLOCK_MONOTONIC, &ts2);

// gettimeofday
struct timeval tv1, tv2;
gettimeofday(&tv1, NULL);
```

**绕过：**
```bash
# 1. Frida hook (see tools-dynamic.md for clock_gettime hook)

# 2. GDB: skip rdtsc by patching with constant
(gdb) set {unsigned char[2]} 0x401234 = {0x90, 0x90}  # NOP the rdtsc

# 3. Pin tool to fix TSC reads
# 4. faketime library
LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="2024-01-01" ./binary
```

<a id="signal-based-anti-debug"></a>
### 基于信号的反调试

```c
// SIGTRAP handler — INT3 under debugger is caught by debugger, not handler
signal(SIGTRAP, handler);
__asm__("int3");
// If handler runs: no debugger. If debugger catches: debugged.

// SIGALRM timeout — kill self if analysis takes too long
signal(SIGALRM, kill_handler);
alarm(5);

// SIGSEGV handler that does real work (see patterns.md for MBA pattern)
signal(SIGSEGV, real_logic_handler);
*(int*)0 = 0;  // deliberate crash → handler runs real code
```

**绕过：**
```bash
# GDB: pass signals to program instead of handling them
(gdb) handle SIGTRAP nostop pass
(gdb) handle SIGALRM ignore
(gdb) handle SIGSEGV nostop pass

# For alarm-based: patch alarm() to return immediately
```

<a id="syscall-level-evasion"></a>
### 系统调用层规避

```c
// Direct syscall instead of libc — bypasses LD_PRELOAD hooks
long ret;
asm volatile("syscall" : "=a"(ret) : "a"(101), "D"(0), "S"(0), "d"(0), "r"(0));
// Syscall 101 = ptrace on x86_64
```

**绕过：** 必须直接修补二进制，或用 ptrace 在系统调用层拦截。
```bash
# GDB: catch syscall
(gdb) catch syscall 101
(gdb) commands
> set $rax = 0
> continue
> end
```

---

<a id="windows-anti-debug-advanced"></a>
## Windows 反调试（进阶）

<a id="peb-process-environment-block-checks"></a>
### PEB（进程环境块）检查

```c
// BeingDebugged flag (offset 0x2 in PEB)
bool debugged = NtCurrentPeb()->BeingDebugged;

// NtGlobalFlag (offset 0x68/0xBC in PEB)
// When debugger: FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS = 0x70
DWORD flags = *(DWORD*)((BYTE*)NtCurrentPeb() + 0xBC); // 64-bit offset
if (flags & 0x70) exit(1);
```

**绕过（x64dbg）：**
```text
# ScyllaHide plugin auto-patches PEB fields
# Manual: dump PEB, zero BeingDebugged and NtGlobalFlag
```

<a id="ntqueryinformationprocess"></a>
### NtQueryInformationProcess

```c
// ProcessDebugPort (0x7)
DWORD_PTR debugPort = 0;
NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
if (debugPort != 0) exit(1);

// ProcessDebugObjectHandle (0x1E)
HANDLE debugObj = NULL;
NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0x1E, &debugObj, sizeof(debugObj), NULL);
if (status == 0) exit(1); // STATUS_SUCCESS means debugger present

// ProcessDebugFlags (0x1F) — returns inverse: 0 = debugger present
DWORD noDebug = 0;
NtQueryInformationProcess(GetCurrentProcess(), 0x1F, &noDebug, sizeof(noDebug), NULL);
if (noDebug == 0) exit(1);
```

**绕过：** 钩住 `NtQueryInformationProcess` 返回假值，或使用 ScyllaHide。

<a id="heap-flags"></a>
### 堆标志

```c
// Process heap has debug flags when debugger attached
PHEAP heap = (PHEAP)GetProcessHeap();
// Flags at offset 0x70 (64-bit): should be HEAP_GROWABLE (0x2)
// ForceFlags at offset 0x74: should be 0
if (heap->Flags != 0x2 || heap->ForceFlags != 0) exit(1);
```

<a id="tls-callbacks"></a>
### TLS 回调

**关键技术：** TLS（线程局部存储）回调在 `main()` / 入口点**之前**执行。

```c
// Registered in PE header's TLS directory
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        if (IsDebuggerPresent()) {
            ExitProcess(1);  // Kills process before main runs
        }
    }
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK callbacks[] = { TlsCallback, NULL };
```

**在 IDA/Ghidra 中检测：** 查看 PE 的 TLS Directory → AddressOfCallBacks。列在那里的函数会在入口点之前执行。

**绕过：** 在 x64dbg 中对 TLS 回调下断点（Options → Events → TLS Callbacks），或修补 TLS 目录项。

<a id="hardware-breakpoint-detection"></a>
### 硬件断点检测

```c
// Read debug registers via GetThreadContext
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) exit(1);

// Also via exception handler: deliberate exception, check DR regs in handler
```

**绕过：**
```bash
# x64dbg: use software breakpoints instead, or hook GetThreadContext
# Frida: hook GetThreadContext to zero DR registers
```

<a id="software-breakpoint-detection-int3-scanning"></a>
### 软件断点检测（INT3 扫描）

```c
// CRC / hash check over code section
unsigned char *code = (unsigned char*)function_addr;
uint32_t checksum = 0;
for (int i = 0; i < code_size; i++) {
    checksum += code[i];
    if (code[i] == 0xCC) exit(1);  // INT3 = software breakpoint
}
if (checksum != EXPECTED_CHECKSUM) exit(1);
```

**绕过：** 改用硬件断点（DR0-DR3），不要用软件断点。或者钩住扫描函数。

<a id="exception-based-anti-debug"></a>
### 基于异常的反调试

```c
// UnhandledExceptionFilter — under debugger, filter is NOT called
SetUnhandledExceptionFilter(handler);
RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
// If handler runs: no debugger
// If debugger catches: debugger present

// INT 2D — debugger single-step anomaly
__asm { int 2dh }  // Debugger silently consumes the exception
// If execution continues: debugger present
```

<a id="ntsetinformationthread-thread-hiding"></a>
### NtSetInformationThread（隐藏线程）

```c
// Hide thread from debugger — stops all debug events
typedef NTSTATUS(NTAPI *pNtSIT)(HANDLE, ULONG, PVOID, ULONG);
pNtSIT NtSIT = (pNtSIT)GetProcAddress(GetModuleHandle("ntdll"), "NtSetInformationThread");
NtSIT(GetCurrentThread(), 0x11 /*ThreadHideFromDebugger*/, NULL, 0);
// After this, debugger won't see breakpoints or exceptions from this thread
```

**绕过：** 钩住 `NtSetInformationThread` 忽略 class 0x11，或修补该调用。

---

<a id="anti-vm--anti-sandbox"></a>
## 反虚拟机 / 反沙箱

<a id="cpuid-hypervisor-bit"></a>
### CPUID 的 hypervisor 位

```c
int regs[4];
__cpuid(regs, 1);
if (regs[2] & (1 << 31)) {  // ECX bit 31 = hypervisor present
    exit(1);
}

// Hypervisor brand string
__cpuid(regs, 0x40000000);
char brand[13] = {0};
memcpy(brand, &regs[1], 12);
// "VMwareVMware", "Microsoft Hv", "KVMKVMKVM", "XenVMMXenVMM"
```

**绕过：** 修补 `cpuid` 结果，或用 `LD_PRELOAD` 钩住包装函数。

<a id="mac-address--hardware-fingerprinting"></a>
### MAC 地址 / 硬件指纹

```text
Known VM MAC prefixes:
  VMware:     00:0C:29, 00:50:56
  VirtualBox: 08:00:27
  Hyper-V:    00:15:5D
  Parallels:  00:1C:42
  QEMU:       52:54:00
```

<a id="timing-based-vm-detection"></a>
### 基于时序的虚拟机检测

```c
// VM exits on privileged instructions are measurably slower
uint64_t start = __rdtsc();
__cpuid(regs, 0);  // Forces VM exit
uint64_t delta = __rdtsc() - start;
if (delta > 500) { /* likely VM */ }
```

<a id="file--registry-artifacts"></a>
### 文件 / 注册表痕迹

```text
Files: C:\Windows\System32\drivers\vm*.sys, vbox*.dll, VBoxService.exe
Registry: HKLM\SOFTWARE\VMware, Inc.\VMware Tools
Services: VMTools, VBoxService
Processes: vmtoolsd.exe, VBoxTray.exe, qemu-ga.exe
Linux: /sys/class/dmi/id/product_name contains "VirtualBox"|"VMware"
       dmesg | grep -i "hypervisor detected"
```

<a id="resource-checks-cpu-count-ram-disk"></a>
### 资源检查（CPU 核数、内存、磁盘）

```c
// Sandboxes typically have minimal resources
SYSTEM_INFO si;
GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) exit(1);

MEMORYSTATUSEX ms;
ms.dwLength = sizeof(ms);
GlobalMemoryStatusEx(&ms);
if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) exit(1); // < 2GB RAM

// Disk size check (< 60GB = sandbox)
GetDiskFreeSpaceEx("C:\\", NULL, &total, NULL);
```

**绕过：** 使用资源配置充足的虚拟机（4+ CPU、8GB+ 内存、100GB+ 磁盘）。

---

<a id="anti-dbi-dynamic-binary-instrumentation"></a>
## 反 DBI（动态二进制插桩）

<a id="frida-detection"></a>
### Frida 检测

```c
// 1. Check /proc/self/maps for frida-agent
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
    if (strstr(line, "frida") || strstr(line, "gadget")) exit(1);
}

// 2. Check for Frida's default port (27042)
int sock = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(27042), .sin_addr.s_addr=inet_addr("127.0.0.1")};
if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) exit(1);

// 3. Check for inline hooks (function prologue modification)
// Compare first bytes of libc functions against expected values
unsigned char *strcmp_bytes = (unsigned char *)strcmp;
if (strcmp_bytes[0] == 0xE9 || strcmp_bytes[0] == 0xFF) exit(1); // JMP = hooked

// 4. Thread name check
// Frida creates threads with names like "gmain", "gdbus", "frida-*"
DIR *dir = opendir("/proc/self/task");
while ((entry = readdir(dir))) {
    char comm_path[256];
    snprintf(comm_path, sizeof(comm_path), "/proc/self/task/%s/comm", entry->d_name);
    // Read comm and check for "gmain", "gdbus"
}

// 5. Named pipe detection (Windows)
// Frida creates \\.\pipe\frida-* named pipes
```

**用 Frida 绕过 Frida 检测：**
```javascript
// Hook the detection functions themselves
Interceptor.attach(Module.findExportByName(null, "strstr"), {
    onEnter(args) {
        this.haystack = Memory.readUtf8String(args[0]);
        this.needle = Memory.readUtf8String(args[1]);
    },
    onLeave(retval) {
        if (this.needle && (this.needle.includes("frida") || this.needle.includes("gadget"))) {
            retval.replace(ptr(0)); // Not found
        }
    }
});

// Early Frida load (before anti-DBI runs)
// Use frida-gadget as early-init shared library
```

<a id="pindynamorio-detection"></a>
### Pin/DynamoRIO 检测

```c
// Check for instrumentation libraries in /proc/self/maps
// Pin: "pin-", "pinbin", "pinatrace"
// DynamoRIO: "dynamorio", "drcov", "drrun"

// Instruction count timing — DBI adds overhead
// Execute known instruction sequence, compare execution time
```

---

<a id="code-integrity--self-hashing"></a>
## 代码完整性 / 自哈希

```c
// CRC32 over .text section
uint32_t crc = compute_crc32(text_start, text_size);
if (crc != EXPECTED_CRC) exit(1);  // Code was modified (breakpoints, patches)

// MD5/SHA256 of function bodies
unsigned char hash[32];
SHA256(function_addr, function_size, hash);
if (memcmp(hash, expected_hash, 32) != 0) exit(1);
```

**绕过：**
1. **硬件断点**（不修改代码，DR0-DR3）
2. **修补比较**，让它永远成功
3. **钩住哈希函数**，返回期望值
4. **模拟执行**而非调试（Unicorn/Qiling——不修改代码）
5. **快照 + 还原：** 前后转储内存，diff 找出检查点

**循环中的自校验：**
```c
// Continuous integrity check in separate thread
void *watchdog(void *arg) {
    while (1) {
        if (compute_crc32(text_start, text_end - text_start) != saved_crc) {
            memset(flag_buffer, 0, flag_len);  // Destroy flag
            exit(1);
        }
        usleep(100000);
    }
}
```
**绕过：** 杀掉看门狗线程，或把它的 sleep 改成无限。

---

<a id="anti-disassembly-techniques"></a>
## 反反汇编技巧

<a id="opaque-predicates"></a>
### 不透明谓词

```asm
; Condition that always evaluates the same way but looks data-dependent
mov eax, [some_memory]
imul eax, eax          ; x^2
and eax, 1             ; x^2 mod 2 is always 0 for any x
jnz fake_branch        ; Never taken, but disassembler doesn't know
; real code here
```

**识别：** Z3/SMT 可以证明该分支永远走/永远不走。

<a id="junk-bytes--overlapping-instructions"></a>
### 垃圾字节 / 指令重叠

```asm
jmp real_code
db 0xE8           ; Looks like start of CALL to linear disassembler
real_code:
mov eax, 1        ; Real code — disassembler may misalign here
```

**修复：** 改用图模式反汇编（Ghidra/IDA 处理得很好）。手工方式：取消定义，然后从正确偏移重新分析。

<a id="jump-in-the-middle"></a>
### 跳进指令中间

```asm
; Jumps into the middle of a multi-byte instruction
eb 01          ; jmp +1 (skip next byte)
e8             ; fake CALL opcode — disassembler tries to decode as call
90             ; real: NOP (landed here from jmp)
```

<a id="function-chunking--scattered-code"></a>
### 函数分块 / 代码离散

函数被拆分到不连续的块中，用无条件跳转连接，破坏线性的函数边界识别。

**工具：** IDA 的 "Append function tail"，或在每个块上用 Ghidra 的 "Create function"。

<a id="control-flow-flattening-advanced"></a>
### 控制流平坦化（进阶）

在基础 switch-case 之外（见 patterns.md），现代 OLLVM 变体还使用：
- **虚假控制流：** 用不透明谓词构造假分支
- **指令替换：** `a + b` → `a - (-b)`，`a ^ b` → `(a | b) & ~(a & b)`
- **字符串加密：** 运行时解密，用完即清

**反混淆工具：**
- **D-810**（IDA 插件）：基于模式的反混淆、MBA 化简
- **GOOMBA**（Ghidra）：针对 OLLVM 的自动化反混淆
- **Miasm**：符号执行反混淆
- **Arybo** / **SiMBA**：MBA 表达式化简

```bash
# D-810: install in IDA plugins directory, Edit → Plugins → D-810
# Simplifies MBA expressions: (a | b) & ~(a & b) → a ^ b
# Removes opaque predicates via pattern matching
```

<a id="mixed-boolean-arithmetic-mba-identification--simplification"></a>
### 混合布尔算术（MBA）的识别与化简

```python
# Common MBA patterns and their simplified forms:
# (x & y) + (x | y) == x + y
# (x ^ y) + 2*(x & y) == x + y
# (x | y) - (x & ~y) == y
# ~(~x & ~y) == x | y (De Morgan's)
# (x | y) & ~(x & y) == x ^ y

# SiMBA tool for automated simplification:
# pip install simba-simplifier
from simba import simplify_mba
expr = "(a | b) + (a & b) - (~a & b)"
print(simplify_mba(expr))  # → a
```

CTF writeup 中的技巧见 [anti-analysis-ctf.md](anti-analysis-ctf.md)：用 SIGILL 处理器切换模式（Hack.lu 2015）、SIGFPE 的 strace 侧信道（PlaidCTF 2017）、指令轨迹求逆（MeePwn 2017）、无调用函数链（THC 2018）、通过 `process_vm_writev` 实现父进程修补子进程二进制转储（Google CTF Quals 2018）。

---

<a id="comprehensive-bypass-strategies"></a>
## 综合绕过策略

<a id="universal-bypass-checklist"></a>
### 通用绕过检查清单

1. **找出所有反分析检查** — 搜索：`ptrace`、`IsDebuggerPresent`、`rdtsc`、`cpuid`、`NtQuery`、`GetTickCount`、`CheckRemoteDebuggerPresent`、`/proc/self`、`SIGTRAP`、`alarm`
2. **静态打补丁** — 运行前用 pwntools 或 Ghidra 把检查 NOP 掉/改掉
3. **LD_PRELOAD**（Linux）— 钩住 libc 函数返回假值
4. **ScyllaHide**（Windows x64dbg）— 自动修补 PEB、钩住 NT 函数
5. **模拟执行**（Unicorn/Qiling）— 没有调试器痕迹可被检测
6. **内核层绕过** — 修改 `/proc/sys/kernel/yama/ptrace_scope`，使用 `prctl`

<a id="layered-anti-debug-real-world-pattern"></a>
### 分层反调试（真实场景模式）

很多 CTF 题目会叠加多层检查：
```text
1. TLS callback → IsDebuggerPresent (before main)
2. main() → ptrace(TRACEME)
3. Watchdog thread → timing check + /proc scan
4. Code section → self-CRC32 integrity
5. Signal handler → real logic in SIGSEGV handler
```

**思路：** 打补丁前先找出**所有**检查，再系统地逐个修补或挂钩。若数量太多无法逐个处理，就在模拟器中运行。

<a id="quick-reference-check-to-bypass"></a>
### 速查：检查项到绕过手法

| 反调试检查 | 平台 | 绕过 |
|---|---|---|
| `ptrace(TRACEME)` | Linux | `LD_PRELOAD`、补丁为 `ret 0`、`catch syscall` |
| `IsDebuggerPresent` | Windows | ScyllaHide、Frida 钩子、PEB 补丁 |
| `NtQueryInformationProcess` | Windows | ScyllaHide、钩 ntdll |
| `rdtsc` 时序 | 两者 | NOP 掉 rdtsc、Frida 时间钩子、Pin |
| `/proc/self/status` | Linux | 挂载命名空间、钩 fopen |
| `alarm(N)` | Linux | GDB 中 `handle SIGALRM ignore` |
| `SIGTRAP` 处理器 | Linux | `handle SIGTRAP nostop pass` |
| `SIGFPE` 处理器侧信道 | Linux | `strace -e signal=SIGFPE` 统计每个输入的次数 |
| TLS 回调 | Windows | x64dbg 中对 TLS 下断、打补丁 |
| DR 寄存器扫描 | Windows | 改用软件断点、钩 GetThreadContext |
| INT3 扫描 / CRC | 两者 | 硬件断点、修补 CRC 比较 |
| Frida 检测 | 两者 | 尽早加载 gadget、钩 strstr |
| CPUID hypervisor | 两者 | 修补 CPUID 结果、用裸机 |
| 线程隐藏 | Windows | 钩 NtSetInformationThread |

---

<a id="trap-flag-self-check-with-cmovz-patcher-hacklu-2018"></a>
### Trap Flag 自检与 cmovz 补丁（Hack.lu 2018）

**模式：** 二进制用 `pushf; pop edx; and edx, 0x100` 检查 `EFLAGS`（单独取出单步 Trap Flag），并把结果用在 `cmovz` 中，使得只有在 TF 位清零时才覆盖正确的那条指令。在 gdb 中单步会让 TF 保持置位，`cmovz` 永远不触发，程序于是静悄悄走错代码路径而不崩溃。

```asm
check_debugger:
    pushf
    pop   edx
    and   edx, 0x100          ; Trap Flag only
    test  edx, edx
    cmovz eax, ebx            ; overwrite `eax` only when NOT single-stepping
    mov   [rip+target], eax
```

**用硬件断点绕过：**
```gdb
(gdb) hbreak *0x56557267       # hardware BP, no INT3, no TF side effect
(gdb) run
(gdb) # inspect EAX at the hbreak — the patched value is now written
```

**关键点：** `pushf; pop reg; and reg, 0x100` 是不触发陷阱就能检查 TF 的最干净方式。单步会改变可见的 EFLAGS，还可能扰动指令流水线，因此软件断点加 `stepi` 都会污染这项检查。硬件断点（`hbreak`）正常执行指令、执行后再停下，检查会按“未调试”模式走。对任何读取 EFLAGS、RFLAGS 或 DR6 的反调试，都用同样的修法。

**参考：** Hack.lu CTF 2018 — Forgetful Commander，writeup 11858

---

<a id="sigfpe-handler-for-mprotect-code-mutation-hacklu-2018"></a>
### SIGFPE 处理器改写代码（Hack.lu 2018）

**模式：** 二进制用 `sys_sigaction` 安装自定义 `SIGFPE` 处理器，并安排一条算术指令触发陷阱（例如除以零）。处理器在内核投递的上下文中运行，对 `.text` 页调用 `mprotect` 使其可写，然后改写原本应保持不变的代码。静态分析会漏掉这次改写，因为正常路径下 FPE 根本不会触发；常规动态分析也会漏掉，因为多数调试器会在投递前截获 SIGFPE。

```c
// Handler installed at startup
void on_fpe(int sig, siginfo_t *info, void *uap) {
    ucontext_t *ctx = uap;
    void *page = (void *)((uintptr_t)ctx->uc_mcontext.gregs[REG_RIP] & ~0xfff);
    mprotect(page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
    // Patch a constant used by the next check
    *((uint32_t *)(page + 0x42)) = 0xDEADBEEF;
}
```

**绕过：**
```bash
# Let SIGFPE reach the program, not the debugger
gdb ./challenge
(gdb) handle SIGFPE nostop noprint pass
(gdb) break *on_fpe
(gdb) run
```

**关键点：** 会 `mprotect` 并改写代码的信号处理器，其控制流是反编译器无法建模的跨界结构。`SIGFPE` 尤其有效，因为正常执行时几乎不会触发，改写在攻击者命中构造好的输入之前一直潜伏。当你在同时调用 `mprotect` 的二进制中看到 `sys_sigaction(SIGFPE,...)` 或 `signal(SIGFPE,...)` 时，用 `strace -e signal=SIGFPE` 跟踪处理器，并通过比较第一次 FPE 前后 `.text` 页的差异来标注被改写的区域。

**参考：** Hack.lu CTF 2018 — Cheat Console，writeup 11868
