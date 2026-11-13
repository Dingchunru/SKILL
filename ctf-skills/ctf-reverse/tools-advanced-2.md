# 高级逆向工程工具（第二部分）

高级 GDB 脚本、Ghidra 自动化、补丁框架，以及 CTF 中由 GDB 驱动的专项技巧。是 [tools-advanced.md](tools-advanced.md) 的续篇。

## 目录
- [高级 GDB 技巧](#高级-gdb-技巧)
  - [Python 脚本](#python-脚本)
  - [用 GDB 脚本爆破](#用-gdb-脚本爆破)
  - [条件断点](#条件断点)
  - [观察点](#观察点)
  - [反向调试（rr）](#反向调试rr)
  - [GDB Dashboard / GEF / pwndbg](#gdb-dashboard--gef--pwndbg)
- [高级 Ghidra 脚本](#高级-ghidra-脚本)
- [打补丁策略](#打补丁策略)
  - [Binary Ninja 打补丁（Python API）](#binary-ninja-打补丁python-api)
  - [LIEF（可执行格式插桩库）](#lief可执行格式插桩库)
- [用 ILP/LP 求解器配合 GDB 提取约束 (BackdoorCTF 2017)](#用-ilplp-求解器配合-gdb-提取约束-backdoorctf-2017)
- [位置编码输入 + 零标志位监控 (EKOPARTY 2017)](#位置编码输入--零标志位监控-ekoparty-2017)
- [用 LD_PRELOAD 导出仅可执行二进制 (BackdoorCTF 2017)](#用-ld_preload-导出仅可执行二进制-backdoorctf-2017)
- [PEDA current_inst 逐比特抓取 flag (CONFidence CTF 2019 Teaser)](#peda-current_inst-逐比特抓取-flag-confidence-ctf-2019-teaser)

---

<a id="advanced-gdb-techniques"></a>
## 高级 GDB 技巧

<a id="python-scripting"></a>
### Python 脚本

```python
# ~/.gdbinit or source from GDB
import gdb

class TraceCompare(gdb.Breakpoint):
    """Log all comparison operations."""
    def __init__(self, addr):
        super().__init__(f"*{addr}", gdb.BP_BREAKPOINT)

    def stop(self):
        frame = gdb.selected_frame()
        rdi = int(frame.read_register("rdi"))
        rsi = int(frame.read_register("rsi"))
        rdx = int(frame.read_register("rdx"))
        # Read compared buffers
        inferior = gdb.selected_inferior()
        buf1 = inferior.read_memory(rdi, rdx).tobytes()
        buf2 = inferior.read_memory(rsi, rdx).tobytes()
        print(f"memcmp({buf1!r}, {buf2!r}, {rdx})")
        return False  # Don't stop, just log

# Usage in GDB:
# (gdb) source trace_cmp.py
# (gdb) python TraceCompare(0x401234)
```

<a id="brute-force-with-gdb-script"></a>
### 用 GDB 脚本爆破

```python
# Byte-by-byte brute force via GDB Python API
import gdb, string

def bruteforce_flag(check_addr, success_addr, fail_addr, flag_len):
    flag = []
    for pos in range(flag_len):
        for ch in string.printable:
            candidate = ''.join(flag) + ch + 'A' * (flag_len - pos - 1)
            gdb.execute('start', to_string=True)
            gdb.execute(f'b *{check_addr}', to_string=True)
            # Write candidate to stdin pipe
            # ... (setup input)
            gdb.execute('continue', to_string=True)
            rip = int(gdb.parse_and_eval('$rip'))
            if rip == success_addr:
                flag.append(ch)
                break
        gdb.execute('delete breakpoints', to_string=True)
    return ''.join(flag)
```

<a id="conditional-breakpoints"></a>
### 条件断点

```bash
# Break only when register has specific value
(gdb) b *0x401234 if $rax == 0x41
(gdb) b *0x401234 if *(char*)$rdi == 'f'

# Break on Nth hit
(gdb) b *0x401234
(gdb) ignore 1 99    # Skip first 99 hits, break on 100th

# Log without stopping
(gdb) b *0x401234
(gdb) commands
> silent
> printf "rax=%lx rdi=%lx\n", $rax, $rdi
> continue
> end
```

<a id="watchpoints"></a>
### 观察点

```bash
# Hardware watchpoint — break when memory changes
(gdb) watch *(int*)0x601050        # Break on write to address
(gdb) rwatch *(int*)0x601050       # Break on read
(gdb) awatch *(int*)0x601050       # Break on read or write

# Watch a variable by name (needs debug symbols)
(gdb) watch flag_buffer[0]

# Conditional watchpoint
(gdb) watch *(int*)0x601050 if *(int*)0x601050 == 0x42
```

<a id="reverse-debugging-rr"></a>
### 反向调试（rr）

```bash
# Record execution
rr record ./binary
# Replay with reverse execution support
rr replay

# In rr replay (GDB commands plus):
(gdb) reverse-continue     # Run backward to previous breakpoint
(gdb) reverse-stepi        # Step backward one instruction
(gdb) reverse-next         # Reverse next
(gdb) when                 # Show current event number

# Set checkpoint and return to it
(gdb) checkpoint
(gdb) restart 1           # Return to checkpoint 1
```

**核心用途：** 步过了关键位置时，反向执行回去，而不是从头重跑。对付会破坏状态的反调试尤其宝贵。

<a id="gdb-dashboard--gef--pwndbg"></a>
### GDB Dashboard / GEF / pwndbg

```bash
# pwndbg (most popular for CTF)
# https://github.com/pwndbg/pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# Key pwndbg commands:
pwndbg> context           # Show registers, stack, code, backtrace
pwndbg> vmmap             # Memory map (like /proc/self/maps)
pwndbg> search -s "flag{" # Search memory for string
pwndbg> telescope $rsp 20 # Smart stack dump
pwndbg> cyclic 200        # Generate De Bruijn pattern
pwndbg> hexdump $rdi 64   # Pretty hex dump
pwndbg> got               # Show GOT entries
pwndbg> plt               # Show PLT entries

# GEF (alternative)
# https://github.com/hugsy/gef
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Key GEF commands:
gef> xinfo $rdi           # Detailed info about address
gef> checksec             # Binary security features
gef> heap chunks          # Heap chunk listing
gef> pattern create 100   # De Bruijn pattern
```

---

<a id="advanced-ghidra-scripting"></a>
## 高级 Ghidra 脚本

```python
# Ghidra Python (Jython) — run via Script Manager or headless

# Batch rename functions matching a pattern
from ghidra.program.model.symbol import SourceType
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.getName().startswith("FUN_"):
        # Check if function contains specific instruction pattern
        body = func.getBody()
        inst_iter = currentProgram.getListing().getInstructions(body, True)
        for inst in inst_iter:
            if inst.getMnemonicString() == "CPUID":
                func.setName("anti_vm_check_" + hex(func.getEntryPoint().getOffset()),
                            SourceType.USER_DEFINED)
                break

# Extract all XOR constants from a function
def extract_xor_constants(func):
    """Find all XOR operations and their immediate operands."""
    constants = []
    body = func.getBody()
    inst_iter = currentProgram.getListing().getInstructions(body, True)
    for inst in inst_iter:
        if inst.getMnemonicString() == "XOR":
            for i in range(inst.getNumOperands()):
                op = inst.getOpObjects(i)
                if op and hasattr(op[0], 'getValue'):
                    constants.append(int(op[0].getValue()))
    return constants

# Bulk decompile and search for pattern
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)

for func in fm.getFunctions(True):
    result = decomp.decompileFunction(func, 30, monitor)
    if result.depiledFunction():
        code = result.getDecompiledFunction().getC()
        if "strcmp" in code or "memcmp" in code:
            print(f"Comparison in {func.getName()} at {func.getEntryPoint()}")
```

---

<a id="patching-strategies"></a>
## 打补丁策略

<a id="binary-ninja-patching-python-api"></a>
### Binary Ninja 打补丁（Python API）

```python
import binaryninja as bn

bv = bn.open_view("binary")

# NOP out instruction
bv.write(0x401234, b"\x90" * 5)  # 5-byte NOP

# Patch conditional jump (JNZ → JZ)
bv.write(0x401234, b"\x74")  # 0x75 (JNZ) → 0x74 (JZ)

# Insert always-true (mov eax, 1; ret)
bv.write(0x401234, b"\xb8\x01\x00\x00\x00\xc3")

bv.save("patched")
```

<a id="lief-library-for-instrumenting-executable-formats"></a>
### LIEF（可执行格式插桩库）

```python
import lief

# Parse and modify ELF/PE/Mach-O
binary = lief.parse("binary")

# Add a new section
section = lief.ELF.Section(".patch")
section.content = list(b"\xcc" * 0x100)
section.type = lief.ELF.Section.TYPE.PROGBITS
section.flags = lief.ELF.Section.FLAGS.EXECINSTR | lief.ELF.Section.FLAGS.ALLOC
binary.add(section)

# Modify entry point
binary.header.entrypoint = 0x401000

# Hook imported function
binary.patch_pltgot("strcmp", 0x401000)

binary.write("patched")
```

**LIEF 的优势：** 跨格式（ELF、PE、Mach-O）、Python API、可新增节/段、修改头部、打补丁到导入函数。

---

<a id="gdb-constraint-extraction-with-ilplp-solver-backdoorctf-2017"></a>
## 用 ILP/LP 求解器配合 GDB 提取约束 (BackdoorCTF 2017)

当二进制在输入字节之间强制线性算术关系时，用 GDB 自动提取约束，再交给 ILP 求解器求解。

**技巧：** 发送位置编码的输入（`input[i] = i`），这样在比较触发时，你能确切知道涉及哪些位置、它们的和/差必须等于什么。把日志中记录的所有比较约束收集起来，交给 PuLP 或 Gurobi。

```python
from pulp import *

n = 32  # flag length
prob = LpProblem("crackme", LpMinimize)
x = [LpVariable(f'x{i}', 32, 126, cat='Integer') for i in range(n)]
prob += 0  # dummy objective

# Constraints extracted via GDB automation (input[i]=i, monitor comparisons):
prob += x[3] + x[7] == 0xAB
prob += x[1] - x[5] == 0x0C
# ... add all extracted constraints ...

# Constrain to printable ASCII
for xi in x:
    prob += xi >= 32
    prob += xi <= 126

prob.solve(PULP_CBC_CMD(msg=0))
flag = ''.join(chr(int(value(xi))) for xi in x)
print("Flag:", flag)
```

**用 GDB 自动化提取约束：**
```python
# In GDB Python: set input[i]=i, run, log every CMP instruction result
import gdb

class CmpLogger(gdb.Breakpoint):
    def stop(self):
        frame = gdb.selected_frame()
        # Read compared values, map back to input indices via position encoding
        return False
```

**关键点：** 当二进制在输入字节之间强制线性算术关系时，只要通过 GDB 自动化把约束提取出来，ILP 求解器就能直接给出满足条件的赋值。

**参考：** BackdoorCTF 2017

---

<a id="gdb-position-encoded-input-with-zero-flag-monitoring-ekoparty-2017"></a>
## 位置编码输入 + 零标志位监控 (EKOPARTY 2017)

发送 `input[i] = i` 的输入（位置编码）。单步执行并监控 CPU 零标志位（ZF）。当涉及某个位置数值的比较处 ZF 被置位时，说明比较匹配 —— 记录下该位置的期望值。

```python
import gdb

# Script: single-step binary with position-encoded input, watch ZF
class ZFMonitor(gdb.Breakpoint):
    def stop(self):
        zf = (int(gdb.parse_and_eval('$eflags')) >> 6) & 1
        if zf:
            rip = int(gdb.parse_and_eval('$rip'))
            # Disassemble at rip to find the compared immediate
            disasm = gdb.execute(f'x/1i {rip-5}', to_string=True)
            print(f"ZF set at {rip:#x}: {disasm.strip()}")
        return False

# Run once with input b'\x00\x01\x02\x03...\x1f'
# ZF fires when comparison matches the position's own value -> that IS the key byte
```

这样一遍就能把每个输入字节映射到它应有的值，无需手工逆向。

**关键点：** 位置编码输入（`input[i]=i`）配合零标志位监控，可以一遍扫出完整的密钥/口令 —— 当第 i 个位置的期望值恰好等于 i 时，零标志位就会触发。

**参考：** EKOPARTY CTF 2017

---

<a id="ld_preload-to-dump-execute-only-binary-backdoorctf-2017"></a>
## 用 LD_PRELOAD 导出仅可执行二进制 (BackdoorCTF 2017)

一个二进制的权限是仅可执行（mode `--x`，没有读位）。文件无法直接读取，常规工具也读不了，但内核在执行时仍会把它映射进内存。

LD_PRELOAD 一个共享库，用构造函数在进程内部运行，通过 `/proc/self/mem` 读取自身内存：

```c
// dump_xo.c — compile: gcc -shared -fPIC -o dump_xo.so dump_xo.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((constructor)) void dump() {
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[256];
    unsigned long base = 0, end = 0;

    // Find the execute-only binary's mapping (r-xp or --xp)
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "binary_name")) {
            sscanf(line, "%lx-%lx", &base, &end);
            break;
        }
    }
    fclose(maps);

    FILE *mem = fopen("/proc/self/mem", "rb");
    fseek(mem, base, SEEK_SET);
    size_t size = end - base;
    void *buf = malloc(size);
    fread(buf, 1, size, mem);
    fclose(mem);

    FILE *out = fopen("/tmp/dumped_binary", "wb");
    fwrite(buf, 1, size, out);
    fclose(out);
}
// Usage: LD_PRELOAD=./dump_xo.so ./binary_xo
```

**关键点：** 仅可执行权限阻止了读文件，但阻止不了执行。LD_PRELOAD 构造函数运行在进程内部，而 `/proc/self/mem` 无论文件权限如何都能访问已映射的内存。

**参考：** BackdoorCTF 2017

---

<a id="peda-current_inst-bit-by-bit-flag-scraper-confidence-ctf-2019-teaser"></a>
## PEDA current_inst 逐比特抓取 flag (CONFidence CTF 2019 Teaser)

**模式（Elementary）：** 一个庞大的混淆校验器对 flag 的每个比特各分派一次 `call functionN`。每次检查读取 `flag[offset] >> bit & 1`，调用不透明的 `functionN(that_bit)`，再把返回值与常量比较。与其反编译数百个包装函数，不如用 GDB+PEDA 单步走完分派器，直接读取 `edi`（参数）和 `eax`（返回值）：

```python
# peda.current_inst(rip) returns (addr, mnemonic_str); use it as a cheap
# disassembler to track the shift/add offsets passed to each checker.
def get_current_inst():
    return peda.current_inst(peda.getreg("rip"))[1]

peda.execute('file ./elementary')
peda.set_breakpoint(0x555555554000 + 0xCEB88)
peda.execute("run < _input")         # _input = 'A' * 103 (length only)

flag = ['0'] * 832                    # 104 bytes * 8 bits
while peda.getreg("rip") < 0x555555554000 + 0xD827F:
    offset = bit = 0
    while 'and' != get_current_inst()[:3]:
        cur = get_current_inst()
        if cur == 'mov    rax,QWORD PTR [rbp-0x18]':
            offset = 0; bit = 0
        elif cur.startswith('sar'):
            bit = int(cur.split(',')[1], 16)     # shift count -> bit index
        elif cur.startswith('add'):
            offset = int(cur.split(',')[1], 16)  # byte index in flag
        peda.execute('si')
    while 'call' not in get_current_inst(): peda.execute('si')
    tmp = peda.getreg('edi')
    peda.execute('ni')
    ret = peda.getreg('eax')
    # Oracle: if return == arg the checker voted "bit=0", else "bit=1"
    flag[offset * 8 + bit] = '0' if (ret != 0 and tmp == ret) else '1'
    peda.execute('set $eax=0')        # neutralise so loop continues
```

**关键点：** 任何形如 `f_i(bit_i) == const_i` 的校验器都是黑盒 oracle —— 你不需要理解 `f_i`。PEDA 的 `current_inst()` 加上 `si`/`ni`，三十行 Python 就能在一次运行中收齐所有比特；解析前面的 `sar imm` / `add imm` 指令即可得到 `(字节偏移, 比特下标)`，无需反汇编校验器的算术逻辑。

**参考：** CONFidence CTF 2019 Teaser — Elementary，writeup 13927
