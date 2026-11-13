# CTF Reverse - 高级工具与反混淆

面向商业壳/保护器、二进制差异对比、反混淆框架、模拟执行以及 angr 之外的符号执行的高级工具链。

关于高级 GDB 脚本、Ghidra 自动化、补丁框架以及 GDB 驱动的 CTF 技巧，见 [tools-advanced-2.md](tools-advanced-2.md)。

## 目录
- [VMProtect 分析](#vmprotect-分析)
  - [识别特征](#识别特征)
  - [分析思路](#分析思路)
  - [工具](#工具)
  - [CTF 策略](#ctf-策略)
- [Themida / WinLicense 分析](#themida--winlicense-分析)
  - [Themida 识别特征](#themida-识别特征)
  - [CTF 下的处理思路](#ctf-下的处理思路)
- [二进制差异对比](#二进制差异对比)
  - [BinDiff](#bindiff)
  - [Diaphora](#diaphora)
- [反混淆框架](#反混淆框架)
  - [D-810（IDA）](#d-810ida)
  - [GOOMBA（Ghidra）](#goombaghidra)
  - [Miasm](#miasm)
- [Qiling 框架（模拟执行）](#qiling-框架模拟执行)
- [Triton（动态符号执行）](#triton动态符号执行)
- [Manticore（符号执行）](#manticore符号执行)
- [Rizin / Cutter](#rizin--cutter)
- [RetDec（可重定向反编译器）](#retdec可重定向反编译器)
- [自定义 VM 字节码提升到 LLVM IR (Google CTF 2017)](#自定义-vm-字节码提升到-llvm-ir-google-ctf-2017)

---

<a id="vmprotect-analysis"></a>
## VMProtect 分析

VMProtect 把 x86/x64 代码虚拟化为由生成的 VM 解释执行的自定义字节码，是 CTF 中最难对付的保护器之一。

<a id="recognition"></a>
### 识别特征

```bash
# VMProtect signatures
strings binary | grep -i "vmp\|vmprotect"
# PE sections: .vmp0, .vmp1 (VMProtect adds its own sections)
readelf -S binary | grep ".vmp"
# Large binary with entropy > 7.5 in certain sections
```

**关键指标：**
- 大量 `push` / `pop` 的序言（VM 入口会把所有寄存器压栈）
- 大型 switch-case 分派器（VM handler 主循环）
- VM handler 中内嵌反调试检查
- 变异引擎：同一条 opcode 在不同构建中对应不同的 handler

<a id="approach"></a>
### 分析思路

```text
1. Identify VM entry points — look for pushad/pushaq-like sequences
2. Find the handler table — large indirect jump (jmp [reg + offset])
3. Trace handler execution — each handler ends with jump to next
4. Identify handlers:
   - vAdd, vSub, vMul, vXor, vNot (arithmetic)
   - vPush, vPop (stack operations)
   - vLoad, vStore (memory access)
   - vJmp, vJcc (control flow)
   - vRet (VM exit — restores real registers)
5. Build disassembler for VM bytecode
6. Simplify / deobfuscate the lifted IL
```

<a id="tools"></a>
### 工具

- **VMPAttack**（IDA 插件）：自动识别 VM handler
- **NoVmp**：基于 VTIL 的去虚拟化（开源）
- **VMProtect devirtualizer scripts**：社区维护的 IDA/Binary Ninja 脚本
- **CTF 思路：** 通常追踪特定操作（加密、比较）比完整去虚拟化更容易

<a id="ctf-strategy"></a>
### CTF 策略

```python
# Trace VM execution dynamically to extract operations on flag
# Hook VM handler dispatch to log opcode + operands

import frida

script = """
var vm_dispatch = ptr('0x...');  // Address of handler table jump
Interceptor.attach(vm_dispatch, {
    onEnter(args) {
        // Log handler index and stack state
        var handler_idx = this.context.rax;  // or whichever register
        console.log('Handler:', handler_idx, 'RSP:', this.context.rsp);
    }
});
"""
```

**关键点：** CTF 中几乎不需要完全去虚拟化。重点追踪对输入执行了哪些操作，并 hook VM 内部调用的比较/加密函数。

---

<a id="themida--winlicense-analysis"></a>
## Themida / WinLicense 分析

与 VMProtect 类似，但额外叠加了多层反调试。

<a id="themida-recognition"></a>
### Themida 识别特征
- 节区：`.themida`、`.winlice`
- 极重的反调试（内核级检查、驱动安装）
- 代码变异 + 虚拟化 + 加壳的组合

<a id="approach-for-ctf"></a>
### CTF 下的处理思路
1. **导出脱壳后的代码：** 让它运行，脱壳后 dump 进程内存
2. **绕过反调试：** 在 x64dbg 中使用 ScyllaHide 并加载 Themida 专用预设
3. **修复导入表：** 用 Scylla 插件重建 IAT
4. **专注 dump 出的代码：** 脱壳完成后按普通二进制进行分析

```bash
# x64dbg workflow for Themida:
1. Load binary
2. Enable ScyllaHide → Profile: Themida
3. Run to OEP (Original Entry Point) — may need several attempts
4. Dump with Scylla: OEP → IAT Autosearch → Get Imports → Dump
5. Fix dump: Scylla → Fix Dump
6. Analyze fixed dump in Ghidra/IDA
```

---

<a id="binary-diffing"></a>
## 二进制差异对比

补丁分析、1-day 漏洞利用开发，以及提供两个版本二进制的 CTF 题目都离不开它。

<a id="bindiff"></a>
### BinDiff

```bash
# Export from IDA/Ghidra first, then diff
# IDA: File → BinExport → Export as BinExport2
# Ghidra: Use BinExport plugin

# Command line diffing
bindiff primary.BinExport secondary.BinExport
# Opens in BinDiff GUI — shows matched/unmatched functions
```

**关键指标：**
- 每对函数的相似度评分（0.0-1.0）
- 高亮显示发生变化的指令
- 未匹配的函数 = 新增/删除的代码

<a id="diaphora"></a>
### Diaphora

BinDiff 的免费开源替代品，以 IDA 插件形式运行。

```bash
# In IDA:
# File → Script file → diaphora.py
# Export first binary, then open second and diff

# Ghidra version: diaphora_ghidra.py
```

**对 CTF 的用处：** 当题目同时提供 "打过补丁" 和 "原始" 两个二进制时，差异对比能直接暴露漏洞或隐藏功能。

---

<a id="deobfuscation-frameworks"></a>
## 反混淆框架

<a id="d-810-ida"></a>
### D-810（IDA）

面向 IDA Pro 的基于模式的反混淆插件，特别适合 OLLVM 混淆过的二进制。

```text
Capabilities:
- MBA simplification: (a ^ b) + 2*(a & b) → a + b
- Dead code elimination
- Opaque predicate removal
- Constant folding
- Control flow unflattening (partial)

Installation: Copy to IDA plugins directory
Usage: Edit → Plugins → D-810 → Select rules → Apply
```

<a id="goomba-ghidra"></a>
### GOOMBA（Ghidra）

```text
GOOMBA (Ghidra-based Obfuscated Object Matching and Bytes Analysis):
- Integrates with Ghidra's P-Code
- Simplifies MBA expressions
- Pattern matching for known obfuscation

Installation: Copy .jar to Ghidra extensions
Usage: Code Browser → Analysis → GOOMBA
```

<a id="miasm"></a>
### Miasm

功能强大的逆向框架，具备符号执行与 IR 提升能力。

```python
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.expression.expression import *

# Load binary and lift to Miasm IR
cont = Container.from_stream(open("binary", "rb"))
machine = Machine(cont.arch)
mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)

# Disassemble function
asmcfg = mdis.dis_multiblock(entry_addr)

# Lift to IR
lifter = machine.lifter_model_call(loc_db=cont.loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

# Symbolic execution
from miasm.ir.symbexec import SymbolicExecutionEngine
sb = SymbolicExecutionEngine(lifter)
# Execute symbolically, then simplify expressions
```

**适用场景：** 反混淆表达式树、化简复杂算术、追踪混淆代码中的数据流。

---

<a id="qiling-framework-emulation"></a>
## Qiling 框架（模拟执行）

基于 Unicorn 的跨平台模拟框架，额外提供 OS 层支持（系统调用、文件系统、注册表）。

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

# Emulate Linux ELF
ql = Qiling(["./binary"], "rootfs/x8664_linux",
            verbose=QL_VERBOSE.DEBUG)

# Hook specific address
@ql.hook_address
def hook_check(ql, address, size):
    if address == 0x401234:
        ql.arch.regs.rax = 0  # Bypass check
        ql.log.info("Anti-debug bypassed")

# Hook syscall
@ql.hook_syscall(name="ptrace")
def hook_ptrace(ql, request, pid, addr, data):
    return 0  # Always succeed

# Hook API (Windows)
@ql.set_api("IsDebuggerPresent", target=ql.os.user_defined_api)
def hook_isdebug(ql, address, params):
    return 0

ql.run()
```

**相对 Unicorn 的优势：**
- OS 层模拟（文件 I/O、网络、注册表）
- 多平台（Linux、Windows、macOS、Android、UEFI）
- 内置调试器接口
- 用于加载库的 rootfs

**CTF 适用场景：**
- 模拟异构架构（ARM、MIPS、RISC-V）的二进制
- 一次性绕过所有反调试（无调试器痕迹）
- 无需硬件即可对嵌入式/IoT 固件做 fuzz
- 不改代码即可追踪执行

---

<a id="triton-dynamic-symbolic-execution"></a>
## Triton（动态符号执行）

基于 Pin 的动态二进制分析框架，具备符号执行、污点分析和 AST 化简能力。

```python
from triton import *

ctx = TritonContext(ARCH.X86_64)

# Load binary sections
with open("binary", "rb") as f:
    binary = f.read()
ctx.setConcreteMemoryAreaValue(0x400000, binary)

# Symbolize input
for i in range(32):
    ctx.symbolizeMemory(MemoryAccess(INPUT_ADDR + i, CPUSIZE.BYTE), f"input_{i}")

# Emulate instructions
pc = ENTRY_POINT
while pc:
    inst = Instruction(pc, ctx.getConcreteMemoryAreaValue(pc, 16))
    ctx.processing(inst)

    # At comparison point, extract path constraint
    if pc == CMP_ADDR:
        ast = ctx.getPathConstraintsAst()
        model = ctx.getModel(ast)
        for k, v in sorted(model.items()):
            print(f"input[{k}] = {chr(v.getValue())}", end="")
        break

    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
```

**Triton 与 angr 对比：**
| 特性 | Triton | angr |
|---|---|---|
| 执行方式 | 具体 + 符号（DSE） | 全符号 |
| 速度 | 更快（具体值驱动） | 较慢（探索所有路径） |
| 路径爆炸 | 不易发生（只跟随一条路径） | 主要问题 |
| API | C++ / Python | Python |
| 最适合 | 单路径反混淆、污点追踪 | 多路径探索 |

**核心用途：** Triton 在反混淆上表现突出 —— 具体执行程序，同时记录符号状态，再化简收集到的约束。

---

<a id="manticore-symbolic-execution"></a>
## Manticore（符号执行）

Trail of Bits 的符号执行工具，与 angr 类似，但原生支持 EVM（以太坊）。

```python
from manticore.native import Manticore

m = Manticore("./binary")

# Hook success/failure
@m.hook(0x401234)
def success(state):
    buf = state.solve_one_n_batched(state.input_symbols, 32)
    print("Flag:", bytes(buf))
    m.kill()

@m.hook(0x401256)
def fail(state):
    state.abandon()

m.run()
```

**最适合：** EVM/智能合约分析、较简单的 Linux 二进制。对于复杂逆向任务，angr 通常更成熟。

---

<a id="rizin--cutter"></a>
## Rizin / Cutter

Rizin 是 radare2 的持续维护分支，Cutter 是其基于 Qt 的图形界面。

```bash
# Rizin CLI (r2-compatible commands)
rizin -d ./binary
> aaa                    # Analyze all
> afl                    # List functions
> pdf @ main             # Print disassembly
> VV                     # Visual graph mode

# Cutter GUI
cutter binary           # Open in GUI with decompiler
```

**Cutter 的优势：**
- 内置 Ghidra 反编译器（通过 r2ghidra 插件）
- 图视图、十六进制编辑器、调试面板集于一个 GUI
- 集成 Python/JavaScript 脚本控制台
- 免费开源

---

<a id="retdec-retargetable-decompiler"></a>
## RetDec（可重定向反编译器）

基于 LLVM 的反编译器，支持多种架构，免费开源。

```bash
# Install
pip install retdec-decompiler
# Or use web: https://retdec.com/decompilation/

# CLI
retdec-decompiler binary
# Outputs: binary.c (decompiled C), binary.dsm (disassembly)

# Specific function
retdec-decompiler --select-ranges 0x401000-0x401100 binary
```

**优势：** 多架构支持（x86、ARM、MIPS、PowerPC、PIC32），免费，输出可编译的 C 代码。适合 Ghidra 支持不佳的架构。

---

<a id="custom-vm-bytecode-lifting-to-llvm-ir-google-ctf-2017"></a>
## 自定义 VM 字节码提升到 LLVM IR (Google CTF 2017)

对于复杂的自定义 VM，可以把 VM 字节码转译成 LLVM IR，利用 LLVM 的优化 pass 化简代码，再对优化后的 IR 做反编译。

```python
# Pipeline: VM bytecode → custom disassembler → LLVM IR → optimize → decompile
# 1. Write disassembler for the custom VM opcodes
# 2. Emit LLVM IR for each opcode:
#    INC reg  → %reg = add i32 %reg, 1
#    CDEC reg → conditional decrement
#    CALL fn  → call void @fn()
# 3. Use MCJIT or llc to optimize:
#    opt -O3 -S vm_lifted.ll -o vm_optimized.ll
# 4. Load optimized IR in IDA or decompile with RetDec
# Result: 1300 lines → 150 lines after inlining + constant folding
```

**关键点：** LLVM 的优化 pass（内联、常量折叠、死代码消除）能极大化简提升后的 VM 字节码。一个含 26 个寄存器、3 种 opcode 的自定义 VM 会生成 1300 行 IL，经过 `-O3` 后缩减到约 150 行，从而暴露出底层算法（例如 Collatz 序列计算）。
