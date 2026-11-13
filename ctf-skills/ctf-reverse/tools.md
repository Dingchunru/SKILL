# CTF Reverse - 工具速查

## 目录
- [GDB](#gdb)
  - [基础命令](#基础命令)
  - [PIE 二进制调试](#pie-二进制调试)
  - [单行命令自动化](#单行命令自动化)
  - [内存查看](#内存查看)
- [Radare2](#radare2)
  - [基础会话](#基础会话)
  - [r2pipe 自动化](#r2pipe-自动化)
- [Ghidra](#ghidra)
  - [无头分析](#无头分析)
  - [用模拟器解密](#用模拟器解密)
  - [MCP 命令](#mcp-命令)
- [Unicorn 模拟执行](#unicorn-模拟执行)
  - [基础配置](#基础配置)
  - [混合模式（64 位切 32 位）](#混合模式64-位切-32-位)
  - [寄存器追踪 Hook](#寄存器追踪-hook)
  - [追踪寄存器变化](#追踪寄存器变化)
- [Python 字节码](#python-字节码)
  - [反汇编](#反汇编)
  - [提取常量](#提取常量)
  - [Pyarmor 静态脱壳（1shot）](#pyarmor-静态脱壳1shot)
- [WASM 分析](#wasm-分析)
  - [反编译成 C](#反编译成-c)
  - [常见模式](#常见模式)
- [Android APK](#android-apk)
  - [提取](#提取)
  - [关键位置](#关键位置)
  - [搜索](#搜索)
  - [Flutter APK（Blutter）](#flutter-apkblutter)
  - [HarmonyOS HAP/ABC（abc-decompiler）](#harmonyos-hapabcabc-decompiler)
- [.NET 分析](#net-分析)
  - [工具](#工具)
  - [两阶段 XOR + AES-CBC 解码模式 (Codegate 2013)](#两阶段-xor--aes-cbc-解码模式-codegate-2013)
  - [NativeAOT](#nativeaot)
- [加壳二进制](#加壳二进制)
  - [UPX](#upx)
  - [自定义壳](#自定义壳)
  - [PyInstaller](#pyinstaller)
- [LLVM IR](#llvm-ir)
  - [转换为汇编](#转换为汇编)
- [RISC-V 二进制分析 (EHAX 2026)](#risc-v-二进制分析-ehax-2026)
- [Binary Ninja](#binary-ninja)
- [用 dogbolt.org 对比反编译器](#用-dogboltorg-对比反编译器)
- [常用命令](#常用命令)
- [用 boolector SMT2 反推自定义哈希 (OTW Advent 2018)](#用-boolector-smt2-反推自定义哈希-otw-advent-2018)

关于动态插桩工具（Frida、angr、lldb、x64dbg），见 [tools-dynamic.md](tools-dynamic.md)。

---

<a id="gdb"></a>
## GDB

<a id="basic-commands"></a>
### 基础命令
```bash
gdb ./binary
run                      # Run program
start                    # Run to main
b *0x401234              # Breakpoint at address
b *main+0x100            # Relative breakpoint
c                        # Continue
si                       # Step instruction
ni                       # Next instruction (skip calls)
x/s $rsi                 # Examine string
x/20x $rsp               # Examine stack
info registers           # Show registers
set $eax=0               # Modify register
```

<a id="pie-binary-debugging"></a>
### PIE 二进制调试
```bash
gdb ./binary
start                    # Forces PIE base resolution
b *main+0xca            # Relative to main
b *main+0x198
run
```

<a id="one-liner-automation"></a>
### 单行命令自动化
```bash
gdb -ex 'start' -ex 'b *main+0x198' -ex 'run' ./binary
```

<a id="memory-examination"></a>
### 内存查看
```bash
x/s $rsi                 # String at RSI
x/38c $rsi               # 38 characters
x/20x $rsp               # 20 hex words from stack
x/10i $rip               # 10 instructions from RIP
```

---

<a id="radare2"></a>
## Radare2

<a id="basic-session"></a>
### 基础会话
```bash
r2 -d ./binary           # Open in debug mode
aaa                      # Analyze all
afl                      # List functions
pdf @ main               # Disassemble main
db 0x401234              # Set breakpoint
dc                       # Continue
ood                      # Restart debugging
dr                       # Show registers
dr eax=0                 # Modify register
```

<a id="r2pipe-automation"></a>
### r2pipe 自动化
```python
import r2pipe

r2 = r2pipe.open('./binary')        # add flags=['-d'] to open in debug mode
r2.cmd('aaa')
funcs = r2.cmdj('aflj') or []       # cmdj returns {} or None on failure, check it
for f in funcs:
    print(f"{f['addr']:#x}  {f['name']}")
r2.quit()
```

**关键点：** 纯静态分析时打开句柄不要加 `flags=['-d']` —— 一次 `cmdj('aflj')` 就能返回所有已分析函数；`cmdj` 失败时返回 `{}` 或 `None` 而不是抛异常，所以索引之前先做检查。

更深入的内容见 [radare2-r2pipe.md](radare2-r2pipe.md)：[用 r2ghidra 原地反编译](radare2-r2pipe.md#用-r2ghidra-就地反编译)、[用 ESIL 模拟单个函数](radare2-r2pipe.md#用-esil-模拟单个函数)、[批处理模式下用 wx 打字节补丁](radare2-r2pipe.md#在批处理模式下用-wx-打字节补丁)。

---

<a id="ghidra"></a>
## Ghidra

<a id="headless-analysis"></a>
### 无头分析
```bash
analyzeHeadless /path/to/project tmp -import binary -postScript script.py
```

<a id="emulator-for-decryption"></a>
### 用模拟器解密
```java
EmulatorHelper emu = new EmulatorHelper(currentProgram);
emu.writeRegister("RSP", 0x2fff0000);
emu.writeRegister("RBP", 0x2fff0000);

// Write encrypted data
emu.writeMemory(dataAddress, encryptedBytes);

// Set function arguments
emu.writeRegister("RDI", arg1);

// Run until return
emu.setBreakpoint(returnAddress);
emu.run(functionEntryAddress);

// Read result
byte[] decrypted = emu.readMemory(outputAddress, length);
```

<a id="mcp-commands"></a>
### MCP 命令
- 侦察：`list_functions`、`list_imports`、`list_strings`
- 分析：`decompile_function`、`get_xrefs_to`
- 标注：`rename_function`、`rename_variable`

---

<a id="unicorn-emulation"></a>
## Unicorn 模拟执行

<a id="basic-setup"></a>
### 基础配置
```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)

# Map code segment
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, code_bytes)

# Map stack
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)

# Run
mu.emu_start(start_addr, end_addr)
```

<a id="mixed-mode-64-to-32-switch"></a>
### 混合模式（64 位切 32 位）
```python
# When a 64-bit stub jumps into 32-bit code via retf/retfq:
# - retf pops 4-byte EIP + 2-byte CS (6 bytes)
# - retfq pops 8-byte RIP + 8-byte CS (16 bytes)

uc32 = Uc(UC_ARCH_X86, UC_MODE_32)
# Copy memory regions, then GPRs
reg_map = {
    UC_X86_REG_EAX: UC_X86_REG_RAX,
    UC_X86_REG_EBX: UC_X86_REG_RBX,
    UC_X86_REG_ECX: UC_X86_REG_RCX,
    UC_X86_REG_EDX: UC_X86_REG_RDX,
    UC_X86_REG_ESI: UC_X86_REG_RSI,
    UC_X86_REG_EDI: UC_X86_REG_RDI,
    UC_X86_REG_EBP: UC_X86_REG_RBP,
}
for e, r in reg_map.items():
    uc32.reg_write(e, mu.reg_read(r) & 0xffffffff)  # mu = 64-bit emulator from above
uc32.reg_write(UC_X86_REG_EFLAGS, mu.reg_read(UC_X86_REG_RFLAGS) & 0xffffffff)

# SSE-heavy blobs need XMM registers copied
for xr in [UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
           UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7]:
    uc32.reg_write(xr, mu.reg_read(xr))

# Run 32-bit, then copy regs/memory back to 64-bit
```

**提示：** 设置 `UC_IGNORE_REG_BREAK=1` 可屏蔽未实现寄存器产生的警告。

<a id="register-tracing-hook"></a>
### 寄存器追踪 Hook
```python
def hook_code(uc, address, size, user_data):
    if address == TARGET_ADDR:
        rsi = uc.reg_read(UC_X86_REG_RSI)
        print(f"0x{address:x}: rsi=0x{rsi:016x}")

mu.hook_add(UC_HOOK_CODE, hook_code)
```

<a id="track-register-changes"></a>
### 追踪寄存器变化
```python
prev_rsi = [None]
def hook_rsi_changes(uc, address, size, user_data):
    rsi = uc.reg_read(UC_X86_REG_RSI)
    if rsi != prev_rsi[0]:
        print(f"0x{address:x}: RSI changed to 0x{rsi:016x}")
        prev_rsi[0] = rsi

mu.hook_add(UC_HOOK_CODE, hook_rsi_changes)
```

---

<a id="python-bytecode"></a>
## Python 字节码

<a id="disassembly"></a>
### 反汇编
```python
import marshal, dis

with open('file.pyc', 'rb') as f:
    f.read(16)  # Skip header (varies by Python version)
    code = marshal.load(f)
    dis.dis(code)
```

<a id="extract-constants"></a>
### 提取常量
```python
for ins in dis.get_instructions(code):
    if ins.opname == 'LOAD_CONST':
        print(ins.argval)
```

<a id="pyarmor-static-unpack-1shot"></a>
### Pyarmor 静态脱壳（1shot）

仓库：`https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot`

```bash
# Basic usage (recursive processing)
python /path/to/oneshot/shot.py /path/to/scripts

# Specify pyarmor runtime library explicitly
python /path/to/oneshot/shot.py /path/to/scripts -r /path/to/pyarmor_runtime.so

# Save outputs to another directory
python /path/to/oneshot/shot.py /path/to/scripts -o /path/to/output
```

注意事项：
- 运行 `shot.py` 前必须先存在 `oneshot/pyarmor-1shot`。
- 支持范围：Pyarmor 8.x-9.x（`PY` + 六位数字头格式）。
- Pyarmor 7 及更早（`PYARMOR` 头）不在支持范围内。
- 反汇编输出总体可靠；反编译源码属于实验性质。

---

<a id="wasm-analysis"></a>
## WASM 分析

<a id="decompile-to-c"></a>
### 反编译成 C
```bash
wasm2c checker.wasm -o checker.c
gcc -O3 checker.c wasm-rt-impl.c -o checker
```

<a id="common-patterns"></a>
### 常见模式
- `w2c_memory` —— 线性内存数组
- `wasm_rt_trap(N)` —— 运行时错误
- 导出函数：`flagChecker`、`validate`

---

<a id="android-apk"></a>
## Android APK

<a id="extraction"></a>
### 提取
```bash
apktool d app.apk -o decoded/   # Best - decodes XML
jadx app.apk                     # Decompile to Java
unzip app.apk -d extracted/      # Simple extraction
```

<a id="key-locations"></a>
### 关键位置
- `res/values/strings.xml` —— 字符串资源
- `AndroidManifest.xml` —— 应用元数据
- `classes.dex` —— Dalvik 字节码
- `assets/`、`res/raw/` —— 资源文件

<a id="search"></a>
### 搜索
```bash
grep -r "flag\|CTF" decoded/
strings decoded/classes*.dex | grep -i flag
```

<a id="flutter-apk-blutter"></a>
### Flutter APK（Blutter）

```bash
# Run Blutter on arm64 build
python3 blutter.py path/to/app/lib/arm64-v8a out_dir
```

<a id="harmonyos-hapabc-abc-decompiler"></a>
### HarmonyOS HAP/ABC（abc-decompiler）

仓库：`https://github.com/ohos-decompiler/abc-decompiler`

```bash
# Extract .hap first to obtain .abc files
unzip app.hap -d hap_extracted/
```

关键启动模式：
```bash
# Use CLI entrypoint (avoid java -jar GUI mode)
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI [options] <input>
```

```bash
# Basic decompile
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -d "out" ".abc"

# Recommended for .abc
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple --log-level ERROR -d "out_abc_simple" ".abc"
```

注意事项：
- 先用 `-m simple --log-level ERROR`。
- 如果 `auto` 失败，先改用 `-m simple` 重试。
- 报错不总意味着完全失败；检查 `out_xxx/sources/`。
- 每次运行使用全新的输出目录。

---

<a id="net-analysis"></a>
## .NET 分析

<a id="tools"></a>
### 工具
- **dnSpy** —— 调试 + 反编译（最佳）
- **ILSpy** —— 反编译器
- **dotPeek** —— JetBrains 反编译器

<a id="nativeaot"></a>
### NativeAOT
- 寻找 `System.Private.CoreLib` 字符串
- 类型元数据仍在但结构被重排
- 搜索带长度前缀的 UTF-16 模式

<a id="two-stage-xor--aes-cbc-decode-pattern-codegate-2013"></a>
### 两阶段 XOR + AES-CBC 解码模式 (Codegate 2013)

**模式：** .NET 二进制中保存着一个加密字节数组，先做 XOR 解码、再做 AES-256-CBC 解密。同一个密钥值同时用作 AES 的 Key 和 IV。

**步骤：**
1. 从二进制中提取硬编码的字节数组和密钥字符串（dnSpy/ILSpy）
2. 对每个字节做 XOR（可能是多轮，例如先 `0x25` 再 `0x58`，等价于单次 `0x7D`）
3. 对 XOR 结果做 Base64 解码
4. 用 `RijndaelManaged` 做 AES-256-CBC 解密，提取出的密钥同时作为 Key 和 IV

```python
from Crypto.Cipher import AES
from base64 import b64decode

# Step 1: XOR decode
data = bytearray(encrypted_bytes)
for i in range(len(data)):
    data[i] ^= 0x7D  # Combined XOR key (0x25 ^ 0x58)

# Step 2: Base64 decode
ct = b64decode(bytes(data))

# Step 3: AES-256-CBC decrypt (same value for key and IV)
key = b"9e2ea73295c7201c5ccd044477228527"  # Padded to 32 bytes
cipher = AES.new(key, AES.MODE_CBC, iv=key)
plaintext = cipher.decrypt(ct)
```

**关键点：** .NET 反编译中出现 `RijndaelManaged` 时，要检查 Key 和 IV 是否被设为同一个值 —— 这是 CTF 中的常见套路。XOR 阶段通常只是真正加密之前的一层简单混淆。

---

<a id="packed-binaries"></a>
## 加壳二进制

<a id="upx"></a>
### UPX
```bash
upx -d packed -o unpacked
strings binary | grep UPX     # Check for UPX signature
```

<a id="custom-packers"></a>
### 自定义壳
1. 在脱壳 stub 之后下断点
2. dump 内存
3. 修复 PE/ELF 头部

<a id="pyinstaller"></a>
### PyInstaller
```bash
python pyinstxtractor.py binary.exe
# Look in: binary.exe_extracted/
```

---

<a id="llvm-ir"></a>
## LLVM IR

<a id="convert-to-assembly"></a>
### 转换为汇编
```bash
llc task.ll --x86-asm-syntax=intel
gcc -c task.s -o file.o
```

---

<a id="risc-v-binary-analysis-ehax-2026"></a>
## RISC-V 二进制分析 (EHAX 2026)

**模式（iguessbro）：** 静态链接、已 strip 的 RISC-V ELF 二进制，无法在 x86 上原生运行。

**用 Capstone 反汇编：**
```python
from capstone import *

with open('binary', 'rb') as f:
    code = f.read()

# RISC-V 64-bit with compressed instruction support
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC | CS_MODE_RISCV64)
md.detail = True

# Disassemble from entry point (check ELF header for e_entry)
TEXT_OFFSET = 0x10000  # typical for static RISC-V
for insn in md.disasm(code[TEXT_OFFSET:], TEXT_OFFSET):
    print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
```

**常见 RISC-V 模式：**
- `li a0, N` → 加载立即数（参数设置）
- `mv a0, s0` → 寄存器移动
- `call offset` → 函数调用（auipc + jalr 对）
- `beq/bne a0, zero, label` → 条件分支
- `sd/ld` → 64 位存储/加载
- `addiw` → 32 位加法（W 后缀 = 字操作）

**与 x86 的关键差异：**
- 没有标志寄存器 —— 比较内联在分支指令中
- 参数在 a0-a7（不是 rdi/rsi/rdx）
- 返回值在 a0
- 保存寄存器 s0-s11（被调用者保存）
- 压缩指令（2 字节）与标准指令（4 字节）混排 —— 需用 `CS_MODE_RISCVC`

**RISC-V 中的反逆向手法：**
- 用字符串常量做假 flag（检查 `"n0t_th3_r34l"` 之类的模式）
- 时序反爆破（rdtime 指令）
- 递增密钥的 XOR 解密：`decrypted[i] = enc[i] ^ (key & 0xFF) ^ 0xA5; key += 7`

**模拟执行：** `qemu-riscv64 -L /usr/riscv64-linux-gnu/ ./binary`（需要交叉工具链的 sysroot）

---

<a id="binary-ninja"></a>
## Binary Ninja

交互式反汇编/反编译器，社区增长迅速。

**反编译输出：** HLIL（High-Level Intermediate Language）、伪 C、伪 Rust、伪 Python。

```bash
# Open binary
binaryninja binary
```

```python
# Headless analysis (Python API)
import binaryninja
bv = binaryninja.open_view("binary")
for func in bv.functions:
    print(func.name, hex(func.start))
    print(func.hlil)  # High-Level IL
```

**社区插件：** 通过 Plugin Manager 安装（Ctrl+Shift+P → "Plugin Manager"）。

**免费版：** https://binary.ninja/free/（云端，功能受限）。

**相对 Ghidra 的优势：** 启动更快、IL 表示更清晰、脚本化的 Python API 更好用。

---

<a id="decompiler-comparison-with-dogboltorg"></a>
## 用 dogbolt.org 对比反编译器

**dogbolt.org** 会对同一个二进制同时运行多个反编译器，并并排展示结果。

**支持的反编译器：** Hex-Rays (IDA)、Ghidra、Binary Ninja、angr、RetDec、Snowman、dewolf、Reko、Relyze。

**适用场景：**
- 反编译输出难以理解 —— 与替代结果对比以求清晰
- 某个反编译器处理不了某个构造 —— 另一个可能处理正确
- 不想在本地安装所有工具时做快速初筛
- 通过交叉比对输出验证反编译器正确性

```bash
# Upload via web interface: https://dogbolt.org/
# Or use the API:
curl -F "file=@binary" https://dogbolt.org/api/binaries/
```

**关键点：** 不同反编译器擅长不同的代码构造。当一个输出不可读时，另一个往往能生成更清晰的伪代码，交叉比对还能发现反编译器的 bug。

---

<a id="useful-commands"></a>
## 常用命令

```bash
# File info
file binary
checksec --file=binary
rabin2 -I binary

# String extraction
strings binary | grep -iE "flag|secret"
rabin2 -z binary

# Sections
readelf -S binary
objdump -h binary

# Symbols
nm binary
readelf -s binary

# Disassembly
objdump -d binary
objdump -M intel -d binary
```

---

<a id="boolector-smt2-for-custom-hash-reversal-otw-advent-2018"></a>
## 用 boolector SMT2 反推自定义哈希 (OTW Advent 2018)

**模式：** 由位运算构成的自定义哈希函数适合交给 SMT 求解器。对于这类实例，boolector 的 QF_BV（位向量）逻辑明显比 Z3 更快。把哈希直接翻译成 SMT2，断言输出，求解输入。

```smt
(set-logic QF_BV)
(declare-fun input () (_ BitVec 64))
(assert (bvuge input #x0000000020202020))   ; printable lower bound
(assert (bvule input #x000000007e7e7e7e))   ; printable upper bound

; Emit the hash function as bvxor/bvrol/bvadd chains
(define-fun hash ((x (_ BitVec 64))) (_ BitVec 64) ...)
(assert (= (hash input) #xdeadbeefcafef00d))
(check-sat) (get-model)
```

```bash
boolector -m --output-format=smt2 hash.smt2
```

**关键点：** Z3 是默认选择，但对于位级哈希题，boolector 常常快 10-100 倍。从 IDA/r2 把每个基本块提升为 `bvxor`/`bvrol`/`bvadd` 并输出 SMT2，让求解器去找原像。

**参考：** OverTheWire Advent 2018 — Jackinthebox，writeup 12789
