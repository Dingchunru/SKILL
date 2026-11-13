# CTF Reverse - 模式与技巧

## 目录
- [自定义 VM 逆向](#自定义-vm-逆向)
  - [分析步骤](#分析步骤)
  - [常见 VM 模式](#常见-vm-模式)
  - [基于 RVA 的 opcode 分派](#基于-rva-的-opcode-分派)
  - [状态机 VM（9 万+ 状态）](#状态机-vm9-万-状态)
  - [通过模糊测试与指令集发现逆向自定义 VM (hxp CTF 2017)](#通过模糊测试与指令集发现逆向自定义-vm-hxp-ctf-2017)
- [反调试技巧](#反调试技巧)
  - [常见检查](#常见检查)
  - [绕过方法](#绕过方法)
  - [LD_PRELOAD Hook](#ld_preload-hook)
  - [pwntools 二进制打补丁（Crypto-Cat）](#pwntools-二进制打补丁crypto-cat)
- [Nanomites](#nanomites)
  - [Linux（基于信号）](#linux基于信号)
  - [Windows（调试事件）](#windows调试事件)
  - [分析](#分析)
- [自修改代码](#自修改代码)
  - [模式：XOR 解密](#模式xor-解密)
- [已知明文 XOR（flag 前缀）](#已知明文-xorflag-前缀)
  - [变体：XOR 位置下标](#变体xor-位置下标)
- [混合模式（x86-64 / x86）Stager](#混合模式x86-64--x86stager)
- [LLVM 混淆（控制流平坦化）](#llvm-混淆控制流平坦化)
  - [模式](#模式)
  - [反混淆](#反混淆)
- [S 盒 / 密钥流生成](#s-盒--密钥流生成)
  - [Fisher-Yates 洗牌（Xorshift32）](#fisher-yates-洗牌xorshift32)
  - [Xorshift64* 密钥流](#xorshift64-密钥流)
  - [识别模式](#识别模式)
- [SECCOMP/BPF 过滤器分析](#seccompbpf-过滤器分析)
  - [BPF 分析](#bpf-分析)
- [异常处理器混淆](#异常处理器混淆)
  - [RtlInstallFunctionTableCallback](#rtlinstallfunctiontablecallback)
  - [向量化异常处理器（VEH）](#向量化异常处理器veh)
- [内存 dump 分析](#内存-dump-分析)
  - [二进制自转储内存的情形](#二进制自转储内存的情形)
  - [已知明文攻击](#已知明文攻击)
- [逐字节一致的变换](#逐字节一致的变换)
- [x86-64 易错点](#x86-64-易错点)
  - [符号扩展](#符号扩展)
  - [循环边界处的状态更新](#循环边界处的状态更新)
- [自定义 mangle 函数逆向](#自定义-mangle-函数逆向)
- [基于位置的变换逆向](#基于位置的变换逆向)
- [十六进制编码字符串比较](#十六进制编码字符串比较)
- [基于信号的二进制探索](#基于信号的二进制探索)

关于恶意软件打补丁、多阶段 shellcode 加载器、时序/信号 oracle，以及 CTF 专用的运行时攻击（INT3 coredump oracle、信号处理器链、printf 格式串 VM、四叉树图像格式），见 [patterns-runtime.md](patterns-runtime.md)。

---

<a id="custom-vm-reversing"></a>
## 自定义 VM 逆向

<a id="analysis-steps"></a>
### 分析步骤
1. 识别 VM 结构：寄存器、内存、指令指针
2. 逆向 `executeIns`/`runvm` 函数，弄清各 opcode 的含义
3. 编写反汇编器解析字节码
4. 对反汇编结果做反编译，理解算法

<a id="common-vm-patterns"></a>
### 常见 VM 模式
```c
switch (opcode) {
    case 1: *R[op1] *= op2; break;      // MUL
    case 2: *R[op1] -= op2; break;      // SUB
    case 3: *R[op1] = ~*R[op1]; break;  // NOT
    case 4: *R[op1] ^= mem[op2]; break; // XOR
    case 5: *R[op1] = *R[op2]; break;   // MOV
    case 7: if (R0) IP += op1; break;   // JNZ
    case 8: putc(R0); break;            // PRINT
    case 10: R0 = getc(); break;        // INPUT
}
```

<a id="rva-based-opcode-dispatching"></a>
### 基于 RVA 的 opcode 分派
- opcode 是指向 handler 函数的 RVA
- handler 执行操作、读取下一个 RVA、然后跳转
- 沿 RVA 链遍历即可映射出所有 handler

<a id="state-machine-vms-90k-states"></a>
### 状态机 VM（9 万+ 状态）
```java
// BFS for valid path
var agenda = new ArrayDeque<State>();
agenda.add(new State(0, ""));
while (!agenda.isEmpty()) {
    var current = agenda.remove();
    if (current.path.length() == TARGET_LENGTH) {
        println(current.path);
        continue;
    }
    for (var transition : machine.get(current.state).entrySet()) {
        agenda.add(new State(transition.getValue(),
                            current.path + (char)transition.getKey()));
    }
}
```

**关键点：** 当题目把一个字节码数据块和一个分派循环一起给出时，基本就是自定义 VM。先把 opcode 跳转表逆向清楚，再写反汇编器提升字节码，最后才去理解算法。

<a id="custom-vm-reverse-engineering-via-fuzzing-and-instruction-set-discovery-hxp-ctf-2017"></a>
### 通过模糊测试与指令集发现逆向自定义 VM (hxp CTF 2017)

当对分派循环做静态分析过于复杂时，可以用系统的黑盒方法来逆向未知 VM 字节码：

**第 1 步：确定指令对齐方式。**
把字节码按不同位宽（6-11 位）导出为位串，找出指令的对齐方式。寻找暗示 opcode 边界的重复模式。

**第 2 步：用随机字节模糊测试。**
发送单条指令并观察寄存器/内存的变化来映射 opcode。削减到最小程序：找出能产生每种可观测效果的最短输入。

**第 3 步：建立指令集。**
发现的 ISA 示例（变长 6-11 位）：
```text
000 xxxxxxxx  jmpz    001 xxxxxxxx  jmp     010 xxxxxxxx  call
011 xxxxxxxx  label   1000 xxxxxxx  loadram  1001 xxxxxxx  saveram
110 xxxxxxxx  loadi   11100 xxxxxx  shl      11101 xxxxxx  shr
111100 not    111101 and    111110 or    111111 setif
```

**第 4 步：编写汇编器/反汇编器。**
为发现的 ISA 编写汇编与反汇编工具，然后反汇编题目字节码以理解其算法。

**第 5 步：实现缺失的原语。**
如果该 ISA 缺少预期操作，就用可用指令合成。例如：仅用 AND/OR/NOT（没有原生 XOR 或 ADD）实现 XTEA 解密：
```python
# XOR from AND/OR/NOT:  XOR(a, b) = (a OR b) AND NOT(a AND b)
# ADD via full-adder chains using AND/OR/NOT for carry propagation
def xor_from_primitives(a, b):
    return (a | b) & ~(a & b)

def add_from_primitives(a, b, bits=32):
    carry = 0
    result = 0
    for i in range(bits):
        ai = (a >> i) & 1
        bi = (b >> i) & 1
        sum_bit = xor_from_primitives(xor_from_primitives(ai, bi), carry)
        carry = (ai & bi) | (carry & xor_from_primitives(ai, bi))
        result |= (sum_bit << i)
    return result
```

**关键点：** 当对 VM 分派循环的静态分析过于复杂时，黑盒模糊测试能更快地映射出 ISA。发送单条指令并观察状态变化。变长指令集需要测试多个位宽。一旦 ISA 已知，即使只有最少的原语（AND/OR/NOT），也能实现复杂算法（如 XTEA）。

**参考：** hxp CTF 2017

---

<a id="anti-debugging-techniques"></a>
## 反调试技巧

<a id="common-checks"></a>
### 常见检查
- `IsDebuggerPresent()`（Windows）
- `ptrace(PTRACE_TRACEME)`（Linux）
- `/proc/self/status` 中的 TracerPid
- 时序检查（`rdtsc`、`time()`）
- 注册表检查（Windows）

<a id="bypass-technique"></a>
### 绕过方法
1. 找到调试检查之后的 `test` 指令
2. 在 `test` 处下断点
3. 修改寄存器以绕过条件判断

```bash
# In radare2
db 0x401234          # Break at test
dc                   # Run
dr eax=0             # Clear flag
dc                   # Continue
```

<a id="ld_preload-hook"></a>
### LD_PRELOAD Hook
```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/ptrace.h>

long int ptrace(enum __ptrace_request req, ...) {
    long int (*orig)(enum __ptrace_request, pid_t, void*, void*);
    orig = dlsym(RTLD_NEXT, "ptrace");
    // Log or modify behavior
    return orig(req, pid, addr, data);
}
```

编译：`gcc -shared -fPIC -ldl hook.c -o hook.so`
运行：`LD_PRELOAD=./hook.so ./binary`

**关键点：** 反调试检查是大多数逆向题的第一道障碍。在 `main()` 靠前的位置寻找 `ptrace`、`IsDebuggerPresent` 或时序检查，先打补丁或 hook 掉它们，再做深入分析。

<a id="pwntools-binary-patching-crypto-cat"></a>
### pwntools 二进制打补丁（Crypto-Cat）
直接用 pwntools 把反调试调用替换成 `ret` 指令：
```python
from pwn import *

elf = ELF('./challenge', checksec=False)
elf.asm(elf.symbols.ptrace, 'ret')   # Replace ptrace() with immediate return
elf.save('patched')                   # Save patched binary
```

其他常见补丁：
```python
elf.asm(addr, 'nop')                  # NOP out an instruction
elf.asm(addr, 'xor eax, eax; ret')    # Return 0 (bypass checks)
elf.asm(addr, 'mov eax, 1; ret')      # Return 1 (force success)
```

---

<a id="nanomites"></a>
## Nanomites

<a id="linux-signal-based"></a>
### Linux（基于信号）
- `SIGTRAP`（`int 3`）→ 自定义操作
- `SIGILL`（`ud2`）→ 自定义操作
- `SIGFPE`（`idiv 0`）→ 自定义操作
- `SIGSEGV`（空指针解引用）→ 自定义操作

<a id="windows-debug-events"></a>
### Windows（调试事件）
- `EXCEPTION_DEBUG_EVENT` → 主处理器
- 父进程通过 `PTRACE_POKETEXT` 修改子进程
- 魔术标记：`0x1337BABE`、`0xDEADC0DE`

<a id="analysis"></a>
### 分析
1. 检查是否存在 `fork()` + `ptrace(PTRACE_TRACEME)`
2. 找到 `WaitForDebugEvent` 循环
3. 把 EAX 的取值映射到具体操作
4. 记录操作序列以重建算法

**关键点：** Nanomite 把真正的计算藏在只有在调试器父进程下才会触发的信号/异常处理器里。如果二进制 fork 之后子进程调用 `ptrace(TRACEME)`，那么父进程才是真正的 CPU —— 记录它的 POKE 操作即可重建算法。

---

<a id="self-modifying-code"></a>
## 自修改代码

<a id="pattern-xor-decryption"></a>
### 模式：XOR 解密
```asm
lea     rax, next_block
mov     dl, [rcx]        ; Input char
xor_loop:
    xor     [rax+rbx], dl
    inc     rbx
    cmp     rbx, BLOCK_SIZE
    jnz     xor_loop
jmp     rax              ; Execute decrypted
```

**解法：** 数据块起始处的已知 opcode 能反推出 XOR 密钥（flag 字符）。

**关键点：** 自修改代码用每个输入字符作为密钥解密下一个代码块。每个解密块开头的已知合法 opcode（例如函数序言）能反推出正确的密钥字节，从而逐字符恢复 flag。

---

<a id="known-plaintext-xor-flag-prefix"></a>
## 已知明文 XOR（flag 前缀）

**模式：** 给定密文字节，且已知 flag 格式（例如 `0xL4ugh{`）。

**方法：**
1. 假设使用循环重复的 XOR 密钥。
2. 用已知前缀（以及任何提示短语）恢复密钥字节。
3. 遍历较小的密钥长度，并校验输出是否全为可打印字符。

```python
enc = bytes.fromhex("...")  # ciphertext
known = b"0xL4ugh{say_yes_to_me"
for klen in range(2, 33):
    key = bytearray(klen)
    ok = True
    for i, b in enumerate(known):
        if i >= len(enc):
            break
        ki = i % klen
        v = enc[i] ^ b
        if key[ki] != 0 and key[ki] != v:
            ok = False
            break
        key[ki] = v
    if not ok:
        continue
    pt = bytes(enc[i] ^ key[i % klen] for i in range(len(enc)))
    if all(32 <= c < 127 for c in pt):
        print(klen, key, pt)
```

**注：** 题目提示常常原样出现在 flag 正文里（例如 "say_yes_to_me"）。

<a id="variant-xor-with-position-index"></a>
### 变体：XOR 位置下标
**模式：** `cipher[i] = plain[i] ^ key[i % k] ^ i`（或 `^ (i & 0xff)`）。

**症状：**
- 循环密钥 XOR 大致能对上已知前缀，但后面的位置开始出错
- 用已知前缀求出的"密钥"每前进一个下标就变化 +1

**修正：** 先去掉下标 XOR，再用已知前缀恢复密钥。
```python
enc = bytes.fromhex("...")
known = b"0xL4ugh{say_yes_to_me"
for klen in range(2, 33):
    key = bytearray(klen)
    ok = True
    for i, b in enumerate(known):
        if i >= len(enc):
            break
        ki = i % klen
        v = (enc[i] ^ i) ^ b  # strip index XOR
        if key[ki] != 0 and key[ki] != v:
            ok = False
            break
        key[ki] = v
    if not ok:
        continue
    pt = bytes((enc[i] ^ i) ^ key[i % klen] for i in range(len(enc)))
    if all(32 <= c < 127 for c in pt):
        print(klen, key, pt)
```

---

<a id="mixed-mode-x86-64--x86-stagers"></a>
## 混合模式（x86-64 / x86）Stager

**模式：** 64 位 ELF 通过远返回（`retf`/`retfq`）跳入 32 位代码块，通常发生在反调试之后。

**识别：**
- 字节 `0xCB`（retf）或 `0xCA`（retf imm16），有时前面还有 `0x48`（retfq）
- 32 位反汇编显示紧凑循环中的 SSE 指令（`psubb`、`pxor`、`paddb`）
- 存在计算跳转进入 32 位区域

**易错点：**
- `retf` 弹出**6 个字节**：4 字节 EIP + 2 字节 CS（不是 8 字节）
- 32 位代码块可能依赖继承来的 **XMM 状态**与 **EFLAGS**
- 切换模拟器时若未传递 XMM/标志位，输出会出错

**绕过/模拟要点：**
1. 建立 UC_MODE_32 模拟器，复制内存 + 通用寄存器、**EFLAGS** 以及 **XMM 寄存器**
2. 运行 32 位代码块，再把内存 + 寄存器复制回 64 位环境
3. 如果反调试用 `fork/ptrace` + 代码补丁，就模拟父进程记录 POKE 并在子进程中施加

---

<a id="llvm-low-level-virtual-machine-obfuscation-control-flow-flattening"></a>
## LLVM 混淆（控制流平坦化）

<a id="pattern"></a>
### 模式
```c
while (1) {
    if (i == 0xA57D3848) { /* block */ }
    if (i != 0xA5AA2438) break;
    i = 0x39ABA8E6;  // Next state
}
```

<a id="de-obfuscation"></a>
### 反混淆
1. 编写 GDB 脚本在 `je` 指令处下断点
2. 记录状态变量的取值
3. 映射状态转移
4. 重建真实的控制流

**关键点：** 控制流平坦化把结构化的 if/else/循环替换为单一的分派 switch。状态变量是关键 —— 运行时追踪它的取值即可重建原始控制流图，无需与混淆做静态缠斗。

---

<a id="s-box--keystream-generation"></a>
## S 盒 / 密钥流生成

<a id="fisher-yates-shuffle-xorshift32"></a>
### Fisher-Yates 洗牌（Xorshift32）
```python
def gen_sbox():
    sbox = list(range(256))
    state = SEED
    for i in range(255, -1, -1):
        state = ((state << 13) ^ state) & 0xffffffff
        state = ((state >> 17) ^ state) & 0xffffffff
        state = ((state << 5) ^ state) & 0xffffffff
        j = state % (i + 1) if i > 0 else 0
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox
```

<a id="xorshift64-keystream"></a>
### Xorshift64* 密钥流
```python
def gen_keystream():
    ks = []
    state = SEED_64
    mul = 0x2545f4914f6cdd1d
    for _ in range(256):
        state ^= (state >> 12)
        state ^= (state << 25)
        state ^= (state >> 27)
        state = (state * mul) & 0xffffffffffffffff
        ks.append((state >> 56) & 0xff)
    return ks
```

<a id="identifying-patterns"></a>
### 识别模式
- Xorshift32：移位 13、17、5（没有乘法常量）
- Xorshift64*：移位 12、25、27，然后乘以 `0x2545f4914f6cdd1d`
- 另一个常见常量：`0x9e3779b97f4a7c15`（黄金分割比例）

**关键点：** 通过 Fisher-Yates 洗牌模式（从 255 往下计数、与 PRNG 选出的下标交换）识别 S 盒生成，通过 xorshift 常量识别密钥流生成器。一旦确定 PRNG 家族，算法就完全由其种子确定。

---

<a id="seccompbpf-filter-analysis"></a>
## SECCOMP/BPF 过滤器分析

```bash
seccomp-tools dump ./binary
```

<a id="bpf-analysis"></a>
### BPF 分析
- `A = sys_number` 后跟各种比较
- 内存操作为 `mem[N] = A`、`A = mem[N]`
- 映射成约束方程后用 z3 求解

```python
from z3 import *
flag = [BitVec(f'c{i}', 32) for i in range(14)]
s = Solver()
s.add(flag[0] >= 0x20, flag[0] < 0x7f)
# Add constraints from filter
if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[c].as_long()) for c in flag))
```

**关键点：** SECCOMP（安全计算模式）过滤器把 flag 校验编码为作用于系统调用参数的 BPF 字节码。用 `seccomp-tools` 导出过滤器，把比较与内存操作翻译成 z3 约束，就能在完全不运行二进制的情况下求出 flag。

---

<a id="exception-handler-obfuscation"></a>
## 异常处理器混淆

<a id="rtlinstallfunctiontablecallback"></a>
### RtlInstallFunctionTableCallback
- 动态注册异常处理器
- 处理器会安装新的处理器、修改代码
- 使用 x64dbg 并对异常处理器下断点

<a id="vectored-exception-handlers-veh"></a>
### 向量化异常处理器（VEH）
- `AddVectoredExceptionHandler` 安装处理器
- 处理器在异常地址处解密代码
- 单步跟踪，导出解密后的代码

**关键点：** 基于异常处理器的混淆把真实控制流藏在由故意触发异常而调用的 SEH/VEH 处理器里。断点应下在异常处理器内部而不是触发异常的指令上，才能跟随真正的执行路径。

---

<a id="memory-dump-analysis"></a>
## 内存 dump 分析

<a id="when-binary-dumps-memory"></a>
### 二进制自转储内存的情形
- 检查是否读取 `/proc/self/maps`
- 检查是否读取 `/proc/self/mem`
- 堆数据常常被追加到 dump 中

<a id="known-plaintext-attack"></a>
### 已知明文攻击
```python
prologue = bytes([0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5])
encrypted = data[func_offset:func_offset+8]
partial_key = bytes(a ^ b for a, b in zip(encrypted, prologue))
```

**关键点：** 当二进制读取 `/proc/self/mem` 或 `/proc/self/maps` 时，它是在转储自身内存 —— 可能是在加密之后进行的。用已知的函数序言（`endbr64; push rbp; mov rbp, rsp`）作为已知明文，即可从加密后的 dump 中恢复 XOR 密钥。

---

<a id="byte-wise-uniform-transforms"></a>
## 逐字节一致的变换

**模式：** 输出缓冲区中每个字节仅独立依赖对应的输入字节（字节之间没有耦合）。

**检测：**
- 改变一个输入位置 → 只有一个输出位置变化
- 输入端全部填入同一个字节 → 输出缓冲区变成常量

**求解：**
1. 对 0..255 的每个字节值，用该字节重复填充输入运行程序
2. 记录输出字节 → 构建正向与逆向映射
3. 把逆向映射作用于静态目标字节，恢复 flag

---

<a id="x86-64-gotchas"></a>
## x86-64 易错点

<a id="sign-extension"></a>
### 符号扩展
```python
esi = 0xffffffc7  # NOT -57

# For XOR: low byte only
esi_xor = esi & 0xff  # 0xc7

# For addition: full 32-bit with overflow
r12 = (r13 + esi) & 0xffffffff
```

<a id="loop-boundary-state-updates"></a>
### 循环边界处的状态更新
汇编常常把状态更新拆到循环边界两侧：
```asm
    jmp loop_middle        ; First iteration in middle!

loop_top:                   ; State for iterations 2+
    mov  r13, sbox[a & 0xf]
    ; Uses OLD 'a', not new!

loop_middle:
    ; Main computation
    inc  a
    jne  loop_top
```

**关键点：** 反编译器经常在 x86-64 符号扩展和循环边界状态更新上出错。对于涉及 `movsx`/`cdqe` 的运算，务必拿反编译结果与原始汇编核对；并确认循环变量是在使用之前还是之后更新的。

---

<a id="custom-mangle-function-reversing"></a>
## 自定义 mangle 函数逆向

**模式（Flag Appraisal）：** 二进制每次用中间状态处理 2 个输入字节，再与静态目标比较。

**方法：**
1. 从 `.rodata` 段提取静态目标字节
2. 理解 mangle 逻辑：按字节对处理，并携带滚动状态
3. 编写逆函数（逆序处理，逐步撤销每个操作）
4. 把目标字节输入逆函数 → 恢复 flag

**关键点：** 当二进制带滚动状态逐对处理输入并与静态目标比较时，从 `.rodata` 提取目标值并写出逆函数即可。按逆序处理目标字节、逐步撤销每个操作，就能恢复原始输入。

---

<a id="position-based-transformation-reversing"></a>
## 基于位置的变换逆向

**模式（PascalCTF 2026）：** 二进制对输入加上或减去位置下标。

**逆向：**
```python
expected = [...]  # Extract from .rodata
flag = ''
for i, b in enumerate(expected):
    if i % 2 == 0:
        flag += chr(b - i)   # Even: input = output - i
    else:
        flag += chr(b + i)   # Odd: input = output + i
```

---

<a id="hex-encoded-string-comparison"></a>
## 十六进制编码字符串比较

**模式（Spider's Curse）：** 输入被转换为十六进制，再与十六进制常量比较。

**快速解法：** 从 strings/Ghidra 中提取十六进制常量并解码：
```bash
echo "4d65746143..." | xxd -r -p
```

---

<a id="signal-based-binary-exploration"></a>
## 基于信号的二进制探索

**模式（Signal Signal Little Star）：** 二进制把 UNIX 信号用作二叉树导航机制。

**识别：**
- 多处带 `SA_SIGINFO` 的 `sigaction()` 调用
- `sigaltstack()` 设置（备用信号栈）
- 处理器解码内嵌载荷，并安装下一对信号
- 两种类型：Node（安装子节点）与 Leaf（打印消息后退出）

**求解思路：**
1. 通过 `LD_PRELOAD` hook `sigaction`，记录信号安装情况
2. 发送信号，对二叉树做 DFS
3. 每一步观察安装了哪两个信号
4. 发送其中一个，检查程序是退出（叶子）还是再安装两个（节点）
5. 如果走错叶子，就回溯并尝试兄弟分支

```c
// LD_PRELOAD interposer to log sigaction calls
int sigaction(int signum, const struct sigaction *act, ...) {
    if (act && (act->sa_flags & SA_SIGINFO))
        log("SET %d SA_SIGINFO=1\n", signum);
    return real_sigaction(signum, act, oldact);
}
```

恶意软件打补丁、多阶段 shellcode、时序/信号 oracle 以及 CTF 题解技巧见 [patterns-runtime.md](patterns-runtime.md)。
