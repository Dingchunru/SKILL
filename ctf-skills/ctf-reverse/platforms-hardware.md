# CTF Reverse - 硬件与高级架构逆向

HD44780 LCD GPIO 重建、RISC-V 高级扩展与调试、ARM64/AArch64 逆向与利用。

## 目录
- [HD44780 LCD 控制器 GPIO 重建 (32C3 2015)](#hd44780-lcd-控制器-gpio-重建-32c3-2015)
- [RISC-V（进阶）](#risc-v进阶)
  - [自定义扩展](#自定义扩展)
  - [特权模式](#特权模式)
  - [RISC-V 调试](#risc-v-调试)
- [ARM64/AArch64 逆向与利用](#arm64aarch64-逆向与利用)
- [MIPS64 Cavium OCTEON 协处理器 2 加密引擎 (SEC-T CTF 2017)](#mips64-cavium-octeon-协处理器-2-加密引擎-sec-t-ctf-2017)
- [EFM32 ARM 单片机 MMIO AES (SEC-T CTF 2017)](#efm32-arm-单片机-mmio-aes-sec-t-ctf-2017)
- [MBR/引导加载器逆向：QEMU + GDB (Square CTF 2017)](#mbr引导加载器逆向qemu--gdb-square-ctf-2017)
- [Game Boy ROM Z80 分析：bgb 调试器 (Square CTF 2017)](#game-boy-rom-z80-分析bgb-调试器-square-ctf-2017)
- [KVM Guest 分析：ioctl + KVM_EXIT_HLT 基本块链 (CSAW 2018)](#kvm-guest-分析ioctl--kvm_exit_hlt-基本块链-csaw-2018)
- [Coreboot ROM XOR 常量对翻位定位地址 (Hack.lu 2018)](#coreboot-rom-xor-常量对翻位定位地址-hacklu-2018)

---

<a id="hd44780-lcd-controller-gpio-reconstruction-32c3-2015"></a>
## HD44780 LCD 控制器 GPIO 重建 (32C3 2015)

从原始 Raspberry Pi GPIO 录制数据中恢复 HD44780 LCD 上显示的文字：

1. **识别信号线：** 把 GPIO 引脚映射到 HD44780 信号（4 位模式下为 RS、CLK、D4-D7）
2. **时钟边沿检测：** 在时钟下降沿（1->0 跳变）采样数据线
3. **拼接半字节：** 把两次 4 位采样合并成一个 8 位命令/数据字节
4. **DRAM 地址映射：** HD44780 多行显示的地址并不连续：
   - 第 0 行：0x00-0x27
   - 第 1 行：0x40-0x67
   - 第 2 行：0x14-0x3B
   - 第 3 行：0x54-0x7B

```python
display = [' '] * 80  # 4 lines x 20 chars
cursor = 0

for timestamp, gpio_state in sorted(gpio_log):
    if falling_edge(gpio_state, CLK_PIN):
        nibble = extract_data_bits(gpio_state)
        byte = assemble_nibble(nibble)  # Two nibbles per byte
        if rs_high(gpio_state):  # RS=1: data write
            display[dram_to_position(cursor)] = chr(byte)
            cursor += 1
        else:  # RS=0: command (set cursor, clear, etc.)
            cursor = parse_command(byte)
```

**关键点：** GPIO 引脚到信号的映射很少被记载；通过找出跳变次数最多的引脚来识别 CLK，通过和数据模式的关联来识别 RS（命令/数据阶段交替出现）。

---

<a id="risc-v-advanced"></a>
## RISC-V（进阶）

超出基础反汇编的范围（见 [tools.md](tools.md#risc-v-二进制分析-ehax-2026)）：

<a id="custom-extensions"></a>
### 自定义扩展

```text
Bitmanip extensions (Zbb, Zbc, Zbs):
  clz, ctz, cpop         -> count leading/trailing zeros, popcount
  orc.b, rev8            -> byte-level bit manipulation
  andn, orn, xnor        -> negated logic operations
  clmul, clmulh, clmulr  -> carry-less multiplication (crypto)
  bset, bclr, binv, bext -> single-bit operations

Crypto extensions (Zk*):
  aes32esi, aes32dsmi     -> AES round operations
  sha256sig0, sha512sum0  -> SHA hash acceleration
  sm3p0, sm4ed            -> Chinese crypto standards
```

<a id="privileged-modes"></a>
### 特权模式

```text
Machine mode (M):  Highest privilege, firmware/bootloader
Supervisor mode (S): OS kernel
User mode (U):      Applications

CSR registers to watch:
  mstatus/sstatus    -> privilege level, interrupt enable
  mtvec/stvec       -> trap handler address
  mepc/sepc         -> exception return address
  mcause/scause     -> trap cause
  satp              -> page table root (virtual memory)
```

<a id="risc-v-debugging"></a>
### RISC-V 调试

```bash
# OpenOCD + GDB for hardware debugging
openocd -f interface/jlink.cfg -f target/riscv.cfg

# GDB for RISC-V
riscv64-unknown-elf-gdb binary
(gdb) target remote :3333

# QEMU with GDB server
qemu-riscv64 -g 1234 -L /usr/riscv64-linux-gnu/ ./binary
riscv64-linux-gnu-gdb -ex 'target remote :1234' ./binary
```

---

<a id="arm64aarch64-reversing-and-exploitation"></a>
## ARM64/AArch64 逆向与利用

AArch64（ARM 64 位）出现在移动应用、云服务器（AWS Graviton）、Apple Silicon 以及 CTF 题目中。它与 x86-64 的关键差异会同时影响逆向与利用。

**环境准备与模拟执行：**

```bash
# Install cross-toolchain and emulator
apt install gcc-aarch64-linux-gnu gdb-multiarch qemu-user-static

# Run AArch64 binary on x86 host
qemu-aarch64-static -L /usr/aarch64-linux-gnu/ ./arm64_binary

# Debug with GDB
qemu-aarch64-static -g 12345 -L /usr/aarch64-linux-gnu/ ./arm64_binary &
gdb-multiarch -ex 'set arch aarch64' -ex 'target remote :1234' ./arm64_binary

# With library preloading (for challenges that ship libc)
qemu-aarch64-static -g 12345 -E LD_PRELOAD=./libc.so.6 -L ./lib ./arm64_binary
```

**AArch64 调用约定（与 x86-64 的关键差异）：**

```text
Registers:
  x0-x7    -- function arguments AND return values (x0 = first arg / return)
  x8       -- indirect result location (struct returns)
  x9-x15   -- caller-saved temporaries
  x19-x28  -- callee-saved (preserved across calls)
  x29 (fp) -- frame pointer
  x30 (lr) -- link register (return address, NOT on stack by default)
  sp       -- stack pointer (must be 16-byte aligned)
  xzr      -- zero register (reads as 0, writes discarded)

Key exploitation differences:
  - Return address in LR (x30), not on stack -- pushed only if function calls others
  - No RIP-relative addressing like x86 -- uses ADRP+ADD pairs for PC-relative loads
  - Fixed 4-byte instruction width -- no variable-length gadget tricks
  - NOP = 0xD503201F (not 0x90)
  - BLR x8 / BR x30 -- indirect calls/jumps use register operands
```

**Ghidra/IDA 中常见的 AArch64 模式：**

```text
# PC-relative address loading (equivalent to x86 LEA):
ADRP  x0, #0x411000      ; Load page address (4KB aligned)
ADD   x0, x0, #0x8       ; Add page offset -> x0 = 0x411008

# Function prologue:
STP   x29, x30, [sp, #-0x30]!  ; Push fp + lr, decrement sp
MOV   x29, sp                   ; Set frame pointer

# Function epilogue:
LDP   x29, x30, [sp], #0x30    ; Pop fp + lr, increment sp
RET                              ; Branch to x30 (lr)

# Switch/jump table:
ADR   x1, jump_table
LDRB  w2, [x1, x0]       ; Load offset byte
ADD   x1, x1, w2, SXTB   ; Sign-extend and add
BR    x1                   ; Indirect branch
```

**AArch64 上的 ROP：**

```python
from pwn import *

# AArch64 gadgets differ from x86:
# - "pop {x0}; ret" equivalent: LDP x0, x1, [sp], #0x10; RET
# - Prologue gadgets: LDP x29, x30, [sp, #0x20]; ... RET
# - system() call: x0 = pointer to "/bin/sh", BLR to system

context.arch = 'aarch64'
elf = ELF('./arm64_binary')

# Common gadget pattern in AArch64 libc:
# LDP X19, X20, [SP,#var_s10]
# LDP X29, X30, [SP+var_s0],#0x20
# RET
# Controls x19, x20, x29, x30 and advances sp by 0x20
```

**关键点：** AArch64 的固定指令宽度和基于寄存器的返回地址（`lr`/`x30`）使 ROP gadget 比 x86 更加受限。要寻找 `LDP`（成对加载）这一类从栈上弹出多个寄存器的 gadget。函数序言/尾声中的 `STP`/`LDP` 指令对（用于保存/恢复被调用者保存寄存器）是 gadget 的主要来源。

**识别时机：** `file` 输出 "ELF 64-bit LSB ... ARM aarch64"。Ghidra 能自动识别，但对于裸二进制可能需要手动选择处理器。在 x86 宿主机上用 `qemu-aarch64-static` 进行模拟。

**工具：** radare2（`r2 -AA -a arm -b 64`）、Ghidra（自动识别）、`aarch64-linux-gnu-objdump -d`、Unicorn Engine（`UC_ARCH_ARM64`）

**参考：** Google CTF 2016 "Forced Puns"、Insomni'hack 2018 "onecall"

---

<a id="mips64-cavium-octeon-coprocessor-2-crypto-sec-t-ctf-2017"></a>
## MIPS64 Cavium OCTEON 协处理器 2 加密引擎 (SEC-T CTF 2017)

Cavium OCTEON 网络处理器通过 MIPS 协处理器 2（CP2）的 `dmtc2`（写入 CP2）和 `dmfc2`（从 CP2 读出）指令实现硬件 AES 与 SHA256。这些指令在反汇编器看来只是普通的寄存器移动，实际上却在驱动硬件加密引擎。

**OCTEON 关键 CP2 寄存器布局：**
```text
AES key registers:
  0x0104 – AES key quadword 0
  0x0105 – AES key quadword 1
  0x0106 – AES key quadword 2
  0x0107 – AES key quadword 3

SHA256 hash registers:
  0x400E–0x4012 – SHA256 intermediate hash words
  0x404F        – SHA256 control/result

dmtc2  rN, 0x0104   ; load 64 bits of AES key into CP2 register 0x104
dmtc2  rN, 0x0105   ; ...next quadword
```

**分析步骤：**
1. 在 IDA/Ghidra 中反汇编 —— 出现选择子位于 0x100-0x40FF 范围内的 `dmtc2`/`dmfc2` 即表明使用了 OCTEON CP2
2. 对照 Cavium OCTEON 硬件参考手册查阅寄存器语义
3. 追踪密钥加载序列，恢复 AES 或 HMAC 的密钥材料

**关键点：** MIPS 上的硬件加密加速器表现为 CP2 寄存器写入（`dmtc2`/`dmfc2`）。识别出基址寄存器后，对照厂商文档即可还原其含义。

**参考：** SEC-T CTF 2017

---

<a id="efm32-arm-microcontroller-mmio-aes-sec-t-ctf-2017"></a>
## EFM32 ARM 单片机 MMIO AES (SEC-T CTF 2017)

Silicon Labs EFM32 Cortex-M 二进制 —— 一个加载到 0x1000 的平坦二进制，运行于 Thumb 模式。

**IDA 配置：**
```text
Processor: ARM Little-endian (ARMv7-M)
Load address: 0x1000
Set T register = 1 (force Thumb mode decoding)
```

**AES 加速器 MMIO 布局（EFM32 AES 外设基址 0x400E0000）：**
```text
0x400E0000 + 0x000  CTRL   – enable, decrypt mode
0x400E0000 + 0x004  CMD    – start/stop
0x400E0000 + 0x010  KEYLA  – key low word 0
0x400E0000 + 0x014  KEYLB  – key low word 1
0x400E0000 + 0x018  KEYLC  – key low word 2
0x400E0000 + 0x01C  KEYLD  – key low word 3
```

该二进制加载两个独立的值，将它们异或后再作为 AES 密钥写入。用组合出的密钥在 ECB 模式下解密内嵌的密文块。

```python
from Crypto.Cipher import AES

key_part_a = bytes.fromhex("...")  # extracted from IDA .data section
key_part_b = bytes.fromhex("...")  # second value
key = bytes(a ^ b for a, b in zip(key_part_a, key_part_b))

cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
```

**关键点：** 单片机上的硬件 AES 加速器表现为特定基址上的 MMIO 寄存器写入 —— 对照厂商参考手册（Silicon Labs 外设的 EFM32 Reference Manual）即可还原。

**参考：** SEC-T CTF 2017

---

<a id="mbrbootloader-reversing-with-qemu--gdb-square-ctf-2017"></a>
## MBR/引导加载器逆向：QEMU + GDB (Square CTF 2017)

在 QEMU 中启动软盘/磁盘镜像并开启 GDB stub，然后用 GDB 附加，即可对 16 位实模式或 32 位保护模式下的引导加载器代码进行完整的源码级调试。

```bash
# Boot with GDB stub on port 1234; -S pauses execution at start
qemu-system-x86_64 -fda disk.img -s -S

# In another terminal, attach GDB
gdb -ex "set architecture i8086" \
    -ex "target remote :1234" \
    -ex "break *0x7c00" \
    -ex "continue"

# Common MBR entry point is 0x7c00 (BIOS loads MBR here)
# Step through bootloader, inspect registers and memory:
(gdb) x/20i $pc
(gdb) info registers
(gdb) x/16xb 0x7c00
```

要绕过口令校验：找到比较之后的那个条件跳转，在镜像文件中将其 NOP 掉，或修改比较指令使其永远成功。

```bash
# Find the comparison offset in the image and patch it
python3 -c "
data = open('disk.img', 'rb').read()
# Replace JNZ (0x75) with JMP-short-always or NOP
data = data[:offset] + b'\x90\x90' + data[offset+2:]
open('disk_patched.img', 'wb').write(data)
"
```

**关键点：** QEMU 的 `-s` 参数会在 1234 端口暴露一个 GDB stub，从而可以对 MBR/引导加载器代码进行完整调试 —— 流程与用户态调试完全一致。

**参考：** Square CTF 2017

---

<a id="game-boy-rom-z80-analysis-in-bgb-debugger-square-ctf-2017"></a>
## Game Boy ROM Z80 分析：bgb 调试器 (Square CTF 2017)

Game Boy ROM 使用 Sharp SM83（LR35902）CPU，它是 Z80/8080 的混合体。用 **bgb** 模拟器加载 ROM，它提供类似 GDB 的调试功能：断点、内存查看和寄存器显示。

**比较标志位时值得关注的关键指令：**
```asm
LD   A, [HL]    ; load byte from memory pointed to by HL into A
AND  [HL]       ; A = A & *HL  — compares player byte against memory value
CP   N          ; compare A with immediate N (sets Z flag if equal)
```

当输入校验过程中执行到 `and (hl)` 或 `cp (hl)` 时，期望的字节在内存窗口中的 `(hl)` 地址处直接可见。

**bgb 工作流：**
1. 加载 ROM：File → Open ROM
2. 在反汇编视图中右键 → "Run to cursor"，或按 F2 设置断点
3. 比较发生时，查看 Registers 面板（HL 的值）与 Memory 面板（`*HL`）
4. 记录期望值，然后前进到下一个比较位置

**关键点：** Game Boy ROM 是 Z80/SM83 架构。bgb 调试器提供类似 GDB 的功能；关键比较使用 `(hl)` 间接寻址，因此在比较时内存视图中能直接看到期望值。

**参考：** Square CTF 2017

---

<a id="kvm-guest-analysis-via-ioctl--kvm_exit_hlt-block-chaining-csaw-2018"></a>
## KVM Guest 分析：ioctl + KVM_EXIT_HLT 基本块链 (CSAW 2018)

**模式：** 一个用户态进程承载着基于 KVM 的虚拟机，其 guest "程序" 只是一串以 `HLT` 结尾的代码块。宿主处理器读取 `KVM_EXIT_HLT`，检查 guest 寄存器，并通过在 `0x2020A0` 处的跳转表中查找 `rax` 来分派到下一个代码块。完成对整个程序的逆向需要：(1) 用 `strace -v` 运行二进制以捕获 `KVM_GET_REGS`/`KVM_SET_REGS` 成对调用，(2) 从 KVM 内存区域中导出每个代码块，(3) 根据宿主以 rax 为索引的表重建分派图。

```bash
# 1. Observe KVM ioctls + register snapshots
strace -v -e ioctl ./challenge 2>&1 | grep -E "KVM_RUN|KVM_(GET|SET)_REGS"

# 2. Dump guest code memory (offset + size from KVM_SET_USER_MEMORY_REGION ioctl)
gdb -batch -ex "attach $(pgrep challenge)" \
    -ex "dump binary memory guest.bin 0x400000 0x410000" \
    -ex "detach"

# 3. Disassemble each HLT-terminated block
objdump -D -b binary -m i386:x86-64 guest.bin | less
```

```python
# Rebuild the dispatch graph
import struct
with open("challenge", "rb") as f:
    data = f.read()
# Host table at 0x2020A0 maps rax → next block offset
table = struct.unpack_from("<128Q", data, 0x2020A0)
for rax, ptr in enumerate(table):
    if ptr:
        print(f"rax={rax:02x} → block {ptr:#x}")
```

**关键点：** 基于 KVM 的题目将控制流藏在宿主进程中，而不是 guest 中。guest 代码本身只是一堆不透明的代码块。对 KVM ioctl 执行 `strace` 可以替代调试器：每次 `KVM_EXIT_HLT` 都是一个"基本块边界"，而宿主的响应就是真正的转移函数。任何时候见到链接了 `-lkvm` 或打开 `/dev/kvm` 的 CTF 二进制，就应当放弃常规逆向流程，转而从 ioctl trace 入手。

**参考：** CSAW CTF Qualification Round 2018 — kvm，writeup 11206

---

<a id="coreboot-rom-xor-pair-bit-flip-address-discovery-hacklu-2018"></a>
## Coreboot ROM XOR 常量对翻位定位地址 (Hack.lu 2018)

**模式：** 固件镜像在启动时通过把 ROM 中的两个常量异或来计算 flag 所在地址。挑战服务允许攻击者在 ROM 中任意位置翻转一个比特位，并观察新的 flag 地址。计算出预期地址 `X = C1 ^ C2`，与对外公布的地址比较，则相差的那一位 —— 在设计良好的题目中恰好多一位 —— 就告诉你哪一对 ROM 字节+比特控制着重定向。

```python
# Two constants in ROM
C1 = 0xEF56BF92
C2 = 0xEF5A3F92
intended = C1 ^ C2          # 0xC8000 per the source
actual   = 0xC0000          # where the flag really lives in memory

diff = intended ^ actual    # 0x08000 → bit 15
# Find the ROM offset that, when a single bit is flipped, produces `actual`.
# The flip must land in either C1 or C2 so the XOR result has bit 15 cleared.
```

**关键点：** 两个 ROM 常量的异或是一个线性操作：任一对操作数中单比特的翻转都会把对应比特异或进结果。在计算出的地址与观测到的地址之间逐位比较汉明距离，就能得到一个有界的候选补丁位置列表 —— 通常只有一两个。固件中的地址对非常可疑：它们经常会通过 XOR、ADD 或 SUB 组合起来，而每一种算术关系都是定向单比特翻转攻击的候选。该技巧同样适用于 rowhammer：敏感比特是两个常量之间的*差分*，而不是常量本身。

**参考：** Hack.lu CTF 2018 — 1-bit-missile，writeups 11862、11865
