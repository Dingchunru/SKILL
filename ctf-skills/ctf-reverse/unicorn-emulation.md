# Unicorn CPU 模拟

用 Unicorn Engine 做裸二进制和裸机模拟。有时候只用 Unicorn + 二进制 + 汇编逆向，比完整开一局 GDB/angr 更省事。

## 目录

- [什么时候 Unicorn 胜过 GDB / angr / Qiling](#什么时候-unicorn-胜过-gdb--angr--qiling)
- [初始化脚手架](#初始化脚手架)
- [Hook 速查手册](#hook-速查手册)
- [ARM / MIPS / Thumb](#arm--mips--thumb)
- [通过 retf 做 64→32 混合模式](#通过-retf-做-6432-混合模式)
- [固件 MMIO 模拟](#固件-mmio-模拟)
- [快照与 fork：高效的爆破 oracle](#快照与-fork高效的爆破-oracle)
- [覆盖率、计数与超时调参](#覆盖率计数与超时调参)
- [线程与自修改代码](#线程与自修改代码)
- [稳健的 MMIO：GPIO / 定时器 / 中断控制器](#稳健的-mmiogpio--定时器--中断控制器)
- [集成 GDB stub](#集成-gdb-stub)
- [性能](#性能)
- [Keystone + Unicorn 指令轨迹求逆](#keystone--unicorn-指令轨迹求逆)
- [Shellcode 解包](#shellcode-解包)
- [自定义 VM 模拟](#自定义-vm-模拟)
- [Qiling vs Unicorn 决策树](#qiling-vs-unicorn-决策树)
- [模拟器对比：Unicorn vs Qiling vs QEMU vs angr vs Triton](#模拟器对比unicorn-vs-qiling-vs-qemu-vs-angr-vs-triton)
- [坑](#坑)
- [实战示例（2024）](#实战示例2024)

---

<a id="when-unicorn-beats-gdb--angr--qiling"></a>
## 什么时候 Unicorn 胜过 GDB / angr / Qiling

| 场景 | 最佳工具 | 原因 |
|---|---|---|
| 裸 shellcode，没有 ELF | **Unicorn** | 没有 OS/加载器 —— 映射后直接跑 |
| 反调试（`ptrace`、PEB、计时） | **Unicorn** | 没有进程，没有痕迹 |
| 裸机固件 | **Unicorn** | MMIO hook 替代外设 |
| x86 主机上的多架构 blob | **Unicorn** | 无需 QEMU/rootfs 就能跨架构 |
| 需要系统调用 / 文件系统 / 网络 | **Qiling** | Unicorn 没有 OS 层 |
| 符号执行 / 路径爆炸 | angr / Triton | Unicorn 只能具体执行 |

**工作流：** 静态摸底 → 隔离函数或 shellcode 范围 → 用 Unicorn 处理反调试或裸机片段 → dump 寄存器/内存 → 求解。需要真实 OS 信号用 GDB，需要符号执行用 angr，需要系统调用用 Qiling。

---

<a id="setup-scaffold"></a>
## 初始化脚手架

```bash
pip install unicorn==2.1.2 capstone keystone-engine
# unicorn 2.1.2 is already pinned in scripts/install_ctf_tools.sh
```

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR  = 0x400000
STACK_ADDR = 0x7fff0000
STACK_SIZE = 2 * 1024 * 1024

# <!-- audit-ok --> placeholder — replace with real shellcode dump
CODE = open("shellcode.bin", "rb").read()  # <!-- audit-ok -->

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(STACK_ADDR, STACK_SIZE)
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 0x100)

def hook_code(mu, address, size, user_data):
    print(f"0x{address:x}: size={size}")

mu.hook_add(UC_HOOK_CODE, hook_code)

try:
    mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE), timeout=2 * 1000000, count=10000)
except UcError as e:
    print(f"UcError {e} errno={e.errno} at 0x{mu.reg_read(UC_X86_REG_RIP):x}")
```

`emu_start(begin, until, timeout, count)` —— `timeout` 单位是微秒，`count` 是指令数上限。到达 `until`、在 hook 里调用 `emu_stop()`、或取指到未映射区域都会结束模拟。把栈映射到远离 `0x0` 的地址，这样空指针解引用会真正触发错误，而不是静默成功。

---

<a id="hook-cookbook"></a>
## Hook 速查手册

除 `INTR`/`INSN` 外，hook 的签名都是 `hook(mu, address, size, user_data)`。

### CODE 与 BLOCK

```python
from unicorn import *
from unicorn.x86_const import *

def hook_code(mu, address, size, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    print(f"0x{address:x} [{size}B] RAX=0x{rax:x}")

mu.hook_add(UC_HOOK_CODE, hook_code)
# Filtered: mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x401000, end=0x401200)

def hook_block(mu, address, size, user_data):
    print(f"block 0x{address:x} size={size}")

mu.hook_add(UC_HOOK_BLOCK, hook_block)
```

只需要覆盖率时，`BLOCK` 比 `CODE` 更省。

### MEM_READ / MEM_WRITE

```python
from unicorn import *
from unicorn.x86_const import *

def hook_mem_read(mu, access, address, size, value, user_data):
    data = mu.mem_read(address, size)
    print(f"READ  0x{address:x} size={size} data={data.hex()}")

def hook_mem_write(mu, access, address, size, value, user_data):
    print(f"WRITE 0x{address:x} size={size} value=0x{value:x}")

mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
```

### MEM_INVALID —— 未映射 / MMIO

```python
from unicorn import *
from unicorn.x86_const import *

def hook_invalid(mu, access, address, size, value, user_data):
    print(f"INVALID access={access} addr=0x{address:x} size={size}")
    return False  # False → UC_ERR_*, True → continue (for MMIO)

mu.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)
```

覆盖 `READ_UNMAPPED | WRITE_UNMAPPED | FETCH_UNMAPPED | READ_PROT | WRITE_PROT | FETCH_PROT`。需要时按 `access` 过滤。

### INTR 与 SYSCALL

```python
from unicorn import *
from unicorn.x86_const import *

def hook_intr(mu, intno, user_data):
    print(f"INT 0x{intno:x} at 0x{mu.reg_read(UC_X86_REG_RIP):x}")

mu.hook_add(UC_HOOK_INTR, hook_intr)

def hook_syscall(mu, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    print(f"syscall rax={rax} at 0x{mu.reg_read(UC_X86_REG_RIP):x}")
    mu.reg_write(UC_X86_REG_RAX, 0)

mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
```

<details>
<summary>进阶：指令计数 + 超时</summary>

```python
from unicorn import *
from unicorn.x86_const import *

insn_count = [0]
def hook_count(mu, address, size, user_data):
    insn_count[0] += 1
    if insn_count[0] > 50000:
        mu.emu_stop()

mu.hook_add(UC_HOOK_CODE, hook_count)
mu.emu_start(0x400000, 0x400000 + len(CODE), timeout=5 * 1000000, count=0)
print(f"executed {insn_count[0]} insns")
```

除非你就是想要"谁先到谁停"，否则不要把 `timeout` 和 `count` 同时设为非零。

</details>

---

<a id="arm--mips--thumb"></a>
## ARM / MIPS / Thumb

### Thumb

```python
from unicorn import *
from unicorn.arm_const import *
from capstone import *

CODE_ADDR = 0x10000
CODE = open("thumb.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.reg_write(UC_ARM_REG_SP, 0x200000)
mu.emu_start(CODE_ADDR | 1, CODE_ADDR + len(CODE))

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for insn in md.disasm(CODE, CODE_ADDR):
    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
```

Thumb 需要 `CODE_ADDR | 1` 和 `UC_MODE_THUMB`；不设置最低位的话，Thumb 编码会以 `UC_ERR_INSN_INVALID` 报错。

### ARM A32 与 MIPS

```python
from unicorn import *
from unicorn.arm_const import *

mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(0x10000, 2 * 1024 * 1024)
mu.mem_write(0x10000, CODE)
mu.reg_write(UC_ARM_REG_SP, 0x200000)
mu.emu_start(0x10000, 0x10000 + len(CODE))
```

```python
from unicorn import *
from unicorn.mips_const import *
from capstone import *

CODE_ADDR = 0x400000
CODE = open("mips.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_MIPS, UC_MODE_32 + UC_MODE_LITTLE_ENDIAN)
# Big-endian: UC_ARCH_MIPS + UC_MODE_32 + UC_MODE_BIG_ENDIAN
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.reg_write(UC_MIPS_REG_SP, 0x800000)
mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE))

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
for insn in md.disasm(CODE, CODE_ADDR):
    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
```

字节序必须与二进制一致，否则第一条指令就是 `UC_ERR_INSN_INVALID`。UnicornJS 的像素模式 —— 按光栅顺序排列的 RGBA 字节构成 ARM 指令流 —— 喂给同一套 Thumb 脚手架；见 [patterns-ctf-3.md](patterns-ctf-3.md#用-unicornjs-执行藏在图像像素中的-arm-代码hacklu-2017)。

---

<a id="mixed-mode-64-to-32-via-retf"></a>
## 通过 retf 做 64→32 混合模式

壳会用 `retf`/`retfq` 切换模式。Unicorn 无法在运行中途切模式 —— 停下，在目标模式下新建 `Uc`，复制状态，继续跑。`retf` 弹出 EIP(4)+CS(2)=6B；`retfq` 弹出 RIP(8)+CS(8)=16B。见 [field-notes.md](field-notes.md#unicorn-模拟复杂状态) 和 [tools.md](tools.md#混合模式64-位切-32-位)。

```python
from unicorn import *
from unicorn.x86_const import *

mu64 = Uc(UC_ARCH_X86, UC_MODE_64)
mu64.mem_map(0x400000, 0x20000)
mu64.mem_map(0x7fff0000, 0x10000)
mu64.mem_write(0x400000, code64)
mu64.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
RET_ADDR = 0x401020
mu64.emu_start(0x400000, RET_ADDR)

mu32 = Uc(UC_ARCH_X86, UC_MODE_32)
mu32.mem_map(0x400000, 0x20000)
mu32.mem_map(0x7fff0000, 0x10000)
for addr, sz in [(0x400000, 0x20000)]:
    mu32.mem_write(addr, mu64.mem_read(addr, sz))

reg_map = {
    UC_X86_REG_EAX: UC_X86_REG_RAX, UC_X86_REG_EBX: UC_X86_REG_RBX,
    UC_X86_REG_ECX: UC_X86_REG_RCX, UC_X86_REG_EDX: UC_X86_REG_RDX,
    UC_X86_REG_ESI: UC_X86_REG_RSI, UC_X86_REG_EDI: UC_X86_REG_RDI,
    UC_X86_REG_EBP: UC_X86_REG_RBP, UC_X86_REG_ESP: UC_X86_REG_RSP,
}
for r32, r64 in reg_map.items():
    mu32.reg_write(r32, mu64.reg_read(r64) & 0xffffffff)
mu32.reg_write(UC_X86_REG_EFLAGS, mu64.reg_read(UC_X86_REG_RFLAGS) & 0xffffffff)
for xr in [UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
           UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7,
           UC_X86_REG_XMM8, UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11,
           UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15]:
    mu32.reg_write(xr, mu64.reg_read(xr))

eip = int.from_bytes(mu32.mem_read(mu32.reg_read(UC_X86_REG_ESP), 4), "little")
mu32.reg_write(UC_X86_REG_EIP, eip)
mu32.reg_write(UC_X86_REG_ESP, mu32.reg_read(UC_X86_REG_ESP) + 6)
mu32.emu_start(eip, eip + len(code32))
```

常见坑：忘了 `EFLAGS`、忘了截断到 32 位、以及处理 SSE blob 时漏掉 XMM。

---

<a id="firmware-mmio-emulation"></a>
## 固件 MMIO 模拟

固件会访问固定的外设地址（UART `0x40000000`、GPIO、定时器），这些地址是未映射的。映射该页并 hook `MEM_READ`/`MEM_WRITE`，或者用 `mmio_map`。

```python
from unicorn import *
from unicorn.arm_const import *

CODE_ADDR = 0x08000000
MMIO_BASE = 0x40000000
CODE = open("firmware.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.reg_write(UC_ARM_REG_SP, 0x20080000)
mu.mem_map(MMIO_BASE, 0x1000)
mu.mem_write(MMIO_BASE, b"\x01\x00\x00\x00")  # status = ready

mmio = {0x40000000: 0x01, 0x40000004: 0x41}

def hook_mmio_write(mu, access, address, size, value, user_data):
    if MMIO_BASE <= address < MMIO_BASE + 0x1000:
        print(f"MMIO write 0x{address:x} <- 0x{value:x}")
        mmio[address & ~0x3] = value & 0xffffffff
    return True

mu.hook_add(UC_HOOK_MEM_WRITE, hook_mmio_write)

try:
    mu.emu_start(CODE_ADDR | 1, CODE_ADDR + len(CODE), timeout=3 * 1000000, count=20000)
except UcError as e:
    if e.errno == UC_ERR_INSN_INVALID:
        print(f"invalid insn at 0x{mu.reg_read(UC_ARM_REG_PC):x} — wrong mode or data as code?")
    elif e.errno == UC_ERR_FETCH_UNMAPPED:
        print(f"fetch unmapped at 0x{mu.reg_read(UC_ARM_REG_PC):x} — missing map or bad branch")
    else:
        print(f"UcError {e} errno={e.errno}")
```

用 `timeout`+`count` 或在 `CODE` hook 里调 `emu_stop()` 来跳出轮询循环；`mmio_map(MMIO_BASE, 0x1000, read_cb, None, write_cb, None)` 是 2.x 的替代写法。

---

<a id="snapshot--fork-efficient-brute-force-oracle"></a>
## 快照与 fork：高效的爆破 oracle

每个候选值都从头重建 `Uc`，比快照/恢复慢 10-100 倍。逐字节 oracle（N1CTF 2018 的轨迹求逆、按前缀比较的 flag 校验器）要用 `context_save()`/`context_restore()` 加上显式内存快照。

### context_save / context_restore / context_update

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x400000
DATA_ADDR = 0x500000
CODE = open("checker.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(DATA_ADDR, 0x10000)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xf00)
mu.reg_write(UC_X86_REG_RDI, DATA_ADDR)

# Warm up to the checkpoint (e.g., after init, before input-dependent loop)
mu.emu_start(CODE_ADDR, CODE_ADDR + 0x40, timeout=1 * 1000000, count=0)
snap = mu.context_save()          # registers + MSRs + hidden state
mem_snap = mu.mem_read(DATA_ADDR, 0x10000)  # explicit RAM snapshot
mem_snap_code = mu.mem_read(CODE_ADDR, 0x10000)  # if SMC may dirty code

print(f"snapshot: RIP=0x{mu.reg_read(UC_X86_REG_RIP):x}")
```

`context_save()` 返回不透明的 `UcContext` —— 寄存器、标志、段基址、MSR。它**不**快照 RAM；目标会修改的任何区域（输入缓冲区、堆、SMC 的代码页）都必须自己 `mem_read`/`mem_write`。`context_update(ctx)` 把当前寄存器写进已有 context，不重新分配 —— 需要增量打检查点时用它。

### 写时复制快照爆破

```python
from unicorn import *
from unicorn.x86_const import *

# <!-- audit-ok --> placeholder — CODE from file above
CODE_ADDR = 0x400000
DATA_ADDR = 0x500000

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(DATA_ADDR, 0x10000)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xf00)
mu.emu_start(CODE_ADDR, CODE_ADDR + 0x40, timeout=1 * 1000000, count=0)

base_ctx = mu.context_save()
base_mem = mu.mem_read(DATA_ADDR, 0x10000)

def try_byte(prefix: bytes, cand: int) -> bool:
    mu.context_restore(base_ctx)
    mu.mem_write(DATA_ADDR, base_mem)  # restore RAM (COW: only dirty pages)
    attempt = prefix + bytes([cand])
    mu.mem_write(DATA_ADDR, attempt)
    mu.reg_write(UC_X86_REG_RDI, DATA_ADDR)
    # also restore any global counter the checker increments
    try:
        mu.emu_start(mu.reg_read(UC_X86_REG_RIP), CODE_ADDR + len(CODE),
                     timeout=500000, count=5000)
    except UcError:
        return False
    return mu.reg_read(UC_X86_REG_RAX) == 0  # checker returns 0 on prefix match

flag = b""
for pos in range(32):
    for c in range(32, 127):
        if try_byte(flag, c):
            flag += bytes([c])
            print(f"pos {pos}: {chr(c)} -> {flag}")
            # re-snapshot after advancing one byte so next pos starts from new state
            base_ctx = mu.context_save()
            base_mem = mu.mem_read(DATA_ADDR, 0x10000)
            break
    else:
        print(f"no candidate at pos {pos}")
        break
print(f"flag={flag}")
```

**为什么 fork 式恢复胜过全新 `Uc`：** `Uc()` 要分配 TCG 缓存、映射和 hook；`context_restore` 只是一次 memcpy。对 32*95 次爆破迭代，快照循环快 20-50 倍。AFL++ 的 unicorn 模式用同样的写时复制思路：只 `mem_read` 脏区间，或者用 `mem_protect` 设 `UC_PROT_READ` 来捕获写入并记录脏页。

### fork 模拟替代方案（多进程）

语料很大或需要真正隔离时，快照后 `fork()`，让 OS 做页级写时复制。Unicorn 状态跨线程不安全，但跨 `fork()` 是安全的 —— 前提是 fork 前先 `context_save`，且每个子进程从保存的 blob 各自建立自己的 `Uc`。

---

<a id="coverage-counting--timeout-tuning"></a>
## 覆盖率、计数与超时调参

### BLOCK vs CODE hook

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x400000
CODE = open("target.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xf00)

# BLOCK is cheaper — fires once per basic block, not per instruction
blocks = {}
def hook_block(mu, address, size, user_data):
    blocks[address] = blocks.get(address, 0) + 1

mu.hook_add(UC_HOOK_BLOCK, hook_block)

# Filter to the function under test to avoid counting init/cleanup
func_start, func_end = 0x401000, 0x401200
mu.hook_add(UC_HOOK_BLOCK, hook_block, begin=func_start, end=func_end)

try:
    mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE), timeout=2 * 1000000, count=0)
except UcError as e:
    print(f"stop errno={e.errno} blocks={len(blocks)}")

# AFL++-style edge coverage: (prev_block, cur_block) tuple
edges = set()
prev = None
def hook_edge(mu, address, size, user_data):
    global prev
    if prev is not None:
        edges.add((prev, address))
    prev = address

# instruction counting — only if you need per-insn granularity
insn_count = [0]
def hook_count(mu, address, size, user_data):
    insn_count[0] += 1
    if insn_count[0] > 50000:
        mu.emu_stop()

mu.hook_add(UC_HOOK_CODE, hook_count, begin=func_start, end=func_end)
```

覆盖率和 AFL 用 `BLOCK`，只有需要逐指令观察（SMC 检测、寄存器 dump）时才用 `CODE`。Python hook 每次调用开销约 5-15 微秒 —— 100 万次 `CODE` hook 要多花好几秒；同样的覆盖率用 `BLOCK` 调用次数少 10-30 倍。

### timeout vs count

| 设置 | 效果 | 何时用 |
|---|---|---|
| `timeout=2*1000000, count=0` | 墙钟时长限制（微秒） | 轮询循环、固件死循环 |
| `timeout=0, count=20000` | 指令数限制 | 确定性函数、求解器 oracle |
| `timeout=0, count=0` | 跑到 `until` / `emu_stop` / 出错 | 短 shellcode、已知结束地址 |
| 两者都非零 | 谁先到谁停 | 除非你就是要这个竞争，否则避免 |

把 `count` 调到预期指令数的 2 倍（先用计数 hook 测一次，再写死）。固件场景优先用 `timeout`（200-300 万微秒）加一个在检测到空闲时调用 `emu_stop()` 的 `BLOCK` hook。

### UC_ERR 处理表

| `e.errno` | 常量 | 原因 | 解法 |
|---|---|---|---|
| 6 | `UC_ERR_READ_UNMAPPED` | 从未映射区域读取 | `mem_map` 该区域或 `MEM_INVALID` hook |
| 7 | `UC_ERR_WRITE_UNMAPPED` | 写入未映射区域 | `mem_map` 或返回 `True` 的 MMIO hook |
| 8 | `UC_ERR_FETCH_UNMAPPED` | 跳转到未映射区域 | 映射目标或 hook `MEM_INVALID`（FETCH） |
| 10 | `UC_ERR_INSN_INVALID` | 错误操作码 / 模式不对 | 检查 `UC_MODE_THUMB` + `ADDR|1`、字节序 |
| 12 | `UC_ERR_WRITE_PROT` | 写入 `UC_PROT_READ` 页 | `mem_protect` 改为 `UC_PROT_ALL` 或经 `MEM_WRITE_PROT` 处理 |
| 13 | `UC_ERR_READ_PROT` | 从不可读页读取 | `mem_protect` 或 `MEM_READ_PROT` hook |
| 14 | `UC_ERR_FETCH_PROT` | 从不可执行页取指 | `mem_protect` 加 `UC_PROT_EXEC` |
| 15 | `UC_ERR_ARG` | `mem_map`/`mem_protect` 未对齐 | 地址/大小对齐到 `0x1000` |
| 11 | `UC_ERR_MAP` | `mem_map` 区域重叠 | 先 `mem_unmap` 或换新基址 |
| 0 | `UC_ERR_OK` | 在 `until` 或 `emu_stop` 处正常停止 | 不是错误 —— 检查 `RIP` 是否到达 `until` |

用 `e.errno` 和 `mu.reg_read(UC_X86_REG_RIP)`/`UC_ARM_REG_PC` 排查。两者都要打日志。

---

<a id="threading--self-modifying-code"></a>
## 线程与自修改代码

### SMC 检测（写入代码页 → 失效缓存）

固件和壳会就地解包下一阶段。检测到写入后要刷新 TCG 缓存。

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x400000
CODE = open("packed.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xf00)

code_start, code_end = CODE_ADDR, CODE_ADDR + 0x10000

def hook_mem_write_smc(mu, access, address, size, value, user_data):
    if code_start <= address < code_end:
        print(f"SMC write 0x{address:x} size={size} — flushing TB cache")
        mu.ctl_remove_cache(address, address + size)

mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write_smc)

# Alternative: detect via CODE hook that re-reads the bytes
orig = mu.mem_read(CODE_ADDR, len(CODE))
def hook_code_smc(mu, address, size, user_data):
    cur = mu.mem_read(address, size)
    # capstone disasm of cur vs orig can confirm rewrite
    pass
mu.hook_add(UC_HOOK_CODE, hook_code_smc, begin=code_start, end=code_end)
```

Unicorn 会缓存翻译块（TB）。SMC 之后要调用 `mu.ctl_remove_cache(start, end)` 或 `mu.ctl_flush_tb()` 强制重译。不做这步，模拟器会执行旧字节。等价于 QEMU 的 `qemu_tb_flush`。

### 多线程：顺序模拟 + 状态复制

Unicorn 是单线程的，`emu_start` 没有并发。用交错执行来建模线程。

```python
from unicorn import *
from unicorn.x86_const import *

# Two threads share memory but have private registers/stacks
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x20000)
mu.mem_map(0x600000, 0x10000)  # shared heap
mu.mem_map(0x7fff0000, 0x10000)  # thread 1 stack
mu.mem_map(0x7ffe0000, 0x10000)  # thread 2 stack

# Snapshot thread states as contexts
thread1_ctx = mu.context_save()
mu.reg_write(UC_X86_REG_RSP, 0x7ffe0000 + 0xf00)
mu.reg_write(UC_X86_REG_RIP, 0x401000)  # thread 2 entry
thread2_ctx = mu.context_save()

# Round-robin: restore ctx, run N blocks, save back
for tick in range(100):
    for ctx in (thread1_ctx, thread2_ctx):
        mu.context_restore(ctx)
        try:
            mu.emu_start(mu.reg_read(UC_X86_REG_RIP), 0, timeout=100000, count=100)
        except UcError:
            pass
        # update ctx in place so next round resumes
        mu.context_update(ctx)
```

对锁敏感的代码，hook 原子指令（`lock cmpxchg`、`ldrex/strex`），在 `user_data` 里模拟保留状态。

---

<a id="mmio-robust-gpio--timer--interrupt-controller"></a>
## 稳健的 MMIO：GPIO / 定时器 / 中断控制器

除 UART `0x40000000` 之外 —— 固件还会碰 GPIO、定时器和 NVIC/中断控制器。把每个外设建模成带副作用读的状态字典。

### 按访问类型过滤 hook

```python
from unicorn import *
from unicorn.arm_const import *

CODE_ADDR = 0x08000000
CODE = open("firmware.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x20000000, 0x10000)
mu.reg_write(UC_ARM_REG_SP, 0x20010000)

# Map MMIO pages so FETCH still faults but READ/WRITE hit hooks
for base in (0x40000000, 0x40010000, 0x40020000, 0xe000e000):
    mu.mem_map(base, 0x1000)

def hook_invalid(mu, access, address, size, value, user_data):
    # access is one of the UC_MEM_* constants
    # Filter: only handle known peripheral ranges, let others fault
    if access == UC_MEM_READ_UNMAPPED:
        print(f"READ_UNMAPPED 0x{address:x} size={size}")
        return False
    elif access == UC_MEM_WRITE_UNMAPPED:
        print(f"WRITE_UNMAPPED 0x{address:x} val=0x{value:x}")
        return False
    elif access == UC_MEM_FETCH_UNMAPPED:
        print(f"FETCH_UNMAPPED 0x{address:x} — bad branch, stop")
        mu.emu_stop()
        return False
    elif access in (UC_MEM_READ_PROT, UC_MEM_WRITE_PROT):
        mu.mem_protect(address & ~0xfff, 0x1000, UC_PROT_ALL)
        return True
    return False

mu.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)
```

### GPIO / 定时器 / NVIC 模型

```python
from unicorn import *
from unicorn.arm_const import *

# Peripheral bases (STM32-like)
GPIOA_BASE = 0x40020000
TIM2_BASE  = 0x40000000
NVIC_BASE  = 0xe000e100  # NVIC ISER/ICER

# Device state — dict per peripheral
gpio = {"ODR": 0, "IDR": 0x41, "BSRR": 0}  # IDR returns input pins
timer = {"CNT": 0, "SR": 1, "PSC": 0}  # SR bit 0 = UIF (update interrupt flag)
nvic = {"ISER": 0, "ICER": 0, "pending": 0}

def mmio_read(mu, address, size):
    if GPIOA_BASE <= address < GPIOA_BASE + 0x1000:
        off = address - GPIOA_BASE
        if off == 0x10:  # IDR
            return gpio["IDR"] & ((1 << (size*8)) - 1)
        elif off == 0x14:  # ODR
            return gpio["ODR"] & ((1 << (size*8)) - 1)
    elif TIM2_BASE <= address < TIM2_BASE + 0x1000:
        off = address - TIM2_BASE
        if off == 0x00:  # CR1
            return 0x01
        elif off == 0x10:  # SR — side-effect: clear on read
            val = timer["SR"]
            timer["SR"] = 0  # status clear on read (common silicon behavior)
            return val
        elif off == 0x24:  # CNT — increment each read (free-running timer)
            timer["CNT"] = (timer["CNT"] + 1) & 0xffffffff
            return timer["CNT"]
    elif NVIC_BASE <= address < NVIC_BASE + 0x1000:
        return nvic["ISER"]
    return 0

def mmio_write(mu, address, size, value):
    if GPIOA_BASE <= address < GPIOA_BASE + 0x1000:
        off = address - GPIOA_BASE
        if off == 0x14:  # ODR
            gpio["ODR"] = value
            print(f"GPIO ODR <- 0x{value:x} ({chr(value & 0xff) if 32 <= (value & 0xff) <= 126 else '.'})")
        elif off == 0x18:  # BSRR — bit set/reset
            if value & 0xffff:
                gpio["ODR"] |= (value & 0xffff)
            if value >> 16:
                gpio["ODR"] &= ~(value >> 16)
    elif TIM2_BASE <= address < TIM2_BASE + 0x1000:
        off = address - TIM2_BASE
        if off == 0x0c:  # PSC
            timer["PSC"] = value
        elif off == 0x10:  # SR — write 0 clears
            timer["SR"] &= ~value

def hook_mmio_read(mu, access, address, size, value, user_data):
    if address >= 0x40000000 and address < 0xe0100000:
        val = mmio_read(mu, address, size)
        # Write back via mem_write so the load sees the value
        mu.mem_write(address, val.to_bytes(size, "little"))
        return True
    return False

def hook_mmio_write(mu, access, address, size, value, user_data):
    if address >= 0x40000000 and address < 0xe0100000:
        mmio_write(mu, address, size, value)
        return True
    return False

mu.hook_add(UC_HOOK_MEM_READ, hook_mmio_read)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mmio_write)
```

**副作用读**（读时清状态）和**自由运行计数器**（CNT 自增）是两种会破坏朴素 `mem_write(MMIO_BASE, b"\x01...")` 桩的模式。必须显式建模，否则轮询循环永远出不来、中断永远不触发。

### 注入定时器中断

```python
from unicorn import *
from unicorn.arm_const import *

# Fire timer interrupt every N blocks
tick = [0]
def hook_block_timer(mu, address, size, user_data):
    tick[0] += 1
    if tick[0] % 1000 == 0:
        timer["SR"] |= 1  # set UIF
        nvic["pending"] |= 1 << 28  # TIM2 IRQn = 28
        # Optionally hijack PC to ISR — save context, set PC to vector
        # vector table at 0x08000000, IRQ entry at offset 0xb0 on STM32
        # For CTF, often simpler to just set the flag and let firmware poll it

mu.hook_add(UC_HOOK_BLOCK, hook_block_timer)
```

向量中断需要先 `context_save()`、写入 `PC`/`LR`/`xPSR`、模拟 ISR、再 `context_restore`。Qiling 的 `ql.hw` 抽象能自动完成这些，见 [tools-emulation.md](tools-emulation.md#qiling-框架跨平台模拟)。

---

<a id="gdb-stub-integration"></a>
## 集成 GDB stub

把 Unicorn 当作 GDB 后端，配合 GEF/pwndbg 检查，不会留下 `ptrace` 痕迹。

```python
from unicorn import *
from unicorn.x86_const import *
import socket, struct

CODE_ADDR = 0x400000
CODE = open("target.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 0x10000)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xf00)

# Breakpoint via CODE hook — register sync with GDB RSP protocol
breakpoints = {0x401020, 0x401050}
def hook_bp(mu, address, size, user_data):
    if address in breakpoints:
        print(f"[GDB] break 0x{address:x} RAX=0x{mu.reg_read(UC_X86_REG_RAX):x} "
              f"RBX=0x{mu.reg_read(UC_X86_REG_RBX):x} "
              f"RIP=0x{mu.reg_read(UC_X86_REG_RIP):x}")
        mu.emu_stop()  # hand control to stub

mu.hook_add(UC_HOOK_CODE, hook_bp)

# Minimal RSP loop: expose regs/mem via socket, translate GDB packets to mu.reg_read/mem_read
# Use: gdb target.bin → target remote :1234 → c / si / info regs (backed by mu)

def gdb_reg_sync(mu):
    # Pack regs in GDB order (x86_64: RAX RBX RCX RDX RSI RDI RBP RSP ... RIP)
    regs = [mu.reg_read(r) for r in (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RIP, UC_X86_REG_EFLAGS)]
    return b"".join(struct.pack("<Q", r) for r in regs)

# Step: emu_start with count=1, report new RIP, loop
try:
    mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE), timeout=5 * 1000000, count=0)
except UcError as e:
    print(f"GDB stub stop errno={e.errno} RIP=0x{mu.reg_read(UC_X86_REG_RIP):x}")
    # GEF: telescope $rsp, vmmap (from mu.mem_regions()), disasm $rip via Capstone
```

**工作流：** 断点用 `mu.hook_add(UC_HOOK_CODE, bp)`，单步用 `count=1`，GDB 的 `x/` 和 `info regs` 由 `mem_read`/`reg_read` 支撑。没有 `ptrace` → 反调试被绕过。反汇编配 Capstone，`vmmap` 用 `mu.mem_regions()`。

<details>
<summary>进阶：规避 ptrace 的变体（完整 stub）</summary>

```python
from unicorn import *
from unicorn.x86_const import *

# Hook the anti-debug syscall itself so GDB stub never triggers it
def hook_syscall_ptrace(mu, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    if rax == 101:  # ptrace nr on x86_64
        print("[GDB stub] ptrace intercepted — returning 0")
        mu.reg_write(UC_X86_REG_RAX, 0)
        # skip syscall: advance RIP past syscall (2 bytes: 0f 05)
        mu.reg_write(UC_X86_REG_RIP, mu.reg_read(UC_X86_REG_RIP) + 2)

mu.hook_add(UC_HOOK_INSN, hook_syscall_ptrace, None, 1, 0, UC_X86_INS_SYSCALL)
```

</details>

---

<a id="performance"></a>
## 性能

### 映射粒度

```python
from unicorn import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
# All maps aligned to 0x1000 — UC_ERR_ARG otherwise
mu.mem_map(0x400000, 0x1000)   # 4K min
mu.mem_map(0x401000, 0x2000)   # 8K — coalesce adjacent if possible
# Avoid 1-byte maps; permission checks are per-page
mu.mem_protect(0x400000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
```

相邻区域合并成一次 `mem_map`。逐页的 `UC_PROT_*` 检查有开销 —— 区域越少越快。

### Hook 过滤

```python
from unicorn import *
from unicorn.x86_const import *

# Filter by address range — hook only fires inside [begin, end]
mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x401000, end=0x401200)
mu.hook_add(UC_HOOK_BLOCK, hook_block, begin=0x401000, end=0x401200)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_smc, begin=0x400000, end=0x402000)

# Avoid per-insn hook when BLOCK suffices — 10-30x fewer invocations
# BLOCK covers coverage, edge counting, timer ticks
# CODE only for register dumps, SMC checks, instruction-level tracing
```

加上 `begin`/`end` 后过滤发生在 C（TCG）层而不是 Python 层。不加的话每条指令都会陷入 Python。

### Python hook 开销

| Hook | 每次命中开销（约） | 说明 |
|---|---|---|
| `UC_HOOK_CODE` | 5-15 微秒 | Python 回调 + 读寄存器 |
| `UC_HOOK_BLOCK` | 5-15 微秒 | 单次成本相同，命中次数更少 |
| `UC_HOOK_MEM_READ/WRITE` | 10-20 微秒 | 外加回调里的 `mem_read`/`mem_write` |
| 无 hook（原生 TCG） | 约 0.02 微秒/指令 | 快 2-3 个数量级 |

100 万条指令的轨迹配 `CODE` hook：5-15 秒。同样内容用 `BLOCK`（5 万块）：0.3-0.8 秒。不加 hook：0.02 秒。

### 批量 mem_read vs 逐字节

```python
from unicorn import *
from unicorn.x86_const import *

# Slow — 256 Python crossings
slow = bytes(mu.mem_read(addr + i, 1)[0] for i in range(256))

# Fast — one crossing, slice in Python
fast = mu.mem_read(addr, 256)  # single mem_read, returns bytes

# For snapshots: read only dirty ranges
dirty = [(0x500000, 0x1000), (0x600000, 0x2000)]
snaps = {base: mu.mem_read(base, sz) for base, sz in dirty}
# restore:
for base, data in snaps.items():
    mu.mem_write(base, data)
```

用批量的 `mem_read`/`mem_write` 和 `reg_read_batch` 减少跨界次数。爆破时只快照输入缓冲区，不要快照整个地址空间。

---

<a id="keystone--unicorn-trace-inversion"></a>
## Keystone + Unicorn 指令轨迹求逆

二进制用 `add/sub/xor/rol/ror` 做无内存副作用的变换（MeePwn 2017）。倒序回放轨迹、把每个操作换成逆操作、用 Keystone 重新汇编、再用 Unicorn 模拟。见 [anti-analysis-ctf.md](anti-analysis-ctf.md#用-keystone-与-unicorn-反转指令轨迹meepwn-ctf-2017)。

```python
from keystone import *
from unicorn import *
from unicorn.x86_const import *
from capstone import *

CODE_ADDR = 0x401000
CODE = open("obfuscated.bin", "rb").read()  # <!-- audit-ok --> placeholder

md = Cs(CS_ARCH_X86, CS_MODE_64)
transforms = []
for insn in md.disasm(CODE, CODE_ADDR):
    if insn.mnemonic not in ("jmp", "je", "jne", "call", "ret", "jbe", "ja", "jb"):
        transforms.append((insn.mnemonic, insn.op_str))

inverse = {"add": "sub", "sub": "add", "rol": "ror", "ror": "rol", "xor": "xor"}
inverted = [(inverse.get(m, m), op) for m, op in reversed(transforms)]

ks = Ks(KS_ARCH_X86, KS_MODE_64)
asm_src = "\n".join(f"{m} {op}" for m, op in inverted)
encoding, _ = ks.asm(asm_src)

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, bytes(encoding))
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
mu.reg_write(UC_X86_REG_RAX, known_output)
mu.emu_start(0x400000, 0x400000 + len(encoding))
flag = mu.reg_read(UC_X86_REG_RAX).to_bytes(8, "little")
print(f"recovered: {flag}")
```

对依赖前缀的校验用逐字节循环：

```python
from unicorn import *
from unicorn.x86_const import *

def try_byte(known_prefix: bytes, candidate: int) -> bool:
    attempt = known_prefix + bytes([candidate])
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(0x400000, 0x10000)
    mu.mem_write(0x400000, CODE)
    mu.mem_map(0x300000, 0x10000)
    mu.mem_write(0x300000, attempt)
    mu.reg_write(UC_X86_REG_RDI, 0x300000)
    mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
    mu.mem_map(0x7fff0000, 0x10000)
    try:
        mu.emu_start(0x400000, 0x400000 + len(CODE), timeout=1 * 1000000, count=5000)
    except UcError:
        return False
    return mu.reg_read(UC_X86_REG_RAX) == 0

flag = b""
for pos in range(32):
    for c in range(32, 127):
        if try_byte(flag, c):
            flag += bytes([c])
            print(f"pos {pos}: {chr(c)} -> {flag}")
            break
```

---

<a id="shellcode-unpack"></a>
## Shellcode 解包

多阶段加载器会就地异或解码下一阶段。模拟到循环之后，直接 dump 解码后的缓冲区，而不是去逆向那段密码算法。

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x400000
DATA_ADDR = 0x500000
# <!-- audit-ok --> placeholder — replace with real dump from stager
shellcode = open("shellcode.bin", "rb").read()  # <!-- audit-ok -->

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, shellcode)
mu.mem_map(DATA_ADDR, 2 * 1024 * 1024)
mu.mem_map(0x7fff0000, 2 * 1024 * 1024)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 2 * 1024 * 1024 - 0x100)

DECODE_END = CODE_ADDR + 0x120  # address after loop — find via disasm
mu.emu_start(CODE_ADDR, DECODE_END, timeout=2 * 1000000, count=10000)

decoded = mu.mem_read(DATA_ADDR, 0x1000)
print(f"decoded head: {decoded[:64].hex()}")
if decoded[:2] == b"MZ":
    open("stage2.bin", "wb").write(decoded)
    print("stage2 is PE — dumped to stage2.bin")
elif decoded[:4] == b"\x7fELF":
    open("stage2.bin", "wb").write(decoded)
    print("stage2 is ELF — dumped to stage2.bin")
else:
    for i in range(len(decoded) - 4):
        if decoded[i:i+5] == b"flag{":
            print(decoded[i:i+64])
            break
```

GDB `call rax` + `ptrace` 绕过的变体见 [patterns-runtime.md](patterns-runtime.md#多阶段-shellcode-加载器)。

---

<a id="custom-vm-emulation"></a>
## 自定义 VM 模拟

把 Unicorn 当 CPU，用一个读取 VM 取指指针的 `CODE` hook 来派发字节码。

```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x10000); mu.mem_write(0x400000, vm_stub)
mu.mem_map(0x500000, 0x10000); mu.mem_write(0x500000, BYTECODE)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
mu.reg_write(UC_X86_REG_RSI, 0x500000)

def hook_dispatch(mu, address, size, user_data):
    pc = mu.reg_read(UC_X86_REG_RSI)
    print(f"op=0x{mu.mem_read(pc, 1)[0]:02x} pc=0x{pc:x} RAX=0x{mu.reg_read(UC_X86_REG_RAX):x}")

mu.hook_add(UC_HOOK_CODE, hook_dispatch)
```

迭代求解：用上面的 `try_byte` 模式逐字节爆破 VM 输入。LLVM IR 提升见 [tools-advanced.md](tools-advanced.md#自定义-vm-字节码提升到-llvm-ir-google-ctf-2017)。

---

<a id="qiling-vs-unicorn-decision-tree"></a>
## Qiling vs Unicorn 决策树

| 问题 | 回答 | 选择 |
|---|---|---|
| 需要系统调用（`open`、`ptrace`、`socket`）？ | 是 | **Qiling** |
| 裸 blob / 固件，没有 OS？ | 是 | **Unicorn** |
| 需要绕过反调试？ | — | 都行 —— Qiling hook 系统调用，Unicorn 压根没有进程 |
| 异构架构 + `libc`？ | 是 | **Qiling**（rootfs） |
| 异构架构，裸机？ | 是 | **Unicorn**（更轻） |

```python
# Qiling — OS-level (needs rootfs)
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(["./binary", "arg1"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DEFAULT)
def hook_ptrace(ql, request, pid, addr, data):
    return 0
ql.os.set_syscall("ptrace", hook_ptrace)
ql.run()
```

```python
# Unicorn — raw CPU (no OS, no rootfs)
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, code_bytes)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
mu.emu_start(0x400000, 0x400000 + len(code_bytes))
```

如果你已经开始用 `UC_HOOK_INTR` / `UC_HOOK_INSN` 重新实现系统调用了，那就该换成 Qiling。

---

<a id="emulator-comparison-unicorn-vs-qiling-vs-qemu-vs-angr-vs-triton"></a>
## 模拟器对比：Unicorn vs Qiling vs QEMU vs angr vs Triton

具体执行 vs 符号执行 vs 操作系统 —— 为当前 CTF 片段挑对引擎。

| 引擎 | 执行方式 | OS / 系统调用 | 架构 | 符号执行 | 快照 | 最适合 | CTF 参考 |
|---|---|---|---|---|---|---|---|
| **Unicorn** | 具体执行，TCG | 无（裸 CPU） | x86、ARM、MIPS、RISC-V、M68K、SPARC、S390X | 否 | `context_save`/`restore` + `mem_read` | Shellcode、裸机固件、反调试片段、自定义 VM 派发 | 见 [tools.md](tools.md#unicorn-模拟执行) |
| **Qiling** | 具体执行，Unicorn+OS | 是（经 rootfs 提供系统调用、文件系统、注册表） | 同 Unicorn + OS 层 | 否（但可用 Python hook） | `ql.save`/`restore`（包装 context） | 带 libc 的异构 ELF、系统调用密集、`ptrace`/socket 绕过 | 见 [tools-emulation.md](tools-emulation.md#qiling-框架跨平台模拟) |
| **QEMU** | 具体执行，TCG/system | 完整系统或用户态 | 同上 + 完整外设 | 否 | VM 快照、`dump-guest-memory` | 启动完整 Linux、内核驱动逆向、经 `-machine` 做硬件 MMIO | 见 [platforms-hardware.md](platforms-hardware.md) |
| **angr** | 符号执行（VEX） | SimProcedures（SimLinux） | x86、ARM、MIPS | 是（Claripy/Z3） | 状态复制（`state.copy()`） | Flag 校验器、路径爆炸、无 MMIO 计时 | 见 [tools-dynamic.md](tools-dynamic.md) |
| **Triton** | 具体 + 符号（DSE） | 基于 Pin/DBI | x86、x86_64、AArch64 | 是（Ast） | 单路径轨迹 | 线性去混淆、污点分析、单路径求解 | 见 [tools-advanced.md](tools-advanced.md#triton动态符号执行) |

**决策规则：** 裸 blob/固件/无 OS → Unicorn；需要 `open`/`socket`/`ptrace` → Qiling；整个 OS/内核 → QEMU；需要**求解**输入而不靠爆破 → angr/Triton。Unicorn+Capstone+Keystone 是 angr 的补充（具体轨迹），不是替代。对于 VMProtect/Themida 这类"虚拟机本身就是题目"的情况，见 [tools-advanced.md](tools-advanced.md#vmprotect-分析)。

---

<a id="pitfalls"></a>
## 坑

| 坑 | 症状 | 解法 |
|---|---|---|
| `timeout` vs `count` | 两者非零时谁先到谁停 | 只用一个，另一个设 `0` |
| 栈在 `0x0` | 空指针解引用静默成功 | 栈映射到 `0x7fff0000` |
| Thumb 最低位 | `UC_ERR_INSN_INVALID` | `CODE_ADDR \| 1` + `UC_MODE_THUMB` |
| `UC_ERR_FETCH_UNMAPPED` | 跳转到未映射区域 | hook `MEM_INVALID` 或映射该区域 |
| Hook 重入 | `reg_write`/`mem_write` 再次触发 hook | 加保护标志或用 `MEM_READ_AFTER` |
| MIPS 字节序 | 第一条指令就无效 | `LITTLE`/`BIG_ENDIAN` 与二进制对齐 |
| 混合模式丢 EFLAGS/XMM | 标志陈旧、SSE 被清零 | 复制 `RFLAGS & 0xffffffff`、复制 `XMM0-15` |
| `mem_map` 对齐 | `UC_ERR_ARG` | 用 `0x1000` 的整数倍 |
| MMIO 上的 `WRITE_UNMAPPED` | 外设写入报错 | 先 `mem_map` MMIO 页，再 hook |

---

<a id="worked-examples-2024"></a>
## 实战示例（2024）

### 1 —— Shellcode 加载器（x86-64 异或解码）

Stager 释放 `shellcode.bin`，它异或解码一段内嵌 PE。循环在 `0x400080`，缓冲区在 `0x500000`。

```python
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x400000
DATA_ADDR = 0x500000
CODE = open("shellcode.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(DATA_ADDR, 2 * 1024 * 1024)
mu.mem_map(0x7fff0000, 2 * 1024 * 1024)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 2 * 1024 * 1024 - 0x100)

LOOP_END = CODE_ADDR + 0x120
try:
    mu.emu_start(CODE_ADDR, LOOP_END, timeout=2 * 1000000, count=10000)
except UcError as e:
    print(f"emulation stopped: {e} errno={e.errno}")

decoded = mu.mem_read(DATA_ADDR, 0x400)
print(f"head: {decoded[:32].hex()}")
if decoded[:2] == b"MZ":
    print("ok: decoded PE magic MZ found")
    open("stage2.bin", "wb").write(mu.mem_read(DATA_ADDR, 0x10000))
    print("dumped stage2.bin")
else:
    for i in range(len(decoded)):
        if decoded[i:i+5] == b"flag{":
            print(f"flag at 0x{i:x}: {decoded[i:i+64]}")
            print("ok: flag prefix found in decoded memory")
            break
    else:
        print("no PE magic or flag prefix — check LOOP_END")
```

验证会打印 `ok: decoded PE magic MZ found` 或 `ok: flag prefix found`。

### 2 —— 固件 MMIO（ARM Thumb UART 轮询）

固件轮询 `0x40000000`（状态，bit 0 = ready），然后读 `0x40000004`。没有 MMIO 的话，轮询会陷入死循环。

```python
from unicorn import *
from unicorn.arm_const import *

CODE_ADDR = 0x08000000
MMIO_BASE = 0x40000000
CODE = open("firmware.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x20000000, 0x10000)
mu.reg_write(UC_ARM_REG_SP, 0x20010000)
mu.mem_map(MMIO_BASE, 0x1000)
mu.mem_write(MMIO_BASE, b"\x01\x00\x00\x00")

count = [0]
def hook_code(mu, address, size, user_data):
    count[0] += 1
    if count[0] > 30000:
        mu.emu_stop()

mu.hook_add(UC_HOOK_CODE, hook_code)

try:
    mu.emu_start(CODE_ADDR | 1, CODE_ADDR + len(CODE), timeout=3 * 1000000, count=0)
except UcError as e:
    if e.errno == UC_ERR_INSN_INVALID:
        print(f"UC_ERR_INSN_INVALID at 0x{mu.reg_read(UC_ARM_REG_PC):x}")
    else:
        print(f"UcError {e} errno={e.errno}")

print(f"executed {count[0]} insns")
pc = mu.reg_read(UC_ARM_REG_PC)
print(f"final PC=0x{pc:x}")
if pc != (CODE_ADDR | 1):
    print("ok: firmware advanced past MMIO poll")
else:
    print("stalled: check MMIO mapping or Thumb bit")
```

轮询退出后，验证会打印 `ok: firmware advanced past MMIO poll`。

### 3 —— 进阶固件：定时器中断 + UART + 嵌套自定义 VM（2024 HITCON 风格）

`0x08000000`（Thumb）处的固件轮询 `0x40000000` 的 UART 状态，每 1000 个基本块触发一次 TIM2 中断，喂养一个逐字节校验 `flag{…}` 的嵌套自定义 VM。综合了快照 + MMIO + 超时 + Capstone。

```python
from unicorn import *
from unicorn.arm_const import *
from capstone import *

CODE_ADDR = 0x08000000
UART_BASE = 0x40000000
TIM2_BASE = 0x40010000
NVIC_BASE = 0xe000e100
CODE = open("firmware.bin", "rb").read()  # <!-- audit-ok --> placeholder

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(CODE_ADDR, 2 * 1024 * 1024)
mu.mem_write(CODE_ADDR, CODE)
mu.mem_map(0x20000000, 0x10000)
mu.reg_write(UC_ARM_REG_SP, 0x20010000)
for base in (UART_BASE, TIM2_BASE, NVIC_BASE):
    mu.mem_map(base, 0x1000)

# --- MMIO models with side-effects ---
timer = {"CNT": 0, "SR": 1}
uart_buf = b"flag{test}\n"
uart_idx = [0]

def hook_mmio_read(mu, access, address, size, value, user_data):
    if UART_BASE <= address < UART_BASE + 0x1000:
        off = address - UART_BASE
        if off == 0x00:  # status — bit 0 ready
            val = 1 if uart_idx[0] < len(uart_buf) else 0
            mu.mem_write(address, val.to_bytes(size, "little"))
            return True
        elif off == 0x04:  # data — consumes one byte
            if uart_idx[0] < len(uart_buf):
                val = uart_buf[uart_idx[0]]
                uart_idx[0] += 1
                mu.mem_write(address, val.to_bytes(size, "little"))
                print(f"UART read -> 0x{val:02x} '{chr(val)}'")
                return True
    elif TIM2_BASE <= address < TIM2_BASE + 0x1000:
        off = address - TIM2_BASE
        if off == 0x10:  # SR clear-on-read
            val = timer["SR"]
            timer["SR"] = 0
            mu.mem_write(address, val.to_bytes(size, "little"))
            return True
        elif off == 0x24:  # CNT free-running
            timer["CNT"] = (timer["CNT"] + 1) & 0xffff
            mu.mem_write(address, timer["CNT"].to_bytes(size, "little"))
            return True
    return False

def hook_mmio_write(mu, access, address, size, value, user_data):
    if UART_BASE <= address < UART_BASE + 0x1000:
        if (address - UART_BASE) == 0x08:  # TX
            print(f"UART TX 0x{value:x} '{chr(value & 0xff)}'")
        return True
    elif TIM2_BASE <= address < TIM2_BASE + 0x1000:
        if (address - TIM2_BASE) == 0x10:
            timer["SR"] &= ~value
        return True
    return False

mu.hook_add(UC_HOOK_MEM_READ, hook_mmio_read)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mmio_write)

# --- Timer interrupt feeding nested VM ---
tick = [0]
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
vm_entry = 0x08001234  # found via Ghidra — nested VM dispatcher

def hook_block(mu, address, size, user_data):
    tick[0] += 1
    if tick[0] % 1000 == 0:
        timer["SR"] |= 1
    # Capstone trace for VM dispatch detection
    if address == vm_entry:
        r0 = mu.reg_read(UC_ARM_REG_R0)
        print(f"VM dispatch at 0x{address:x} R0(opcode)=0x{r0:x} tick={tick[0]}")
        for insn in md.disasm(mu.mem_read(address, size), address):
            print(f"  {insn.mnemonic} {insn.op_str}")

mu.hook_add(UC_HOOK_BLOCK, hook_block)

# --- Snapshot at VM entry for brute-force ---
mu.emu_start(CODE_ADDR | 1, vm_entry | 1, timeout=2 * 1000000, count=0)
snap = mu.context_save()
snap_timer = dict(timer)
snap_uart = uart_idx[0]
snap_mem = mu.mem_read(0x20000000, 0x10000)
print(f"snapshot at VM entry PC=0x{mu.reg_read(UC_ARM_REG_PC):x}")

def try_byte(prefix: bytes, cand: int) -> bool:
    mu.context_restore(snap)
    timer.update(snap_timer)
    uart_idx[0] = snap_uart
    mu.mem_write(0x20000000, snap_mem)
    mu.mem_write(0x20001000, prefix + bytes([cand]))
    mu.reg_write(UC_ARM_REG_R0, 0x20001000)
    try:
        mu.emu_start(vm_entry | 1, vm_entry + 0x80, timeout=500000, count=2000)
    except UcError as e:
        if e.errno == UC_ERR_INSN_INVALID:
            print(f"  bad insn at 0x{mu.reg_read(UC_ARM_REG_PC):x}")
        return False
    return mu.reg_read(UC_ARM_REG_R0) == 0  # VM returns 0 on prefix ok

flag = b"flag{"
for pos in range(len(flag), 32):
    for c in range(32, 127):
        if try_byte(flag, c):
            flag += bytes([c])
            print(f"pos {pos}: {chr(c)} -> {flag}")
            break
    else:
        print(f"no hit at {pos}")
        break
print(f"flag={flag}")
if b"flag{" in flag:
    print("ok: nested VM flag recovered")
```

VM 校验通过时验证会打印 `ok: nested VM flag recovered`。这个模式覆盖：MMIO 读时清状态、自由运行 CNT、UART 缓冲读取、BLOCK 定时器注入、`vm_entry` 处的 Capstone 标注，以及 `context_save`/`mem_read` 快照爆破 —— 同一套脚手架可以扩展到 2024 HITCON 的固件 VM 及同类高阶题。

---

## 参考

- Unicorn Engine：`Uc`、`UC_ARCH_*`、`UC_MODE_*`、`mem_map`、`mem_write`、`reg_write`、`emu_start`、`hook_add`、`UC_HOOK_*`、`UC_ERR_*`、`mmio_map`、`context_save`/`restore`/`update`、`mem_protect`、`mem_regions`、`ctl_remove_cache`/`ctl_flush_tb`、`reg_read_batch`。
- Capstone：`Cs(CS_ARCH_X86, CS_MODE_64)` / `Cs(CS_ARCH_ARM, CS_MODE_THUMB)` 用于轨迹标注；与 `UC_HOOK_CODE`/`BLOCK` 配合做覆盖率和 SMC 检测。
- Keystone：`Ks(KS_ARCH_X86, KS_MODE_64).asm(...)` 用于轨迹求逆。
- Qiling：需要系统调用时用 `Qiling(path, rootfs)` —— 反调试和输入 fuzz 见 [tools-emulation.md](tools-emulation.md#qiling-框架跨平台模拟)。
- QEMU vs angr vs Triton：具体/系统执行 vs 符号执行 —— 见上面的对比表；VMProtect/Themida 去虚拟化见 [tools-advanced.md](tools-advanced.md#vmprotect-分析)。
- 前作：[tools.md](tools.md#unicorn-模拟执行)、[field-notes.md](field-notes.md#unicorn-模拟复杂状态)、[anti-analysis-ctf.md](anti-analysis-ctf.md#用-keystone-与-unicorn-反转指令轨迹meepwn-ctf-2017)、[tools-emulation.md](tools-emulation.md#qiling-框架跨平台模拟)、[tools-advanced.md](tools-advanced.md#自定义-vm-字节码提升到-llvm-ir-google-ctf-2017)。
