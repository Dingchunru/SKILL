---
tags:
  - arbitrary-write
  - seccomp-bypass
  - timing-side-channel
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "规则管理中存在堆写原语，可覆盖 __free_hook，从而触发 BPF 过滤器预言机逐位泄漏内存内容。"
proof-of-concept: no
---

# SeccompTools — pwnable.tw（500 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10408`
>
> Flag：`FLAG{u_r_master_of_secooooooomp!}`

## 题目概况

一个 seccomp BPF 规则的编辑器/模拟器（x86-64，PIE、Full RELRO、NX、栈 canary），链接 glibc 2.23。程序允许用户创建自定义 BPF（Berkeley Packet Filter）seccomp 规则、反汇编它们、模拟执行并装载进内核。它通过 `fopen`/`fread` 从文件加载示例规则，并在装载前校验规则"允许 ORW"。加载完示例后，`FILE *stream` 指针被存到 BSS 里，稍后被 `fclose`。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## 漏洞

### V1 — BPF_LEN 的模拟器/内核差异（主要，可 Exploit）

**根因：** 程序的 BPF 模拟器**没有**实现 `BPF_LD | BPF_LEN` 指令（opcode `0x80`）。在模拟器里执行完该指令后 `A` 仍是 0；而在真实 Linux 内核 seccomp 中，`BPF_LEN` 会把 `sizeof(struct seccomp_data)` = **64** 载入 `A`。

```text
Emulator:  BPF_LEN → A = 0  (unimplemented, A unchanged)
Kernel:    BPF_LEN → A = 64 (sizeof(struct seccomp_data))
```

这就形成**解析差异**：可以构造一条规则，它通过模拟器的 ORW 校验，但装进内核后是一个完全不同的策略。

```python
# Bypass the ORW check:
BPF_STMT(BPF_LD | BPF_LEN, 0)          # emulator: A=0, kernel: A=64
BPF_JUMP(BPF_JEQ, 64, bypass_to_real, 0)  # emulator: false→allow, kernel: true→real_filter
BPF_STMT(BPF_RET, SECCOMP_RET_ALLOW)    # emulator always reaches here
# ... actual malicious filter follows (kernel only) ...
```

**影响：** 可以装入任意 seccomp 过滤器，而 ORW 校验看不到它们。

### V2 — SECCOMP_RET_ERRNO 让 `open()` 返回 0（可 Exploit）

**根因：** 当 seccomp 过滤器对 `open` 系统调用返回 `SECCOMP_RET_ERRNO(0)` 时，内核跳过该系统调用并返回 0（不报错）。由于 fd 0 = stdin，`fopen()` 会拿到一个以 fd 0（stdin）为底的 `FILE *`。之后从这个流 `fread()` 读到的就是用户输入而不是文件内容。

```c
// In the binary, loading an example rule:
stream = fopen("allow_orw.bpf", "rb");   // open() → blocked by seccomp → returns 0 (stdin)
fread(filter_buf, 1, filter_size, stream); // reads from stdin!
// filter_size comes from the first 2 bytes of the "file" (user-controlled)
```

**影响：** `filter_size`（最大 0xffff）由发送的前 2 个字节控制，而 `filter_buf` 在 BSS 的固定偏移（`0x203080`）。发送尺寸 `0x1008` 就会越过 0x1000 字节的 `filter_buf`，覆盖紧邻的 `stream` 指针（位于 `filter_buf + 0x1000`）。

### V3 — BSS 中 `stream` 指针覆盖 → FSOP（可 Exploit）

**根因：** `FILE *stream` 指针在 BSS 中位于 `filter_buf` 之后 0x1000 字节。借助 V2 的溢出，攻击者把 `stream` 改成指向同一缓冲区中伪造的 `_IO_FILE_plus` 结构。程序调用 `fclose(stream)` 时，就会顺着假 vtable 走到攻击者控制的代码。

```c
// After fread overflow:
// filter_buf[0x1000] now contains &fake_FILE (points back into filter_buf)
fclose(stream);  // → calls fake_vtable->__finish(fake_FILE)
```

**影响：** `fclose` 经假 vtable 分发时获得完整 RIP 控制。

### V4 — 基于 seccomp 的侧信道预言机泄漏地址（可 Exploit）

**根因：** BPF 过滤器可以检查 `seccomp_data` 的各个字段，包括 `instruction_pointer`（执行系统调用的那条 libc 代码地址）和系统调用参数（`args[0]`–`args[5]`，其中包含缓冲区地址）。让过滤器在特定位为 1 时返回 `SECCOMP_RET_ERRNO`、否则返回 `SECCOMP_RET_ALLOW`，就构成了一个侧信道预言机。

```c
struct seccomp_data {
    int   nr;                  // offset 0x00: syscall number
    __u32 arch;                // offset 0x04
    __u64 instruction_pointer; // offset 0x08: libc address!
    __u64 args[6];             // offset 0x10: includes buffer addresses (PIE leak)
};
```

预言机的判读方式是观察 `fread`（内部调用 `read`）成功还是阻塞：
- 若过滤器对某次 `read` 返回 `ERRNO`，`fread` 会循环重试 → 程序看起来卡住（无输出）。
- 若返回 `ALLOW`，`read` 成功 → 程序打印 "Done!"。

**影响：** 可以逐位或逐字节泄漏 PIE 基址（来自 `args[0]` = `read` 的缓冲区地址）和 libc 基址（来自 `instruction_pointer` = `read` 系统调用的地址）。

## 利用流程（所有解法通用）

16 份解法都是同样的三阶段结构：

### 阶段一 —— 用 seccomp 预言机泄漏地址

装入一个 BPF 过滤器（借 V1 绕过 ORW 校验），用侧信道预言机（V4）泄漏：
- **PIE 基址**：来自 `seccomp_data.args[0]`（传给 `read` 的缓冲区地址）或 `seccomp_data.args[1]`
- **libc 基址**：来自 `seccomp_data.instruction_pointer`（执行 `read` 系统调用处的 libc 地址）

### 阶段二 —— 强制从 stdin 读取以溢出 BSS

装入新过滤器，令其对特定示例文件的 `open()` 返回 `ERRNO(0)`（V2）。触发"加载示例"代码路径 → `fopen` 返回以 stdin 为底的 `FILE *` → `fread` 读到攻击者控制的数据 → 溢出 `filter_buf`（0x1000 字节）+ 覆盖 `stream` 指针（V3）。

### 阶段三 —— 伪造 FILE 结构做 FSOP

溢出后的缓冲区里放一个伪造的 `_IO_FILE_plus` 结构，带假 vtable。程序调用 `fclose(stream)` 时经假 vtable 分发，从而控制 RIP。

## 利用路径变体（阶段三的收尾）

### 路径 A — 经 vtable 劫持执行 `system("/bin/sh")` 或 `system(";sh;")`（约 50%）

**使用范围：** 解法 370、821、14、2972、3972、38838、408

把 `"/bin/sh"` 或 `";sh;"` 放进假 FILE 的 `_flags` 字段，把 vtable 的 `__finish` 或 `__close` 项指向 `system`。`fclose` 调用 `vtable->__finish(fp)` 时即执行 `system(fp)`，而 `fp` 指向的内容以 shell 命令开头。

有些解法不整体伪造 vtable，而是借 `_IO_str_overflow` 或 `_vtable_offset` 技巧经 `_IO_str_jumps` 调到 `system`。

### 路径 B — `setcontext` + ORW ROP 链（约 40%）

**使用范围：** 解法 exp.py（主）、8153、9251、22319、31599、34817、35282

把 vtable 的 `__finish` 指向 `setcontext+53`（glibc 2.23）。这个 gadget 会从 `_IO_FILE` 结构的字段里加载一批寄存器（把 `rdi` 当作结构指针），然后把栈迁移到攻击者控制的 ROP 链上。ROP 链执行：

```python
open("/home/seccomp-tools/flag", O_RDONLY)
read(fd, buffer, 0x100)
write(1, buffer, 0x100)
```

之所以更偏爱这种收尾，是因为 `execve` 可能被此前装入的 seccomp 过滤器拦住。

### 路径 C — `mprotect` + shellcode（约 10%）

**使用范围：** 解法 5586、8153

借 FSOP 拿到 RIP 后，用 ROP 链调用 `mprotect(bss_page, 0x1000, RWX)`，再跳到嵌在 BSS 缓冲区里的 shellcode。shellcode 用 ORW 读 flag。

### 路径 D — 经 FSOP 触发格式化字符串 → 两阶段泄漏 + shell

**使用范围：** 解法 6748

不直接调 `system`，而是伪造 FILE 结构去触发带格式化字符串（`%21$p`）的 `printf`，泄漏栈/libc 地址；然后再走一轮 FSOP，用解析出的完整地址调用 `system`。

## 预言机技巧变体

| 技巧 | 速度 | 使用者 |
|-----------|-------|---------|
| 逐位探测（每个地址 36–48 次迭代） | 约 30–60 秒 | 370、1980、5586、8153、9251、35282、38838 |
| 对 16 位片段二分（每片段 log₂ 次探测） | 约 15–30 秒 | 31599、34817、408 |
| 逐字节，用 `fread` 尺寸编码 | 约 40–50 秒 | exp.py（主）、821 |
| 逐 nibble，用 `write` 尺寸侧信道 | 约 60–90 秒 | 3972 |
| 每字节 256 值暴力（线性扫描） | 约 120 秒以上 | 370、2972 |

## 关键偏移（pwnable.tw 远端，glibc 2.23）

```python
# Binary
filter_buf_bss    = 0x203080   # BSS offset of the BPF filter buffer
stream_bss        = 0x204088   # BSS offset of FILE *stream (filter_buf + 0x1008)
allow_orw_bpf_str = 0x277c     # ".rodata" offset of "allow_orw.bpf" string
puts_plt          = 0xa70

# libc
system            = 0x45390
setcontext_53     = 0x47b75    # setcontext+53 (register load gadget)
__open_nocancel_7 = 0xf6460    # common instruction_pointer leak offset
main_arena        = 0x3c3b20
_IO_2_1_stderr_   = 0x3c4680
_IO_stdfile_1_lock = 0x3c5770

# ROP gadgets (libc)
pop_rdi           = 0x21102
pop_rsi           = 0x202e8
pop_rdx           = 0x1b92
pop_rax           = 0x33544
syscall_ret       = 0xbb7c5    # or 0x35426, 0x106c05
mprotect          = 0x100b80

# one_gadgets
one_gadgets       = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

## `seccomp_data` 布局（供 BPF 预言机使用）

```c
struct seccomp_data {
    0x00: int   nr;                   // syscall number
    0x04: __u32 arch;                 // AUDIT_ARCH_X86_64 = 0xC000003E
    0x08: __u64 instruction_pointer;  // → libc address (where syscall insn lives)
    0x10: __u64 args[0];              // → filename ptr for open, buf ptr for read
    0x18: __u64 args[1];              // → buf ptr (PIE leak via fread→read)
    0x20: __u64 args[2];              // → size (controllable via fread loop)
    0x28: __u64 args[3];
    0x30: __u64 args[4];
    0x38: __u64 args[5];
};
// sizeof(seccomp_data) = 64 = 0x40
// BPF accesses 32-bit words: data[0x08]=ip_low, data[0x0c]=ip_high, etc.
```

## 题解文章

| 文件 | 泄漏技巧 | 收尾方式 | 备注 |
|------|---------------|--------|-------|
| `370.md` | 用 fread 尺寸编码做逐字节扫描 | 经 vtable 执行 `system(";sh;")` | 两个脚本；详细的 BPF 规则构造 |
| `821.md` | 逐字节 fread 尺寸预言机 | `_IO_str_overflow` → `system` | 详细三步讲解；seccomp 过滤器树的优先级 |
| `14.md` | 逐位探测（48 次迭代） | `setcontext` + mprotect + shellcode | 用 `seccomp-tools asm` 编译规则 |
| `1980.md` | 逐位探测 | 假 FILE vtable → `system` | 用 `args[1]` 做堆泄漏 |
| `2972.md` | 对 open 的 args[0] 二分 | FSOP vtable `system(";sh;")` | 用 `seccomp-tools asm` 编译 |
| `3972.md` | 逐 nibble，用 write() 参数 | 格式化字符串泄漏 → `system` | 最有创意：用了多种 write() 触发方式 |
| `5586.md` | 逐字节，借 fread 内部 read | `setcontext` → mprotect + ORW shellcode | 用 read 尺寸编码的详细 BPF 预言机 |
| `6748.md` | 对 16 位片段二分 | `setcontext` → mprotect + shellcode | 过滤器数量最少的优雅解法 |
| `8153.md` | 用 `fopen` 成功/失败做逐位探测 | `setcontext` + ORW ROP | 最后一段用 `mprotect` + shellcode |
| `9251.md` | open 参数二分 + seccomp 树 | `setcontext` → 栈迁移 → ORW ROP | 详细解释 seccomp 过滤器树的优先级 |
| `22319.md` | 多种 read 尺寸下逐位探测 | 假 FILE `_IO_finish` → `setcontext` | 用 pwntools 的 `FileStructure` |
| `31599.md` | 对 `instruction_pointer` 二分 | `setcontext` + ORW ROP 链 | 干净的二分；PIE 与 libc 分开泄漏 |
| `34817.md` | 用 BPF `jge` 二分 | `setcontext` + `openat` ORW ROP | 用 `SECCOMP_ASSEMBLER.py` 辅助 |
| `35282.md` | 用 fread 尺寸+偏移逐位 | 假 FILE vtable → `one_gadget` / `system` | 堆地址 + libc 泄漏 |
| `38838.md` | 对 16 位半字二分 | `setcontext` + ORW ROP | 用 `FileStructure`；干净的两阶段泄漏 |
| `408.md` | 用 read 尺寸/偏移编码逐位 | 假 FILE → `execve` | 最简单的 vtable 劫持 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit：BPF 预言机 + House of Spirit + FSOP → ORW ROP |
| `IO_FILE.py` | 辅助：`_IO_FILE_plus` 与 `_IO_jump_t` 结构体构造器 |
| `SECCOMP_ASSEMBLER.py` | 辅助：BPF 汇编 → 字节码编译器 |
| `desc.txt` | 题目描述 |
| `artifacts/` | 原始题目二进制与 libc |
| `solution/*.md` | 社区 writeup（16 份解法） |
