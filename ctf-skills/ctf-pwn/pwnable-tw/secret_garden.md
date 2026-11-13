---
tags:
  - double-free
  - fastbin-dup
  - one-gadget
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "花朵节点上的双重释放漏洞可做 fastbin 伪造，在 __malloc_hook 上分配出 chunk 并执行 one_gadget。"
proof-of-concept: no
---

# Secret Garden — pwnable.tw（350 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10203`
>
> Flag：`FLAG{FastBiN_C0rruption_t0_BUrN_7H3_G4rd3n}`

## 题目概况

一道菜单式堆题（x86-64，Full RELRO、PIE、NX、栈 canary），链接 glibc 2.23。程序在堆上管理一个"花"结构体数组 —— 每朵花有一个名字缓冲区（尺寸由用户通过 `malloc` 指定）、24 字节的颜色字符串和一个 in-use 标志。菜单包括：（1）Raise a flower、（2）Visit the garden、（3）Remove a flower、（4）Clean the garden、（5）Leave。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## 程序结构

### 花朵结构体（0x28 字节，malloc 分配）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00` | `in_use` | `uint32_t`（1 = 存活，0 = 已移除） |
| `0x08` | `name` | `char *`（malloc 分配，尺寸由用户指定） |
| `0x10` | `color` | `char[24]`（内联，scanf `%23s`） |

### 全局状态

- `flower_array[100]` —— BSS 中的 `flower *` 指针数组（最多 100 朵）
- `flower_count` —— 已栽种的花朵总数

### 菜单操作

1. **Raise** —— 为结构体 `malloc(0x28)`，为名字 `malloc(size)`，用 `read()` 读名字、用 `scanf` 读颜色，置 `in_use = 1`。
2. **Visit** —— 遍历数组，打印 `in_use != 0` 的花朵的名字和颜色。
3. **Remove** —— `free(flower->name)`，置 `flower->in_use = 0`。**不清空 name 指针、不清空数组槽、不释放结构体。**
4. **Clean** —— 遍历数组，对 `in_use == 0` 的花朵：`free(flower_struct)` 并把数组槽置空。

## 漏洞

### V1 — 名字缓冲区的 Use-After-Free / 双重释放（主要，可 Exploit）

**根因：** "Remove"操作释放了花朵的名字缓冲区，却没有清空 `name` 指针，也没有清空数组槽。`in_use` 标志被置 0，但花朵结构体仍可访问。由此可得：

- **Use-After-Free**：Remove 之后"Visit"仍会打印 name 指针指向的内容（此时已是释放后的内存，装着堆元数据 fd/bk 指针）。
- **双重释放**：对同一朵花 Remove 两次 → 名字缓冲区被释放两次，破坏 fastbin 的空闲链表。

```c
// Remove (simplified pseudocode)
void remove_flower(int idx) {
    if (flower_array[idx] != NULL) {
        free(flower_array[idx]->name);   // free name buffer
        flower_array[idx]->in_use = 0;   // mark as removed
        // BUG: name pointer NOT cleared
        // BUG: array slot NOT nulled
        // BUG: struct NOT freed
    }
}
```

**影响：** 已释放的名字缓冲区里的 `fd` 指针（在 fastbin 中）或 `fd`/`bk` 指针（在 unsorted/small bin 中）可经 Visit 泄漏。双重释放则可做 fastbin duplication 以实现任意写。

### V2 — 名字缓冲区的部分写（助攻）

**根因：** Raise 时名字通过 `read(0, name_buf, size)` 读取。`read()` 不会补 NUL，而 `calloc`/`malloc` 得到的缓冲区可能残留堆元数据，写入字节数少于分配尺寸时就会保留原有数据（来自已释放 chunk 的 libc 指针）。

```c
// Raise (simplified)
flower->name = malloc(size);
read(0, flower->name, size);  // partial write preserves old fd/bk at offset 8+
```

**影响：** 分配到一个此前装过 unsorted bin 指针的 chunk，只写 8 字节 → 偏移 8 处的 libc `main_arena+0x58` 指针得以保留 → 可经 Visit 泄漏。

## 利用路径

所有解法都利用 V1（UAF/双重释放），区别在于泄漏策略和最终代码执行手段。

---

### 路径 A — Unsorted Bin 泄漏 + Fastbin Dup → 覆盖 `__malloc_hook`

**使用范围：** exp.py、解法 2311、2605、821（方法 2）、1351，以及大多数 writeup

这是最经典、最常见的做法。

**步骤：**

1. **经 Unsorted Bin 泄漏 libc：**
   - 栽两朵花 A（尺寸 > 0x80，例如 0x100）和 B（作屏障，防止 top chunk 合并）。
   - Remove A → 名字缓冲区进入 unsorted bin → `fd`/`bk` = `main_arena+0x58`。
   - Clean → A 的结构体被释放进 fastbin，槽位清空。
   - 以同样尺寸栽 A' → 结构体复用 fastbin，名字复用那个 unsorted chunk。
   - 只写 8 字节 → 偏移 8 处的 libc 指针得以保留。
   - Visit → 读出 `main_arena+0x58` → `libc_base = leak - 0x3c3b78`。

2. **Fastbin 复制（双重释放）：**
   - 以尺寸 0x60 栽 D 和 E（chunk 尺寸 0x70 → fastbin 下标 5）。
   - Remove D、Remove E、Remove D → fastbin：`D → E → D`（成环）。
   - 栽花时把 `p64(__malloc_hook - 0x23)` 作为名字 → 覆盖 D 的 `fd`。
   - 再栽两次，把 E 和 D 取走。
   - 下一次 0x70 分配返回 `__malloc_hook - 0x23` 处的假 chunk。
     - `__malloc_hook - 0x1b` 处的字节是某个 libc 指针的最高字节 = `0x7f`，可以当作合法的假 chunk 尺寸（0x70 fastbin，同时置了 IS_MMAPPED 位）。

3. **把 one_gadget 写进 `__malloc_hook`：**
   - 假 chunk 起点在 `__malloc_hook` 之前 0x23 字节。
   - 写入 `\x00 * 0x13 + p64(one_gadget)` → 覆盖 `__malloc_hook`。

4. **触发：**
   - 对任意花朵做双重释放 → glibc 检测到破坏 → `malloc_printerr` → `abort` 的回溯过程中调用 `malloc` → `__malloc_hook` 触发 → `execve("/bin/sh")`。
   - 另一种做法：直接再调一次 Raise（菜单 1）触发 `malloc`。

**one_gadget 偏移（glibc 2.23）：**
```python
0x45216   # rax == NULL
0x4526a   # [rsp+0x30] == NULL
0xef6c4   # [rsp+0x50] == NULL  (most commonly used)
0xf0567   # [rsp+0x70] == NULL
```

**可靠性：** 堆布置确定，几乎 100% 可靠。

---

### 路径 B — Fastbin Dup → 任意读（伪造花朵结构体）→ 栈上 ROP

**使用范围：** 解法 8、10、59、78、184、644、821（方法 1）

这条路先造一个任意读原语，再去覆盖栈上的返回地址。

**步骤：**

1. **经 Fastbin 泄漏堆地址：**
   - 反复栽种/移除同尺寸花朵填充 fastbin。
   - 新栽的花结构体与一个已释放的名字重叠 → Visit 泄漏 `fd` 指针 → 得到堆基址。

2. **泄漏 libc：**
   - 可走 unsorted bin（同路径 A），也可用堆泄漏 + 任意读去够到堆上的 libc 指针。

3. **经 `environ` 泄漏栈地址：**
   - 用 fastbin dup 造出花朵结构体与名字缓冲区的重叠。
   - 伪造结构体，让 `name` 指向 `libc.sym['environ']`。
   - Visit → 打印 `environ` 的内容 → 得到栈地址。

4. **Fastbin Dup 打到栈上：**
   - 找一个栈地址，使得 `[addr+8]` 处是 `0x7f`（合法的 fastbin 尺寸字节），通常在 `environ_value - 0x18b` 之类的偏移处。
   - 双重释放 0x70 尺寸的 chunk，植入指向该栈地址的假 `fd`。
   - 最后一次分配返回栈上的缓冲区。
   - 写入 ROP 链（`pop rdi; ret` → `/bin/sh` → `system`），覆盖 `read()` 的返回地址（名字缓冲区的 `read()` 调用返回到存在漏洞的栈帧）。

**可靠性：** 确定性。不依赖 one_gadget 的约束条件。

---

### 路径 C — Fastbin Dup → `_IO_list_all` / `stdout` vtable 劫持

**使用范围：** 解法 78（变体）、138、278、365、370（变体）、100、1172、1236

这条路打的是 glibc 2.23 中 FILE 流的 vtable 机制。

**步骤：**

1. **泄漏 libc + 堆：** 同路径 A/B。

2. **Fastbin Dup 打向 `_IO_list_all` 或 `stdout`：**
   - 目标取 `_IO_list_all - 0x23`（该处有 `0x7f` 尺寸字节）或 `stdout + 0xd8 - 0x3b`（类似）。
   - 双重释放 0x70 的 chunk，把假 `fd` 植向目标。

3. **覆盖 `_IO_list_all`**，令其指向受控的堆区域，其中放置：
   - 一个满足字段约束的伪造 `_IO_FILE` 结构。
   - 一个假 vtable，其 `__overflow` / `xsputn` 函数指针 = `one_gadget` 或 `system`。

4. **经 `exit(0)`（菜单 5）或 `abort` 触发：**
   - `exit` → `__run_exit_handlers` → `_IO_cleanup` → `_IO_flush_all_lockp` → 遍历 `_IO_list_all` → 调用 vtable 函数 → one_gadget/system。
   - 或者：任意 malloc 错误（双重释放）→ `malloc_printerr` → `abort` → `_IO_flush_all_lockp` → 同样路径。

**可靠性：** 需要精心构造结构体。在 glibc 2.23 上有效（当时尚未强制 vtable 检查）。

---

### 路径 D — Fastbin Dup → 覆盖 `main_arena` top → `__free_hook`

**使用范围：** 解法 550

一种不常见的做法：覆盖 `main_arena.top`，改变后续分配的去向。

**步骤：**

1. 用 UAF 泄漏 libc + 堆。
2. **Fastbin dup 打进 `main_arena`**（利用某个位置带有合法尺寸字节的堆地址）。
3. **覆盖 `main_arena.top`** 为 `__free_hook - 0xb58`（该地址处有非零数据，可充当新 top chunk 的尺寸）。
4. **反复分配**，把 top chunk 推到 `__free_hook` 附近。
5. **把 `__free_hook` 覆盖为 `system`**。
6. **释放**一个含 `"/bin/sh"` 的 chunk → `system("/bin/sh")`。

**可靠性：** 可行，但要多次分配才能推到 `__free_hook`，比较脆弱。

---

### 路径 E — Unsorted Bin Attack → `global_max_fast` → 大 fastbin → `__free_hook`

**使用范围：** 解法 821（方法 1）

1. **Unsorted bin attack** 把 `main_arena+0x58` 写进 `global_max_fast`，于是所有尺寸的 chunk 都被当作 fastbin 处理。
2. **释放一个大 chunk** → 它落进映射到有用地址的"fastbin"槽。
3. **从该 fastbin 分配**，得到 `__free_hook` 附近的 chunk。
4. **把 `__free_hook` 覆盖为 `system`**。

**可靠性：** 布置复杂，用的人少。

---

### 路径 F — `__realloc_hook` + `__malloc_hook` 组合

**使用范围：** 解法 2311、2605

路径 A 的变体，专门对付 one_gadget 约束不满足的情况：

1. 同样 fastbin dup 到 `__malloc_hook - 0x23`。
2. 把 `one_gadget` 写进 `__realloc_hook`，把 `__libc_realloc + 20` 写进 `__malloc_hook`。
3. 调用 `malloc` → `__malloc_hook` → `__libc_realloc(+20)` → `__realloc_hook` → `one_gadget`。
4. 多出来的 `realloc` 栈帧会调整 `rsp` 对齐，使 one_gadget 的约束得以满足。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| libc 泄漏（unsorted bin fd/bk） | V1：释放进 unsorted bin 后 UAF 读 | 确定性 |
| 堆泄漏（fastbin fd） | V1：释放进 fastbin 后 UAF 读 | 确定性 |
| Fastbin 复制 | V1：对同一名字缓冲区双重释放 | 确定性 |
| 任意写（fastbin dup） | 假 fd → 在目标地址分配 | 确定性（需合法尺寸字节） |
| 栈泄漏 | 经伪造花朵结构体任意读到 `environ` | 任意读后确定性 |
| 代码执行 | `__malloc_hook`、`__free_hook`、vtable 或栈上 ROP | 确定性 |

## 关键偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
main_arena      = 0x3c3b20
main_arena_top  = 0x3c3b78   # main_arena + 0x58 (unsorted bin head)
__malloc_hook   = 0x3c3b10
__realloc_hook  = 0x3c3b08
__free_hook     = 0x3c57a8
_IO_list_all    = 0x3c4520
_IO_2_1_stdout  = 0x3c4620
environ         = 0x3c5f38   # (in some solutions: __libc_argv = 0x3c82f8)
system          = 0x45390
bin_sh          = 0x18c177
pop_rdi         = 0x21102    # pop rdi; ret
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `8.md` | B | fastbin dup → 经 environ 泄漏后在栈上 ROP | 完整任意读链；泄漏堆、libc、栈、canary |
| `10.md` | B | fastbin dup → 经 TLS/mmap 泄漏后在栈上 ROP | 少见：借 mmap chunk 的 TLS 区域泄漏 libc |
| `59.md` | B | fastbin dup → 栈上 ROP | 干净写法；经 environ 泄漏 libc、栈 |
| `60.md` | B | 切分 unsorted bin → 栈上 ROP | 用剩余 chunk 的元数据泄漏 libc |
| `78.md` | C | fastbin dup → `_IO_2_1_stdout_` vtable | 把 stdout 的 vtable 指针改成假 vtable |
| `100.md` | C | fastbin dup → `_IO_list_all` → exit 触发 | 伪造 IO 流，经 exit(0) 触发 |
| `138.md` | C | fastbin dup → `_IO_list_all` | Ruby 脚本；IO_flush_all 打 one_gadget |
| `184.md` | B | fastbin dup → 经 `__libc_argv` 在栈上 ROP | 从 __libc_argv 而非 environ 泄漏栈 |
| `278.md` | C | fastbin dup → stdout vtable 劫持 | 把 stdout 的 vtable 换成含 one_gadget 的假 vtable |
| `331.md` | A | unsorted bin 泄漏 → fastbin dup → `__malloc_hook` | 第一次顺带完成 libc+堆泄漏，再覆盖 malloc_hook |
| `365.md` | C | fastbin dup → `_IO_list_all` + 假 IO | 在堆上构造完整假 FILE 结构 |
| `370.md` | A | fastbin dup → 经 IO_list vtable 打 `__malloc_hook` | 变体：把 IO stdout 的 vtable 换成 one_gadget |
| `550.md` | D | fastbin dup → 覆盖 `main_arena.top` → `__free_hook` | 少见：劫持 top chunk 去够 `__free_hook` |
| `644.md` | B | fastbin dup → 经 environ 在栈上 ROP | 经典：泄漏栈，ROP 覆盖 read() 返回地址 |
| `821.md` | E + A | unsorted bin attack → `global_max_fast` + fastbin → `__free_hook` | 一篇 writeup 里给出三种利用方法 |
| `1172.md` | A | fastbin dup → `__malloc_hook` | 简洁；标准套路 |
| `1236.md` | A | fastbin dup → `_IO_2_1_stdout_` vtable | 把 stdout 的 vtable 换成 one_gadget |
| `1351.md` | C | fastbin dup → stdout vtable | Ruby；经 vtable 打 one_gadget |
| `2311.md` | F | fastbin dup → `__realloc_hook` + `__malloc_hook` 组合 | 借 realloc 修正 rsp 对齐以适配 one_gadget |
| `2605.md` | A | fastbin dup → `__malloc_hook` | 标准套路，附详细堆操作过程 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit（fastbin dup → `__malloc_hook` → one_gadget） |
| `desc.txt` | 题目描述 |
| `artifacts/` | 原始题目二进制 + libc |
| `solution/*.md` | 社区 writeup（128 份解法） |
