---
tags:
  - out-of-bounds-write
  - information-leak
  - house-of-orange
  - io-file-exploit
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "在填写书籍作者时的 off-by-null 写入可泄露堆地址，而覆盖 top chunk 大小可触发 House of Orange，通过 _IO_flush_all_lockp 实现 _IO_FILE vtable 利用。"
proof-of-concept: no
---

# BookWriter — pwnable.tw（500 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10304`
>
> Flag：`FLAG{Th3r3_4r3_S0m3_m4gic_in_t0p}`

## 题目概览

一个堆笔记类二进制（x86-64，Full RELRO、NX、Stack Canary、关闭 PIE），链接 glibc 2.23。程序管理一个 “author” 名字和最多 8 页动态分配的文本。它**没有 free/delete** 操作——想让 chunk 进入 free list，唯一途径是 House of Orange 技巧（破坏 top chunk 大小，诱使 `sysmalloc` 释放旧的 top）。

基于 BKP CTF 2017 的 “memo” 题目，修复了部分 bug 并修改了控制流。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)    # .bss addresses are fixed
```

## 全局数据布局（BSS）

```text
0x602040  num_pages         (uint32_t, max 8)
0x602060  author[0x40]      (char, NO NUL terminator if fully filled)
0x6020A0  page_ptrs[8]      (char *[8])
0x6020E0  page_sizes[8]     (uint64_t[8])
```

注意 `page_ptrs[8]`（位于 `0x6020E0`）与 `page_sizes[0]` 是同一块内存。这正是越界索引技巧的关键。

## 漏洞

### V1 —— `edit()` 中基于 `strlen` 的大小更新（主要，堆溢出）

**根因：** `edit()` 调用 `read_n(page, page_size)` 之后，会用 `page_size = strlen(page)` 更新保存的大小。如果页内容中没有 NUL 字节，`strlen` 就会越过 chunk 边界读进下一个 chunk 的元数据。

```c
// edit() pseudocode
void edit(int idx) {
    read_n(page_ptrs[idx], page_sizes[idx]);  // fill to exact capacity
    page_sizes[idx] = strlen(page_ptrs[idx]); // BUG: strlen walks into next chunk
}
```

**触发方式：** 分配一个大小为 N 的页并用 N 个非 NUL 字节填满。`strlen` 会越过 chunk 数据读进后一个 chunk 的 `size` 字段（非零），返回一个大于 N 的值。此时再次 `edit()` 就会按这个被放大的大小写入，溢出到相邻 chunk。

**影响：** 覆盖 **top chunk 的 size 字段**。这就能启用 House of Orange：把 top chunk 大小设成满足 `sysmalloc` 页对齐检查的值，然后 `malloc` 一个大于被破坏 top chunk 的请求 → `sysmalloc` 会对旧 top 调用 `_int_free()`，把它放进 unsorted bin。

### V2 —— `add()` 中的越界索引（页计数溢出）

**根因：** `add()` 扫描 `page_ptrs[0..8]`（共 9 个元素）寻找空位，但该数组只有 8 个条目。`page_ptrs` 的索引 8 与 `page_sizes[0]` 是同一块内存。

```c
// add() pseudocode
for (int i = 0; i <= 8; i++) {   // BUG: should be i < 8
    if (page_ptrs[i] == NULL) {
        page_ptrs[i] = malloc(size);
        page_sizes[i] = size;
        break;
    }
}
```

**触发方式：** 填满全部 8 个页槽（索引 0-7）。下一次 `add()` 会把 `malloc` 的返回值写入 `page_ptrs[8]`，而它实际上是 `page_sizes[0]`。此时 `page_sizes[0]` 里是一个**堆指针**（一个非常大的值），于是 `edit(0)` 就变成一次巨大的任意堆写入。

**技巧的前提：** 如果 `page_sizes[0]` 为 0（页 0 以大小 0 分配），那么 `page_ptrs[0]` 在扫描看来是 NULL，于是 `add()` 会在索引 0 处替换它，并把 `page_sizes[0]` 设为新的 `malloc` 返回值。无论哪种情况，`page_sizes[0]` 都会变得很大。

### V3 —— Author 缓冲区信息泄露（堆泄露）

**根因：** 位于 `0x602060` 的 author 缓冲区有 0x40 字节。如果把它填满（没有 NUL 终止符），`information()` 用 `printf("%s", author)` 打印时就会继续读进 `page_ptrs[0]`——也就是一个堆地址。

```c
// set author
read_n(author, 0x40);  // no NUL terminator if 0x40 bytes sent

// information()
printf("Author : %s\n", author);  // leaks page_ptrs[0] after the 0x40 author bytes
```

**影响：** 通过越过 author 缓冲区读入 `page_ptrs[0]` 来泄露堆基址。

### V4 —— 没有 `free()` 操作

程序没有提供删除/释放功能。这意味着：
- 标准的 UAF/double-free 攻击不可行。
- 让 chunk 进入 free list 的**唯一**办法是 House of Orange（V1 → 破坏 top chunk → `sysmalloc` 释放旧 top）。

## 利用路径

全部 90 篇解法都使用 **House of Orange** 技巧。区别在于具体的 FSOP 布局，以及触发伪造 `_IO_FILE` 执行的机制。

---

### 路径 A —— House of Orange → 通过 `_IO_list_all` unsorted bin 攻击实现 FSOP（标准做法）

**使用者：** 约 95% 的解法（138、185、194、1172、1177、1303、1351、1689、1829、1922、1980、10840、17006、18324、21260 等）

**步骤：**

1. **堆泄露（V3）：** 用 0x40 个非 NUL 字节作为 author 发送。调用 `information()` → author 字符串泄露进 `page_ptrs[0]` → 得到堆基址。

2. **破坏 top chunk（V1）：** 分配一个与 top chunk 相邻的页（例如大小 0x18 或 0x28）。编辑两次：第一次利用 `strlen` 放大保存的大小，第二次把 top chunk 的大小覆盖为一个精心挑选的值（例如 `0xfc1`、`0xfe1`、`0x0fc1`、`0x0ed1`）。新大小必须满足：
   - `old_top + new_size` 按页对齐
   - `new_size > MINSIZE`
   - `prev_inuse` 位置位

3. **触发 `sysmalloc`（House of Orange）：** `add(0x1000, ...)`——请求超过被破坏的 top chunk 大小 → `sysmalloc` 把旧 top 释放进 **unsorted bin**，并 mmap 一块新区域。

4. **libc 泄露：** 从被释放的旧 top（现在在 unsorted bin 里）分配一个小 chunk。剩下的 unsorted chunk 的 `fd`/`bk` 指向 `main_arena+88`。用 `view()` 读取 → 得到 libc 基址。

5. **越界索引技巧（V2）：** 填满剩余页槽。第 9 次 `add()` 会把一个堆指针写入 `page_sizes[0]` → `edit(0)` 变成一次巨大的堆写入。

6. **构造伪造 `_IO_FILE` + unsorted bin 攻击：** 利用这个巨大的 `edit(0)` 写入：
   - 一个伪造的 `_IO_FILE_plus` 结构，其 `flags = "/bin/sh\x00"`、`_IO_buf_size = 0x61`（以便落入 `smallbin[4]`）、`bk = &_IO_list_all - 0x10`。
   - vtable 指针指向一块受控堆区域，其中在 `__overflow` 偏移处放 `system`。
   - `_IO_write_ptr > _IO_write_base` 且 `_mode <= 0`，以通过 `_IO_flush_all_lockp` 的检查。

7. **触发：** 调用 `add()`，其大小会使 `malloc` 遍历 unsorted bin。unsorted bin 攻击把 `main_arena+0x58` 写到 `_IO_list_all`。在排序过程中，伪造 chunk 落入 `smallbin[4]`，可通过 `_IO_list_all->_chain->_chain` 到达。当 `_IO_flush_all_lockp` 遍历这条链时（经由 `exit()` 或 `malloc_printerr`），会调用 `_IO_OVERFLOW(fake_file)` → `system("/bin/sh")`。

**触发变体：**
- **`exit()`（菜单选项 5）：** exp.py 使用这种方式——更干净，不需要 abort。
- **`malloc_printerr`：** 多数解法触发一次 unsorted bin 破坏，进而调用 `abort()` → `_IO_flush_all_lockp`。在 glibc 2.23 中，`abort()` 会刷新 IO。某些 libc 构建（比如 pwnable.tw 的这份）在 abort 时**不会**刷新，因此需要用 `exit()`。

---

### 路径 B —— House of Orange 配合扩展的 top chunk 操纵

**使用者：** 解法 194、1297、1316、1395、1986

部分解法完全避开越界索引技巧，而是反复放大 top chunk 破坏以伸入堆的更深处：

1. 按上述方式执行 House of Orange。
2. 拿到 unsorted bin 之后，**再次扩展旧 top chunk 的大小**（第二次 `strlen` 技巧），以重叠更多 chunk。
3. 利用重叠区域直接写入伪造的 `_IO_FILE`，无需索引 8 的别名。

这个变体更复杂，但不依赖 V2。

---

### 路径 C —— House of Orange → unsorted bin 攻击 → 覆盖 `__malloc_hook`

**使用者：** 解法 1177、1303

部分解法不用 FSOP，而是用 unsorted bin 攻击改写另一个目标：

1. 执行 House of Orange 并拿到 libc 泄露。
2. 用 unsorted bin 攻击把一个受控指针写入 `__malloc_hook`（或其附近位置）。
3. 在 `__malloc_hook` 处放一个 `one_gadget` 地址。
4. 触发 `malloc` → `one_gadget` → shell。

由于 unsorted bin 攻击只会写入 `main_arena+0x58`（并非任意值），这种做法需要更精细的堆布局。解题者会把它与额外的破坏手段串联，把 `one_gadget` 送进 `__malloc_hook`。

---

### 路径 D —— 把 author 缓冲区当作伪造 chunk / vtable 宿主

**使用者：** 解法 138、194、1177

由于 author 缓冲区位于固定的 BSS 地址（`0x602060`），部分解法：

1. 用 `information()` 配合 “change author” 把受控数据写进 author 缓冲区。
2. 让伪造 `_IO_FILE` 的 vtable 指向 `0x602060`（author 缓冲区）。
3. 在 author 缓冲区内正确的 vtable 偏移处放入 `system`。

这利用了无 PIE 的特性，得到一个可预测的 vtable 地址，无需做堆相对计算。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 堆地址泄露 | V3：author 的 `printf` 溢出读进 `page_ptrs[0]` | 确定性 |
| top chunk 大小破坏 | V1：`edit()` 中基于 `strlen` 的大小放大 | 确定性 |
| 把旧 top 释放进 unsorted bin | 经 `sysmalloc` 实现的 House of Orange | 确定性（大小正确时） |
| libc 泄露 | 读 unsorted bin chunk 的 `fd`/`bk` | 确定性 |
| 巨大堆写入 | V2：越界索引，`page_sizes[0]` = 堆指针 | 确定性 |
| 覆盖 `_IO_list_all` | unsorted bin 攻击（`bk->fd = main_arena+0x58`） | 确定性 |
| 代码执行 | FSOP：`_IO_OVERFLOW` → `system("/bin/sh")` | 确定性 |

## top chunk 大小的关键约束

破坏 top chunk 大小时，它必须满足（`sysmalloc` 会检查）：

```text
1. (old_top + old_size) must be page-aligned (0x1000)
2. old_size > MINSIZE (0x20)
3. old_size has PREV_INUSE bit set (LSB = 1)
4. old_size < requested_size (so sysmalloc triggers)
```

各解法常用的取值（取决于分配偏移）：

| Chunk 相对页起始的偏移 | top chunk 大小 | 备注 |
|------------------------|---------------|-------|
| `0x30`（大小 0x18+元数据） | `0xfd1` | 最常见 |
| `0x30` | `0xfe1` | 另一种对齐 |
| `0x20`（大小 0x18） | `0xfe1` | |
| `0x120` | `0xed1` | 初始分配较大之后 |
| `0x220` | `0xde1` | |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
main_arena_off  = 0x3c3b20    # main_arena (unsorted bin = main_arena + 0x58 + 0x10)
__malloc_hook   = 0x3c3b10
_IO_list_all    = 0x3c4520
system          = 0x45390
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# unsorted bin leak: leaked_ptr - 0x3c4188 = libc_base  (or - 0x3c3b78 depending on chunk)
```

## 题解文章

| 文件 | 路径 | 关键技术 | 备注 |
|------|------|---------------|-------|
| `138.md` | A + D | FSOP，vtable 在堆上，`_wide_data` 技巧 | Ruby；用 author 存放 vtable 数据 |
| `185.md` | A | 通过 `_IO_list_all` 的 FSOP，大小为 0 的索引技巧 | 干净的 Python2；引用 angelboy 博客 |
| `194.md` | B | 扩展 top chunk，不用索引 8 技巧 | 用较大的初始分配做第二次 top 破坏 |
| `1172.md` | A | 标准 FSOP，`page_sizes[0]` 技巧 | 简洁；对约束条件有良好注释 |
| `1177.md` | A + C | unsorted bin → author 缓冲区作为伪造 chunk → `__malloc_hook` | 用 BSS 地址作为伪造 chunk 的 fd/bk |
| `1297.md` | B | 反复扩展 top，重叠多个 chunk | 复杂的多阶段堆操纵 |
| `1303.md` | A + C | FSOP + 通过 `__malloc_hook` 使用 `one_gadget` | 使用 unsorted bin 破坏链 |
| `1316.md` | B | 大分配实现重叠，`_IO_str_jumps` vtable | 用 `_IO_str_jumps-8` 绕过 vtable 检查 |
| `1351.md` | A | 标准 FSOP，用前导 NUL 字节重置大小 | |
| `1689.md` | A | 通过直接堆重叠实现 FSOP | 紧凑；内联构造 vtable |
| `1829.md` | A | 使用自定义 `_wide_data` 的 FSOP | |
| `1922.md` | A | 标准 FSOP | 干净，日志良好 |
| `1980.md` | A | FSOP，详细标注 `_IO_FILE` 字段 | 教学向：标注了每个结构字段 |
| `1986.md` | A | FSOP，指出 `scanf` 内部会调用 malloc | 提示：`scanf` 内部会 malloc |
| `2121.md` | A | FSOP，vtable 放在 heap+offset 处 | |
| `10840.md` | A | 干净的 Python3 利用 | |
| `17006.md` | A | 紧凑的 FSOP | |
| `18324.md` | A | FSOP，指出可靠性问题 | |
| `21260.md` | A | FSOP，详细计算 vtable | |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的利用脚本（自包含，不依赖 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/bookwriter` | 题目二进制（x86-64，stripped） |
| `artifacts/libc_64.so.6` | 远程 libc（glibc 2.23） |
| `solution/*.md` | 社区题解（90 篇） |
