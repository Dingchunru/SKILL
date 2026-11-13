---
tags:
  - use-after-free
  - double-free
  - tcache-poisoning
  - io-file-exploit
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.29
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "只有两个分配槽时，利用 realloc(ptr, 0) 双重释放做 tcache poisoning，污染 _IO_2_1_stdout_ 并劫持 __free_hook。"
proof-of-concept: no
---

# Re-alloc Revenge — pwnable.tw（350 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10310`
>
> Flag：`FLAG{r3alloc_the_heap_r3alloc_the_file_Str34m_r3alloc_my_lif3}`

## 题目概况

一道堆菜单题（x86-64，Full RELRO、PIE、NX、Canary、FORTIFY），链接 **glibc 2.29**（Ubuntu 2.29-0ubuntu2）。程序只有两个堆槽（`heap[0]`、`heap[1]`），单次分配上限 `0x78` 字节，且**没有任何查看/打印功能**。所有分配底层都用 `realloc()` —— 连"释放"操作也是 `realloc(ptr, 0)`。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO          # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

## 程序逻辑

| 菜单 | 操作 | 行为 |
|------|--------|----------|
| 1 Alloc | `allocate(idx, size, data)` | 要求 `heap[idx] == NULL`；`size <= 0x78`；`malloc(size)` + `read_input` |
| 2 Realloc | `reallocate(idx, size, data)` | 要求 `heap[idx] != NULL`；`size <= 0x78`；`realloc(ptr, size)` |
| 3 Free | `rfree(idx)` | 先 `realloc(heap[idx], 0)` 再 `heap[idx] = NULL` |
| 4 Exit | | |

## 漏洞

### V1 — `realloc(ptr, 0)` 造成的 UAF / 悬垂指针（主要）

**根因：** `reallocate` 函数（菜单项 2）调用 `realloc(heap[idx], size)`。当 `size == 0` 时，glibc 的 `realloc` 行为等同于 `free(ptr)` 并返回 `NULL`。程序检查了返回值 —— 因为它是 `NULL`，就把这次调用当成"失败"，于是**没有清空 `heap[idx]`**：

```c
// reallocate (simplified)
void *p = realloc(heap[idx], size);
if (p == NULL) {
    // "failure" path — heap[idx] NOT cleared
    return;
}
heap[idx] = p;  // only reached if realloc succeeded
```

相比之下，干净的 `rfree`（菜单项 3）同样调用 `realloc(ptr, 0)`，但**无条件**把 `heap[idx]` 置 0。

**影响：** 执行 `realloc(idx, 0)` 之后，`heap[idx]` 里留着指向已释放 chunk 的悬垂指针。由此可得：
- **UAF 写**：`realloc(idx, 原尺寸, data)` 会写进已释放的 chunk（修改它在 tcache 中的 `fd` 指针）。
- **双重释放**：再次 `realloc(idx, 0)` 会把同一个 chunk 再 free 一次（需要先清掉 tcache 的 `key` 字段以绕过 glibc 2.29 的双重释放检测）。

### V2 — `allocate` 中的 off-by-one NUL（次要，助攻）

`allocate` 里的 `read_input` 在 `buf[nread]` 处补一个 NUL 字节。当恰好发送 `size` 字节（不带换行）时，这个 `\x00` 会写到 chunk 可用区之后一个字节 —— 一个**poison null byte**，可以破坏下一个 chunk 的 size 字段。

## 关键限制

- **只有 2 个槽**（`heap[0]`、`heap[1]`）—— 极大限制了堆操作空间，必须巧妙地用 `realloc` 做尺寸调整、切分、合并。
- **最大 0x78** —— 所有分配都落在 tcache bin（0x20–0x80）内。要拿到 libc 指针，得设法把 chunk 送进 unsorted/smallbin。
- **没有输出原语** —— 没有"查看"或"打印"功能。泄漏只能靠 FSOP（覆盖 `_IO_2_1_stdout_`）。
- **Full RELRO** —— GOT 只读。必须打 hook（`__free_hook`、`__malloc_hook`、`__realloc_hook`）。
- **glibc 2.29** —— tcache 带有用于检测双重释放的 `key` 字段（通过 UAF 覆盖它来绕过）。

## 关键技术：两个槽下的 Tcache Poisoning

只有 2 个槽时的 write-what-where 原语：

```python
alloc(0, 0x78)                      # allocate chunk P (tcache bin 0x80)
realloc(0, 0)                       # free P → tcache[0x80] = [P], heap[0] = P (dangling)
realloc(0, 0x78, p64(target_addr))  # UAF write: P.fd = target_addr
alloc(1, 0x78)                      # pop P from tcache; entries[0x80] = target_addr
realloc(1, 0x28)                    # shrink P to 0x30, remainder goes to different bin
free(1)                             # free P(0x30) → tcache[0x30]; heap[1] = NULL
alloc(1, 0x78, payload)             # pops target_addr from tcache[0x80] → write payload there
```

窍门在于：把 P 从 tcache 取出后，先**改成另一个尺寸**再释放，这样 tcache[0x80] 的链头仍然指向 `target_addr`。

## 利用路径

51 份解法核心策略一致（V1 UAF → tcache poison → stdout 泄漏 → 覆盖 hook），区别主要在于如何取得 libc 指针。

---

### 路径 A — 伪造大 chunk → Unsorted Bin → 部分覆盖 stdout（最常见）

**使用范围：** 解法 821、2972、3025、3148、6923、7905、8153、9074、9251、9448、15522、17006、20719、26250、31599、34817、exp.py

**步骤：**

1. **伪造一个大 chunk**（size 在 `0x421`–`0x811` 之间），用 `realloc` 调整尺寸时把伪造的 size 字段写进相邻 chunk。伪造 chunk 必须足够大以绕过 tcache（> 0x408 字节，或把 tcache 计数填满到 7）。

2. **释放这个伪造 chunk**，让它进入 **unsorted bin**。这会把 `main_arena` 指针（libc 地址）写进该 chunk 的 `fd`/`bk` 字段。

3. **部分覆盖** `fd` 指针（低 2 字节），把它改指向 `_IO_2_1_stdout_`（或 `stdout - 8`）。由于 libc 按页对齐，第 4 个 nibble（第 12–15 位）是随机的 → **1/16 爆破**。

4. **在 stdout 处分配**，把它的 `_flags` 改成 `0xfbad1800`，并把 `_IO_read_ptr`、`_IO_read_end`、`_IO_read_base` 清零。下一次 `puts()`（菜单输出）就会泄漏 libc 内存。

5. **由泄漏算出 libc 基址**：`libc_base = leaked_ptr - 0x1e7570`。

6. **Tcache poison** 把某个 bin 指向 `__free_hook - 8`（或 `__realloc_hook`），在那里写入 `"/bin/sh\0" + p64(system)`。

7. **触发**：`free(idx)` → `realloc(heap[idx], 0)` → `__realloc_hook(heap[idx], 0)` = `system("/bin/sh")`。

**变体 —— 填满 tcache + `malloc_consolidate`：** 有些解法把某个尺寸的 tcache 填到 7 条（反复用 `realloc(0)/realloc(size)` 的 UAF），然后向菜单发送超长输入（`"1" * 0x400`）触发 `malloc_consolidate`。fastbin 中的 chunk 会合并进 smallbin，于是无需伪造大 chunk 就能拿到 libc 指针。

---

### 路径 B — 污染 Tcache 的 `perthread_struct`（1/16 或 1/256）

**使用范围：** 解法 821、3480、6247、15522（1/256 变体）、34817

**步骤：**

1. **双重释放**（借 UAF）得到一个 `fd` 可被改写的 tcache chunk。

2. **部分覆盖 `fd`** 为 `\x10\x60`（或按堆布局用 `\x10\x90`、`\x10\xa0`），指向 **`tcache_perthread_struct`**（堆内偏移约 0x10）。这对堆 ASLR 的 nibble 是 **1/16 爆破**。

3. **把 tcache struct 当作普通 chunk 分配出来** → 完全掌控所有 tcache bin 的计数和链头指针。

4. **把所有计数设为 0xff**（或 0x07）→ 此后释放任何 chunk 都会绕过 tcache 直接进 unsorted bin（因为 tcache 看起来已满）。

5. **释放 tcache struct 本身** → 进入 unsorted bin → libc 指针落到该结构体里。

6. **部分覆盖** unsorted bin 的 `fd` 指向 `_IO_2_1_stdout_` → FSOP 泄漏（又一次 1/16 爆破，本路径总计 1/256）。

7. 收尾与路径 A 相同：覆盖 hook → shell。

---

### 路径 C — 反复 UAF 填满 Tcache + Smallbin 合并

**使用范围：** 解法 9251、26250、34817

不伪造任何 chunk 尺寸的更干净变体：

1. 反复执行 `realloc(0)` + `realloc(size)` 的 UAF 循环，把某个尺寸的 **tcache 填到 7 条**（每轮释放同一个 chunk，两次释放之间把 `key` 清掉）。

2. **触发 `malloc_consolidate`**：向菜单发送超长输入（`sla("choice: ", "1"*0x400)`）。fastbin 中的 chunk 合并进 smallbin → 出现 libc 指针。

3. **UAF 改写** smallbin 的 `fd` → 部分覆盖到 stdout → FSOP 泄漏。

4. 收尾同上：覆盖 hook → shell。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| UAF / 悬垂指针 | V1：`realloc(ptr, 0)` 返回 NULL，槽位未清空 | 确定性 |
| Tcache fd 覆盖 | UAF + `realloc(idx, size, payload)` | 确定性 |
| 双重释放 | UAF + 清 `key` 字段 + 再次 `realloc(idx, 0)` | 确定性 |
| Unsorted/smallbin libc 指针 | 伪造大 chunk，或填满 tcache 后合并 | 确定性（堆布置） |
| Stdout FSOP 泄漏 | 部分覆盖 fd → `_IO_2_1_stdout_` | **1/16 爆破** |
| 控制 tcache struct | 部分覆盖 fd → `tcache_perthread_struct` | **1/16 爆破** |
| 任意写 | 两槽缩容技巧下的 tcache poisoning | 泄漏后确定性 |
| 代码执行 | `__free_hook = system` 或 `__realloc_hook = system/one_gadget` | 任意写后确定性 |

## 偏移（glibc 2.29，Ubuntu 2.29-0ubuntu2）

```python
_IO_2_1_stdout_  = 0x1e5760
_IO_file_jumps   = 0x1e7570   # common leak delta
system           = 0x52fd0
__free_hook      = 0x1e75a8
__realloc_hook   = 0x1e4c28
__malloc_hook    = 0x1e4c30
main_arena_top   = 0x1e4ca0
one_gadgets      = [0xe21ce, 0xe21d1, 0xe21d4, 0xe237f, 0xe2383, 0x106ef8]
```

## Hook 目标对比

| 目标 | 触发方式 | 参数 |
|--------|--------------|----------|
| `__free_hook` | `rfree(idx)` → 内部 `realloc(heap[idx], 0)` 会调用 `free()` | `heap[idx]`（设成 `"/bin/sh"`） |
| `__realloc_hook` | 任意 `realloc()` 调用 | `(heap[idx], size)` —— 第一个参数就是那个指针 |
| `__malloc_hook` | `alloc(idx, size)` 触发 `malloc()` | `size` 参数（用处较小） |

多数解法打 `__free_hook - 8`，写入 `"/bin/sh\0" + p64(system)`，再 `free(idx)` 即调用 `system("/bin/sh")`。也有解法把 `__realloc_hook` 换成 one_gadget。

## 题解文章

| 文件 | 路径 | 爆破 | 关键技术 |
|------|------|-----------|---------------|
| `exp.py` | A | 1/16 | 伪造 0x431 chunk → unsorted bin → 部分覆盖 stdout |
| `821.md` | B | 1/16 | 污染 tcache struct → unsorted bin → stdout |
| `1763.md` | A | 1/16 | 极简 tcache poison → stdout |
| `2972.md` | A | 1/16 | 伪造 0x4d1 chunk → 部分覆盖 stdout |
| `3025.md` | A | 1/16 | 伪造 chunk + 部分写 `__free_hook` |
| `3148.md` | A | 1/16 | 标准伪造 chunk + stdout FSOP |
| `3480.md` | B | 1/16 | tcache struct → unsorted bin → stdout；另有 1/256 变体 |
| `6247.md` | A | 1/16 | chunk spray + 伪造 0x811 → 部分覆盖 |
| `6249.md` | A | 1/16 | 控制 tcache struct + 伪造 unsorted chunk |
| `6923.md` | A | 1/16 | tcache struct + 覆盖 `__free_hook` |
| `7905.md` | A | 1/16 | 中文详细分析；伪造 0x431、stdout FSOP |
| `8153.md` | A | 1/16 | 技巧解析；记录了 1/16 与 1/256 两种变体 |
| `9074.md` | A | 1/16 | 用 0x91/0x81 尺寸的伪造 chunk 辗转进 unsorted bin |
| `9251.md` | A | 1/16 | tcache perthread struct + 覆盖 stdout |
| `9448.md` | B | 1/256 | 双重爆破：堆 + libc 的 nibble |
| `15522.md` | B | 1/256 | tcache struct + unsorted bin + 部分写 |
| `20719.md` | A | 1/16 | 伪造 0xa1 chunk + 用 UAF 填满 tcache |
| `26250.md` | C | 1/16 | 详细解说，stdout 偏移取 0xe7 |
| `31599.md` | A | 1/16 | 干净解法，结构与 3025 相同 |
| `34817.md` | C | 1/16 | 填满 tcache + 超长菜单输入触发 `malloc_consolidate` |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit（纯 socket，不用 pwntools，爆破自动重试） |
| `desc.txt` | 题目描述 |
| `artifacts/` | 原始二进制与 libc |
| `solution/*.md` | 社区 writeup（51 份解法） |
