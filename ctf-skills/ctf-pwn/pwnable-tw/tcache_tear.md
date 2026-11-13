---
tags:
  - double-free
  - tcache-poisoning
  - arbitrary-write
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.27
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "tcache 中的双重释放可把任意内存地址链进 tcache 链表，在 __free_hook 上伪造 chunk 从而执行 system。"
proof-of-concept: no
---

# Tcache Tear — pwnable.tw（200 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10207`
>
> Flag：`FLAG{tc4ch3_1s_34sy_f0r_y0u}`

## 题目概况

一个简单的堆笔记程序（x86-64，No PIE、Full RELRO、NX、Canary、FORTIFY），链接 **glibc 2.27**（带 tcache）。程序提供四个操作：malloc+写入、free、info（打印名字）、exit。程序先把 0x20 字节的"Name"存到 `0x602060` 的 BSS 缓冲区，然后进入菜单循环，全局只跟踪一个堆指针。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO            # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)     # fixed addresses in BSS
  FORTIFY:  Enabled
```

### 菜单操作

| 选项 | 行为 |
|--------|--------|
| 1 — Malloc | `malloc(size)`，`size <= 0xFF`，往 chunk 里读 `size` 字节，指针存到 `0x602088` |
| 2 — Free | `free(ptr)` —— 释放 `0x602088` 处的 chunk，**不**把指针置空 |
| 3 — Info | 用 `write(1, name, 0x20)` 打印 `0x602060` 处 Name 缓冲区的 0x20 字节 |
| 4 — Exit | 调用 `exit(0)` |

### 关键 BSS 布局

```text
0x602040  stdout (pointer to _IO_2_1_stdout_)
0x602060  Name buffer (0x20 bytes, written once at start)
0x602080  [padding]
0x602088  last_malloc_ptr (the single tracked heap pointer)
```

## 漏洞

### V1 — Tcache 双重释放（主要，可 Exploit）

**根因：** free 操作在释放之后**不**把 `0x602088` 的全局指针置空。glibc 2.27 的 tcache 没有双重释放检测（不查 key/count），因此同一个 chunk 可以被释放两次。

```c
// Pseudocode for free operation
void do_free() {
    free(*(void **)0x602088);  // frees chunk
    // pointer NOT zeroed — still points to freed chunk
}
```

**影响：** 经典的 tcache 双重释放 → tcache poisoning。双重释放之后，同一个 chunk 在 tcache 空闲链表里出现两次。再把它分配回来就能改写它的 `fd` 指针为任意地址，使后续分配返回受控地址。

### V2 — 小尺寸下的堆溢出（可 Exploit）

**根因：** malloc 操作往 chunk 里读 `size` 字节，而 `size < 0x10` 时实际分配仍是 `malloc(size)`（最小 chunk 0x20）。`read` 用的是**用户给的尺寸**而不是实际 chunk 尺寸。另外，名字缓冲区的首次 `read` 和数据读取在某些代码路径下都允许写入超过名义大小的数据。

更关键的是，很多解法利用的是：先 `malloc(0)` 或很小的尺寸，再写入大段载荷 —— `read(0, buf, size)` 在 size=0 时立即返回，但 `0x602088` 处的数据缓冲区仍指向那个 chunk，后续操作（尤其是在 BSS 里伪造 chunk）依靠的是固定的 BSS 布局，而不是堆溢出本身。

**影响：** 能写入大段载荷（伪造的 chunk 头、padding），用于在 BSS 中布置 unsorted bin chunk。

### V3 — 固定的 BSS 地址（把 Name 缓冲区当假 chunk）（助攻）

**根因：** 没有 PIE，`0x602060` 的 Name 缓冲区和 `0x602088` 的指针都是**固定已知地址**。攻击者可以：
1. 程序启动时把伪造的 chunk 元数据写进 Name 缓冲区
2. 用 tcache poisoning 让分配的 chunk 与 Name 缓冲区重叠
3. 在 BSS 里伪造大 chunk（unsorted bin 尺寸），从而让 libc 指针被写入那里

```c
// At startup:
write(1, "Name:", 5);
read(0, name_buf, 0x20);  // name_buf = 0x602060
// Attacker writes: p64(0) + p64(0x501)  → fake chunk header
```

## 利用路径

所有解法都用 V1（tcache 双重释放）做 tcache poisoning，区别在于**如何泄漏 libc**和**覆盖什么来实现代码执行**。

---

### 路径 A — Tcache Poisoning → 在 BSS 伪造 unsorted bin chunk → 泄漏 libc → `__free_hook`

**使用范围：** 多数解法（exp.py、138、1177、1297、1316、1351、1763、10178、11631、11699、13060、14032、14334、14479、14826、15522、16609 等）

这是主流做法（约占 90%）。

**步骤：**

1. **在 Name 缓冲区布置伪造 chunk 头。** 在 "Name:" 提示处发送 `p64(0) + p64(0x501)`（或其他大尺寸，如 `0x421`、`0x511`、`0x531`）。这会在 `0x602060` 处放下假 chunk 头，尺寸大于 tcache 上限（glibc 2.27 为 0x408），保证它被释放时进入 unsorted bin。

2. **Tcache poison 在 BSS 上拿到分配。** 对 tcache 尺寸的 chunk 做双重释放：
   ```python
   malloc(0x80, "A")
   free()              # chunk goes to tcache
   free()              # same chunk in tcache again (double-free)
   malloc(0x80, p64(target_bss_addr))  # overwrite fd with BSS address
   malloc(0x80, "dummy")               # consume first copy
   malloc(0x80, payload)               # returns BSS address — write fake chunk body
   ```

3. **写入假 chunk 主体 + 下一个 chunk 的头。** 放在 BSS 地址处的载荷必须包含：
   - 假 chunk 主体（padding 填满声明尺寸）
   - 一个合法的"下一个 chunk"，其 `PREV_INUSE` 已置位（以通过 `free()` 的合并检查）
   - 覆盖 `last_malloc_ptr`（`0x602088`），指向 `0x602060+0x10` 处的假 chunk

4. **释放这个假 chunk。** 由于尺寸超过 tcache 上限，它进入 **unsorted bin**。glibc 会把 `main_arena+96` 写进该 chunk 的 `fd` 和 `bk` 字段 —— 而这两个字段此刻与 Name 缓冲区重叠。

5. **经 Info 泄漏 libc。** 调 Info（选项 3），它会打印 Name 缓冲区的 0x20 字节。从名字起点 `+0x10` 处的 `fd`/`bk` 指针里就能读到 `main_arena+96`。计算 `libc_base = leaked_value - 0x3ebca0`。

6. **Tcache poison 覆盖 `__free_hook`。** 对另一个 tcache bin 再做一次双重释放：
   ```python
   malloc(0x50, "A"); free(); free()
   malloc(0x50, p64(libc + __free_hook))
   malloc(0x50, "dummy")
   malloc(0x50, p64(libc + system))  # or one_gadget
   ```

7. **触发 shell。**
   - `malloc(0x30, "/bin/sh\x00"); free()` → 经被 hook 的 `free` 调用 `system("/bin/sh")`。
   - 或把 `one_gadget` 写进 `__free_hook`/`__malloc_hook` 再触发。

**可靠性：** 100% 确定 —— BSS 地址固定，不需要爆破 ASLR。

---

### 路径 B — Tcache Poisoning → `_IO_2_1_stdout_` FSOP 泄漏 → `__free_hook`

**使用范围：** 解法 11968、13424

这个变体不伪造 unsorted bin chunk，而是破坏 `stdout` 的 FILE 结构来泄漏 libc。

**步骤：**

1. **Tcache poison 指向 `stdout` 指针。** 用双重释放把 chunk 分配到 `0x602040`（BSS 中类似 GOT 的 `stdout` 指针）处，改写 `_IO_2_1_stdout_` 地址的低字节来重定向它，或者直接把 tcache 污染到 `_IO_2_1_stdout_` 上分配。

2. **破坏 `_IO_2_1_stdout_` 的 flags 和写指针。** 写入：
   ```python
   p64(0xFBAD1800) +  # _flags: _IO_MAGIC | _IO_IS_APPENDING | _IO_CURRENTLY_PUTTING
   p64(0) * 3 +       # _IO_read_ptr, _IO_read_end, _IO_read_base = 0
   b'\x00'             # partial overwrite of _IO_write_base → leak from lower address
   ```

3. **接收 libc 泄漏。** 下一次经 stdout 的 `write` 会从 libc 数据段泄出内容，给出一个 libc 指针。

4. **收尾与路径 A 相同：** `__free_hook = system`，然后 `free("/bin/sh")`。

**可靠性：** 若 ASLR 随机化了 `_IO_2_1_stdout_` 地址的 nibble，可能需要约 1/16 的字节爆破。

---

### 路径 C — Tcache Poisoning → 经 `__free_hook` 调 `printf` → 格式化字符串 → `system`

**使用范围：** 解法 13424

一个有创意的两阶段做法：

1. **部分覆盖 BSS 中的 `stderr` 指针**，让它指向 `__free_hook` 附近（需要对 ASLR 做 1 字节爆破）。
2. **经 tcache poisoning 把 `printf@plt` 写进 `__free_hook`**。
3. **`malloc` 一个装着格式化字符串（`%23$lx`）的 chunk**，再 `free()` 它 → `printf("%23$lx")` 从栈上泄漏一个 libc 返回地址。
4. **解析泄漏值**，算出 `system` 地址，再次用 `system` 覆盖 `__free_hook`。
5. **`free("/bin/sh\x00")` → shell。**

**可靠性：** 约 1/16（4 位 ASLR 爆破）。

---

### 路径 D — 堆溢出 + Unsorted Bin Attack（变体）

**使用范围：** 解法 1324

有些解法不走"tcache 污染到 BSS"，而是用小尺寸分配造成的堆缓冲区溢出去改写相邻 tcache chunk 的元数据，再转入 unsorted bin 泄漏。

**步骤：**
1. 分配不同尺寸的 chunk，造出相邻的 tcache 项。
2. 借小尺寸分配的溢出改写相邻已释放 chunk 的 `fd` 指针。
3. 把分配重定向到 BSS 或其他受控区域。
4. 继续做 libc 泄漏和 `__free_hook` 覆盖。

---

### 路径 E — 操纵 Tcache 结构体

**使用范围：** 解法 138

这种做法直接改写 **`tcache_perthread_struct`**（堆起始处的每线程 tcache 元数据），从而直接操控各 bin 的计数和链头：

1. Tcache poison 到 tcache struct 上分配。
2. 把某个 bin 的计数设成很大的值（让 tcache 自认为"已满"）。
3. 此后该尺寸的释放会走 fastbin/unsorted bin 而不是 tcache → 泄漏 `main_arena` 指针。
4. 再配合 `_IO_2_1_stdout_` 的 FSOP 技巧泄漏 libc。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| Tcache 双重释放 | V1：free 后不置空指针 | 确定性 |
| Tcache poisoning（任意分配） | V1 + glibc 2.27 无 tcache 检查 | 确定性 |
| 在 BSS 伪造 unsorted bin chunk | V3：无 PIE + Name 缓冲区 | 确定性 |
| 经 unsorted bin fd/bk 泄漏 libc | 释放假 chunk → Info | 确定性 |
| 经 `_IO_2_1_stdout_` 泄漏 libc | FSOP 部分覆盖 | 约 1/16 爆破 |
| 覆盖 `__free_hook` | tcache poisoning 到 hook 地址 | 确定性 |
| 代码执行 | `free("/bin/sh")` → `system` | 确定性 |

## 偏移（远端 libc，glibc 2.27）

```python
# libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so
main_arena  = 0x3EBC40    # main_arena+96 = 0x3EBCA0
__free_hook = 0x3ED8E8
__malloc_hook = 0x3EBC30
system      = 0x4F440
one_gadgets = [0x4F2C5, 0x4F322, 0x10A38C]

# BSS (No PIE)
name_buf    = 0x602060
last_ptr    = 0x602088
stdout_ptr  = 0x602040
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `exp.py` | A | tcache dup → BSS 里伪造 0x421 chunk → 泄漏 → `__free_hook` = one_gadget | 干净的参考 exploit |
| `138.md` | E | 操纵 tcache struct → FSOP stdout 泄漏 | Ruby；最复杂的做法 |
| `1177.md` | A | 伪造 0x701 chunk → unsorted bin 泄漏 → `__free_hook` = system | 标准套路 |
| `1297.md` | A | 在 BSS+0x98 伪造 0x91 chunk → 泄漏 → `__free_hook` = one_gadget | 紧凑 |
| `1316.md` | A | 伪造 0x431 chunk → 循环填充 → `__free_hook` = system | 注释详细 |
| `1324.md` | D | 堆溢出改 tcache fd → BSS 假 chunk | 溢出变体 |
| `1351.md` | A | 伪造 0x501 chunk → one_gadget | 极简 |
| `1763.md` | A | 伪造 0x511 chunk → `__free_hook` = system | 极简 |
| `10178.md` | A | 伪造 0x501 chunk → `__free_hook` = system | 用 ptrlib |
| `11631.md` | A | 伪造 0x501 chunk → `__free_hook` = one_gadget | 标准做法 |
| `11968.md` | B | 覆盖 stdout → FSOP 泄漏 libc → `__free_hook` = system | 不需要假 chunk |
| `13060.md` | A | tcache dup → 伪造 0x421 chunk → one_gadget | 干净 |
| `13424.md` | C | 爆破 stderr → free_hook 写 `printf@plt` → 格式化字符串泄漏 → system | 两阶段；有创意 |
| `14032.md` | A | 伪造 0x111 chunk → one_gadget | 假 chunk 较小 |
| `14334.md` | A | 0x500 unsorted chunk → 详细讲解 | 注释最全 |
| `14479.md` | A | 伪造 0x531 chunk → one_gadget | 标准，附 flag |
| `14826.md` | A | 伪造 0x461 chunk → `__free_hook` = system | 用 `malloc(0, payload)` |
| `15522.md` | A | 伪造 0x501 chunk → one_gadget | 标准 |
| `16609.md` | A | 伪造 0x418 chunk → system | 结构清晰 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit（不依赖 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/tcache_tear` | 原始题目二进制（stripped，x86-64） |
| `solution/*.md` | 社区 writeup（128 份解法） |
