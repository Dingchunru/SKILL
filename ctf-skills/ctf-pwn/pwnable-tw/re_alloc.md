---
tags:
  - use-after-free
  - tcache-poisoning
  - got-overwrite
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.29
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "向 realloc 传入 0 会释放 chunk 却不清空指针，进而在 glibc 2.29 上做 tcache poisoning，用 system 覆盖 GOT 表项。"
proof-of-concept: no
---

# Re-alloc — pwnable.tw（200 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10106`

## 题目概况

一道堆菜单题（x86-64，Partial RELRO、NX、栈 canary、**No PIE**、FORTIFY），链接的是 **glibc 2.29**。程序对两个堆槽（`heap[0]` 和 `heap[1]`）提供 allocate、reallocate、free 三个操作，核心分配器用的是 `realloc()`。关键点在于：在 glibc 2.29 中 `realloc(ptr, 0)` 等价于 `free(ptr)`，但程序**没有把堆表里的指针清空** —— 这构成了 Use-After-Free。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO        # GOT 可写
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
  FORTIFY:  Enabled
```

## 程序逻辑（伪代码）

```c
void *heap[2];  // global pointer table at 0x4040B0

void allocate() {
    int idx = read_long();           // idx must be 0 or 1
    if (heap[idx]) { puts("..."); return; }
    long size = read_long();
    heap[idx] = realloc(NULL, size); // equivalent to malloc(size)
    read_input(heap[idx], size);     // read_input has off-by-null
}

void reallocate() {
    int idx = read_long();
    if (!heap[idx]) { puts("..."); return; }
    long size = read_long();
    heap[idx] = realloc(heap[idx], size);  // size=0 → free, but ptr stays!
    if (heap[idx])
        read_input(heap[idx], size);
}

void rfree() {
    int idx = read_long();
    if (!heap[idx]) { puts("..."); return; }
    realloc(heap[idx], 0);   // free, BUT heap[idx] NOT cleared!
    heap[idx] = NULL;        // ... wait, it IS cleared here
}

// read_long uses __read_chk → atoll(buf) to parse integers
```

## 漏洞

### V1 — Reallocate 中 `realloc(ptr, 0)` 造成的 Use-After-Free

**根因：** 在 glibc 2.29 中，`realloc(ptr, 0)` 会释放 chunk 并返回 `NULL`。在 `reallocate()` 里，返回值（`NULL`）被写回 `heap[idx]`，槽位因此被清零。而 `rfree()` 同样调用 `realloc(ptr, 0)` —— 关键差别在于 `reallocate()` **可以在同一个下标上再次调用**，因为释放之后 `heap[idx] = NULL`，随后的 `realloc(NULL, new_size)` 就等价于 `malloc(new_size)`。

UAF 正是由这条序列产生的：
```python
alloc(0, 0x18, "AAAA")       // heap[0] = chunk_A
realloc(0, 0)                 // free(chunk_A), heap[0] = NULL
                              // chunk_A is now in tcache[0x20]
realloc(0, 0x18, payload)    // realloc(NULL, 0x18) = malloc(0x18)
                              // returns chunk_A (from tcache)
                              // heap[0] = chunk_A again
                              // payload overwrites tcache fd pointer
```

`alloc` 用 `if (heap[idx])` 来阻止重复分配，但 `realloc(0,0)` 已经把 `heap[idx]` 清空，于是可以通过精心地轮换槽位，在另一个槽仍然引用同一块内存时释放 chunk，实现经典的 **tcache poisoning** UAF。

**影响：** 通过篡改 tcache 的 fd 指针实现任意写 → 可写任意地址（例如 GOT 表项）。

### V2 — `atoll` 的 GOT 可写（Partial RELRO + No PIE）

**根因：** Partial RELRO 且无 PIE，GOT 位于固定的已知地址。`read_long()` 调用 `atoll()` 把用户输入的字符串转成整数。把 `atoll@GOT` 覆盖为 `printf@PLT` 后，之后每次 `read_long()` 都变成 `printf(用户输入)` —— 整数输入就此变身**格式化字符串攻击**。

```text
Key GOT/PLT addresses (fixed, no PIE):
  atoll@GOT   = 0x404048
  printf@PLT  = 0x401070
  realloc@GOT = 0x404058
  heap table  = 0x4040B0
```

### V3 — `read_input` 的 off-by-null（次要）

`read_input` 在 `buf[size]` 处补 NUL，会写到已分配区域之后一个字节。主利用一般用不到这一点，但有解题者提到过。

## 利用路径

所有解法都遵循两阶段策略：（1）用 tcache poisoning 覆盖 GOT；（2）借助这次 GOT 覆盖完成泄漏并拿 shell。

---

### 路径 A — Tcache Poison → `atoll@GOT = printf` → 格式化字符串泄漏 → `atoll@GOT = system` → `system("/bin/sh")`

**使用范围：** 约 90% 的解法（1006、1832、16991、17048、17704、18324、18331、18416、19131、21490、21778、22377、25572、26467、28302、exp.py）

**阶段一：Tcache Poisoning 覆盖 `atoll@GOT`**

1. 在槽 0 分配一个 chunk，用 `realloc(0, 0)` 释放，再 `realloc(0, 同尺寸, p64(atoll_got))` 把 tcache 的 fd 指针改成 `atoll@GOT`。
2. 在槽 1 分配，把 tcache 里原本那个 chunk 取走。
3. 清理两个槽（realloc 成别的尺寸再 free，把 chunk 挪到其他 bin）。
4. 此时该 size class 的 tcache 链下一个节点就是 `atoll@GOT`。
5. 再次分配 —— 该 tcache 的第二次分配返回指向 `atoll@GOT` 的指针。
6. 把 `printf@PLT`（0x401070）写进 `atoll@GOT`。

不少解法会针对**两个不同的 size class**（比如 0x20 和 0x50 的 tcache bin）各做一次，这样后面还留有一次干净的覆盖机会。

**阶段二：格式化字符串泄漏**

`atoll@GOT` 指向 `printf` 之后，每次 `read_long()` 都会执行 `printf(用户输入)`：
```python
# Trigger printf as "atoll" — leak libc via format string
free("%3$p")       # printf("%3$p") leaks a stack value
# or
free("%21$p")      # leaks __libc_start_main return address
# or
free("%23$p")      # another common offset for libc leak
```

常见的栈上泄漏偏移：
- `%3$p` → `__read_chk` 的返回地址（相对 libc 基址偏移 `0x12e009`）
- `%21$p` / `%23$p` → `__libc_start_main+235`（相对 libc 基址偏移 `0x26b6b`）
- `%9$s` + GOT 地址 → 用 `%s` 格式实现任意读

**阶段三：用 `system` 覆盖 `atoll@GOT`**

泄漏到 libc 后，再次覆盖 `atoll@GOT`，写入 `system()`：

```python
# Since atoll is now printf, we need to carefully craft inputs
# that make printf return the right values for idx/size
alloc("", "%88c", p64(libc.sym['system']))  # or similar trick
```

棘手之处在于：现在 `printf` 是 idx/size 的解析器，它的**返回值**（打印的字符数）会被当作解析出的整数。解题者用特定长度的格式化字符串来控制"下标"和"尺寸"的取值。

**阶段四：Shell**

```python
# Any call to read_long() with "/bin/sh" now calls system("/bin/sh")
free("/bin/sh")   # → system("/bin/sh")
```

---

### 路径 B — Tcache Poison → `realloc@GOT = printf` → 格式化字符串 → ROP

**使用范围：** 解法 1006（变体）、27939

不覆盖 `atoll@GOT`，而是把 `realloc@GOT` 覆盖为 `printf@PLT`。这样每次 `reallocate()` 都成为格式化字符串攻击，但由于 `realloc` 的第一个参数是堆指针（充当格式化字符串），控制流会复杂得多。

有些解法把 `realloc@GOT` 覆盖成 `atoll@PLT`（让 realloc 按堆地址上的 ASCII 内容返回一个指针），从而实现 GOT 层面的跳转。

一个更高级的变体（27939）借此用 `leave; ret` gadget 做栈迁移，执行完整的 ROP 链。

---

### 路径 C — Tcache Poison → GOT 覆盖 → `__malloc_hook = one_gadget`

**使用范围：** 解法 18331、18324

在最初的 `atoll → printf` 覆盖之后，用 `%n` 格式化字符串写把 `__malloc_hook` 覆盖成 one_gadget 地址。这样就省去了第二次 tcache poison：

```python
# Use %hn writes to set __malloc_hook byte-by-byte
free("%{}c%{}$hn".format(low_2bytes, offset))   # write 2 bytes at a time
```

随后触发 `malloc` 即可跳到 one_gadget。

---

### 路径 D — `atoll → printf` + `%n` 清空堆表 → 第二次 Tcache Poison

**使用范围：** exp.py（随题提供的 exploit）

1. 第一次 tcache poison：`atoll@GOT = printf@PLT`。
2. 用 `printf("%9$n", ...)` 这类格式化字符串把 `heap[0]`/`heap[1]` 表项和 tcache 元数据**清零**，重置分配器状态。
3. 做**第二次** tcache poison（此时"atoll"已是 `printf`，下标/尺寸直接用原始字节传递）。
4. 用 `system` 覆盖 `atoll@GOT`。
5. `free("/bin/sh")` → `system("/bin/sh")`。

这种做法更复杂，但完全确定，不依赖 `printf` 返回值的技巧。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| Use-After-Free | V1：reallocate 中的 `realloc(ptr, 0)` | 确定性 |
| Tcache fd 污染 | UAF → 覆盖已释放 chunk 的 fd | 确定性 |
| 任意 GOT 写 | tcache 返回指向 GOT 的指针 | 确定性（无 PIE） |
| 格式化字符串（泄漏） | `atoll@GOT = printf` → `printf(用户输入)` | 确定性 |
| 格式化字符串（写入） | 通过 printf 做 `%n` / `%hn` 写 | 确定性 |
| 代码执行 | `atoll@GOT = system` → `system("/bin/sh")` | 确定性 |

## 关键地址（无 PIE）

```python
# Binary (fixed)
atoll_got    = 0x404048
printf_plt   = 0x401070
printf_got   = 0x404038
realloc_got  = 0x404058
alarm_got    = 0x404040
heap_table   = 0x4040B0   # heap[0], heap[1]

# Libc offsets (glibc 2.29, pwnable.tw)
__libc_start_main = 0x26B6B   # offset for %21$p leak
__read_chk_ret    = 0x12E009  # offset for %3$p leak
system            = 0x52FD0
__malloc_hook     = 0x1E4C30
__free_hook       = 0x1E6E48
one_gadgets       = [0xE6E73, 0xE6E76, 0xE6E79, 0x106EF8]
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `1006.md` | A | tcache poison → printf → 经 realloc GOT 打 one_gadget | 用 GOT 表当格式化字符串缓冲区 |
| `1763.md` | — | "Same exploit with re-alloc-revenge" | 仅作参考 |
| `1832.md` | A | tcache poison → printf 泄漏 → system | 干净写法，用 `%15$p` 泄漏 |
| `16609.md` | A | prepare() 辅助函数整理 tcache 状态 | 辅助函数结构清晰 |
| `16991.md` | A | 双 bin tcache poison + `%9$s` 读 GOT | 用 `%s` 直接读 GOT 表项 |
| `17048.md` | B | 同时覆盖 alarm/atoll/signal/realloc 的 GOT | 有创意的多 GOT 覆盖 |
| `17704.md` | A | `atoll → printf`、`%15$p` 泄漏、覆盖 system | 紧凑；顺带覆盖 realloc GOT 夺回控制 |
| `18324.md` | A+C | `%n` 格式化写 `__malloc_hook` | 逐字节写 one_gadget |
| `18331.md` | A | 简洁的漏洞分析 + exploit | 提到 off-by-null 和 UAF |
| `18416.md` | A | 双 size class tcache poison | 对 0x20 与 0x50 两个 bin 各打一次 |
| `19131.md` | A | `%9$s` 读 GOT 再打 system | 用格式化字符串直接泄漏 GOT |
| `21490.md` | A | 标准套路 | 代码清晰 |
| `21778.md` | A | 提到"准备工作"的难点 | 坦言 tcache 布置是照抄的 |
| `22377.md` | A | 双 bin poison（0x30 + 0x60） | `%3$p` 泄漏偏移 0x12e009 |
| `25572.md` | A | 栈偏移枚举循环 | 扫遍所有栈偏移找 libc |
| `26467.md` | A | `%p` 链式泄漏、`%15c` 控制尺寸 | 极简套路 |
| `27939.md` | B | GOT 跳转 + 栈迁移 + ROP 链 | 最复杂；用 leave/ret 走完整 ROP |
| `28302.md` | A | 格式化字符串覆盖 GOT + `%n` | 详细的栈偏移分析 |
| `exp.py` | D | `%n` 清状态 → 第二次 tcache poison | 最稳健；完全确定 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit（tcache poison + 格式化字符串 + 第二次 poison） |
| `desc.txt` | 题目描述 |
| `artifacts/re-alloc` | 题目二进制（x86-64，glibc 2.29） |
| `solution/*.md` | 社区 writeup（83 份解法） |
