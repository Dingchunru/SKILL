---
tags:
  - use-after-free
  - information-leak
  - fastbin-dup
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
description: "牢房笔记管理中的 use-after-free 可泄露堆与 libc 指针，随后通过 fastbin 重复分配覆盖 __malloc_hook。"
proof-of-concept: no
---

# Break Out — pwnable.tw（350 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10400`

## 题目概览

一个监狱管理二进制（x86-64，PIE、Full RELRO、NX、Stack Canary），链接 glibc 2.23（没有 tcache）。它从冒号分隔的文件加载囚犯数据库，并提供命令：`list` 列出囚犯、为囚犯写 `note`（使用 `realloc`）、`punish` 惩罚囚犯（释放其 note）。关键防御机制是 `secure_read()`：它在启动时解析 `/proc/self/maps` 构建可写区域白名单，每次向 note 缓冲区 `read()` 都会对照该白名单校验——只允许写入 **[heap]** 区域。这意味着普通的堆溢出永远无法直接触达 libc/GOT/hook。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

题目提供两个文件：`breakout`（主二进制）和 `prisoner`（数据库文件）。

## 关键数据结构

### 囚犯结构（0x40 字节，链表）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00` | `risk` | `char *`（指向静态字符串） |
| `0x08` | `name` | `char *` |
| `0x10` | `nickname` | `char *` |
| `0x14` | `age` | `int32_t` |
| `0x18` | `cell` | `int32_t` |
| `0x20` | `sentence` | `char *` |
| `0x28` | `note_size` | `int32_t` |
| `0x2c` | `pad` | `int32_t` |
| `0x30` | `note` | `char *`（经 `realloc` 分配） |
| `0x38` | `next` | `struct prisoner *` |

囚犯保存在单向链表中。`note` 命令调用 `realloc(prisoner->note, size)`，并通过 `secure_read` 写入。`punish` 命令调用 `free(prisoner->note)` 却**不清空指针**——这是典型的悬垂指针。

### 白名单（`secure_read` 防御）

在启动时，`secure_self()` 解析 `/proc/self/maps`，把 `[heap]` 区域的起止地址存入 BSS 全局变量（`dst_whitelist`）。每次 `secure_read()` 都会校验目标缓冲区是否落在这个范围内。这样就阻止了直接写 libc、栈或 BSS。

## 漏洞

### V1 —— `punish` 中的 use-after-free / 悬垂指针

**根因：** `punish(cell)` 调用 `free(prisoner->note)`，但**没有**把 `prisoner->note` 置为 `NULL`，也没有把 `prisoner->note_size` 清零。

**影响：**
- **UAF 读：** 释放之后，`list` 仍会打印 note 内容，泄露堆元数据（被释放 chunk 的 fd/bk 指针）。
- **通过 realloc 重叠实现 UAF 写：** 由于结构指针数组和 note 缓冲区都在堆上，对某个囚犯的 note 调用 `realloc` 可能分配出与已释放囚犯结构重叠的内存，从而完全控制另一个囚犯的字段（name、note 指针、next 指针、note_size）。

### V2 —— 通过操纵 `next` 指针伪造囚犯

**根因：** 实现 V1 重叠之后，攻击者可以把某个囚犯的 `next` 指针设为任意含有受控数据的堆地址。`list` 命令会沿链表遍历，打印伪造囚犯的字段，包括它的 `note` 指针（用于读取）以及 `name`/`risk`（用于显示——即泄露原语）。

**影响：** 把 `next` 指向一个精心构造的伪造囚犯结构，可以：
- 把 `note` 设为任意地址 → `list` 泄露其内容
- 把 `note_size` 设为受控值 → 后续 `note` 命令写到任意的 `note` 地址
- 这在**堆内**提供任意读写；配合进一步技巧还能扩展到堆外。

## 利用路径

所有解法都以 V1（UAF）取得堆控制起步，然后在如何**绕过 `secure_read`** 向堆外写入上分道扬镳。

---

### 路径 A —— unsorted bin 攻击 → 覆盖 `dst_whitelist` → `__realloc_hook` = `system`

**使用者：** 解法 59、278、408、exp.py 变体

**步骤：**

1. **泄露堆基址：** 通过 `punish` 释放一个囚犯结构，然后对另一个囚犯用 `note` 分配进这个已释放的结构。`list` 会从重叠的结构字段中泄露堆指针。

2. **泄露 PIE 基址：** 用伪造囚犯技巧（V2）读取某个已知囚犯的 `risk` 字段——它指向二进制中某个固定偏移的字符串（如 `"High"`）→ 得到 PIE 基址。

3. **泄露 libc 基址：** 有了 PIE 基址后，让伪造囚犯的 `note` 指向某个 GOT 表项（如 `got["mprotect"]`）→ `list` 泄露已解析的地址 → 得到 libc 基址。

4. **通过 unsorted bin 攻击绕过 `secure_read`：**
   - 伪造一个囚犯，其 `next` 指向 BSS 中 `dst_whitelist` 附近。
   - 用 unsorted bin 攻击（把 unsorted bin chunk 的 `bk` 覆盖为 `&dst_whitelist - 0x10`）把一个 `main_arena` 地址写到 `dst_whitelist` 上。
   - 现在 `secure_read` 会认为整个 libc 数据段都可写。

5. **覆盖 `__realloc_hook`：** 让伪造囚犯的 `note` 指向 `__realloc_hook`，通过 `note` 写入 `system`。

6. **触发：** 找一个 note 内容为 `"/bin/sh\0"` 的囚犯——对它调用 `realloc` 就会触发 `__realloc_hook(system)` → shell。

---

### 路径 B —— House of Orange（通过 `_IO_list_all` 实现 FSOP）

**使用者：** 解法 57、186、1303、1980、2233、2972、3025、3917、8153、9251

**步骤：**

1. **泄露堆 + libc：** 与路径 A 的第 1–3 步相同（UAF 重叠 → 伪造囚犯 → 读取指针）。

2. **在堆上伪造 unsorted bin chunk：** 用伪造囚犯的 `note` 写入，构造一个伪造的 unsorted bin chunk，满足：
   - `fd = 0`（让 unsorted bin 遍历崩溃）
   - `bk = &_IO_list_all - 0x10`（unsorted bin 攻击目标）
   - size 字段设为 `0x61`（匹配 smallbin[4]）
   - 前 8 字节 = `"/bin/sh\0"`

3. **构造伪造的 `_IO_FILE_plus` 结构：** 内嵌在 chunk 头之后：
   - `_IO_write_ptr > _IO_write_base`（触发 overflow 路径）
   - `_mode = 0` 或 `_mode = -1`
   - `vtable` → 指向堆上的伪造 vtable
   - 伪造 vtable 的 `__overflow` 槽 → `system`

4. **触发：** 任意一次对 unsorted bin 做排序的 `malloc`（或 `exit()`）→ glibc 遍历 `_IO_list_all` → 找到伪造 FILE → 调用 `vtable->__overflow(file)` → `system("/bin/sh")`。

**说明：** 这只需要堆写入，因此完全绕过 `secure_read`——无需破坏白名单。

---

### 路径 C —— fastbin 攻击 → 覆盖 `__malloc_hook`

**使用者：** 解法 6923、21490、31599、exp.py

**步骤：**

1. **泄露堆 + libc：** 同样的 UAF 技巧。

2. **fastbin 布局调整：** 借助伪造囚犯的 note 指针操纵制造重叠 chunk。释放一个 `0x70` 大小的 chunk，然后用写原语把它的 `fd` 指针覆盖为 `__malloc_hook - 0x23`（glibc 2.23 经典的 `0x7f` 伪造大小技巧）。

3. **沿 fastbin 分配：** 两次 `malloc(0x60)`——第二次会返回位于 `__malloc_hook - 0x23` 的伪造 chunk。

4. **写入 hook：** 填充 0x13 字节到达 `__realloc_hook`，然后写入：
   - `__realloc_hook = one_gadget`（例如 `0xf0567`）
   - `__malloc_hook = __libc_realloc + 0xb`（`push rbp` 入口，它会调整栈，从而使 `[rsp+0x70] == NULL` 满足 one_gadget 的约束）

5. **触发：** 下一次 `malloc` → `__malloc_hook` → `realloc(+0xb)` → `__realloc_hook` → one_gadget → shell。

**白名单绕过：** 关键洞察在于 `realloc` 会先把旧内容拷贝到新 chunk。预先把 payload 放在旧 note 里（位于堆上，能通过 `secure_read`），再触发 `realloc` 到一个会在 `__malloc_hook` 处分配的大小，拷贝操作就会把 payload 写入 libc 内存——从而绕过 `secure_read`，因为 `realloc` 内部的 `memcpy` 不经过白名单检查。

---

### 路径 D —— 覆盖 `_IO_file_jumps` / stdout vtable

**使用者：** 解法 363、786

**步骤：**

1. **泄露 libc：** 通过 UAF + 伪造囚犯读取。

2. **伪造一个囚犯**，其 `next` 指向 libc 中的 `_IO_file_jumps(stdout) - 0x30`。这样伪造囚犯的 `note_size`/`note` 字段就与 stdout 的 vtable 指针区域重叠。

3. **覆盖 `stdout` 的 vtable 指针**，指向堆上受控的伪造 vtable，并把其中 `__xsputn` 或 `__overflow` 槽设为 one_gadget 或 `system`。

4. **触发：** 任何 `puts`/`printf` 输出（例如 `list`）都会用到被破坏的 vtable → shell。

---

### 路径 E —— large bin 攻击 → `_dl_open_hook` + ROP

**使用者：** 解法 8033

**步骤：**

1. **泄露全部地址：** 通过标准 UAF 链获取堆、PIE、libc 地址。

2. **large bin 攻击：** 构造 large bin chunk，然后把某个 large bin chunk 的 `bk_nextsize` 改坏为 `_dl_open_hook - 0x10`。在下一次插入 large bin 时，`_dl_open_hook` 会被一个堆地址覆盖。

3. **在堆上准备 ROP 链：** 用 `setcontext+53` 作为栈 pivot gadget，ROP 链调用 `execve("/bin/sh", NULL, NULL)`。

4. **触发 `abort`：** 破坏某个 chunk 的元数据，引发 glibc 断言失败 → `abort()` → 使用 `_dl_open_hook` → 跳到堆上 → 栈 pivot → ROP 链 → shell。

---

### 路径 F —— 用 `note_size = malloc_size` 技巧打到 `__free_hook`

**使用者：** 解法 3917

**步骤：**

1. **伪造一个囚犯**，其 `next` 指向 `__free_hook - 0x28`。在伪造囚犯的布局中，`note_size` 字段与 `__free_hook` 的高位字节重叠，`note` 字段与 `__free_hook` 重叠。

2. **把 `one_gadget` 写入 `__free_hook`**：对伪造的 cell 调用 `note`——此时 `realloc` 会以 `size = note_size`（即 hook 地址的高位，被当作整数）调用。这会触发一次很大的分配 → 旧 note 被释放 → `__free_hook` 被触发。

3. **另一种做法：** 每次 2 字节地写入 one_gadget 地址，即调用 `note(cell, oneshot_low16, "A")`，它会执行 `realloc(note, low16)`——大小本身就是地址片段，会被写进与 `__free_hook` 重叠的 `note_size` 位置。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 堆指针泄露 | V1：UAF + `list` 读取被释放 chunk 的元数据 | 确定性 |
| PIE 基址泄露 | V2：伪造囚犯的 `risk`/`name` → 二进制字符串指针 | 确定性 |
| libc 泄露 | V2：伪造囚犯的 `note` → GOT 表项，或 unsorted bin 的 fd/bk | 确定性 |
| 任意堆读写 | V2：伪造囚犯 + 受控的 `note`/`note_size` | 确定性 |
| 绕过白名单（House of Orange） | 路径 B：只需堆写入，无需破坏白名单 | 约 50%（取决于堆对齐） |
| 绕过白名单（unsorted bin 攻击） | 路径 A：覆盖 BSS 中的 `dst_whitelist` | 确定性 |
| 绕过白名单（fastbin + realloc 拷贝） | 路径 C：`realloc` 的 memcpy 绕过 `secure_read` | 确定性 |
| 代码执行 | `__realloc_hook`/`__malloc_hook`/`__free_hook` 或 FSOP | 绕过之后确定性 |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
__malloc_hook  = 0x3c3b10
__realloc_hook = 0x3c3b08
__free_hook    = 0x3c57a8
_IO_list_all   = 0x3c4520
system         = 0x45390
one_gadgets    = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# realloc + 0xb (push rbp trampoline for one_gadget stack fix)
realloc_tramp  = 0x83b1b
# Binary offsets
str_High       = 0x1c28       # "High" string in .rodata
whitelist_bss  = 0x203030     # dst_whitelist pointer in .bss
got_mprotect   = 0x202ed8
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `57.md` | B（House of Orange） | UAF → 伪造囚犯 → 构造 unsorted bin → FSOP | 需要 libc 基址低位为负 |
| `59.md` | A（unsorted bin） | UAF → 泄露全部 → unsorted bin 覆盖白名单 → `__realloc_hook` | 详细解释了 bug |
| `186.md` | B（House of Orange） | 仅靠堆写入的简单 House of Orange | 用重试循环保证可靠性 |
| `278.md` | A（unsorted bin） | Ruby 利用；UAF → 绕过白名单 → `__realloc_hook = system` | 干净的结构操纵 |
| `363.md` | D（stdout vtable） | 覆盖 stdout 的 `_IO_file_jumps` 指针 → one_gadget | 不需要堆技巧 |
| `408.md` | A（unsorted bin） | UAF → unsorted bin `bk` → 白名单 → `__realloc_hook` | 针对 binmap 的堆整理 |
| `786.md` | D（stdout vtable） | 伪造囚犯 `next` → libc FILE vtable 区域 → one_gadget | 只靠应用逻辑 |
| `1303.md` | B（House of Orange） | 完整 FSOP，详细伪造 `_IO_FILE_plus` 布局 | 远程堆偏移很折腾 |
| `1980.md` | C（fastbin） | UAF → 栈泄露 → PIE 泄露 → fastbin 攻击 → one_gadget | 通过 `environ` 泄露 |
| `2121.md` | C（fastbin） | 经典的 fastbin 打到 `__malloc_hook - 0x23` | 标准的 0x7f 技巧 |
| `2233.md` | B（House of Orange） | unsorted bin → `_IO_list_all` → FSOP → `system("/bin/sh")` | |
| `2972.md` | B（House of Orange） | 紧凑的 House of Orange 实现 | |
| `3025.md` | B（House of Orange） | “题目简单，远程环境难拿 shell” | 远程堆偏移问题 |
| `3917.md` | F（`__free_hook`） | 伪造囚犯 `next` → `__free_hook - 0x28` → 每次 2 字节写入 one_gadget | 很有创意的 `note_size` 滥用 |
| `6923.md` | C（fastbin） | UAF → 重叠 chunk → fastbin fd → `__malloc_hook` → one_gadget | |
| `8033.md` | E（large bin） | large bin 攻击 → `_dl_open_hook` → `setcontext` 栈 pivot → ROP | 最复杂的路径 |
| `8153.md` | B（House of Orange） | 通过 `_IO_list_all` 实现 FSOP | 中文题解 |
| `9251.md` | B（House of Orange） | UAF → 伪造囚犯 → House of Orange FSOP | |
| `13344.md` | B（House of Orange） | 通过伪造 FILE 实现 FSOP；用 `environ` 泄露全部地址 | 干净的 Python3 利用 |
| `21490.md` | C（fastbin） | fastbin + realloc 拷贝绕过 `secure_read` | `realloc` 的 `memcpy` 是关键 |
| `31599.md` | C（fastbin） | UAF → fastbin → `__malloc_hook` → `realloc_tramp` + one_gadget | 标准的 hook 链 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的利用脚本（fastbin + realloc hook 链） |
| `desc.txt` | 题目描述 |
| `artifacts/breakout` | 题目二进制（stripped，PIE） |
| `artifacts/prisoner` | 囚犯数据库文件 |
| `artifacts/libc_64.so.6` | 远程 libc（glibc 2.23） |
| `solution/*.md` | 社区题解（72 篇） |
