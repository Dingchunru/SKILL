---
tags:
  - heap-buffer-overflow
  - unsorted-bin-attack
  - house-of-orange
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.24
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "食谱解析中的堆溢出破坏了堆元数据，进而触发 House of Orange 并改写 glibc 2.24 中的 _IO_FILE 跳转表。"
proof-of-concept: no
---

# Food Store — pwnable.tw（500 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10406`
>
> Flag: `FLAG{C4ptur3_th3_Fl4g_c4ptuR3_the_f00d}`

## 题目概览

一个菜单驱动的“食材店”游戏二进制（x86-64，PIE，Full RELRO，NX，栈 Canary），运行在 Ubuntu 17.04 + glibc 2.24（无 tcache）。玩家管理食谱、烹饪菜肴、在商店买卖食材、完成 NPC 委托，赚取等级/能力/金钱。seccomp 沙箱只允许 `open`/`read`/`write`/`close`/`mmap`/`munmap`/`exit`——没有 `execve`。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO            # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  Seccomp:  open/read/write/close/mmap/munmap/exit only
```

### 关键结构

```c
struct recipe {            // 0x90 bytes (malloc'd)
    char name[24];         // +0x00  (scanf "%23s")
    ingredient *ings[13];  // +0x18  (pointers to ingredient structs)
    recipe *next;          // +0x80  (singly-linked list)
};

struct ingredient {        // 0x30 bytes (calloc'd or custom)
    char name[32];         // +0x00
    int price;             // +0x20
    int quantity;          // +0x24
};

struct dish {              // 0x40 bytes (malloc'd when cooking)
    char name[24];         // +0x00
    int price;             // +0x18
    int energy;            // +0x1c
    dish *next;            // +0x20  (singly-linked list)
};
```

## 漏洞

### V1 — `recipe->next` 指针未初始化（主漏洞，可利用）

**根因：** `add_recipe()` 用 `malloc(0x90)` 分配新的 recipe 结构体后，偏移 `+0x80` 处的 `next` 指针**从未被初始化**。若该堆块此前被使用并释放过，该区域会残留陈旧的堆元数据（fd/bk 指针）或用户控制的数据。

```c
// add_recipe (simplified)
recipe *r = malloc(sizeof(recipe));  // 0x90 bytes
scanf("%23s", r->name);             // name is written
// ... ingredient pointers are set ...
// r->next is NEVER set to NULL
recipe_head->next = r;              // inserted into linked list with stale next
```

**影响：** 通过精心安排分配与释放的顺序，让 0x90 字节的堆块被复用时在 `+0x80` 处留存受控数据，攻击者即可让 `recipe->next` 指向任意地址。由此获得：

- **伪造链表节点**：`show_recipe()` 和 `remove_recipe()` 会遍历被破坏的链表，读写/释放攻击者指定的地址。
- **任意释放**：`remove_recipe()` 会释放攻击者指定地址上的伪造 recipe 堆块。
- **堆/libc/栈泄漏**：伪造节点的食谱名与食材数据会被打印出来，从而泄漏指针。

### V2 — 分配尺寸交叠（使能条件）

dish 结构体是 0x40 字节，recipe 是 0x90 字节。先烹饪菜品再释放，然后分配 recipe（或反过来），可以安排不同大小的堆块，使 recipe 的 `next` 字段与先前释放的 dish 或 ingredient 堆块中写入的数据发生交叠。

### V3 — 经商店触发的食材类型混淆（次要，用于刷钱/能力）

制作一个自定义食材后购买同一个槽位，自定义食材（带随机高价）会替换标准食材。用该食材烹饪能得到价值大量金钱与能量的菜品，从而支撑后续所需的刷取。

## 利用路径

所有解法都需要大量“刷游戏”来积累等级、能力和金钱，以完成足够的分配。flag 文件由程序预先打开为 fd 3，且 seccomp 禁止 `execve`，因此所有路径最终都是一条 ORW（open/read/write）ROP 链去读 flag。

---

### 路径 A — 未初始化 `next` → 堆/libc 泄漏 → `__free_hook` = `setcontext` → ORW ROP

**相关题解：** 370、8153、31599、37709

**步骤：**

1. **刷取：** 烹饪、进食、完成委托，升到 4 级以上并攒够钱。
2. **堆泄漏：** 安排分配/释放顺序，使某个 recipe 未初始化的 `next` 指向一个含堆地址的已释放堆块。`show_recipe()` 或烹饪菜单会把它当食谱标题打印出来 → **堆基址**。
3. **libc 泄漏：** 让伪造 recipe 的食材列表指向一个已释放的 large/unsorted bin 堆块（含 `main_arena` 指针）。食材显示或食谱标题会泄漏一个 libc 地址 → **libc 基址**。
4. **ORW ROP 布局：** 创建多个 recipe，每个 24 字节名字里放 2 个 ROP gadget，再加一个 `add rsp, 0x60; pop; pop; pop; ret` 滑板把它们串起来。
5. **覆盖 `__free_hook`：** 借未初始化 next 技巧把 `__free_hook - 0x80` 链入 recipe 链表。`remove_recipe()` 对这个伪造 recipe 做“unlink”时，会把一个堆指针写入 `__free_hook`，随后把它覆盖成 `setcontext+0x35`。
6. **触发：** 释放一个 `+0xa0` 字段指向 ROP 链的堆块。`setcontext` 迁移 rsp → ORW ROP 执行 → `read(3, buf, 0x100)` + `write(1, buf, 0x100)` → flag 输出到 stdout。

---

### 路径 B — 未初始化 `next` → 劫持 `_dl_open_hook` → `gets` → ORW ROP

**相关题解：** 2311、22319、31599（替代方案）

1. **堆 + libc 泄漏：** 同路径 A（未初始化 `next` → bin 指针泄漏）。
2. **写-任意地址：** 未初始化 next 原语可以在任何含零的地址写入一个堆指针。目标选 `_dl_open_hook`（`dlopen`/abort 过程中使用的函数指针表）。
3. **触发 abort：** 释放一个非法/伪造的堆块地址 → glibc 检测到损坏 → 调用 `__libc_message` → `backtrace` → `_dl_open_hook->dlopen_mode()` → 受控调用。
4. **迁移 + `gets`：** 受控调用命中类似 `call [rax+0x48]` 的 gadget，该偏移处放 `gets`。`gets()` 把 ORW ROP 链读到栈/堆上 → flag。

---

### 路径 C — 未初始化 `next` → `__realloc_hook` = `leave; ret` → 栈迁移 → ORW ROP

**相关题解：** 8153、37709

1. **泄漏堆 + libc**：同样用未初始化 next 技巧。
2. **把 `__realloc_hook - 0x80` 链入 recipe 链表。** 借 `remove_recipe()` 的 unlink 把 `leave; ret` gadget 写到 `__realloc_hook`。
3. **在堆区准备 ROP payload**（recipe 名字 + `gets` 地址）。
4. **触发 `realloc(ptr, 0)`：** `remove_recipe` 内部会调用 `realloc` → `__realloc_hook` 生效 → `leave; ret` 把 rsp 迁移到一条基于堆的 ROP 链，链中包含 `gets`。
5. **`gets` 读入最终的 ORW ROP** → `read(3, heap, 0x100)` + `write(1, heap, 0x100)` → flag。

---

### 路径 D — Unsorted Bin Attack → 破坏 `stdin->_IO_buf_end` → 覆盖栈 → ORW ROP

**相关题解：** 1351、755

1. **泄漏堆 + libc**：用未初始化 next。
2. **Unsorted bin attack：** 把 unsorted bin 的 `bk` 破坏为 `stdin->_IO_buf_end - 0x10`。下一次从 unsorted bin 分配时会把 `main_arena` 地址写到 `_IO_buf_end`，从而把 stdin 的内部缓冲区扩展到覆盖一大片可写区域。
3. **栈泄漏：** 用扩展后的 stdin 缓冲区，或经伪造 recipe 读 `__environ`，泄漏栈地址。
4. **经 stdin 覆盖栈：** 下一次 `scanf` 会越过原缓冲区边界读取，直接写到栈上。把 `leave; ret` + ORW ROP 链注入到返回地址区域。
5. **返回 → ROP → flag。**

---

### 路径 E — 对 flag FILE 调 `fclose` 的 FSOP → `_IO_str_overflow` → `setcontext` → ORW ROP

**相关题解：** 821、36997、2972

1. **泄漏堆 + libc**：用未初始化 next。
2. **释放 flag FILE 结构体：** 让伪造 recipe 链表指向预先打开的 flag 的 `FILE *`（在堆上）。`remove_recipe()` 把它释放进 unsorted bin。
3. **在被释放的 FILE 上重新分配：** 用 `make_ingredient`（商店菜单）分配与已释放 FILE 结构体重叠的堆块。伪造一个 `_IO_FILE_plus`：
   - vtable 指向 `_IO_str_jumps - 0x10`（使 `__overflow` 槽 → `setcontext+0x35`）
   - `_IO_buf_base` 设为含 ROP 链的堆地址
4. **触发 `fclose` 或 `exit`：** 程序退出时调用 `fclose(f_flag)` → `_IO_OVERFLOW` 经伪造 vtable 派发 → `setcontext` 迁移栈 → ORW ROP → flag。

---

### 路径 F — 把 `stdin->fd` 从 0 改成 3 → `scanf` 直接读 flag

**相关题解：** 408

1. **泄漏堆 + libc**：用未初始化 next + 食材类型混淆。
2. **破坏食材指针：** 造一个地址与 `stdin->fd - 0x24` 重叠的食材（使食材的 `quantity` 字段与 `stdin->fd` 互为别名）。
3. **递增 `stdin->fd`：** 逛商店触发“补货”操作，递增 quantity 字段，把 fd 从 0 变成 3。
4. **`add_recipe` 中的 `scanf("%23s")`** 现在从 fd 3（flag 文件）而非 stdin 读取 → flag 变成食谱名 → 由 `show_recipe()` 打印出来。

**优雅之处：** 该路径完全不用 ROP——只改 `stdin->fd` 一个字节，就让 flag 出现在食谱标题里。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 未初始化的 `recipe->next` | V1：malloc 的 0x90 堆块中残留的堆数据 | 确定性（需精心堆布局） |
| 链表中出现任意地址 | V1 的应用：经先前分配控制 `next` | 控制堆布局后 |
| 堆地址泄漏 | 伪造链表节点 → 作为食谱标题打印 | 确定性 |
| libc 泄漏 | 伪造 recipe 中的 unsorted/large bin fd/bk | 确定性 |
| 任意释放 | 对伪造链表节点调 `remove_recipe()` | 破坏链表后 |
| 代码执行 | `__free_hook`/`__realloc_hook`/`_dl_open_hook`/FSOP | 泄漏后确定性 |
| 读取 flag | ORW ROP（seccomp 禁止 execve） | 确定性 |

## 偏移（Ubuntu 17.04 libc 2.24-9ubuntu2.2）

```python
main_arena       = 0x3C1B00
__free_hook      = 0x3C3788
__realloc_hook   = 0x3C3778  # (also __memalign_hook - 0x10)
_dl_open_hook    = 0x3C6F48
setcontext       = 0x48045   # mov rsp, [rdi+0xa0]; ...; ret
pop_rdi          = 0x1FD7A
pop_rsi          = 0x1FCBD
pop_rdx          = 0x1B92
pop_rax          = 0x3A998
syscall_ret      = 0xBC765   # syscall; cmp rax, -0xfff; jae; ret
add_rsp_0x60_pop3 = 0xF8766  # add rsp, 0x60; pop rbx; pop rbp; pop r12; ret
leave_ret        = 0x424A5
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `370.md` | A | 未初始化 next → large bin 泄漏 → `__realloc_hook` + `setcontext` → ORW | 用 ctypes 预测 RNG 以把握委托时机 |
| `821.md` | E | 未初始化 next → 释放 flag FILE → FSOP `_IO_str_overflow` → `setcontext` | 释放 `f_flag` FILE 结构体，伪造 vtable |
| `2311.md` | B | 未初始化 next → `_dl_open_hook` → 触发 abort → `gets` → ORW | 向 `_dl_open_hook` 写堆指针，用坏释放触发 |
| `755.md` | D | 未初始化 next → unsorted bin attack → 破坏 `stdin->_IO_buf_end` → 栈 ROP | 扩展 stdin 缓冲区以覆盖栈 |
| `408.md` | F | 食材类型混淆 → 改 `stdin->fd` 0→3 → scanf 读 flag | 优雅：不用 ROP，flag 变成食谱标题 |
| `1351.md` | D | 未初始化 next → unsorted bin attack → stdin 破坏 → 栈覆盖 | 与 755 类似，布局不同 |
| `8033.md` | A | 未初始化 next → `__free_hook` = `gets` → 栈迁移 → ORW | 把 `__free_hook` 覆盖为 `gets`，再读 ROP |
| `8153.md` | A | 未初始化 next → `__free_hook` = `setcontext` → ORW | 路径 A 的干净实现 |
| `9251.md` | B + C | 未初始化 next → `_dl_open_hook` → `setcontext` → `gets` → ORW | 用 `authdes_marshal` gadget 作调用原语 |
| `22319.md` | B | 未初始化 next → `_dl_open_hook` → `setcontext+53` → `gets` → ORW | 从堆上的 `_IO_2_1_stderr_` 泄漏 libc |
| `31599.md` | A | 未初始化 next → large bin 泄漏 → 经 unlink 写 `__free_hook` → `setcontext` → ORW | 详尽，把 ORW 拆散在多个食谱标题里 |
| `36134.md` | B | 未初始化 next → `_dl_open_hook` → `gets` → ORW | 造自定义食材实现高价/高能力 |
| `36997.md` | E | 未初始化 next → 释放 flag FILE → FSOP → `setcontext` → ORW | `_IO_str_overflow` 配伪造 vtable |
| `37709.md` | C | 未初始化 next → `__realloc_hook` = `leave; ret` → 堆迁移 → `gets` → ORW | 经 `__realloc_hook` 中 `leave; ret` 做栈迁移 |
| `2972.md` | E | 未初始化 next → 释放 flag FILE → FSOP `_IO_str_overflow` → `setcontext` | 与 821 类似，堆喷射实现 FILE 重叠 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用利用脚本（socket 实现，流水线化以应对 60 秒 alarm） |
| `desc.txt` | 题目描述 |
| `artifacts/food_store` | 原始题目二进制 |
| `solution/*.md` | 社区题解文章（15 个解法） |
