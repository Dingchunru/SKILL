---
tags:
  - stack-exhaustion
  - heap-overlap
  - arbitrary-write
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
description: "耗尽 mmap 分配的 split-stack 段会让 libgcc morestack 把动态栈分配与堆缓冲区重叠，从而可以覆盖返回地址。"
proof-of-concept: no
---

# BabyAllocator — pwnable.tw (500 分)

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10404`
>
> Flag: `FLAG{Spl1t_st4ck_spl1t_h34p_th3n_spl1t_7h3_sh3ll}`

## 题目概览

一个用 GCC **`-fsplit-stack`** 特性编译的、已 strip 的 x86-64 二进制，链接 glibc 2.23。split-stack 机制使用 `libgcc/generic-morestack.c` 中的 `__morestack` / `__morestack_allocate_stack_space`，在当前栈段耗尽时通过 `mmap` 动态分配新的栈段。程序提供菜单驱动的 "allocator" 界面：

1. **在栈上分配** —— `alloca()`，大小 `[0x80, 0xFFF]`，用 `scanf("%15s")` 读入 15 字节名字
2. **在堆上分配** —— `malloc()`，大小 `> 0xFF`，读入 15 字节名字
3. **写入数据** —— 写入当前分配缓冲区
4. **新建 allocator** —— 递归调用菜单函数（压入新栈帧，可能触发 `__morestack` 分配新栈段）
5. **释放** —— 从当前递归调用返回（弹回上一帧/上一段）
6. **退出**

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO            # GOT not writable
  Stack:    No canary
  NX:       NX enabled
  PIE:      No PIE (base 0x3fe000/0x400000)
```

## 漏洞

### V1 — `scanf` 破坏 split-stack 段元数据（主要，可利用）

**根因：** split-stack 机制会在每个 mmap 栈页的基址（最低地址）存放段级元数据（`struct stack_segment`）。而 `__isoc99_scanf` 等 libc 函数**并未用 `-fsplit-stack` 编译**，不知道 split-stack 的段边界。`scanf` 的局部变量（内部缓冲区、指向 `stdin`/`stdout` 的 `_IO_FILE` 指针）可能向下越过当前栈帧，**覆盖页基址处的 `struct stack_segment` 头**。

```c
// From gcc/libgcc/generic-morestack.c
struct stack_segment {
    struct stack_segment *next;    // +0x00
    struct stack_segment *prev;    // +0x08
    size_t size;                   // +0x10
    void *old_stack;               // +0x18
    void *old_stack_limit;         // +0x20
    struct dynamic_allocation_blocks *free_dynamic_allocation;  // +0x28
    ...
};

struct dynamic_allocation_blocks {
    struct dynamic_allocation_blocks *next;
    size_t size;
    void *block;   // <-- returned by __morestack_allocate_stack_space
};
```

**触发方式：** 通过精心控制递归深度（选项 4）和 `alloca` 大小（选项 1），攻击者把 `$rsp` 摆到某个位置，使得下一次 `alloca` 期间调用 `scanf` 时，其内部局部变量恰好落在 `stack_segment` 头上。关键破坏：

- **`free_dynamic_allocation`**（`+0x28`）被覆盖为指向 `_IO_2_1_stdin_` 的指针（`scanf` 内部在栈上留下的 libc 地址）。
- **`size`**（`+0x10`）被覆盖为一个很大的值，或 **`prev`**/**`next`** 指针被破坏。

**影响：** 下一次调用 `__morestack_allocate_stack_space` 时会检查 `free_dynamic_allocation`。由于它现在指向 `stdin`，函数会把 `stdin` 的字段解释成 `dynamic_allocation_blocks` 结构：

- `stdin->_flags`（0xfbad208b）→ `.next`
- `stdin+0x08` 处的字节 → `.size`（某个大值）
- `stdin+0x10` 处的字节 → `.block`（`_IO_2_1_stdin_+0x84..0x90` 附近的地址）

如果 `.size >= requested_size`，就返回 `.block` —— 给攻击者一个**写入 libc `_IO_2_1_stdin_` 结构及周边内存（包括 `__malloc_hook`、`__free_hook`、`_IO_2_1_stdout_`）的原语**。

### V2 — `scanf` 破坏段的 `prev`/`next` 指针（替代破坏目标）

与 V1 同根因，但针对不同字段。通过调整不同的栈对齐，`scanf` 的局部变量可以覆盖：

- **`prev`** —— 使 `release()` 弹到错误的段，可能是攻击者控制内容的段
- **`next`** —— 使后续压段使用伪造的段头
- **`size`** —— 膨胀段大小，使后续 `alloca` 返回越过段边界、进入更老栈帧的指针

### V3 — 段大小破坏 → 栈帧重叠（替代方案）

如果 `scanf` 把某段的 `size` 字段覆盖成非常大的值，那么回到该段后，`alloca` 可以分配到真实段边界之外，与**之前递归层的旧栈帧**重叠，从而覆盖保存的返回地址 → ROP。

## 关键数据结构

### `struct stack_segment`（位于每个 mmap 栈页的基址）

| 偏移 | 字段 | 说明 |
|------|------|------|
| `+0x00` | `next` | 链表中的下一个段 |
| `+0x08` | `prev` | 上一个段 |
| `+0x10` | `size` | 该段可用大小 |
| `+0x18` | `old_stack` | 切换段前保存的 RSP |
| `+0x20` | `old_stack_limit` | 保存的栈边界 |
| `+0x28` | `free_dynamic_allocation` | 动态分配块链表 |

### `struct dynamic_allocation_blocks`（由 `free_dynamic_allocation` 指向）

| 偏移 | 字段 | 说明 |
|------|------|------|
| `+0x00` | `next` | 空闲链表中的下一个块 |
| `+0x08` | `size` | 该块大小 |
| `+0x10` | `block` | 由 `__morestack_allocate_stack_space` 返回的指针 |

## 利用路径

---

### 路径 A — `free_dynamic_allocation` → `stdin` → 写 `__malloc_hook` / FSOP

**使用解法：** exp.py、1351、1980、8153、31599、32010、35917、37983

**步骤：**

1. **深度递归**，把 RSP 推到 mmap 栈段上（3 次 `alloca(0xFFF)` + 多次 `recurse()`）。
2. **精确的 `alloca` 大小** 摆好 RSP，使 `scanf` 的局部变量用 `&_IO_2_1_stdin_` 覆盖 `free_dynamic_allocation`。
3. **`release()` + `alloca(large)`** —— 被破坏的 `free_dynamic_allocation` 令 `__morestack_allocate_stack_space` 返回 `stdin+0x90`（或类似偏移），得到**写入 libc 数据的原语**。
4. **覆盖 `_IO_2_1_stdout_`**，构造 `_IO_write_base` 指向 GOT 表项的 stdout FILE 结构 → stdout flush 时泄露已解析的 libc 地址 → **libc 基址**。
5. **覆盖 `stdin` vtable 指针**，指向伪造 vtable，其中 `__underflow` = `one_gadget`。
6. **触发 `scanf`**（递归 + 选项 1）→ `__uflow` 经伪造 vtable 分发 → **shell**。

**变体（31599、32010、35917）：** 不劫持 vtable，而是用 `one_gadget` 或 `puts` gadget 覆盖 `__malloc_hook`。通过 `malloc()`（选项 2，堆分配）触发。部分解法先用 `__malloc_hook → puts_gadget` 做两阶段泄露，再把 `__malloc_hook` 改写为 `one_gadget`。

**可靠性：** 一旦找到正确的递归深度和 alloca 大小即为确定性。本地与远程的偏移标定不同（通常需要一个小常数调整）。

---

### 路径 B — 段 `size` / `prev` 破坏 → 栈帧重叠 → ROP

**使用解法：** 59、363、550、821、1194、1458、1980、2673、5586、6748、9251、10102、14523、26957

最常见的思路。不针对 `free_dynamic_allocation`，而是破坏段元数据，在旧栈帧中实现**栈缓冲区溢出**。

**步骤：**

1. **通过精心设计的递归和 `alloca` 模式创建相邻栈段**。可选地穿插大块 `malloc`（堆）分配来控制 mmap 布局、制造空隙。
2. **触发 `scanf` 破坏**段的 `size` 字段（膨胀）或 `prev` 指针（重定向）。
3. **通过反复 `release()` 回到被破坏的段**。膨胀的 `size` 使该帧后续 `alloca` 能写到**真实段边界之外**，进入更老栈帧的栈内存。
4. **用 ROP 链覆盖**某个返回帧保存的 RBP/RIP。
5. **ROP 泄露 libc**（例如 `puts(GOT_entry)` 或 `write(1, GOT_entry, 8)`）→ 计算 libc 基址。
6. **第二阶段 ROP**：`read` 到 BSS → `system("/bin/sh")`，或 `mprotect` + `read` shellcode → 跳转到 shellcode，或直接 `one_gadget`。

**常用 ROP gadget（无 PIE 二进制）：**

```python
pop_rdi     = 0x40194e
pop_rsi     = 0x4016df
pop_rdx_rax = 0x4026c5  # pop rdx; pop rax; add rsp, 8; pop rbp; ret
mprotect    = 0x400e98   # PLT
read_plt    = 0x400e48
puts_plt    = 0x400e10
write_plt   = 0x400e18
```

**变体（821，"memory gap"）：** 创建栈 A–D，用 mmap 堆在段之间制造空隙，释放堆留下空隙，再把新段分配到空隙中更高的地址，用 `scanf` 破坏较低段的 `size`，然后向下溢出到更老的帧。

**变体（14523，"fake prev"）：** 把段 A 的 `prev` 指针覆盖为 A 与 B 之间伪造的段头。伪造头的 `prev` 被部分覆盖（1/16 爆破）指向段 D。沿伪造链弹出会跳过若干段，落到 C 段，攻击者可在那里覆盖返回地址。

**可靠性：** 大多数变体为确定性。14523 的 `prev` 部分覆盖需要 1/16 爆破。

---

### 路径 C — TLS 破坏 → 劫持 `_call_tls_dtors`

**使用解法：** 9251

一条奇特的路径，目标是紧邻栈段的线程本地存储（TLS）区域：

1. **通过深度递归把栈段摆到 `fs_base`（TLS 段）旁边**。
2. **破坏 `fs:[-0x108]`**（`__call_tls_dtors` 链表指针），指向攻击者控制的栈数据。
3. **破坏 `fs:[0x30]`**（`PTR_DEMANGLE` 使用的指针守卫），值为 `value ^ read_gadget_addr`。
4. **调用 `exit()`**（向 size 提示输入非法内容）→ `_call_tls_dtors` → 解混淆后的函数指针 → `read` gadget → 从 socket 读取 ROP 链 → `puts(GOT)` → 泄露 libc → `system("/bin/sh")`。

**可靠性：** 约 15/16（取决于 libc 地址在特定位置是否含有 0xf 半字节）。

---

### 路径 D — 堆喷射 + 覆盖 `__malloc_hook`

**使用解法：** 8153

1. **喷射堆**：用 0xFF 次 `malloc(0x20000)` 大分配，每次填入 `p64(target_gadget)`，在内存中形成 "gadget 滑板"。
2. **触发 `scanf` 破坏**，获得 `stdin` 附近的写指针。
3. **通过写原语用 `puts` gadget 地址覆盖 `__malloc_hook`**。
4. **以 `size = GOT_entry` 触发 malloc** → `puts(GOT_entry)` 泄露 libc。
5. **用 `one_gadget` 覆盖 `__malloc_hook`** → 触发 `malloc` → shell。

**可靠性：** 约 1/32（堆喷射命中正确页面的概率）。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|------|------|--------|
| `scanf` 破坏段元数据 | V1：split-stack + libc 栈使用 | 深度/大小正确时确定性 |
| 写入 `stdin`/`stdout`/hooks | V1 → `free_dynamic_allocation` = `&stdin` | 确定性 |
| 栈帧重叠（ROP） | V2/V3：被破坏的 `size`/`prev` | 确定性（大多数变体） |
| 经 stdout FSOP 泄露 libc | 伪造 stdout 的 `_IO_write_base` = GOT | 确定性 |
| 经 `puts(GOT)` ROP 泄露 libc | 栈重叠 → ROP 链 | 确定性 |
| 代码执行 | `one_gadget` / `__malloc_hook` / ROP → `system` | 确定性 |
| TLS 劫持 | 破坏紧邻栈的 TLS | 约 15/16 |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
# Binary (No PIE)
pop_rdi         = 0x40194e
pop_rsi         = 0x4016df
pop_rdx_rax     = 0x4026c5   # pop rdx; pop rax; add rsp, 8; pop rbp; ret
pop_rsp_r13     = 0x401ee1
mprotect_plt    = 0x400e98
read_plt        = 0x400e48
puts_plt        = 0x400e10
write_plt       = 0x400e18
GOT_puts        = 0x603f40

# libc
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
system          = 0x45390
__malloc_hook   = 0x3c3b10
__free_hook     = 0x3c57a8
stdin           = 0x3c38e0   # _IO_2_1_stdin_
stdout          = 0x3c4620   # _IO_2_1_stdout_
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|----------|----------|------|
| `59.md` | B | 爆破栈对齐 → ROP | "纯凭运气解出"；后来才理解 scanf 破坏 |
| `363.md` | B | mprotect + read shellcode → ROP | "我自己也看不懂我的解法" |
| `550.md` | B | `free_dynamic_allocation` → 栈地址 → ROP | 对核心漏洞解释清晰 |
| `821.md` | B | memory gap 技巧 → 栈重叠 → ROP + one_gadget | 详细的 mmap 布局操纵 |
| `1194.md` | B | scanf 伪造 `heap_alloca` 缓冲区 → ROP | 用 `ret2csu` 构造干净 ROP |
| `1351.md` | B | 深度递归 → mprotect + shellcode | 简洁；gadget 链干净 |
| `1458.md` | A | `free_dynamic_allocation` → stdin → `__malloc_hook` | 两阶段：malloc_hook → 泄露，再 → one_gadget |
| `1980.md` | B | scanf 破坏头 → alloca 到栈 → ROP | 记录了漏洞机制 |
| `2673.md` | B | 在 `[rbx+0x28]` 留下伪造栈地址 → ROP | 简短但有效 |
| `2972.md` | B | 251 次 recurse + release 模式 → ROP | 解释很少；大量试错 |
| `5586.md` | B | 57 次填栈 + 多次 release → ROP | 使用 `ret2csu` 模式 |
| `6748.md` | B | 大规模 recurse（0x10 次 alloca + 0x60 次裸调用）+ releases → ROP | 试错对齐 |
| `8153.md` | D | 堆喷射 0xFF × malloc(0x20000) + `__malloc_hook` | 约 1/32 可靠性；基于喷射 |
| `9251.md` | C | TLS 破坏 → `_call_tls_dtors` → read gadget → ROP | 最奇特的路径；约 15/16 可靠性 |
| `10102.md` | B | 覆盖段 `prev` → 伪造段链 → 栈重叠 | `prev` 部分覆盖需 1/16 爆破 |
| `14523.md` | B | 经堆空隙制造相邻 mmap 栈 → scanf 破坏 `size` | 记录了 8 次失败尝试的日志 |
| `26957.md` | B | 用低地址覆盖段头 `+0x00` → alloca 溢出 | 简洁 |
| `31599.md` | A | `free_dynamic_allocation` → stdin → `__malloc_hook` → 泄露 + one_gadget | 干净的两阶段利用 |
| `32010.md` | A | 写 stdin → stdout FSOP 泄露 → stdout vtable → one_gadget | 使用 vtable `call [rax+0x38]` 的 FSOP |
| `35917.md` | A | 写 stdin+0x90 → `__malloc_hook` → puts 泄露 → one_gadget | 详细；包含 `realloc` 对齐技巧 |
| `37983.md` | B | 滥用 mmap 顺序 → 相邻栈 → scanf → ROP | 仅本地；包含分析 scanf 偏移的 IDA 脚本 |

## 文件

| 文件 | 说明 |
|------|------|
| `exp.py` | 可用利用脚本（路径 A：FSOP stdin/stdout vtable 劫持） |
| `desc.txt` | 题目描述 |
| `artifacts/babyallocator` | 原始题目二进制（x86-64、已 strip、-fsplit-stack） |
| `artifacts/libc_64.so.6` | 远程 libc（glibc 2.23） |
| `solution/*.md` | 社区题解（21 份） |
