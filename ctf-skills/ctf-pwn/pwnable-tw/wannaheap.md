---
tags:
  - off-by-null
  - heap-consolidation
  - arbitrary-write
platform: pwnable.tw
points: 400
arch: x86-64
libc: glibc-2.24
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "在 treap 键插入中出现一个 off-by-null 字节，可跨活跃树节点触发向低地址的堆合并，在 glibc 2.24 上实现任意写。"
proof-of-concept: no
---

# WannaHeap — pwnable.tw（400 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10305`
>
> Flag：`FLAG{I_w4nt_2_pl4y_w1th_f1l3_str34m}`

## 题目概况

一个基于 treap（树-堆）的键值存储（x86-64，Full RELRO、PIE、NX、栈 canary），运行在 **Ubuntu 17.04 + glibc 2.24** 上 —— 这是首个引入 `_IO_vtable_check` 的 glibc，而且**没有 tcache**。**seccomp** 沙箱拦掉了 `execve`，并把 `read` 限制在 `count <= 0x1337`、`mmap` 只允许不可执行页。程序没有实现 `free`。flag 只能通过 ORW（open/read/write）读取。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  seccomp:  ALLOW open/read(≤0x1337)/write/close/munmap/mmap(no EXEC)/rt_sigreturn/exit/exit_group
```

### 程序流程

1. **创建数据堆**：询问 `Size` → `calloc(size+1)` → 读取 `Content`。如果第一个尺寸超过 `0x313370`，会再问一个尺寸。
2. **菜单**：`[A]llocate`（把键+数据插入 treap）、`[R]ead`（按键查找、打印数据，然后 **`close(1)`**）、`[F]ree`（未实现）、`[E]xit`。
3. seccomp 在数据堆创建**之后**才安装（所以最初那次 `read` 不受限制）。

## 关键数据结构

### Treap 节点（0x28 字节，在自定义分配器里随机加 padding）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00` | `left_child` | `node *` |
| `0x08` | `right_child` | `node *` |
| `0x10` | `key` | `uint64_t` |
| `0x18` | `data_ptr` | `char *`（经 `strdup`） |
| `0x20` | `priority` | `uint32_t`（来自 `/dev/urandom`） |

自定义分配器调用 `calloc(0x28 + rand()%535 + rand()%8560)`，把节点放在 chunk 内一个随机偏移处（前面垫 `0xda`、后面垫 `0x42`），因此堆布局不可预测。

## 漏洞

### V1 — 相对数据堆的任意空字节写（主要）

**根因：** 在"创建数据堆"函数里，第一次 `scanf` 得到的尺寸 `S1` 会被记住。若 `S1 > 0x313370`，程序会反复索要，直到拿到合法的 `S2 ≤ 0x313370`。缓冲区按 `S2` 分配，但 NUL 终止符却写在 `S1` 偏移处：

```c
scanf("%lu", &size);
uVar1 = size;                        // remember S1
while (size > 0x313370) {
    scanf("%lu", &size);             // get S2
}
buf = calloc(1, size + 1);          // allocate with S2
read_n(buf, size);                   // read S2 bytes
*(char*)(buf + uVar1) = 0;          // NULL write at S1 offset!
```

**影响：** 大尺寸（例如 `0x300000`）的 `calloc` 会走 `mmap`，而 `mmap` 落在 libc **下方固定的偏移处**，因此 `S1` 可以打中 libc 可写段的任意字节。关键目标是 `_IO_2_1_stdin_->_IO_buf_base`（位于 `stdin + 0x38`），把它的最低字节清成 `\x00`。

**触发：**
```python
S1 = mmap_gap + libc.sym['_IO_2_1_stdin_'] + 0x38 - 0x10
# Typical values: 0x6c28e8 or 0x6d58e8 depending on mmap_gap (0x301000 or 0x314000)
S2 = 0x300000  # or 0x313370
```

空字节写之后，`_IO_buf_base` 从 `stdin+0x83` 变成 `stdin+0x00`（或按对齐变成 `stdin+0x40`），于是之后从 stdin 读取的数据会**直接写进 FILE 结构**，包括 `_IO_buf_end` —— 后者还能被扩展到覆盖 `main_arena` 乃至更远。

### V2 — `strdup` 中的未初始化栈缓冲区泄漏

**根因：** `Allocate` 读数据字段时，用 `read_n` 读进一个 **0x18 字节、从不清理的栈缓冲区**，结果再交给 `strdup`，而 `strdup` 会复制到第一个 `\0` 为止。

```c
char buf[0x18];  // uninitialized!
read_n(buf, 0x18);
node->data = strdup(buf);
```

**影响：** 在 treap 插入深度为 2 时，栈上 `buf+8` 处残留着指向 `_IO_2_1_stdout_` 的指针（其最低字节是 `\x00`）。只要发送**恰好 9 字节**数据，第 9 个字节就会覆盖那个 `\x00`，使 `strdup` 把 stdout 指针剩下的 5 个字节也复制进去。用 `[R]ead` 读回来就泄漏了 `stdout >> 8`，进而推出 `libc_base`。

```python
# Leak: send 9 bytes, read back, extract bytes [9:14]
stdout_partial = u64(b'\x00' + leaked_5_bytes + b'\x00\x00')
libc_base = stdout_partial - libc.sym['_IO_2_1_stdout_']
```

这个泄漏是概率性的（约 50%），因为 treap 的随机优先级决定哪个节点落在深度 2。各解法都会重试直到成功。

## 利用路径

所有解法都共用 V1（对 `stdin->_IO_buf_base` 做空字节写）+ V2（经未初始化栈泄漏 libc），区别在 FSOP / 代码执行策略。

---

### 路径 A — 经 Unsorted Bin Attack 打 `_dl_open_hook` + `setcontext` → ORW ROP

**使用范围：** 解法 194、821、1155、1763、1922、7905、8153、31599、exp.py

**步骤：**

1. **空字节写** `stdin->_IO_buf_base` 的最低字节 → stdin 缓冲区现在与 FILE 结构重叠。
2. **泄漏 libc**（V2：分配两个节点，读回第二个）。
3. **扩展 `_IO_buf_end`**：空字节写之后的第一次 stdin 读取会覆盖 `_IO_buf_end`（位于 `stdin+0x40`），把它扩展到覆盖 `main_arena`。
4. **一发改掉所有东西**：一次大 `send()` 同时改写：
   - `stdin` 的 FILE 结构（修好 `_lock`、把 `vtable = _IO_file_jumps` 以通过 vtable 校验、扩展 `_IO_buf_end`）
   - `_IO_wide_data_0` 区域（内嵌一个**假 unsorted bin chunk**，其 `bk = _dl_open_hook - 0x10`）
   - `main_arena`（伪造 `bins[]` 指向假 chunk；把 `top` 设为 gadget `mov rdi,rax; call [rax+0x20]`；内嵌 `setcontext+53` 和用于栈迁移的 ucontext 帧）
5. **触发**：载荷在某个偏移上的字节恰好是 `'A'` → 触发 `Allocate` → `calloc` → 走到伪造的 unsorted bin → **unsorted bin attack** 把 `&main_arena+0x58` 写进 `_dl_open_hook`。
6. **崩溃路径**：`malloc` 检测到破坏 → `malloc_printerr` → `__libc_message(do_abort)` → `__backtrace` → `__libc_dlopen_mode("libgcc_s.so.1")` → `_dl_open` 发现 `_dl_open_hook != NULL` → 调用 `(*_dl_open_hook->dlopen_mode)()`。
7. `rax = _dl_open_hook = main_arena+0x58`，它指向 gadget `mov rdi, rax; call [rax+0x20]` → 以受控的 `rdi` 调用 `setcontext+53` → **栈迁移**到 ORW ROP 链。
8. **ROP**：`open("/home/wannaheap/flag") → read(1, buf, 0x100) → write(0, buf, 0x100)`。

**关键细节：** `Read` 会调 `close(1)`，所以 `open` 拿到的是 fd 1；输出必须走 fd 0（socket），因为服务器上的 fd 2 是 `/dev/null`。

---

### 路径 B — 劫持 `_IO_str_overflow` vtable + `setcontext` → ORW ROP

**使用范围：** 解法 369、2972、6247、36997

glibc 2.24 的 `_IO_vtable_check` 允许位于 `__libc_IO_vtables` 段内的 vtable。`_IO_str_jumps` 正在该范围内，所以把 FILE 的 vtable 指向 `_IO_str_jumps` 内部某个偏移就能通过校验。`_IO_str_overflow` 会调用 `fp->_s._allocate_buffer(new_size)` —— 即 `fp+0xe0` 处的函数指针。

**步骤：**

1. 同路径 A（空字节写、泄漏、扩展 `_IO_buf_end`）。
2. **伪造 stdout**：用精心构造的 FILE 覆盖 `_IO_2_1_stdout_` —— 把 `vtable = _IO_str_jumps - 0x20`（使 `__xsputn` 槽映射到 `_IO_str_overflow`）、`_IO_buf_end = (target_rdi - 100) / 2`（控制 `new_size` 参数）、`fp->_s._allocate_buffer = setcontext+53`（位于 `fp+0xe0`）。
3. **触发**：载荷中的 `'E'` 字节会触发 `Exit` → `puts("Goodbye")` → stdout 的 `__xsputn` → `_IO_str_overflow` → `call [fp+0xe0]` = `setcontext+53`。
4. `setcontext` 把栈迁到 ORW ROP 链。

---

### 路径 C — 劫持 `_IO_wstr_finish` / `_IO_wfile_jumps` vtable + 栈迁移 → ORW ROP

**使用范围：** 解法 8153、36997（变体）

用的是 `_IO_wfile_jumps`（同样位于合法的 vtable 段）。`_IO_wstr_finish` 会调用 `fp->_wide_data->_wide_vtable->__doallocate(fp)` —— 一串间接调用，可以引向栈迁移 gadget。

**步骤：**

1–3. 同路径 A。
4. **伪造 stdout**：设 `vtable = _IO_wfile_jumps + offset`，让 `_wide_data` 指向一块受控区域，其中放一个假 wide vtable，包含 `xchg rax, rsp; ret`，或 `call [rdi+0x18]` → `setcontext+53`。
5. **触发**：对 stdout 的 `puts` → wide vtable 分发 → 栈迁移 → ORW ROP。

---

### 路径 D — 经 stdin 操纵打 `__free_hook` + `setcontext`（不用 unsorted bin attack）

**使用范围：** 解法 186

**步骤：**

1–3. 同路径 A。
4. 不走 unsorted bin attack，而是直接操控 `stdin->_IO_markers`、`_IO_save_base`、`_IO_save_end`、`_IO_read_base`，以触发 stdin 缓冲区管理过程中 libc 内部的 `malloc()`、`free()`、`memcpy()` 调用。
5. 布置堆使 `free()` 作用在一个受控缓冲区上，然后把 `__free_hook` 覆盖为 `setcontext+53 - 7`（避开会触发 Exit 的 `0x45 = 'E'` 字节）。
6. 以受控的 `rdi` 触发 `free()` → `setcontext` → ORW ROP。

---

### 路径 E — 侧信道逐字节读 flag

**使用范围：** 解法 369、1351

拿到 ROP 之后不直接输出 flag，而是：
1. `open` + `read` 把 flag 读进内存。
2. 用比较 gadget（`cmp byte ptr [rax], dl; ret`、`setbe al; ret`）把 flag 的每个字节与猜测值比较。
3. 依据比较结果二选一：从 socket `read`（一直阻塞等输入 = flag 字节 ≥ 猜测值），或触发 EOF（flag 字节 < 猜测值）→ 二分查找。

这种方式更慢，但在直接向 socket `write` 不可靠时仍然可行。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 对 libc 的任意空字节写 | V1：创建数据堆时的尺寸不一致 | 确定性（mmap 偏移固定） |
| 覆盖 stdin 的 FILE 结构 | V1 → `_IO_buf_base` 最低字节被清零 | 确定性 |
| 泄漏 libc 基址 | V2：`strdup` 的未初始化栈 | 每次连接约 50%（取决 treap 深度） |
| 扩展 `_IO_buf_end` | 经被污染的 stdin 缓冲区覆盖 | V1 之后确定性 |
| 覆盖 `main_arena` | 扩展后的 stdin 缓冲区够到 `main_arena` | 扩展之后确定性 |
| 代码执行 | FSOP（多条路径：`_dl_open_hook`、`_IO_str_overflow`、`_IO_wstr_finish`、`__free_hook`） | 泄漏 libc 后确定性 |
| ORW 读 flag | ROP 链：`open→read→write(fd=0)` | 确定性 |

## 偏移（libc 2.24-9ubuntu2.2，sha1 4e5dfd83...）

```python
_IO_2_1_stdin_   = 0x3c18c0
_IO_2_1_stdout_  = 0x3c2600
_IO_file_jumps   = 0x3be400
_IO_str_jumps    = 0x3be4c0
_IO_wfile_jumps  = 0x3bdec0
_dl_open_hook    = 0x3c62e0
main_arena       = 0x3c1b00
__malloc_hook    = 0x3c1af0
__free_hook      = 0x3c3788
_IO_stdfile_0_lock = 0x3c3770
setcontext       = 0x48010     # +53 = 0x48045
open / read / write = 0xf8660 / 0xf8880 / 0xf88e0

# Gadgets
mov_rdi_rax_call = 0x6ebbb     # mov rdi, rax; call [rax+0x20]
pop_rdi = 0x1fd7a
pop_rsi = 0x1fcbd
pop_rdx = 0x1b92
pop_rax = 0x3a998
pop_rdx_rsi = 0x116d69
syscall_ret = 0xbc765
ret = 0x937

# Null write target (varies by mmap gap)
# mmap_gap = 0x301000 → S1 = 0x6c28e8
# mmap_gap = 0x314000 → S1 = 0x6d58e8
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `186.md` | D | 操纵 stdin → `__free_hook` + `setcontext` | 不用 unsorted bin attack，也不劫持 FSOP vtable |
| `194.md` | A | `_dl_open_hook` + `setcontext` → ORW | 步骤讲解干净 |
| `369.md` | B + E | `_IO_str_overflow` + 侧信道二分 | 逐字节读 flag |
| `408.md` | A | 绕过 vtable 校验打 `_dl_open_hook` | 紧凑的 exploit |
| `705.md` | B | 经 `_dl_find_dso_for_object` 绕过 vtable 校验 + `leave; ret` | 少见的基于 RBP 的迁移 |
| `821.md` | A | `_dl_open_hook` + `setcontext` → ORW | 结构布局注释详细 |
| `1155.md` | A | `_dl_open_hook` → `setcontext+53` → ORW | 干净的模块化 exploit |
| `1351.md` | B + E | `_IO_str_overflow` + 侧信道 | 用 `cmp`/`jb` gadget 做二分 |
| `1763.md` | A | `_dl_open_hook` + `setcontext` | 处理随机偏移 |
| `1922.md` | A | `_dl_open_hook` + 详细堆布局 | 中英双语 writeup |
| `2972.md` | B | `_IO_str_overflow` + `setcontext` → ORW | 简洁；直接输出 flag |
| `3498.md` | A | `_dl_open_hook` + `setcontext` | 注释稀疏，exploit 可用 |
| `6247.md` | A | `_dl_open_hook` + `setcontext` | 完整重建结构体 |
| `7905.md` | A | `_dl_open_hook` + `setcontext` | 变量命名详尽 |
| `8153.md` | C | `_IO_wstr_finish` + `xchg rax,rsp` 迁移 | 另一条 vtable 路径 |
| `31599.md` | A | `_dl_open_hook` + 详细（中文）writeup | 分析最全面 |
| `36997.md` | C | `_IO_wfile_jumps` + `call [rdi+0x18]` → `setcontext` | 较现代的 FSOP 做法 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit（`_dl_open_hook` 路径） |
| `desc.txt` | 题目描述 |
| `artifacts/` | 原始二进制 |
| `solution/*.md` | 社区 writeup（39 份解法） |
