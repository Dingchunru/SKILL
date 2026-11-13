---
tags:
  - heap-buffer-overflow
  - tcache-poisoning
  - arbitrary-write
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.27
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "报告评论解析中的堆缓冲区溢出，可破坏 tcache 的 next 指针，实现任意内存写入并覆盖 __free_hook。"
proof-of-concept: no
---

# Bounty Program α — pwnable.tw（500 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10208`
>
> Flag：`FLAG{s0m3_3nv_Ar3_pow3rful_it_h3lp_you_lif3_mor3_e4sy}`

## 题目概览

一个漏洞赏金平台二进制（x86-64，PIE、Full RELRO、NX、Stack Canary），链接 glibc 2.27。用户可以注册/登录、管理产品、提交/编辑/评估漏洞报告，以及管理漏洞类型。还有一个 `wrapper` 二进制，会在 `execve` 主程序之前提示输入环境变量名/值对——这正是关键提示：`GLIBC_TUNABLES` 可以控制 malloc 的行为。

程序包含一个用户系统（链表）、产品/类型/报告管理（有复杂的堆交互），以及一套把报告关联到用户的评估流程。所有字符串字段内部都使用 `calloc`/`strdup`/`strtok`。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## 漏洞

### V1 —— `add_type` 中 `strtok` 续接泄露（主要）

**根因：** `add_type` 函数用 `strtok(buf, ",")` 从一块 `calloc` 分配的缓冲区里解析逗号分隔的类型名。当 `size` 传入 `-1`（或无符号的 `0xFFFFFFFF` → 极大）时，`calloc(1, size)` 失败返回 NULL，但代码随后调用 `strtok(NULL, ",")`，它会从**上一次** strtok 的状态继续——读取最后一个已解析 token 之后的任意堆数据。

```c
// add_type (simplified)
buf = calloc(1, size);       // size = -1 → calloc fails → buf = NULL
read(0, buf, size);          // read to NULL = no-op or ignored
tok = strtok(buf, ",");      // strtok(NULL, ",") → continues from previous state!
printf("type: %s\n", tok);   // leaks heap/libc pointers from adjacent memory
```

**影响：** 通过先前的字符串操作精心摆放 strtok 内部状态指针，续接读取就能读到任意堆数据。这一漏洞可用于：
- **泄露堆地址**——strtok 走进被释放 chunk 的元数据或相邻分配
- **泄露 libc 地址**——如果 strtok 状态指向 unsorted bin chunk 的 fd/bk 指针附近
- **tcache 投毒**——`strtok(NULL, ",")` 调用可以在现有堆数据的逗号位置写入一个 NUL 字节，随后的价格解析又会把攻击者控制的值写进 tcache 元数据

### V2 —— 密码溢出覆盖 contact 指针

**根因：** 用户结构依次存储用户名（0x1e 字节）、密码（0xf 字节）、一个 contact 指针及其他字段。`change_password` 函数最多向密码字段读入 `0x3f` 字节，但密码缓冲区只有 0xf 字节——溢出会触达偏移 `+0x38` 处的 contact 指针。

```c
// change_password
read(0, user->password, 0x3f);  // 0x3f bytes into a 0xf-byte field
// overflow overwrites: price(+0x30), uid(+0x34), contact_ptr(+0x38)
```

**影响：** 覆盖 `contact_ptr` 可以获得：
- **任意读**——`change_contact` 向 `contact_ptr` 中的地址写入；`show_products` / `user_info` 则从所指向的内存读取（通过产品结构中的 company 指针）
- **任意写**——`change_contact` 把攻击者数据写到被覆盖的指针处

### V3 —— 用户结构 / 评估伪造用户

**根因：** `evaluate` 函数遍历用户链表，并根据报告数据修改用户结构。通过构造被释放的用户 chunk 与类型名数据重叠的堆布局，攻击者可以伪造用户结构，控制其 `prev`/`next` 指针、用户名和密码——从而以某个“伪造”用户登录，而该用户与关键堆元数据重叠。

### V4 —— 通过用户名溢出泄露堆地址

**根因：** 用 0x1e 字节的用户名注册，然后用 0x1f 字节的用户名（多追加一个垃圾字节）登录时，`user_info` 展示会打印 `name` 字段；由于边界处缺少 NUL 终止，会泄露相邻结构字段中的堆指针（被评估报告链表的 `next` 指针）。

```c
// user_info display
printf("Name > %s\n", user->name);  // 0x1e bytes, no NUL → leaks next 6 bytes
```

### V5 —— MD5 Contact 预言机

**根因：** `user_info` 命令会显示 contact 缓冲区（20 字节）的 MD5 哈希。通过 V2 把 contact 指针指向目标地址，再对 MD5 哈希逐字节爆破，攻击者就能一次一字节地读取任意内存。

## 关键数据结构

### 用户结构（约 0x60 字节，堆分配）

| 偏移 | 字段 | 大小 |
|--------|-------|------|
| `0x00` | `username` | 0x1e 字节 |
| `0x1e` | `password` | 0x0f 字节 |
| `0x30` | `price` | uint32_t |
| `0x34` | `uid` | uint32_t |
| `0x38` | `contact_ptr` | char * |
| `0x40` | `report_head` | void * |
| `0x48` | `prev` | user * |
| `0x50` | `next` | user * |

### 全局状态

- **用户链表**——已注册用户的双向链表
- **产品数组**——最多 8 个产品，每个产品带 name/company/comment 指针以及一个报告链表
- **类型数组**——最多 8 种漏洞类型，每种带一个名字（`strdup` 分配）和一个价格
- **报告**——关联到产品，包含标题、描述（`calloc` 分配）、类型 ID、提交者

## 利用路径

### 路径 A —— strtok 续接 + 密码溢出 → 任意读写 → `__free_hook` + `setcontext`

**使用者：** 解法 821、9251、6748、6923、8153、18331、26957

1. **设置 `GLIBC_TUNABLES`**——用 wrapper 设置 `glibc.malloc.perturb=N`，它会把被释放的 chunk 填满已知字节，使堆布局更可预测。
2. **堆泄露**——用 0x1e 字节的用户名注册一个用户。评估之后，`user_info` 会越过用户名边界泄露堆指针。另一种做法是用 strtok 续接（V1）配合 `size=-1` 泄露被释放 chunk 的 fd 指针。
3. **libc 泄露**——用 V2 把 contact 指针覆盖为某个产品的 company 字段。把 company 指针改为指向一块包含 unsorted bin fd/bk（libc 的 main_arena 指针）的堆位置。通过 `show_products` 读取。另一种做法是在把 unsorted bin chunk 的元数据摆进 strtok 路径之后，用续接读取。
4. **任意读写原语**——借助 V2：`change_password` 把 `contact_ptr` 覆盖为目标地址；`change_contact` 向其写入。再串联起来覆盖 `product.company` 以实现读取。
5. **把 `setcontext+53` 写到 `__free_hook`**——当 `free()` 被调用时，`rdi` 指向被释放的 chunk。`setcontext+53` 会从 `[rdi+offset]` 读取寄存器值，从而实现完全受控的寄存器上下文切换。
6. **触发**——在某个堆分配中放入 ROP 链 / `mprotect` + shellcode payload，然后释放它。`setcontext` 把 `rsp` pivot 到该 payload → `mprotect(heap, 0x1000, RWX)` → `read(0, heap, 0x200)` → 跳转到 shellcode → `open("/home/bounty_program/flag")` + `read` + `write`。

### 路径 B —— MD5 预言机逐字节泄露 → 栈泄露 → 栈上 ROP

**使用者：** 解法 1351、25916

1. **堆泄露**——与路径 A 相同。
2. **通过 MD5 预言机泄露 libc**——用 V2 把 `contact_ptr` 指向某个 libc 指针附近。读取 `user_info` 得到 20 字节 contact 缓冲区的 MD5。通过比对计算出的 MD5，逐字节爆破（每字节 256 次尝试，完整指针需要 6 字节）。慢但可靠。
3. **栈泄露**——把 contact 指向 `libc.sym['environ']`，经 MD5 预言机读取（或者在建立任意读之后直接读取）。
4. **栈上 ROP**——用 V2 的任意写把一条 ROP 链写到栈上（`pop rdi; /bin/sh; system` 或 `mprotect` + shellcode）。覆盖保存的 RIP 完成 pivot。

### 路径 C —— strtok 续接 tcache 投毒 → `__malloc_hook`

**使用者：** 解法 31599、32010

1. 借助 strtok 续接（V1）和堆风水实现**堆 + libc 泄露**。
2. **tcache 投毒**——布置堆，使 `strtok(NULL, ",")` 走进某个 tcache chunk 的 `fd` 指针。strtok 在逗号位置写入的 NUL 字节，配合价格写入，会把 fd 破坏成指向 `__malloc_hook`。
3. **从被投毒的 tcache 分配**——下一次 `strdup` / 类型分配会返回一个位于 `__malloc_hook` 的 chunk。写入 `add_rsp_0x48` gadget（栈 pivot）或 `one_gadget`。
4. **触发**——下一次 `malloc` 调用跳转到该 gadget → pivot 到堆上的 ROP 链 → `open/read/write` 读取 flag。

### 路径 D —— 堆风水 + 伪造用户 + 评估利用

**使用者：** 解法 exp.py（主）、3148、6247

1. **复杂的堆风水**——用较大的报告描述和类型分配，构造出被释放用户 chunk 可被复用的精确堆布局。
2. **创建伪造用户**——构造一个类型名，当它被放进被释放的用户槽位时，形成一个合法的用户结构，用户名、密码和指针均可控。
3. **以伪造用户登录**——伪造用户的 contact 指针或报告头指向一个目标（例如用于 libc 泄露的 unsorted bin chunk）。
4. **建立读写**——通过伪造用户重叠的字段取得读/写原语。
5. **`__free_hook` + `setcontext`**——收尾方式与路径 A 相同。

### 路径 E —— 覆盖 tcache `thread_per_struct` → 泄露 `environ` → 栈上 ROP

**使用者：** 解法 32858

1. 借助 strtok 续接实现**堆 + libc 泄露**。
2. **覆盖 `tcache_perthread_struct`**——用一段较大的报告描述覆盖 tcache 元数据结构，把某个 bin 的条目重定向到 `libc.sym['environ'] - offset`。
3. **从被破坏的 tcache 分配**——`calloc` 返回一个与 `environ` 重叠的 chunk。从漏洞报告的描述输出中读出栈指针。
4. **栈上 ROP**——用 tcache 投毒在栈返回地址处分配。直接写入 ROP 链。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 堆地址泄露 | V4：用户名溢出 / V1：strtok 续接 | 确定性 / 约 1/256 |
| libc 地址泄露 | V1：strtok 靠近 unsorted bin / V2：任意读 | 确定性 |
| 栈地址泄露 | V5：对 `environ` 使用 MD5 预言机 / V2：任意读 | 确定性 |
| 任意读 | V2：密码溢出 → contact 指针 → show | 确定性 |
| 任意写 | V2：密码溢出 → contact 指针 → change contact | 确定性 |
| tcache 投毒 | V1：strtok 写 NUL + 价格写入 | 依赖堆布局 |
| 代码执行 | `__free_hook` = `setcontext+53` 或 `__malloc_hook` = gadget | 取得任意写后确定性 |

## 偏移（pwnable.tw `libc-2.27.so`）

```python
__free_hook      = 0x3ed8e8
__malloc_hook    = 0x3ebc30
setcontext_53    = 0x520a5
mprotect         = 0x11bae0
_IO_2_1_stderr_  = 0x3ec680
main_arena+96    = 0x3ebca0
environ          = 0x3ee098
pop_rdi          = 0x2155f
pop_rsi          = 0x23e6a
pop_rdx          = 0x1b96
pop_rax          = 0x439c8
leave_ret        = 0x54803
syscall_ret      = 0xd2975
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `exp.py` | D | strtok + 堆风水 + 伪造用户 + `__free_hook` → `setcontext` | 最复杂；完整的堆操纵 |
| `821.md` | A | strtok 泄露 + 密码溢出 → `setcontext` + `mprotect` + shellcode | 干净的 `setcontext` 用法 |
| `1351.md` | B | MD5 预言机逐字节 → 栈泄露 → `mprotect` + shellcode ROP | `GLIBC_TUNABLES` perturb=1 |
| `2972.md` | D | strtok + 通过寄存器伪造用户 → 经 `show_vuln` 泄露 libc → `setcontext` | 极简堆风水 |
| `3148.md` | D | strtok + 堆喷洒 + 伪造用户 → `__free_hook` → `setcontext` | 堆布局注释详细 |
| `6247.md` | D | `tcache_max` tunable + unsorted bin 合并 → `__free_hook` | 使用 `glibc.malloc.tcache_max` |
| `6748.md` | A | 密码溢出 → 任意读写 → tcache fd 投毒 → `setcontext` | 结构良好的面向对象利用 |
| `6923.md` | A | strtok `-1` 泄露 × 2 → 密码溢出 → `__free_hook` → `setcontext` | 直接用 strtok 泄露 libc |
| `8153.md` | A + B | 密码溢出 → `__environ` → 栈上 ROP | 基于栈的收尾 |
| `9251.md` | A | 密码溢出 → 任意读写 → `leave; ret` + malloc_hook → ROP | 用 `fopen` + `fgets` 读 flag |
| `18331.md` | A | strtok `size=-1` → 密码溢出 → 任意读写 → 覆盖栈返回地址 | 不用 `setcontext`；直接打栈 |
| `25916.md` | B + E | MD5 预言机 + `_dl_open_hook` 链 → `setcontext` | 最复杂；经 `_dl_open_hook` 多阶段利用 |
| `26957.md` | C | strtok tcache 投毒 → `__malloc_hook` + `setcontext` | 直接破坏 tcache FD |
| `31599.md` | C | strtok 续接 → tcache 投毒 → `__malloc_hook` = `add_rsp_0x48` → ROP | 最干净的 tcache 投毒方案 |
| `32010.md` | D | strtok 泄露 + 报告/类型重叠 → `__malloc_hook` = `leave; ret` | `leave; ret` pivot |
| `32858.md` | E | 覆盖 tcache_perthread_struct → 泄露 `environ` → 栈上 ROP | 独特的 tcache 结构方案 |
| `34817.md` | D | strtok + `__free_hook` → `setcontext` → open/read/write ROP | 两个脚本变体 |
| `36134.md` | B | MD5 预言机 + 密码溢出 + 堆风水 → `leave; ret` → ROP | 所有泄露都靠逐字节 MD5 |

## 说明

- **不用 `system("/bin/sh")`**——flag 位于 `/home/bounty_program/flag`，且 seccomp 或沙箱限制禁止直接拿 shell。所有解法都用 `open/read/write` shellcode 或 ROP 来读取 flag 文件。
- **`GLIBC_TUNABLES`**——wrapper 的环境变量提示就是预期线索。设置 `glibc.malloc.perturb=N` 会用字节 N 填充被释放的堆，使堆布局确定、泄露可靠。部分解法还用 `glibc.malloc.tcache_max` 或 `glibc.malloc.check`。
- **Full RELRO**——GOT 只读，所以所有利用都改为针对 `__free_hook` 或 `__malloc_hook`。

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的利用脚本（堆风水 + 伪造用户方案） |
| `desc.txt` | 题目描述 |
| `artifacts/bounty_program_alpha.tar.gz` | 原始题目二进制 + wrapper + libc |
| `solution/*.md` | 社区题解（24 篇） |
