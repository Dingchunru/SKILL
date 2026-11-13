---
tags:
  - heap-buffer-overflow
  - unsorted-bin-attack
  - tcache-poisoning
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
description: "一字节堆溢出可让重叠的堆 chunk 在 FORTIFY_SOURCE 约束下伪造 tcache 条目，并劫持 __free_hook。"
proof-of-concept: no
---

# Bounty Program β — pwnable.tw（500 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10410`
>
> Flag：`FLAG{STRt0k_1s_v3ry_d4ng3rouS_And_d0nt_f0rg3t_ch3ck_NuLl_p7r}`

## 题目概览

一个漏洞赏金平台二进制（x86-64，Full RELRO、PIE、NX、Canary、FORTIFY），链接 glibc 2.27。用户可以注册/登录、创建产品、提交带描述的漏洞报告、管理漏洞类型，以及评估 bug。还有一个 `wrapper` 二进制，会在执行主程序前设置一个环境变量。这是 “Bounty Program α” 的修补版——`malloc` 换成了 `calloc`，基于 `strlen` 的密码泄露被移除，基于 `urandom` 的描述初始化也被移除——但核心的 `strtok` UAF bug 依然存在。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

## 关键数据结构

### User（0x58 字节）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00` | `password` | `char[16]` |
| `0x10` | `username` | `char[32]` |
| `0x30` | `bounty` | `void *` |
| `0x38` | **`contact`** | `char *`（写原语的目标） |
| `0x40` | `uid` | `uint64_t` |
| `0x48` | `ref_cnt` | `uint64_t` |
| `0x50` | `next` | `struct User *` |

### 漏洞报告（0x140 字节）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x000` | `title` | `char[256]` |
| `0x100` | `user_ptr` | `struct User *` |
| `0x108` | `descrip_size` | `uint64_t` |
| `0x110` | `ID` | `uint32_t` |
| `0x118` | **`descrip_ptr`** | `char *` |
| `0x120` | `type_ptr` | `struct Type *` |
| `0x128` | `next` | `struct Report *` |
| `0x130` | `prev` | `struct Report *` |
| `0x138` | `evaluated` | `uint8_t` |

### 漏洞类型（0x10 字节）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00` | `name_ptr` | `char *` |
| `0x08` | `price` | `int` |
| `0x0c` | `ref_cnt` | `int` |

## 漏洞

### V1 —— 通过 `calloc(NULL)` 触发 `strtok` UAF（主要，可利用）

**根因：** 在 `add_type()` 中，用户可控的 `size` 被传给 `calloc(1, size)`。传入 `-1`（或 `0xffffffff` / `0xffffffffffffffff`）会使 `calloc` 失败并返回 `NULL`。代码**没有**检查返回值。随后调用 `strtok(NULL, ",")`——由于第一个参数是 `NULL`，`strtok` 会复用此前某次 `strtok` 调用留下的内部 `olds` 指针，从而在**已经释放的内存**上操作。

```c
// add_type (simplified)
char *buf = calloc(1, user_size);  // returns NULL on huge size
// NO NULL CHECK
strtok(buf, ",");  // if buf==NULL, reuses olds from prior strtok
// iterates: strtok(NULL, ",") reads/writes through freed chunk
```

**影响：**
- **读原语：** `olds` 指针指向一个被释放的 chunk。如果该 chunk 在某个 free list（unsorted bin、smallbin、fastbin、tcache）中，其 `fd`/`bk` 元数据就会被当作“类型名”读出并打印回来 → 泄露**堆**和 **libc** 地址。
- **写原语：** `strtok` 会扫描分隔符 `,`（字节 `0x2c`）。如果被释放 chunk 的元数据中某个指针含有 `0x2c`（例如 `0x????2c??`），`strtok` 就会用 NUL **覆盖**该字节，从而改变这个指针。这会破坏堆元数据或结构体字段指针。

### V2 —— 通过 `strtok` 的 NUL 写入破坏堆指针

**根因：** `strtok` 会把分隔符字节替换成 `\x00`。当 `olds` 指向一个含有 `0x2c` 的堆指针时（这很常见——例如地址 `0x5555????2c10`），该 `0x2c` 字节会被清零 → `0x5555????0010`。这就把指针实际改成了另一个堆位置。

**影响：** 配合堆布局调整，可以提供：
- 把某份报告的 `descrip_ptr` 改坏，使其与另一个结构重叠
- 破坏 tcache/fastbin 的 `fd` 指针，实现任意分配
- 破坏用户的 `contact` 指针，从而能通过 `change_contact()` 实现任意写

### V3 —— 通过修改报告造成描述指针重叠

**根因：** `modify_report()` 允许把描述大小改得更大并调用 `realloc()`。如果新的描述与先前释放的报告或类型 chunk 重叠，就能通过描述读写这块重叠内存。

## 利用路径

所有解法都利用 V1（`strtok` UAF）实现泄露。区别在于写原语和最终劫持方式。

---

### 路径 A —— `strtok` UAF → 泄露 libc/堆 → `__free_hook` + `setcontext` → ORW ROP

**使用者：** 解法 370、821、3148、5586、6247、8153、22319、31599、36134、36997

**步骤：**

1. **泄露 libc：** 调用 `add_type(large_size, ...)` 让某个 chunk 进入 unsorted bin。接着 `add_type(-1, ...)` 触发 `strtok` UAF——`olds` 指向被释放 chunk 的元数据 → 读回 `main_arena` 指针 → 算出 libc 基址。

2. **泄露堆：** 把一个较小的 chunk 释放进 fastbin/tcache，再触发一次 `strtok` UAF → 读回堆的 `fd` 指针 → 算出堆基址。

3. **堆布局调整：** 精心安排分配，使某份报告的描述位于地址 `0x????2cXX`。用 `strtok` 的 NUL 写入（V2）破坏某个被释放 chunk 的 `fd` 指针，把它重定向到与报告结构或用户结构重叠的位置。

4. **写原语：** 三选一：
   - 通过被破坏的 fastbin/tcache 分配，把某个用户的 `contact` 指针覆盖为 `__free_hook`，再用 `change_contact()` 把 `setcontext+53` 写到 `__free_hook`。
   - 把某份报告的 `descrip_ptr` 改坏，使其指向 `__free_hook`，再通过 `modify_report()` 写入。
   - 直接对 tcache fd 投毒，在 `__malloc_hook` 处分配。

5. **触发：** 对某个首 8 字节指向 `SigreturnFrame` 或 ROP 链的 chunk 调用 `free()`。`setcontext+53` 完成栈 pivot。ROP 链执行 `open("/home/bounty_program/flag") → read → write(1, ...)`。

**可靠性：** 约 50–100%，取决于堆基址对齐（部分解法要求 `heap_base & 0xf000 == 0xf000` 才能用 `0x2c` 技巧，也就是 1/16 的爆破概率）。

---

### 路径 B —— `strtok` UAF → tcache 投毒 → `__malloc_hook` + 栈 pivot → ORW

**使用者：** 解法 25916、34817、37983

**步骤：**

1. **泄露 libc + 堆：** 与路径 A 相同，反复调用 `add_type(-1)`。

2. **堆填充：** 分配较大的描述，使下一次分配对齐到 `0x????2cXX`，让 `strtok` 的 NUL 写入把某个 tcache chunk 的 `fd` 改坏，指向一个受控位置（例如 `__malloc_hook` 附近）。

3. **tcache 投毒：** 被改坏的 `fd` 链中现在包含一个位于 `__malloc_hook - 0x14` 附近的伪造条目。沿 tcache 链连续分配，直到落在 `__malloc_hook` 上，然后用 `add_rsp_0x48` 或 `leave; ret` gadget 覆盖它。

4. **触发：** 下一次 `calloc`（通过 `remove_type` 传入精心构造的 size 作为 `rbp` 值）会触发 `__malloc_hook`。栈 pivot 会落在预先放好的、执行 ORW 的 ROP 链上。

**可靠性：** 在某些配置下比路径 A 更高，因为它避开了用户结构破坏带来的复杂度。

---

### 路径 C —— `strtok` UAF → 报告重叠 → 伪造报告 → `__malloc_hook` + `leave; ret`

**使用者：** 解法 370（exp.py）、9251、32010

**步骤：**

1. **泄露：** 同样用 strtok UAF 获取 libc 和堆地址。

2. **堆布局：** 把某份报告的描述安排在一个可被 NUL 写入的地址上。用 strtok 的 NUL 写入让描述指针与另一份报告的结构内存重叠。

3. **伪造报告：** 通过重叠的描述写入，伪造一份 `descrip_ptr = __malloc_hook` 的报告。对这份伪造报告调用 `modify_report()`，把 `leave; ret` 写到 `__malloc_hook`。

4. **放置 ROP 链：** 通过某份漏洞报告的标题/描述，把 ROP 链放到已知的堆地址上。

5. **触发：** `remove_type(heap_rop_address, ...)` → `calloc(1, heap_rop_address)` → `__malloc_hook(heap_rop_address)` → `leave; ret` pivot 到 ROP 链 → ORW shellcode。

---

### 路径 D —— `GLIBC_TUNABLES` + 关闭 tcache → fastbin UAF → `__free_hook`

**使用者：** 解法 2972、3498、6923

**步骤：**

1. **关闭 tcache：** 用 wrapper 设置 `GLIBC_TUNABLES=glibc.malloc.tcache_count=0`（或 `tcache_max=32`）。这会迫使所有分配走 fastbin/smallbin/unsorted bin，简化堆布局调整。

2. **泄露 + 重叠：** 同样用 strtok UAF，但没有 tcache 后 free list 的行为更可预测，被释放的用户结构会直接进入 fastbin。

3. **释放 root 用户：** 分配一份与某个被释放用户结构重叠的报告。修改该报告，把用户的 `contact` 字段改坏为 `__free_hook`。用 `change_contact()` 写入 `setcontext+53`。

4. **通过 free 触发：** 释放一份标题中含有 SROP 帧 / ROP payload 的报告 → `setcontext` 完成 pivot → ORW。

---

### 路径 E —— `strtok` UAF → 控制 `tcache_perthread_struct` → 任意分配

**使用者：** 解法 2972

**步骤：**

1. **安排 tcache chunk** 位于地址 `0x????2cXX`，释放它，然后再释放另一个同尺寸 chunk。

2. **strtok 的 NUL 写入** 改变第一个 chunk 的 `fd` 指针，使其指向堆顶的 `tcache_perthread_struct`。

3. **`strdup`**（内部被调用）会消费被投毒的 tcache 链，并在 `tcache_perthread_struct` 之上分配，从而完全控制所有 tcache bin 的头指针。

4. **写入任意 tcache 条目**，把后续分配重定向到 `__free_hook` 或 `__malloc_hook`。

## 与 Bounty Program α 的差异

| 特性 | Alpha | Beta |
|---------|-------|------|
| `malloc` 与 `calloc` | `malloc` | `calloc`（会清零内存） |
| 经 `strlen` 的密码哈希泄露 | 存在 | 已移除 |
| 描述中的 urandom | 存在 | 已移除 |
| `change_contact`/`change_password` | 做了 `strlen` 检查 | 定长输入 |
| 核心 `strtok` bug | 存在 | **仍然存在** |
| `calloc(-1)` 返回 NULL | 不适用 | 可利用（无 NULL 检查） |

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| libc 泄露（main_arena） | V1：对 unsorted bin chunk 的 strtok UAF | 确定性 |
| 堆泄露 | V1：对 fastbin/tcache chunk 的 strtok UAF | 确定性 |
| 在 0x2c 处写 NUL 字节 | V2：覆盖 strtok 分隔符 | 需要指针中含 `0x2c`（约 1/16 堆 ASLR） |
| 任意写 | 被破坏的 contact/描述指针 | 对齐后确定性 |
| 代码执行 | `__free_hook`/`__malloc_hook` + setcontext/leave;ret | 取得写之后确定性 |
| 读取 flag（不用 `execve`） | ORW ROP 链：open→read→write | 必需（seccomp 或沙箱） |

## 偏移（pwnable.tw `libc-2.27.so`）

```python
main_arena       = 0x3ebc40
unsorted_bin     = 0x3ebca0   # main_arena + 0x60
__malloc_hook    = 0x3ebc30
__free_hook      = 0x3c57a8   # (some solutions use 0x3ed8e8)
setcontext       = 0x520a5    # +53 offset for the usable gadget
leave_ret        = 0x54803
pop_rdi          = 0x2155f
pop_rsi          = 0x23e6a
pop_rdx          = 0x1b96
pop_rax          = 0x439c8
syscall_ret      = 0xd2975
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `370.md` | A | strtok UAF → tcache 清空 → `__free_hook` + setcontext | 两种思路；用 `evaluate` 操纵用户结构 |
| `821.md` | A | strtok UAF → 描述重叠 → `__malloc_hook` + setcontext | 详细的结构分析；用 `GLIBC_TUNABLES` 设 tcache_count=0 |
| `2972.md` | E | strtok → 控制 tcache_perthread_struct | 4 位爆破；用 `strdup` 从被投毒的 tcache 分配 |
| `3148.md` | D | strtok UAF → 伪造 unlink → `__free_hook` | 不需要 GLIBC_TUNABLES；堆布局调整详细 |
| `3498.md` | D | α 和 β 用同一套利用；不用环境变量 | 用 `REMOTE`/`BETA` 开关切换 |
| `5586.md` | A | `GLIBC_TUNABLES=tcache_max=32` → fastbin UAF | 关闭 tcache 以简化 fastbin |
| `6247.md` | D | `GLIBC_TUNABLES=tcache_max=216` → fastbin → 覆盖 contact | 用注册/删除来塑造堆 |
| `6923.md` | C | strtok → `__malloc_hook` + calloc 触发 | 精确的堆对齐；`mprotect` + shellcode |
| `8153.md` | A | strtok + 兼容 α/β | 指出 β 只在 calloc 上不同；strtok bug 相同 |
| `9251.md` | C | 通过 strtok 的 NUL 写入实现 double free → `__malloc_hook` + `leave;ret` | 详细的 NPC/实体相邻技巧 |
| `22319.md` | A | strtok → `__free_hook` + setcontext → mprotect + shellcode | 代码干净；爆破堆基址 |
| `25916.md` | B | tcache 投毒 → 在 `__malloc_hook` 附近分配 | 用堆填充实现 0x2c 对齐 |
| `31599.md` | C | strtok → 描述重叠 → `__malloc_hook` + `leave;ret` | 通过系统调用链实现 ORW |
| `32010.md` | A | strtok → 用户 contact → `__free_hook` + setcontext | 全面的堆遍历；用 fopen 读 flag |
| `34817.md` | B | 1/16 爆破；tcache fd 投毒 → `__free_hook` | 两个脚本（fastbin 版 + tcache 版） |
| `36134.md` | B | 通过 strtok 的 NUL 写入做 tcache 投毒 → `__malloc_hook` | `add_rsp_0x48` gadget + `pop rsp` pivot；解题干净 |
| `36997.md` | A | strtok → 覆盖 `0x2c` → `__malloc_hook` + `leave;ret` | 详细的 strtok 源码分析；1/16 |
| `37983.md` | A | 用 `rand ^ 0xDADADADA` 类型混淆实现产品重叠 | 指出了 α/β 修补之间的差异 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的利用脚本（堆偏移爆破 + ORW shellcode） |
| `desc.txt` | 题目描述 |
| `artifacts/` | 原始题目二进制（bounty_program_beta.tar.gz） |
| `solution/*.md` | 社区题解（22 篇） |
