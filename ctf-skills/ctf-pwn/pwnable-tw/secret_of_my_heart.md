---
tags:
  - off-by-null
  - heap-consolidation
  - fastbin-dup
platform: pwnable.tw
points: 400
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "创建 secret 时的一字节 off-by-null 可清掉 prev_inuse 位，触发向低地址合并进仍在使用的 chunk，进而覆盖 __malloc_hook。"
proof-of-concept: no
---

# Secret Of My Heart — pwnable.tw（400 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10302`
>
> Flag：`FLAG{It_just_4_s3cr3t_on_the_h34p}`

## 题目概况

一道堆菜单题（x86-64，Full RELRO、PIE、NX、Canary），链接 glibc 2.23。玩家可以新增、查看、删除"secret"。每个 secret 的元数据结构体（0x30 字节）位于一块随机的 `mmap` 区域（以 `srand(time(0))` 播种）；其内容缓冲区则在主堆上 `malloc` 出来。内容最大 0x100 字节，没有编辑功能。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO         # GOT not writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## 关键数据结构

### Secret 结构体（0x30 字节，位于 mmap 区域）

```c
struct heart {            // 0x30 bytes, at mmap'd address
    size_t size;          // +0x00
    char   name[0x20];   // +0x08   read 0x20 bytes, NO NUL terminator
    char  *secret;        // +0x28   malloc(size), on main heap
};
```

secret 元数据数组位于一块随机的 `mmap` 地址。最多 100 项。`secret` 指针指向一个 `malloc` 出来的堆 chunk，真正的内容存在那里。

## 漏洞

### V1 — 一字节 off-by-null（poison null byte）—— 主要

**根因：** 创建 secret 时，内容由 `read_n(buf, size)` 读取，然后在 `buf[bytes_read]` 处补 NUL。如果恰好发送 `size` 字节（不带行尾换行），则 `bytes_read == size`，NUL 就写到了 `buf[size]` —— 越过分配区域一个字节。

```c
// ADD function (decompiled)
chunk[5] = (size_t)malloc(size);
printf("secret of my heart :");
result = (_BYTE *)(chunk[5] + (int)read_F((void *)chunk[5], size));
*result = 0;   // <-- off-by-one NULL at buf[size]
```

**影响：** 当 `size == chunksize - 8` 时（例如 `size = 0xf8` → chunk `0x100`，或 `size = 0x88` → chunk `0x90`），这个 NUL 会覆盖**下一个 chunk 尺寸字段的最低字节**，把它的 `prev_inuse` 位清掉（`0x101 → 0x100`）。这就是经典的 **poison null byte** 原语，可借向低地址合并制造 chunk 重叠。

### V2 — name 字段的信息泄漏（堆指针）

**根因：** `name` 字段用 `read_F(name, 0x20)` 读取，**不补 NUL**。`name[0x20]` 缓冲区紧跟着 `secret` 指针（一个堆地址）。`Show` 调用 `printf("Name : %s\n", name)` 时会越过 0x20 字节，把堆指针一起打印出来。

```c
printf("Name : %s\n", (const char *)(unk_202018 + 48LL * idx + 8));
//                     name[0x20] || secret_ptr  ← leaked
```

**影响：** 用 0x20 个非 NUL 字节填满 name → `Show` 泄漏 `secret` 的堆指针 → **堆基址**。

### V3 — 可预测的 mmap 地址（`srand(time(0))`）

**根因：** secret 元数据数组的地址由 `rand() & 0xfffff000` 得出，随机种子是 `srand(time(0))`。攻击者只要在同一时刻本地调用 `srand(time(0))` 就能预测。

```c
srand(time(0));
do { addr = rand() & 0xfffff000; } while (addr <= 0x10000);
secrets = mmap(addr, ...);
```

**影响：** 知道 mmap 基址就能在元数据区伪造 chunk，并把 fastbin 攻击打向那里（例如修改某个 secret 的 `secret` 指针以实现任意读写）。

### V4 — 隐藏命令（0x1305）

把 `4869`（= `0x1305`）当作菜单选项发送，会打印 mmap 基址然后退出。实际利用中用不上（因为它会断开连接），但可以确认 mmap 地址。

## 利用路径

所有解法都用 V1（poison null byte）制造 chunk 重叠，区别在具体的堆布局、泄漏策略和最终劫持目标。

---

### 路径 A — Poison Null Byte → 重叠 chunk → Unsorted Bin 泄漏 → Fastbin Dup → `__malloc_hook`

**使用范围：** 约 80% 的解法（exp.py、8153、13204、25916、34817、37983、7905、18331 等）

这是主流做法：

1. **泄漏堆基址（V2）：** 新增一个 name 填满 0x20 字节的 secret。`Show` 泄漏相邻的 `secret` 指针 → 推出堆基址。

2. **写 poison null byte（V1）：** 依次分配 A、B、C 三个 chunk。释放 B，然后释放并以 `size = chunksize-8` 重新分配 A，触发 off-by-null，清掉 C 尺寸字段中属于 B 的 `prev_inuse` 位。在 padding 里填好伪造的 `prev_size`，使 `free(C)` 触发向低地址合并，把 C 与 B 合成一个大空闲 chunk，从而**覆盖**一个仍处于分配状态的小 chunk D（D 是在释放前于 B、C 之间分配的）。

3. **泄漏 libc：** 重叠的 chunk D 现在与已释放的 unsorted bin 元数据重合，`Show(D)` 读出 `fd` 指针 → `main_arena + 0x58` → 减去偏移 → **libc 基址**。

4. **Fastbin dup / fastbin attack：** 借重叠改写一个已释放 fastbin chunk 的 `fd`，指向 `__malloc_hook - 0x23`（glibc 2.23 里经典的 0x7f 尺寸技巧）。两次 `malloc(0x68)` 之后，第三次就返回 `__malloc_hook` 附近的指针。

5. **覆盖 `__malloc_hook`：**
   - **简单做法：** 直接把 `one_gadget` 写进 `__malloc_hook`。
   - **realloc 技巧：** 把 `one_gadget` 写进 `__realloc_hook`，把 `realloc + offset` 写进 `__malloc_hook`。malloc 触发后先跳到 realloc，后者在 `call __realloc_hook` 之前用额外的 `push` 调整了 `rsp`，从而满足 one_gadget 的 `[rsp+0x30]==NULL` 约束。

6. **触发：** 任意会调用 `malloc` 的操作（例如新增一个 secret，或通过双重释放触发 `malloc_printerr`）→ one_gadget → shell。

**realloc hook 技巧细节：**

```python
# user data starts at __malloc_hook - 0x13
payload = b'\x00' * 0x0b       # padding to reach __realloc_hook
payload += p64(one_gadget)      # __realloc_hook
payload += p64(realloc + 0xc)   # __malloc_hook
# Flow: malloc → jmp __malloc_hook (= realloc+0xc)
#       → push rbx; sub rsp,0x38; ... call __realloc_hook
#       → one_gadget with adjusted rsp
```

---

### 路径 B — Poison Null Byte + 可预测 mmap（V3）→ Fastbin 打进 mmap 区 → 任意读写

**使用范围：** 解法 370、8、59、821、1303、2277、3498、34817

这个变体利用可预测的 mmap 地址，在元数据区伪造 chunk：

1. **预测 mmap 基址（V3）：** 本地执行 `srand(time(0)); rand() & 0xfffff000`。

2. **泄漏堆基址（V2）：** 同路径 A。

3. **Poison null byte → 重叠：** 同路径 A。

4. **Fastbin 攻击打向 mmap 区：** 把被污染的 fastbin `fd` 指向 mmap 元数据区（里面装着各 secret 结构体）。malloc 在元数据区返回 chunk 后，就能改写某个 secret 结构体的 `secret` 指针，令其指向任意地址。

5. **任意读：** 让 `secret` 指向装着 unsorted bin `fd` 的堆地址 → `Show` 泄漏 libc。

6. **任意写：** 让 `secret` 指向 `__malloc_hook`、`__free_hook` 或 `__environ` → 按需覆盖或泄漏。

7. **劫持：**
   - `__free_hook = system` → 释放一个含 `"/bin/sh"` 的 secret。
   - `__malloc_hook = one_gadget` → 触发 malloc。

---

### 路径 C — Poison Null Byte → 经 `__environ` 泄漏栈 → 栈上 ROP

**使用范围：** 解法 8、59、3498

1. **同样的重叠 + libc 泄漏**，同路径 A/B。
2. **泄漏栈：** 把某个 secret 的 `secret` 指针指向 `libc.__environ` → `Show` 泄漏栈地址。
3. **在栈上做 fastbin 攻击：** 用该栈地址找到 `read_n()` 返回地址附近一个值为 0x7f 的字节，在那里放一个假 fastbin chunk。
4. **ROP 链：** 用 `pop rdi; ret; "/bin/sh"; system` 覆盖 `read_n()` 的返回地址。

---

### 路径 D — House of Orange / FSOP（覆盖 `_IO_list_all`）

**使用范围：** 解法 138、278、1006

不打 hook，而是破坏 `_IO_list_all` / `_IO_2_1_stdout_` 的 vtable：

1. **同样的重叠 + libc 泄漏。**
2. **Fastbin 攻击打向 `stdout`：** 把 FILE 结构体的 vtable 指针改成堆上的假 vtable，其 `xsputn` 槽放 `system` 或 `one_gadget`。
3. **触发：** 任意 `printf`/`puts` 调用都会走被污染的 vtable → shell。

另一种做法是改坏 `_IO_list_all`，让它指向堆上的假 FILE 结构（溢出处理函数为 `system`），然后触发 `malloc_printerr` → `_IO_flush_all_lockp` → shell。

---

### 路径 E — House of Einherjar（直接版）

**使用范围：** 解法 821、3498

这里的 poison null byte 用法不同 —— 不走常规的向低地址合并，而是精心构造 `prev_size`，让合并一路回溯到一个放在 mmap 元数据区（或受控堆地址）的假 chunk，从而直接把分配引导到任意位置。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 一字节 off-by-null | V1：add 中的 `buf[size] = 0` | 确定性 |
| 堆基址泄漏 | V2：name[0x20] 未补 NUL | 确定性 |
| mmap 基址预测 | V3：`srand(time(0))` | 约 1 秒的时间窗口 |
| Chunk 重叠 | V1 + 向低地址合并 | 确定性 |
| libc 泄漏（unsorted bin fd） | 重叠 chunk 读到已释放的元数据 | 确定性 |
| Fastbin dup / 污染 | 重叠 → 同一 chunk 的双重视图 | 确定性 |
| 写 `__malloc_hook` | fastbin 攻击到 `malloc_hook - 0x23` | 确定性 |
| 代码执行 | 经 `__malloc_hook` 或 `__free_hook` 打 `one_gadget` | 确定性 |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
__malloc_hook   = 0x3c3b10
__realloc_hook  = 0x3c3b08
__free_hook     = 0x3c57a8
__libc_realloc  = 0x83b10
main_arena + 88 = 0x3c3b78   # unsorted bin fd leak value
system          = 0x45390
environ         = 0x3c5f38
bin_sh          = 0x18c177
_IO_list_all    = 0x3c4520
stdout          = 0x3c4620

# Fake fastbin chunk for __malloc_hook
fake_chunk      = __malloc_hook - 0x23   # *(fake+8) = 0x7f from adjacent relocation

# one_gadgets
one_gadgets     = [0x4526a, 0xef6c4, 0xf0567]

# realloc trick offsets (realloc + N skips N bytes of push prologue)
realloc_offsets = [0x0, 0x2, 0x4, 0x6, 0xb, 0xc, 0xd]
# Winning combo: __malloc_hook = realloc+0xc, __realloc_hook = 0x4526a
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `370.md` | B | 预测 mmap + fastbin 打进 mmap → vtable 攻击 | 覆盖 `_IO_2_1_stdout_` 的 vtable |
| `8.md` | B + C | 预测 mmap + fastbin → environ → 栈上 ROP | 完整链条：堆 → libc → 栈 |
| `59.md` | B + C | 预测 mmap + poison null → environ → 栈上 ROP | 用 numpy 预测 rand |
| `138.md` | D | 经 `_IO_list_all` 做 House of Orange / FSOP | Ruby 脚本；伪造 FILE 结构 |
| `278.md` | D | fastbin → 覆盖 stdout vtable | Ruby；破坏 `_IO_2_1_stdout_` |
| `550.md` | A | poison null → 重叠 → unlink → libc → fastbin → `__free_hook` | 经典 unlink + top chunk 技巧 |
| `821.md` | B + E | 预测 mmap + House of Einherjar → `__free_hook` | 双脚本，含 rand 预测服务 |
| `1006.md` | A | poison null → 重叠 → fastbin dup → `__malloc_hook` | 标准套路，先做堆泄漏 |
| `1303.md` | B | 预测 mmap → fastbin 打进 mmap → `__malloc_hook` | 用 C 辅助程序复现 srand/rand |
| `2277.md` | B | 预测 mmap → fastbin 打进 mmap → `__free_hook` | 用了 unsorted bin attack |
| `3498.md` | B + E | 预测 mmap + Einherjar → fastbin → `__free_hook` | 详细的结体分析 |
| `7905.md` | A | poison null → 重叠 → unlink → libc 泄漏 → fastbin → `__malloc_hook` | 结构清晰的 exploit |
| `8153.md` | A | poison null → 重叠 → fastbin dup → `__malloc_hook` | realloc hook 技巧 |
| `13204.md` | A | poison null → 重叠 → `__malloc_hook` + one_gadget | 中文详细 writeup |
| `18331.md` | A | 标准 poison null → fastbin → `__malloc_hook` | 简洁 |
| `25916.md` | A | poison null → 重叠 → fastbin → `__malloc_hook` | 用双重释放触发 |
| `34817.md` | B + A | 预测 mmap + poison null → fastbin → `__malloc_hook` | realloc 技巧 |
| `37983.md` | B + E | 预测 mmap + Einherjar → 分配到 mmap → `__malloc_hook` | realloc 技巧，注释详细 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit（自包含，不用 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/secret_of_my_heart` | 原始题目二进制（stripped，PIE） |
| `artifacts/libc_64.so.6` | 远端 libc（glibc 2.23） |
| `solution/*.md` | 社区 writeup（99 份解法） |
