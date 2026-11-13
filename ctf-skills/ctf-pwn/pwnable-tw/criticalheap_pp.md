---
tags:
  - type-confusion
  - use-after-free
  - arbitrary-write
platform: pwnable.tw
points: 600
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "多态 C++ 对象在没有虚析构函数的情况下被销毁，导致悬垂指针复用与类型混淆，从而实现任意内存写入。"
proof-of-concept: no
---

# Critical Heap++ — pwnable.tw（600 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10500`
>
> Flag：`FLAG{Cr1t1c4l_h34p_is_very_cr4zyyyyyyyyyy}`
>
> 注意：通过 `localtime()`/TZ 技巧无需 shell 即可读到诱饵 flag `FLAG{Oh_y0u_f1nd_th3_s3cr3t_1n_loc4ltim3}`。真实 flag 需要 shell → 用口令 `"Crazy heap !!"` 运行 setuid 的 `get_flag` 二进制。

## 题目概览

一个堆管理程序（x86-64，**Full RELRO**、Canary、NX、**无 PIE**，基址 `0x400000`），链接 glibc 2.23。它在 BSS 数组（`0x604040`）中维护最多 10 个堆槽位，每个 `0x48` 字节，共三种类型：Normal、Clock 和 System。二进制中**没有显式的 `free()` 调用**——所有堆释放都通过 libc 内部间接发生（`setenv`/`realloc`、`localtime`/`tzset`、`realpath`）。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
```

### 堆类型

| 类型 | Magic | 能力 |
|------|-------|-------------|
| Normal（`1`） | `0x13371337` | 显示/修改内容（格式化字符串漏洞的 `printf`）、名字缓冲区 |
| Clock（`2`） | `0xdeadbeef` | 显示/更新时间（`localtime()` → 触发 `tzset()` → 释放旧的 TZ） |
| System（`3`） | `0x48694869` | `setenv`/`unsetenv`/`realpath`/`getenv` ——与 libc 的堆内部交互 |

### 菜单

`1.Create / 2.Show / 3.Rename / 4.Play / 5.Delete / 6.Exit`

## 漏洞

### V1 —— `realpath(buf, buf)` 堆缓冲区溢出（主要，可利用）

**根因：** 在操作 System 堆时，选项 3（“Get real path”）会调用 `realpath(path, path)`，其中 `path` 同时作为源和目标是同一个堆缓冲区。当 `path` 是像 `"."` 这样的短相对路径时，`realpath` 会把它解析成完整绝对路径（例如 `"/home/critical_heap++/home"`——26 字节）并写回这个小缓冲区，**溢出到下一个堆 chunk 的元数据**。

```c
// Simplified from decompilation
char *path = entry->cwd;  // from get_current_dir_name(), can be "."
realpath(path, path);      // source == destination → overflow
```

**触发方式：** 通过 `unsetenv("PWD")` + `setenv("PWD", ".")` 设置 `PWD="."`，然后创建一个 System 堆（它会调用 `get_current_dir_name()`——当 `PWD` 与 `.` 匹配时返回 `strdup(".")`）。对它调用 `realpath`。

**影响：** 用 `0x656d`（ASCII 的 `"me"`，来自 `/home/critical_heap++/ho**me**`）覆盖相邻空闲 chunk 的 `size` 字段。这就造出一个远超其实际分配范围的巨大空闲 chunk，从而可以进行受控的重叠分配。

```c
// PoC demonstrating the overflow:
setenv("PWD", ".", 1);
char *c = get_current_dir_name();  // returns "." (malloc'd, tiny chunk)
// allocate victim right after
char *victim = malloc(1);          // victim chunk size = 0x21
realpath(c, c);                    // overflow! writes "/home/critical_heap++/home"
// victim chunk size is now 0x656d
```

### V2 —— 通过 Normal 堆的格式化字符串读取（可利用）

**根因：** `Play → Normal → 1.Show content` 会调用 `__printf_chk(1, content)`，而 content 由用户控制。虽然 FORTIFY 会阻断 `%n` 和按位置引用参数 `%N$`，但顺序的 `%c`/`%p`/`%s` 仍可用于读取。

```c
// User controls content via "Change content"
__printf_chk(1, content);  // format string vuln — arbitrary read
```

**触发方式：** 把 content 设为 `"%c"*11 + "%s" + p64(target_addr)`。`%s` 会从目标地址读取（该地址经 `read()` → `strncpy()` 路径被放到栈上）。

**影响：** 任意内存读。可用于泄露：
- **libc 基址**（由于无 PIE，可从固定地址读取 GOT 表项，如 `atoi@GOT`）
- **堆地址**（从 name/content 缓冲区读取残留指针）
- **栈地址**（从 libc 读取 `environ` 指针）

### V3 —— `localtime()`/`tzset()` 可控释放（使能点）

**根因：** 当 `TZ` 环境变量变化时，`tzset()`（由 `localtime()` 调用）会释放旧的时区数据缓冲区并分配新的。通过控制 `TZ`，我们就能控制被释放 chunk 的大小。

```c
// Inside glibc tzset/localtime:
tz = getenv("TZ");
free(old_tz);                    // frees old TZ strdup
old_tz = tz ? __strdup(tz) : NULL;
```

**影响：** 可制造特定大小的 fastbin chunk（尤其是 0x70）：
1. `setenv("TZ", "A"*0x60)` —— 为 TZ 数据分配一个 0x70 chunk
2. 更新 Clock 堆 → `localtime()` → `tzset()` 读取新 TZ → 释放旧的 0x70 chunk

### V4 —— `setenv`/`realloc(environ)` 可控分配/释放（使能点）

**根因：** glibc 的 `setenv` 会对内部的 environ 数组使用 `realloc`。增加/删除环境变量会触发 `realloc`，释放旧缓冲区并分配新的，造出大小可控的 unsorted bin chunk。

**影响：** 配合 V1，可实现精确的堆布局控制——把空闲 chunk 放在 `realpath` 溢出能够触及的位置。

### V5 —— Show 时的名字缓冲区泄露（次要）

**根因：** `Show` 用 `printf("%s", name)` 打印堆名字。由于 `strdup` 可能把 name chunk 放在其他数据旁边，而名字在边界处并不总是有 NUL 终止，相邻的堆元数据（包括空闲 chunk 中的 libc 指针）就可能泄露。

## 利用路径

### 路径 A —— `realpath` 溢出 → fastbin 攻击 → `__malloc_hook`（最常见）

**使用者：** 解法 11、59、370、678、755、1351、1912、1980、2972、3851、7905、34817、38838、exp.py

**步骤：**

1. **泄露 libc**：通过 V2（格式化字符串读 GOT 表项）或 V5（名字缓冲区与空闲 chunk 相邻）。

2. **制造 0x70 fastbin chunk**：通过 V3——把 `TZ` 设为一个 0x60 字节的字符串，创建一个 Clock 堆，然后把 `TZ` 改为 `":"` 并更新时间 → `localtime()` → `tzset()` 释放旧的 0x70 TZ chunk。

3. **触发 V1（`realpath` 溢出）：** 准备好 `PWD="."`，创建一个 System 堆取得很小的 `cwd` 缓冲区，调用 `realpath` → 溢出进相邻的空闲 chunk，把它的 `size` 改坏为 `0x656d`。

4. **从被破坏的 chunk 分配：** 这个 0x656d 大小的空闲 chunk 进入 unsorted bin。后续 `malloc` 会从中切出若干块，最终产生一个**与 0x70 fastbin chunk 重叠**的 chunk。

5. **fastbin 投毒：** 用 `Rename` 把重叠的 0x70 chunk 的 `fd` 指针覆盖为 `__malloc_hook - 0x23`（该处存在 `0x7f` 字节可充当伪造 chunk 大小）。

6. **从 fastbin 分配两次：** 第一次 `malloc(0x60)` 返回真实的 0x70 chunk。第二次返回位于 `__malloc_hook - 0x13` 的伪造 chunk。

7. **覆盖 `__malloc_hook`：** 对伪造 chunk 执行 `Rename`：`"\x00"*3 + p64(one_gadget)` 会把 `one_gadget` 写到 `__malloc_hook`。

8. **触发：** 后续任意 `malloc`（例如 `Create` 一个新堆 → `strdup(name)`）都会调用 `__malloc_hook` → one_gadget → shell。

```python
# Core fastbin attack payload
rename(name_chunk, 'X'*offset + p64(0) + p64(0x71) + p64(__malloc_hook - 0x23))
# ... two mallocs of 0x60 ...
rename(fake_chunk, '\x00'*3 + p64(one_gadget))
```

### 路径 B —— `realpath` 溢出 → unsafe unlink → 覆盖 BSS → FSOP/`stdout` 劫持

**使用者：** 解法 278、550、755

**步骤：**

1. **泄露 libc + 堆**：通过 V2（格式化字符串）。

2. **触发 V1**，破坏某个 unsorted bin chunk 的 size。

3. **从被破坏的 chunk 分配**，使其与某个 `environ` 数组缓冲区（来自 `setenv` → `realloc`）重叠。伪造能通过 unlink 的 `FD->bk == P && BK->fd == P` 检查的 chunk 元数据（fd、bk、size），其中 `fd = 0x604088-0x18`、`bk = 0x604088-0x10`（指向 BSS 中的堆槽位数组）。

4. **触发 unsafe unlink**：调用 `setenv`，它会对 environ 数组 `realloc` → 与伪造 chunk 合并 → unlink 把 `&heap_slots[N].name - 0x18` 写入 `heap_slots[N].name`。

5. **对槽位 N 使用 `Rename`** 覆盖 BSS 堆数组中的其他槽位。把某个槽位的 name 指向 BSS 中的 `stdout` FILE 指针。

6. **在堆上伪造 `_IO_FILE_plus`** 结构，把 `vtable.__xsputn = system`，flags 中含有 `"/bin/sh"`。

7. **覆盖 `stdout`**，使其指向伪造的 FILE 结构。下一次 `printf` 调用 → `system("sh")`。

### 路径 C —— `realpath` 溢出 → 重叠 chunk → unsorted bin 攻击 → 在 BSS 分配 → 栈 pivot/ROP

**使用者：** 解法 550、755、821

**步骤：**

1. **泄露 libc + 堆 + 栈**：通过 V2。
2. **触发 V1** 溢出，制造重叠 chunk。
3. **破坏某个空闲 chunk 的 `bk`**，使其指向一个具有合法伪造 size 的 BSS 地址。
4. **从 unsorted bin 分配**——`malloc` 会把该 BSS 地址当作 chunk 返回。用 `Rename` 覆盖堆槽位的 `name` 指针。
5. **把某个槽位的 name 指向栈上保存的 RBP**。`Rename` 写入栈 pivot gadget 或 ROP 链（`pop rdi; ret; "/bin/sh"; system`）。
6. 函数返回时，控制流被劫持。

### 路径 D —— `realpath` 溢出 → 覆盖 `_IO_list_all` → 通过 malloc abort 触发 FSOP

**使用者：** exp.py、解法 38838

**步骤：**

1. **泄露 libc + 堆**：通过 V2 或 V5。
2. **触发 V1** 并制造重叠 chunk，从而获得对 BSS 堆槽位的任意写。
3. **在堆上伪造 `_IO_FILE_plus`**：`flags = "/bin/sh\0"`、`_IO_write_base < _IO_write_ptr`（满足 overflow 检查）、`vtable` 指向含有 `__overflow = system` 的伪造 vtable。
4. **覆盖 `_IO_list_all`**，使其指向伪造的 FILE 结构。
5. **触发 `malloc` abort**（例如 double-free 或破坏）→ `_IO_flush_all_lockp` → 遍历 `_IO_list_all` → 对伪造 FILE 调用 `__overflow` → `system("/bin/sh")`。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 堆溢出（把下一个 chunk 的 size 改成 0x656d） | V1：`realpath(buf, buf)` | 确定性 |
| 任意内存读 | V2：Normal 堆中的格式化字符串 | 确定性 |
| 可控释放（0x70 fastbin） | V3：`localtime()`/`tzset()` 的 TZ 变化 | 确定性 |
| 可控分配/释放（unsorted bin） | V4：`setenv`/`realloc(environ)` | 确定性 |
| libc 泄露 | V2（读 GOT）或 V5（堆相邻） | 确定性 |
| fastbin 投毒 → `__malloc_hook` | 重叠 chunk + 覆盖 fd | 布局确定后确定性 |
| 代码执行 | `__malloc_hook` = one_gadget / FSOP | 确定性 |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
__malloc_hook  = 0x3c3b10
__free_hook    = 0x3c57a8
_IO_list_all   = 0x3c4520
system         = 0x45390
one_gadgets    = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
# For fake fastbin chunk at __malloc_hook:
fake_fast_addr = __malloc_hook - 0x23   # or -0x13 (user data)
# BSS heap slots array
heap_slots     = 0x604040
```

## 拿到 shell 之后：取真实 flag

shell 以 `uid=1000` 运行。真实 flag 属于 `uid=1001`，权限 `400`：
```text
-r-------- 1 1001 1001   43 .You_found_the_fl4g
-r-sr-xr-x 1 1001 1001 9232 get_flag          # setuid 1001
```

执行：`cd /home/critical_heap++ && ./get_flag` → 输入 `"Crazy heap !!"` → 打印真实 flag。

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `11.md` | A | 格式化字符串泄露 + 通过重叠 chunk 的 fastbin | Ruby 利用 |
| `59.md` | A | `%s` 读 GOT 泄露 + realpath 溢出 + fastbin 攻击 | 干净的 Python2 |
| `278.md` | B | unsafe unlink → BSS → `stdout` FSOP | 最复杂的思路；解释详细 |
| `370.md` | A | localtime 释放 + realpath 溢出 + fastbin | 指出了两个 flag（诱饵 + 真实） |
| `550.md` | C | 两个重叠的 environ 缓冲区 → unsorted bin 攻击 → BSS → 栈 pivot | 非常详细的 8 步题解 |
| `560.md` | A | 操纵 node 结构 → BSS 链接 → 任意写 | 使用 `tsearch` 树破坏 |
| `678.md` | A | 删除再重建泄露 + fastbin 攻击 | 紧凑的利用 |
| `755.md` | B+C | unsafe unlink + 修复树 + 覆盖 BSS → ROP | 详细，含树节点修复 |
| `821.md` | A | 多次触发 realpath + environ 操纵 | 用 environ realloc 制造 unsorted bin |
| `1351.md` | A | 各种 TZ 大小 → fastbin 大小 + realpath + fastbin 攻击 | 有条理的堆布置 |
| `1912.md` | A | localtime 释放制造 fastbin + realpath 溢出 | 格式化字符串用 `%s` + GOT 泄露 |
| `1980.md` | A | 大量环境变量操纵 + realpath + 经 `__free_hook` 的 FSOP | 用 `gets` gadget 覆盖 `stdout` |
| `2972.md` | A | 标准 fastbin 攻击 | 干净的 Python3 |
| `3851.md` | A | 通过 show 泄露堆/libc + fastbin 攻击 | 冗长，含堆布局管理 |
| `7905.md` | A | 详细中文题解；记录了诱饵 flag 陷阱 | 最全面分析；完整的格式化字符串 + fastbin |
| `8153.md` | — | 一行说明（“realpath overflow”） | 无利用代码 |
| `34817.md` | A | `PWD=../critical_heap++` 变体 | 用相对路径变体触发 realpath |
| `38838.md` | D | 经 `_IO_list_all` 的 FSOP + 伪造 vtable | 用堆重叠 → BSS → 覆盖 `_IO_list_all` |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的利用脚本（经 `_IO_list_all` 的 FSOP 路径） |
| `desc.txt` | 题目描述 |
| `artifacts/libc_64.so.6` | 远程 libc（glibc 2.23） |
| `solution/*.md` | 社区题解（24 篇） |
