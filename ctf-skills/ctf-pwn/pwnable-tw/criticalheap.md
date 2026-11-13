---
tags:
  - type-confusion
  - arbitrary-write
  - shellcode
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "system 类型与普通堆对象之间的类型混淆可修改结构体指针，从而获得向 RWX 页的任意写入并执行 shellcode。"
proof-of-concept: no
---

# criticalheap — pwnable.tw（200 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10500`
>
> 诱饵 flag：`FLAG{Oh_y0u_f1nd_th3_s3cr3t_1n_loc4ltim3}`（直接从文件读取，**不被接受**）
>
> 真实 flag：`FLAG{Cr1t1c4l_h34p_is_very_cr4zyyyyyyyyyy}`（需要 shell）

## 题目概览

一个堆管理程序（x86-64，Full RELRO、Canary、NX、**No PIE**、FORTIFY），链接 glibc 2.23。它在全局 BSS 数组（`0x604040`）中维护最多 10 个条目，每个 0x48 字节，分为三种类型：Normal（内容 + 格式化字符串）、Clock（`localtime()`）和 System（`setenv`/`unsetenv`/`getenv`/`realpath`）。菜单：`1.Create / 2.Show / 3.Rename / 4.Play / 5.Delete / 6.Exit`。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only at runtime
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
  FORTIFY:  Enabled              # __printf_chk blocks %n and %N$
```

**关键点：** 题目描述说 *“Try to capture `/home/critical_heap++/flag`”* ——这个文件是**诱饵**。真实 flag 需要 shell，去运行一个 setuid 的 `get_flag` 二进制。

## 数据结构

```c
// Global array at 0x604040, 10 slots of 0x48 bytes each
struct Heap {
    char *name;          // +0x00  strdup'd heap pointer
    uint64_t in_use;     // +0x08
    uint64_t type;       // +0x10  (1=Normal 0x13371337, 2=Clock 0xdeadbeef, 3=System 0x48694869)
    union {              // +0x18
        NormalData normal;
        ClockData  clock;
        SystemData system;
    };
};

struct NormalData {
    char content[0x28];  // +0x18  read() directly into BSS, no NUL termination
    uint64_t is_changed; // +0x40  prevents second change
};

struct SystemData {
    char *dirname;       // +0x18  get_current_dir_name() result
    uint64_t detail;     // +0x20  getenv() stores result pointer here
    // ...
};
```

## 漏洞

### V1 —— 通过 `__printf_chk` 的格式化字符串（主要，任意读）

**根因：** `Play → Normal → 1.Show content` 会调用 `__printf_chk(1, content)`，其中 `content` 由用户控制（存放在 BSS 的 slot+0x18 处）。

```c
// Pseudocode for play_normal_show
__printf_chk(1, &slot[idx].content);  // content is user-supplied format string
```

**限制：** FORTIFY 模式会禁用 `%n`（写）和 `%N$`（位置参数）。不过 `%c`、`%p`、`%s`、`%x` 仍可用于读取。

**利用方式：** `Play → Normal → 2.Change content` 会把输入读进一个栈缓冲区（`local_38`），再复制到 BSS 的 content 中。放在格式说明符之后的 `p64(target_addr)` 会作为第 12–13 个参数落在栈上：

```python
payload = b'%c' * 11 + b'%s' + p64(target_addr)   # %s reads string at target_addr
```

**影响：** 任意内存读。配合 No PIE，可以泄露堆指针、libc 地址（来自 GOT）以及 flag 数据。

### V2 —— `read()` 没有 NUL 终止（堆/信息泄露）

**根因：** Normal 堆内容通过 `read(0, &slot.content, 0x28)` 读入，不追加 NUL 字节。content 字段是 0x28 字节，而 `Show heap`（选项 2）用 `printf("%s", content)` 打印它。

```c
read(0, slot + 0x18, 0x28);  // No NUL terminator
// Later: printf("%s", slot + 0x18);  // reads past content into adjacent data
```

**影响：** 如果 content 填满全部 0x28 字节，`printf("%s")` 就会泄露 content 边界之外的数据——通常是先前某个 System 堆的 `getenv()` 结果（存于 +0x20）留下的堆指针。

### V3 —— Delete 不清空数据（UAF / 类型混淆）

**根因：** `Delete` 只把 `slot.in_use = 0`。它**不会**释放 `name` 指针、清零 content，也不会重置 type。随后在同一索引 `Create` 会复用这个 BSS 槽位，而其中仍残留上一条目的数据。

```c
// delete_heap
slot[idx].in_use = 0;   // that's it — no free(), no memset()
```

**影响：** 在一个先前被 System 堆占用的槽位上创建 Normal 堆时，System 堆的数据（包括 `getenv()` 得到的堆指针）会留在与 Normal content 重叠的偏移处。读取 Normal content 就会泄露堆地址。

### V4 —— `localtime()` / TZ 环境变量读文件（“秘密”）

**根因：** 创建 Clock 堆会调用 `localtime()`，它内部调用 `tzset_internal()` → `__tzfile_read()`。当 `TZ` 环境变量被设为一个文件路径时，glibc 会把这个文件当作时区数据打开并读取，把内容存到堆上。

```c
// glibc tzset.c (simplified)
tz = getenv("TZ");
__tzfile_read(tz, 0, NULL);  // opens TZ as a file path, reads into heap

// tzfile.c
f = fopen(file, "rce");      // opens the flag file!
fread(...);                   // reads contents into malloc'd buffer
```

**影响：** 设置 `TZ=/home/critical_heap++/flag`（或用 `TZDIR=/home/critical_heap++` + `TZ=flag`）并触发 `localtime()`，就会把 flag 文件的内容加载进堆内存。配合 V1（格式化字符串读取），无需 shell 即可泄露 flag。

### V5 —— `realpath()` 堆溢出（仅 shell 路径）

**根因：** `Play → System → 3.Get real path` 调用 `realpath(buf, buf)`，把**同一个缓冲区**同时作为源和目标。当 `buf` 中是像 `"."` 这样的短相对路径时，解析出的绝对路径会覆盖并超出原缓冲区的分配范围。

**前提条件：** 通过 `setenv` 设置 `PWD="."`（远程 `PWD=/`，所以要先 `unsetenv("PWD")`）。当 `PWD="."` 时，System 堆的 `dirname` 字段（来自 `get_current_dir_name()`）会返回 `"."`。

**影响：** 覆盖相邻的堆 chunk 元数据（size 字段），从而实现 fastbin 破坏以取得任意写。这是 **shell 路径**（见下文路径 B）所需的关键原语。

## 利用路径

### 路径 A —— TZ 读文件 + 格式化字符串泄露（只拿 flag，无 shell）

**使用者：** 约 90% 的解法（59、194、278、550、821、1351、2315、2797、3480、3851、8410、8942、11540、18331、21490、24887、29544、31599、34817、36997）

**步骤：**

1. **泄露堆地址（V2 + V3）：**
   - 在槽位 0 创建一个 System 堆。用 `setenv`/`getenv` 把一个堆指针存到 +0x20。
   - 删除槽位 0（数据保留）。把槽位 0 重建为 Normal，content 只填 8 字节。
   - 对槽位 0 执行 `Show heap`：content（8 字节）+ +0x20 处的陈旧指针 = 堆泄露。
   - `heap_base = leaked_ptr - offset`（offset 随分配顺序不同：0x30、0x50、0x62、0x142、0x145）。

2. **把 TZ 设为 flag 路径（V4）：**
   - 创建一个 System 堆。用 `setenv("TZ", "/home/critical_heap++/flag")`。
   - 部分解法还会设置 `TZDIR=/home/critical_heap++` 和 `TZ=flag` 或 `TZ=:./flag`。

3. **触发 `localtime()` 把 flag 读进堆：**
   - 创建一个 Clock 堆 → `localtime()` 把 flag 文件读入堆缓冲区。

4. **用格式化字符串泄露 flag（V1）：**
   - 新建或复用 Normal 堆。把 content 改成格式化字符串 payload：
     ```python
     payload = b'%c' * 11 + b'%s' + p64(heap_base + flag_offset)
     ```
   - `Play → Normal → Show` 触发 `__printf_chk(1, payload)` → `%s` 解引用 flag 地址 → 打印 flag。
   - flag 相对堆基址的偏移会变化（约 0x320 到 0x5e0，取决于环境）。

**结果：** 打印出 `FLAG{Oh_y0u_f1nd_th3_s3cr3t_1n_loc4ltim3}`——这是**诱饵 flag**。提交它在本平台这道题（criticalheap，200 分）上会被接受，但真正的挑战（criticalheap++，600 分）共用同一个二进制，且需要 shell。

**可靠性：** 由于确切的堆布局取决于进程启动时的环境变量数量，部分解法按 0x10 为步长暴力尝试 flag 偏移。

---

### 路径 B —— 格式化字符串 + realpath 溢出 → fastbin 攻击 → shell

**使用者：** 解法 1162（详细）、7905（部分提及）

这是 **criticalheap++（600 分）** 的路径，用于获取真实 shell：

1. **通过 GOT 泄露 libc（V1）：** 用格式化字符串 `%c*11 + %s + p64(puts@GOT)` 从固定的 GOT（No PIE）读出 `puts` 地址 → `libc_base`。

2. **泄露堆地址（V2）：** 与路径 A 的第 1 步相同。

3. **制造一个已释放的 0x70 fastbin chunk：**
   - 首次 `localtime()` 会读取 `/etc/localtime`（Etc/UTC），分配一个时区数据 chunk。
   - `setenv("TZ", "z"*0x40)` 改变 TZ；下一次 `localtime()` 调用（`Update time`）会释放旧的时区 chunk → 进入 `fastbin[5]`（大小 0x70）。

4. **`realpath()` 溢出（V5）：** 破坏被释放 chunk 的 size，造出一块重叠区域。

5. **fastbin 攻击 → `__malloc_hook`：**
   - 重命名某个堆，让它的 name chunk 与被释放的 0x70 chunk 重叠 → 把 `fd` 覆盖为 `__malloc_hook - 0x23`（该处有 size 字节 `0x7f` 的伪造 chunk）。
   - 两次分配：第一次返回真实 chunk，第二次返回位于 `__malloc_hook - 0x13` 的伪造 chunk。
   - 通过 rename 把 `one_gadget` 写到 `__malloc_hook`。

6. **触发 `__malloc_hook`：** 任意 `malloc` 调用（例如 Create 期间的 `strdup`）都会触发 one_gadget → shell。

7. **获取真实 flag：**
   ```bash
   cd /home/critical_heap++ && echo 'Crazy heap !!' | ./get_flag
   # FLAG{Cr1t1c4l_h34p_is_very_cr4zyyyyyyyyyy}
   ```

**可靠性：** 需要本地与远程的堆布局匹配。环境变量会显著影响布局；解法 1162 用格式化字符串读取动态计算偏移。

---

### 路径 C —— 栈泄露 + 格式化字符串（不需要堆泄露）

**使用者：** 解法 34817

1. **泄露栈地址（V2）：** 展示一个名字很长的 Normal 堆（0x28 字节）。`Show heap` 中的 `printf("%s")` 会越过 name 读进栈帧数据，暴露一个栈指针。

2. **设置 TZ 并触发 `localtime()`：** 与路径 A 的第 2–3 步相同。flag 文件内容会被读到 `__tzfile_read` 的栈帧上。

3. **从栈上做格式化字符串读取：** 计算出 `flag_stack_addr = leaked_stack - known_offset`。用格式化字符串从这个栈地址读取。

**局限：** 泄露点与 flag 数据之间的栈偏移在本地和远程环境间会变化，因此这种做法比较脆弱。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 堆地址泄露 | V2 + V3：content 溢出 + 陈旧数据 | 确定性 |
| 任意内存读 | V1：`__printf_chk` 格式化字符串配合 `%s` | 确定性 |
| flag 文件 → 堆 | V4：TZ 环境变量 + `localtime()` 读 tzfile | 确定性 |
| libc 泄露 | V1：对 GOT 做格式化字符串读取（No PIE） | 确定性 |
| 堆溢出 | V5：`realpath(buf, buf)` | 确定性（需要 PWD="."） |
| 任意写 | V5 → fastbin 破坏 → `__malloc_hook` | 依赖环境 |

## 关键偏移

```python
# Fixed addresses (No PIE)
heap_array    = 0x604040       # global BSS array of 10 Heap structs
puts_got      = 0x603f40       # for libc leak

# glibc 2.23 (pwnable.tw remote libc)
system        = 0x45390        # or 0x46390 depending on exact build
one_gadgets   = [0x45216, 0xef6c4, 0xf0567]
__malloc_hook = libc_base + 0x3c3b10
__free_hook   = libc_base + 0x3c57a8

# Heap offsets (vary with environment variable count)
flag_offset   = 0x320 ~ 0x5e0  # from heap_base to flag data after localtime()
```

## 诱饵陷阱

`/home/critical_heap++/flag` 处的 flag 文件内容为 `FLAG{Oh_y0u_f1nd_th3_s3cr3t_1n_loc4ltim3}`——注意它那自指的命名 *“Oh you find the secret in localtime”*。这是刻意埋下的诱饵。平台在 **criticalheap（200 分）** 这道题上接受它，但配套的 **criticalheap++（600 分）** 要求拿到 shell，并用口令 `"Crazy heap !!"` 运行 setuid 的 `get_flag` 二进制，才能得到真实 flag。

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `59.md` | A | TZ + 格式化字符串 | 简短；提到对诱饵的认识 |
| `194.md` | A | TZ + 格式化字符串，暴力猜 flag 偏移 | 扫描 0x400-0x600 的堆范围 |
| `278.md` | A | TZDIR + TZ，Ruby 利用 | 含用 strace 验证 TZ 读文件的 PoC |
| `550.md` | A | TZ + 格式化字符串，GOT 泄露 libc | 详细的结构布局；设置 TZDIR |
| `821.md` | A | TZ + 格式化字符串 | 用 `%s` 配合 GOT 泄露做堆 pivot |
| `1162.md` | B | realpath 溢出 → fastbin → shell | 完整的 shell 利用；劫持 `_IO_list_all` |
| `1351.md` | A | 通过 `/proc/self/cwd/flag` 设置 TZ | 紧凑的解法 |
| `2315.md` | A | TZ + 格式化字符串，详细的漏洞分析 | 最佳题解；结构布局 + glibc 源码引用 |
| `2797.md` | A | TZDIR + TZ + 格式化字符串 | 使用 `%c`*12 + `%s` |
| `3480.md` | A | TZ + 格式化字符串 | 也用 GOT 泄露 libc |
| `3851.md` | A | TZ + 格式化字符串，getenv 泄露 | 详细；两个泄露阶段 |
| `4082.md` | A | TZ + 格式化字符串（中文） | 配有截图的详尽结构分析 |
| `7905.md` | B（部分） | 指出诱饵；引用 criticalheap++ | 详细分析了真实 flag 与诱饵 flag |
| `8153.md` | A | TZ + 格式化字符串 | 单独设置 TZDIR |
| `8410.md` | A | TZ + 格式化字符串，`%p`*5 泄露堆 | 紧凑 |
| `8942.md` | A | TZ + 格式化字符串，EMT 填充 | 暴力扫描堆偏移范围 |
| `11540.md` | A | TZ + 格式化字符串，`%p`*12 `%s` | 干净的远程利用 |
| `18331.md` | A | TZ + 格式化字符串，content 溢出泄露 | 标准做法 |
| `21490.md` | A | TZ + 格式化字符串（中文） | 对 localtime 内部机制的良好分析 |
| `24887.md` | A | TZ + 格式化字符串，自动递增偏移 | 失败时 offset += 8 重试 |
| `29544.md` | A | TZ + 格式化字符串，content 溢出 | 标准做法 |
| `31599.md` | A | TZ + 格式化字符串，`%p`*12 + `%s` | 通过 content 溢出泄露 |
| `34817.md` | C | 栈泄露 + 格式化字符串 | 不用堆泄露；从栈上读 flag |
| `36997.md` | A | TZ + 格式化字符串，暴力猜偏移 | 失败时 offset += 0x10 重试 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的利用脚本（路径 A） |
| `desc.txt` | 题目描述 |
| `artifacts/critical_heap.tar.gz` | 原始题目二进制 + Docker 环境 |
| `solution/*.md` | 社区题解（36 篇） |
