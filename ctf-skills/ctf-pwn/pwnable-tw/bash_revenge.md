---
tags:
  - logic-flaw
  - file-descriptor-leak
  - command-injection
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "利用泄露的文件描述符和 bash 内部内置命令，可以逃出受限执行模式并执行特权二进制。"
proof-of-concept: no
---

# Bash Revenge — pwnable.tw（500 分）

[← 返回 pwnable.tw 题目索引](README.md)

> 有一个带有若干漏洞（例如 CVE-2016-9401）的旧版 bash。
> 你能为这道题写一个 1-day 利用吗？:p
>
> `nc chall.pwnable.tw 10407`
>
> Flag：`FLAG{us3_4ft3r_fr33_1n_bash_1s_p0w3rful}`

## 题目概览

你会连到一个被 `chroot` 关押的 x86-64 bash 4.3.0(2) shell。这个 jail 里**只有 bash 及其依赖库**——没有 `cat`、`ls`、`id` 或任何其他二进制。flag 位于 `/flag`，属于 root，且在 chroot 之外。另有一个属于 root 的 xinetd 服务监听 `127.0.0.1:1337`，通过 `/bin/cat /flag` 提供 flag。bash 编译时**不支持 `/dev/tcp`**，所以要拿到 flag，唯一的办法是在 bash 内部取得**任意代码执行**，然后用原生的 `socket()`/`connect()` 系统调用访问 loopback 上的 flag 服务。

```text
bin/bash:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)    # Fixed addresses in .text/.bss/.got
  NOT stripped
  Uses bash's OWN internal allocator (lib/malloc/malloc.c), NOT glibc malloc

libc: Ubuntu 16.04 glibc 2.23-0ubuntu10
```

## 关键数据结构

### bash 内部 malloc 的 chunk 头

bash 使用自己实现的 `malloc`，chunk 格式是自定义的：

```c
union mhead {
  bits64_t mh_align;              // 8 bytes total
  struct {
    char     mi_alloc;            // 0xf7 = ISALLOC, 0x54 = ISFREE
    char     mi_index;            // bucket index in nextf[]
    u_bits16_t mi_magic2;         // must be 0x5555
    u_bits32_t mi_nbytes;         // size of user data
  } minfo;
};
// Trailing guard: u_bits32_t == mi_nbytes (size footer)
```

在 bucket 3 中分配 0x30 字节，合法已分配 chunk 头就是单个 qword **`0x30555503f7`**。

### SHELL_VAR 结构

```c
typedef struct variable {
  char *name;                        // +0x00
  char *value;                       // +0x08  → arbitrary read target
  char *exportstr;                   // +0x10
  sh_var_value_func_t *dynamic_value;// +0x18  → called on $VAR expansion
  sh_var_assign_func_t *assign_func; // +0x20  → called on VAR=value
  int attributes;                    // +0x28
  int context;                       // +0x2c
} SHELL_VAR;                         // sizeof = 0x30
```

## 漏洞

### V1 —— CVE-2016-9401：`popd` 越界释放（主要，可利用）

**根因：** 在 `builtins/pushd.def` 中，`popd_builtin` 接受 `popd +-N`，其中 N 由 `legal_number` 解析，而它**允许负数**。边界检查只拒绝 `which > offset`，所以负的 `which` 能通过：

```c
// pushd.def:popd_builtin
i = (direction == '+') ? directory_list_offset - which : which;
free(pushd_directory_list[i]);   // line 384 — OOB index
```

如果 `pushd` 从未被调用过，则 `pushd_directory_list == NULL`，于是：

```text
popd +-N  →  free( *(void**)(8 * N) )
```

这就是**对存放在任意、攻击者选定的固定地址处的指针执行 `free()`**。由于 bash 不是 PIE，目标可以是任意固定的 `.bss`/`.data` 地址。

**影响：** 可以对任意经固定地址可达的指针执行任意释放。这是整个利用唯一的入口——所有解法都建立在这个原语之上。

### V2 —— 通过 `localbuf` 注入 NUL 字节（使能点）

**根因：** bash 把原始命令输入读入位于固定地址 `0x6b7c40` 的全局 `char localbuf[128]`。这个缓冲区保存来自 `read()` 的原始字节，**包括 NUL 字节**，而这些字节随后会被命令解析器忽略。

**影响：** 攻击者可以构造一条命令，其原始字节在已知地址处包含一个**伪造的 malloc chunk**（带 NUL 字节元数据）。这一点很关键，因为 bash 的字符串操作通常无法产生 NUL 字节，而分配器要求头部包含特定的 magic 字节。

### V3 —— 通过 `printf`/`echo -ne` 注入 NUL 字节（使能点）

**根因：** `printf` 和 `echo -ne` 会解释 `\x00` 转义序列，并向 stdout 写入 NUL 字节。stdout 是**带缓冲**的，因此输出会累积在堆缓冲区中，其相对堆基址的偏移是可预测的。

**影响：** 任意二进制数据（包括 NUL 字节）都能被写进堆上的 stdout 缓冲区，从而无需 `localbuf` 也能构造伪造 chunk。

### V4 —— 通过被释放的 BSS 指针泄露堆地址（使能点）

**根因：** 若干全局 BSS 指针（`ps1_prompt`、`ps2_prompt`、`the_current_wd`、`dollar_vars[1]` 等）指向堆上分配的字符串。用 V1 把它们释放后，字符串数据会被 free-list 的 `next` 指针取代。再把对应变量读回来（例如 `echo $PS2`、`echo $1`、`pwd`）即可泄露堆地址。

### V5 —— `/proc/self/maps` 泄露（替代路径，仅 “Bash Revenge”）

**根因：** 在 “Bash Revenge” 变体（端口 10407）中，`/proc` 可访问。`cat /proc/$$/maps` 可直接泄露堆基址与 libc 基址。

## 利用路径

所有解法共享同一条核心流程：**V1（任意释放）→ 伪造 chunk → 被回收为可控结构 → 任意读 + RIP 劫持 → ROP → shellcode → socket 连接 flag 服务**。区别在于如何植入伪造 chunk、回收成什么结构，以及如何实现代码执行。

---

### 路径 A —— `localbuf` 伪造 chunk → SHELL_VAR 回收 → `setcontext` ROP

**使用者：** 解法 370（exp.py）、1428、2311、2972、3498、7905、8153、15989、36714

**步骤：**

1. **在 `localbuf` 中植入伪造 chunk：** 发送一条原始命令，使其在偏移 `+0x30` 或 `+0x40` 处的字节构成合法的 bash-malloc chunk 头（`0x30555503f7`）+ 正文 + 大小 footer。该 chunk 位于一个已知的固定地址。

2. **通过 V1 释放伪造 chunk：** `popd +-(localbuf_offset/8)` 会解引用存放在 `localbuf` 中的指针（在第 1 步植入），并释放它，从而把伪造 chunk 插入 bash 的 free list。

3. **用 SHELL_VAR 回收：** 触发一次变量赋值（例如 `A=B C=D`），它会通过 `new_shell_variable()` 分配一个 `SHELL_VAR` 结构。这次分配会复用刚被释放的伪造 chunk，把结构放进 `localbuf` 内。

4. **任意读（libc 泄露）：** 把 SHELL_VAR 的 `value` 指针（位于 `+0x08`）覆盖为某个 GOT 表项（例如 `read@got = 0x6b2288`）。执行 `echo $C` 会打印该 GOT 值 → 得到 libc 基址。

5. **通过 `dynamic_value` 劫持 RIP：** 把 SHELL_VAR 的 `dynamic_value` 指针（位于 `+0x18`）设为 `gets` 或 `setcontext+53`。展开 `$VAR` 时会调用 `dynamic_value(var_ptr)`，从而在 `rdi` 指向该结构的情况下取得 RIP 控制权。
   - **`gets` 阶段：** `dynamic_value = gets` → 读入一个 `setcontext` ucontext 帧 + ROP 链到 `localbuf`。
   - **`setcontext+53` 阶段：** 通过该 ucontext 帧把栈 pivot 进 ROP 链。

6. **ROP → shellcode：** `read(0, bss, N)`，然后 `mprotect(bss, 0x1000, RWX)`，再跳转到 shellcode。

7. **Shellcode：** 原生系统调用：`socket(AF_INET, SOCK_STREAM, 0)` → `connect(fd, {127.0.0.1:1337}, 16)` → `read(fd, buf, 0x100)` → `write(1, buf, 0x100)`。

---

### 路径 B —— `printf` stdout 缓冲区伪造 chunk → SHELL_VAR

**使用者：** 解法 821、1351、2311（bash 变体）、9251、22319、26957、28605、28652、31599、33090

**步骤：**

1. **泄露堆地址：** 通过 V1 释放一个 BSS 指针（例如 `ps1_prompt`、`ps2_prompt`、`the_current_wd`、`$1`），再把释放后的值读回来，得到一个堆指针。

2. **在堆上植入伪造 chunk：** 用 `printf "\x00...\xf7\x03\x55\x55..."` 或 `echo -ne`，向位于 `heap_base + 0x2808`（可预测的偏移）的 stdout 缓冲区写入一个伪造 chunk。

3. **释放伪造 chunk：** 算出该伪造 chunk 在堆上的地址，把指向它的指针植入已知位置，然后通过 V1 释放。

4. **回收并利用 SHELL_VAR：** 与路径 A 的第 3–7 步相同，只是受控内存位于堆上而不是 `localbuf` 中。

部分解法用基于 `printf` 的循环覆盖：回收之后，由于该结构就位于 stdout 缓冲区内，直接用 `printf` 覆盖 SHELL_VAR 的各个字段。

---

### 路径 C —— 数组元素 / JOB 结构劫持

**使用者：** 解法 1351、22319、35463、36714

**变体思路：** 不用（或在 SHELL_VAR 之外额外用）以下结构来回收伪造 chunk：

- **数组元素：** bash 数组存储 `{int64_t index; char *value; ...}`。把数组元素与一个偏移 0 处为 `char *name` 的结构混淆，就能通过数组索引实现任意读。解法 1351 和 22319 用 `arr[N]=value` 配合精心构造的索引，来触发 `assign_func` 或 `bind_array_var_internal`。

- **JOB 结构：** 后台任务（`cmd &`）会分配带函数指针（`j_cleanup`）的 JOB 结构。释放一个伪造 chunk 并让 JOB 结构将其回收，就能在任务清理时取得 RIP 控制权。解法 22319 和 35463 用 `jobs` 内置命令，通过命令字符串指针泄露，然后触发清理。

---

### 路径 D —— `tilde_expansion_preexpansion_hook` / `longjmp` 劫持

**使用者：** 解法 2972、36714

**替代的 RIP 劫持方式：**

- **`tilde_expansion_preexpansion_hook`：** BSS 中的一个函数指针，在展开 `~` 时被调用。用 “printf 缓冲区植入伪造 chunk” 的手法覆盖它，然后用 `~AAAA...`（很长的波浪号展开）触发。RDI/RSI/RDX 可部分由输入长度控制。

- **`top_level` longjmp 缓冲区：** 读取位于 `0x6B90E0` 的 `top_level` jmp_buf，提取 glibc 指针保护（`PTR_MANGLE`）所用的 XOR 密钥，加密新的 RBP/RSP/RIP，覆盖该缓冲区，然后触发 `exit 0` → `longjmp(top_level)` → 栈 pivot 到 ROP。

---

### 路径 E —— 通过 `printf -v` / free-list 操纵覆盖 GOT

**使用者：** 解法 1428

**步骤：**

1. 释放若干 chunk，让它们进入 free list。
2. 用 `printf -v varname` 分配内存，并把受控数据写入 free-list 的 next 指针。
3. 串联多次分配，最终把一个受控值写到某个 GOT 表项（例如 `dcgettext@got → add_ret_gadget`）。
4. 当 bash 调用该 GOT 函数时，就会落到这个 gadget 上，再由它调用 `gets` 读入完整的 ROP 链。

---

### 路径 F —— `/proc/self/maps` 直接泄露（仅 Bash Revenge）

**使用者：** 解法 1351（bash revenge 变体）

在端口 10407 上，`/proc` 已挂载：

```bash
cat /proc/$$/maps
```

这会直接泄露堆基址和 libc 基址，完全跳过堆泄露这一环节。其余利用流程沿用路径 B。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 固定地址任意释放 | V1：CVE-2016-9401 `popd +-N` | 确定性 |
| 已知地址伪造 chunk | V2：`localbuf` 或 V3：`printf` stdout 缓冲区 | 确定性 |
| 堆地址泄露 | V4：释放 BSS 指针后读回 | 确定性 |
| libc 泄露 | 通过 SHELL_VAR 的 `value` 指针读 GOT | 确定性 |
| 栈泄露（可选） | 读取 `shell_environment` 或 `__environ` | 确定性 |
| RIP 控制 | SHELL_VAR 的 `dynamic_value`/`assign_func` | 确定性 |
| 代码执行 | `setcontext+53` → ROP → `mprotect` → shellcode | 确定性 |
| flag 外带 | shellcode：`socket`→`connect`→`read`→`write` | 确定性 |

## 偏移（libc 2.23-0ubuntu10，amd64）

```python
# bash binary (non-PIE)
localbuf       = 0x6b7c40
read_got       = 0x6b2288
snprintf_got   = 0x6b2030
stdin_bss      = 0x6b5110
ps1_prompt     = 0x6b86d8   # (varies by solution)
the_current_wd = 0x6b7ec0
dollar_vars    = 0x6b8920

# libc offsets
read           = 0xf7250
gets           = 0x6ed80
setcontext     = 0x47b75    # +53 for the register-loading gadget
mprotect       = 0x101770
pop_rdi        = 0x21102
pop_rsi        = 0x202e8
pop_rdx        = 0x1b92
pop_rax        = 0x33544
syscall_ret    = 0xbc375
```

## 题解文章

| 文件 | 主要路径 | 堆泄露方式 | RIP 劫持 | 备注 |
|------|-------------|------------------|------------|-------|
| `370.md` | A | 释放 `the_current_wd` | `setcontext` + ROP | 两个脚本；反弹连接 shellcode |
| `821.md` | B | 释放 `$1` + `printf` | `setcontext` + ROP | 关闭历史记录以保证堆稳定 |
| `1351.md` | B + F | `/proc/self/maps`（revenge）/ 暴力猜堆（bash） | 通过数组赋值触发 `setcontext` | 针对两个端口的两种变体 |
| `1428.md` | A | `localbuf` | 通过 `dynamic_value` 触发 `setcontext` | 题解清晰；解释了 NUL 字节技巧 |
| `2311.md` | A + E | `localbuf` | `gets` → `setcontext` | 格式详细；也描述了 Bash（200 分） |
| `2972.md` | D | 通过 `printf -v` 泄露栈/堆 | `tilde_expansion_hook` | 用嵌套函数控制栈深度 |
| `3148.md` | B | 释放 `ps1_prompt` | `setcontext` + ROP | 简洁；用 `echo -ne` 写入 NUL 字节 |
| `3498.md` | A | 释放 `the_current_wd` | 通过 `xchg edi,esp` 做栈 pivot | 详细记录了 chunk 元数据 |
| `6748.md` | B | 数组元素喷洒 | `setcontext` + ROP | 使用 `printf` 缓冲区喷洒 + 数组释放 |
| `7905.md` | A | 释放 `dollar_vars` | `setcontext` + mmap + shellcode | 完整的 BashInterface 类 |
| `8153.md` | A | `localbuf` + GOT 泄露 | `gets` → `setcontext` | 题解详细，含 Docker 复现 |
| `9251.md` | B | 释放 `$0` + `echo -ne` | 通过 JOB 清理触发 `setcontext` | 也尝试过数组类型混淆 |
| `15989.md` | B | 释放 `current_host_name` | 通过 JOB 结构触发 `setcontext` | 用 `echo -ne` 写堆 |
| `22319.md` | C | `export` 喷洒 + 释放 | 通过 JOB 的 `j_cleanup` 调用 `gets` | 借助 coproc + `jobs` 泄露 |
| `26957.md` | B | `popd` 堆泄露 | 通过 HIST 结构触发 `setcontext` | 用 history 对象做回收 |
| `28605.md` | B | 释放 `PS2` | `xchg edi,esp` 栈 pivot | 14 个 chunk 的堆喷洒 |
| `28652.md` | B | `the_current_wd` | 通过 SHELL_VAR 触发 `setcontext` | 用 `read -e -N 128` 向 `lbuf` 写 NUL |
| `31599.md` | B | `export` 泄露 | 通过 SHELL_VAR 触发 `setcontext` | 基于数组的释放来获得堆 chunk |
| `33090.md` | B | `printf` 写堆 | `setcontext` + `$leak1` | 用 `printf -v` 技巧写 NUL 数据 |
| `35463.md` | C | `C_ENV` 喷洒 + 释放 | 通过 JOB 调用 `gets` | 借助 coproc 做大量自动化 |
| `36714.md` | D | `pushd` + 变量分配 | 覆盖 `longjmp` 缓冲区 | 独特思路：加密新的 jmp_buf |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的利用脚本（localbuf 伪造 chunk 方案） |
| `desc.txt` | 题目描述 |
| `artifacts/` | 原始题目压缩包（`bash_revenge.tgz`） |
| `solution/*.md` | 社区题解（21 篇） |
