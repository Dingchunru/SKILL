---
tags:
  - format-string
  - fini-array-overwrite
  - stack-pivoting
platform: pwnable.tw
points: 400
arch: x86-64
libc: glibc-2.23
relro: full
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "stdout 被关闭后仅有的一次 printf 调用，可通过在 stderr 上做 1 字节格式串改写，并借栈迁移把执行流循环起来。"
proof-of-concept: no
---

# Printable — pwnable.tw（400 分）

[← 返回 pwnable.tw 题目索引](README.md)

> Everything is printable
>
> `nc chall.pwnable.tw 10307`
>
> Flag: `FLAG{FILE_str34m_1s_pr1nt4bl3}`

## 题目概览

一个极简的 x86-64 No-PIE 二进制，Full RELRO、NX、且虽存在 canary 但从不检查。程序读入 0x80 字节，随后把缓冲区当作格式串交给 `printf`——但在格式串执行**之前**就 `close(1)` 了，所以输出是“盲”的。`printf` 之后调用 `exit(0)`——main 函数永不返回。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO          # GOT is read-only
  Stack:    No canary found     # canary exists but exit() is called, never checked
  NX:       NX enabled
  PIE:      No PIE (0x400000)
  libc:     glibc 2.23 (Ubuntu GLIBC 2.23-0ubuntu5)
```

反编译的 `main`：

```c
void main() {
    char buf[0x80];             // rbp-0x90
    init_proc();                // setvbuf(stdin/out/err, ...); alarm(60)
    memset(buf, 0, 0x80);
    printf("Input :");          // flushed to fd1 BEFORE close
    close(1);                   // stdout closed — printf output goes nowhere
    read(0, buf, 0x80);         // 0x80 bytes, no overflow
    printf(buf);                // FORMAT STRING BUG (blind — fd1 is closed)
    exit(0);                    // never returns through main
}
```

关键约束：
- **盲格式串**：`close(1)` 使 `printf` 输出无法刷出到 fd1。此外 `vfprintf` 内部用 `buffered_vfprintf` 辅助函数，带 0x2000 字节的栈缓冲区——一旦写满，对 fd1 的写入失败会让 `printf` 提前退出，于是 `%n` 的写入被限制在约 8192 个字符。
- **无返回**：调用的是 `exit(0)`，所以主栈上没有返回地址可直接覆盖。
- **Full RELRO**：GOT 只读，`ret2dlresolve` 不可行。
- **No PIE**：`.text` 与 `.bss` 地址固定（0x400000、0x601000）。

二进制的 `.bss` 中有拷贝重定位后的 libc FILE 指针：

```text
0x601020 : FILE *stdout   → &_IO_2_1_stdout_
0x601030 : FILE *stdin    → &_IO_2_1_stdin_
0x601040 : FILE *stderr   → &_IO_2_1_stderr_
```

## 漏洞

### V1 — 盲格式串（主漏洞，可利用）

```c
read(0, buf, 0x80);
printf(buf);                // attacker-controlled format string
```

`printf` 被调用时缓冲区位于 `rsp`，因此用户输入从 `%6$` 开始。0x80 字节的输入除格式符外，还能容纳最多 4 个内嵌指针（位于偏移 0x50–0x78 处）。

**关键栈参数：**
- `%23$` —— 在第二次调用（已获得循环之后）时，一个恰好指向 printf 自身返回地址的栈指针。
- `%25$` / `%60$` —— `__libc_start_main` 的返回地址 → libc 泄漏锚点。
- `%42$` —— 指向 `_dl_fini` 状态的指针（具体是用于计算 `fini_array` 位置的 `link_map->l_addr`）。可写。
- `%53$` —— 一个可以改指到 printf 返回地址的栈指针。

## 利用路径

所有解法的核心难点一致：**先获得 printf 循环**（单次格式串是盲的且随后 exit），再**恢复输出**（fd1 已关闭），然后**泄漏 libc** 并**取得代码执行**。

---

### 路径 A — `_dl_fini` 劫持 → 伪造 `fini_array` 形成循环 → stdout→stderr 互换 → 泄漏 + ROP

**相关题解：** 8153（exp.py）、31599、36233、36997、38641、35917、11177

**思路：** `exit()` 会调用 `_dl_fini()`，后者计算 `fini_array = link_map->l_addr + DT_FINI_ARRAY->d_un.d_ptr`。`link_map` 指针就在栈上 `%42$` 处。通过覆盖 `l_addr`（或 fini_array 偏移），算出的数组指针会移到可写的 `.bss`，在那里放入一个指回 `main`（`0x400925`，即 `close(1)` 之后的位置）的函数指针。

**步骤：**

1. **把 `fini_array` 重定向进 `.bss`：** 写 `%42$` 改变 `l_addr`，使 `fini_array + l_addr` 指向某个 `.bss` 地址（如 `0x601000`）；同时在那个 `.bss` 位置写入 `0x400925`（`read`+`printf` 序列）的地址。

2. **把 `stdout` 换成 `stderr`：** 对 `0x601020` 的 `stdout` 指针做部分覆盖，使其指向 `_IO_2_1_stderr_` 而非 `_IO_2_1_stdout_`。二者在同一个 libc 页内，只有 1-2 个低字节不同。这需要猜 libc ASLR 的一个 nibble → **1/16 概率**。

3. **`exit()` 执行时**，`_dl_fini` 会调用伪造的 fini_array 条目 → 跳回 `read(0,buf,0x80); printf(buf)`——此时就有了 **printf 循环**，且输出走 `stderr`（fd2 = socket）。

4. **泄漏：** 用 `%23$p`（或 `%57$p`、`%60$p`）泄漏栈地址和 libc 地址。

5. **取 shell：** 有多种子方案：
   - **`add rsp, 0x80; ret` gadget**：用这个 libc gadget 覆盖 printf 的返回地址，并在缓冲区的正确偏移放上 `pop rdi; ret | "/bin/sh" | system`。
   - **One-gadget**：直接把 printf 的返回地址覆盖为 one-gadget 地址。
   - **栈迁移到 BSS + ROP**：经反复的格式串写，在 `.bss` 里搭 ROP 链，再把 `rsp` 迁过去。

**概率：** 每个连接约 1/16（`stdout→stderr` 互换需要猜 libc nibble）。部分变体还要猜栈熵 → 1/256 或 1/4096。

---

### 路径 B — 顺序（非位置）格式串 → 改指栈指针 → 循环

**相关题解：** 821、2311（爆破版）、3498、7905、22319、15724

**思路：** glibc 的 `vfprintf` 对**非位置**的 `%` 说明符是惰性处理的（一次取一个参数），但只要遇到位置式 `%N$`，就立刻切换到 `printf_positional`（先一次性缓存全部参数）。把非位置写入放在第一个位置写入**之前**，就能在**同一次 printf 调用里先改指某个栈指针、再通过它写入**。

**步骤：**

1. **第一份 payload（顺序技巧）：** 用 25 个 `%c` 把参数指针推进到第 26 个（即 `argv`，一个栈到栈的指针）；然后用 `%hn` 把 printf 返回地址槽的低 16 位写进该指针，完成改指；再用位置式 `%53$hhn` 通过被改指的指针写入，把 printf 返回地址的低字节从 `0x52` 改成 `0x25` → 重定向到 `0x400925`（`read`+`printf` 循环）。

2. **约束：** `%hn` 的值等于 `printf_ret & 0xffff`，必须小于 0x2000（stdio 缓冲区上限）。这意味着栈页的 nibble 必须为 0 → **1/16**。栈的低 12 位也是随机的 → 再叠加 **1/256** 的猜测（返回地址 16 字节对齐，低 nibble 固定 → 8 位熵）。

3. **后续 payload：** 已进入循环，每轮都用位置式 `%53$hhn` 继续覆盖返回地址。完成 `stdout→stderr` 互换（若尚未做，1/16），泄漏 libc/栈，再把 ROP 链或 one-gadget 写到返回地址。

**概率：** 视变体而定，每个连接 1/4096 到 1/65536。

---

### 路径 C — `_dl_fini` 劫持 → BSS ROP 链（无需泄漏）

**相关题解：** 2311（不爆破版）、2972、8153

**思路：** 不做 libc 泄漏，而是完全用 No-PIE 二进制自身的 gadget（`__libc_csu_init` 的 pop/call gadget）搭多段 ROP 链，实现 `execve("/bin/sh", 0, 0)`。

**步骤：**

1. **经路径 A 的 `fini_array` 劫持获得 printf 循环。**

2. **用反复的格式串迭代把 ROP 链逐字节写进 `.bss`。** 每轮经 `%hhn` 把一个非零字节写到指定的 `.bss` 地址。

3. **迁移：** 用 `pop rsp; pop r13; pop r14; pop r15; ret`（`0x4009bd`）覆盖 printf 返回地址，目标指向 `.bss`。

4. **ROP 链用 `__libc_csu_init` gadget** 调 `read(0, bss, large)` 读第二段 payload，再对 GOT/栈上的某个 libc 地址做部分覆盖造出 `syscall` gadget，最后 `execve("/bin/sh", 0, 0)`。

**概率：** 在 1/16 的 `fini_array` 偏移对齐成立后是确定性的；若 `l_addr` 操纵足够精确，则完全确定性。

---

### 路径 D — 单发：经 atexit 把 `stdin@bss` 部分覆盖为 one-gadget

**相关题解：** 11177、6748

**思路：** `exit()` 路径会经过 `__run_exit_handlers`，它使用一个 `atexit` 函数列表。栈上的某个指针（可通过 `%42$` 访问）会影响 atexit 数组的偏移。把这个偏移改成指向 `stdout@bss`，再把 `stdout@bss` 处的 libc 指针部分覆盖为 one-gadget，`exit()` 就会直接跳到 one-gadget。

**步骤：**

1. 覆盖 atexit 偏移（经 `%42$`），把退出处理重定向到 `stdout@bss`（`0x601020`）。
2. 把 `stdout` 指针的低 3 字节部分覆盖为 one-gadget 地址。
3. 爆破 libc 剩余的 12 位熵 → **1/4096**。

**概率：** 每个连接 1/4096。payload 更简单，一次完成。

---

### 路径 E — 伪造 FILE 结构体 → 虚表劫持 → one-gadget

**相关题解：** 3498

**思路：** 先（经路径 A 或 B）获得 printf 循环，再在 `.bss` 里构造带自制虚表的伪造 `FILE` 结构体，把 `stdout@bss` 改指向该结构体。虚表的 `xsputn` 项指向 `add byte ptr [rax], al` gadget，`printf` 的 `buffered_vfprintf` 路径会反复调用它，每次都把 `al` 加到 `[rax]`（其中 `rax = stdin@bss`），逐步把那个 libc 指针“变形”成 one-gadget。

**步骤：**

1. 获得 printf 循环。
2. 在 `.bss` 构造伪造 FILE 结构体，`flags = 0x8002`，虚表指向 gadget。
3. 把 `stdout` 换成该伪造结构体。
4. 调用 `add [rax], al` gadget 约 58 次，每次都把 `al` 加到 `stdin@bss` 里的 libc 指针上，缓慢逼近 one-gadget。
5. 指针命中后，下一次 `printf` 触发 one-gadget。

**概率：** 取决于初始 libc 布局；可能还需要额外猜 nibble。

## 关键地址（No-PIE 二进制）

```python
# Binary
main_read_printf = 0x400925    # read(0,buf,0x80); printf(buf) — loop target
fini_array       = 0x600db8    # .fini_array (read-only segment)
bss_start        = 0x601000    # writable .bss
stdout_bss       = 0x601020    # copy-relocated stdout
stdin_bss        = 0x601030    # copy-relocated stdin
stderr_bss       = 0x601040    # copy-relocated stderr

# Gadgets
pop_rdi          = 0x4009c3    # pop rdi; ret
pop_rsi_r15      = 0x4009c1    # pop rsi; pop r15; ret
pop_rsp_3        = 0x4009bd    # pop rsp; pop r13; pop r14; pop r15; ret (stack pivot)
csu_pop6         = 0x4009ba    # pop rbx; rbp; r12; r13; r14; r15; ret
csu_call         = 0x4009a0    # call [r12+rbx*8](r15, r14, r13)
ret              = 0x4009c4    # ret
```

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
_IO_2_1_stderr_      = 0x3c4540
_IO_2_1_stdout_      = 0x3c4620
__libc_start_main_ret = 0x20830
system               = 0x45390
bin_sh               = 0x18c177
one_gadgets          = [0x4526a, 0xef6c4, 0xf0567]
```

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 格式串（盲） | `close(1)` 之后的 `printf(buf)` | 确定性 |
| printf 循环 | `fini_array` 劫持或改指栈指针 | 1/16（fini）或 1/4096（栈） |
| 恢复输出 | `stdout@bss` → `_IO_2_1_stderr_` 部分覆盖 | 1/16（libc nibble） |
| libc 泄漏 | `%25$p` 或 `%60$p`（输出恢复后） | 确定性 |
| 栈泄漏 | `%23$p` 或 `%11$p` | 确定性 |
| 代码执行 | printf 返回地址上的 ROP 链 / one-gadget | 泄漏后确定性 |

## 题解文章

| 文件 | 主要路径 | 关键技术 | 概率 | 备注 |
|------|-------------|---------------|-------------|-------|
| `821.md` | B | 顺序格式串 → 改指栈 → one-gadget | 1/4096 | 爆破栈猜测 |
| `1351.md` | A | `l_addr` 劫持 → stdout→stderr → 泄漏 → one-gadget | 1/16 | 使用 link_map 指针 |
| `2311.md` | B + C | 顺序格式串 → BSS ROP（无泄漏）+ 确定性变体 | 1/4096 或确定性 | 两份脚本：爆破与不爆破 |
| `2972.md` | A + C | `fini_array` → 经 `__libc_csu_init` 的 BSS ROP | 约 1/16 | `mprotect` + shellcode |
| `3148.md` | A | `fini_array` → 泄漏 → 栈上 one-gadget | 1/16 | 简洁；直接写 one-gadget |
| `3498.md` | E | 伪造 FILE 虚表 → `add [rax], al` × N → one-gadget | 1/4096 | 最具创意 |
| `3568.md` | A | stdout→stderr → 泄漏 → 格式串写 one-gadget | 1/16 | 中文题解 |
| `6748.md` | D | atexit → 部分覆盖 stdin 为 one-gadget | 1/4096 | 爆破 libc 12 位 |
| `7905.md` | B | 顺序技巧 → 循环 → ROP | 1/65536 | 分析最详尽 |
| `8153.md` | A | `l_addr` + stdout 互换 → 泄漏 + `add rsp` ROP | 1/16 | 干净的多阶段；题解详尽 |
| `11177.md` | D | atexit 偏移 → 部分覆盖 | 1/4096 | 尺寸优化的格式串写入器 |
| `15724.md` | B | 改指栈 → 泄漏 → one-gadget | 1/16 | 一次拿到栈 + libc 泄漏 |
| `22319.md` | B | 栈迁移 → `__libc_csu_init` ROP → `syscall` | 1/4096 | 不需要 libc 泄漏 |
| `24887.md` | A | `fini_array` → 泄漏 → 格式串写 one-gadget | 1/16 | 使用 formatstring 库 |
| `31599.md` | A | `fini_array` → 泄漏 → `add rsp` gadget + 内联 ROP | 1/16 | exp.py 的做法 |
| `35917.md` | A | `_dl_fini` 分析 → `fini_array` 偏移 | 1/16 | 详尽的逆向分析 |
| `36233.md` | A | `fini_array` + stdout→stderr → 泄漏 → `add rsp, 0x80` ROP | 1/16 | 详细中文题解 |
| `38641.md` | A | `fini_array` → stdout 互换 → 泄漏 → `add rsp` + ROP | 1/16 | 干净的利用脚本 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用利用脚本（路径 A：`fini_array` + stdout 互换 + ROP） |
| `desc.txt` | 题目描述 |
| `solution/*.md` | 社区题解文章（47 个解法） |
