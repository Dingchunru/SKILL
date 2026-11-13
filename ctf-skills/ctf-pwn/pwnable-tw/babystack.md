---
tags:
  - information-leak
  - brute-force-oracle
  - stack-buffer-overflow
  - rop
platform: pwnable.tw
points: 250
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "利用 strncmp 构成的密码校验预言机，可以逐字节还原栈 canary 和随机密码，进而通过栈溢出构造 ROP 链。"
proof-of-concept: no
---

# BabyStack — pwnable.tw（250 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10205`
>
> Flag：`FLAG{Its_juS7_a_st4ck0v3rfl0w}`

## 题目概览

一个 stripped 的 x86-64 PIE 二进制，保护全开，链接 glibc 2.23。程序实现了一个简单的登录/登出菜单，密码是 16 字节随机数据，从 `/dev/urandom` 读取。这个密码同时充当自定义的 “canary”——它必须保持完整，程序才能从 `main` 干净地 `return`（通过 `memcmp` 与一块 mmap 备份做比对）。两个辅助函数（`Login` 和 `Copy`）共用同一处栈帧位置，因此可以构造基于 `strcpy` 的溢出。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    Canary found         # custom canary, not glibc __stack_chk
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

## 程序逻辑

### `main` 栈帧（`sub rsp, 0x60`）

| 相对 rbp 的偏移 | 字段 | 大小 |
|------------------|-------|------|
| `rbp-0x60` | `copy_dest` —— Copy 通过 `strcpy` 写入此处 | 64 字节 |
| `rbp-0x20` | `password` —— 来自 `/dev/urandom` 的 16 字节随机数 | 16 字节 |
| `rbp-0x10` | `choice` —— 菜单输入缓冲区 | 16 字节 |
| `rbp+0x00` | saved rbp | 8 字节 |
| `rbp+0x08` | **返回地址**（指向 `__libc_start_main`） | 8 字节 |

从 `copy_dest` 到返回地址的距离：**0x68 = 104 字节**。

### 菜单

```c
while (1) {
    __read_chk(0, choice, 16, 16);
    switch (choice[0]) {
        case '1':
            if (logged_in) logged_in = 0;   // logout
            else Login(password);            // authenticate
            break;
        case '2':
            if (logged_in) {
                if (memcmp(password, mmap_backup, 16) == 0) {
                    eax = 0; return;         // clean exit — triggers ret
                } else __stack_chk_fail();   // password tampered
            } else exit(0);
            break;
        case '3':
            if (logged_in) Copy(copy_dest);  // magic copy
            break;
    }
}
```

### `Login(passwd)` —— `sub rsp, 0x90`，buf 位于 `Login_rbp-0x80`

```c
printf("Your passowrd :");
my_read(buf, 0x7f);                          // read up to 127 bytes
if (strncmp(buf, passwd, strlen(buf)) == 0)
    logged_in = 1;                            // "Login Success !"
```

### `Copy(dst)` —— `sub rsp, 0x90`，buf 位于 `Copy_rbp-0x80`

```c
printf("Copy :");
my_read(buf, 0x3f);                          // read up to 63 bytes
strcpy(dst, buf);                             // dst = main's rbp-0x60
puts("It is magic copy !");
```

### `my_read(buf, n)`

```c
r = read(0, buf, n);
if (buf[r-1] == '\n') buf[r-1] = '\0';       // NUL-terminates ONLY if last byte is '\n'
```

**关键点：** `Login` 和 `Copy` 都是在同一调用深度上被 `main` 调用的 → 它们的本地缓冲区（`rbp-0x80`）占用**完全相同的那段栈内存**。

## 漏洞

### V1 —— `strncmp` 与 `strlen(input)` —— 密码预言机 / 认证绕过

**根因：** `Login` 用 `strncmp(buf, passwd, strlen(buf))` 把用户提供的缓冲区与密码做比较。比较长度由攻击者控制。

```c
strncmp(buf, passwd, strlen(buf))
```

**认证绕过：** 发送 `\x00`（空字符串，`strlen == 0`）→ `strncmp(..., 0) == 0` → Login Success。这样无需知道密码即可把 `logged_in = 1`。

**逐字节预言机：** 发送 `known_prefix + guess_byte + \x00` 时，`strncmp` 恰好比较 `len(prefix)+1` 个字节。返回 “Login Success” 即表示猜测的字节正确 → 可以逐字节爆破 16 字节密码（每字节平均约 128 次尝试，总共约 2048 次查询）。

### V2 —— 通过共享栈帧的 `strcpy` 溢出

**根因：** `Login` 和 `Copy` 共用同一处栈缓冲区。`Login` 最多可向该缓冲区写入 127 字节，而 `Copy` 通过 `my_read` 只读取 63 字节进去。当 `Copy` 随后调用 `strcpy(dst, buf)` 时，它从这块共享缓冲区拷贝——但 `strcpy` 只在 NUL 处停止。如果此前 `Login` 已经把第 63–126 字节填成非 NUL 数据，`strcpy` 就会拷贝到**远超 63 字节的位置**，溢出覆盖 `main` 的 password 槽、saved rbp 以及返回地址。

```text
Login fills: buf[0..126]  (127 bytes, no NUL at end if no '\n')
Copy reads:  buf[0..62]   (63 bytes, overwrites only first 63)
strcpy:      copies buf[0..NUL) → main's copy_dest (rbp-0x60)
             continues past 63 bytes using Login's leftover data
             → overwrites password (rbp-0x20) and return address (rbp+0x08)
```

**影响：** 完全控制 main 的返回地址（相对 `copy_dest` 的偏移 0x68）。为了让退出时的 `memcmp` 检查通过，必须把 password 槽（偏移 0x40）恢复为原值。

### V3 —— 栈上残留的 libc 指针

**根因：** `Copy` 调用 `strcpy` 和 `puts` 之后，libc 内部函数调用会在该栈帧上留下返回地址及其他 libc 指针。由于 `Login` 和 `Copy` 共用同一处栈帧，后续的 `Login` 调用可以在缓冲区内的已知偏移处观察到这些残留的 libc 指针。

**影响：** 先通过溢出把 password 槽用已知的非 NUL 字节（例如 `'C'*8`）覆盖，再用预言机爆破紧随其后的 6 个字节，攻击者即可还原一个 libc 地址。泄露值通常是 `_IO_file_setbuf+9` 或 `_IO_file_overflow+235`（相对 libc 基址的偏移分别为 `0x78439` 和 `0x7a81b`）。

## 利用路径

所有解法都基于相同的基本原语：用 V1（预言机）做泄露，用 V2（strcpy 溢出）取得控制。区别只在于泄露什么，以及用什么覆盖返回地址。

---

### 路径 A —— 泄露密码 + 泄露 libc + one-gadget（最常见）

**使用者：** 解法 8、370、821、3498、7905、25572、34817、38891 等众多解法

1. **通过 `strncmp` 预言机爆破 16 字节密码**。如果某个字节是 `\x00`，则重新连接（换取新的随机密码）。

2. **泄露 libc 地址：**
   - `Login` 发送 `\x00 + 'A'*63 + 'A'*8`（不带换行）→ 把缓冲区填到 63 字节之后。首字节 `\x00` 绕过认证（`strlen == 0` → 成功，`logged_in = 1`）。
   - `Copy` 发送任意短输入 → `strcpy` 把整个缓冲区拷贝进 `main` 的 `copy_dest`。共享栈上的残留 libc 指针会覆盖 password 槽。
   - 切换登出（`'1'`），然后爆破新的 “密码” 字节——这些现在是 libc 指针。
   - `leaked - 0x78439 = libc_base`（视运行环境也可能是 `leaked - 0x7a81b`）。

3. **覆盖返回地址：**
   - `Login` 发送 `\x00 + 'A'*63 + password + 'B'*24 + p64(one_gadget)`（不带换行）。
   - `Copy` → `strcpy` 溢出 `copy_dest`，在偏移 0x40 处恢复 password，并把 `one_gadget` 放在偏移 0x68（返回地址）处。

4. **触发：** 发送 `'2'` → `memcmp` 通过（password 已恢复）→ `mov eax, 0; leave; ret` → 跳转到 one_gadget。由于 `eax == 0`（由 memcmp 的返回值设置），`rax == NULL` 约束得到满足。

**one-gadget 偏移（glibc 2.23）：**
```python
0x45216   # rax == NULL (preferred — satisfied by memcmp eax=0)
0x4526a   # [rsp+0x30] == NULL
0xef6c4   # [rsp+0x50] == NULL
0xf0567   # [rsp+0x70] == NULL
```

**可靠性：** 每条连接约 94%。只有当随机密码中含有 NUL 字节时才会失败（约 6% 概率），因为 `strcpy` 遇到 NUL 就停止，无法恢复该字节。

---

### 路径 B —— 泄露密码 + 泄露 PIE 基址 + ROP 链

**使用者：** 解法 59、278、533、2605、9952、10128、13019

这个变体额外泄露 PIE 基址，以便使用二进制内的 gadget 构造 ROP 链：

1. **爆破密码**（与路径 A 相同）。

2. **泄露 PIE 基址：** password 之后（`copy_dest` 中偏移 0x40 处），`main_rbp-0x10` 处的下一个栈槽存放着 `__libc_csu_init`（PIE 地址 `0x1060`）。用溢出 + 预言机读取 password 之后的 6 个字节 → `PIE_base = leaked - 0x1060`。

3. **第一次溢出 → ret 到 `read_n`：** 把返回地址覆盖为二进制内的 `my_read` gadget（`PIE+0xca0`）。当 main 返回时，它会以当时 `rdi`/`rsi` 恰好持有的值调用 `my_read`，从而可以发起**第二次、更大的栈溢出**，写入任意字节（不受 `strcpy` 的 NUL 限制）。

4. **第二次溢出 → 完整 ROP：**
   - `pop rdi; ret` + GOT 表项 + `puts@plt` → 运行时泄露 libc。
   - `pop rdi; ret` + `"/bin/sh"` + `system` → 拿到 shell。
   - 或者把栈 pivot 到 BSS，串接 `read` 读入第三段 payload。

**优点：** ROP 链中可以写 NUL 字节（第二次溢出用的是 `read`，不是 `strcpy`）。可以用 `system("/bin/sh")`，不受 one-gadget 约束限制。

**缺点：** 需要泄露 PIE（又要约 2048 次预言机查询），需要两轮 return-to-main 循环（如果 main 重启还要重新泄露密码），更复杂。

---

### 路径 C —— 泄露密码 + 泄露 libc + 通过 choice 缓冲区调用 `system`

**使用者：** 解法 331、821（变体）

一种更简单、可避开 one-gadget 约束的变体：

1. **密码 + libc 泄露**（与路径 A 相同）。
2. **把返回地址覆盖为 `system`。**
3. **用 `'2;sh;\x00'` 作为菜单选项触发**——16 字节的 choice 缓冲区以 `'2'` 开头（触发退出路径），但同一缓冲区在 `choice+2` 处含有 `"sh"`。由于 `system` 收到的 `rdi` 指向栈上的 choice 缓冲区区域，于是执行 `system("sh")`。

**注意：** 这种做法很脆弱——`rdi` 必须恰好指向含有 `"sh"` 的正确栈位置。部分解法使用 `"2;bash\x00"` 或 `"2;/bin/sh;"`。

---

### 路径 D —— 通过增量写入实现不受 NUL 字节限制的 ROP

**使用者：** 解法 278、9952

含有 NUL 字节的地址无法用 `strcpy` 一次性写入。这种思路通过多轮增量写入来构造 ROP 链：

1. 对目标 ROP payload 中的每个 NUL 字节，在单独的 `Login+Copy` 循环中写入该 NUL **之后**的全部内容。每轮都会把一段以 NUL 结尾的字符串放到不同偏移处。
2. 从最高位的 NUL 位置向最低位依次处理，分多轮拼出完整 payload。
3. 最后恢复 password 并触发返回。

这样就能构造任意 ROP 链，不受 NUL 字节限制。

## 关键观察

### 栈布局 —— Login/Copy 共享的缓冲区

```text
             Login/Copy frame               main frame
             ┌──────────────┐          ┌──────────────────┐
rbp-0x80     │ buf[0..126]  │          │                  │
             │  (Login: 127)│          │ copy_dest[0..63] │ rbp-0x60
             │  (Copy:   63)│          │                  │
             │              │          │ password[0..15]  │ rbp-0x20
             │              │          │ choice[0..15]    │ rbp-0x10
             └──────────────┘          │ saved rbp        │ rbp+0x00
                                       │ return address   │ rbp+0x08
                                       └──────────────────┘
```

`strcpy` 之后，Login 的 `buf[0..62]` 映射到 `copy_dest[0..62]`。
Login 的 `buf[63..78]` 映射到 `copy_dest[63..78]`，即 password 槽及其之后的位置。
Login 的 `buf[79..103]` 映射到 saved rbp 和返回地址区域。

### 预言机交互协议

菜单通过 `__read_chk(0, choice, 16, 16)` 精确读取 16 字节。可以在同一个 TCP 段中发送 `"1" + 15_pad_bytes + password_guess` 来实现流水线化。Login 的 `my_read` 会贪婪地读取最多 127 字节，因此把请求体补齐到恰好 127 字节即可让每次查询自动分帧。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 密码预言机（逐字节） | V1：`strncmp` + `strlen(input)` | 确定性（约 2048 次查询） |
| 认证绕过（空字符串） | V1：`strlen("\x00") == 0` | 确定性 |
| 通过 `strcpy` 的栈溢出 | V2：共享栈帧 + `strcpy` 越过 63 字节 | 确定性（payload 中不能含 NUL） |
| libc 泄露（残留指针） | V3：共享栈帧 + 溢出 + 预言机 | 确定性 |
| PIE 泄露（可选） | V3：更深层溢出 + 预言机 | 确定性 |
| 返回地址覆盖 | V2：`copy_dest + 0x68 = ret addr` | 确定性 |
| 绕过 `memcmp` | 在 `copy_dest + 0x40` 处恢复 password | 若 password 含 NUL 则失败（约 6%） |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
# Libc leak offsets (residual pointer on stack)
_IO_file_setbuf_plus_9  = 0x78439    # common in direct process
_IO_file_overflow_plus_235 = 0x7a81b # common under fork-server/socat

# Gadgets
one_gadget_rax_null  = 0x45216   # rax == NULL (best — memcmp sets eax=0)
one_gadget_rsp30     = 0x4526a   # [rsp+0x30] == NULL
one_gadget_rsp50     = 0xef6c4   # [rsp+0x50] == NULL
one_gadget_rsp70     = 0xf0567   # [rsp+0x70] == NULL
system               = 0x45390
bin_sh               = 0x18c177
__libc_start_main    = 0x20740
puts                 = 0x6f690

# PIE offsets (if PIE leak used)
__libc_csu_init      = 0x1060
main                 = 0xecf
my_read              = 0xca0
puts_plt             = 0xae0
pop_rdi_ret          = 0x10c3
pop_rsi_r15_ret      = 0x10c1
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `8.md` | A | 密码预言机 → libc 泄露 → one_gadget | 简洁的 Python，注释详细 |
| `59.md` | B | 密码 + PIE 预言机 → ret-to-read → ROP | 两阶段 ROP；栈 pivot 到 BSS |
| `278.md` | B + D | PIE 泄露 → 增量 NUL 安全 ROP → puts 泄露 | Ruby；处理 ROP 链中的 NUL 字节 |
| `331.md` | C | 密码 → libc → 通过 choice 缓冲区调用 `system` | 用 `"2;bash\x00"` 作为选项触发 system |
| `370.md` | A | 密码 → libc → one_gadget（0xf0567） | 也泄露了 PIE，但最终用 one_gadget |
| `533.md` | B | PIE 泄露 → ret-to-read → `execve` ROP | 通过 ROP 完整调用 `execve` |
| `821.md` | A | 流水线化预言机 → libc → `system` | 批量查询以提速 |
| `2605.md` | B | PIE + 栈泄露 → ret-to-read → one_gadget | 泄露栈地址用于 pivot |
| `3498.md` | A | 密码 → libc → one_gadget（0xf0567） | 简洁；用 `flat()` 构造 payload |
| `7905.md` | A | 密码 → libc → one_gadget（0x45216） | 最详细的题解；完整中文分析 |
| `9952.md` | B + D | PIE → 增量写入 → puts 泄露 → ROP | `build_rop` 处理无 NUL 写入 |
| `10128.md` | B | PIE + 栈 → ret-to-read → 栈 pivot | 使用 `pop rsp` gadget |
| `25572.md` | A | 密码 → libc → one_gadget | 详细题解，来自 taintedbits.com |
| `34817.md` | A | 密码 → libc（`_IO_file_setbuf+9`）→ one_gadget | 简洁的 Python3 |
| `38891.md` | A | 密码 → libc → one_gadget（0x45216） | 极简代码 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的利用脚本（纯 socket，不依赖 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/babystack` | 原始题目二进制（stripped PIE ELF） |
| `artifacts/libc_64.so.6` | 远程 libc（glibc 2.23） |
| `solution/*.md` | 社区题解（132 篇） |
