---
tags:
  - heap-buffer-overflow
  - seccomp-bypass
  - rop
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.27
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "msgpack 数据包反序列化过程中的堆破坏可在 seccomp 之下劫持执行流，并构造 open-read-write 的 ROP 链。"
proof-of-concept: no
---

# HITCON FTP — pwnable.tw（500 分）

[← 返回 pwnable.tw 题目索引](README.md)

> Nobody find all vulnerabilities in HITCON CTF final 2019. :'(
>
> `nc chall.pwnable.tw 10309`
>
> Flag: `FLAG{c4ptur3_th3_f0rtun3_by_h1tc0n_ftp}`

## 题目概览

一个自制的类 TFTP 服务器（x86-64，Full RELRO，Canary，NX，PIE），跑在 UDP 上，用 msgpack 做数据包序列化。服务器为每个连接分配一个 UDP 端口，把 msgpack 数组解析为命令（RRQ=1、WRQ=2、DATA=3、ACK=4、ERR=5、OACK=6），支持带 CRC32 校验和块大小协商的文件读写。seccomp 沙箱只允许文件 I/O、网络（socket/sendto/recvfrom/bind）、内存管理（mmap/mprotect/brk）和 select。主循环处于 `SIGALRM` 定时器（约 60 秒）之下；定时器触发后 `select()` 失败，`main()` 返回。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  Seccomp:  Allowlist (open, read, write, close, stat, fstat, lseek,
            ioctl, openat, brk, mmap, mprotect, select, socket,
            sendto, recvfrom, bind, rt_sigreturn, exit, exit_group)
```

## 漏洞

### V1 — 文件名未终止导致的堆地址泄漏（信息泄漏）

**根因：** 请求结构体用 0x100 字节缓冲区存放 `filename`。当服务器收到含 `"../"` 的文件名时，会拒绝访问并用 `snprintf` 按完整文件名格式化错误消息。如果文件名恰好 0x100 字节，`strncpy` 不会补 NUL 终止符，于是紧接着的 `FILE *fp` 指针会被拼进错误响应。

```c
// Simplified: filename is 0x100 bytes, FILE* follows immediately
struct Request {
    // ...
    char filename[0x100];   // +0x010
    FILE *fp;               // +0x110
    // ...
};
strncpy(req->filename, via.str.ptr, via.str.size);  // no NUL if size == 0x100
// error path:
snprintf(buf, ..., "file (%s) access violation", req->filename);
// leaks fp pointer bytes after the filename
```

**触发：** 先发一个 WRQ 初始化 `fp`，再发一个 RRQ，文件名用 `"../".ljust(0x100, "A")`。错误响应里就在 'A' 填充之后带上了 `FILE*` 堆指针。

**影响：** 泄漏一个堆地址。堆基址 = `leaked_ptr - 0x22ad0`。

### V2 — OACK 选项处理中的类型混淆（任意读）

**根因：** 处理 RRQ/WRQ 数据包时，服务器会检查 `array[3]` 是否为 `MSGPACK_OBJECT_MAP`——但**只在 `array.size == 4` 时检查**。若数组有 5 个及以上元素，该检查被完全跳过，`array[3]` 无论是什么类型都会被当作 `msgpack_object_kv` 条目的 map 来解释。

```c
// Simplified condition — note the short-circuit with ==4
if (via.array.size == 4 && via.array.ptr[3].type != MSGPACK_OBJECT_MAP)
    return error;
// When array.size >= 5, array[3] passes unchecked
```

把字符串或原始字节作为 `array[3]` 发送，攻击者就能控制被解释为 `msgpack_object_kv` 结构体的内存布局。构造一条伪造条目，令 `key.type = MSGPACK_OBJECT_STR`、`key.ptr = target_address`、`val.type = MSGPACK_OBJECT_POSITIVE_INTEGER`，服务器就会读取 `target_address` 处的内存，并把它作为 OACK 选项键放进响应。

**触发：**
```python
fake_kv = p64(5) + p64(0x3f) + p64(target_addr) + p64(2) + p64(0x1337)
send([1, "flag", "octet", fake_kv, "pad"])  # array size=5, bypasses check
# Response: OACK with key = memory_at_target_addr (up to 63 bytes)
```

**影响：** 可对任意地址读取最多 63 字节。用于泄漏 libc（经 `_IO_file_jumps` 或 GOT）、栈（经 `environ`）、PIE 基址和 canary。

### V3 — `check_crc32` / `msgpack_object_print_buffer` 中的栈溢出（代码执行）

**根因：** CRC32 校验函数调用 `msgpack_object_print_buffer(error_buf, payload_len, obj)`，其中 `error_buf` 是 0x204 字节的栈缓冲区，而 `payload_len` 由协商出的 `blksize` 选项控制（最大 0xFFFF）。当 `blksize` 设得很大时，`snprintf` 会把 msgpack 数据对象的字符串表示写远超缓冲区边界，覆盖 `main()` 的 canary、保存的 RBP 和返回地址。

```c
// check_crc32 — simplified
char error_buf[0x204];  // stack buffer
// obj_len comes from the DATA packet's payload length (controlled via blksize)
msgpack_object_print_buffer(error_buf, obj_len, data_obj);
// snprintf inside print_buffer writes string repr of data_obj to error_buf
// If obj_len > 0x204, this overflows the stack
```

**难点：** 因为内部用的是 `snprintf`，无法直接写入 NUL 字节。解题者用**逆序写入**绕开——每次写入都借 `snprintf` 自动补的 NUL 终止符，把零放到递减的偏移处。

**影响：** 完整的栈溢出。配合泄漏到的 canary，可实现 ROP 链或栈迁移。

## 利用路径

全部 20 个解法都走同一条三漏洞链（V1 → V2 → V3）。差别在于泄漏链的具体细节和最终 payload 策略。

---

### 路径 A — 栈迁移到堆 → mprotect + shellcode（最常见）

**相关题解：** 370、821、2972、5586、8153、31599、34306、35463、36997

1. **V1：** 用超长 `"../"` 文件名泄漏堆地址。
2. **V2：** 泄漏 libc（经堆上 FILE 结构体的 `_IO_file_jumps` 或 `_IO_2_1_stderr_`）、栈（`environ`）、canary（stack+offset+1，跳过首字节 NUL），以及可选的 PIE 基址。
3. **V3：** 把 `blksize` 设为 0xFFFF。反复溢出 `check_crc32` 的栈缓冲区，逆序写入：
   - 恢复 canary（先写第 1-7 字节，再用 NUL 终止第 0 字节）
   - 用指向 `datain` 缓冲区（堆）或受控区域的指针覆盖保存的 RBP
   - 用 `leave; ret` gadget 覆盖返回地址（栈迁移）
4. **把 ROP 链写到 `datain` 缓冲区：** `pop rdi; heap_page; pop rsi; 0x1000; pop rdx; 7; mprotect; shellcode_addr`
5. **Shellcode：** `open("/home/hitcon_ftp/flag") → read(fd, buf, 0x100) → sendto(0, buf, len, 0, saved_sockaddr, 16)`——把 flag 经 UDP 发回攻击者地址（从堆上的请求结构体中取出）。
6. **等待约 60 秒** 让 SIGALRM 触发 → `select()` 失败 → `main()` 返回到 ROP。

### 路径 B — 直接在栈上布 ROP 链（不用 shellcode）

**相关题解：** 3578、6748、28605、28652、34817、36134

泄漏链相同，但不做迁移：
1. 借反复的 `check_crc32` 溢出，把完整 ROP 链直接写到 `main()` 的栈帧上。
2. ROP：用 libc gadget 和 syscall 做 `open(flag_path) → read(fd, buffer, N) → sendto(0, buffer, N, 0, sockaddr, 16)`。
3. 部分变体直接调用二进制自身的 `send_err()` / `process_send()` 函数（PIE+0x2855 一类地址），借现有 TFTP 协议把 flag 发出去。

### 路径 C — `close(3) + open(flag)` → 复用现有 FILE（取巧变体）

**相关题解：** 6748

1. ROP 链先 `close(3)`（服务器打开的文件描述符），再 `open("/home/hitcon_ftp/flag")`，从而复用 fd 3。
2. 然后调用二进制自身的 `process_send(request)`，它从 fd 3 关联的 FILE（此时已指向 flag 文件）读取数据，并通过正常 TFTP 协议发回。

### 路径 D — 用 CRC32 暴力破解完成初次泄漏（不需要 V1）

**相关题解：** 9251、11177、33090、34817

不用 V1 做堆泄漏：
1. 利用 `check_crc32` 里的 `strlen()`——CRC 只算到第一个 NUL 字节。通过补齐到已知栈偏移并逐字节暴力（每字节 256 次尝试），攻击者可用 `CRC32(padding + guess_byte) == expected` 判断栈上的值。
2. 暴力 4-5 个字节的栈指针（约 5×256 = 1280 个包），得到代码/PIE 基址。
3. 再用 V2 泄漏其余信息（libc、canary、堆），用 V3 做溢出。

**缺点：** 更慢（约 1280 次往返 vs. V1 的 1 次），需要低延迟连接。有解题者从日本 VPS 跑以避免超时。

### 路径 E — 经 TLS/ld.so 泄漏 canary（替代栈 canary 泄漏）

**相关题解：** 3498

不从栈上泄漏 canary：
1. 用 V2 从 libc 读 `_rtld_global` → 得到 `ld.so` 基址 → 读 TLS 块 → 从 `tcbhead_t.stack_guard`（TLS+0xba8 一类偏移）取出 canary。
2. 这样就不必知道 canary 在栈上的确切位置。

### 路径 F — 遍历 auxv 取得 PIE 与 canary（exp.py 的做法）

**相关题解：** exp.py（本目录的参考利用脚本）

1. **V1：** 借 msgpack ExtType 技巧泄漏堆（发送大量 map 键触发 realloc，再从复用内存里解析泄漏的键）。
2. **V2：** 从请求结构体读 `FILE*` → `_IO_file_jumps` → libc 基址。读 `environ` → 栈。遍历 `envp[]` 直到 NULL → 找到 `auxv[]`。解析 `AT_PHDR` → PIE 基址。解析 `AT_RANDOM` → 读 16 字节随机块 → 取出 canary（前 8 字节，最低位清 0）。
3. **V3：** 构造 ROP 链镜像，按 NUL 字节切分成多段。每段以 WRQ+DATA 对发送；`snprintf` 的 NUL 终止符负责产生零字节。ROP：`open(flag) → read(3, buf, 0x80) → send_data(request, buf, 0x80) → exit(0)`。

## 泄漏原语总结

| 泄漏目标 | 方法 | 来源 |
|------|-----|--------|
| 堆基址 | V1：`"../"` 文件名溢出泄漏 `FILE*` | 除路径 D 外的所有解法 |
| 堆基址（备选） | V3：用 CRC32 暴力栈指针 → V2 读取 | 路径 D 解法 |
| libc 基址 | V2：从堆或二进制读 `_IO_file_jumps` / `_IO_2_1_stderr_` / GOT 项 | 通用 |
| 栈地址 | V2：读 `libc.environ` | 通用 |
| PIE 基址 | V2：从栈读返回地址，或 V3：CRC32 暴力 | 多数解法 |
| 栈 canary | V2：读 `stack_addr - offset + 1`（跳过第 0 字节 NUL） | 多数解法 |
| canary（备选） | V2：经 `_rtld_global` 链读 TLS 的 `stack_guard` | 解法 3498 |
| canary（备选） | V2：从 auxv 读 `AT_RANDOM` 的前 8 字节 | exp.py |

## 执行触发

SIGALRM 处理函数**不会**调用 `exit()`。它只是打断 `select()`，后者返回 `-1`（EINTR），使主循环跳出、`main()` 返回——返回进攻击者的 ROP 链。所有解法都必须等约 60 秒才会发生。

## 关键偏移（远端 libc，glibc 2.27）

```python
# libc gadgets
pop_rdi     = 0x2155f
pop_rsi     = 0x23e6a
pop_rdx     = 0x1b96
pop_rax     = 0x439c8
pop_rsp     = 0x3960
pop_rdx_r10 = 0x1306b4
syscall_ret = 0xd2975
leave_ret   = 0x54803

# libc symbols / offsets
_IO_file_jumps = 0x3e82a0
_IO_2_1_stderr = 0x3ec680
environ        = 0x3ee098
mprotect       = 0x11bae0

# Binary internals
request_delta  = 0x13b10   # from heap base to first request struct
send_data      = 0x257e    # PIE offset: function to send data via TFTP
send_err       = 0x2855    # PIE offset: function to send error via TFTP
flag_path_bss  = 0x20d160  # PIE offset: "/home/hitcon_ftp/flag" if stored via OACK
```

## seccomp 策略

白名单：`rt_sigreturn`、`exit_group`、`exit`、`open`、`read`、`write`、`close`、`stat`、`fstat`、`lseek`、`ioctl`、`openat`、`brk`、`mmap`、`mprotect`、`select`、`socket`、`sendto`、`recvfrom`、`bind`。其余一律 KILL。

因此 `execve` 被禁止，所有利用都必须用 open/read + sendto 把 flag 外带出去。

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `370.md` | A | 堆泄漏 → mprotect + shellcode（经保存的 sockaddr 发 sendto） | 干净，使用 pwntools shellcraft |
| `821.md` | A | mprotect + 手写 shellcode | 详细 DATA_HDR 常量，定位 datain 缓冲区 |
| `2972.md` | A | mprotect + `jmp rsp` shellcode | mprotect 后用 `jmp rsp` gadget |
| `3498.md` | A + E | 经 TLS（`_rtld_global` 链）取 canary | 替代的 canary 泄漏路径 |
| `3578.md` | B | 直接 ROP：open/read/sendto | 用二进制的 `send_err` 回传 flag |
| `5586.md` | A | mprotect + shellcode | 从堆上请求结构体取 sockaddr |
| `6748.md` | B + C | `close(3) + open(flag)` → 经 `process_send` 复用 fd 3 | 优雅的 fd 劫持变体 |
| `8153.md` | A | leave;ret 迁移 → mprotect + sendto shellcode | 干净的 NUL 字节处理 |
| `9251.md` | D | CRC32 暴力 libc_pthread → 扫堆 | 暴力 4 字节 libpthread 地址 |
| `11177.md` | D | CRC32 暴力栈指针 | 暴力 5 个栈字节，再任意读拿其余 |
| `25916.md` | B | 直接 ROP：经 syscall 做 open/read/sendto | 使用裸 syscall gadget |
| `28605.md` | A | 堆泄漏 → mprotect + 汇编 sendto | 详细漏洞说明 |
| `28652.md` | B | ROP：open → xchg_eax_edi → read → `send_err` | 调用二进制自身的发送函数 |
| `31599.md` | A | leave;ret 迁移 → open/read → `send_data` | 用 PIE 的 `send_data` 回传 flag |
| `33090.md` | D | CRC32 暴力 PIE 基址 | 在多个栈偏移上暴力 5 个字节 |
| `34306.md` | A | mprotect + 带类型 shellcode | 在内存中修补 `process_new` 的比较 |
| `34817.md` | D + B | CRC32 暴力 PIE → 任意读 → 直接 ROP | 结尾调 `send_err` |
| `35463.md` | A | mprotect + 带类型 shellcode + sendto | 3 个 bug：溢出、类型混淆、参数不匹配 |
| `36134.md` | B | 直接 ROP：open/read → `send_err` | 最干净的 ROP，复用二进制的错误发送路径 |
| `36997.md` | A | mprotect + shellcode，shellcode 内建 UDP socket | shellcode 新建 socket 发 flag |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 参考利用脚本（遍历 auxv + 多阶段 NUL 字节安全溢出） |
| `desc.txt` | 题目描述 |
| `artifacts/hitcon_ftp` | 题目二进制 |
| `solution/*.md` | 社区题解文章（20 个解法） |
