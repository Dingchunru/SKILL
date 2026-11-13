---
name: ctf-pwn
description: 提供 CTF 挑战中的二进制漏洞利用技术。当已经拿到存在漏洞的原生目标或服务，需要把内存破坏或底层原语转化为代码执行或提权时使用，例如缓冲区溢出、格式化字符串、堆漏洞、ROP、ret2libc、shellcode、内核利用、seccomp 绕过、沙箱逃逸或 Windows/Linux 利用链。如果主要障碍是看不懂二进制在做什么，不要使用本技能，先用逆向工程。不要用于纯 Web 漏洞、磁盘或流量取证，或独立的密码学/数学挑战。
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
  keywords: binary elf heap tcache uaf unlink rop ret2libc format stack overflow shellcode seccomp kernel libc exploit gadget fsop srop
---

# CTF 二进制利用（Pwn）

二进制利用（pwn）类 CTF 挑战的速查。每种技术在这里给出一行摘要，完整细节见各支持文件。

## 定位

已经有一个可运行或可连接的原生目标，需要把内存破坏或底层原语（栈、堆、格式化字符串、整数、竞态、内核）变成代码执行、任意读写或 flag 读取。

- **适用**：ELF/PE 二进制、远程 `nc` 服务、内核模块、沙箱内的原生程序。
- **不适用**：还不知道二进制在做什么 → 先用 `/ctf-reverse`；漏洞在 HTTP、模板或浏览器 → `/ctf-web`。
- 只做静态可利用性评估时，先读 [static-signals.md](static-signals.md)。

## 标准产出（Definition of Done）

1. **判定**：漏洞类型 + 根因（函数、地址、偏移）。
2. **利用脚本**：可直接运行的 `exp.py`（pwntools），含目标地址、libc 版本/偏移、所需工具版本。
3. **验证**：实际拿到的 flag；失败时给出精确失败点（崩溃地址、缺失的泄露或原语）。
4. **复现说明**：保护机制、seccomp 策略、依赖文件（libc/ld）与运行命令。

## 解题工作流

1. **侦察**：`file`、`checksec`、`readelf -h/-l`；确认架构、保护、libc 版本；有源码先读危险调用。
2. **定位漏洞**：从输入点回溯到危险操作（`gets`、`strcpy`、`scanf("%s")`、`printf`、free 后使用）。
3. **最小验证**：先拿到确定证据（崩溃偏移、一次任意写、libc 泄露），再谈完整链。
4. **构造利用**：按保护机制选目标（GOT、返回地址、hook、vtable、内核结构体），必要时上 ROP/SROP/FSOP。
5. **验证 flag**：本地复现后打远程；记录偏移、libc 版本、seccomp 策略。

## 检索与路由

入口索引：[catalog.md](catalog.md)（每篇参考文档一行：用途、关键章节）；程序化检索用 [catalog.json](catalog.json)。只加载命中的文件，不要整目录通读。

| 症状 / 题型 | 首个文件 |
|---|---|
| 栈溢出、ret2win、canary、结构体指针覆盖 | [overflow-basics.md](overflow-basics.md) |
| ret2libc、syscall ROP、栈迁移、ret2csu | [rop-and-shellcode.md](rop-and-shellcode.md)、[rop-advanced.md](rop-advanced.md) |
| 格式化字符串（泄露、GOT 覆写、盲打） | [format-string.md](format-string.md) |
| 堆 UAF、tcache、unlink、House of * | [heap-techniques.md](heap-techniques.md)、[heap-techniques-2.md](heap-techniques-2.md) |
| FSOP、`_IO_FILE`、vtable 劫持 | [heap-fsop.md](heap-fsop.md) |
| 内核模块、QEMU、KASLR/SMEP 绕过 | [kernel.md](kernel.md)、[kernel-techniques.md](kernel-techniques.md)、[kernel-bypass.md](kernel-bypass.md) |
| 自定义 VM、FUSE、busybox、模拟器 | [sandbox-escape.md](sandbox-escape.md) |
| 泄露方式选择、原语排序 | [attack-playbook.md](attack-playbook.md) |
| 只有二进制、先判断能不能打 | [static-signals.md](static-signals.md) |
| 具体 pwnable.tw 题目 | [pwnable-tw/README.md](pwnable-tw/README.md)（43 题，按分数、标签、保护机制检索） |

## 前置条件

**Python 包（全平台）：**
```bash
pip install "pwntools==4.15.0" "ROPgadget==7.7" "ropper==1.13.13"
# 或通过脚本：bash scripts/install_ctf_tools.sh python
```

**uv 替代方案：**
```bash
uv venv && uv pip install "pwntools==4.15.0" "ROPgadget==7.7" "ropper==1.13.13"
```

**Linux（apt）：**
```bash
apt install gdb binutils strace ltrace qemu-system-x86
```

**可选的跨架构支持（ARM/MIPS — Debian/Ubuntu）：**
```bash
apt install qemu-user qemu-user-static gdb-multiarch binutils-multiarch libc6-armhf-cross libc6-arm64-cross libc6-mips-cross
```

**macOS（Homebrew）：**
```bash
brew install gdb binutils qemu
```

**Ruby gems（全平台）：**
```bash
gem install one_gadget seccomp-tools
```

**手动安装：**
- pwndbg — Linux：[GitHub](https://github.com/pwndbg/pwndbg)，macOS：`brew install pwndbg/tap/pwndbg-gdb`
- checksec — 随 pwntools 提供（`checksec --file=binary`）

**MCP 服务（可选）：** WinDbg MCP（[svnscha/mcp-windbg](https://github.com/svnscha/mcp-windbg)）用于 Windows 崩溃转储、实时断点驱动利用、内核/驱动调试；IDA Pro MCP / Ghidra MCP 用于反编译漏洞函数——见 [tools-mcp.md](tools-mcp.md)。

## 参考文档（按需加载）

- [catalog.md](catalog.md) - 全量文档索引：每篇的用途、关键章节、字节数；配套 [catalog.json](catalog.json) 供程序化检索
- [overflow-basics.md](overflow-basics.md) - 栈/全局缓冲区溢出、ret2win、canary 绕过、fork 服务上的 canary 逐字节爆破、结构体指针覆盖、有符号整数绕过、隐藏 gadget、基于 stride 的越界读泄露、未检查 memcpy 长度导致的解析器栈溢出（含 callee-saved 寄存器恢复）
- [rop-and-shellcode.md](rop-and-shellcode.md) - 核心 ROP 链（ret2libc、syscall ROP、rdx 控制、shell 交互）、ret2csu、坏字符 XOR 绕过、冷门 x86 gadget（BEXTR/XLAT/STOSB/PEXT）、通过 `xchg rax,esp` 栈迁移、`sprintf()` gadget 链绕过坏字符、canary XOR 尾声作为 RDX 清零 gadget、以 `stub_execveat` 系统调用和 `read()` 返回值替代 execve
- [rop-advanced.md](rop-advanced.md) - 进阶 ROP 技术：通过 `leave;ret` 双重栈迁移到 BSS、带 UTF-8 约束的 SROP（Sigreturn-Oriented Programming）、seccomp 绕过、RETF 架构切换（x64→x32）绕过 seccomp、输入反转的 shellcode、`.fini_array` 劫持、ret2vdso、pwntools 模板、x32 ABI 系统调用别名绕过 seccomp、基于时间的盲 shellcode 外带
- [format-string.md](format-string.md) - 格式化字符串利用（泄露、GOT 覆盖、盲打、过滤绕过、canary 泄露、`__free_hook`、`.rela.plt` 修补、覆盖保存的 EBP 做 `.bss` 迁移、覆盖 `argv[0]` 泄露栈信息、`.fini_array` 循环做多阶段利用、连续 `%p` 绕过 `__printf_chk`、单次调用泄露 + GOT 覆盖、输入变换后的 ROT13 格式化字符串利用）
- [advanced.md](advanced.md) - seccomp 进阶技术、UAF、JIT、冷门 GOT、进制转换造成堆重叠、树结构栈分配不足、ret2dlresolve、内核利用（基础）
- [heap-techniques.md](heap-techniques.md) - House of Apple 2（含 setcontext SUID 变体）、House of Einherjar、House of Orange/Spirit/Lore/Force、堆布局 groom、自定义分配器（nginx、talloc）、经典 unlink、musl libc 堆（meta 指针 + atexit 劫持）、tcache stashing unlink 攻击、unsafe unlink + top chunk 合并
- [heap-techniques-2.md](heap-techniques-2.md) - CTF writeup 中的堆变体：UAF vtable 指针编码 shell 参数、未初始化 chunk 残留指针泄露、tcache strcpy 空字节溢出 + 向后合并、相邻结构体函数指针溢出实现 libc 泄露 + GOT 覆盖、隐藏菜单 tcache 投毒、tcache double-free + 伪造 `_IO_FILE` vtable 劫持 stdout、tcache 提升为 fastbin 的跨 bin 攻击、6 位索引越界 + `written_bytes` 累加器、对 calloc chunk 翻转 IS_MMAPED 位实现 unsorted bin 泄露、仅低位堆指针覆盖绕过文件名正则限制的 fastbin、自定义分配器 unsafe unlink 打 GOT
- [heap-fsop.md](heap-fsop.md) - FILE 结构体（`_IO_FILE`）利用：fastbin stdout vtable 两阶段劫持绕过 PIE + Full RELRO、`_IO_buf_base` 空字节劫持 stdin、glibc 2.24+ `_IO_FILE` vtable 校验绕过、对 stdin `_IO_buf_end` 的 unsorted bin 攻击、通过 `mp_` 结构破坏 unsorted bin、`realloc(ptr, 0)` 当作 `free()` 的 UAF、单字节引用计数回绕 UAF
- [advanced-exploits.md](advanced-exploits.md) - 进阶利用技术（第 1 部分）：VM 有符号比较、BF JIT shellcode、类型混淆、off-by-one 索引破坏、DNS 溢出、ASAN shadow memory、带编码约束的格式化字符串、自定义 canary 保留、有符号整数绕过、感知 canary 的部分溢出、CSV 注入、MD5 原像 gadget、VM GC UAF slab 复用、路径穿越清洗绕过、FSOP + 通过 openat/mmap/write 绕过 seccomp
- [advanced-exploits-2.md](advanced-exploits-2.md) - 进阶利用技术（第 2 部分）：自修改绕过字节码校验器、io_uring UAF 注入 SQE、int32→int16 整数截断、GC 空引用级联破坏、多次 fgets 覆盖 stdout FILE 实现无泄露 libc、有符号/无符号 char 下溢堆溢出、XOR 密钥流爆破写原语、tcache 指针解密堆泄露、伪造 chunk size 提升 unsorted bin、FSOP stdout TLS 泄露、通过 `__call_tls_dtors` 劫持 TLS 析构、自定义影子栈指针溢出绕过、有符号 int 溢出造成负向越界堆写、XSS 到二进制 pwn 的桥接
- [advanced-exploits-4.md](advanced-exploits-4.md) - 进阶利用技术（第 4 部分）：Windows SEH 覆盖 + pushad VirtualAlloc ROP、IAT 相对解析、分离进程的 shell 稳定性、SeDebugPrivilege 提权到 SYSTEM、ARM 缓冲区溢出配 Thumb shellcode、Forth 解释器 system 字利用、GF(2) 高斯消元做多轮 tcache 投毒、单比特翻转利用原语（mprotect + 迭代改代码）、用静物演化生成 Game of Life shellcode、菜单驱动 strdup/free 顺序造成 UAF、以 `system()` 为合法调用目标绕过 Windows CFG、神经网络输出越界索引函数指针、计数器溢出绕过 shellcode 唯一字节数限制
- [advanced-exploits-3.md](advanced-exploits-3.md) - 进阶利用技术（第 3 部分）：栈变量重叠/进位破坏越界、8 位循环计数器造成 1 字节溢出、游戏 AI 算术平均越界读、任意读写 GOT 覆盖 getshell、`__environ` + memcpy 溢出泄露栈、uint16 跳转截断造成 JIT 沙箱逃逸、DNS 压缩指针多问题栈溢出 + ROP、篡改程序头绕过 ELF 代码签名、游戏关卡格式有符号/无符号坐标不一致、缺失 O_CLOEXEC 导致文件描述符继承、元数据解析中的符号扩展整数下溢、只读原语构造 ROP 链、4 字节 shellcode 配合持久寄存器做时间侧信道、CRC oracle 当任意读、UTF-8 大小写转换缓冲区溢出
- [advanced-exploits-5.md](advanced-exploits-5.md) - 进阶利用技术（第 5 部分）：数据解释类利用——Chip-8 模拟器越界内存打 ret2libc、双精度浮点快排重排 canary、布隆过滤器 `abs(INT_MIN)` 负索引越界写
- [sandbox-escape.md](sandbox-escape.md) - 自定义 VM 利用、FUSE/CUSE 设备、busybox/受限 shell、shell 技巧、`process_vm_readv` 沙箱绕过、命名管道文件大小绕过、CPU 模拟器 print 操作码的 Python eval 注入
- [kernel.md](kernel.md) - Linux 内核利用基础：环境搭建、QEMU 调试、堆喷结构（tty_struct、poll_list、user_key_payload、seq_operations）、内核栈溢出、canary 泄露、提权（ret2usr、内核 ROP）、覆盖 modprobe_path、覆盖 core_pattern、kmalloc 大小不匹配堆溢出 + struct file f_op 破坏
- [kernel-techniques.md](kernel-techniques.md) - 内核利用技术：tty_struct kROP（伪造 vtable + 栈迁移）、通过 ioctl 寄存器控制实现任意地址写、userfaultfd 竞态稳定化、SLUB 分配器内部（freelist 加固/混淆）、通过内核 panic 泄露、MADV_DONTNEED 扩大竞态窗口（DiceCTF 2026）、跨 cache CPU 拆分攻击（DiceCTF 2026）、PTE 重叠文件写（DiceCTF 2026）、利用文件打开失败绕过 addr_limit 读写内核内存
- [kernel-bypass.md](kernel-bypass.md) - 内核保护绕过：KASLR/FGKASLR 绕过（`__ksymtab`）、KPTI 绕过（swapgs trampoline、信号处理器、通过 ROP 改 modprobe_path/core_pattern）、SMEP/SMAP 绕过、GDB 调试内核模块、initramfs/virtio-9p 工作流、利用模板、利用投递
- [field-notes.md](field-notes.md) - 详细 pwn 笔记：堆利用速查、额外利用笔记、常用命令
- [attack-playbook.md](attack-playbook.md) - Linux 用户态攻击 playbook：输入/权限边界侦察、按缓解措施选择泄露方式、原语排序工作流
- [static-signals.md](static-signals.md) - 与利用相关的静态信号（libc 版本、seccomp 策略、RELRO/PIE/canary/NX 证据），用于评估可利用性
- [pwnable-tw/README.md](pwnable-tw/README.md) - 43 篇 pwnable.tw writeup（orw、start、calc、hacknote、babystack、tcache_tear、death_note、dubblesort、applestore、bookwriter 等），每题包含环境、保护措施、根因缺陷和具体利用链
- [tools-mcp.md](tools-mcp.md) - pwn 方向的 MCP 服务集成：WinDbg MCP 会话模型（`open_cdb_dump`/`open_cdb_remote`/`open_kd_session` + `session_id`）、崩溃转储初筛、在转储中扫描 `flag{` 内存、实时断点/硬件观察点/内存补丁利用、`!dh -f` 检查 Windows 缓解措施（相当于 `checksec`）、用 kd 在内核态窃取 token；IDA/Ghidra MCP 用于漏洞利用开发（先反编译漏洞函数，只在需要精确 gadget 字节时下到汇编）

---

## 何时切换技能

- 如果还不理解二进制在做什么，先切换到 `/ctf-reverse`，再尝试利用。
- 如果利用路径更依赖 Web 端点、会话漏洞或上传原语而不是内存破坏，切换到 `/ctf-web`。

## 快速开始命令

```bash
# 二进制分析
checksec --file=binary
file binary
readelf -h binary

# 查找 gadget
ROPgadget --binary binary | grep "pop rdi"
ropper -f binary --search "pop rdi"
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# 调试
gdb -q binary -ex 'start' -ex 'checksec'

# 用 pattern 找偏移
python3 -c "from pwn import *; print(cyclic(200))"
python3 -c "from pwn import *; print(cyclic_find(0x61616168))"

# 识别 libc
./libc-database/find puts <leaked_addr_last_3_nibbles>
```

## 源码危险信号

- 多线程/`pthread` -> 竞态条件
- `usleep()`/`sleep()` -> 时间窗口
- 多线程共享全局变量 -> TOCTOU

## 竞态条件利用

```bash
bash -c '{ echo "cmd1"; echo "cmd2"; sleep 1; } | nc host port'
```

## 常见漏洞

- 缓冲区溢出：`gets()`、`scanf("%s")`、`strcpy()`
- 格式化字符串：`printf(user_input)`
- 整数溢出、UAF、竞态条件

## 保护机制对利用策略的影响

| 保护 | 状态 | 影响 |
|-----------|--------|-------------|
| PIE | 关闭 | 所有地址（GOT、PLT、函数）固定——可直接覆盖 |
| RELRO | Partial | GOT 可写——可以做 GOT 覆盖攻击 |
| RELRO | Full | GOT 只读——需要换目标（hooks、vtable、返回地址） |
| NX | 开启 | 栈/堆上不能执行 shellcode——用 ROP 或 ret2win |
| Canary | 存在 | 栈破坏会被检测——需要泄露，或避开栈溢出（改用堆） |

**快速决策树：**
- Partial RELRO + 无 PIE -> GOT 覆盖（最简单，地址固定）
- Full RELRO -> 目标改为 `__free_hook`、`__malloc_hook`（glibc < 2.34）或返回地址
- 存在栈 canary -> 优先堆攻击，或先泄露 canary

## 栈缓冲区溢出

1. 找偏移：`cyclic 200` 然后 `cyclic -l <value>`
2. 检查保护：`checksec --file=binary`
3. 无 PIE + 无 canary = 直接 ROP
4. 通过格式化字符串或部分覆盖泄露 canary
5. 在 fork 服务上逐字节爆破 canary（最多 7*256 次尝试）

**带 magic value 的 ret2win：** 溢出 -> `ret`（对齐）-> `pop rdi; ret` -> magic -> win()。**栈对齐：** `movaps` 处 SIGSEGV = 多加一个 `ret` gadget。**偏移：** 缓冲区在 `rbp - N`，返回地址在 `rbp + 8`，总偏移 = N + 8。**输入过滤：** 确保 payload 不包含 `memmem()` 禁止的字符串。**Gadget：** `ROPgadget --binary binary | grep "pop rdi"`，或用 pwntools `ROP()` 找 CMP 立即数中的隐藏 gadget。完整利用代码见 [overflow-basics.md](overflow-basics.md)。

## 解析器栈溢出（未检查的 memcpy）

**模式：** 自定义文件解析器（PCAP、图片、压缩包）分配固定栈缓冲区，但输入记录可能超出。`memcpy` 在长度校验之前拷贝，覆盖保存的寄存器和返回地址。需要恢复 callee-saved 寄存器：`rbx` 指向可读内存（BSS）、循环计数器设为退出值，然后 `ret` gadget + win 函数。见 [overflow-basics.md](overflow-basics.md#未校验-memcpy-长度导致解析器栈溢出metactf-flash-2026)。

## 结构体指针覆盖（堆菜单类挑战）

**模式：** 菜单对带数据缓冲区和指针的结构体做创建/修改/删除。把名字溢出到指针字段并写入 GOT 地址，再通过修改功能写入 win 地址。完整利用和 GOT 目标选择表见 [overflow-basics.md](overflow-basics.md)。

## 有符号整数绕过

**模式：** `scanf("%d")` 不检查符号；负数数量 * 单价 = 负总价，绕过余额检查。见 [overflow-basics.md](overflow-basics.md)。

## 感知 Canary 的部分溢出

**模式：** 溢出缓冲区与 canary 之间的 `valid` 标志。用 `./` 作为无操作路径填充来精确控制长度。完整利用链见 [overflow-basics.md](overflow-basics.md) 和 [advanced.md](advanced.md)。

## 全局缓冲区溢出（CSV 注入）

**模式：** 相邻的全局变量；通过额外的 CSV 分隔符溢出并改变文件名字符串指针。完整利用见 [overflow-basics.md](overflow-basics.md) 和 [advanced.md](advanced.md)。

## 构造 ROP 链

通过 `puts@PLT(puts@GOT)` 泄露 libc，返回 vuln，第二阶段执行 `system("/bin/sh")`。完整两阶段 ret2libc 模式、泄露解析和返回目标选择见 [rop-and-shellcode.md](rop-and-shellcode.md)。

**DynELF 自动识别 libc：** `pwntools.DynELF(leak_func, pointer_in_libc)` 可以在不知道 libc 版本的情况下远程解析 libc 符号。见 [rop-and-shellcode.md](rop-and-shellcode.md#dynelf-自动探测-libcrc3-ctf-2016)。

**小缓冲区中的受限 shellcode：** 缓冲区太小时，用 `read()` shellcode stub（< 20 字节）拉取完整的第二阶段 shellcode。见 [rop-and-shellcode.md](rop-and-shellcode.md#小缓冲区中的受限-shellcodetum-ctf-2016)。

**纯系统调用 ROP：** 当 `system()`/`execve()` 崩溃（CET/IBT）时，用 libc 中的 `pop rax; ret` + `syscall; ret`。见 [rop-and-shellcode.md](rop-and-shellcode.md)。

**ret2csu：** `__libc_csu_init` 中的 gadget 可以控制 `rdx`、`rsi`、`edi` 并调用任意 GOT 函数——不依赖 libc gadget 的通用三参数调用。见 [rop-and-shellcode.md](rop-and-shellcode.md#ret2csu--__libc_csu_init-gadgetcrypto-cat)。

**坏字符 XOR 绕过：** 写入 `.data` 前先用密钥 XOR payload 数据，再用 ROP gadget 原地 XOR 回来。可避开空字节、换行等被过滤字符。见 [rop-and-shellcode.md](rop-and-shellcode.md#rop-中用-xor-编码绕过坏字符crypto-cat)。

**冷门 gadget（BEXTR/XLAT/STOSB/PEXT）：** 没有标准 `mov` 写 gadget 时，串联冷门 x86 指令实现逐字节内存写。见 [rop-and-shellcode.md](rop-and-shellcode.md#冷门-x86-gadget--bextrxlatstosbpextcrypto-cat)。

**栈迁移（xchg rax,esp）：** 溢出不够放完整 ROP 链时，把栈指针换到攻击者控制的堆/缓冲区。需要先用 `pop rax; ret` 载入迁移地址。见 [rop-and-shellcode.md](rop-and-shellcode.md#通过-xchg-raxesp-做栈迁移crypto-cat)。

**rdx 控制：** `puts()` 之后 rdx 会被破坏成 1。用 libc 的 `pop rdx; pop rbx; ret`，或重新进入二进制的 read 设置 + 栈迁移。见 [rop-and-shellcode.md](rop-and-shellcode.md)。

**Canary XOR 尾声作为 rdx 清零 gadget：** 没有 `pop rdx; ret` 时，跳进 canary 检查尾声 `xor rdx, fs:28h`——canary 完好时它会把 RDX 清零。见 [rop-and-shellcode.md](rop-and-shellcode.md#栈-canary-xor-收尾作为-rdx-清零-gadgetvolgactf-2017)。

**stub_execveat 替代 execve：** 没有 `pop rax; ret` 时，用 `stub_execveat`（系统调用 322/0x142）代替 `execve`——正好发送 0x142 字节，让 `read()` 的返回值设置 rax。见 [rop-and-shellcode.md](rop-and-shellcode.md#用-stub_execveat-系统调用替代-execveasis-ctf-2018)。

**Shell 交互：** `execve` 之后 `sleep(1)`，然后 `sendline(b'cat /flag*')`。见 [rop-and-shellcode.md](rop-and-shellcode.md)。

## 经过输入变换的格式化字符串

**ROT13 编码的格式化字符串：** 输入在到达 `printf` 前被 ROT13/Caesar 变换时，先用逆变换预编码格式化字符串 payload，使其到达时保持完整。见 [format-string.md](format-string.md#通过-rot13-编码的格式化字符串利用sunshinectf-2018)。

## 内核利用

**通过文件打开失败绕过 addr_limit：** 内核模块把 `addr_limit = KERNEL_DS` 但在错误路径上没恢复时，强制触发错误（例如把目标文件变成目录），让用户态 `read()`/`write()` 保留内核内存访问能力。见 [kernel-techniques.md](kernel-techniques.md#通过文件打开失败绕过内核-addr_limitmidnight-sun-ctf-2018)。

## 沙箱与模拟器逃逸

**CPU 模拟器 eval 注入：** 模拟器的 print 操作码用 `eval('"' + buf + '"')` 处理转义序列时，通过 ADD 操作码在模拟器内存中构造 `"+__import__("os").system("cmd")#`，闭合字符串并执行 Python。见 [sandbox-escape.md](sandbox-escape.md#cpu-模拟器-print-指令的-python-eval-注入midnight-sun-ctf-2018)。

## 进阶利用原语

**神经网络函数指针越界：** 二进制把神经网络输出当作函数指针数组索引且没有边界检查时，重新训练权重/偏置，产生越界索引，从偏置数组中读出目标地址。见 [advanced-exploits-4.md](advanced-exploits-4.md#神经网络输出作为函数指针下标越界swampctf-2018)。

**计数器溢出绕过 shellcode 唯一字节数限制：** shellcode 被限制为 N 个唯一字节时，喷洒栈破坏 `seen[256]` 计数器，然后重新执行 main（跳过 `memset`），让溢出的计数器在第二轮允许任意字节。见 [advanced-exploits-4.md](advanced-exploits-4.md#通过计数器溢出绕过-shellcode-唯一字节数限制blaze-ctf-2018)。

## 深入笔记

确认挑战确实以利用为主后，再使用 [field-notes.md](field-notes.md)。

- 堆与分配器笔记：House of Apple、tcache、unsafe unlink、talloc、UAF、FSOP
- 进阶利用笔记：seccomp 绕过、ret2vdso、io_uring、整数截断、ASAN、时间 oracle
- 沙箱与混合笔记：pyjail 交叉、busybox 逃逸、自定义 VM、shell 技巧、路径清洗器
- 内核与 Windows 笔记：内核 playbook、SEH、CFG 绕过、提权
- 历史案例笔记：较老但仍可复用的 CTF 利用模式
