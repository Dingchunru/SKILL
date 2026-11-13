# ctf-pwn 文档索引

> 本文件由 `scripts/build_skill_catalog.py` 生成，请勿手工编辑。
>
> 用法：按「用途」定位候选文件，只加载命中的那一篇；同名 `catalog.json`
> 提供相同信息的机器可读版本（含路径、摘要、标签、章节、字节数）。

## 技术参考

| 文档 | 用途 | 关键章节 |
|---|---|---|
| [advanced-exploits-2.md](advanced-exploits-2.md) | 进阶利用技术（第 2 部分）：自修改绕过字节码校验器、io_uring UAF 注入 SQE、int32→int16 整数截断、GC 空引用级联破坏、多次 fgets 覆盖 stdout FILE 实现无泄露 libc、有符号/无符号 char 下溢堆溢出、XOR 密钥流爆破写原语、tcache 指针解密堆泄露、伪造 chunk size 提升 unsorted bin、FSOP stdout TLS 泄露、通过 __call_tls_dtors 劫持 TLS… | 通过自修改绕过字节码校验器（srdnlenCTF 2026）、io_uring UAF 与 SQE 注入（ApoorvCTF 2026）、整数截断绕过 int32 到 int16（ApoorvCTF 2026）、GC 空引用级联破坏（DiceCTF 2026）、多次 fgets 覆写 stdout FILE 实现无泄漏 libc（Midnightflag 2026） |
| [advanced-exploits-3.md](advanced-exploits-3.md) | 进阶利用技术（第 3 部分）：栈变量重叠/进位破坏越界、8 位循环计数器造成 1 字节溢出、游戏 AI 算术平均越界读、任意读写 GOT 覆盖 getshell、__environ + memcpy 溢出泄露栈、uint16 跳转截断造成 JIT 沙箱逃逸、DNS 压缩指针多问题栈溢出 + ROP、篡改程序头绕过 ELF 代码签名、游戏关卡格式有符号/无符号坐标不一致、缺失 O_CLOEXEC 导致文件描述符继承、元数据解析中的符号扩展整数下溢、只读原语构造 ROP… | 栈变量重叠 / 进位破坏造成越界（srdnlenCTF 2026）、8 位循环计数器造成 1 字节溢出（srdnlenCTF 2026）、游戏 AI 算术平均造成越界读（BSidesSF 2024）、通过 GOT 覆盖实现任意读/写到 shell（BSidesSF 2026）、通过 __environ 与 memcpy 溢出泄漏栈（BSidesSF 2026） |
| [advanced-exploits-4.md](advanced-exploits-4.md) | 进阶利用技术（第 4 部分）：Windows SEH 覆盖 + pushad VirtualAlloc ROP、IAT 相对解析、分离进程的 shell 稳定性、SeDebugPrivilege 提权到 SYSTEM、ARM 缓冲区溢出配 Thumb shellcode、Forth 解释器 system 字利用、GF(2) 高斯消元做多轮 tcache 投毒、单比特翻转利用原语（mprotect + 迭代改代码）、用静物演化生成 Game of Life… | Windows SEH 覆盖 + pushad VirtualAlloc ROP（RainbowTwo HTB）、SeDebugPrivilege 提权到 SYSTEM（RainbowTwo HTB）、ARM 缓冲区溢出与 Thumb shellcode（HackIM 2016）、Forth 解释器命令执行（32C3 2015）、GF(2) 高斯消元实现多轮 tcache 投毒（Midnight Flag 2026） |
| [advanced-exploits-5.md](advanced-exploits-5.md) | 进阶利用技术（第 5 部分）：数据解释类利用——Chip-8 模拟器越界内存打 ret2libc、双精度浮点快排重排 canary、布隆过滤器 abs(INT_MIN) 负索引越界写 | Chip-8 模拟器越界内存实现 ret2libc（IceCTF 2018）、双精度浮点快速排序重排 Canary（CSAW 2018）、布隆过滤器 abs(INT_MIN) 负下标越界写（DragonCTF Teaser 2018） |
| [advanced-exploits.md](advanced-exploits.md) | 进阶利用技术（第 1 部分）：VM 有符号比较、BF JIT shellcode、类型混淆、off-by-one 索引破坏、DNS 溢出、ASAN shadow memory、带编码约束的格式化字符串、自定义 canary 保留、有符号整数绕过、感知 canary 的部分溢出、CSV 注入、MD5 原像 gadget、VM GC UAF slab 复用、路径穿越清洗绕过、FSOP + 通过 openat/mmap/write 绕过 seccomp | VM 有符号比较 Bug（0xFun 2026）、BF JIT 括号不配对导致 RWX Shellcode（VuwCTF 2025）、解释器中的类型混淆（VuwCTF 2025）、Off-by-One 索引破坏 size 字段（VuwCTF 2025）、双次调用 win() 模式（VuwCTF 2025） |
| [advanced.md](advanced.md) | seccomp 进阶技术、UAF、JIT、冷门 GOT、进制转换造成堆重叠、树结构栈分配不足、ret2dlresolve、内核利用（基础） | Seccomp 进阶技巧、ROP 链中的 rdx 控制、释放后使用（UAF）利用、JIT 编译利用、小众语言解释器的 GOT 覆写 |
| [attack-playbook.md](attack-playbook.md) | Linux 用户态攻击 playbook：输入/权限边界侦察、按缓解措施选择泄露方式、原语排序工作流 | 侦察、泄漏选择、控制流与写目标、路由到具体技术、Payload 检查清单 |
| [field-notes.md](field-notes.md) | 详细 pwn 笔记：堆利用速查、额外利用笔记、常用命令 | 堆利用、其他利用笔记、常用命令 |
| [format-string.md](format-string.md) | 格式化字符串利用（泄露、GOT 覆盖、盲打、过滤绕过、canary 泄露、__free_hook、.rela.plt 修补、覆盖保存的 EBP 做 .bss 迁移、覆盖 argv[0] 泄露栈信息、.fini_array 循环做多阶段利用、连续 %p 绕过 __printf_chk、单次调用泄露 + GOT 覆盖、输入变换后的 ROT13 格式化字符串利用） | 格式化字符串基础、参数重定向（非位置化 %n 技巧）、盲打 Pwn（未提供二进制）、带过滤绕过的格式化字符串、格式化字符串泄漏 canary + PIE |
| [heap-fsop.md](heap-fsop.md) | FILE 结构体（_IO_FILE）利用：fastbin stdout vtable 两阶段劫持绕过 PIE + Full RELRO、_IO_buf_base 空字节劫持 stdin、glibc 2.24+ _IO_FILE vtable 校验绕过、对 stdin _IO_buf_end 的 unsorted bin 攻击、通过 mp_ 结构破坏 unsorted bin、realloc(ptr, 0) 当作 free() 的 UAF、单字节引用计数回绕 UAF | Fastbin stdout Vtable 两阶段劫持（PIE + Full RELRO，ASIS CTF 2017）、_IO_buf_base 空字节覆盖劫持 stdin（Tokyo Westerns 2017）、glibc 2.24+ _IO_FILE Vtable 校验绕过（HITCON 2017）、针对 stdin _IO_buf_end 的 Unsorted Bin 攻击（HITCON 2017）、通过 mp_ 结构破坏 Unsorted Bin（HITCON 2017） |
| [heap-techniques-2.md](heap-techniques-2.md) | CTF writeup 中的堆变体：UAF vtable 指针编码 shell 参数、未初始化 chunk 残留指针泄露、tcache strcpy 空字节溢出 + 向后合并、相邻结构体函数指针溢出实现 libc 泄露 + GOT 覆盖、隐藏菜单 tcache 投毒、tcache double-free + 伪造 _IO_FILE vtable 劫持 stdout、tcache 提升为 fastbin 的跨 bin 攻击、6 位索引越界 + written_bytes… | UAF 中 vtable 指针编码为 shell 参数（BCTF 2017）、未初始化 chunk 残留指针泄漏（picoCTF 2018）、tcache strcpy 空字节溢出 + 向后合并（HITCON 2018）、相邻结构体函数指针溢出实现 libc 泄漏 + GOT 覆盖（RITSEC 2018）、隐藏菜单项 1337 实现 tcache 投毒（FireShell 2019） |
| [heap-techniques.md](heap-techniques.md) | House of Apple 2（含 setcontext SUID 变体）、House of Einherjar、House of Orange/Spirit/Lore/Force、堆布局 groom、自定义分配器（nginx、talloc）、经典 unlink、musl libc 堆（meta 指针 + atexit 劫持）、tcache stashing unlink 攻击、unsafe unlink + top chunk 合并 | House of Apple 2 — 针对 glibc 2.34+ 的 FSOP（0xFun 2026）、House of Einherjar — Off-by-One 空字节（0xFun 2026）、堆利用、自定义分配器利用、经典堆 Unlink 攻击（Crypto-Cat） |
| [kernel-bypass.md](kernel-bypass.md) | 内核保护绕过：KASLR/FGKASLR 绕过（__ksymtab）、KPTI 绕过（swapgs trampoline、信号处理器、通过 ROP 改 modprobe_path/core_pattern）、SMEP/SMAP 绕过、GDB 调试内核模块、initramfs/virtio-9p 工作流、利用模板、利用投递 | KASLR 与 FGKASLR 绕过、KPTI 绕过方法、CET 影子栈（SHSTK）与 IBT —— 信号帧绕过（Wolv / IERAE 2024）、SMEP / SMAP 绕过、KPTI / SMEP / SMAP 速查 |
| [kernel-techniques.md](kernel-techniques.md) | 内核利用技术：tty_struct kROP（伪造 vtable + 栈迁移）、通过 ioctl 寄存器控制实现任意地址写、userfaultfd 竞态稳定化、SLUB 分配器内部（freelist 加固/混淆）、通过内核 panic 泄露、MADV_DONTNEED 扩大竞态窗口（DiceCTF 2026）、跨 cache CPU 拆分攻击（DiceCTF 2026）、PTE 重叠文件写（DiceCTF 2026）、利用文件打开失败绕过 addr_limit 读写内核内存 | tty_struct RIP 劫持与 kROP、userfaultfd 稳定竞态、SLUB 分配器内部机制、通过内核 panic 泄漏、用 MADV_DONTNEED + mprotect 扩大竞态窗口（DiceCTF 2026） |
| [kernel.md](kernel.md) | Linux 内核利用基础：环境搭建、QEMU 调试、堆喷结构（tty_struct、poll_list、user_key_payload、seq_operations）、内核栈溢出、canary 泄露、提权（ret2usr、内核 ROP）、覆盖 modprobe_path、覆盖 core_pattern、kmalloc 大小不匹配堆溢出 + struct file f_op 破坏 | 环境搭建与信息收集、堆喷常用的内核结构体、内核栈溢出与 canary 泄漏、提权原语、modprobe_path 覆写 |
| [overflow-basics.md](overflow-basics.md) | 栈/全局缓冲区溢出、ret2win、canary 绕过、fork 服务上的 canary 逐字节爆破、结构体指针覆盖、有符号整数绕过、隐藏 gadget、基于 stride 的越界读泄露、未检查 memcpy 长度导致的解析器栈溢出（含 callee-saved 寄存器恢复） | 栈缓冲区溢出、结构体指针覆写（堆菜单题）、有符号整数绕过（负数量）、绕过 canary 的部分溢出、通过步长/速率泄漏的越界读（DiceCTF 2026） |
| [rop-advanced.md](rop-advanced.md) | 进阶 ROP 技术：通过 leave;ret 双重栈迁移到 BSS、带 UTF-8 约束的 SROP（Sigreturn-Oriented Programming）、seccomp 绕过、RETF 架构切换（x64→x32）绕过 seccomp、输入反转的 shellcode、.fini_array 劫持、ret2vdso、pwntools 模板、x32 ABI 系统调用别名绕过 seccomp、基于时间的盲 shellcode 外带 | 通过 leave;ret 双重栈迁移到 BSS（Midnightflag 2026）、受 UTF-8 载荷约束的 SROP（DiceCTF 2026）、seccomp 绕过、用 RETF 切换架构绕过 seccomp（Midnightflag 2026）、带输入反转的栈上 shellcode |
| [rop-and-shellcode.md](rop-and-shellcode.md) | 核心 ROP 链（ret2libc、syscall ROP、rdx 控制、shell 交互）、ret2csu、坏字符 XOR 绕过、冷门 x86 gadget（BEXTR/XLAT/STOSB/PEXT）、通过 xchg rax,esp 栈迁移、sprintf() gadget 链绕过坏字符、canary XOR 尾声作为 RDX 清零 gadget、以 stub_execveat 系统调用和 read() 返回值替代 execve | 构造 ROP 链、ret2csu — __libc_csu_init gadget（Crypto-Cat）、ROP 中用 XOR 编码绕过坏字符（Crypto-Cat）、冷门 x86 gadget — BEXTR/XLAT/STOSB/PEXT（Crypto-Cat）、通过 xchg rax,esp 做栈迁移（Crypto-Cat） |
| [sandbox-escape.md](sandbox-escape.md) | 自定义 VM 利用、FUSE/CUSE 设备、busybox/受限 shell、shell 技巧、process_vm_readv 沙箱绕过、命名管道文件大小绕过、CPU 模拟器 print 操作码的 Python eval 注入 | Python 沙箱逃逸、VM 利用（自定义字节码）、FUSE/CUSE 字符设备利用、Busybox / 受限 shell 提权、Shell 技巧 |
| [static-signals.md](static-signals.md) | 与利用相关的静态信号（libc 版本、seccomp 策略、RELRO/PIE/canary/NX 证据），用于评估可利用性 |  |
| [tools-mcp.md](tools-mcp.md) | pwn 方向的 MCP 服务集成：WinDbg MCP 会话模型（open_cdb_dump/open_cdb_remote/open_kd_session + session_id）、崩溃转储初筛、在转储中扫描 flag{ 内存、实时断点/硬件观察点/内存补丁利用、!dh -f 检查 Windows 缓解措施（相当于 checksec）、用 kd 在内核态窃取 token；IDA/Ghidra MCP 用于漏洞利用开发（先反编译漏洞函数，只在需要精确 gadget… | WinDbg MCP（Windows 崩溃转储、实时与内核调试）、用 IDA / Ghidra MCP 开发利用 |

## 辅助工具

| 脚本 | 用途 |
|---|---|
| `scripts/fmtstr_payload_suite.py` | Format-string payload suite: leak, GOT overwrite, short writes. |
| `scripts/ret2libc_two_stage.py` | Two-stage ret2libc: leak libc via puts, then ret2system /bin/sh. |
| `scripts/seccomp_orw_generator.py` | Seccomp ORW (open/read/write) shellcode generator. |
| `scripts/shellcraft_asm.py` | Shellcraft assembly generation: amd64 linux shellcode via pwntools. |
| `scripts/srop_execve.py` | SROP execve: sigreturn-oriented programming to execve('/bin/sh'). |

## 题库

- [pwnable-tw 题目索引](pwnable-tw/README.md) — 43 道题，按分数、保护机制和标签路由。
