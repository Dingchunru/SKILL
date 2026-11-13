# Pwn 实战笔记

支撑 [`SKILL.md`](SKILL.md) 的详细 pwn 笔记。在确认题目确实需要利用之后再读这个文件。

## 目录

- [堆利用](#堆利用)
- [其他利用笔记](#其他利用笔记)
  - [talloc 池头伪造](#talloc-池头伪造)
  - [JIT 编译利用](#jit-编译利用)
  - [解释器中的类型混淆](#解释器中的类型混淆)
  - [Off-by-One 下标 / 大小破坏](#off-by-one-下标--大小破坏)
  - [两次 win() 调用](#两次-win-调用)
  - [通过 GOT 覆写实现任意读写到 shell](#通过-got-覆写实现任意读写到-shell)
  - [通过 __environ 与 memcpy 溢出泄漏栈](#通过-__environ-与-memcpy-溢出泄漏栈)
  - [uint16 跳转截断导致的 JIT 沙箱逃逸](#uint16-跳转截断导致的-jit-沙箱逃逸)
  - [DNS 压缩指针栈溢出](#dns-压缩指针栈溢出)
  - [通过程序头绕过 ELF 代码签名](#通过程序头绕过-elf-代码签名)
  - [游戏关卡格式的符号/无符号坐标不一致](#游戏关卡格式的符号无符号坐标不一致)
  - [缺少 O_CLOEXEC 导致文件描述符继承](#缺少-o_cloexec-导致文件描述符继承)
  - [元数据解析中的符号扩展整数下溢](#元数据解析中的符号扩展整数下溢)
  - [仅有只读原语时构造 ROP 链](#仅有只读原语时构造-rop-链)
  - [小众语言解释器的 GOT 覆写](#小众语言解释器的-got-覆写)
  - [协议栈泄漏](#协议栈泄漏)
  - [计时攻击恢复 flag](#计时攻击恢复-flag)
  - [DNS 记录缓冲区溢出](#dns-记录缓冲区溢出)
  - [ASAN 影子内存利用](#asan-影子内存利用)
  - [格式化字符串 .fini_array 循环做多阶段利用](#格式化字符串-fini_array-循环做多阶段利用)
  - [RWX .fini_array 劫持配合格式化字符串](#rwx-fini_array-劫持配合格式化字符串)
  - [保留自定义 canary](#保留自定义-canary)
  - [MD5 原像 gadget 构造](#md5-原像-gadget-构造)
  - [Python 沙箱逃逸](#python-沙箱逃逸)
  - [VM GC 触发的 UAF（slab 复用）](#vm-gc-触发的-uafslab-复用)
  - [GC 空引用级联破坏](#gc-空引用级联破坏)
  - [通过步长/速率泄漏做越界读](#通过步长速率泄漏做越界读)
  - [带 UTF-8 约束的 SROP](#带-utf-8-约束的-srop)
  - [VM 利用（自定义字节码）](#vm-利用自定义字节码)
  - [FUSE/CUSE 字符设备利用](#fusecuse-字符设备利用)
  - [Busybox/受限 shell 提升](#busybox受限-shell-提升)
  - [process_vm_readv 沙箱绕过](#process_vm_readv-沙箱绕过)
  - [命名管道（mkfifo）绕过文件大小检查](#命名管道mkfifo绕过文件大小检查)
  - [Shell 技巧](#shell-技巧)
  - [通过 leave;ret 二次栈迁移到 BSS](#通过-leaveret-二次栈迁移到-bss)
  - [用 RETF 切换架构绕过 seccomp](#用-retf-切换架构绕过-seccomp)
  - [通过多次 fgets 覆写 stdout FILE 实现无泄漏 libc](#通过多次-fgets-覆写-stdout-file-实现无泄漏-libc)
  - [有符号/无符号 char 下溢导致堆溢出](#有符号无符号-char-下溢导致堆溢出)
  - [通过 `__call_tls_dtors` 劫持 TLS 析构函数](#通过-__call_tls_dtors-劫持-tls-析构函数)
  - [有符号 int 溢出导致负向越界堆写](#有符号-int-溢出导致负向越界堆写)
  - [通过指针溢出绕过自定义影子栈](#通过指针溢出绕过自定义影子栈)
  - [Windows SEH 覆写 + VirtualAlloc ROP](#windows-seh-覆写--virtualalloc-rop)
  - [SeDebugPrivilege 提权到 SYSTEM](#sedebugprivilege-提权到-system)
  - [mmap/munmap 大小不匹配 UAF](#mmapmunmap-大小不匹配-uaf)
  - [strcspn 间接注入空字节](#strcspn-间接注入空字节)
  - [用 system() 作为合法调用目标绕过 Windows CFG](#用-system-作为合法调用目标绕过-windows-cfg)
  - [4 字节 shellcode 配计时侧信道](#4-字节-shellcode-配计时侧信道)
  - [把 CRC oracle 当作任意读原语](#把-crc-oracle-当作任意读原语)
  - [UTF-8 大小写转换缓冲区溢出](#utf-8-大小写转换缓冲区溢出)
- [常用命令](#常用命令)

<a id="heap-exploitation"></a>
## 堆利用

- tcache poisoning（glibc 2.26+）、fastbin dup / double free
- House of Force（旧版 glibc）、unsorted bin attack
- **House of Apple 2**（glibc 2.34+）：`__free_hook`/`__malloc_hook` 被移除后，通过 `_IO_wfile_jumps` 做 FSOP（File Stream Oriented Programming）。伪造 FILE，`_flags = " sh"`，vtable 链 → `system(fp)`。对 SUID 二进制：用 `setcontext()` 变体做栈迁移 → `setuid(0)` → `system()`（uid != euid 时 dash 会丢权限）。见 [heap-techniques.md](heap-techniques.md#suid-程序的-setcontext-变体midnight-flag-2026)。
- **经典 unlink**：破坏相邻 chunk 元数据，触发向后合并得到 write-what-where 原语。仅限 2.26 之前的 glibc。见 [heap-techniques.md](heap-techniques.md#经典堆-unlink-攻击crypto-cat)。
- **House of Force：** 把 top chunk 大小改成 `0xffffffffffffffff`，下一次 `malloc(target - top - 2*SIZE_SZ)` 就返回任意地址。仅限 2.29 之前的 glibc。见 [heap-techniques.md](heap-techniques.md#house-of-forcecsaw-ctf-2016)。
- **House of Einherjar**：off-by-one 空字节清掉 PREV_INUSE，配合自指 unlink 做向后合并。
- **Safe-linking**（glibc 2.32+）：tcache 的 fd 被混淆为 `ptr ^ (chunk_addr >> 12)`。
- 查 glibc 版本：`strings libc.so.6 | grep GLIBC`
- 被释放的 chunk 里含 libc 指针（fd/bk）→ 通过错误信息或缺失的空终止符泄漏
- 堆风水：控制分配顺序/大小、制造空洞、把目标摆在溢出源旁边
- **Unsafe unlink + top chunk 合并**：unlink 把自指写进 BSS 后，在 BSS 伪造一个延伸到 top chunk 的假 chunk。`free()` 触发合并，堆基址被搬到 BSS。后续 malloc 返回 BSS 内存。见 [heap-techniques.md](heap-techniques.md#unsafe-unlink-到-bss--top-chunk-合并seccon-2016)。

**House of Orange：** 破坏 top chunk 大小 → 大尺寸 malloc 迫使走 sysmalloc → 旧 top 在没有调用 `free()` 的情况下被释放。与 FSOP 串联。见 [heap-techniques.md](heap-techniques.md#house-of-orange)。

**House of Spirit：** 在目标区域伪造假 chunk，`free()` 它，再重新分配以获得写权限。需要合法的大小 + 下一 chunk 大小。见 [heap-techniques.md](heap-techniques.md#house-of-spirit)。

**House of Lore：** 破坏 smallbin 的 `bk` → 链接假 chunk → 第二次 malloc 返回攻击者可控地址。见 [heap-techniques.md](heap-techniques.md#house-of-lore)。

**ret2dlresolve：** 伪造 Elf64_Sym/Rela，无需泄漏就解析任意 libc 函数。`Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])`。需要部分 RELRO。见 [advanced.md](advanced.md#ret2dlresolve)。

**tcache stashing unlink（glibc 2.29+）：** 在 tcache 装载期间破坏 smallbin chunk 的 `bk` → 把任意地址链进 tcache → 得到写原语。见 [heap-techniques.md](heap-techniques.md#tcache-stashing-unlink-攻击)。

**UAF vtable 指针编码出 shell 参数：** UAF 之后，堆喷射把 `system()` 放到偏移 +3 处。当通过被劫持的 vtable 调用 `system(this)` 时，低字节包含 `0x6873`（"sh"）的对象地址同时充当命令字符串参数。见 [heap-techniques-2.md](heap-techniques-2.md#uaf-中-vtable-指针编码为-shell-参数bctf-2017)。

**Fastbin stdout vtable 两阶段劫持（PIE + Full RELRO）：** 用 libc 中 stdout 区域的 0x7f 字节作为假的 fastbin chunk 大小。两阶段：先把 vtable 重定向到 `gets()`（rdi=stdout），再让 `gets()` 把 vtable 改成 `system()` 并写入命令字符串。见 [heap-techniques.md](heap-fsop.md#fastbin-stdout-vtable-两阶段劫持pie--full-relroasis-ctf-2017)。

House of Apple 2 FSOP 链（+ setcontext 的 SUID 变体）、House of Orange/Spirit/Lore/Force、tcache stashing unlink、自定义分配器利用（nginx pools、talloc）、经典 unlink、musl libc 堆，见 [heap-techniques.md](heap-techniques.md)。ret2dlresolve、通过进制转换做堆重叠、树形数据结构栈分配不足，见 [advanced.md](advanced.md)。

**GF(2) 高斯消元做 tcache poisoning：** 当确定性异或密码作为副作用破坏堆元数据时，把破坏建模为 GF(2) 上的线性代数。找出一组密钥种子，它们的组合异或能把 tcache 的 `fd` 从当前值变成目标地址。见 [advanced-exploits-4.md](advanced-exploits-4.md#gf2-高斯消元实现多轮-tcache-投毒midnight-flag-2026)。

<a id="additional-exploit-notes"></a>
## 其他利用笔记

<a id="talloc-pool-header-forgery"></a>
### talloc 池头伪造
**模式：** talloc（Samba/CUPS 中的层次化分配器）池头伪造。伪造带可控 `end`/`object_count` 字段的假池头，把下一次 `talloc()` 重定向到任意地址。泄漏 GOT 得 libc，把 `__free_hook` 写成 `system()`。见 [heap-techniques.md](heap-techniques.md#talloc-池头部伪造实现任意读写boston-key-party-2016)。

<a id="jit-compilation-exploits"></a>
### JIT 编译利用
**模式：** 指令编码中的 off-by-one -> 机器码错位。把 shellcode 作为减法操作数的字节嵌入，用 2 字节 `jmp` 指令把它们串起来。见 [advanced.md](advanced.md)。

**BF JIT 括号不平衡：** 不配对的 `]` 会从栈上弹出磁带地址（RWX）→ 用 `+`/`-` 往磁带写 shellcode，触发 `]` 跳过去执行。见 [advanced.md](advanced.md)。

<a id="type-confusion-in-interpreters"></a>
### 解释器中的类型混淆
**模式：** 解释器打错类型标签 → 结构体字段被重新解释。某个变体里未使用的填充字节，在另一个变体里变成活跃的指针/数据。把 flag 字节当作类型值会触发 UNKNOWN_DATA dump。见 [advanced.md](advanced.md)。

<a id="off-by-one-index--size-corruption"></a>
### Off-by-One 下标 / 大小破坏
**模式：** 数组下标 0 映射到 `entries[-1]`，与结构体元数据（大小字段）重叠。大小被改坏 → 越界读泄漏 canary/libc，再越界写放 ROP 链。见 [advanced.md](advanced.md)。

<a id="double-win-call"></a>
### 两次 win() 调用
**模式：** `win()` 里有 `if (attempts++ > 0)` —— 需要调用两次。叠两个返回地址：`p64(win) + p64(win)`。见 [advanced.md](advanced.md)。

<a id="arbitrary-readwrite-to-shell-via-got-overwrite"></a>
### 通过 GOT 覆写实现任意读写到 shell
**模式：** 二进制显式提供读/写原语。通过 GOT 读泄漏 libc，把 `strtoll@GOT` 覆写成 `system`，下一次调用就变成 `system(用户输入)`。选那些"第一个参数是用户可控字符串"的 GOT 目标。见 [advanced-exploits-3.md](advanced-exploits-3.md#通过-got-覆盖实现任意读写到-shellbsidessf-2026)。

<a id="stack-leak-via-__environ-and-memcpy-overflow"></a>
### 通过 __environ 与 memcpy 溢出泄漏栈
**模式：** 只有只读原语且带 `memcpy(stack_buf, user_addr, user_len)` 的二进制。通过 GOT 泄漏 libc，通过 `__environ` 泄漏栈，把 ROP 地址预先种在输入缓冲区，再溢出 memcpy 把它们拷到返回地址上，发 EOF 触发返回。见 [advanced-exploits-3.md](advanced-exploits-3.md#通过-__environ-与-memcpy-溢出泄漏栈bsidessf-2026)。

<a id="jit-sandbox-escape-via-uint16-jump-truncation"></a>
### uint16 跳转截断导致的 JIT 沙箱逃逸
**模式：** JIT 编译器把条件跳转偏移截断成 uint16，代码超过 64KB 时造成错位。把 2 字节的 shellcode 片段塞进 `add` 立即数里，用 `jmp $+3` 把它们串起来执行。见 [advanced-exploits-3.md](advanced-exploits-3.md#条件跳转-uint16-截断导致-jit-沙箱逃逸bsidessf-2026)。

<a id="dns-compression-pointer-stack-overflow"></a>
### DNS 压缩指针栈溢出
**模式：** 自实现 DNS 服务器不跟踪解压后的名字长度。压缩指针链反复访问同一段数据，把栈缓冲区撑爆。把 ROP 链拆到多个 DNS question 条目里。见 [advanced-exploits-3.md](advanced-exploits-3.md#dns-压缩指针栈溢出与多问题-ropbsidessf-2026)。

<a id="elf-code-signing-bypass-via-program-headers"></a>
### 通过程序头绕过 ELF 代码签名
**模式：** 签名方案只哈希节头和节内容，不哈希程序头。追加 shellcode，修改 LOAD 段的 `p_offset` 指向追加的数据 —— 签名照样有效，加载器却执行了攻击者代码。见 [advanced-exploits-3.md](advanced-exploits-3.md#通过程序头篡改绕过-elf-代码签名bsidessf-2026)。

<a id="game-level-format-signedunsigned-coordinate-mismatch"></a>
### 游戏关卡格式的符号/无符号坐标不一致
**模式：** 关卡编辑器按有符号整数解析坐标，却用无符号比较做边界检查 —— 负坐标通过检查，并把方块 ID（任意字节）写到关卡数组之前，从而可以覆写栈上的返回地址。通过隐藏的开发者模式泄漏栈地址，把 shellcode 编码成方块 ID。见 [advanced-exploits-3.md](advanced-exploits-3.md#游戏关卡格式的有符号无符号坐标不匹配bsidessf-2026)。

<a id="file-descriptor-inheritance-via-missing-o_cloexec"></a>
### 缺少 O_CLOEXEC 导致文件描述符继承
**模式：** 服务把秘密读进 `memfd_create()` 得到的 FD，但没带 `MFD_CLOEXEC`，随后为用户命令调用 `system()` —— 子进程继承了这个 FD。用 shell 引号拆分（`p'r'oc` 而不是 `proc`）绕过 `strstr()` 关键字过滤，读取 `/proc/self/fd/N`。见 [advanced-exploits-3.md](advanced-exploits-3.md#缺少-o_cloexec-导致文件描述符被继承bsidessf-2026)。

<a id="sign-extension-integer-underflow-in-metadata-parsing"></a>
### 元数据解析中的符号扩展整数下溢
**模式：** 元数据解析器的 `to_int32` 会把 >= 0x80000000 的无符号值转成负的有符号整数。用它当数组下标/偏移就会越界访问内存。逐字节迭代从内存里泄漏 flag。见 [advanced-exploits-3.md](advanced-exploits-3.md#元数据解析中的符号扩展整数下溢bsidessf-2026)。

<a id="rop-chain-construction-with-read-only-primitive"></a>
### 仅有只读原语时构造 ROP 链
**模式：** 二进制只有 `read()` 原语 —— 没有写，也没有 win 函数。通过 GOT 泄漏 libc，然后从 libc 里内容恰好等于所需 ROP gadget 地址的偏移处读取，"导入"任意字节值到栈上。读原语同时充当写原语。见 [advanced-exploits-3.md](advanced-exploits-3.md#仅用只读原语构造-rop-链bsidessf-2026)。

<a id="esoteric-language-got-overwrite"></a>
### 小众语言解释器的 GOT 覆写
**模式：** Brainfuck/Pikalang 解释器磁带无界 = 相对于缓冲区基址的任意读写。把指针移到 GOT，逐个字节覆写成 `system()`。见 [advanced.md](advanced.md)。

<a id="protocol-stack-bleeding"></a>
### 协议栈泄漏
自定义网络协议按长度字段回显数据，当长度超过实际数据时就会泄漏栈内存（Heartbleed 式）。见 [overflow-basics.md](overflow-basics.md#协议长度字段栈泄漏ekoparty-ctf-2016)。

<a id="timing-attack-flag-recovery"></a>
### 计时攻击恢复 flag
校验耗时随正确字符变化；逐字节测量候选项的耗时，就能一个字符一个字符地恢复 flag。见 [advanced-exploits.md](advanced-exploits.md#逐字符恢复-flag-的时序攻击rc3-ctf-2016)。

<a id="dns-record-buffer-overflow"></a>
### DNS 记录缓冲区溢出
**模式：** 大量 AAAA 记录会把 DNS 响应解析器的栈缓冲区撑爆。搭一个返回过量记录的 DNS 服务器，覆写返回地址。见 [advanced.md](advanced.md)。

<a id="asan-shadow-memory-exploitation"></a>
### ASAN 影子内存利用
**模式：** 二进制带 AddressSanitizer，同时有格式化字符串 + 越界写。ASAN 可能使用"假栈"（50% 概率）。泄漏 PIE、判断真栈还是假栈、算出越界写偏移来覆写返回地址。见 [advanced.md](advanced.md)。

<a id="format-string-fini_array-loop-for-multi-stage-exploitation"></a>
### 格式化字符串 .fini_array 循环做多阶段利用
**模式：** `printf()` 之后没有任何 GOT 函数被调用。把 `.fini_array[0]` 改成 `main()` 形成重入循环。阶段一：泄漏 libc/栈。阶段二：`printf@GOT` 改成 `system()`，`__stack_chk_fail@GOT` 改成 `main()`。阶段三：破坏 canary 触发 `__stack_chk_fail` 重入，此时 `printf(input)` 已经变成 `system(input)`。见 [format-string.md](format-string.md#格式化字符串-fini_array-循环做多阶段利用codegate-2016)。

<a id="format-string-with-rwx-fini_array-hijack"></a>
### RWX .fini_array 劫持配合格式化字符串
**模式（Encodinator）：** Base85 编码的输入位于 RWX 内存并传给 `printf()`。把 shellcode 写进 RWX 区域，用格式化字符串的 `%hn` 写覆写 `.fini_array[0]`。用收敛循环确定 base85 的参数编号。见 [advanced.md](advanced.md)。

<a id="custom-canary-preservation"></a>
### 保留自定义 canary
**模式：** 缓冲区溢出必须保留已知的 canary 值。在正确偏移写入确切的 canary 字节：`b'A' * 64 + b'BIRD' + b'X'`。见 [advanced.md](advanced.md)。

<a id="md5-preimage-gadget-construction"></a>
### MD5 原像 gadget 构造
**模式（Hashchain）：** 暴力搜索带 `eb 0c` 前缀（jmp +12）的 MD5 原像，跳过中间字节；第 14-15 字节变成 2 字节的 i386 指令。用 `31c0`（xor eax）、`cd80`（int 0x80）这类 gadget 拼出系统调用链。C 代码和 v2 技巧见 [advanced.md](advanced.md)。

<a id="python-sandbox-escape"></a>
### Python 沙箱逃逸
用 f-string 绕过 AST，用 `b'flag.txt'`（bytes 与 str 的区别）绕过 audit hook，通过 MRO 恢复 `__builtins__`。见 [sandbox-escape.md](sandbox-escape.md)。

<a id="vm-gc-triggered-uaf-slab-reuse"></a>
### VM GC 触发的 UAF（slab 复用）
**模式：** 带 NEWBUF/SLICE/GC 操作码的自定义 VM。切片会创建共享 slab 引用；丢弃切片并 GC 时，slab 被释放而父对象仍持有它。分配函数对象复用该 slab，通过 UAF 读泄漏代码指针，再覆写成 win() 地址。见 [advanced.md](advanced.md)。

<a id="gc-null-reference-cascading-corruption"></a>
### GC 空引用级联破坏
**模式：** 标记-整理 GC 顺着空引用走到堆地址 0，在那里造出假对象。整理阶段 memmove 会通过相邻对象头级联破坏 → 越界访问 → libc 泄漏 → FSOP。见 [advanced.md](advanced.md)。

<a id="oob-read-via-striderate-leak"></a>
### 通过步长/速率泄漏做越界读
**模式：** 字符串处理函数的步长由用户控制，可以越过空终止符，一次一个字节地泄漏栈 canary 和返回地址。然后用泄漏出来的值做溢出。见 [overflow-basics.md](overflow-basics.md)。

<a id="srop-with-utf-8-constraints"></a>
### 带 UTF-8 约束的 SROP
**模式：** 当 payload 必须是合法 UTF-8（Rust 二进制、JSON 解析器）时，用 SROP —— 只需要 3 个 gadget。跨寄存器字段边界的多字节 UTF-8 序列正好"修好"高字节。见 [rop-advanced.md](rop-advanced.md)。

<a id="vm-exploitation-custom-bytecode"></a>
### VM 利用（自定义字节码）
**模式：** 自定义 VM 的系统调用里有越界读写。通过异或编码的函数指针泄漏 PIE，再溢出把指针改写成 `win() ^ KEY`。见 [sandbox-escape.md](sandbox-escape.md)。

<a id="fusecuse-character-device-exploitation"></a>
### FUSE/CUSE 字符设备利用
寻找 `cuse_lowlevel_main()` / `fuse_main()`，后门写处理函数里带命令解析。利用它 `chmod /etc/passwd` 再修改内容获得 root。见 [sandbox-escape.md](sandbox-escape.md)。

<a id="busyboxrestricted-shell-escalation"></a>
### Busybox/受限 shell 提升
通过字符设备找可写路径，瞄准 `/etc/passwd` 或 `/etc/sudoers`，先改权限再改内容。见 [sandbox-escape.md](sandbox-escape.md)。

<a id="process_vm_readv-sandbox-bypass"></a>
### process_vm_readv 沙箱绕过
**模式：** 沙箱用 `process_vm_readv()` + `realpath()` 校验文件路径。用 `mmap(MAP_FIXED)` 在固定地址映射只有 `PROT_READ` 的内存 —— 沙箱的 `process_vm_readv` 静默失败，从而完全绕过路径校验。见 [sandbox-escape.md](sandbox-escape.md#利用-process_vm_readv-失败实现沙箱逃逸0ctf-2016)。

<a id="named-pipe-mkfifo-file-size-bypass"></a>
### 命名管道（mkfifo）绕过文件大小检查
**模式：** 二进制在读取之前用 `stat()` 检查文件大小。命名管道报告 `st_size = 0`，却能通过 `read()` 送出任意数据。`mkfifo /tmp/pipe && cat payload > /tmp/pipe &`，然后把管道传给二进制。配合 `ln -s /flag arena.c` 在 ROP 里复用字符串。见 [sandbox-escape.md](sandbox-escape.md#用命名管道-mkfifo-绕过文件大小检查nuit-du-hack-2016)。

<a id="shell-tricks"></a>
### Shell 技巧
`exec<&3;sh>&3` 做 fd 重定向，用 `$0` 代替 `sh`，用 `ls -la /proc/self/fd` 找到正确的 fd。见 [sandbox-escape.md](sandbox-escape.md)。

<a id="double-stack-pivot-to-bss-via-leaveret"></a>
### 通过 leave;ret 二次栈迁移到 BSS
**模式：** 只能溢出很小一段（只有 RBP + RIP）。把 RBP 覆写成 BSS 地址，RIP 覆写成 `leave; ret` gadget。`leave` 令 RSP = RBP（BSS）。BSS 上的第二阶段调用 `fgets(BSS+offset, large_size, stdin)` 载入完整 ROP 链。见 [rop-advanced.md](rop-advanced.md#通过-leaveret-双重栈迁移到-bssmidnightflag-2026)。

<a id="retf-architecture-switch-for-seccomp-bypass"></a>
### 用 RETF 切换架构绕过 seccomp
**模式：** seccomp 阻止 64 位系统调用（`open`、`execve`）。用 `retf` gadget 装载 CS=0x23（IA-32e 兼容模式）。在 32 位模式下，`int 0x80` 使用另一套系统调用号（open=5、read=3、write=4），过滤器没覆盖。需要用 `mprotect` 把 BSS 变成可执行以运行 32 位 shellcode。见 [rop-advanced.md](rop-advanced.md#用-retf-切换架构绕过-seccompmidnightflag-2026)。

<a id="leakless-libc-via-multi-fgets-stdout-file-overwrite"></a>
### 通过多次 fgets 覆写 stdout FILE 实现无泄漏 libc
**模式：** 拿不到 libc 泄漏。用 ROP 串起多次 `fgets(addr, 7, stdin)`，在 BSS 上构造假的 stdout FILE 结构。把 `_IO_write_base` 指向 GOT 条目，调用 `fflush(stdout)` → 泄漏 GOT 内容 → 得到 libc 基址。每次写 7 字节可以避免空字节破坏，因为 libc 指针的高位本来就是 `\x00`。见 [advanced-exploits-2.md](advanced-exploits-2.md#多次-fgets-覆写-stdout-file-实现无泄漏-libcmidnightflag-2026)。

<a id="signedunsigned-char-underflow-to-heap-overflow"></a>
### 有符号/无符号 char 下溢导致堆溢出
**模式：** 大小字段以 `signed char` 存储，使用时转成 `unsigned char`。`size = -112` → `(unsigned char)(-112) = 144`，把 127 字节的缓冲区溢出 17 字节。配合异或密钥流爆破做字节精度的写，伪造 chunk 大小使 chunk 晋升到 unsorted bin（libc 泄漏），用 FSOP stdout 泄漏 TLS，再覆写 TLS 析构函数（`__call_tls_dtors`）拿 RCE。见 [advanced-exploits-2.md](advanced-exploits-2.md#有符号无符号-char-下溢到堆溢出--tls-析构函数劫持midnightflag-2026)。

<a id="tls-destructor-hijack-via-__call_tls_dtors"></a>
### 通过 `__call_tls_dtors` 劫持 TLS 析构函数
**模式：** glibc 2.34+ 上 House of Apple 2 的替代方案。伪造 `__tls_dtor_list` 条目，函数指针用指针保护混淆：`encoded = rol(target ^ pointer_guard, 0x11)`。需要从 TLS 段泄漏 pointer guard（通过 FSOP stdout 重定向）。退出时每个节点都会调用 `PTR_DEMANGLE(func)(obj)`。见 [advanced-exploits-2.md](advanced-exploits-2.md#覆写-tls-析构函数通过-__call_tls_dtors-实现-rce)。

<a id="signed-int-overflow-to-negative-oob-heap-write"></a>
### 有符号 int 溢出导致负向越界堆写
**模式（Canvas of Fear）：** 索引公式 `y * width + x` 在 32 位有符号 int 中溢出为负值，通过边界检查并反向写进堆元数据。用它破坏相邻 chunk 的大小/指针，通过 unsorted bin 泄漏 libc，把数据指针重定向到 `environ` 泄漏栈，然后把 ROP 链写到 main 的返回地址。当二进制位于 Web API 之后时，串起 XSS → Fetch API → 堆利用，并在 API 参数里注入 `\n`，借 `sendline()` 实现命令堆叠。完整利用链、XSS 桥接模式、RGB 像素写原语见 [advanced-exploits-2.md](advanced-exploits-2.md#有符号-int-溢出导致负向越界堆写--xss-到二进制-pwn-的桥接midnight-2026)。

<a id="custom-shadow-stack-bypass-via-pointer-overflow"></a>
### 通过指针溢出绕过自定义影子栈
**模式（Revenant）：** `.bss` 里的用户态影子栈带无界指针。通过递归让 `shadow_stack_ptr` 越过数组进入用户可控内存（例如 `username` 缓冲区），在那里写入 `win()`，再溢出硬件栈的返回地址与之匹配。两道检查都通过。完整利用和 `.bss` 布局分析见 [advanced-exploits-2.md](advanced-exploits-2.md#通过指针溢出自定义影子栈绕过midnight-2026)。

<a id="windows-seh-overwrite--virtualalloc-rop"></a>
### Windows SEH 覆写 + VirtualAlloc ROP
格式化字符串泄漏击破 ASLR。覆写 SEH（结构化异常处理）并栈迁移到 ROP 链。`pushad` 构造 VirtualAlloc 调用帧以绕过 DEP（数据执行保护）。在基于线程的服务器上，用分离进程的启动器保证 shell 稳定。见 [advanced-exploits-4.md](advanced-exploits-4.md#windows-seh-覆盖--pushad-virtualalloc-roprainbowtwo-htb)。

<a id="sedebugprivilege-to-system"></a>
### SeDebugPrivilege 提权到 SYSTEM
`SeDebugPrivilege` + Meterpreter `migrate -N winlogon.exe` -> SYSTEM。见 [advanced-exploits-4.md](advanced-exploits-4.md#sedebugprivilege-提权到-systemrainbowtwo-htb)。

<a id="mmapmunmap-size-mismatch-uaf"></a>
### mmap/munmap 大小不匹配 UAF
用 mmap(small)/munmap(large) 过度解除映射，摧毁相邻映射。线程栈填进这个空洞，旧的缓冲区指针就变成"写进栈"。这是无竞争的 UAF 变体。见 [advanced-exploits-4.md](advanced-exploits-4.md#mmapmunmap-大小不匹配-uaf-覆盖线程栈0ctf-2017)。

<a id="strcspn-indirect-null-byte-injection"></a>
### strcspn 间接注入空字节
`strcspn(buf, "\r\n")` 加空字节写入，会在注入的换行处截断字符串。绕过 CGI 的空字节过滤实现路径穿越。见 [advanced-exploits-4.md](advanced-exploits-4.md#用-strcspn-实现间接空字节注入bsidessf-2017)。

<a id="windows-cfg-bypass-using-system-as-valid-call-target"></a>
### 用 system() 作为合法调用目标绕过 Windows CFG
**模式：** Windows CFG 会校验间接调用目标，但 msvcrt 的 `system()` 是合法 API 入口，能通过校验。把函数指针覆写成 `system()`，参数里用逗号代替空格绕过输入过滤。见 [advanced-exploits-4.md](advanced-exploits-4.md#用-system-作为合法调用目标绕过-windows-cfginsomnihack-2017)。

<a id="4-byte-shellcode-with-timing-side-channel"></a>
### 4 字节 shellcode 配计时侧信道
**模式：** 二进制在 4096 次迭代的循环里只执行用户 shellcode 的 4 个字节。被调用者保存寄存器（r12-r15）跨迭代保持，可以逐步构建状态。4096 倍的循环放大时序差异，便于可靠测量侧信道。见 [advanced-exploits-3.md](advanced-exploits-3.md#借助持久寄存器的-4-字节-shellcode-与计时侧信道google-ctf-2017)。

<a id="crc-oracle-as-arbitrary-read-primitive"></a>
### 把 CRC oracle 当作任意读原语
**模式：** CRC 在单字节上是双射。溢出指针来控制 CRC 输入地址，预先算出全部 256 个单字节 CRC，再反向查表还原任意内存的每个字节。串起多次读取就能泄漏 GOT、libc、栈和 canary。见 [advanced-exploits-3.md](advanced-exploits-3.md#crc-预言机作为任意读原语asis-ctf-2017)。

<a id="utf-8-case-conversion-buffer-overflow"></a>
### UTF-8 大小写转换缓冲区溢出
**模式：** Unicode 大小写转换可能让字符的字节长度变长（例如 2 字节 UTF-8 转大写后变成 4 字节）。如果缓冲区按输入长度分配，变长的输出就会溢出。影响 GLib 的 `g_utf8_strup()`、ICU 以及类似函数。见 [advanced-exploits-3.md](advanced-exploits-3.md#utf-8-大小写转换缓冲区溢出hitb-ctf-2017)。

<a id="useful-commands"></a>
## 常用命令

`checksec`、`one_gadget`、`ropper`、`ROPgadget`、`seccomp-tools dump`、`strings libc | grep GLIBC`。完整命令列表和 pwntools 模板见 [rop-advanced.md](rop-advanced.md)。
