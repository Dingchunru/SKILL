# pwnable.tw 题目目录

> 本文件由 `scripts/build_skill_catalog.py` 生成，请勿手工编辑。
>
> 共 43 道题。每行给出目标环境、保护机制、标签和一句话根因；
> 完整分析、利用链与偏移见各题链接。按标签检索见文末。

## 题目一览

| 题目 | 分数 | 架构 | Libc | 保护机制 | 标签 | 一句话根因 |
|---|---|---|---|---|---|---|
| [orw](orw.md) | 100 | i386 | static | Partial RELRO / Canary / NX off / No PIE | `shellcode` `seccomp-bypass` | 在固定地址的 RWX BSS 缓冲区执行用户 shellcode，但 seccomp 过滤器只允许 open、read、write 系统调用，需借此读取 flag 文件。 |
| [start](start.md) | 100 | i386 | static | No RELRO / No Canary / NX off / No PIE | `stack-buffer-overflow` `information-leak` `shellcode` | 在一个极简的 32 位汇编二进制中，利用栈缓冲区溢出通过 sys_write 泄漏栈指针，并返回到栈上的用户 shellcode。 |
| [3x17](3x17.md) | 150 | x86-64 | static | Partial RELRO / No Canary / NX / No PIE | `arbitrary-write` `fini-array-overwrite` `rop` `static-binary` | 一次任意 24 字节写入可以覆盖 .fini_array 条目，让 __libc_csu_fini 循环执行，把 RSP 迁移到用户输入处并执行调用 execve 的 ROP 链。 |
| [calc](calc.md) | 150 | i386 | static | Partial RELRO / Canary / NX / No PIE | `integer-underflow` `stack-buffer-overflow` `rop` `static-binary` | 算术表达式 token 索引中的整数下溢可导致任意栈读写，从而能在返回地址处构造 ROP 链。 |
| [hacknote](hacknote.md) | 150 | i386 | glibc-2.23 | Partial RELRO / Canary / NX / No PIE | `use-after-free` `got-overwrite` `ret2libc` | 笔记管理中的 use-after-free 允许把用户数据重新分配到笔记元数据堆块，从而覆盖打印函数指针并调用 system。 |
| [bash](bash.md) | 200 | x86-64 | glibc-2.23 | Partial RELRO / Canary / NX / No PIE | `logic-flaw` `race-condition` `command-injection` | 受限 bash shell 中创建临时环境文件时的竞态条件，使得攻击者可以执行任意 shell 命令以绕过限制。 |
| [criticalheap](criticalheap.md) | 200 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / No PIE | `type-confusion` `arbitrary-write` `shellcode` | system 类型与普通堆对象之间的类型混淆可修改结构体指针，从而获得向 RWX 页的任意写入并执行 shellcode。 |
| [re_alloc](re_alloc.md) | 200 | x86-64 | glibc-2.29 | Partial RELRO / Canary / NX / No PIE | `use-after-free` `tcache-poisoning` `got-overwrite` | 向 realloc 传入 0 会释放 chunk 却不清空指针，进而在 glibc 2.29 上做 tcache poisoning，用 system 覆盖 GOT 表项。 |
| [silver_bullet](silver_bullet.md) | 200 | i386 | glibc-2.23 | Partial RELRO / No Canary / NX / No PIE | `off-by-one` `stack-buffer-overflow` `ret2libc` | strncat 的 off-by-one 会把子弹威力整数写成 0，于是第二次输入能溢出栈帧，进而做 ret2libc。 |
| [starbound](starbound.md) | 200 | i386 | glibc-2.23 | Partial RELRO / No Canary / NX / No PIE | `integer-overflow` `stack-pivoting` `rop` | 菜单跳转表接受负下标，可读到表外，进而把栈迁移到用户输入上执行 ROP 链。 |
| [tcache_tear](tcache_tear.md) | 200 | x86-64 | glibc-2.27 | Full RELRO / Canary / NX / No PIE | `double-free` `tcache-poisoning` `arbitrary-write` | tcache 中的双重释放可把任意内存地址链进 tcache 链表，在 __free_hook 上伪造 chunk 从而执行 system。 |
| [babystack](babystack.md) | 250 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / PIE | `information-leak` `brute-force-oracle` `stack-buffer-overflow` `rop` | 利用 strncmp 构成的密码校验预言机，可以逐字节还原栈 canary 和随机密码，进而通过栈溢出构造 ROP 链。 |
| [applestore](applestore.md) | 300 | i386 | glibc-2.23 | Partial RELRO / Canary / NX / No PIE | `stack-pivoting` `type-confusion` `arbitrary-write` `got-overwrite` | 把栈上分配的商品节点插入堆管理的购物车双向链表后，删除商品时会产生任意写原语，可通过覆盖 GOT 劫持控制流。 |
| [death_note](death_note.md) | 300 | i386 | static | Partial RELRO / Canary / NX / No PIE | `out-of-bounds-write` `alpha-shellcode` `got-overwrite` | 笔记选择处存在负索引，允许把地址写进 GOT 数组，从而将执行流重定向到存放在可执行堆上的可打印字母数字 shellcode。 |
| [dubblesort](dubblesort.md) | 300 | i386 | glibc-2.23 | Full RELRO / Canary / NX / PIE | `canary-bypass` `stack-buffer-overflow` `ret2libc` | 向 scanf 输入非数字可跳过数组元素的赋值而不写入，从而在排序过程中绕过栈 canary，实现 ret2libc。 |
| [kidding](kidding.md) | 300 | i386 | static | Partial RELRO / No Canary / NX / No PIE | `stack-buffer-overflow` `rop` `seccomp-bypass` `reverse-shell` | 静态二进制在标准流被关闭的情况下存在栈溢出，需构造 ROP 链建立反向 socket 连接才能取回 flag。 |
| [mno2](mno2.md) | 300 | i386 | static | Partial RELRO / No Canary / NX / No PIE | `alpha-shellcode` `seccomp-bypass` | 在固定的 RWX 内存区执行字母数字 shellcode，并在 seccomp 限制下用自修改代码拼出 syscall 指令。 |
| [spirited_away](spirited_away.md) | 300 | i386 | glibc-2.23 | Partial RELRO / Canary / NX / No PIE | `house-of-spirit` `stack-buffer-overflow` `ret2libc` | 长度字段的 off-by-one 可在栈上伪造 chunk 头，经 free() 触发 House of Spirit，从而覆盖返回地址。 |
| [alive_note](alive_note.md) | 350 | i386 | glibc-2.23 | Partial RELRO / Canary / NX off / No PIE | `heap-buffer-overflow` `alpha-shellcode` `got-overwrite` | 越界索引写入可以覆盖 free 的 GOT 表项，跳转到散布在堆 note 块中的 3 字节字母数字 shellcode 片段链。 |
| [break_out](break_out.md) | 350 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / PIE | `use-after-free` `information-leak` `fastbin-dup` | 牢房笔记管理中的 use-after-free 可泄露堆与 libc 指针，随后通过 fastbin 重复分配覆盖 __malloc_hook。 |
| [caov](caov.md) | 350 | x86-64 | glibc-2.23 | Full RELRO / No Canary / NX / No PIE | `use-after-free` `type-confusion` `fastbin-dup` | 在 C++ 键值对的编辑流程中复用悬垂的对象指针会引发堆上类型混淆，从而破坏 fastbin 并覆盖伪造的 vtable。 |
| [heap_paradise](heap_paradise.md) | 350 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / PIE | `off-by-null` `fastbin-dup` `io-file-exploit` | 单字节 off-by-null 溢出配合 fastbin 合并与重复分配，在没有 show 功能的情况下通过 _IO_2_1_stdout_ 泄漏 libc。 |
| [re_alloc_revenge](re_alloc_revenge.md) | 350 | x86-64 | glibc-2.29 | Full RELRO / Canary / NX / PIE | `use-after-free` `double-free` `tcache-poisoning` `io-file-exploit` | 只有两个分配槽时，利用 realloc(ptr, 0) 双重释放做 tcache poisoning，污染 _IO_2_1_stdout_ 并劫持 __free_hook。 |
| [secret_garden](secret_garden.md) | 350 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / PIE | `double-free` `fastbin-dup` `one-gadget` | 花朵节点上的双重释放漏洞可做 fastbin 伪造，在 __malloc_hook 上分配出 chunk 并执行 one_gadget。 |
| [ghost_party](ghost_party.md) | 400 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / PIE | `type-confusion` `use-after-free` `vtable-hijack` | 把不匹配的 C++ 派生类对象重新分配到已释放的槽位，会造成类型混淆，从而可将虚表重定向到 system。 |
| [printable](printable.md) | 400 | x86-64 | glibc-2.23 | Full RELRO / No Canary / NX / No PIE | `format-string` `fini-array-overwrite` `stack-pivoting` | stdout 被关闭后仅有的一次 printf 调用，可通过在 stderr 上做 1 字节格式串改写，并借栈迁移把执行流循环起来。 |
| [secret_of_my_heart](secret_of_my_heart.md) | 400 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / PIE | `off-by-null` `heap-consolidation` `fastbin-dup` | 创建 secret 时的一字节 off-by-null 可清掉 prev_inuse 位，触发向低地址合并进仍在使用的 chunk，进而覆盖 __malloc_hook。 |
| [seethefile](seethefile.md) | 400 | i386 | glibc-2.23 | Partial RELRO / Canary / NX / No PIE | `io-file-exploit` `vtable-hijack` `arbitrary-write` | 在 BSS 段伪造 _IO_FILE 结构，fclose 时劫持文件 vtable 指针，把执行流重定向到 system。 |
| [wannaheap](wannaheap.md) | 400 | x86-64 | glibc-2.24 | Full RELRO / Canary / NX / PIE | `off-by-null` `heap-consolidation` `arbitrary-write` | 在 treap 键插入中出现一个 off-by-null 字节，可跨活跃树节点触发向低地址的堆合并，在 glibc 2.24 上实现任意写。 |
| [babyallocator](babyallocator.md) | 500 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / No PIE | `stack-exhaustion` `heap-overlap` `arbitrary-write` | 耗尽 mmap 分配的 split-stack 段会让 libgcc morestack 把动态栈分配与堆缓冲区重叠，从而可以覆盖返回地址。 |
| [bash_revenge](bash_revenge.md) | 500 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / PIE | `logic-flaw` `file-descriptor-leak` `command-injection` | 利用泄露的文件描述符和 bash 内部内置命令，可以逃出受限执行模式并执行特权二进制。 |
| [bookwriter](bookwriter.md) | 500 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / No PIE | `out-of-bounds-write` `information-leak` `house-of-orange` `io-file-exploit` | 在填写书籍作者时的 off-by-null 写入可泄露堆地址，而覆盖 top chunk 大小可触发 House of Orange，通过 _IO_flush_all_lockp 实现 _IO_FILE vtable 利用。 |
| [bounty_program_a](bounty_program_a.md) | 500 | x86-64 | glibc-2.27 | Full RELRO / Canary / NX / PIE | `heap-buffer-overflow` `tcache-poisoning` `arbitrary-write` | 报告评论解析中的堆缓冲区溢出，可破坏 tcache 的 next 指针，实现任意内存写入并覆盖 __free_hook。 |
| [bounty_program_b](bounty_program_b.md) | 500 | x86-64 | glibc-2.27 | Full RELRO / Canary / NX / PIE | `heap-buffer-overflow` `unsorted-bin-attack` `tcache-poisoning` | 一字节堆溢出可让重叠的堆 chunk 在 FORTIFY_SOURCE 约束下伪造 tcache 条目，并劫持 __free_hook。 |
| [de_aslr](de_aslr.md) | 500 | x86-64 | glibc-2.23 | Full RELRO / No Canary / NX / No PIE | `ret2dlresolve` `rop` `information-leak` | 在没有任何输出函数的二进制中，利用 gets() 的栈缓冲区溢出，通过 ret2dlresolve 解析 system() 并执行 shell。 |
| [food_store](food_store.md) | 500 | x86-64 | glibc-2.24 | Full RELRO / Canary / NX / PIE | `heap-buffer-overflow` `unsorted-bin-attack` `house-of-orange` | 食谱解析中的堆溢出破坏了堆元数据，进而触发 House of Orange 并改写 glibc 2.24 中的 _IO_FILE 跳转表。 |
| [hitcon_ftp](hitcon_ftp.md) | 500 | x86-64 | glibc-2.27 | Full RELRO / Canary / NX / PIE | `heap-buffer-overflow` `seccomp-bypass` `rop` | msgpack 数据包反序列化过程中的堆破坏可在 seccomp 之下劫持执行流，并构造 open-read-write 的 ROP 链。 |
| [seccomptools](seccomptools.md) | 500 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / PIE | `arbitrary-write` `seccomp-bypass` `timing-side-channel` | 规则管理中存在堆写原语，可覆盖 __free_hook，从而触发 BPF 过滤器预言机逐位泄漏内存内容。 |
| [stupid_boss](stupid_boss.md) | 500 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / PIE | `use-after-free` `type-confusion` `got-overwrite` | 员工类结构中的 use-after-free 漏洞可篡改函数指针，把执行流劫持到 system。 |
| [unexploitable](unexploitable.md) | 500 | x86-64 | glibc-2.23 | Partial RELRO / No Canary / NX / No PIE | `stack-buffer-overflow` `srop` `stack-pivoting` | 一个没有任何输出函数的栈溢出，可用 Sigreturn-Oriented Programming（SROP）布置寄存器状态并调用 execve。 |
| [criticalheap_pp](criticalheap_pp.md) | 600 | x86-64 | glibc-2.23 | Full RELRO / Canary / NX / No PIE | `type-confusion` `use-after-free` `arbitrary-write` | 多态 C++ 对象在没有虚析构函数的情况下被销毁，导致悬垂指针复用与类型混淆，从而实现任意内存写入。 |
| [digimon](digimon.md) | 600 | x86-64 | glibc-2.23 | Partial RELRO / Canary / NX / PIE | `use-after-free` `race-condition` `vtable-hijack` | 并发战斗线程之间的竞态在 Digimon 对象上造成 use-after-free，从而可以覆盖虚函数表指针。 |
| [omegago](omegago.md) | 600 | x86-64 | glibc-2.23 | Partial RELRO / No Canary / NX / No PIE | `type-confusion` `out-of-bounds-write` `got-overwrite` | 围棋棋盘上的坐标编码混淆导致数组越界索引，从而实现任意 GOT 覆盖并劫持程序执行流。 |

## 标签索引

| 标签 | 题目 |
|---|---|
| `alpha-shellcode` | alive_note、death_note、mno2 |
| `arbitrary-write` | 3x17、applestore、babyallocator、bounty_program_a、criticalheap、criticalheap_pp、seccomptools、seethefile、tcache_tear、wannaheap |
| `brute-force-oracle` | babystack |
| `canary-bypass` | dubblesort |
| `command-injection` | bash、bash_revenge |
| `double-free` | re_alloc_revenge、secret_garden、tcache_tear |
| `fastbin-dup` | break_out、caov、heap_paradise、secret_garden、secret_of_my_heart |
| `file-descriptor-leak` | bash_revenge |
| `fini-array-overwrite` | 3x17、printable |
| `format-string` | printable |
| `got-overwrite` | alive_note、applestore、death_note、hacknote、omegago、re_alloc、stupid_boss |
| `heap-buffer-overflow` | alive_note、bounty_program_a、bounty_program_b、food_store、hitcon_ftp |
| `heap-consolidation` | secret_of_my_heart、wannaheap |
| `heap-overlap` | babyallocator |
| `house-of-orange` | bookwriter、food_store |
| `house-of-spirit` | spirited_away |
| `information-leak` | babystack、bookwriter、break_out、de_aslr、start |
| `integer-overflow` | starbound |
| `integer-underflow` | calc |
| `io-file-exploit` | bookwriter、heap_paradise、re_alloc_revenge、seethefile |
| `logic-flaw` | bash、bash_revenge |
| `off-by-null` | heap_paradise、secret_of_my_heart、wannaheap |
| `off-by-one` | silver_bullet |
| `one-gadget` | secret_garden |
| `out-of-bounds-write` | bookwriter、death_note、omegago |
| `race-condition` | bash、digimon |
| `ret2dlresolve` | de_aslr |
| `ret2libc` | dubblesort、hacknote、silver_bullet、spirited_away |
| `reverse-shell` | kidding |
| `rop` | 3x17、babystack、calc、de_aslr、hitcon_ftp、kidding、starbound |
| `seccomp-bypass` | hitcon_ftp、kidding、mno2、orw、seccomptools |
| `shellcode` | criticalheap、orw、start |
| `srop` | unexploitable |
| `stack-buffer-overflow` | babystack、calc、dubblesort、kidding、silver_bullet、spirited_away、start、unexploitable |
| `stack-exhaustion` | babyallocator |
| `stack-pivoting` | applestore、printable、starbound、unexploitable |
| `static-binary` | 3x17、calc |
| `tcache-poisoning` | bounty_program_a、bounty_program_b、re_alloc、re_alloc_revenge、tcache_tear |
| `timing-side-channel` | seccomptools |
| `type-confusion` | applestore、caov、criticalheap、criticalheap_pp、ghost_party、omegago、stupid_boss |
| `unsorted-bin-attack` | bounty_program_b、food_store |
| `use-after-free` | break_out、caov、criticalheap_pp、digimon、ghost_party、hacknote、re_alloc、re_alloc_revenge、stupid_boss |
| `vtable-hijack` | digimon、ghost_party、seethefile |
