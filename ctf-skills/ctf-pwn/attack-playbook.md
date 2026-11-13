# Linux 用户态攻击手册

把这份文档当作 Linux/glibc 目标的工作流视图。它回答*该看什么*、*该追哪个原语*；完整的 payload、版本相关的绕过和 CTF 题解请看链接过去的技术笔记。

## 侦察

在选择利用路径之前，先枚举输入面和权限边界：

- 参数与环境：`argv`、`getopt()`、`getenv()`、`LD_PRELOAD`、`PATH`。
- 文件：攻击者可选择的 `fopen()`/`read()` 路径，以及 `/etc/program.conf`、`~/.config/...` 之类的配置文件。
- 标准输入：`read()` 与 `fgets()` 循环。
- 网络套接字：`accept()`、`recv()`、`recvfrom()`。
- IPC：D-Bus、Unix 域套接字、共享内存。
- 权限边界：SUID/SGID 状态，以及进程是否会改变 UID/EUID。
- 事件路径：信号处理函数（`SIGUSR*`、`SIGALRM`、…）以及任何非信号安全的代码。
- 伪文件系统接口：从 `/proc` 或 `/sys` 读取的值。

记录哪个入口点能到达危险的内存分配、拷贝、格式化输出汇点、解引用或特权操作。一个难以触达的 bug，通常不如一个触达不了但更强的原语。

来自 ELF 元数据、libc 构建和加固工具的静态信号可以帮助给候选原语排序，但它们本身不能证明可利用性。当请求要求评估可利用性或安全影响时，选路之前先读 [static-signals.md](static-signals.md)。

## 泄漏选择

找出能击破目标实际启用的那些缓解措施的最小泄漏：

| 秘密 | 可用来源 |
| --- | --- |
| libc | unsorted/small/large-bin 的 `fd`/`bk`、栈上的返回路径、可写函数指针、堆/栈残留、FILE 结构 |
| heap | tcache/fastbin/largebin 元数据、栈残留、TLS |
| stack | 未初始化栈、保存的帧、libc `__environ` |
| canary | 未初始化/越界读的栈、TLS |
| binary | 栈残留，以及带二进制偏移的函数/数据指针 |
| 内存布局 | 针对 `/proc/self/maps` 的文件读原语 |

获取泄漏的常见手段：

- 读取未初始化的堆或栈分配。
- 利用格式化字符串 bug。
- 把 FILE 结构破坏转化为任意读。
- 把溢出或任意分配转化为越界读。
- 把写原语与"之后会从中打印或拷贝"的对象组合起来。

识别 libc 用 [format-string.md](format-string.md#格式化字符串基础) 里链接的数据库。格式化字符串的完整机制见 [format-string.md](format-string.md)。

## 控制流与写目标

在检查完二进制保护、libc 版本和写原语的强度之后再选目标：

| 写目标 | 典型条件 |
| --- | --- |
| 返回地址 | 可控的栈写或溢出 |
| 二进制 GOT | 部分 RELRO |
| libc GOT | 取决于版本；要对照目标 libc 验证 |
| malloc/free/realloc hook | glibc < 2.34 |
| FILE vtable | 较老的 glibc；新目标通常需要绕过 vtable 校验 |
| FILE wide vtable | 在现代 glibc 上可用 |
| 二进制函数指针 / `fini_array` | 该二进制特有的可写目标 |
| `l_addr` 加函数指针 | 该二进制特有的基址/指针组合 |

Payload 选择：

- **ROP** —— 有 gadget 地址且能控制栈时。
- **SROP** —— sigreturn 触发点能替代大量 gadget 需求时。
- **One gadget** —— 能满足它的寄存器/栈约束时。
- **`system("/bin/sh")`** —— 能把 `/bin/sh` 放进 `rdi` 且栈对齐可保持时。

版本相关的现代 libc 链路：[nobodyisnobody/docs](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc) 和 [n132/Libc-GOT-Hijacking](https://github.com/n132/Libc-GOT-Hijacking)。

## 路由到具体技术

| 情形 | 权威深入资料 |
| --- | --- |
| 输入作为格式串到达 `printf`/`sprintf`/`syslog` | [format-string.md](format-string.md) |
| 破坏能到达 `_IO_FILE`，尤其在 Full RELRO 下 | [heap-fsop.md](heap-fsop.md) |
| Bug 属于 tcache/fastbin/unsorted/largebin 或分配器元数据 | [heap-techniques.md](heap-techniques.md) |
| 需要栈迁移、ret2libc、系统调用 ROP 或 shellcode | [rop-and-shellcode.md](rop-and-shellcode.md) |
| 需要 SROP、现代 ROP、vDSO 或 seccomp 规避 | [rop-advanced.md](rop-advanced.md) |
| 需要精确的栈/canary 行为，或部分覆盖 | [overflow-basics.md](overflow-basics.md) |

## Payload 检查清单

- **栈迁移：** 用可控的 `rbp` 加 `leave`，或 `mov rsp, <reg>`；在证明读/写/执行预期之后，再迁移到输入区、BSS、堆或残留栈。
- **ROP：** 保持 16 字节栈对齐；用 `ret` 做填充，用 `setcontext` 获得大范围寄存器控制，必要时复用已有的 vtable/函数指针。
- **Shellcode：** 已存在 RWX 就优先用；否则通过 ROP 调 `mprotect`/`mmap`。面对过滤器时，考虑无空字节、字母数字、分阶段、自修改以及精心编码的 ModR/M 形式。
- **部分覆盖：** 只有当邻近代码/数据在已知低位上不同时，才只覆盖尾部字节；要把爆破概率算进去。
- **Seccomp：** 枚举允许的系统调用，寻找等价调用，执行被阻断时改用 ORW。见 [advanced.md](advanced.md#seccomp-进阶技巧)。
- **TLS：** 破坏它可以暴露 canary、tcache 状态、栈保护值或析构函数指针；见 [heap-techniques.md](heap-techniques.md#堆利用) 中的分配器笔记。
- **环境变量：** 检查它们是否会改变 libc/应用行为、禁用或影响缓存行为、填充 payload，或让布局变得可预测。
- **盲爆破：** 没有直接 oracle 时，利用可区分的崩溃/挂起/输出时序；在改用其他原语之前先估算尝试预算。
