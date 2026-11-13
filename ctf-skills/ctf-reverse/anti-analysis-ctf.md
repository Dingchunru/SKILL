# CTF Reverse - 反分析专题题解

CTF 特有的反分析技巧：信号处理器诡计、指令轨迹反转、无 call 的函数链、
由父进程打补丁的子进程二进制 dump。核心反分析分类法（Linux/Windows 反调试、反虚拟机、
反 DBI、代码完整性、反反汇编）见 [anti-analysis.md](anti-analysis.md)。

## 目录
- [用 SIGILL 处理器切换执行模式（Hack.lu 2015）](#用-sigill-处理器切换执行模式hacklu-2015)
- [通过 strace 计数利用 SIGFPE 信号处理器侧信道（PlaidCTF 2017）](#通过-strace-计数利用-sigfpe-信号处理器侧信道plaidctf-2017)
- [用 Keystone 与 Unicorn 反转指令轨迹（MeePwn CTF 2017）](#用-keystone-与-unicorn-反转指令轨迹meepwn-ctf-2017)
  - [通过栈帧操纵实现无 call 函数链（THC CTF 2018）](#通过栈帧操纵实现无-call-函数链thc-ctf-2018)
  - [通过 strace process_vm_writev dump 父进程打过补丁的子进程二进制（Google CTF Quals 2018）](#通过-strace-process_vm_writev-dump-父进程打过补丁的子进程二进制google-ctf-quals-2018)
- [通过构造函数断点 dump ConfuserEx 动态模块（Kaspersky 2018）](#通过构造函数断点-dump-confuserex-动态模块kaspersky-2018)

---

<a id="sigill-handler-for-execution-mode-switching-hacklu-2015"></a>
## 用 SIGILL 处理器切换执行模式（Hack.lu 2015）

二进制可以安装 SIGILL（非法指令）处理器，在 x86 与 x86-64 执行模式之间切换，或实现自定义操作码分发：

1. **注册信号：** `signal(SIGILL, handler)` 安装非法指令异常的回调
2. **模式切换：** 处理器修改保存的指令指针或段寄存器，在 32 位与 64 位代码之间切换
3. **自定义操作码：** 非法 x86 指令触发处理器，处理器把操作数字节解释为自定义 VM 操作码

```c
// 信号处理器把"非法"指令解码为自定义操作码
void sigill_handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *ctx = (ucontext_t *)ucontext;
    unsigned char *pc = (unsigned char *)ctx->uc_mcontext.gregs[REG_RIP];
    // 从 PC 处的字节解码自定义操作码
    // 把 PC 推过这条自定义指令
    ctx->uc_mcontext.gregs[REG_RIP] += opcode_length;
}
```

**关键要点：** 如果二进制在执行早期就为 SIGILL/SIGSEGV/SIGTRAP 安装信号处理器，就要怀疑是自定义指令分发。用 `strace -e signal` 跟踪信号投递，或让 GDB 不拦截：`handle SIGILL nostop pass`。

---

<a id="sigfpe-signal-handler-side-channel-via-strace-counting-plaidctf-2017"></a>
## 通过 strace 计数利用 SIGFPE 信号处理器侧信道（PlaidCTF 2017）

二进制用 SIGFPE 信号处理器做控制流，导致静态分析不可靠。通过 strace 统计 SIGFPE 信号数量来爆破 —— 正确的输入字符会产生更多信号。

```bash
# 统计每个候选输入字符产生的 SIGFPE 信号数
for c in {a..z} {A..Z} {0..9}; do
    count=$(echo -n "${c}AAAAAAA" | strace -e signal=SIGFPE ./binary 2>&1 | grep -c SIGFPE)
    echo "$c: $count"
done
# 产生最多 SIGFPE 的字符即为正确字符
# 对每个位置重复，逐步延长已知前缀
```

**关键要点：** 信号处理器（SIGFPE、SIGSEGV、SIGILL）制造了静态分析看不见的隐式控制流。信号触发次数与校验进度相关。用 `strace -e signal=SIGFPE` 计数，就把不透明的信号式校验变成了可测量的侧信道，支持逐字符爆破。

---

<a id="instruction-trace-inversion-with-keystone-and-unicorn-meepwn-ctf-2017"></a>
## 用 Keystone 与 Unicorn 反转指令轨迹（MeePwn CTF 2017）

UPX 加壳的二进制对 flag 施加一串纯算术变换（sub、add、xor、rol、ror）。没有内存副作用 —— 纯寄存器算术。IDAPython 跟踪非跳转指令，然后反转该序列即可恢复 flag。

**反转规则：**
- 逆序排列指令序列（最后一条指令最先执行）
- 交换互逆运算对：`add ↔ sub`、`rol ↔ ror`、`xor` 自逆

```python
# IDAPython：收集混淆例程中的非跳转指令
import idaapi, idc

def trace_transforms(start_ea, end_ea):
    instructions = []
    ea = start_ea
    while ea < end_ea:
        mnem = idc.print_insn_mnem(ea)
        if mnem not in ('jmp', 'je', 'jne', 'call', 'ret'):
            instructions.append((ea, mnem, idc.print_operands(ea)))
        ea = idc.next_head(ea)
    return instructions

transforms = trace_transforms(0x401000, 0x401200)

# 反转：逆序，并交换 add/sub 与 rol/ror
inverse_map = {'add': 'sub', 'sub': 'add', 'rol': 'ror', 'ror': 'rol', 'xor': 'xor'}
inverted = [(mnem, op) for (_, mnem, op) in reversed(transforms)]
inverted = [(inverse_map.get(m, m), op) for m, op in inverted]
```

```python
# 用 Keystone 汇编反转后的指令，再用 Unicorn 模拟执行
from keystone import *
from unicorn import *
from unicorn.x86_const import *

ks = Ks(KS_ARCH_X86, KS_MODE_64)
uc = Uc(UC_ARCH_X86, UC_MODE_64)

asm_src = '\n'.join(f'{mnem} {op}' for mnem, op in inverted)
encoding, _ = ks.asm(asm_src)

CODE_BASE = 0x400000
uc.mem_map(CODE_BASE, 0x10000)
uc.mem_write(CODE_BASE, bytes(encoding))

# 把初始寄存器状态设为观测到的输出值
uc.reg_write(UC_X86_REG_RAX, known_output)
uc.emu_start(CODE_BASE, CODE_BASE + len(encoding))
flag_bytes = uc.reg_read(UC_X86_REG_RAX).to_bytes(8, 'little')
```

**PEB 反调试注意：** 如果二进制读取 `PEB.BeingDebugged` 并在两个比较目标值之间选择，IDAPython 下跟踪到的指令可能使用调试模式的目标值。跟踪前先把 `BeingDebugged` 补丁为 0，或者识别出两个分支并使用非调试的目标值。

**关键要点：** 纯算术混淆（无内存写入）完全可通过跟踪、逆序指令序列并交换逆运算来还原。PEB 反调试可能静默改变比较目标 —— 始终确认实际走的是哪个分支。

**参考：** MeePwn CTF 2017

---

<a id="call-less-function-chaining-via-stack-frame-manipulation-thc-ctf-2018"></a>
### 通过栈帧操纵实现无 call 函数链（THC CTF 2018）

**模式：** 二进制在栈上构建函数指针链表来隐藏函数调用，然后修改保存的 RBP 与返回地址，使 `leave; ret` 沿链表串联执行，全程没有任何显式 `CALL` 指令。IDA 无法反编译，因为 push/pop 不平衡、函数边界无法确定。

链中的每个函数：
1. 把操作数和下一个函数的地址压栈
2. 把保存的 RBP 设为指向下一个栈帧
3. 把返回地址设为下一个函数
4. `leave` 从 RBP 恢复 RSP（移动到下一帧），`ret` 跳到下一个函数

```python
# 反转后的处理链（每个函数都通过 leave/ret 执行）：
def reverse_processing(byte):
    res = byte | 0x80       # OR 0x80
    res = res ^ 0xCA        # XOR 0xCA
    res = (res + 66) & 0xFF # ADD 66
    res = res ^ 0xCA        # XOR 0xCA（重复）
    res = (res + 66) & 0xFF
    res = res ^ 0xCA
    res = (res + 66) & 0xFF
    res = res ^ 0xFE        # XOR 0xFE（最终）
    return res
# 按相反顺序施加，然后反转字符序列
```

**关键要点：** 通过把保存的 RBP 指向下一个栈帧、保存的 RIP 指向下一个函数，`leave; ret` 就能在没有任何 `call` 指令的情况下串联函数。跟踪 call/ret 平衡的反汇编器因此无法识别函数边界。对每个函数体单独打补丁，IDA 才能处理。

**检测：** 二进制中有大量以 `leave; ret` 结尾的小代码块，却没有对应的 `call` 指令。栈上交织着函数指针和数据。IDA 报 "stack frame is too big" 或无法创建函数。

**参考：** THC CTF 2018

---

<a id="parent-patched-child-binary-dump-via-strace-process_vm_writev-google-ctf-quals-2018"></a>
### 通过 strace process_vm_writev dump 父进程打过补丁的子进程二进制（Google CTF Quals 2018）

**模式（Keygenme）：** 二进制 fork。子进程是塞满 `int3`（`0xcc`）陷阱的桩代码。父进程用 `ptrace` + `process_vm_writev`，在每个陷阱触发前把真实指令写进子进程，然后继续单步。对子进程做静态分析只能看到垃圾；在单进程调试器里做动态分析又看不到父进程的写入。

**绕过 —— 让 strace 替你干活：**
```bash
# 记录父进程执行的每一次 process_vm_writev，包括完整 iov 内容。
strace -f -e trace=process_vm_writev -e write=all -o trace.log ./keygenme

# 每条记录形如：
#   process_vm_writev(child_pid, [{iov_base="\x48\x89\xe5...", iov_len=12}], 1,
#                     [{iov_base=0x400c80, iov_len=12}], 1, 0) = 12
```

解析日志，提取 `(remote_addr, bytes)` 对，生成 IDA `patch_bytes` 脚本：
```python
import re, pathlib
patches = []
pattern = re.compile(
    r'process_vm_writev\(\d+, \[{iov_base="([^"]+)", iov_len=(\d+)}\].*?\[{iov_base=(0x[0-9a-f]+)',
)
for m in pattern.finditer(pathlib.Path('trace.log').read_text()):
    data = m.group(1).encode('latin1').decode('unicode_escape').encode('latin1')
    addr = int(m.group(3), 16)
    patches.append((addr, data))

with open('patch.py', 'w') as fh:
    for addr, data in patches:
        for i, b in enumerate(data):
            fh.write(f'patch_byte({addr + i:#x}, {b:#x})\n')
```

在 IDA 中加载 `patch.py`（File → Script file）应用父进程写入的每条指令，陷阱密布的子进程就变成完全可读的二进制。有了打过补丁的二进制，加密例程只是一个普通循环 —— 对不可逆部分做黑盒，把最后的 `strcmp` 替换成泄露期望值。

**关键要点：** 任何用 ptracer 改写被跟踪者代码段的反分析方案，对父进程上的 `strace` 都是透明的。`process_vm_writev` 调用同时携带目标地址和字节，所以一次 strace 就足以 dump 出真实代码。同样的技巧也适用于使用 `ptrace(PTRACE_POKEDATA)` 或通过 `write()` 写 `/proc/<pid>/mem` 的自修改加壳器。

**参考：** Google CTF Quals 2018 —— 题解 10330

---

<a id="confuserex-dynamic-module-dump-via-constructor-breakpoint-kaspersky-2018"></a>
## 通过构造函数断点 dump ConfuserEx 动态模块（Kaspersky 2018）

**模式：** ConfuserEx（.NET 保护器）加密方法体，并在运行时从 `<Module>` 构造函数中解密。在 dnSpy 里在构造函数上下断点，单步直到动态模块在内存中完整构建，右键 → **Save Module** 即可 dump 出 token 完整的解密程序集。对 dump 结果运行 `de4dot` 重命名混淆符号。

```text
dnSpy:
  File → Open → target.exe
  Assembly Explorer → <Module> .cctor → F9（断点）
  F5 运行；等待加载完成
  右键程序集 → Save Module → out.exe
$ de4dot out.exe        # 符号清理
```

**关键要点：** ConfuserEx 只保护磁盘上的代码，不保护运行时表示。只要 .NET 保护器提供一个执行解密的已编译构造函数，构造函数执行后 dump 出的模块就是明文二进制。再接 de4dot 撤销后续的符号混淆。

**参考：** Kaspersky Industrial CTF 2018 —— glardomos，题解 12325
