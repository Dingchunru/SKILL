# CTF Reverse - 模拟执行与侧信道工具

模拟执行框架（Qiling、Triton）与侧信道测量工具（Intel Pin、LD_PRELOAD hook），
适用于反调试、自修改代码或跨架构目标让普通 GDB/Frida 难以奏效的 CTF 挑战。

核心动态分析工具（Frida、angr、lldb、x64dbg）见 [tools-dynamic.md](tools-dynamic.md)。

## 目录
- [Qiling 框架（跨平台模拟）](#qiling-框架跨平台模拟)
  - [Qiling 安装](#qiling-安装)
  - [基本用法](#基本用法)
  - [通过模拟绕过反调试](#通过模拟绕过反调试)
  - [用 Qiling 做输入模糊测试](#用-qiling-做输入模糊测试)
- [Triton（动态符号执行）](#triton动态符号执行)
- [Intel Pin 指令计数侧信道（Hackover CTF 2015）](#intel-pin-指令计数侧信道hackover-ctf-2015)
  - [结合遗传算法的 Intel Pin 指令计数（hxp CTF 2017）](#结合遗传算法的-intel-pin-指令计数hxp-ctf-2017)
- [仅凭操作码重建轨迹（0CTF 2016）](#仅凭操作码重建轨迹0ctf-2016)
- [用 LD_PRELOAD 冻结 time() 以获得确定性分析（EKOPARTY 2017）](#用-ld_preload-冻结-time-以获得确定性分析ekoparty-2017)
  - [LD_PRELOAD memcmp 侧信道逐字节爆破（Blaze CTF 2018）](#ld_preload-memcmp-侧信道逐字节爆破blaze-ctf-2018)

---

<a id="qiling-framework-cross-platform-emulation"></a>
## Qiling 框架（跨平台模拟）

Qiling 带 OS 层支持地模拟二进制（系统调用、文件系统、注册表）。它构建在 Unicorn 之上，
但补上了 Unicorn 缺少的 OS 层。

<a id="qiling-installation"></a>
### Qiling 安装

```bash
pip install qiling
# 下载目标 OS 的 rootfs：
git clone https://github.com/qilingframework/rootfs
```

<a id="basic-usage"></a>
### 基本用法

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

# Linux ELF 模拟
ql = Qiling(["./binary", "arg1"], "rootfs/x8664_linux",
            verbose=QL_VERBOSE.DEFAULT)
ql.run()

# Windows PE 模拟（不需要 Windows！）
ql = Qiling(["rootfs/x86_windows/bin/binary.exe"], "rootfs/x86_windows")
ql.run()

# ARM/MIPS 模拟（IoT 固件）
ql = Qiling(["rootfs/arm_linux/bin/binary"], "rootfs/arm_linux")
ql.run()
```

<a id="anti-debug-bypass-via-emulation"></a>
### 通过模拟绕过反调试

```python
from qiling import Qiling

ql = Qiling(["./binary"], "rootfs/x8664_linux")

# hook ptrace 系统调用 —— 返回 0（成功）
def hook_ptrace(ql, ptrace_request, pid, addr, data):
    ql.log.info("ptrace bypassed")
    return 0

ql.os.set_syscall("ptrace", hook_ptrace)

# hook 指定地址（例如反虚拟机检查）
def skip_check(ql):
    ql.arch.regs.rax = 0  # 强制成功
    ql.log.info(f"Skipped check at {ql.arch.regs.rip:#x}")

ql.hook_address(skip_check, 0x401234)

ql.run()
```

<a id="input-fuzzing-with-qiling"></a>
### 用 Qiling 做输入模糊测试

```python
# 用不同输入模拟二进制以寻找 flag
import string
from qiling import Qiling

def test_input(candidate):
    ql = Qiling(["./binary"], "rootfs/x8664_linux",
                verbose=QL_VERBOSE.DISABLED, stdin=candidate.encode())
    ql.run()
    return ql.os.stdout.read()

for ch in string.printable:
    output = test_input("flag{" + ch)
    if b"Correct" in output:
        print(f"Found: {ch}")
```

**相比 GDB/Frida 的优势：**
- 没有调试器痕迹（默认绕过所有反调试）
- 跨平台且无需硬件（在 x86 主机上跑 ARM、MIPS、RISC-V）
- 用 Python 脚本化（迭代比 GDB 快）
- 支持快照/恢复，便于爆破

**关键要点：** Qiling 模拟的是整个 OS 层（系统调用、文件系统、注册表），不只是 CPU。
这意味着像 `ptrace(TRACEME)` 这类反调试检查会自然返回成功，无需打补丁；
而且你可以在 x86 主机上分析 ARM/MIPS 二进制，不需要 QEMU 或真实硬件。

**适用场景：** 异构架构二进制、IoT 固件、重度反调试、对大量输入做自动化测试。

---

<a id="triton-dynamic-symbolic-execution"></a>
## Triton（动态符号执行）

完整的 Triton 参考见 [tools-advanced.md](tools-advanced.md#triton动态符号执行)。快速用法：

```python
from triton import *

ctx = TritonContext(ARCH.X86_64)

# 把输入缓冲区符号化
for i in range(32):
    ctx.symbolizeMemory(MemoryAccess(0x600000 + i, CPUSIZE.BYTE), f"flag_{i}")

# 处理指令并收集约束
# 在比较点处求解 flag
model = ctx.getModel(ctx.getPathConstraintsAst())
flag = ''.join(chr(v.getValue()) for _, v in sorted(model.items()))
```

**关键要点：** Triton 擅长单路径 DSE（动态符号执行），而这正是 angr 路径爆炸的痛点。
喂给它一条具体执行轨迹，符号化特定输入，在比较点求解约束。
对于执行流已知的线性代码路径，它比 angr 更快。

**最适场景：** 单路径符号执行、去混淆、污点分析。对线性代码路径比 angr 快。

---

<a id="intel-pin-instruction-counting-side-channel-hackover-ctf-2015"></a>
## Intel Pin 指令计数侧信道（Hackover CTF 2015）

**模式：** 用 Intel Pin 的 `inscount0` 工具对二进制逐字符爆破。每个正确字符都会让比较逻辑
执行得更深（指令数更多）。

```python
import string
from subprocess import Popen, PIPE

pin = './pin'
tool = './source/tools/ManualExamples/obj-intel64/inscount0.so'
binary = './target'

key = ''
while True:
    best_count, best_char = 0, ''
    for c in string.printable:
        cmd = [pin, '-injection', 'child', '-t', tool, '--', binary]
        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        p.communicate((key + c + '\n').encode())
        with open('inscount.out') as f:
            count = int(f.read().split()[-1])
        if count > best_count:
            best_count, best_char = count, c
    key += best_char
    print(f"Found: {key}")
```

**关键要点：** Movfuscated 二进制（用 `movfuscator` 编译）会把每条指令展开成一串 `mov`，
使静态分析不可行。但逐字符比较仍然会产生可测量的指令数差异。
Pin 的 `inscount0.so` 统计执行的总指令数 —— 每个位置上的正确字符会多执行约 1000+ 条指令
（比较继续进行得更远）。对带顺序输入检查的混淆二进制同样有效。

---

<a id="intel-pin-instruction-counting-with-genetic-algorithm-hxp-ctf-2017"></a>
### 结合遗传算法的 Intel Pin 指令计数（hxp CTF 2017）

对于只有在每个字符检查通过后才解密下一段的自修改代码，标准的逐字符 Pin 计数会失败：
搜索空间太大，而且字符之间可能相互影响。此时改用遗传算法更高效地探索输入空间。

```python
import subprocess
import random
import string

PIN_PATH = '/tmp/pin-3.5/pin'
TOOL_PATH = 'source/tools/ManualExamples/obj-intel64/inscount0.so'

def fitness(candidate):
    """在 Pin 下运行二进制，返回指令数作为适应度。"""
    proc = subprocess.Popen(
        [PIN_PATH, '-t', TOOL_PATH, '--', './binary'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(candidate.encode())
    # inscount0 把计数写到 stderr 或 inscount.out
    try:
        with open('inscount.out') as f:
            return int(f.read().split()[-1])
    except:
        return 0

def mutate(individual, rate=0.1):
    """随机变异个体中的字符。"""
    result = list(individual)
    for i in range(len(result)):
        if random.random() < rate:
            result[i] = random.choice(string.printable[:62])
    return result

# 遗传算法参数
FLAG_LEN = 40
POP_SIZE = 100
SURVIVORS = 20

# 初始化随机种群
population = [random.choices(string.printable[:62], k=FLAG_LEN) for _ in range(POP_SIZE)]

for generation in range(10000):
    # 用指令数为每个个体打分
    scored = [(fitness(''.join(p)), p) for p in population]
    scored.sort(reverse=True)
    best_score, best_individual = scored[0]
    print(f"Gen {generation}: {best_score} {''.join(best_individual)}")

    # 保留最优个体，变异填充种群
    survivors = [s[1] for s in scored[:SURVIVORS]]
    population = survivors + [mutate(random.choice(survivors)) for _ in range(POP_SIZE - SURVIVORS)]
```

**针对 Go 二进制修改 Pin（表查找式 flag 校验）：**
当标准 `inscount` 因为计数增量与正确性不相关（例如表查找比较）而失败时，
可修改 Pin 的 icount 工具，只统计成功分支地址处的执行次数。用这个定向计数器逐字符爆破：

```cpp
// 修改版 inscount0.cpp —— 只统计特定地址的执行次数
static ADDRINT target_addr = 0x401234;  // 成功分支地址
static UINT64 target_count = 0;

VOID CountAtTarget(ADDRINT ip) {
    if (ip == target_addr) target_count++;
}

VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CountAtTarget,
                   IARG_INST_PTR, IARG_END);
}
```

**关键要点：** 当每个正确字符会解锁新的代码段（自修改或多阶段解密）时，
指令数与正确程度单调相关。遗传算法能同时发现多个正确字符，因此比逐字符爆破
更高效地探索输入空间。对 40 字符的 flag 大约 30 分钟收敛。
对于指令总数与正确性无关的表查找比较，改为针对特定分支地址计数。

**参考：** hxp CTF 2017

---

<a id="opcode-only-trace-reconstruction-0ctf-2016"></a>
## 仅凭操作码重建轨迹（0CTF 2016）

给定一条只有操作码（没有寄存器/内存值）的执行轨迹，重建程序：按地址排序/去重轨迹、
切分为基本块、标注函数。排序算法尤其容易中招 —— 分支决策会泄漏元素顺序。

**方法：**
1. 按地址排序轨迹条目，去重以恢复代码布局
2. 识别基本块边界（跳转、调用、返回）
3. 从轨迹顺序映射分支的 taken/not-taken 决策
4. 对排序算法，分区比较揭示了全部输入元素的相对顺序

**关键要点：** 没有数据值的执行轨迹仍会通过分支决策泄漏信息。
快排的分区比较在每一步揭示哪个元素更大/更小，仅凭分支方向就能完整恢复排序后的输入。

---

<a id="ld_preload-time-freeze-for-deterministic-analysis-ekoparty-2017"></a>
## 用 LD_PRELOAD 冻结 time() 以获得确定性分析（EKOPARTY 2017）

通过 LD_PRELOAD 覆盖 `time()` 返回常量，冻结任何以时间戳为种子的 PRNG。
一旦二进制的加密变成确定性的，就能在不理解 VM 或加密内部实现的情况下爆破每个输出字节。

```c
// freeze_time.c —— 编译：gcc -shared -fPIC -o freeze.so freeze_time.c
#include <time.h>

time_t time(time_t *t) {
    if (t) *t = 1234567890;
    return 1234567890;
}
```

```bash
# 构建并使用：
gcc -shared -fPIC -o freeze.so freeze_time.c
LD_PRELOAD=./freeze.so ./binary

# 逐字节 oracle：冻结时间运行，尝试每个候选字节，
# 观察输出 —— 正确字节产生期望的输出字符。
for byte in $(seq 0 255); do
    output=$(echo -n "$(printf '\x%02x' $byte)" | LD_PRELOAD=./freeze.so ./binary)
    # 把输出与已知/期望值对比
done
```

如果还涉及 `srand()` 或 `rand()`，把 `rand()` 也一并覆盖：
```c
int rand(void) { return 42; }
```

**关键要点：** LD_PRELOAD 函数拦截能冻结非确定性来源（time、rand）。
一旦确定，即便复杂的 VM 也会变成可处理的逐字节 oracle。

**参考：** EKOPARTY CTF 2017

---

<a id="ld_preload-memcmp-side-channel-for-byte-by-byte-bruteforce-blaze-ctf-2018"></a>
### LD_PRELOAD memcmp 侧信道逐字节爆破（Blaze CTF 2018）

**模式：** 用 LD_PRELOAD 库替换 `memcmp`，让它返回匹配字节数而不是标准的 -1/0/1。
这把任何基于 memcmp 的校验变成逐字节 oracle。配合 GDB Python 脚本自动化，
即可爆破每个字符位置。

```c
// memcmp_hook.c - 编译：gcc -shared -fPIC -o hook.so memcmp_hook.c
int memcmp(const char *s1, const char *s2, int n) {
    int cnt = 0;
    for (int i = 0; i < n; ++i) {
        if (s1[i] == s2[i]) cnt++;
        else break;
    }
    return cnt;
}
```

```bash
# 与 GDB 配合：LD_PRELOAD=./hook.so gdb ./binary
# 在 memcmp 之后下断点，读返回值即匹配字节数
# 在每个位置迭代字符，找出使计数增大的那个
```

**关键要点：** 用 LD_PRELOAD 把 memcmp 替换成返回匹配计数，就把任何基于比较的校验
变成逐字节 oracle。配合 GDB 脚本，无需逆向校验算法即可自动化爆破密码/flag 校验。

**检测：** 二进制用 `memcmp` 或 `strcmp` 做 flag 校验（在 `ltrace` 输出或导入表中可见）。
该比较函数被调用时传入用户输入与计算得出/存储的期望值。

**参考：** Blaze CTF 2018
