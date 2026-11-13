# CTF Reverse - 运行时打补丁与 Oracle 技巧

恶意样本脱壳、多阶段 shellcode、时序/信号侧信道，以及依赖运行时状态而非静态模式匹配的
CTF 专用 oracle 攻击。

静态逆向模式（自定义 VM、反调试、自修改代码、LLVM 混淆、S-box 生成、SECCOMP/BPF、
内存 dump、x86-64 坑点、逐字节变换）见 [patterns.md](patterns.md)。

## 目录
- [通过打补丁绕过恶意样本的反分析](#通过打补丁绕过恶意样本的反分析)
- [多阶段 Shellcode 加载器](#多阶段-shellcode-加载器)
- [时序侧信道攻击](#时序侧信道攻击)
- [多线程反调试：诱饵 + 信号处理器混合布尔算术（ApoorvCTF 2026）](#多线程反调试诱饵--信号处理器混合布尔算术apoorvctf-2026)
- [INT3 补丁 + coredump 爆破 Oracle（Pwn2Win 2016）](#int3-补丁--coredump-爆破-oraclepwn2win-2016)
- [信号处理器链 + LD_PRELOAD Oracle（Nuit du Hack 2016）](#信号处理器链--ld_preload-oraclenuit-du-hack-2016)
- [printf 格式化字符串 VM 反编译到 Z3（SECCON 2017）](#printf-格式化字符串-vm-反编译到-z3seccon-2017)
- [四叉树递归图像格式解析器（Google CTF Quals 2018）](#四叉树递归图像格式解析器google-ctf-quals-2018)

---

<a id="malware-anti-analysis-bypass-via-patching"></a>
## 通过打补丁绕过恶意样本的反分析

**模式（Carrot）：** 恶意样本在执行 payload 前做多项环境检查。

**需要打补丁的常见检查：**
| 检查 | 技术 | 补丁 |
|-------|-----------|-------|
| `ptrace(PTRACE_TRACEME)` | 反调试 | 把 `cmp -1` 改成 `cmp 0` |
| `sleep(150)` | 反沙箱计时 | 把 sleep 值改成 1 |
| `/proc/cpuinfo` 中的 "hypervisor" | 反虚拟机 | 把 `JNZ` 改成 `JZ` |
| "VMware"/"VirtualBox" 字符串 | 反虚拟机 | 把 `JNZ` 改成 `JZ` |
| `getpwuid` 用户名检查 | 环境 | 翻转比较 |
| `LD_PRELOAD` 检查 | 反 hook | 跳过检查 |
| 风扇转速 / 硬件检查 | 反虚拟机 | 把 `JLE` 改成 `JGE` |
| 主机名检查 | 环境 | 把 `JNZ` 改成 `JZ` |

**Ghidra 打补丁流程：**
1. 找到检查函数，定位条件跳转
2. 点击该指令 → `Ctrl+Shift+G` → 修改操作码
3. `JNZ`（0x75）→ `JZ`（0x74），或反之
4. 立即数：直接修改操作数字节
5. 导出：按 `O` → 选择 "Original File" 格式
6. 对打补丁后的二进制 `chmod +x`

**服务端校验绕过：**
- 如果打补丁后的二进制会向远程服务器发送系统信息，那些数据也要一并打补丁
- 修改数据采集函数里的字符串地址
- 把格式字符串改成直接内嵌正确值

---

<a id="multi-stage-shellcode-loaders"></a>
## 多阶段 Shellcode 加载器

**模式（I Heard You Liked Loaders）：** 嵌套 shellcode，带 XOR 解码循环与反调试。

**调试流程：**
1. 在启动器的 `call rax` 处下断，单步进入 shellcode
2. 绕过 ptrace 反调试：单步到 syscall，`set $rax=0`
3. 单步穿过 XOR 解码循环（如果被隐藏则在 `int3` 上断）
4. 逐个阶段重复，直到最终 payload

**从 `mov` 指令提取 flag：**
```python
# 最终阶段每次用 mov ebx, value 载入 4 字节 flag
# 提取小端 4 字节块
values = [0x6174654d, 0x7b465443, ...]  # 来自反汇编
flag = b''.join(v.to_bytes(4, 'little') for v in values)
```

---

<a id="timing-side-channel-attack"></a>
## 时序侧信道攻击

**模式（Clock Out）：** 校验耗时随正确字符而变化（命中时 sleep 更长）。

**利用：**
```python
import time
from pwn import *

flag = ""
for pos in range(flag_length):
    best_char, best_time = '', 0
    for c in string.printable:
        io = remote(host, port)
        start = time.time()
        io.sendline((flag + c).ljust(total_len, 'X'))
        io.recvall()
        elapsed = time.time() - start
        if elapsed > best_time:
            best_time = elapsed
            best_char = c
        io.close()
    flag += best_char
```

---

<a id="multi-thread-anti-debug-with-decoy--signal-handler-mixed-boolean-arithmetic-apoorvctf-2026"></a>
## 多线程反调试：诱饵 + 信号处理器混合布尔算术（ApoorvCTF 2026）

**模式（A Golden Experience Requiem）：** 多层反分析的多线程二进制：线程 1 执行诱饵操作
（假 AES + 用 `ud2` 故意崩溃），线程 2 在 SIGSEGV 信号处理器里用混合布尔算术（MBA）
做真正的 flag 计算，线程 3 计算后擦除内存以防事后分析。

**线程布局：**
| 线程 | 用途 | 陷阱 |
|--------|---------|------|
| 线程 1 | 诱饵：看似 AES 的运算 → `ud2` 崩溃 | 分析者把时间浪费在逆向假加密上 |
| 线程 2 | 真正的 flag：带 MBA 变换的 SIGSEGV 处理器 | 藏在信号处理器里，不在主代码路径上 |
| 线程 3 | 内存擦除器：计算完成后把 flag 数据清零 | 阻止内存 dump |
| 主线程 | 基于 rdtsc 的反调试计时检查 | 惩罚挂调试器执行 |

**解法 —— 用纯 Python 模拟 MBA 逻辑：**
```python
# MBA 辅助函数（从汇编中提取）
def mba_add(a, b): return (a + b) & 0xff
def mba_xor(a, b): return (a ^ b) & 0xff

def mba_transform(i):
    """来自信号处理器的位置相关变换。"""
    val = (i * 7 + 0x3f) & 0xff
    rotated = ((i << 3) | (i >> 5)) & 0xff
    return mba_xor(val, rotated)

# S-box（复用了 SHA-256 的初始哈希值）
SBOX = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def sbox_lookup(i):
    idx = i & 7
    shift = ((i >> 3) & 3) * 8
    return (SBOX[idx] >> shift) & 0xff

# 两个交错的 rodata 数组（偶数下标 → array1，奇数 → array2）
rodata1 = bytes.fromhex("39407691b717c97879013adf3a2adea11c2b04e0")
rodata2 = bytes.fromhex("bb19b025e37eaa786c4116e7aeea00c9c623940d")

flag = []
for i in range(40):  # flag 长度
    t = mba_transform(i)
    s = sbox_lookup(i)
    mem = rodata1[i // 2] if i % 2 == 0 else rodata2[i // 2]
    flag.append(chr(t ^ s ^ mem))

print(''.join(flag))
```

**关键要点：** 真正的 flag 逻辑在信号处理器（SIGSEGV/SIGILL）里，不在主线程。线程 1 的类 AES 代码和 `ud2` 崩溃是有意的误导。`rdtsc` 计时检查能发现调试器并破坏输出。绕过方法是把 MBA 逻辑从汇编中提取出来、用 Python 重新实现 —— 绝不要在调试器下运行该二进制。

**检测指标：**
- 多次 `pthread_create` 调用，各自不同的处理函数
- `signal(SIGSEGV, handler)` 或 `sigaction` 设置
- `ud2` 指令（故意的非法指令）
- 用于计时检查的 `rdtsc` 指令
- SHA-256 常量（0x6a09e667...）被当作查找表使用，而不是用于哈希

---

<a id="int3-patch--coredump-brute-force-oracle-pwn2win-2016"></a>
## INT3 补丁 + coredump 爆破 Oracle（Pwn2Win 2016）

不必逆向复杂的变换逻辑：在变换之后把某个字节改成 `0xCC`（INT3），开启 core dump，
然后对每个字符跑一遍二进制，用 `strings` 从 coredump 里取出变换结果来爆破。

```bash
# 把变换输出点的字节改为 0xCC
printf '\xcc' | dd of=binary bs=1 seek=$((0x400ebb)) conv=notrunc
ulimit -c unlimited
# 逐位置爆破：
for c in $(seq 32 126); do
    echo -ne "$(printf '\\x%02x' $c)$known_suffix" | ./binary 2>/dev/null
    strings core | grep -q "$expected" && echo "Found: $c"
done
```

**关键要点：** 把 INT3/SIGTRAP 当作断点 oracle —— coredump 会在崩溃点捕获计算后的状态。免去了对变换逻辑的完整逆向。

---

<a id="signal-handler-chain--ld_preload-oracle-nuit-du-hack-2016"></a>
## 信号处理器链 + LD_PRELOAD Oracle（Nuit du Hack 2016）

二进制用 Unix 信号做控制流：`main()` 向自己发送 1024 次 SIGINT，每个处理器校验一个密码字符，
然后调用 `signal()` 安装下一个处理器。绕过方法：LD_PRELOAD 一个自定义 `signal()`，
记录它何时被调用（说明该字符正确），逐位置爆破。

```c
// LD_PRELOAD 库：
#include <signal.h>
sighandler_t signal(int sig, sighandler_t handler) {
    write(2, "CORRECT\n", 8);  // signal() 被调用 = 该字符正确
    return SIG_DFL;
}
```

**关键要点：** 信号处理器链式反逆向可以通过 LD_PRELOAD hook `signal()` 击败。
安装下一个处理器而调用 `signal()` 这一行为，本身就是确认当前字符正确的侧信道。

---

<a id="printf-format-string-vm-decompilation-to-z3-seccon-2017"></a>
### printf 格式化字符串 VM 反编译到 Z3（SECCON 2017）

一个完全由 `%hhn` 格式化字符串实现的"虚拟机"。`%hhn` 把已打印字符数（mod 256）
写入被指向的字节。一串 `%Nc%hhn` 指令就能实现任意的字节到内存写入，实际上构成了字节码 VM。

**第 1 步：识别指令类型。**
统计唯一的格式模式，确定指令集：
```bash
# 归一化数字并统计唯一模式
sed -e 's/[[:digit:]]\+/1/g' program.fs | sort | uniq -c | sort -nr
```

**第 2 步：编写反编译器。**
把格式模式转换为 C 风格伪代码。每个 `%N...%hhn` 对对应一次内存写入：
提取写入地址（来自参数指针）和值（来自字符计数）。

**第 3 步：识别算法。**
伪代码通常会揭示一个关于字节的线性方程组。把内存地址映射为符号变量。

**第 4 步：生成 Z3 约束并求解。**
```python
from z3 import *

flag_len = 32  # 根据反编译输出调整
flag = [BitVec(f'f{i}', 8) for i in range(flag_len)]
s = Solver()

# 约束为可打印 ASCII
for f in flag:
    s.add(f >= 0x20, f <= 0x7e)

# 加入反编译出的格式化字符串操作约束
# 例如 flag[3] + flag[7] == 0xAB (mod 256)
# 这些来自写入序列：每个 %hhn 累积字符计数
# 并把结果写到目标字节
s.add((flag[0] + flag[1]) & 0xFF == 0x9A)  # 示例约束
s.add((flag[2] ^ flag[3]) & 0xFF == 0x3F)  # 示例约束
# ...（加入反编译得到的全部约束）

if s.check() == sat:
    m = s.model()
    print(bytes([m[f].as_long() for f in flag]))
```

**反编译方法详解：**
1. 从每个 `%N...%hhn` 对中提取写入地址与值
2. 把内存地址映射为符号变量（flag 字节）
3. 由写入序列构建方程组
4. 用 Z3 求解

**关键要点：** `%hhn` 把已打印字符数（mod 256）写入被指向的字节。一串 `%Nc%hhn`
指令实现任意字节写内存，实际上构成字节码 VM。反编译步骤：(1) 从每个 `%N...%hhn`
对提取写入地址与值，(2) 把内存地址映射为符号变量，(3) 由写入序列构建方程组，
(4) 用 Z3 求解。

**参考：** SECCON 2017

---

<a id="quadtree-recursive-image-format-parser-google-ctf-quals-2018"></a>
## 四叉树递归图像格式解析器（Google CTF Quals 2018）

**模式：** 题目提供一个私有图像格式。逆向后发现它是四叉树：画布被切成能容纳它的最大
2 的幂正方形，该正方形递归四分，一个 1 字节命令说明四个象限中哪些要继续细分。
标记为"叶子"的象限后面跟 3 字节 RGB 颜色；其余继续递归。

```python
# 命令字节：bit 3..0 = {左上, 右上, 左下, 右下}
# 位为 1 ⇒ 继续细分；位为 0 ⇒ 叶子（后 3 字节 = RGB）

def parse(stream, x, y, size):
    cmd = stream.read(1)[0]
    half = size // 2
    children = [
        (x,        y       ),
        (x + half, y       ),
        (x,        y + half),
        (x + half, y + half),
    ]
    for i, (cx, cy) in enumerate(children):
        if cmd & (1 << (3 - i)):
            parse(stream, cx, cy, half)
        else:
            rgb = stream.read(3)
            fill_rect(cx, cy, half, half, rgb)
```

一直递归到 `half == 1`（或遇到"叶子"位），边解析边把画布画出来。
一旦象限位序对上，flag 图像就能正确渲染。

**关键要点：** CTF 中的私有图像/压缩格式几乎总是四叉树、LZ77 变体或 Huffman 流。
寻找那种"短命令字节后面跟更多命令或定宽叶子数据"的递归结构。
原型解析器时打印每次调用的递归深度和偏移 —— 深度不匹配就是位序或叶子大小有误的第一信号。

**参考：** Google CTF Quals 2018 —— 题解 10335
