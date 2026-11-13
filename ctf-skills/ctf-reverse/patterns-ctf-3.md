# CTF Reverse - 赛事专用模式（第三部分）

## 目录
- [用 Z3 求解单行 Python 布尔电路（BearCatCTF 2026）](#用-z3-求解单行-python-布尔电路bearcatctf-2026)
- [滑动窗口 popcount 差分递推（BearCatCTF 2026）](#滑动窗口-popcount-差分递推bearcatctf-2026)
- [通过 ioctl 从键盘 LED 读摩尔斯码（PlaidCTF 2013）](#通过-ioctl-从键盘-led-读摩尔斯码plaidctf-2013)
- [C++ 析构函数隐藏校验（Defcamp 2015）](#c-析构函数隐藏校验defcamp-2015)
- [系统调用副作用导致内存破坏（Hack.lu 2015）](#系统调用副作用导致内存破坏hacklu-2015)
- [定位 MFC 对话框事件处理器（WhiteHat 2015）](#定位-mfc-对话框事件处理器whitehat-2015)
- [VM 顺序密钥链暴力（Midnight Flag 2026）](#vm-顺序密钥链暴力midnight-flag-2026)
- [无终止符的 Burrows-Wheeler 逆变换（ASIS CTF Finals 2016）](#无终止符的-burrows-wheeler-逆变换asis-ctf-finals-2016)
- [利用 OpenType 字体连字隐藏信息（Hack The Vote 2016）](#利用-opentype-字体连字隐藏信息hack-the-vote-2016)
- [带自修改代码的 GLSL Shader VM（ApoorvCTF 2026）](#带自修改代码的-glsl-shader-vmapoorvctf-2026)
- [以指令计数器作为密码学状态（MetaCTF Flash 2026）](#以指令计数器作为密码学状态metactf-flash-2026)
- [带符号整数溢出的线程竞争（Codegate 2017）](#带符号整数溢出的线程竞争codegate-2017)
- [借助 ROM 符号表逆向 ESP32/Xtensa 固件（Insomni'hack 2017）](#借助-rom-符号表逆向-esp32xtensa-固件insomnihack-2017)
- [用 objdump 模式提取批量破解 crackme（DEF CON 2017）](#用-objdump-模式提取批量破解-crackmedef-con-2017)
- [Fork + 管道 + 死分支反分析（RCTF 2017）](#fork--管道--死分支反分析rctf-2017)
- [按日期上锁的二进制（Hack.lu 2017）](#按日期上锁的二进制hacklu-2017)
- [用 UnicornJS 执行藏在图像像素中的 ARM 代码（Hack.lu 2017）](#用-unicornjs-执行藏在图像像素中的-arm-代码hacklu-2017)
- [x86 16 位 MBR 的 psadbw 约束求解（CSAW 2017）](#x86-16-位-mbr-的-psadbw-约束求解csaw-2017)
- [逐层反演 sigmoid 还原 TensorFlow 深度网络（N1CTF 2018）](#逐层反演-sigmoid-还原-tensorflow-深度网络n1ctf-2018)
- [把 BPF 过滤器 JIT 编译为 x64 汇编再分析（Midnight Sun CTF 2018）](#把-bpf-过滤器-jit-编译为-x64-汇编再分析midnight-sun-ctf-2018)
- [单字节 XOR ROM 反混淆扫描（X-MAS CTF 2018）](#单字节-xor-rom-反混淆扫描x-mas-ctf-2018)
- [WebKit Array.slice 越界 CVE-2016-4622（Codegate 2019）](#webkit-arrayslice-越界-cve-2016-4622codegate-2019)
- [多模数 CRT 注册机 + 矩阵查表口令（Pragyan CTF 2019）](#多模数-crt-注册机--矩阵查表口令pragyan-ctf-2019)

---

<a id="z3-for-single-line-python-boolean-circuit-bearcatctf-2026"></a>
## 用 Z3 求解单行 Python 布尔电路（BearCatCTF 2026）

**模式（Captain Morgan）：** 单行 Python（2000+ 个分号）校验 flag：用海象运算符链把输入当作大端整数逐位拆解，配合位运算构成一个布尔电路。

**识别特征：**
- 单行 Python，语句用分号分隔
- 海象运算符 `:=` 链：`(x := expr)`
- 混淆的 XOR：用 `(x | i) & ~(x & i)` 代替 `x ^ i`
- 输入被当做一个大整数，通过位移拆解

**Z3 解法：**
```python
from z3 import *

n_bytes = 29  # Flag length
ari = BitVec('ari', n_bytes * 8)

# Parse semicolon-separated statements
# Model walrus chains as LShR(ari, shift_amount)
# Evaluate boolean expressions symbolically
# Final assertion: result_var == 0

s = Solver()
s.add(bfu == 0)  # Final validation variable
if s.check() == sat:
    m = s.model()
    val = m[ari].as_long()
    flag = val.to_bytes(n_bytes, 'big').decode('ascii')
```

**关键点：** 单行 Python 混淆本质上是在输入比特上构造布尔电路。海象运算符链只是变量赋值——按分号拆开，逐个符号化翻译成 Z3 即可。混淆的 XOR `(a | b) & ~(a & b)` 就是 `a ^ b`。Z3 解这类电路通常不到一秒。留意 `__builtins__` 访问或 `ord()`/`chr()` 调用，以确定输入→整数的转换方式。

**检测：** 1000+ 个分号的单行 Python、海象运算符、位运算，最后与 0 或 True 比较。

---

<a id="sliding-window-popcount-differential-propagation-bearcatctf-2026"></a>
## 滑动窗口 popcount 差分递推（BearCatCTF 2026）

**模式（Treasure Hunt 4）：** 二进制对输入比特上长度为 16 的滑动窗口，逐位置校验期望的 popcount（置位数）。

**差分递推：**
窗口每次滑动 1 位时：
```text
popcount(window[i+1]) - popcount(window[i]) = bit[i+16] - bit[i]
```
即：`bit[i+16] = bit[i] + (data[i+1] - data[i])`

```python
expected = [...]  # 337 expected popcount values
total_bits = 337 + 15  # = 352

# Brute-force the initial 16-bit window (must have popcount = expected[0])
for start_val in range(0x10000):
    if bin(start_val).count('1') != expected[0]:
        continue

    bits = [0] * total_bits
    for j in range(16):
        bits[j] = (start_val >> (15 - j)) & 1

    valid = True
    for i in range(len(expected) - 1):
        new_bit = bits[i] + (expected[i + 1] - expected[i])
        if new_bit not in (0, 1):
            valid = False
            break
        bits[i + 16] = new_bit

    if valid:
        # Convert bits to bytes
        flag_bytes = bytes(int(''.join(map(str, bits[i:i+8])), 2)
                          for i in range(0, total_bits, 8))
        if b'BCCTF' in flag_bytes or flag_bytes[:5].isascii():
            print(flag_bytes.decode(errors='replace'))
            break
```

**关键点：** 滑动窗口 popcount 的差值构成递推关系：每个新比特由 16 位之前的比特加上 popcount 增量唯一确定。只有前 16 位是自由的（受初始 popcount 约束）。暴力枚举约 4000-8000 个合法初始窗口——对每个窗口，整个比特序列都是确定的。一秒内可跑完。

**检测：** 二进制在固定长度窗口上计算 popcount/汉明重量；期望值数组长度 ≈ 输入比特数 - 窗口大小 + 1；数组元素是小整数（0 到窗口大小）。

---

<a id="morse-code-from-keyboard-leds-via-ioctl-plaidctf-2013"></a>
## 通过 ioctl 从键盘 LED 读摩尔斯码（PlaidCTF 2013）

**模式：** 二进制用 `ioctl(fd, KDSETLED, value)` 闪烁键盘 LED（Num/Caps/Scroll Lock），以时序模式编码摩尔斯码。

```bash
# Step 1: Bypass ptrace anti-debug
# Patch ptrace call at offset with NOP (0x90)
python3 -c "
data = open('binary','rb').read()
data = data[:0x72b] + b'\x90'*5 + data[0x730:]  # NOP the ptrace call
open('patched','wb').write(data)
"

# Step 2: Run under strace, capture ioctl calls
strace -e ioctl ./patched 2>&1 | grep KDSETLED > leds.txt

# Step 3: Decode timing patterns
# Short blink (250ms) = dit (.), long blink (750ms) = dah (-)
# Inter-character pause = 3x, inter-word pause = 7x
```

```python
# Parse strace output to extract Morse
import re
morse_map = {'.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E',
             '..-.':'F', '--.':'G', '....':'H', '..':'I', '.---':'J',
             '-.-':'K', '.-..':'L', '--':'M', '-.':'N', '---':'O',
             '.--.':'P', '--.-':'Q', '.-.':'R', '...':'S', '-':'T',
             '..-':'U', '...-':'V', '.--':'W', '-..-':'X', '-.--':'Y',
             '--..':'Z', '-----':'0', '.----':'1'}
# Map LED on-durations to dots/dashes, group by pauses
```

**关键点：** `KDSETLED` 控制 Linux 上的物理键盘 LED（`/dev/console`），程序必须有控制台访问权限。用 `strace -e ioctl` 捕获所有 LED 状态变化，无需肉眼观察。调用之间的时间间隔决定点还是划。

---

<a id="c-destructor-hidden-validation-defcamp-2015"></a>
## C++ 析构函数隐藏校验（Defcamp 2015）

校验逻辑可能藏在 `main()` 返回后执行的 C++ 析构函数里。`__cxa_atexit` 机制负责注册析构回调：

1. **定位析构函数：** 在 `.init_array`/构造函数区中搜索 `__cxa_atexit` 调用
2. **静态分析：** 找出析构函数中执行 flag 校验的全局对象
3. **动态验证：** 在 `__cxa_finalize` 下断，跟踪 main 之后的执行

```asm
# In IDA/Ghidra: look for atexit registrations
__cxa_atexit(destructor_func, object_ptr, dso_handle);

# Destructor contains actual validation:
# - Regex pattern matching on 4-byte blocks (8 sequential checks)
# - Arithmetic: v2 += -3 * s[i] + 36 + (s[i] ^ 0x2FCFBA)
# - Modular verification of accumulated sum
```

**关键点：** 当 `main()` 看起来过于简单或不完整时，检查全局/静态 C++ 对象的析构函数。`.fini_array` 节和 `__cxa_atexit` 注册项会暴露 main 之后的隐藏逻辑。

---

<a id="syscall-side-effect-memory-corruption-hacklu-2015"></a>
## 系统调用副作用导致内存破坏（Hack.lu 2015）

`rt_sigprocmask` 系统调用会向输出指针写入一个 `sigset_t` 结构。当输入解析给出的指针紧邻安全关键变量时：

1. 某些输入字符（例如 `:` 到 `@` 范围，即 0x3A-0x40）会作为副作用触发 `rt_sigprocmask`
2. 该调用把输出地址处的字节清零，这些字节可能与相邻变量重叠
3. 在小端布局下，把相邻整数变量的最高字节清零，等价于把它置成一个小值

```c
// Memory layout (no ASLR):
// 0x603390: input_buffer[4]
// 0x603394: security_check_var

// Input ':' triggers: rt_sigprocmask(SIG_BLOCK, NULL, (sigset_t*)0x603397, ...)
// This zeros bytes at 0x603397+, corrupting security_check_var's high bytes
```

**关键点：** 审查输入校验函数与系统调用的交互。十六进制转换例程中的“字符→系统调用”映射，可能通过内核态操作产生意料之外的内存写入。

---

<a id="mfc-dialog-event-handler-location-whitehat-2015"></a>
## 定位 MFC 对话框事件处理器（WhiteHat 2015）

在 MFC（Microsoft Foundation Class）应用中找事件处理器：

1. **在 SendMessageW 下断：** 对 `user32!SendMessageW` 下断，拦截对话框消息
2. **筛选 WM_COMMAND：** 消息 ID 0x111 对应按钮点击与控制事件
3. **跟踪消息映射：** 沿 MFC 分发路径 `CWnd::OnWndMsg` → `CCmdTarget::OnCmdMsg` → 处理器函数
4. **OnInitDialog：** 常含解密或校验初始化；由 WM_INITDIALOG（0x110）触发

```asm
# WinDbg/x64dbg:
bp user32!SendMessageW ".if (poi(@esp+8)==0x111) {} .else {gc}"
# Or in IDA: find cross-references to AFX_MSGMAP_ENTRY structures
```

**关键点：** MFC 应用通过分发表路由消息。定位 `AFX_MSGMAP` 结构即可静态枚举所有被处理的消息，无需运行时分析。

---

<a id="vm-sequential-key-chain-brute-force-midnight-flag-2026"></a>
## VM 顺序密钥链暴力（Midnight Flag 2026）

**模式（67）：** 自定义 VM 按 N 字节块校验输入。每块的输出密钥作为下一块的输入，无法并行求解。但单块搜索空间足够小，可以直接暴力（3 字节块为 2^24）。

**识别迹象：**
- 操作码被 XOR 混淆过的字节码（所有字节与同一常量 XOR，结果看起来像 ASCII）
- 迭代变换循环（xorshift + 乘法，重复 1000+ 次），使代数求逆不现实
- CHECK 操作码把累积状态与内嵌常量比较
- 大量重复字节码模式的巨大 `.data` 段

**求解思路：**
1. 解析字节码，提取 CHECK 值（每块之后的期望密钥）
2. 逐块暴力搜索能产生期望密钥的输入字节
3. 把 CHECK 值作为下一块的密钥

```c
// OpenMP-parallelized per-block brute-force
uint32_t process(uint32_t val) {
    for (int i = 0; i < 1000; i++) {
        val ^= (val << 13);
        val ^= (val >> 17);
        val ^= (val << 5);
        val *= 0x2545f491;
    }
    return val;
}

int solve_block(uint32_t old_key, uint32_t expected_key, unsigned char *out) {
    int found = 0;
    #pragma omp parallel for shared(found)
    for (int v = 0; v < 0x1000000; v++) {
        if (found) continue;
        uint32_t input_val = ((v >> 16) << 16) | (v & 0xFF) | ((v >> 8 & 0xFF) << 8);
        uint32_t saved = input_val ^ old_key;
        uint32_t final_val = process(saved);
        if ((final_val ^ saved) == expected_key) {
            #pragma omp critical
            { if (!found) { out[0]=v>>16; out[1]=(v>>8)&0xFF; out[2]=v&0xFF; found=1; } }
        }
    }
    return found;
}
// Compile: gcc -O3 -march=native -fopenmp -o solve solve.c
```

**关键点：** 当变换被有意设计成不可逆（迭代式类哈希函数）时，暴力就是预期解法。OpenMP 并行至关重要——287 块、每块 1670 万个候选，并行几分钟，单线程要几小时。密钥的顺序依赖意味着各块必须按序求解，但单个块的搜索是完全可并行的。

---

<a id="burrows-wheeler-transform-inversion-without-terminator-asis-ctf-finals-2016"></a>
## 无终止符的 Burrows-Wheeler 逆变换（ASIS CTF Finals 2016）

BWT 作用于二进制表示且没有标准终止字符。需要枚举所有可能的原串来暴力求逆。

```python
def bwt_inverse_bruteforce(bwt_string):
    """Invert BWT when no terminating character is present.
    Standard BWT inverse needs the terminator position.
    Without it, try all n possible rotations."""
    n = len(bwt_string)

    # Standard BWT inverse produces a table
    table = [''] * n
    for _ in range(n):
        table = sorted([bwt_string[i] + table[i] for i in range(n)])

    # Without terminator, all n rows are valid candidates
    # Filter by known constraints (e.g., starts with '1' for binary, matches XOR pattern)
    candidates = []
    for row in table:
        # Apply challenge-specific validation
        if is_valid_plaintext(row):
            candidates.append(row)

    return candidates

def bwt_with_xor_rounds(encrypted_hex, num_rounds):
    """Multi-round BWT with XOR key derived from round index"""
    data = bytes.fromhex(encrypted_hex)
    for round_idx in range(num_rounds - 1, -1, -1):
        # Each round: BWT on binary representation, then XOR with round-based key
        binary_str = ''.join(format(b, '08b') for b in data)
        candidates = bwt_inverse_bruteforce(binary_str)
        # Select candidate matching constraints (leading '1', trailing bit rule)
        data = select_valid_candidate(candidates, round_idx)
    return data
```

**关键点：** 标准 BWT 用一个终止字符（如 `$`）标记原串位置。没有它时，逆变换会产生 n 个候选（每个旋转一个）。用领域约束（二进制格式、XOR 轮次结构、flag 前缀）挑出正确候选。

---

<a id="opentype-font-ligature-exploitation-for-hidden-messages-hack-the-vote-2016"></a>
## 利用 OpenType 字体连字隐藏信息（Hack The Vote 2016）

带自定义 OpenType 连字的字体文件，会把可见字符映射到隐藏字形。GSUB（字形替换）表定义了这些映射。

```python
from fontTools.ttLib import TTFont

def decode_font_ligatures(font_path, encoded_text):
    """Extract ligature substitution table and decode message"""
    font = TTFont(font_path)

    # Extract GSUB table for ligature substitutions
    gsub = font['GSUB']

    # Navigate to ligature lookup
    ligature_map = {}
    for lookup in gsub.table.LookupList.Lookup:
        for subtable in lookup.SubTable:
            if hasattr(subtable, 'ligatures'):
                for glyph_name, ligatures in subtable.ligatures.items():
                    for lig in ligatures:
                        # Map: input sequence -> output glyph
                        input_seq = [glyph_name] + lig.Component
                        output = lig.LigGlyph
                        ligature_map[tuple(input_seq)] = output

    print("Ligature mappings found:")
    for inp, out in ligature_map.items():
        print(f"  {inp} -> {out}")

    # Alternative: convert TTF to XML for manual analysis
    # font.saveXML('font_dump.xml')
    # Search for <LigatureSubst> entries

# Command-line approach:
# pip install fonttools
# ttx font.otf  # converts to XML
# grep -A5 'LigatureSubst' font.ttx
```

**关键点：** 带 GSUB 连字表的自定义字体构成一种密码：显示出来的字符与其字形映射并不一致。`fonttools` 的 `ttx` 命令能把字体导出为 XML，连字替换表一目了然。每个连字把一段输入字符序列映射到另一个输出字形。

---

<a id="glsl-shader-vm-with-self-modifying-code-apoorvctf-2026"></a>
## 带自修改代码的 GLSL Shader VM（ApoorvCTF 2026）

**模式（Draw Me）：** 一个 WebGL2 片元着色器在 256x256 的 RGBA 纹理上实现图灵完备的 VM。该纹理既是程序内存也是显示输出。

**纹理布局：**
- **第 0 行：** 寄存器（像素 0 = 指令指针，像素 1-32 = 通用寄存器）
- **第 1-127 行：** 程序内存（RGBA = opcode, arg1, arg2, arg3）
- **第 128-255 行：** VRAM（显示输出）

**操作码：** NOP(0)、SET(1)、ADD(2)、SUB(3)、XOR(4)、JMP(5)、JNZ(6)、VRAM-write(7)、STORE(8)、LOAD(9)。每帧 16 步。

**自修改代码：** 第 1 阶段（解密）用 STORE 操作码对程序内存做 XOR 补丁，第 2 阶段（绘制）再执行这些被改写的内容。解密在绘制代码运行前，把 SET 指令覆盖为正确的像素颜色值。

**为什么 GPU 直接渲染会失败：** GPU 每帧并行跑所有像素，但着色器对每个像素每帧只跟踪**一个**写入目标。一帧内多次 VRAM 写入只有最后一次存活——丢失 75%+ 的像素。同理，并行解密时 STORE 补丁也会互相冲突。

**改用顺序模拟求解：**
```python
from PIL import Image
import numpy as np

img = Image.open('program.png').convert('RGBA')
state = np.array(img, dtype=np.int32).copy()
regs = [0] * 33

# Phase 1: Trace decryption — apply all STORE patches sequentially
x, y = start_x, start_y
while True:
    r, g, b, a = state[y][x]
    opcode = int(r)
    if opcode == 1: regs[g] = b & 255           # SET
    elif opcode == 4: regs[g] = regs[b] ^ regs[a]  # XOR
    elif opcode == 8:                              # STORE — patches program memory
        tx, ty = regs[g], regs[b]
        state[ty][tx] = [regs[a], regs[a+1], regs[a+2], regs[a+3]]
    elif opcode == 5: break                        # JMP to drawing phase
    x += 1
    if x > 255: x, y = 0, y + 1

# Phase 2: Execute drawing code — all VRAM writes preserved
vram = np.zeros((128, 256), dtype=np.uint8)
# ... trace with opcode 7 writing to vram[ty][tx] = color
Image.fromarray(vram, mode='L').save('output.png')
```

**关键点：** GLSL 着色器图灵完备，但 GPU 的并行性会造成写冲突。自修改代码（STORE 补丁）让问题更严重——并行执行产生的补丁会互相覆盖。用 Python 做顺序模拟即可恢复完整输出。`program.png` 文件本身就是字节码。

**检测：** WebGL/shader 题目附带一个 PNG “程序”文件，题面说“什么都渲染不出来”或输出乱码。留意 GLSL 源码中的自定义操作码表。

---

<a id="instruction-counter-as-cryptographic-state-metactf-flash-2026"></a>
## 以指令计数器作为密码学状态（MetaCTF Flash 2026）

**模式（Who's Counting?）：** 手写汇编二进制用一个专用寄存器（如 `r12`）作为指令计数器，几乎每条指令后自增。该计数值参与每个输入字节的 XOR、ROL 和乘法变换，使整条变换路径依赖于“处理到该字节之前执行了多少条指令”。

**识别特征：**
- 手写汇编（没有编译器特征，寄存器用法反常）
- 某个寄存器只做自增（`inc r12` 或 `add r12, 1`），且出现在大多数指令之后
- 变换中引用了这个计数器寄存器（`xor rax, r12`，或 `cl` 派生自计数器的 `rol al, cl`）
- 顺序逐字节处理循环，状态向后传递

**求解思路：**
```python
# Byte-by-byte brute force with emulation
# Since each byte's transformation depends on the counter (which depends
# on all prior instructions), state is path-dependent.

from unicorn import *
from unicorn.x86_const import *

def try_byte(known_prefix, candidate_byte):
    """Emulate binary with known prefix + candidate, check output."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # Map code, stack, data segments
    uc.mem_map(CODE_BASE, 0x10000)
    uc.mem_write(CODE_BASE, binary_code)
    uc.mem_map(STACK_BASE, 0x10000)
    uc.mem_map(DATA_BASE, 0x10000)

    # Write input: known_prefix + candidate
    test_input = known_prefix + bytes([candidate_byte])
    uc.mem_write(DATA_BASE, test_input + b'\x00' * (64 - len(test_input)))

    # Set up registers (rsp, rdi pointing to input, r12 = 0)
    uc.reg_write(UC_X86_REG_RSP, STACK_BASE + 0x8000)
    uc.reg_write(UC_X86_REG_R12, 0)  # instruction counter starts at 0

    try:
        uc.emu_start(CODE_BASE + ENTRY_OFFSET, CODE_BASE + EXIT_OFFSET)
        # Read transformed output, compare against expected
        output = uc.mem_read(OUTPUT_ADDR, len(test_input))
        return output[:len(test_input)] == expected[:len(test_input)]
    except:
        return False

# Recover flag byte by byte
flag = b''
for pos in range(FLAG_LEN):
    for b in range(256):
        if try_byte(flag, b):
            flag += bytes([b])
            print(f"Position {pos}: {chr(b)} -> {flag}")
            break
```

**关键点：** 当某个寄存器充当指令计数器并参与字节变换时，第 N 个字节的变换取决于处理前 N-1 个字节期间执行的精确指令数。这使得解析求逆不可行，因为每个字节位置上的计数值依赖于穿过此前所有字节的执行路径。逐字节暴力 + 完整模拟（Unicorn 或 GDB 脚本）是最可靠的方法——对每个位置试遍 256 个值，并保留正确前缀带来的状态。

**何时能识别：** 二进制没有标准库调用，一贯使用反常寄存器，且存在只增不减的寄存器。每个字节的变换含引用该计数器的操作（XOR、rotate、multiply）。题名暗示“计数”或“指令”。

**备选方法：**
- GDB 脚本：在每个字节变换后下断，比较输出
- 静态分析：手工数指令来算出计数值，再代数反演变换（因计数器累积而易错）

**参考：** MetaCTF Flash CTF 2026 "Who's Counting?"

---

<a id="thread-race-condition-with-signed-integer-overflow-codegate-2017"></a>
## 带符号整数溢出的线程竞争（Codegate 2017）

**模式（Hunting）：** 游戏二进制在技能选择上存在线程安全问题。攻击线程用有符号比较检查 `skill_id <= 4`，然后短暂 sleep 再结算伤害。sleep 期间切换到另一个技能。火球技能使用 `cdqe`（把 EAX 符号扩展为 RAX），把 `0xFFFFFFFF`（冰剑伤害）转成有符号 64 位的 `-1`。从 Boss 的 HP（`0x7FFFFFFFFFFFFFFF`）中减去 `-1` 会触发有符号溢出变成负数，直接击杀 Boss。

```python
# Race condition exploit:
# Thread A: select fireball (skill_id=2, passes <= 4 check)
# Thread A: sleeps for animation
# Main: switch to icesword (skill_id=5, damage=0xFFFFFFFF)
# Thread A: wakes, reads damage from icesword slot
# cdqe: 0xFFFFFFFF -> 0xFFFFFFFFFFFFFFFF (-1 signed)
# boss_hp -= (-1) -> boss_hp = 0x7FFFFFFFFFFFFFFF + 1 = negative -> dead

import time, threading
def race():
    select_skill(2)  # fireball - passes bounds check
    time.sleep(0.001)
    select_skill(5)  # icesword - race into damage calculation
```

**关键点：** `cdqe`（Convert Doubleword to Quadword Extension）把 32 位 EAX 符号扩展为 64 位 RAX。当攻击代码读取 32 位伤害值并做符号扩展时，`0xFFFFFFFF` 变成 `-1`。减去负数相当于加 HP，但如果 HP 已在 `INT64_MAX`，加法会溢出为负数，直接击杀目标。

---

<a id="esp32xtensa-firmware-reversing-with-rom-symbol-map-insomnihack-2017"></a>
## 借助 ROM 符号表逆向 ESP32/Xtensa 固件（Insomni'hack 2017）

**模式（Internet of Fail）：** ESP32 固件（Xtensa 架构），IDA 原生不支持。用 radare2 配合 ESP32 的 ROM 链接脚本（`esp32.rom.ld`）把函数地址映射为名字。再对照公开的 ESP32 HTTP 服务器源码，识别出由约 20 个作用在全局状态变量上的条件 XOR 函数组成的口令校验逻辑。

```bash
# Load ESP32 firmware in radare2
r2 -a xtensa -b 32 firmware.bin

# Apply ROM symbol map from ESP-IDF
# esp32.rom.ld maps addresses like:
# 0x40000000 = ets_printf
# 0x400013A0 = cache_Read_Enable
# Load as flags: . esp32.rom.ld.r2

# Identify HTTP request handler by cross-referencing
# with esp-idf/examples/protocols/http_server
# Look for URI handler registration patterns
```

**关键点：** ESP32 的 Xtensa 架构缺乏主流逆向工具支持，但 ESP-IDF SDK 提供了 ROM 链接脚本，把每个 ROM 函数地址映射到名字。在 radare2 中把它作为符号载入，立刻能解析数百个函数调用。再对照公开的 ESP-IDF 示例代码，即使在去符号固件中也能识别出应用层模式（HTTP 处理器、WiFi 回调）。

---

<a id="batch-crackme-automation-via-objdump-pattern-extraction-def-con-2017"></a>
## 用 objdump 模式提取批量破解 crackme（DEF CON 2017）

通过脚本化 `objdump`，从数百个结构相同的 crackme 中提取比较值与算术操作，不执行程序就能算出密钥。

```bash
# Simple variant: extract CMP immediates directly
objdump -M intel -d $binary | grep -P "cmp\s+rdi" | \
    grep -oP "0x\w{1,2}" | xxd -r -p

# Complex variant: parse add/sub/cmp chains and reverse-compute
# Each binary: series of add/sub rdi,N then cmp rdi,target
# Reverse: start from target, undo operations in reverse order
python3 <<'EOF'
import subprocess, re, glob
for binary in sorted(glob.glob("crackmes/*")):
    asm = subprocess.check_output(["objdump", "-M", "intel", "-d", binary]).decode()
    ops = re.findall(r'(add|sub)\s+rdi,(0x\w+)', asm)
    target = int(re.search(r'cmp\s+rdi,(0x\w+)', asm).group(1), 16)
    # Reverse operations
    for op, val in reversed(ops):
        val = int(val, 16)
        target = (target - val) if op == 'add' else (target + val)
    print(chr(target & 0xff), end='')
EOF
```

**关键点：** 批量 crackme 题目（成百上千个二进制）结构完全相同，只是常量不同。脚本化解析 `objdump` 反汇编，提取立即数与算术序列，再代数反推密钥。无需执行或模拟。

---

<a id="fork--pipe--dead-branch-anti-analysis-rctf-2017"></a>
## Fork + 管道 + 死分支反分析（RCTF 2017）

二进制使用 fork/管道 IPC：父进程写数据后退出，子进程从管道读取后继续。真正的校验藏在一个永远为假的分支里，必须打补丁才能到达。

```bash
# Detection: fork() + pipe() + read()/write() in main
# The child process reads from pipe, needs to know its own PID

# Dead branch pattern:
# cmp DWORD PTR [ebp-0xc], 0x1  ; compares 0 with 1, always false
# je  real_flag_computation      ; never taken

# Patch: change comparison value from 0x1 to 0x0
# Find: 83 7d f4 01 → change to: 83 7d f4 00
python3 -c "
data = open('binary','rb').read()
data = data.replace(b'\x83\x7d\xf4\x01', b'\x83\x7d\xf4\x00')
open('binary_patched','wb').write(data)
"
```

**关键点：** fork+管道建立父子关系，父进程提供数据后退出。死分支（永远为假的比较）藏起真正的校验逻辑。`strace` 能暴露 fork/pipe/read 模式；修改比较常量即可到达隐藏代码路径。

---

<a id="time-locked-binary-with-date-based-key-hacklu-2017"></a>
## 按日期上锁的二进制（Hack.lu 2017）

二进制读取系统日期，只在特定日期（例如 2012 年 12 月 21 日）才正确执行。该日期常量在二进制中表现为 Unix 时间戳或结构化日期比较。

**检测：** 寻找与落在可识别日期区间的大整数常量做比较（Unix 时间戳：2012 年约 1.35B，2017 年约 1.5B）。文化含义是线索：世界末日日期、CTF 发布日、历史事件。

```bash
# Set system clock to the required date
sudo date -s "2012-12-21 00:00:00"
./binary

# Or use faketime to avoid system-wide change
LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="2012-12-21 00:00:00" ./binary

# Restore system time afterward
sudo ntpdate pool.ntp.org
```

**在 IDA/Ghidra 中：** 搜索 `time()` 或 `localtime()` 调用。要关注的 `tm` 结构字段：`tm_year`（距 1900 的年数）、`tm_mon`（从 0 开始）、`tm_mday`。

**关键点：** 基于时间的密钥常使用有文化含义的日期。逆向代码中要始终留意日期比较，在深入分析前先试改系统时钟或用 faketime。

**参考：** Hack.lu CTF 2017

---

<a id="arm-code-in-image-pixels-via-unicornjs-hacklu-2017"></a>
## 用 UnicornJS 执行藏在图像像素中的 ARM 代码（Hack.lu 2017）

JavaScript 题目把 ARM 字节码嵌入图像像素数据。图像在 HTML/JS 源码中经 base64 编码。像素的 RGBA 值编码 ARM 指令。随附的 UnicornJS 库（JavaScript 实现的 ARM CPU 模拟器）负责提取并执行这些字节码。

**识别流程：**
1. 在 JS 源码中找到 base64 块 → 解码 → 得到 PNG/BMP 文件
2. 确认引入了 UnicornJS（`unicorn.js`、`uc.js` 等）→ 说明是 ARM 模拟
3. 提取像素循环：按光栅顺序拼接 RGBA 字节，构成 ARM 指令流
4. 把提取出的字节交给 ARM 反汇编器

```python
from PIL import Image
import capstone

img = Image.open('decoded.png').convert('RGBA')
pixels = list(img.getdata())

# Extract ARM bytecode from pixel data (4 bytes per pixel: R, G, B, A)
arm_code = bytes([channel for pixel in pixels for channel in pixel])

# Disassemble as ARM Thumb or ARM32
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
for insn in md.disasm(arm_code, 0x0):
    print(f"0x{insn.address:04x}: {insn.mnemonic} {insn.op_str}")
```

**关键点：** 多层混淆：ARM 代码藏在图像像素里，经 base64 编码，运行时由 UnicornJS 模拟执行。先确认模拟器库，才能知道要逆向哪种 ISA——库名就暴露了架构。

**参考：** Hack.lu CTF 2017

---

<a id="x86-16-bit-mbr-psadbw-constraint-solving-csaw-2017"></a>
## x86 16 位 MBR 的 psadbw 约束求解（CSAW 2017）

可启动 MBR 用 SSE2 的 `psadbw`（Packed Sum of Absolute Differences of Bytes）作用于 xmm 寄存器来校验 flag。每轮掩码 2 个输入字节，针对已知常量计算 `psadbw`，再把和与期望值比较。

**`psadbw` 语义：**
```asm
psadbw xmm0, xmm1
; For each of 8 byte pairs: sum += |xmm0[i] - xmm1[i]|
; Result stored as 16-bit integer in low qword of xmm0
```

这会生成绝对差之和方程：
```text
|a[0] - k[0]| + |a[1] - k[1]| + ... + |a[7] - k[7]| = C
```

**求解思路：**
```python
import numpy as np
from itertools import product

# For each 2-byte masked group, extract the constants and expected sum
# Equations are not purely linear (absolute value), but printable ASCII
# constrains each byte to [0x20, 0x7e], limiting brute-force space

def solve_psadbw_group(known_constants, expected_sum, printable_range=(0x20, 0x7e)):
    """Brute-force 2 unknown bytes given sum-of-abs-diff constraint."""
    solutions = []
    for a, b in product(range(*printable_range), repeat=2):
        pair = [a, b]
        sad = sum(abs(pair[i] - known_constants[i]) for i in range(len(pair)))
        if sad == expected_sum:
            solutions.append(bytes([a, b]))
    return solutions

# For ambiguous cases with multiple solutions: apply additional constraints
# (flag format prefix, character frequency, subsequent iterations)
```

**关键点：** `psadbw` 产生绝对差之和方程——不是纯线性，但当字节限于可打印 ASCII 时可用受限暴力求解。每组 2 字节相互独立，搜索空间只有 95^2 ≈ 9000 个候选。

**参考：** CSAW CTF 2017

---

<a id="tensorflow-dnn-inversion-by-inverting-sigmoid-layers-n1ctf-2018"></a>
## 逐层反演 sigmoid 还原 TensorFlow 深度网络（N1CTF 2018）

**模式：** 二进制实现了一个 5 层、sigmoid 激活的深度神经网络。输入（flag 字符）在送入网络前先变换为 `1.0/char_value`。从二进制中提取权重与偏置，再逐层反演：应用反 sigmoid、减去偏置、乘以权重矩阵的逆。

```python
import numpy as np

def sigmoid_inv(x):
    return -np.log(1.0/x - 1.0)

# Invert layer by layer from output to input
v = target_output
for i in range(num_layers - 1, -1, -1):
    v = np.dot(sigmoid_inv(v) - biases[i], np.linalg.inv(weights[i]))

# Input was 1.0/char, so flag chars are the multiplicative inverse
flag = ''.join(chr(int(round(1.0 / v[j]))) for j in range(len(v)))
```

**关键点：** 使用可逆激活函数（sigmoid、tanh）且权重矩阵为方阵的神经网络，可以在数学上逐层反演。应用反 sigmoid、减去偏置、乘以权重逆矩阵。注意还要反演输入端的变换（例如 1/x）。

**检测：** 使用 TensorFlow 或自定义 DNN 实现的二进制。留意 sigmoid/tanh 调用、矩阵乘法，以及 `.rodata` 中硬编码的浮点数组（权重/偏置）。方阵权重（N x N）意味着网络可逆。

**参考：** N1CTF 2018

---

<a id="bpf-filter-analysis-via-jit-compilation-to-x64-assembly-midnight-sun-ctf-2018"></a>
## 把 BPF 过滤器 JIT 编译为 x64 汇编再分析（Midnight Sun CTF 2018）

**模式：** 二进制创建原始套接字并挂上 BPF（Berkeley Packet Filter）。当标准 BPF 反汇编器给不出可读输出时，打开内核的 BPF JIT 编译器，把 BPF 字节码转成原生 x64 汇编，再从 dmesg 中读取编译结果。

```bash
# Enable BPF JIT compilation
echo 1 > /proc/sys/net/core/bpf_jit_enable

# Run the binary, then read JIT-compiled BPF from kernel log
dmesg | grep -A 100 "flen="

# Analysis revealed: expects DNS TXT query on UDP port 3333
dig @target -p 3333 'M4d!bKn3~l' TXT
```

**关键点：** Linux 能把 BPF 过滤器 JIT 编译为原生 x64 机器码。当标准 BPF 反汇编器失败或输出不可读时，打开 `bpf_jit_enable` 并从 dmesg 读取编译后的汇编。原生代码往往比 BPF 字节码更好懂。

**检测：** 二进制用 `setsockopt` 搭配 `SO_ATTACH_FILTER`、创建原始套接字（`socket(AF_PACKET, ...)`），或内嵌 `struct sock_fprog` 结构。BPF 程序表现为 `struct sock_filter` 数组（每项 8 字节：opcode、jt、jf、k）。

**参考：** Midnight Sun CTF 2018

---

<a id="single-byte-xor-rom-deobfuscation-sweep-x-mas-ctf-2018"></a>
## 单字节 XOR ROM 反混淆扫描（X-MAS CTF 2018）

**模式：** 一大块不透明数据（GBA ROM、固件、游戏二进制），`binwalk`/`file` 识别不出来。遍历全部 256 个单字节 XOR 密钥，对每个结果再跑 `file` + `strings`；正确的密钥会暴露出可识别的魔数/签名。

```bash
for i in $(seq 0 255); do
  python3 -c "
import sys
k = $i
d = open('blob.bin','rb').read()
open(f'xor_{k}','wb').write(bytes(b^k for b in d))" 
  file "xor_$i" | grep -v data
done
strings "xor_0x42" | grep -i "POKEMON\|ELF\|MZ"
```

**关键点：** 暴力 256 个 XOR 密钥只需几秒，却能破掉任何单字节 XOR 打包。在假设存在自定义算法之前，先跑一遍这个扫描；在输出中找格式魔数（`ELF`、`PK`、`MZ`、`PDF-`、ROM 名称字符串）。

**参考：** X-MAS CTF 2018 — Unown Gift，writeup 12665

---

<a id="webkit-arrayslice-oob-cve-2016-4622-codegate-2019"></a>
## WebKit Array.slice 越界 CVE-2016-4622（Codegate 2019）

**模式：** 题目提供一个 WebKit 二进制，其中 `ArrayPrototype.cpp` 里的 `isJSArray(thisObj) && length == toLength(...)` 边界检查被注释掉了。于是 `Array.prototype.slice` 会越过底层存储读取，造成对相邻 JS 对象的越界访问。串联 Saelo 的 `addrof` / `fakeobj` 原语，即可在 JS 堆中获得任意读写，再通过伪造的 `StructureID` 转向原生代码执行。

```javascript
let oob = new Array(8);
let victim = {a: 1};
let leak = oob.slice(-1, oob.length + 16)[0];  // reads past backing store
```

**关键点：** 任何修改掉安全检的 JIT/引擎题目，几乎都等价于暴露一个经典浏览器 CVE 原语。把仓库内源码与上游 `ArrayPrototype.cpp`、`JSArray.cpp`、`JITOperations.cpp` 对比，找被删掉的 `if`/`assert`——那就是漏洞所在。

**参考：** Codegate CTF 2019 — Butterfree，writeup 12902

---

<a id="multi-modulus-crt-keygen-with-matrix-lookup-password-pragyan-ctf-2019"></a>
## 多模数 CRT 注册机 + 矩阵查表口令（Pragyan CTF 2019）

**模式（Super Secure Vault）：** `main` 要求输入一个数字 `key`（≤30 位），并用五个相互独立的模方程校验，这些模数来自对硬编码大数 `N = "27644437104591489104652716127"` 的切分：`[27644437, 10459, 1489, 1046527, 16127]`：

```
key mod 27644437 == 213
key mod 10459    == 229
key mod 1489     == 25
key mod 1046527  == 83
key mod 16127    == 135
```

五个模数两两互质，由中国剩余定理得到最小的合法 `key = 3087629750608333480917556`。`scanf` 之后，`func2(password, key, N)` 把 `key + N + "80"` 拼成 `v12`，然后对每个口令字节用一张 10000 字节的查找表校验：

```python
# Round 1: index = 100*(10*d0 + d1) + 10*d_mid + d_mid+1
# Round 2: index = 100*((10*d0+d1)**2 % 97) + ((10*d_mid+d_mid+1)**2 % 97)
password = b""
v8, v10 = 0, len(v12) // 2
while v8 < len(v12) // 2:
    idx = 100 * (10*v12[v8] + v12[v8+1]) + 10*v12[v10] + v12[v10+1]
    password += bytes([matrix[idx]]); v8 += 2; v10 += 2
v9, v11 = 0, len(v12) // 2
while v9 < len(v12) // 2:
    a = 10*v12[v9] + v12[v9+1]; b = 10*v12[v11] + v12[v11+1]
    password += bytes([matrix[100*(a*a % 97) + b*b % 97]])
    v9 += 2; v11 += 2
```

CRT（用 `sympy.ntheory.modular.crt` 或手写 `mul_inv`）加上从二进制里 dump 出的 `matrix`，即可复现 flag `pctf{R3v3rS1Ng_#s_h311_L0t_Of_Fun}`。

**关键点：** 五个互质模数把 key 唯一地钉在它们乘积（约 4.7e19）的某个余类上，而该范围落在 30 位输入之内——取最小代表元即可，不要暴力，否则会在 10 万个以上同样合法但难看的 key 上浪费数小时。第二阶段看着复杂，实际只是两组固定的索引生成函数查一张静态表；dump 一次表，两轮都退化成直接的数组读取。

**参考：** Pragyan CTF 2019 — Super Secure Vault，writeup 13760

---

另见：[patterns-ctf.md](patterns-ctf.md) 第一部分，[patterns-ctf-2.md](patterns-ctf-2.md) 第二部分（多层自解密二进制、内嵌 ZIP+XOR 许可证、栈上字符串反混淆、前缀哈希暴力、CVP/LLL 格、决策树混淆、GF(2^8) 高斯消元）。
