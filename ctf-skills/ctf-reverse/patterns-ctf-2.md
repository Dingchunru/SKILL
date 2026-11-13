# CTF Reverse - 赛事专用模式（第二部分）

## 目录
- [多层自解密二进制 (DiceCTF 2026)](#多层自解密二进制-dicectf-2026)
- [内嵌 ZIP + XOR 许可证解密 (MetaCTF 2026)](#内嵌-zip--xor-许可证解密-metactf-2026)
- [从 .rodata XOR 数据块还原栈字符串 (Nullcon 2026)](#从-rodata-xor-数据块还原栈字符串-nullcon-2026)
- [前缀哈希爆破 (Nullcon 2026)](#前缀哈希爆破-nullcon-2026)
- [约束整数校验的 CVP/LLL 格求解 (HTB ShadowLabyrinth)](#约束整数校验的-cvplll-格求解-htb-shadowlabyrinth)
- [决策树函数混淆 (HTB WonderSMS)](#决策树函数混淆-htb-wondersms)
- [GF(2^8) 高斯消元恢复 flag (ApoorvCTF 2026)](#gf28-高斯消元恢复-flag-apoorvctf-2026)
- [改写二进制中的 ROP 链混淆 (PlaidCTF 2016)](#改写二进制中的-rop-链混淆-plaidctf-2016)

---

<a id="multi-layer-self-decrypting-binary-dicectf-2026"></a>
## 多层自解密二进制 (DiceCTF 2026)

**模式（another-onion）：** 二进制包含 N 层（例如 256 层），每层读取 2 个密钥字节，通过 SHA-256 NI 指令派生密钥流，对下一层做 XOR 解密，然后跳转过去执行。必须在时限内解出（例如 30 分钟）。

**判断密钥正确的 oracle：** 错误的密钥字节会产生垃圾代码；正确的密钥字节产生的代码中恰好有 2 条 `call read@plt` 指令（下一层的两次读取）。用这个 oracle 对每层暴力枚举全部 65536 种组合。

**JIT 执行方案（最快）：**
```c
// Map binary's memory at original virtual addresses into solver process
// Compile solver at non-overlapping address: -Wl,-Ttext-segment=0x10000000
void *text = mmap((void*)0x400000, text_size, PROT_RWX, MAP_FIXED|MAP_PRIVATE, fd, 0);
void *bss = mmap((void*)bss_addr, bss_size, PROT_RW, MAP_FIXED|MAP_SHARED, shm_fd, 0);

// Patch read@plt to inject candidate bytes instead of reading stdin
// Patch tail jmp/call to next layer with ret/NOP to return from layer

// Fork-per-candidate: COW gives isolated memory without memcpy
for (int candidate = 0; candidate < 65536; candidate++) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child: remap BSS as MAP_PRIVATE (COW from shared file)
        mmap(bss_addr, bss_size, PROT_RW, MAP_FIXED|MAP_PRIVATE, shm_fd, 0);
        inject_key(candidate >> 8, candidate & 0xff);
        ((void(*)())layer_addr)();  // Execute layer as function call
        // Check: does decrypted code contain exactly 2 call read@plt?
        if (count_read_calls(next_layer_addr) == 2) signal_found(candidate);
        _exit(0);
    }
}
```

**性能档次：**
| 方案 | 速度 | 256 层估算 |
|----------|-------|--------------------|
| Python 子进程 | ~2/s | 数天 |
| Ptrace fork 注入 | ~119/s | 6+ 小时 |
| JIT + 每个候选 fork | ~1000/s | 140 分钟 |
| JIT + 共享 BSS + 32 工作进程 | ~3500/s | **~17 分钟** |

**共享 BSS 优化：** 把 BSS（16MB+）放在 `/dev/shm` 中，父进程以 `MAP_SHARED` 映射。子进程以 `MAP_PRIVATE` 重新映射以获得 COW 语义。这把 fork 的开销从 16MB 页表设置降到约 4KB。

**关键点：** 多层解密题本质上考查的是如何构建高速爆破引擎。JIT 执行（把二进制内存映射进解题进程，把代码当作函数直接调用）比 ptrace 快好几个数量级。基于 fork 的 COW 让每个候选天然获得独立的内存空间。

**易踩的坑：**
- 真实二进制可能用 `call`（0xe8）而非 `jmp`（0xe9）做层间跳转 —— 尾部补丁要相应调整
- BSS 可能通过内核 brk 映射超出 ELF 的 MemSiz —— 需要额外映射空间
- SHA-NI 指令即使 `/proc/cpuinfo` 未标注也可用

---

<a id="embedded-zip--xor-license-decryption-metactf-2026"></a>
## 内嵌 ZIP + XOR 许可证解密 (MetaCTF 2026)

**模式（License To Rev）：** 二进制要求以参数形式提供许可证文件。其中内嵌了一个包含期望许可证的 ZIP 归档，以及一段 XOR 加密的 flag。

**识别特征：**
- `strings` 中能看到 `EMBEDDED_ZIP` 和 `ENCRYPTED_MESSAGE` 符号
- 二进制未被 strip —— `nm` 或 `readelf -s` 能看到 `.rodata` 中的数据符号
- `file` 显示为 PIE 可执行文件，源文件名为 `licensed.c`

**分析流程：**
1. **定位数据符号：**
```bash
readelf -s binary | grep -E "EMBEDDED|ENCRYPTED|LICENSE"
# EMBEDDED_ZIP at offset 0x2220, 384 bytes
# ENCRYPTED_MESSAGE at offset 0x21e0, 35 bytes
```

2. **提取内嵌 ZIP：**
```python
import struct
with open('binary', 'rb') as f:
    data = f.read()
# Find PK\x03\x04 magic in .rodata
zip_start = data.find(b'PK\x03\x04')
# Extract ZIP (size from symbol table or until next symbol)
open('embedded.zip', 'wb').write(data[zip_start:zip_start+384])
```

3. **从 ZIP 中取出许可证：**
```bash
unzip embedded.zip  # Contains license.txt
```

4. **XOR 解密 flag：**
```python
license = open('license.txt', 'rb').read()
enc_msg = open('encrypted_msg.bin', 'rb').read()  # Extract from .rodata
flag = bytes(a ^ b for a, b in zip(enc_msg, license))
print(flag.decode())
```

**关键点：** 完全不需要运行二进制，也不需要绕过到期日期检查。内嵌 ZIP 和加密消息都在 `.rodata` 中 —— 离线提取后直接 XOR 即可。

**反汇编可以印证：**
- `memcmp(user_license, decompressed_embedded_zip, size)` —— 许可证校验
- 对 `EXPIRY_DATE=` 字段用 `sscanf("%d-%d-%d")` 解析日期
- XOR 循环：`ENCRYPTED_MESSAGE[i] ^ license[i]` → 逐字节 `putc()`

**经验：** 当二进制中存在具名符号（`EMBEDDED_*`、`ENCRYPTED_*`）时，直接从二进制中提取数据而不要执行它。与已知明文（这里是许可证）做 XOR 完全可以逆推。

---

<a id="stack-string-deobfuscation-from-rodata-xor-blob-nullcon-2026"></a>
## 从 .rodata XOR 数据块还原栈字符串 (Nullcon 2026)

**模式（stack_strings_1/2）：** 二进制对 `.rodata` 中的数据块执行 `mmap`，XOR 反混淆后，用该数据块校验输入。其解法是重新实现校验循环以恢复 flag。

**识别特征：**
- 出现 `mmap()` 调用，随后是对 `.rodata` 数据的 XOR 循环
- 校验循环带有滚动状态（`eax`、`ebx`、`r9`），并混入 `0x9E3779B9`、`0x85EBCA6B`、`0xA97288ED` 等常量
- 带位置相关移位量的 `rol32()` 运算
- 期望字节存放在反混淆后的缓冲区中

**方法：**
1. 用 pyelftools 提取 `.rodata` 数据块：
   ```python
   from elftools.elf.elffile import ELFFile
   with open(binary, "rb") as f:
       elf = ELFFile(f)
       ro = elf.get_section_by_name(".rodata")
       blob = ro.data()[offset:offset+size]
   ```
2. 结合反汇编中的已知密钥做 XOR，恢复内嵌常量（长度、魔数）
3. 重新实现逐字节校验循环：
   - 每次迭代：由滚动状态算出两个类似哈希的值
   - 把两者 XOR，再与期望字节 XOR，从而恢复输入字节
   - 用常量加法更新滚动状态

**变体（stack_strings_2）：** 增加了位置置换和与前一字符相关的状态依赖：
- 位置置换：字节 `i` 可能被放到输出位置 `pos[i]`
- 状态依赖：`need = (expected - rol8(prev_char, 1)) & 0xFF`
- 必须跟踪每次迭代后会更新为当前字符的 `state` 变量

**需要注意的关键常量：**
- `0x9E3779B9`（黄金分割小数部分，常见于哈希函数）
- `0x85EBCA6B`（MurmurHash3 终混常量）
- `0xA97288ED`（相关哈希常量）
- 移位量为 `i & 7` 的 `rol32()`

---

<a id="prefix-hash-brute-force-nullcon-2026"></a>
## 前缀哈希爆破 (Nullcon 2026)

**模式（Hashinator）：** 二进制对输入的每个前缀分别求哈希，每个前缀输出一个摘要。给定 N 个输出摘要，则 flag 长度为 N-1 个字符。

**攻击方式：** 逐字符恢复输入：
```python
for pos in range(1, len(target_hashes)):
    for ch in charset:
        candidate = known_prefix + ch + padding
        hashes = run_binary(candidate)
        if hashes[pos] == target_hashes[pos]:
            known_prefix += ch
            break
```

**关键点：** 如果每段前缀哈希相互独立（没有链式或 HMAC），问题就分解为 `N` × `|charset|` 次二进制执行。这就是分组密码逐字节攻击在哈希场景下的等价形式。

**识别：** 二进制会输出多行哈希。改变最后一个字符只会改变最后一行哈希；输入长度不同，输出的行数也不同。

---

<a id="cvplll-lattice-for-constrained-integer-validation-htb-shadowlabyrinth"></a>
## 约束整数校验的 CVP/LLL 格求解 (HTB ShadowLabyrinth)

**模式：** 二进制通过矩阵乘法校验 flag：把分组后的输入字符乘以系数矩阵，再与预期的 64 位结果比较。普通代数方法行不通，因为解必须落在可打印 ASCII（32-126）范围内。用 LLL 归约配合基于格的 CVP（最近向量问题）可以高效求解。

**识别：**
1. 二进制把输入字符分组（例如每 4 个一组）
2. 每组乘以一个系数矩阵
3. 结果与硬编码的 64 位值比较
4. 需要求出落在受限范围内的整数解（可打印 ASCII）

**SageMath CVP 求解器：**
```python
from sage.all import *

def solve_constrained_matrix(coefficients, targets, char_range=(32, 126)):
    """
    coefficients: list of coefficient rows (e.g., 4 values per group)
    targets: expected output values
    char_range: valid character range (printable ASCII)
    """
    n = len(coefficients[0])  # characters per group
    mid = (char_range[0] + char_range[1]) // 2

    # Build lattice: [coeff_matrix | I*scale]
    # The target vector includes adjusted targets
    M = matrix(ZZ, n + len(targets), n + len(targets))
    scale = 1000  # Weight to constrain character range

    for i, row in enumerate(coefficients):
        for j, c in enumerate(row):
            M[j, i] = c
        M[n + i, i] = 1  # padding

    for j in range(n):
        M[j, len(targets) + j] = scale

    target_vec = vector(ZZ, [t - sum(c * mid for c in row)
                              for row, t in zip(coefficients, targets)]
                        + [0] * n)

    # LLL + CVP
    L = M.LLL()
    closest = L * L.solve_left(target_vec)  # or use Babai
    solution = [closest[len(targets) + j] // scale + mid for j in range(n)]
    return bytes(solution)
```

**两阶段校验模式：**
1. **阶段一（矩阵运算）：** 用 CVP/LLL 求解 → 恢复前 N 个字符
2. 前 N 个字符作为 AES 密钥 → 解密 `file.bin`（XOR 最后 16 字节 + AES-256-CBC + zlib 解压）
3. **阶段二（自定义 VM）：** 解密后的字节码在自定义 VM 中运行，通过另一套线性方程组（模 2^32）校验剩余字符

**模线性方程组求解（阶段二 —— VM 校验）：**
```python
import numpy as np
from sympy import Matrix

# M * x = v (mod 2^32)
M_mod = Matrix(coefficients) % (2**32)
v_mod = Matrix(targets) % (2**32)
# Gaussian elimination in Z/(2^32)
solution = M_mod.solve(v_mod)  # Returns flag characters
```

**关键点：** 当二进制用大系数线性组合校验输入、而解必须落在小范围（可打印 ASCII）内时，这本质上就是一个格问题。LLL 归约 + CVP 找到最近的格点，从而恢复出受约束的解。

**识别：** 二进制对分组输入执行类矩阵运算，与 64 位常量比较，而朴素爆破空间过大（例如每组 256^4 × 12 组）。

---

<a id="decision-tree-function-obfuscation-htb-wondersms"></a>
## 决策树函数混淆 (HTB WonderSMS)

**模式：** 二进制把输入依次送入约 200+ 个自动生成的函数，每个函数基于输入位置计算一个多项式表达式，与常量比较后向左/右分支。如果不借助脚本提取，静态分析几乎不可行。

**识别：**
1. 大量结构相似、名字随机的函数（例如 `f315732804`）
2. 每个函数对特定输入位置做算术运算
3. 函数会调用其他树函数，或最终调用一个校验函数
4. 反编译代码形如 `if (expr cmp constant) call_left() else call_right()`

**用 Ghidra headless 做批量提取：**
```python
# Extract comparison constants from all tree functions
# Run via: analyzeHeadless project/ tmp -import binary -postScript extract_tree.py
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *

fm = currentProgram.getFunctionManager()
results = []
for func in fm.getFunctions(True):
    name = func.getName()
    if name.startswith('f') and name[1:].isdigit():
        # Find CMP instruction and extract immediate constant
        inst_iter = currentProgram.getListing().getInstructions(func.getBody(), True)
        for inst in inst_iter:
            if inst.getMnemonicString() == 'CMP':
                operand = inst.getOpObjects(1)
                if operand:
                    results.append((name, int(operand[0].getValue())))
```

**利用已知输出格式做约束传播：**
1. 从已知输出字节出发（例如 `http://HTB{...}`）→ 固定若干输入位置
2. 已固定的位置会沿算术约束级联 → 确定依赖位置
3. 树根方程锁定剩余自由变量
4. 从部分 flag 中识别英文单词，用于在多组解之间消歧

**关键点：** 自动生成的决策树看起来令人生畏，但构造上高度重复。与其逐个函数手工逆向，不如用脚本提取（Ghidra、Binary Ninja、radare2）。这棵树只是一个分派器 —— 真正的逻辑在叶子函数及其约束中。

**识别：** 二进制包含数百个结构相似的函数，每个函数引用 3-5 个输入位置，并分支到另外两个函数或同一个叶子函数。

---

<a id="gf28-gaussian-elimination-for-flag-recovery-apoorvctf-2026"></a>
## GF(2^8) 高斯消元恢复 flag (ApoorvCTF 2026)

**模式（Forge）：** strip 过的二进制在 GF(2^8)（256 个元素的伽罗瓦域，使用 AES 多项式）上执行高斯消元。矩阵和增广向量内嵌在 `.rodata` 中，解向量就是 flag。

**基于 AES 多项式（x^8+x^4+x^3+x+1 = 0x11b）的 GF(2^8) 运算：**
```python
def gf_mul(a, b):
    """Multiply in GF(2^8) with AES reduction polynomial."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b  # Reduction: x^8 = x^4+x^3+x+1
        b >>= 1
    return p

def gf_inv(a):
    """Brute-force multiplicative inverse (fine for 256 elements)."""
    if a == 0: return 0
    for x in range(1, 256):
        if gf_mul(a, x) == 1:
            return x
    return 0
```

**求解线性方程组：**
```python
# Extract N×N matrix + N-byte augmentation from binary .rodata
N = 56  # Flag length
# Build augmented matrix: N rows × (N+1) cols

for col in range(N):
    # Find non-zero pivot
    pivot = next((r for r in range(col, N) if aug[r][col] != 0), -1)
    if pivot != col:
        aug[col], aug[pivot] = aug[pivot], aug[col]
    # Scale pivot row by inverse
    inv = gf_inv(aug[col][col])
    aug[col] = [gf_mul(v, inv) for v in aug[col]]
    # Eliminate column in all other rows
    for row in range(N):
        if row == col: continue
        factor = aug[row][col]
        if factor == 0: continue
        aug[row] = [v ^ gf_mul(factor, aug[col][j]) for j, v in enumerate(aug[row])]

flag = bytes(aug[i][N] for i in range(N))
```

**关键点：** GF(2^8) 不是普通整数运算 —— 加法是 XOR，乘法要按多项式约减。最常见的约减多项式是 AES 的 0x11b；在反汇编中寻找常量 `0x1b`。二进制之后可能还会用 AES-GCM 加密结果，但原始解向量（加密前）就是 flag。

**识别：** `.rodata` 中有大矩阵（N² 字节）、基于 XOR 的行变换、常量 `0x1b` 或 `0x11b`，以及 flag 长度与矩阵规模的平方根相符。

---

<a id="rop-chain-obfuscation-in-modified-binary-plaidctf-2016"></a>
## 改写二进制中的 ROP 链混淆 (PlaidCTF 2016)

**模式（quite quixotic quest）：** 一个改造过的 `curl` 二进制，新增自定义选项 `--pctfkey KEY`。密钥校验时把 `esp` 指向某缓冲区地址并返回到存放在 `magic_buf` 符号中的约 250KB ROP 链。该 ROP 链通过 XOR、MD5 和常量比较来校验密钥。

**分析方法：**

1. **发现 ROP 分派：** 寻找 `mov esp, eax; ret` 或类似的栈迁移 —— 它把执行流重定向到 ROP 链
2. **导出 ROP 链：** 用 GDB 脚本逐条反汇编链中每个返回地址之后的指令：
```python
# GDB script to trace ROP gadgets
import gdb

magic_buf = 0x080b0000  # symbol address
buf_size = 0x40000       # quarter megabyte
offset = 0

while offset < buf_size:
    addr = int.from_bytes(gdb.selected_inferior().read_memory(magic_buf + offset, 4), 'little')
    gdb.execute(f'x/3i {addr}')
    # Advance past the gadget (typically 4 bytes per return address)
    offset += 4
```

3. **识别链中的模式：** 寻找展开的循环（重复的 gadget 序列）、跳过数据的 `pop` 指令、以及跳过大段内容的 `ret imm16`
4. **还原算法：** 该链通常依次执行：
   - 密钥长度检查（与常量比较）
   - 字符级运算（累加 ASCII 值、与常量 XOR）
   - 计算哈希（对派生值求 MD5）
   - 比较哈希前缀
   - 把输入与哈希作为密钥流做 XOR
   - 与内嵌常量比较

5. **提取并求解：** 导出内嵌常量，爆破中间值（例如字符和 → 前缀匹配的 MD5），再 XOR 恢复密钥：
```python
import hashlib

# Brute-force the sum that produces correct MD5 prefix
target_prefix = 0xc0050bdd  # extracted from ROP chain
for s in range(128 * 0x35):  # max sum of printable chars * key_length
    h = hashlib.md5(str(s ^ xor_constant).encode()).hexdigest()
    if int(h[:8], 16) == target_prefix:
        md5_key = bytes.fromhex(h)
        break

# XOR embedded values with MD5 keystream to get flag
flag = bytes(v ^ md5_key[i % 16] for i, v in enumerate(embedded_values))
```

**关键点：** ROP 链混淆（"ROPfuscation"）把算法藏在返回导向的 gadget 链中。作为裸地址它难以理解，但只要你 (a) 导出每个 gadget 的反汇编、(b) 过滤重复段并跳过填充区、(c) 标注寄存器副作用，它就变得可分析。这条链在功能上等价于普通代码 —— 只是用 `ret` 代替了顺序执行。大型链（10 万+ gadget）往往包含展开的循环，压缩后大约只剩 1000 行伪代码。

另见：[patterns-ctf.md](patterns-ctf.md) 第一部分（隐藏模拟器 opcode、SPN 静态提取、图像 XOR 平滑度、逐字节密码、数学收敛位图、Windows PE XOR 位图 OCR、两阶段 RC4+VM 加载器、GBA ROM 中间相遇、Sprague-Grundy 博弈论、内核模块走迷宫、多线程 VM 通道）。[patterns-ctf-3.md](patterns-ctf-3.md) 第三部分（Z3 单行 Python 电路、滑动窗口 popcount、键盘 LED 摩斯码、C++ 析构函数隐藏校验、syscall 副作用内存破坏、MFC 对话框事件处理、VM 顺序密钥链爆破、Burrows-Wheeler 变换反演、OpenType 字体连字利用、带自修改代码的 GLSL 着色器 VM、以指令计数器作为密码学状态）。
