# CTF Reverse - 按语言分类的技巧

## 目录
- [Python 字节码逆向（dis.dis 输出）](#python-字节码逆向disdis-输出)
  - [常见模式：按下标奇偶拆分的 XOR 校验](#常见模式按下标奇偶拆分的-xor-校验)
  - [字节码分析要点](#字节码分析要点)
- [Python opcode 重映射](#python-opcode-重映射)
  - [识别](#识别)
  - [还原](#还原)
- [Pyarmor 8/9 静态脱壳（1shot）](#pyarmor-89-静态脱壳1shot)
- [DOS Stub 分析](#dos-stub-分析)
- [Unity IL2CPP 游戏](#unity-il2cpp-游戏)
- [HarmonyOS HAP/ABC 逆向（abc-decompiler）](#harmonyos-hapabc-逆向abc-decompiler)
- [Brainfuck/深奥语言](#brainfuck深奥语言)
  - [Brainfuck 逐字符静态分析 (BSidesSF 2026)](#brainfuck-逐字符静态分析-bsidessf-2026)
  - [Brainfuck 读取次数侧信道 oracle (BSidesSF 2026)](#brainfuck-读取次数侧信道-oracle-bsidessf-2026)
  - [Brainfuck 比较惯用法识别 (BSidesSF 2026)](#brainfuck-比较惯用法识别-bsidessf-2026)
- [UEFI 二进制分析](#uefi-二进制分析)
- [转译成 C](#转译成-c)
- [代码覆盖率侧信道攻击](#代码覆盖率侧信道攻击)
- [函数式语言逆向（OPAL）](#函数式语言逆向opal)
- [特定 Python 版本的字节码 (VuwCTF 2025)](#特定-python-版本的字节码-vuwctf-2025)
- [非双射替换密码的逆向](#非双射替换密码的逆向)
- [FRACTRAN 程序反演 (Boston Key Party 2016)](#fractran-程序反演-boston-key-party-2016)
- [GNU Make 图灵机模拟器 (Hack.lu 2018)](#gnu-make-图灵机模拟器-hacklu-2018)

关于平台/框架相关技巧（Android、Roblox、Godot、Electron、Node.js、Verilog、Ruby/Perl 多语言同源等），见 [languages-platforms.md](languages-platforms.md)。
关于 Go 与 Rust 二进制逆向，见 [languages-compiled.md](languages-compiled.md)。

---

<a id="python-bytecode-reversing-disdis-output"></a>
## Python 字节码逆向（dis.dis 输出）

<a id="common-pattern-xor-validation-with-split-indices"></a>
### 常见模式：按下标奇偶拆分的 XOR 校验

题目给出原始 CPython 字节码（dis.dis 反汇编）。典型模式：
1. 检查 flag 长度
2. 把偶数下标的字符与 key1 异或，结果与列表 p1 比较
3. 把奇数下标的字符与 key2 异或，结果与列表 p2 比较

**逆向方式：**
```python
# Given: p1, p2 (expected values), key1, key2 (XOR keys)
flag = [''] * flag_length
for i in range(len(p1)):
    flag[2*i] = chr(p1[i] ^ key1)      # Even indices
    flag[2*i+1] = chr(p2[i] ^ key2)    # Odd indices
print(''.join(flag))
```

<a id="bytecode-analysis-tips"></a>
### 字节码分析要点
- `LOAD_CONST` 后跟 `COMPARE_OP` 会暴露期望值
- `BINARY_XOR` 标识了变换操作
- 带常量的 `BUILD_TUPLE`/`BUILD_LIST` = 期望输出数组
- 循环结构：`FOR_ITER` + `BINARY_SUBSCR` = 遍历 flag 字符
- 对 `ord` 的 `CALL_FUNCTION` = 字符转整数

**关键点：** Python 字节码题把算法以显式栈操作的形式直接给出。重点关注 `LOAD_CONST` 的值（期望输出）、`BINARY_XOR`/`BINARY_ADD`（变换）以及 `BUILD_TUPLE`（目标数组），即可在不运行字节码的情况下重建校验逻辑。

---

<a id="python-opcode-remapping"></a>
## Python opcode 重映射

<a id="identification"></a>
### 识别
反编译器报 opcode 错误。

<a id="recovery"></a>
### 还原
1. 在 PyInstaller 打包产物中找到被修改的 `opcode.pyc`
2. 与原版 Python opcode 对比
3. 建立映射：`{新 opcode: 原 opcode}`
4. 修补目标 .pyc
5. 正常反编译

**捷径（Hack.lu CTF 2013）：** 如果题目自带被修改的 Python 解释器（例如自定义的 `./py` 二进制），就把 `uncompyle2`/`uncompyle6` 安装到该解释器环境中，用题目自己的运行时来反编译。被修改的解释器认识自己的 opcode 映射，因此标准反编译工具无需手工恢复 opcode 即可工作。

**按 Python 版本选择工具：** `uncompyle6` 支持 Python 2.x–3.8。对于 Python 3.9+ 字节码，使用 [`pycdc`](https://github.com/zrax/pycdc)（从源码编译：`git clone && cmake . && make`）。

**关键点：** opcode 重映射会让所有标准反编译器失效。最快的修法是在 PyInstaller 打包产物中找到被修改的 `opcode.pyc`，与官方 Python 的 opcode 对比，再把目标 `.pyc` 补回标准 opcode 后反编译。

---

<a id="pyarmor-89-static-unpack-1shot"></a>
## Pyarmor 8/9 静态脱壳（1shot）

- 工具：`Lil-House/Pyarmor-Static-Unpack-1shot`
- 适用于 Pyarmor 8.x/9.x 加固脚本，且无需执行样本代码
- 快速签名检查：payload 通常以 `PY` 加六位数字开头（Pyarmor 7 及更早的 `PYARMOR` 格式不受支持）

流程：
1. 确保目标目录中同时包含加固脚本和对应的 `pyarmor_runtime` 库。
2. 运行 one-shot 脱壳，产出 `.1shot.` 输出（反汇编 + 实验性反编译）。
3. 以反汇编为准；当反编译源码不一致时，用字节码核对。

```bash
python /path/to/oneshot/shot.py /path/to/scripts
```

可选参数：
```bash
# Specify runtime explicitly
python /path/to/oneshot/shot.py /path/to/scripts -r /path/to/pyarmor_runtime.so

# Write outputs to another directory
python /path/to/oneshot/shot.py /path/to/scripts -o /path/to/output
```

注意事项：
- 运行 `shot.py` 前必须先存在 `oneshot/pyarmor-1shot` 可执行文件。
- PyInstaller 打包产物或归档应先解包，再用 1shot 处理。

**关键点：** Pyarmor 8/9 对脚本做运行时解密。1shot 直接处理加固字节码和 `pyarmor_runtime` 库，无需执行即可静态脱壳。当实验性反编译源码看起来不一致时，以反汇编输出为准。

---

<a id="dos-stub-analysis"></a>
## DOS Stub 分析

PE 文件可以在 DOS stub 中藏代码：
1. 在 Ghidra/IDA 中检查是否存在大型 DOS stub
2. 在 DOSBox 中运行
3. 在 IDA 中以 16 位 DOS 模式加载
4. 寻找 `int 16h`（键盘输入）

**关键点：** PE 文件可以在 DOS stub（PE 头之前的部分）中嵌入一个功能完整的 16 位 DOS 程序。如果 stub 异常庞大，就在 IDA 中以 16 位 DOS 加载，或在 DOSBox 中运行 —— 题目逻辑可能完全位于 stub 中。

---

<a id="unity-il2cpp-games"></a>
## Unity IL2CPP 游戏

- 用 Il2CppDumper 导出符号
- 如果 Il2CppDumper 失败，考虑 `global-metadata.dat` 可能被加密；在主二进制中搜索字符串/xref，并检查元数据加载路径是否存在自定义解密，然后再导出。
- 寻找 `Start()` 函数
- 密钥派生：`key = SHA256(companyName + "\n" + productName)`
- 用派生出的密钥解密服务器响应

注意：PC 平台的可执行文件大多是 GameAssembly.dll 或 *Assembly.dll，Android 上则是 libil2cpp.so。

**关键点：** IL2CPP 把 C# 编译为原生代码，但 Il2CppDumper 能恢复方法名和偏移。若 dump 失败，`global-metadata.dat` 很可能被加密 —— 在原生二进制中追踪元数据加载路径，找到自定义解密再导出。

---

<a id="harmonyos-hapabc-reverse-abc-decompiler"></a>
## HarmonyOS HAP/ABC 逆向（abc-decompiler）

- 目标文件：`.hap` 包及其中的 `.abc` 字节码
- 工具：`https://github.com/ohos-decompiler/abc-decompiler`
- 从 releases 下载 `jadx-dev-all.jar`

关键的启动注意事项：
- `java -jar` 可能进入 GUI 模式
- 要走 CLI 模式，务必使用：

```bash
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI [options] <input>
```

最常用的命令：
```bash
# Basic decompile to directory
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -d "out" ".abc"

# Decompile .abc (recommended for this scenario)
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple -d "out_hap" "modules.abc"
```

本题推荐参数：
- `-m simple`：降低高层重建程度，避免 SSA/PHI 相关的失败
- `--log-level ERROR`：只保留关键错误
- 完整推荐命令：

```bash
java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple --log-level ERROR -d "out_abc_simple" "modules.abc"
```

参数速查：
- `-d` 输出目录
- `--help` 帮助

注意事项：
- `.hap` 是一个包：先解压（zip），再定位并分析 `.abc`
- 含空格或非 ASCII 字符的路径要加引号
- 每次运行使用新的输出目录名，避免读到过期结果
- 报错不总意味着完全失败；优先查看 `out_xxx/sources/`
- 如果 `auto` 失败，先改用 `-m simple`

标准流程：
1. 用 `-m simple --log-level ERROR` 运行
2. 检查输出中的关键业务文件（例如 `pages/Index.java`）
3. 如果需要更干净的输出，再用 `-m auto` 或 `-m restructure` 重试
4. 如果仍有部分方法失败，保留 `simple` 的输出，沿其他路径继续逻辑分析

**关键点：** HarmonyOS 的 `.hap` 包是包含 `.abc` 字节码的 ZIP 归档。使用 abc-decompiler 的 CLI 模式（`jadx.cli.JadxCLI`）并加 `-m simple` 可获得最可靠的反编译结果 —— 否则可能启动 GUI 而不是处理文件。

---

<a id="brainfuckesolangs"></a>
## Brainfuck/深奥语言

- 检查是否由已知工具（BF-it）编译
- 理解纸带/内存模型
- 对单元格操作做静态分析

<a id="brainfuck-character-by-character-static-analysis-bsidessf-2026"></a>
### Brainfuck 逐字符静态分析 (BSidesSF 2026)

**模式（i-love-my-bf-part1）：** 逐字符校验输入的 BF 程序有可识别的模式：`,`（读字符）之后跟着一串 `+` 操作，其数量等于该字符的期望 ASCII 值。

**提取技巧：**
```python
import re

bf_code = open('challenge.bf', 'r').read()

# Split on comma (input read) — each segment handles one character
segments = bf_code.split(',')
expected = []

for seg in segments[1:]:  # Skip preamble before first comma
    # Count consecutive '+' operations before any branch/output
    plus_count = 0
    for ch in seg:
        if ch == '+':
            plus_count += 1
        elif ch in '-.[]><':
            break  # Stop at first non-increment operation
    if plus_count > 0:
        expected.append(chr(plus_count % 256))

flag = ''.join(expected)
print(f"Flag: {flag}")
```

**变体：**
- `-` 操作：字符值 = `256 - minus_count`
- `+`/`-` 混用：净增量决定该值
- 字符间的单元格清零（`[-]`）：说明每段相互独立
- 基于循环的乘法：`[->>+++<<]` 表示乘以 3 —— 数内层操作次数

**识别：** 大型 BF 文件，呈现 `,` 后跟大量 `+` 或 `-` 的重复模式，随后是比较结构（`[-]` 或 `[->+<]` 模式）。

**关键点：** 做输入校验的 BF 程序结构很简单 —— 每个输入字节都与一个由单元格自增构造出的常量比较。提取自增次数即可在不运行程序的情况下恢复期望输入。

**参考：** BSidesSF 2026 "i-love-my-bf-part1"

<a id="brainfuck-side-channel-via-read-count-oracle-bsidessf-2026"></a>
### Brainfuck 读取次数侧信道 oracle (BSidesSF 2026)

**模式（i-love-my-bf-part2）：** 当 BF 程序逐字符校验输入时，正确的字符会让程序消耗更多输入字节（进入下一个位置的检查）。统计每个候选输入触发的 `,`（读）操作次数，读取次数最多的那个字符就是正确的。

```python
import itertools

def bytes_read_running_bf(bf_code, input_iter, braces):
    """Run BF and count how many input bytes were consumed."""
    tape = [0] * 30000
    ptr = ip = reads = 0
    input_list = list(input_iter)
    input_idx = 0
    while ip < len(bf_code):
        c = bf_code[ip]
        if c == ',':
            if input_idx < len(input_list):
                tape[ptr] = input_list[input_idx]
                input_idx += 1
                reads += 1
            else:
                return reads
        elif c == '.': pass
        elif c == '+': tape[ptr] = (tape[ptr] + 1) % 256
        elif c == '-': tape[ptr] = (tape[ptr] - 1) % 256
        elif c == '>': ptr += 1
        elif c == '<': ptr -= 1
        elif c == '[' and tape[ptr] == 0: ip = braces[ip]
        elif c == ']' and tape[ptr] != 0: ip = braces[ip]
        ip += 1
    return reads

# Recover flag character by character
PRINTABLE = list(range(32, 127))
flag = []
for pos in range(50):  # max flag length
    best_byte = None
    max_reads = 0
    baseline = bytes_read_running_bf(bf, flag + [PRINTABLE[0]], braces)
    for b in PRINTABLE[1:]:
        reads = bytes_read_running_bf(bf, flag + [b], braces)
        if reads > baseline:
            best_byte = b
            break
    if best_byte is None:
        break
    flag.append(best_byte)
print(bytes(flag).decode())
```

**关键点：** BF 输入校验程序是顺序的 —— 读一个字符、检查它，只有匹配才读下一个。读取次数更多的字符就是正确答案，因为程序越过了校验关卡去检查下一个位置。

**参考：** BSidesSF 2026 "i-love-my-bf-part2"

<a id="brainfuck-comparison-idiom-detection-bsidessf-2026"></a>
### Brainfuck 比较惯用法识别 (BSidesSF 2026)

**模式（i-love-my-bf-part3）：** 由高级语言编译而来的 BF 程序会使用可识别的比较惯用法。相等比较 `<[-<->] +<[>-<[-]]>[-<+>]` 比较相邻的两个单元格。只要给 BF 解释器加上检测该模式的插桩，就能直接从纸带上提取比较的操作数（期望的 flag 字节）。

```python
EQ_PATTERN = "<[-<->] +<[>-<[-]]>[-<+>]"

def instrumented_bf_run(bf_code, dummy_input):
    """Run BF, detect equality comparisons, extract operands."""
    tape = [0] * 30000
    ptr = ip = 0
    comparisons = []

    while ip < len(bf_code):
        # Check if current position starts the eq pattern
        if bf_code[ip:ip+len(EQ_PATTERN)] == EQ_PATTERN:
            # The two cells being compared are at ptr-2 and ptr-1
            lhs = tape[ptr - 2]  # User input byte
            rhs = tape[ptr - 1]  # Expected byte
            comparisons.append((chr(lhs), chr(rhs)))
        # ... normal BF execution ...
        ip += 1

    return comparisons

# Expected bytes from comparisons reveal the flag
```

**关键点：** 编译产生的 BF 程序对相等比较、条件分支和循环等操作复用固定的惯用法。在 BF 源码中或执行期间对这些惯用法做模式匹配，就能在不完全理解程序逻辑的情况下提取常量。

**常见 BF 惯用法：**
- `[-]` —— 清零单元格
- `[->+<]` —— 把单元格内容右移
- `<[-<->] +<[>-<[-]]>[-<+>]` —— 两个单元格的相等比较

**参考：** BSidesSF 2026 "i-love-my-bf-part3"

---

<a id="uefi-binary-analysis"></a>
## UEFI 二进制分析

```bash
7z x firmware.bin -oextracted/
file extracted/* | grep "PE32+"
```

- Bootkit 替换引导加载器
- 自定义 VM 保护解密过程
- 把 VM 字节码提升为 C

**关键点：** UEFI 二进制是 PE32+ 可执行文件。用 `7z` 解出固件，用 `file` 找出 PE 文件，再加载进 Ghidra/IDA。Bootkit 会替换引导加载器，因此要重点检查 DXE 驱动与 boot services 协议中的题目逻辑。

---

<a id="transpilation-to-c"></a>
## 转译成 C

对于高度混淆的代码：
```python
for opcode, args in instructions:
    if opcode == 'XOR':
        print(f"r{args[0]} ^= r{args[1]};")
    elif opcode == 'ADD':
        print(f"r{args[0]} += r{args[1]};")
```

用 `-O3` 编译以启用常量折叠。

**关键点：** 把混淆的 VM 字节码转译成 C 再用 `-O3` 编译，编译器的常量折叠与死代码消除会自动化简算法。对于复杂指令集，这比手工反混淆更快。

---

<a id="code-coverage-side-channel-attack"></a>
## 代码覆盖率侧信道攻击

**模式（Coverup, Nullcon 2026）：** PHP 题目在提供加密输出的同时，还附带了 XDebug 代码覆盖率数据。

**原理：**
- PHP 代码使用 `xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE | XDEBUG_CC_BRANCH_CHECK)`
- 加密过程使用依赖数据的分支：`if ($xored == chr(0)) ... if ($xored == chr(1)) ...`
- 覆盖率 JSON 揭示了加密期间执行了哪些分支
- 这泄漏了出现过的 XOR 中间值集合

**利用：**
```python
import json

# Load coverage data
with open('coverage.json') as f:
    cov = json.load(f)

# Extract executed XOR values from branch coverage
executed_xored = set()
for line_no, hit_count in cov['encrypt.php']['lines'].items():
    if hit_count > 0:
        # Map line numbers to the chr(N) value in the if-statement
        executed_xored.add(extract_value_from_line(line_no))

# For each position, filter candidates
for pos in range(len(ciphertext)):
    candidates = []
    for key_byte in range(256):
        xored = plaintext_byte ^ key_byte  # or reverse S-box lookup
        if xored in executed_xored:
            candidates.append(key_byte)
    # Combined with known plaintext prefix, this uniquely determines key
```

**关键点：** 代码覆盖率是一个强有力的 oracle —— 它告诉你走了哪些条件路径。任何带数据相关分支的加密都会通过覆盖率泄漏信息。

**缓解措施识别：** 留意采用无分支/等时实现的加密，它们能抵御这种攻击。

---

<a id="functional-language-reversing-opal"></a>
## 函数式语言逆向（OPAL）

**模式（Opalist, Nullcon 2026）：** 二进制由 OPAL（Optimized Applicative Language，纯函数式语言）编译而成。

**识别特征：**
- `.impl`（实现）和 `.sign`（签名）源文件
- `IMPLEMENTATION` / `SIGNATURE` 关键字
- 嵌套的 `IF..THEN..ELSE..FI` 结构
- 函数命名为 `f1`、`f2` …… `fN`（数字命名）
- 大量使用 `seq[nat]`、`string`、`denotation` 类型

**逆向思路：**
1. 纯函数在数学上可逆 —— 从管道末端开始逐步反推
2. 识别变换链：`f_final(f_n(...f_2(f_1(input))...))`
3. 为每个函数构造其逆函数

**针对 scramble 函数的聚合爆破：**
当某个变换累积的状态依赖于原始（未知）值时：
```python
# Example: f8 adds cumulative offset based on parity of original bytes
# offset contribution per element depends on whether pre-scramble value is even/odd
# Total offset S = sum of contributions, but S mod 256 has only 256 possibilities

decoded = base64_decode(target)
for total_offset_S in range(256):
    candidate = [(b - total_offset_S) % 256 for b in decoded]
    # Verify: recompute S from candidate values
    recomputed_S = sum(contribution(i, candidate[i]) for i in range(len(candidate))) % 256
    if recomputed_S == total_offset_S:
        # Apply remaining inverse steps
        result = apply_inverse_substitution(candidate)
        if all(32 <= c < 127 for c in result):
            print(bytes(result))
```

**核心经验：** 当 scramble 函数存在"先有鸡还是先有蛋"的依赖（结果依赖原始值，而原始值未知）时，应爆破聚合效应（通常是 mod 256，只有 256 种可能），而不是枚举所有可能状态（指数级）。

---

<a id="python-version-specific-bytecode-vuwctf-2025"></a>
## 特定 Python 版本的字节码 (VuwCTF 2025)

**模式（A New Machine）：** 题目针对特定 Python 版本（例如 3.14.0 alpha）。

**关键要求：** 必须编译出那个确切的 Python 版本才能反汇编字节码 —— alpha/beta 版本的 opcode 与稳定版不同。

```bash
# Build specific Python version
wget https://www.python.org/ftp/python/3.14.0/Python-3.14.0a4.tar.xz
tar xf Python-3.14.0a4.tar.xz
cd Python-3.14.0a4 && ./configure && make -j$(nproc)
./python -c "import dis, marshal; dis.dis(marshal.loads(open('challenge.pyc','rb').read()[16:]))"
```

**常见校验：** flag 与 ASCII 值平方组成的元组比较：
```python
# Reverse: flag[i] = sqrt(expected_tuple[i])
import math
flag = ''.join(chr(int(math.isqrt(v))) for v in expected_values)
```

---

<a id="non-bijective-substitution-cipher-reversing"></a>
## 非双射替换密码的逆向

**模式（Coverup, Nullcon 2026）：** S 盒/替换表存在碰撞（多个输入映射到同一输出）。

**检测：**
```python
sbox = [...]  # substitution table
if len(set(sbox)) < len(sbox):
    print("Non-bijective! Collisions exist.")
```

**构建反向查找：**
```python
from collections import defaultdict
rev_sub = defaultdict(list)
for i, v in enumerate(sbox):
    rev_sub[v].append(i)
# rev_sub[output] = [list of possible inputs]
```

**消歧策略：**
1. 已知明文格式（例如 `ENO{`、`flag{`）可固定已知位置的密钥字节
2. 侧信道数据（代码覆盖率、时序）可排除不可能的候选
3. 可打印 ASCII 约束（32-126）可缩小候选空间
4. 重新加密候选，并与已知密文核对

---

<a id="fractran-program-inversion-boston-key-party-2016"></a>
## FRACTRAN 程序反演 (Boston Key Party 2016)

FRACTRAN：一种深奥语言，计算过程是反复乘以一张分数表。输入被编码为质因数分解（ASCII 值作为连续素数的指数）。反演方法：交换每个分数的分子与分母，再把"成功"输出反向跑过这个反演后的程序。

```python
# Original: for each step, find first fraction where n*frac is integer
def fractran_step(n, fractions):
    for num, den in fractions:
        if (n * num) % den == 0:
            return (n * num) // den
    return None  # Halt

# Inversion: swap num/denom in fraction table
inverted = [(d, n) for n, d in fraction_table]
# Run target output through inverted program to recover input
```

**关键点：** FRACTRAN 程序可以通过交换分子与分母来反演。质因数分解编码是理解输入输出的关键 —— 对结果做因式分解，取出连续素数的指数，再映射回 ASCII。

**识别：** 题目提到分数、质因数分解，或给出一个有理数列表。

---

<a id="gnu-make-turing-machine-simulator-hacklu-2018"></a>
## GNU Make 图灵机模拟器 (Hack.lu 2018)

**模式：** 一个 `Makefile` 仅用 Make 宏实现图灵机。纸带是用 `+++-` 编码的一元数（每个 `+` 表示 1，每个 `-` 表示 0），状态转移表是 14 个以空白分隔的词（每个 9 位），递归的 `$(eval)` 调用驱动状态机直到停机。逆向方法是解码转移表并与 [bbchallenge.org](https://bbchallenge.org) 数据库中已收录的 busy-beaver 机器比对，或者用 Python 重新实现解释器。

```make
# Example sink — 14 words of 9 bits each form the transition table
PROGRAM := 0 1A 1R 1 1B 1L 1 1C 1R 0 1D 1L 0 1A 1L 1 1E 1R 1 1A 1L \
           1 1A 1L 0 1E 1R 0 1F 1R 0 1F 1L 1 1E 1L 1 1H 1R 0 1C 1R
```

```python
# Python decoder for the table
def decode_transition(word):
    bits = int(word, 2)
    write = bits >> 7 & 1
    move  = "LR"[bits >> 6 & 1]
    state = chr(ord("A") + (bits & 0x3F))
    return write, move, state

# Simulate until HALT
tape = [0] * 4096
head = 2048
state = "A"
while state != "H":
    symbol = tape[head]
    idx = (ord(state) - ord("A")) * 2 + symbol
    write, move, state = decode_transition(PROGRAM[idx])
    tape[head] = write
    head += 1 if move == "R" else -1
print(sum(tape))   # Busy-beaver score → hashed for the flag
```

**关键点：** `Makefile` 借助递归 `$(eval)` 与字符串替换是图灵完备的，因此任何只给"一个 Makefile"的 CTF 题目都可能藏着完整的解释器。最快的逆向路径是把转移表按文本提取出来、解码每个词，然后本地模拟或查询公开的 busy-beaver 数据库 —— 大多数手写的 BB 机器在前 6 个状态内就能与已发表的机器对上。用 `make -n` 查看展开后的命令而不实际执行，用 `make -d` 观察递归 eval 图。

**参考：** Hackover CTF 2018 — Flagmaker，writeup 11503
