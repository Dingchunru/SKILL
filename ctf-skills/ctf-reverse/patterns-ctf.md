# CTF Reverse - 赛事专用模式（第一部分）

## 目录
- [隐藏模拟器操作码 + LD_PRELOAD 取密钥（0xFun 2026）](#隐藏模拟器操作码--ld_preload-取密钥0xfun-2026)
- [Spectre-RSB SPN 密码 — 静态参数提取（0xFun 2026）](#spectre-rsb-spn-密码--静态参数提取0xfun-2026)
- [图像 XOR 掩码恢复：利用平滑度（VuwCTF 2025）](#图像-xor-掩码恢复利用平滑度vuwctf-2025)
- [数据段 shellcode 经 mmap RWX 执行（VuwCTF 2025）](#数据段-shellcode-经-mmap-rwx-执行vuwctf-2025)
- [递归 execve 逐步相减（VuwCTF 2025）](#递归-execve-逐步相减vuwctf-2025)
- [逐字节分组密码攻击（UTCTF 2024）](#逐字节分组密码攻击utctf-2024)
- [数学收敛位图（EHAX 2026）](#数学收敛位图ehax-2026)
- [Windows PE XOR 位图提取 + OCR（srdnlenCTF 2026）](#windows-pe-xor-位图提取--ocrsrdnlenctf-2026)
- [两阶段加载器：RC4 门禁 + VM 约束（srdnlenCTF 2026）](#两阶段加载器rc4-门禁--vm-约束srdnlenctf-2026)
- [GBA ROM VM 哈希逆推：中间相遇攻击（srdnlenCTF 2026）](#gba-rom-vm-哈希逆推中间相遇攻击srdnlenctf-2026)
- [Sprague-Grundy 博弈论二进制（DiceCTF 2026）](#sprague-grundy-博弈论二进制dicectf-2026)
- [内核模块迷宫求解（DiceCTF 2026）](#内核模块迷宫求解dicectf-2026)
- [多线程 VM 与通道同步（DiceCTF 2026）](#多线程-vm-与通道同步dicectf-2026)
- [通过字符串比对发现被植入后门的共享库（Hack.lu CTF 2012）](#通过字符串比对发现被植入后门的共享库hacklu-ctf-2012)
- [自定义 binfmt 内核模块 + RC4 扁平二进制（BSidesSF 2026）](#自定义-binfmt-内核模块--rc4-扁平二进制bsidessf-2026)
- [哈希解析导入 / 无导入勒索软件（BSidesSF 2026）](#哈希解析导入--无导入勒索软件bsidessf-2026)
- [ELF 节头表损坏反分析（BSidesSF 2026）](#elf-节头表损坏反分析bsidessf-2026)
- [用 VM 轨迹差分替代完整反汇编（CONFidence CTF 2019 Teaser）](#用-vm-轨迹差分替代完整反汇编confidence-ctf-2019-teaser)

---

<a id="hidden-emulator-opcodes--ld_preload-key-extraction-0xfun-2026"></a>
## 隐藏模拟器操作码 + LD_PRELOAD 取密钥（0xFun 2026）

**模式（CHIP-8）：** 非标准操作码 `FxFF` 触发隐藏函数 `superChipRendrer()` → AES-256-CBC 解密。密钥由二进制中的常量派生。

**手法：**
1. 检查所有指令分发分支，寻找非标准操作码
2. 隐藏操作码可能调用加密函数（OpenSSL）
3. 用 `LD_PRELOAD` 钩住 `EVP_DecryptInit_ex`，在运行时截获 AES 密钥：

```c
#include <openssl/evp.h>
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv) {
    // Log key
    for (int i = 0; i < 32; i++) printf("%02x", key[i]);
    printf("\n");
    // Call original
    return ((typeof(EVP_DecryptInit_ex)*)dlsym(RTLD_NEXT, "EVP_DecryptInit_ex"))
           (ctx, type, impl, key, iv);
}
```

```bash
gcc -shared -fPIC -ldl -lssl hook.c -o hook.so
LD_PRELOAD=./hook.so ./emulator rom.ch8
```

---

<a id="spectre-rsb-spn-cipher--static-parameter-extraction-0xfun-2026"></a>
## Spectre-RSB SPN 密码 — 静态参数提取（0xFun 2026）

**模式：** 二进制用缓存侧信道实现 S-box，但所有密码参数（轮密钥、S-box 表、置换）都位于二进制的数据段中。

**关键点：** 不要试图在特殊硬件上运行。直接静态提取参数：
- 8 个 S-box × 8 个输出位，每个 256 项
- 值 `0x340` = 位 1，`0x100` = 位 0
- 64 字节置换表，8 个轮密钥

```python
# Extract from binary data section
import struct
sbox = [[0]*256 for _ in range(8)]
for i in range(8):
    for j in range(256):
        val = struct.unpack('<I', data[sbox_offset + (i*256+j)*4 : ...])[0]
        sbox[i][j] = 1 if val == 0x340 else 0
```

**经验：** 侧信道实现会把查找表嵌入内存。静态提取即可。

---

<a id="image-xor-mask-recovery-via-smoothness-vuwctf-2025"></a>
## 图像 XOR 掩码恢复：利用平滑度（VuwCTF 2025）

**模式（Trianglification）：** 图像被划分为若干三角形区域，每块用 `key = (mask * x - y) & 0xFF` 做 XOR 加密，其中 mask 未知（0-255）。

**恢复：** 自然图像具有平滑的梯度。对 mask 暴力枚举（每块 256 种取值），用相邻像素差评分：

```python
import numpy as np
from PIL import Image

img = np.array(Image.open('encrypted.png'))

def score_smoothness(region_pixels, mask, positions):
    decrypted = []
    for (x, y), pixel in zip(positions, region_pixels):
        key = (mask * x - y) & 0xFF
        decrypted.append(pixel ^ key)
    # Score: sum of absolute differences between adjacent pixels
    return -sum(abs(decrypted[i] - decrypted[i+1]) for i in range(len(decrypted)-1))

for region in regions:
    best_mask = max(range(256), key=lambda m: score_smoothness(region, m, positions))
```

**搜索空间：** 256 个候选 × N 个区域 = 微不足道。平滑度是自然图像上可靠的评分指标。

---

<a id="shellcode-in-data-section-via-mmap-rwx-vuwctf-2025"></a>
## 数据段 shellcode 经 mmap RWX 执行（VuwCTF 2025）

**模式（Missing Function）：** 二进制把数据重定位到 RWX 内存（`mmap` 带 `PROT_READ|PROT_WRITE|PROT_EXEC`）并跳转执行。

**检测：** 寻找带 `PROT_EXEC` 标志的 `mmap`。内嵌 shellcode 常用滚动密钥 XOR。

**分析：** 提取数据段，套用 XOR 密钥（可尝试 3 字节滚动），再反汇编结果。

---

<a id="recursive-execve-subtraction-vuwctf-2025"></a>
## 递归 execve 逐步相减（VuwCTF 2025）

**模式（String Inspector）：** 二进制通过 `execve` 递归调用自身，每次递减常量。

**解法：** 找到基准情形并反推。通常是一个数学关系，例如 `N * M + remainder`。

---

<a id="byte-at-a-time-block-cipher-attack-utctf-2024"></a>
## 逐字节分组密码攻击（UTCTF 2024）

**模式（PES-128）：** 第一个输出字节只依赖第一个输入字节（无扩散）。

**攻击：** 对每个位置枚举全部 256 个字节值，把输出字节与目标密文比对。每个字节命中一次 = 无需密钥即可完整恢复明文。

**检测：** 改变一个输入字节 → 只有对应的输出字节变化。这意味着字节之间零扩散 = 一击即破。

---

<a id="mathematical-convergence-bitmap-ehax-2026"></a>
## 数学收敛位图（EHAX 2026）

**模式（Compute It）：** 二进制按牛顿法的收敛性对复平面坐标分类。分类结果按网格排列，以 ASCII 艺术形式拼出 flag。

**识别特征：**
- 输入文件包含坐标对 (x, y)
- 二进制迭代某个数学函数（如 z^3 - 1 = 0）并输出通过/不通过
- 网格尺寸可由点数量推断（例如 2600 = 130×20）
- CTF 中常见 5 像素高的 ASCII 艺术字体

**针对 z^3 - 1 的牛顿法：**
```python
def newton_converges_to_one(px, py, max_iter=50, target_count=12):
    """Returns True if Newton's method converges to z=1 in exactly target_count steps."""
    x, y = px, py
    count = 0
    for _ in range(max_iter):
        f_real = x**3 - 3*x*y**2 - 1.0
        f_imag = 3*x**2*y - y**3
        J_rr = 3.0 * (x**2 - y**2)
        J_ri = 6.0 * x * y
        det = J_rr**2 + J_ri**2
        if det < 1e-9:
            break
        x -= (f_real * J_rr + f_imag * J_ri) / det
        y -= (f_imag * J_rr - f_real * J_ri) / det
        count += 1
        if abs(x - 1.0) < 1e-6 and abs(y) < 1e-6:
            break
    return count == target_count

# Read coordinates and render bitmap
points = [(float(x), float(y)) for x, y in ...]
bits = [1 if newton_converges_to_one(px, py) else 0 for px, py in points]
WIDTH = 130  # 2600 / 20 rows
for r in range(len(bits) // WIDTH):
    print(''.join('#' if bits[r*WIDTH+c] else '.' for c in range(WIDTH)))
```

**关键点：** 这个二进制是一个数学分类器，不是 flag 校验器。flag 藏在分类结果的可视化图案中，而不是二进制的输出里。把数学逻辑逆向出来，套用到所有坐标上，再可视化成位图。

---

<a id="windows-pe-xor-bitmap-extraction--ocr-srdnlenctf-2026"></a>
## Windows PE XOR 位图提取 + OCR（srdnlenCTF 2026）

**模式（Artistic Warmup）：** 二进制渲染输入文本，并把渲染结果与存储在 `.rdata` 中、经常量 XOR 的目标像素数据比对。无需计算——直接提取期望的像素。

**攻击：**
1. 逆向核心校验函数，弄清渲染与比对逻辑
2. 在 `.rdata` 中找到期望的像素数据块（寻找比对点附近引用的大块数据）
3. 用常量（如 0xAA）XOR 还原期望渲染的 DIB
4. 保存为图片并 OCR，恢复 flag 文本

```python
import numpy as np
from PIL import Image

with open("binary.exe", "rb") as f:
    data = f.read()

# Extract from .rdata section (offsets from reversing)
blob_offset = 0xC3620  # .rdata offset to XOR'd blob
blob_size = 0x15F90     # 450 * 50 * 4 (BGRA)
blob = np.frombuffer(data[blob_offset:blob_offset + blob_size], dtype=np.uint8)
expected = blob ^ 0xAA  # XOR with constant key

# Reshape as BGRA image (dimensions from reversing)
img = expected.reshape(50, 450, 4)
channel = img[:, :, 0]  # Take one channel (grayscale text)
Image.fromarray(channel, "L").save("target.png")

# OCR with charset whitelist
import subprocess
result = subprocess.run(
    ["tesseract", "target.png", "stdout", "-c",
     "tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_"],
    capture_output=True, text=True)
print(result.stdout)
```

**关键点：** 当二进制先渲染文本再比像素时，期望的像素数据其实就是被渲染成图像的 flag。直接从二进制的数据段提取即可，不必理解渲染逻辑。带字符白名单的 OCR 能显著提升 CTF flag 字符的识别率。

---

<a id="two-stage-loader-rc4-gate--vm-constraints-srdnlenctf-2026"></a>
## 两阶段加载器：RC4 门禁 + VM 约束（srdnlenCTF 2026）

**模式（Cornflake v3.5）：** 两阶段恶意加载器——第一阶段用 RC4 校验用户名，第二阶段从 C2 下载，内含基于 VM 的口令校验。

**第一阶段 — RC4 用户名恢复：**
```python
def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

# Key from binary strings, ciphertext from stored hex
username = rc4(b"s3cr3t_k3y_v1", bytes.fromhex("46f5289437bc009c17817e997ae82bfbd065545d"))
```

**第二阶段 — VM 约束提取：**
1. 从 C2 端点下载第二阶段（例如 `/updates/check.php`）
2. 逆向 VM 字节码解释器（通常 15-20 个操作码）
3. 抽取 flag 字符上的线性等式约束
4. 求解约束系统（Z3 或手工）

**关键点：** 多阶段加载器常在第一道关卡用简单加密（RC4），第二道用更复杂的校验（自定义 VM）。VM 内存可能是未初始化的（全零），这会让依赖内存的运算变成常量，从而大幅简化约束提取。

---

<a id="gba-rom-vm-hash-inversion-via-meet-in-the-middle-srdnlenctf-2026"></a>
## GBA ROM VM 哈希逆推：中间相遇攻击（srdnlenCTF 2026）

**模式（Dante's Trial）：** Game Boy Advance ROM 中实现了一个自定义 VM。哈希函数是 FNV-1a 变体，其中引用了未初始化内存（始终为零）。中间相遇攻击把搜索空间一分为二。

**哈希函数结构：**
```python
# FNV-1a variant with XOR/multiply
P = 0x100000001b3        # FNV prime
CUP = 0x9e3779b185ebca87  # Golden ratio constant
MASK64 = (1 << 64) - 1

def fmix64(h):
    """Finalization mixer."""
    h ^= h >> 33; h = (h * 0xff51afd7ed558ccd) & MASK64
    h ^= h >> 33; h = (h * 0xc4ceb9fe1a85ec53) & MASK64
    h ^= h >> 33
    return h

def hash_input(chars, seed_lo=0x84222325, seed_hi=0xcbf29ce4):
    hlo, hhi, ptr = seed_lo, seed_hi, 0
    for c in chars:
        # tri_mix(c, mem[ptr]) — mem is always 0
        delta = ((ord(c) * CUP) ^ (0 * P)) & MASK64
        hlo = ((hlo ^ (delta & 0xFFFFFFFF)) * (P & 0xFFFFFFFF)) & 0xFFFFFFFF
        hhi = ((hhi ^ (delta >> 32)) * (P >> 32)) & 0xFFFFFFFF
        ptr = (ptr + 1) & 0xFF
    combined = ((hhi << 32) | (hlo ^ ptr)) & MASK64
    return fmix64((combined * P) & MASK64)
```

**中间相遇攻击：**
```python
import string

TARGET = 0x73f3ebcbd9b4cd93
LENGTH = 6
SPLIT = 3
charset = [c for c in string.printable if 32 <= ord(c) < 127]

# Forward pass: enumerate first 3 characters from seed state
forward = {}
for c1 in charset:
    for c2 in charset:
        for c3 in charset:
            state = hash_forward(seed, [c1, c2, c3])
            forward[state] = c1 + c2 + c3

# Backward pass: invert fmix64 and final multiply, enumerate last 3 chars
inv_target = invert_fmix64(TARGET)
for c4 in charset:
    for c5 in charset:
        for c6 in charset:
            state = hash_backward(inv_target, [c4, c5, c6])
            if state in forward:
                print(f"Found: {forward[state]}{c4}{c5}{c6}")
```

**关键点：** 中间相遇把搜索量从 `95^6 ≈ 7.4×10^11` 降到 `2×95^3 ≈ 1.7×10^6`，约 430,000 倍加速。前提是哈希函数能从输出端反推（即 `fmix64` 和最后的乘法可逆）。另外：VM 内存若保持为零，相当于从哈希中消去一个变量。

---

<a id="sprague-grundy-game-theory-binary-dicectf-2026"></a>
## Sprague-Grundy 博弈论二进制（DiceCTF 2026）

**模式（Bedtime）：** 去符号的 Rust 二进制进行 N 局有界 Nim 游戏。每局有若干堆，以及单次最多取 k 个的参数。当电脑处于必败局面时，它用 PRNG 走子；玩家必须最优应对，使 PRNG 最终生成非法落子（返回 1）。所有返回值之和必须等于目标值。

**博弈论识别：**
- 有界 Nim：每回合从任意一堆取 1 到 k 个
- 每堆的 **Grundy 值**：`pile_value % (k+1)`
- 所有 Grundy 值做 **XOR**：非零 = 必胜（N 局面），为零 = 必败（P 局面）
- N 局面：电脑必胜（返回 0）
- P 局面：电脑用 PRNG 走子，可能走出非法落子（返回 1）

**通过玩家反馈跟踪 PRNG 状态：**
```python
MASK64 = (1 << 64) - 1

def prng_step(state, pile_count, k):
    """Computer's PRNG move. Returns (pile_idx, amount, new_state)."""
    r12 = state[2] ^ 0x28027f28b04ccfa7
    rax = (state[1] + r12) & MASK64
    s0_new = ROL64((state[0] ** 2 + rax) & MASK64, 32)
    r12_upd = (r12 + rax) & MASK64
    s0_final = ROL64((s0_new ** 2 + r12_upd) & MASK64, 32)

    pile_idx = rax % pile_count
    amount = (r12_upd % k) + 1
    return pile_idx, amount, [s0_final, r12_upd, state[2]]

# Critical: state[2] updated ONLY by user moves (XOR of pile_idx, amount, new_value)
# PRNG moves do NOT affect state[2] — creates feedback loop
```

**求解流程：**
1. 用 GDB 导出游戏数据（所有含堆值与参数的条目）
2. 分类：统计 P 局面（返回 1）与 N 局面（返回 0）
3. 逐个模拟 P 局面：PRNG 走子 → 玩家最优应对 → 跟踪 state[2]
4. 把玩家落子编码成输入格式（4 位十进制对，顺序反转）

**关键点：** 当游戏二进制的 PRNG 状态依赖玩家输入时，必须模拟完整的反馈回路，而不是只解博弈论。用 GDB 硬件观察点找出哪些状态变量受玩家落子影响、哪些受电脑落子影响。

---

<a id="kernel-module-maze-solving-dicectf-2026"></a>
## 内核模块迷宫求解（DiceCTF 2026）

**模式（Explorer）：** Rust 内核模块通过 `/dev/challenge` 的 ioctl 实现一个 3D 迷宫。在迷宫中移动，避开诱饵出口（status=2），找到真出口（status=1），读取 flag。

**ioctl 一览：**
| 命令 | 说明 |
|---------|-------------|
| `0x80046481-83` | 获取迷宫尺寸（3 个轴，每个 8-16） |
| `0x80046485` | 获取状态：0=进行中，1=WIN，2=诱饵 |
| `0x80046486` | 获取墙壁位图（6 个方向） |
| `0x80406487` | 获取 flag（64 字节，仅当 status=1） |
| `0x40046488` | 朝某方向移动（0-5） |
| `0x6489` | 重置位置 |

**带诱饵规避的 DFS 求解器：**
```c
// Minimal static binary using raw syscalls (no libc) for small upload size
// gcc -nostdlib -static -Os -fno-builtin -o solve solve.c -Wl,--gc-sections && strip solve

int visited[16][16][16];
int bad[16][16][16];   // decoy positions across resets

void dfs(int fd, int x, int y, int z) {
    if (visited[x][y][z] || bad[x][y][z]) return;
    visited[x][y][z] = 1;

    int status = ioctl_get_status(fd);
    if (status == 1) { read_flag(fd); exit(0); }
    if (status == 2) { bad[x][y][z] = 1; return; }  // decoy — mark bad

    int walls = ioctl_get_walls(fd);
    int dx[] = {1,-1,0,0,0,0}, dy[] = {0,0,1,-1,0,0}, dz[] = {0,0,0,0,1,-1};
    int opp[] = {2,3,0,1,5,4};  // opposite directions for backtracking

    for (int dir = 0; dir < 6; dir++) {
        if (!(walls & (1 << dir))) continue;  // wall present
        ioctl_move(fd, dir);
        dfs(fd, x+dx[dir], y+dy[dir], z+dz[dir]);
        ioctl_move(fd, opp[dir]);  // backtrack
    }
}
// After decoy hit: reset via ioctl 0x6489, clear visited, re-run DFS
```

**远程部署：** 通过 netcat shell 用 base64 分块上传二进制，解码后执行。

**关键点：** 对内核模块题目，把测试二进制注入 initramfs 并动态探测 ioctl，比静态逆向去符号的内核模块更快。求解器二进制要尽量小（裸系统调用、不依赖 libc），以便快速上传。

---

<a id="multi-threaded-vm-with-channel-synchronization-dicectf-2026"></a>
## 多线程 VM 与通道同步（DiceCTF 2026）

**模式（locked-in）：** 自定义栈式 VM 运行 16 个并发线程，校验一个 30 字符的 flag。线程通过基于 futex 的通道通信。流水线：输入 → XOR 打乱 → 变换 → 四进制状态机 → 最终校验。

**分析思路：**
1. **识别线程角色**：在 GDB 中跟踪各通道的读写模式
2. **提取常量**（XOR 打乱值、查找表）：在特定操作码上设断点
3. **注意逻辑反转：** 合法性检查对合法输入返回 0，对被拦截输入返回非零（与直觉相反）
4. **留意 futex 的怪异行为：** 对无人持有的 mutex 调用 `unlock_pi` 会返回 EPERM=1，这可能改变全部计算结果

**受限状态机的 BFS 状态空间搜索：**
```python
from collections import deque

def solve_flag(scramble_vals, lookup_table, initial_state, target_state):
    """BFS through state machine to find valid flag bytes."""
    flag = [None] * 30
    # Known prefix/suffix from flag format
    flag[0:5] = list(b'dice{')
    flag[29] = ord('}')

    # For each unknown position, try all printable ASCII
    states = {initial_state}
    for pos in range(28, 4, -1):  # processed in reverse
        next_states = {}
        for state in states:
            for ch in range(32, 127):
                transformed = transform(ch, scramble_vals[pos])
                digits = to_base4(transformed)
                new_state = apply_digits(state, digits, lookup_table)
                if new_state is not None:  # valid path exists
                    next_states.setdefault(new_state, []).append((state, ch))
        states = set(next_states.keys())

    # Trace back from target_state to recover flag
```

**关键点：** 多线程 VM 必须跨线程边界追踪数据流。基于通道的通信构成流水线——观察每个线程读写哪些通道，即可判定其角色（输入、变换、校验、输出）。影响计算的常量可能来自意想不到的地方（futex 返回值、线程 ID）。

---

<a id="backdoored-shared-library-detection-via-string-diffing-hacklu-ctf-2012"></a>
## 通过字符串比对发现被植入后门的共享库（Hack.lu CTF 2012）

**模式（Zombie Lockbox）：** 一个 setuid 二进制用 `strcmp` 校验口令。期望的口令用 `strings` 就能看到，在 GDB 下（GDB 会丢掉 suid）也能通过，但正常运行却失败。原因是该二进制链接了一个非标准 libc，它根据 suid 状态改写函数行为。

**检测步骤：**
1. 用 `ldd` 检查是否存在非标准库路径：
```bash
ldd ./binary
# Suspicious: libc.so.6 => /lib/libc/libc.so.6  (non-standard path)
# Normal:    libc.so.6 => /lib32/libc.so.6
```

2. 把可疑 libc 与系统 libc 的字符串做比对：
```bash
strings /lib/libc/libc.so.6 > suspicious_strings
strings /lib32/libc-2.15.so > normal_strings
diff suspicious_strings normal_strings
```

3. 反汇编被改写的函数（例如 `puts`），找出注入代码：
```bash
gdb /lib/libc/libc.so.6
(gdb) disas puts
# Look for unexpected calls or branches
# Injected code may check suid status (getuid/geteuid syscalls)
# and swap the expected password at runtime
```

**关键点：** 当二进制在 GDB 下与正常运行表现不一致时，先 `ldd` 看有没有非标准库路径。setuid 程序在调试器下会丢权限，被植入后门的 libc 可借此通过 `getuid`/`geteuid` 系统调用区分环境并改变行为。`strings | diff` 无需完整反汇编就能快速暴露注入的数据。

---

<a id="custom-binfmt-kernel-module-with-rc4-flat-binaries-bsidessf-2026"></a>
## 自定义 binfmt 内核模块 + RC4 扁平二进制（BSidesSF 2026）

**模式（Private Binary）：** 自定义 Linux 内核模块（`.ko`）为非标准二进制格式注册了 `binfmt` 处理器。当执行具有特定魔数的文件时，内核模块拦截它，在内存中解密内容，然后跳转到入口点。

**逆向思路：**
1. **分析 `.ko`：** 找 `register_binfmt()` 调用——它注册一个带 `load_binary` 回调的 `struct linux_binfmt`
2. **找魔数：** `load_binary` 会拿文件头字节与特定魔数比对以识别格式
3. **提取加密密钥：** 找用 `movabs` 加载 8 字节常量的指令——通常是 RC4 密钥字节
4. **确定加密方案：** 常见选择是 RC4、XOR 或 AES-ECB。RC4 可通过 S-box 初始化循环识别（256 字节数组、交换模式）
5. **解密扁平二进制：** 用恢复出的密钥作用于加密内容，跳过任何头部

```python
from Crypto.Cipher import ARC4

# Extract RC4 key from kernel module (found via movabs instructions)
key = bytes([0x41, 0x42, 0x43, ...])  # Key bytes from .ko disassembly

with open('encrypted.bin', 'rb') as f:
    header = f.read(HEADER_SIZE)  # Skip binfmt header
    encrypted = f.read()

cipher = ARC4.new(key)
decrypted = cipher.decrypt(encrypted)

# The decrypted output is a flat binary (no ELF headers)
# Load at the fixed virtual address specified in the kernel module
# Disassemble with: objdump -b binary -m i386:x86-64 -D decrypted.bin
# Or in Ghidra: import as "Raw Binary", set base address from .ko
```

**内核模块中的检测特征：**
- `register_binfmt` / `unregister_binfmt` 调用
- `vm_mmap()` 或 `vm_brk()` 在固定地址分配内存
- 直接跳转到映射内存（执行入口点）
- S-box 初始化模式（RC4）：循环 0-255，把 `S[i]` 与 `S[j]` 交换

**关键点：** 扁平二进制没有 ELF 头，标准工具无法识别。必须从内核模块中提取加载地址（看 `vm_mmap` 调用里的地址参数），再在反汇编器中把解密后的数据块按该地址导入。内核模块里的 RC4 密钥常以立即数形式出现在 `mov`/`movabs` 指令中，而不是放在数据段。

**参考：** BSidesSF 2026 "Private Binary"

---

<a id="hash-resolved-imports--no-import-ransomware-bsidessf-2026"></a>
## 哈希解析导入 / 无导入勒索软件（BSidesSF 2026）

**模式（Ran Somewhere）：** 恶意二进制没有任何可见导入——所有 API 调用都在运行时通过哈希符号名并与预计算哈希值比对来解析。它用 `dlopen` + 自定义哈希表查找 libc 与 libcrypto 函数。

**识别特征：**
- `readelf -d` 显示没有动态符号，或只有极少数（仅 `dlopen`/`dlsym`）
- 字符串中看不到标准 API 名
- 反汇编中可见哈希计算循环，随后是间接调用
- RC4 加密的内嵌字符串（RSA 公钥、文件路径、口令）

**分析捷径 — LD_PRELOAD 取密钥：**

不必逆向完整的哈希解析与密钥派生流程，直接钩住恶意软件最终调用的加密函数：

```c
// hook_crypto.c — captures AES key used by the ransomware
#define _GNU_SOURCE
#include <dlfcn.h>
#include <openssl/evp.h>
#include <stdio.h>

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv) {
    if (key) {
        FILE *f = fopen("/tmp/aes_key.bin", "wb");
        fwrite(key, 1, 32, f);  // AES-256
        fclose(f);
        fprintf(stderr, "[HOOK] AES key captured\n");
    }
    typedef int (*orig_t)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*,
                          const unsigned char*, const unsigned char*);
    orig_t orig = (orig_t)dlsym(RTLD_NEXT, "EVP_CipherInit_ex");
    return orig(ctx, type, impl, key, iv);
}
```

```bash
# Compile and run
gcc -shared -fPIC -o hook.so hook_crypto.c -ldl
# Run in Docker container (ransomware may be destructive!)
docker run --rm -v $(pwd):/work -w /work ubuntu:22.04 \
  bash -c "LD_PRELOAD=./hook.so ./ransomware; xxd /tmp/aes_key.bin"
```

**哈希解析的常见形式：**
- **SipHash 变体：** 两个 64 位种子，用符号名字节反复混合
- **DJB2/FNV 变体：** 更简单的哈希，常量可识别（`5381`、`0xcbf29ce484222325`）
- **ROR13 类：** Windows 恶意软件的经典写法：`hash = (hash >> 13) | (hash << 19); hash += c`

**拿到密钥后的解密：**
```python
from Crypto.Cipher import AES

key = open('/tmp/aes_key.bin', 'rb').read()
iv = open('/tmp/aes_iv.bin', 'rb').read()  # Also hookable
cipher = AES.new(key, AES.MODE_CBC, iv)

with open('flag.txt.enc', 'rb') as f:
    ct = f.read()
pt = cipher.decrypt(ct)
# Remove PKCS7 padding
pt = pt[:-pt[-1]]
print(pt.decode())
```

**关键点：** 当二进制用哈希解析全部导入时，不要把时间浪费在逆向哈希函数、建彩虹表上。让恶意软件自己完成解析：在沙箱环境中运行它，并对自己关心的函数（OpenSSL 加密函数、文件 I/O、网络调用）挂 `LD_PRELOAD` 钩子。AES 密钥在多次运行间是确定的——只要一次成功，次次成功。

**安全提示：** 可疑勒索软件务必在 Docker 容器或虚拟机中运行。只挂载加密文件的副本，绝不挂原始文件。

**参考：** BSidesSF 2026 "Ran Somewhere"

---

<a id="elf-section-header-corruption-for-anti-analysis-bsidessf-2026"></a>
## ELF 节头表损坏反分析（BSidesSF 2026）

**模式（stubborn-elf）：** 一个 ELF 二进制故意破坏了节头表条目，导致标准分析工具（`readelf`、`objdump`、IDA、Ghidra）崩溃或报错。但操作系统加载器所用的**程序头**完好，因此程序仍能正常运行。flag 被附加在损坏的节之后，并带有魔数标记。

```python
import sys

# Standard tools fail on corrupted section headers
# Manual parsing bypasses section headers entirely

with open("stubborn_elf", "rb") as f:
    data = f.read()

# Search for magic marker appended after ELF sections
magic = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
idx = data.find(magic)
if idx >= 0:
    # Data after magic is XOR-encrypted
    encrypted = data[idx + len(magic):]
    decrypted = bytes(b ^ 0x42 for b in encrypted)
    print(decrypted.decode(errors='ignore'))
```

**关键点：** ELF 的执行只依赖**程序头**（PT_LOAD 段），不依赖节头。节头是给调试器和分析工具用的元数据——运行时可有可无。破坏 ELF 头中的 `e_shoff`、`e_shnum` 或 `e_shstrndx` 会让工具报错，但不影响执行。工具失败时，手工解析二进制，或在载入反汇编器前把 ELF 头中的节头引用清零。

**恢复方法：**
```bash
# Patch section header offset to 0 (removes section table)
printf '\x00\x00\x00\x00\x00\x00\x00\x00' | dd of=binary bs=1 seek=40 conv=notrunc
# Now Ghidra/IDA can load it using program headers only

# Or use readelf -l (program headers only, ignores sections)
readelf -l stubborn_elf
```

**何时能识别：** `readelf -S` 崩溃或输出乱码，`file` 仍识别为 ELF，而 `readelf -l`（小写 L，看程序头）正常。尽管工具报错，二进制照常运行。

**参考：** BSidesSF 2026 "stubborn-elf"

---

<a id="vm-trace-diffing-instead-of-full-disassembly-confidence-ctf-2019-teaser"></a>
## 用 VM 轨迹差分替代完整反汇编（CONFidence CTF 2019 Teaser）

**模式（Go Machine）：** Go 二进制运行一个含 15 个处理器的栈式 VM（分发字符串 `0123456789OEQLCI`），操作码含义在每个 tick 后被一个 LCG 驱动的 `shuffle` 处理器轮换。忠实重写解释器极其痛苦；而 VM 实际计算的是对 4 字符输入分组的简单 32 位哈希。

于是换个做法：在分发例程上挂调试器驱动的 tracer，逐步导出 `(opcode, stack)`，然后比较两个几乎相同输入的轨迹：

```python
# Pseudo-code for an IDAPython / gdb conditional-breakpoint tracer
def on_dispatch():
    op  = read_byte(bytecode + pc)
    top = stack[:sp+1]
    print(f"{decode(op)}\t({'|'.join(hex(x) for x in top)})")

# Replay the dumped trace in plain Python; no bytecode parsing, no shuffle logic:
elif line.startswith('save at (0x51)'):
    return stack[top] == expected_hash   # calculated hash lands at mem[0x51]

# Diff trace("abcd") vs trace("dcba") -> the same mul/mod sequence shows up,
# revealing the real algorithm:
def calc_hash(x, mod):
    for _ in range(8):
        x = x * x % mod
    return x * x_original % mod
```

从轨迹中导出每组的模数（`[0x88ca6b51, 0x8405b751, 0xbfa08c87, 0x82013f23, 0x4666751b, 0x5271083f]`）与期望哈希值，再对 `string.printable` 的 4 字符排列暴力枚举 `calc_hash`。

**关键点：** 带自修改分发的自定义 VM（shuffle、rotor、LCG 键控的操作码表）专门用来惩罚天真的重实现。记录实际执行的指令流可直接绕过这套把戏——对给定输入，轨迹是确定的；对两个只差一个比特的输入做轨迹差分，就能定位藏在 VM 开销之下的“真正算法”。

**参考：** CONFidence CTF 2019 Teaser — Go Machine，writeup 13947

---

另见：[patterns-ctf-2.md](patterns-ctf-2.md) 第二部分（多层自解密二进制、内嵌 ZIP+XOR 许可证、栈上字符串反混淆、前缀哈希暴力、CVP/LLL 格、决策树混淆、GF(2^8) 高斯消元），[patterns-ctf-3.md](patterns-ctf-3.md) 第三部分（Z3 布尔电路、滑动窗口 popcount、键盘 LED 摩尔斯码、C++ 析构函数隐藏校验、VM 顺序密钥链暴力、BWT 逆变换、OpenType 字体连字利用、带自修改代码的 GLSL shader VM）。
