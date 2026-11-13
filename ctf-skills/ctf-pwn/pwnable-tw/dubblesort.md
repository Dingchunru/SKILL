---
tags:
  - canary-bypass
  - stack-buffer-overflow
  - ret2libc
platform: pwnable.tw
points: 300
arch: i386
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "向 scanf 输入非数字可跳过数组元素的赋值而不写入，从而在排序过程中绕过栈 canary，实现 ret2libc。"
proof-of-concept: no
---

# dubblesort — pwnable.tw（300 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10101`
>
> Flag: `FLAG{Dubo_duBo_dub0_s0rttttttt}`

## 题目概览

一个 32 位冒泡排序程序（i386，Full RELRO，PIE，NX，栈 Canary，FORTIFY），链接 glibc 2.23。程序读取一个名字，询问要排序多少个无符号整数，把它们读入固定大小的栈缓冲区，做冒泡排序，再输出结果。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
  FORTIFY:  Enabled
```

## 程序逻辑（反编译）

```c
int main() {
    unsigned int canary = __readgsdword(0x14u);
    unsigned int count;                     // [esp+0x18]
    int array[24];                          // [esp+0x1c] — 0x60 bytes
    char name_buf[0x40];                    // [esp+0x3c] — overlaps array!
    // canary at [esp+0x7c] == array[24]

    printf("What your name :");
    read(0, name_buf, 0x40);               // V1: no NUL terminator
    printf("Hello %s,...");                 // leaks uninitialized stack data

    scanf("%u", &count);                    // no upper-bound check
    for (i = 0; i < count; i++) {           // V2: writes past array[24]
        printf("Enter the %d number : ");
        scanf("%u", &array[i]);             // V3: non-numeric input skips write
    }
    bubble_sort(array, count);
    // print sorted results...
}
```

**关键栈布局**（相对 `esp` 的偏移）：

| 偏移 | 内容 |
|--------|---------|
| `0x1c` | `array[0]` |
| `0x3c` | `name_buf`（与 `array[8]`..`array[23]` 重叠） |
| `0x7c` | 栈 canary = `array[24]` |
| `0x80`–`0x98` | 保存的寄存器 / 填充（7 个 dword）= `array[25]`..`array[31]` |
| `0x9c` | **保存的返回地址** = `array[32]` |
| `0xa0` | 返回目标的第一个参数 = `array[33]` |

## 漏洞

### V1 — 未初始化名字缓冲区泄漏 libc 地址

**根因：** `read(0, name_buf, 0x40)` 不会给输入补 NUL 终止符。位于 `esp+0x3c` 的名字缓冲区与栈上 `esp+0x54` 处的一个 libc 数据段指针重叠（= `name_buf+0x18`，= `array[14]`）。该指针等于 `libc_base + 0x1b0000`（libc 的 `.got.plt` / RW 段起点），页对齐，因此最低字节恒为 `0x00`。

```c
read(0, &buf, 0x40u);                    // does NOT append NUL
__printf_chk(1, "Hello %s,...");          // %s reads until NUL → leaks past input
```

**触发：** 发送恰好 24–28 字节的填充（例如 `"A"*24` 加换行，或 `"A"*28`）。`\n` 或填充会覆盖那个 `0x00` 低字节。随后 `printf("%s")` 会穿过后面的填充，一路打印到该 libc 指针的高 3 个字节。

**影响：** 泄漏 `libc_base + 0x1b0000` 的高 3 字节。由于低字节已知（`0x00`），可重建完整指针 → 算出 `libc_base`。

```python
# Typical leak code from solutions
r.send(b"A" * 24 + b"\n")
r.recvuntil(b"A" * 24 + b"\n")
libc_leak = u32(b"\x00" + r.recv(3))   # restore known 0x00 low byte
libc_base = libc_leak - 0x1b0000
```

**变体（28 字节泄漏）：** 部分解法发送 28 字节（`"A"*28`），在 `name_buf+0x1c` 处读到完整 4 字节 dword，泄漏的是另一个 libc 指针（`libc_base + 0x1ae244`，`__libc_start_main` 的返回路径）。两种做法都可行。

### V2 — 数组写入无边界限制（栈溢出）

**根因：** `count` 变量没有上界检查。程序把 `count` 个无符号整数读入 `array[24]`，完全不做边界校验，因此会越过 24 个元素的缓冲区，写进 canary、保存的寄存器、返回地址及更远处。

```c
scanf("%u", &count);           // user controls count, no max check
for (i = 0; i < count; i++)
    scanf("%u", &array[i]);    // writes to array[0]..array[count-1]
```

**影响：** 直接的栈溢出。当 `count >= 35` 时，攻击者可以覆盖：
- `array[24]` = 栈 canary
- `array[25]`–`array[31]` = 保存的寄存器 / 填充
- `array[32]` = **返回地址**
- `array[33]` = 被调函数的第一个参数
- `array[34]` = 第二个参数 / 后续链

### V3 — 用非数字输入绕过 `scanf("%u")` 对 canary 的写入

**根因：** 当 `scanf("%u", &dst)` 遇到不是合法无符号整数的输入（如 `"+"`、`"-"`、`"a"`、`"nope"`）时，它会**直接返回而不写入**目标。栈上原有的值（即 canary）因而得以保留。

```c
// When user inputs "+" for array[24]:
scanf("%u", &array[24]);  // scanf returns 0, array[24] unchanged
// The real canary at this position survives!
```

**影响：** 攻击者发送非数字字符串即可跳过对 `array[24]` 处 canary 的覆盖，函数结束时的 canary 检查自然通过。

**注意：** `"+"` 和 `"-"` 是最干净的选择——它们会被从输入流中消费掉（不像 `"a"` 会留在缓冲区里，导致后续 `scanf` 调用死循环）。

### V4 — 冒泡排序对 payload 的约束

这**不是漏洞**，而是一个关键的利用约束。所有数字写完后，数组会按无符号比较做升序冒泡排序。payload 必须设计成排序后各值落在正确的栈位置上：

- `array[0]`–`array[23]`：必须 ≤ canary（用 `0` 或小值填充）
- `array[24]`：canary（经 V3 保留，必须留在原位）
- `array[25]`–`array[31]`：必须 ≥ canary 且 ≤ `system` 地址
- `array[32]`：`system` 地址（返回地址）
- `array[33]`+：`"/bin/sh"` 地址（参数）

由于 `system` 和 `"/bin/sh"` 都位于 `0xf7xxxxxx` 区间，而 canary 随机，排序顺序通常是：`{zeros} < canary < system < bin_sh`。这样在约 97% 的情况下可行。约 3% 的失败情形是 `canary > bin_sh`，导致各值排序错位。

## 利用路径 — 栈溢出 + 绕过 Canary 的 ret2libc

**相关题解：** 全部 168 个解法（思路一致，细节略有差异）

**步骤：**

1. **泄漏 libc 基址（V1）：** 用 24–28 个 `'A'` 作名字。`printf("%s")` 会越过输入，打印出栈上的一个 libc 数据段指针。掩码处理后减去 `0x1b0000` 得到 `libc_base`。

2. **计算地址：**
   ```python
   system  = libc_base + 0x3a940
   bin_sh  = libc_base + 0x158e8b
   ```

3. **申请 35 个数字（V2）：** 这样才有足够的槽位越过 canary 和返回地址。

4. **构造能通过冒泡排序的 payload：**
   - 索引 0–23：`0`（小值，排序后沉到底部）
   - 索引 24：`"+"` —— 经 V3 绕过 canary
   - 索引 25–33：`system` 地址（9 份拷贝，确保排序后索引 32 的返回地址被覆盖）
   - 索引 34：`"/bin/sh"` 地址（`system()` 的参数）

5. **排序后栈的样子：**
```text
   [0, 0, ..., 0, canary, system, system, ..., system, bin_sh]
    ^--- 24 ---^   ^24     ^--- indices 25..33 ---^     ^34
```
   main 返回 → `system("/bin/sh")` → shell。

**可靠性：** 每个连接约 97%（仅当随机 canary > `"/bin/sh"` 地址导致排序错位时失败）。

### 各解法的差异

| 差异 | 相关题解 | 说明 |
|-----------|-----------|-------------|
| **24 字节名字泄漏** | 约 60% | 发送 `"A"*24`，在 `\n` 之后泄漏 3 字节，用 `\x00` 低字节重建。偏移 `0x1b0000`。 |
| **28 字节名字泄漏** | 约 30% | 发送 `"A"*28`，在另一偏移处泄漏完整 4 字节 dword。偏移 `0x1ae244`。 |
| **用 `"+"` 跳过 canary** | 约 80% | 最流行的做法；会被 `scanf` 干净地消费掉。 |
| **用 `"-"` 跳过 canary** | 约 10% | 机制同 `"+"`。 |
| **用 `"a"`/`"nope"` 跳过 canary** | 约 10% | 可行，但可能在输入缓冲区留下字符。 |
| **两轮利用** | 1384、13484 | 第一轮用 `main` 地址 + `"+"` 溢出，从排序输出里读出 canary；第二轮用已知 canary 精确落位。更复杂，没有实际优势。 |
| **PIE 泄漏** | 1384、13060 | 28 字节名字还能泄漏 `name_buf+0x20` 处的二进制地址，用于计算两轮方案所需的 `main`。 |
| **填充模式：9×system + bin_sh** | 约 70% | 最常见；复制 system 覆盖索引 25–33。 |
| **填充模式：8×system + 2×bin_sh** | 约 20% | 多加一份 `bin_sh` 以增加余量。 |
| **大 count（40–50）** | 约 15% | 多分配槽位；payload 之后用 `0xFFFFFFFF` 或大值填充。 |

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| libc 数据段泄漏 | V1：未初始化 `name_buf` + `printf("%s")` | 确定性 |
| 越过 canary 的栈溢出 | V2：数组写入循环中无界的 `count` | 确定性 |
| canary 保留 | V3：`scanf("%u")` 遇非数字输入不写入 | 确定性 |
| ret2libc（`system("/bin/sh")`） | payload 在升序冒泡排序后仍成立 | 约 97%（依赖 canary） |

## 偏移（pwnable.tw `libc_32.so.6`，glibc 2.23 i386）

```python
# Leak offset (libc RW segment / .got.plt start)
libc_data_segment = 0x1b0000    # via 24-byte name leak
libc_start_main_ret = 0x1ae244  # via 28-byte name leak (alternative)

# Exploitation
system  = 0x3a940
bin_sh  = 0x158e8b    # "/bin/sh" string in libc
```

## 题解文章

| 文件 | 泄漏方式 | canary 绕过 | 备注 |
|------|-------------|---------------|-------|
| `138.md` | 24 字节，Ruby | `"+"` | Ruby pwnlib；为负地址转成有符号 |
| `100.md` | 24 字节 `"A"*24+"Z"` | `"a"` | 暴力重试循环；payload 未排序 |
| `1006.md` | 24 字节 | `"nope"` | 指出远端只能泄漏 3 字节的限制 |
| `1172.md` | 24 字节 | `"+"`/不给字节 | 简单思路，内联中文注释 |
| `1220.md` | 24 字节 | `"-"` | 干净的最小利用 |
| `1251.md` | 24 字节 | `"-"` | 极简；带本地/远端偏移调试开关 |
| `1269.md` | 25 字节 | `"+"` | 使用 pwntools 的 `libc.symbols` |
| `1316.md` | 24 字节 | `"zz"` | 使用 `libc.search('/bin/sh')` |
| `1351.md` | 24 字节 | `"+"` | 明确说明 `scanf` 对 "+-" 的行为 |
| `1384.md` | **两轮** | 从排序输出读 canary | 同时泄漏 PIE 基址；重跑 main |
| `1428.md` | 23+`"B"` 字节 | `"+"` | 用 `"B"` 标记泄漏完整 4 字节 dword |
| `10115.md` | 28 字节 | `"+"` | 28 字节变体用偏移 `0x1ae244` |
| `10302.md` | 25 字节 | `"-"` | 干净的 Python3 利用 |
| `11540.md` | 28 字节 | `"a"` | 暴力校验 canary；声称约 70% 成功率 |
| `12245.md` | 28 字节 | `"+"` | 中文题解，含详细栈分析 |
| `12973.md` | — | — | 一句话总结：长度不限 + 非数字绕过 canary |
| `13060.md` | 28 字节 | `"-"` | 完整 pwntools 模板，含 `libc_base-1` 填充 |
| `13484.md` | **两轮** | 从排序输出读 canary | 用 magic gadget 而非 system |
| `14479.md` | 28 字节 | `"+"`/`"scanf bypass"` | 用 `0xf0000000` 值做杂乱填充；泄漏含二进制基址 |
| `15134.md` | 28 字节 | `"+"` | 干净，用 `readelf` 显式推导偏移 |
| `15273.md` | 24 字节 | `"+"` | 详尽题解，解释三个 bug |
| `15724.md` | 详细栈分析 | `"+"` | 中文题解，含 `vmmap` / `readelf` 分析 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用利用脚本（纯 socket，不用 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/dubblesort` | 原始题目二进制（i386） |
| `artifacts/libc_32.so.6` | 远端 libc（glibc 2.23，i386） |
| `solution/*.md` | 社区题解文章（168 个解法） |
