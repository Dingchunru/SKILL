---
tags:
  - type-confusion
  - out-of-bounds-write
  - got-overwrite
platform: pwnable.tw
points: 600
arch: x86-64
libc: glibc-2.23
relro: partial
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "围棋棋盘上的坐标编码混淆导致数组越界索引，从而实现任意 GOT 覆盖并劫持程序执行流。"
proof-of-concept: no
---

# OmegaGo — pwnable.tw（600 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10405`
>
> Flag: `FLAG{now_you_can_try_to_fight_with_AlphaGo~}`

## 题目概览

一个简化的围棋游戏（19x19 棋盘）二进制（x86-64，No PIE，Partial RELRO，NX，无 Canary），链接 glibc 2.23。玩家执黑（`X`）与 AI（`O`）对弈。支持的命令有：坐标落子（如 `D19`）、`regret`（悔棋，撤销上一手双方）、`surrender`（认输）。棋盘状态以每格 2 bit 的位图存于 BSS，另有一个**历史数组**记录每一步对应的堆上棋盘快照指针。

```bash
file ./omegago
  ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

checksec:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
```

## 关键数据结构

### 棋盘位图（BSS `g_cur_state`，约 0x609FC0）

19x19 棋盘用每格 2 bit 的位图编码（12 个 qword）：

| 2 bit 值 | 显示 | 含义 |
|-------------|---------|---------|
| `0b00` | `.` | 空 |
| `0b01` | `O` | 白子（AI） |
| `0b10` | `X` | 黑子（玩家） |
| `0b11` | `\x00` | （非法/泄漏标记） |

每个 qword 编码 32 格。棋盘共 361 格 = 11.28 个 qword，按 12 个 qword 存储（最后一个只部分使用）。

### 历史数组（BSS `g_history`，约 0x609460）

固定大小的指针数组，指向堆上的棋盘快照。每步（玩家 + AI 应手 = 2 个条目）会压入一个新的快照指针。数组容量为 **364 个条目**（182 手对），但**没有任何边界检查**。

### AI 玩家对象（堆，0x10 字节）

AI 玩家是一个用 `new` 分配的 C++ 对象（fastbin 0x20 堆块）。其第一个字段是**虚表指针**。AI 落子时会经该虚表调用虚函数。

### 输入缓冲区（BSS `g_input`，0x60943C）

玩家的坐标输入经 `scanf("%10s", g_input)` 读入位于 `0x60943C` 的固定 BSS 缓冲区。去掉 4 字节坐标前缀后的可用地址是 `0x609440`。

## 漏洞

### V1 — 历史数组溢出（主漏洞，可利用）

**根因：** `g_history`（约 0x609460）处的历史数组有 364 个指针的空间，但代码从不检查索引是否超过该上限。利用围棋的**打劫规则**（反复提子的循环），玩家可以在一局中造出远超 182 手的对局，使历史指针写入越过数组，溢进相邻的 **`g_cur_state` 棋盘位图**。

```text
BSS layout:
  0x609460: g_history[0..363]    (364 × 8 = 0xB60 bytes)
  0x609FC0: g_cur_state          (board bitmap, 12 qwords)
```

当 `history_count > 364` 时，新的历史条目会覆盖 `g_cur_state.bitmap[0]`、`bitmap[1]` 等。由于历史条目是**堆指针**，棋盘位图里就有了堆地址，而**可以通过查看棋盘把它们读回来**。

**影响：**
- **堆指针泄漏**：被覆盖的位图格子会显示成棋盘字符，可反向解码为 2 bit 表示再拼回原始指针值。
- **受控指针操纵**：多走一步就能让指针产生可预测的增量（例如每步 +0x80）。配合 `regret`，就得到任意地址读原语。

### V2 — `regret` 解引用被破坏的历史指针（可利用）

**根因：** `regret` 命令通过从 `g_history[last]` 载入棋盘来撤销上一步。若历史已溢出、`g_history[last]` 现在（经 V1）指向攻击者控制的地址，`regret` 就会把任意的堆/内存内容载入显示的棋盘。

```python
regret flow:
  1. Remove last 2 history entries
  2. Copy board from g_history[new_last] into g_cur_state
  3. Display the new board to the player
```

**影响：** 先（经再走一步、按已知偏移移动指针）修改被溢出的指针，再调用 `regret`，玩家即可**读任意内存**——棋盘会把指针目标处的内存以 2 bit 编码的格子显示出来。

### V3 — 借棋盘状态伪造 fastbin 块（House of Spirit）

**根因：** 棋盘状态存放在堆上（作为历史快照的一部分）。由于玩家能控制哪些格子是 `X`（0b10）、`O`（0b01）或 `.`（0b00），就能把任意 2 bit 图案编码进棋盘。关键之处在于：在正确偏移处，一个形如 `..X.....` 的棋盘状态恰好编码出 `0x20`——一个合法的 fastbin 堆块 size 头。

通过在棋盘合适的 qword 偏移处编码两个 `0x21` size 字段，再安排 `surrender` 释放一个落在该区域的指针，玩家就能在堆上伪造出一个 **fastbin 块**。

**影响：** 下一次为 AI 玩家对象做 `new` 分配（大小 0x10，fastbin 0x20）时，会返回这个伪造块，从而与之后玩家可以改写的棋盘状态重叠。

### V4 — 把输入缓冲区当作虚表（代码执行）

**根因：** BSS 中的输入缓冲区 `g_input` 位于 `0x609440`（No PIE，地址固定），可由 `scanf` 写入攻击者控制的数据。若把 AI 玩家对象的虚表指针覆盖为 `0x609440`，下一次虚调用就会把 `*(0x609440)` 当作函数指针解引用。

**影响：** 通过特定的落子把 `0x609440` 编码进棋盘位图（使其 2 bit 编码产生该值），并让溢出触及 AI 对象的虚表字段，玩家就能控制该虚函数指针。发送形如 `"D1\x00\x00" + p64(one_gadget)` 的落子，把 one_gadget 地址放到 `0x609440`，下一次 AI 虚调用就会跳过去 → shell。

## 利用路径

### 路径 A — 历史溢出 → 泄漏 → House of Spirit → 虚表劫持（最常见）

**相关题解：** 59、821、2121、5586、6247、6748、8153、11954、14523、22319、34817

**步骤：**

1. **堆对齐：** 认输 1-2 次调整堆布局，使命历史指针的最低字节比较“友好”（不含 `0b11` 位对，因为这种值无法在棋盘上表示）。

2. **溢出历史做泄漏：**
   - 借打劫循环（在固定位置交替提子）填满棋盘，造出 365+ 条历史记录。
   - 当 history[364] 覆盖 `g_cur_state.bitmap[0]` 时，棋盘上出现一个**堆指针** → **堆泄漏**。
   - 再走一步（例如 `D19`）让指针偏移 `+0x80`。
   - 调用 `regret` → 棋盘改从 `*(shifted_pointer)` 载入，该处含有**libc 地址**（如 `main_arena` 或 `_IO_wfile_jumps`）→ **libc 泄漏**。

3. **造伪造 fastbin 块：**
   - 认输重开。再认输 4-6 次调整堆布局。
   - 在新局中落子，在棋盘两个 qword 对齐位置编码出 `0x21` size 字段（例如 `R8` → 在正确 bit 位置编码 0x20；`D12` → 第二个 size 字段）。
   - 再次溢出历史，让某个历史指针指向伪造块区域。
   - 认输 → 伪造块被释放进 fastbin(0x20)。

4. **在伪造块里分配 AI 对象：**
   - 开新局。AI 玩家对象的 `new` 从 fastbin(0x20) 分配，落在之前释放的伪造块上。
   - 这个伪造块位于某块棋盘状态位图之中，而玩家稍后可以改写它。

5. **覆盖虚表：**
   - 落子编码出 `0x609440`（BSS 输入缓冲区地址），放在与 AI 对象虚表字段重叠的 qword 偏移处。
   - 填满棋盘触发溢出，把编码好的地址压到虚表上。

6. **触发 one-gadget：**
   - 发送带二进制尾部的落子命令：`"F8\x00\x00" + p64(one_gadget)` 或类似形式。坐标部分被当作落子解析，而尾部字节把 one_gadget 地址写进 `0x609440` 的输入缓冲区。
   - AI 的下一次虚调用解引用 `g_input` → `one_gadget` → shell。

**可靠性：** 每次尝试约 50-80%。当堆地址含有 `0b11` 位对（无法在棋盘上表示）时失败。多数解法用循环重试。

---

### 路径 B — 历史溢出 → 操纵 stdin 缓冲区 → 虚表劫持

**相关题解：** 2311

**变体：** 不在棋盘上编码地址，而是操纵堆上的 **stdin 缓冲区**。在 `surrender` 提示处发送长填充输入（如 `"surrender\0".rjust(0x2e0, '\n')`），解题者就把受控数据写进了 stdin 缓冲区的深处。该缓冲区位于堆上，相对堆基址的偏移可预测。

1. 溢出历史泄漏堆地址，并把指针设到 stdin 缓冲区区域。
2. 经填充过的 `surrender`/`regret` 命令把伪造块头（`0x31` size）写进 stdin 缓冲区。
3. 让历史溢出指针指向它，释放该伪造块。
4. AI 对象被分配进 stdin 缓冲区。再经后续 stdin 写入覆盖虚表。
5. 用 `setcontext+87` gadget 替代 one_gadget，更可靠地 `execve("/bin/sh")`。

---

### 路径 C — 历史溢出 → House of Orange

**相关题解：** 26957

**变体：** 不做 fastbin 操作，改用 **House of Orange**：

1. 经历史溢出 + regret 泄漏堆和 libc（同路径 A）。
2. 经填充命令把伪造的 `0x1a1` 大小堆块头写进 stdin 缓冲区。
3. 把伪造块释放进 unsorted bin（尺寸超出 fastbin 范围）。
4. 破坏 unsorted bin 做 unsorted bin attack，覆盖 `_IO_list_all`。
5. 伪造一个 `_IO_FILE` 结构体，虚表指向 `system`，在下一次 `malloc` 错误路径上触发。

---

### 路径 D — 打劫循环 + 填充策略（镜像围棋变体）

**相关题解：** 59、8153

**变体：** 这些解法用**“镜像围棋”**策略高效填满棋盘。在对称位置落子，AI 的应手可预测（它会镜像玩家）。这样就无需复杂的打劫布置，也能稳定造出触发溢出所需的步数。

预先算好的落子序列存放在外部文件（`mirror1`、`super_mirror`、`super_mirror2`）中，重放即可精确控制棋盘状态与溢出次数。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 历史数组溢出 | V1：历史索引无边界检查 | 确定性 |
| 堆指针泄漏 | V1：溢出的指针显示为棋盘 | 确定性 |
| libc 泄漏 | V1+V2：regret 把任意内存载入棋盘 | 确定性 |
| 伪造 fastbin 块 | V3：棋盘位图编码出 0x21 块头 | 确定性 |
| 虚表劫持 | V4：AI 对象被分配进受控区域 | 对齐成功后 |
| 代码执行 | 经虚表调用的 one-gadget/setcontext | 控制虚表后确定性 |

## 编码约束

棋盘每格只能表示 2 bit 值 0、1、2。值 3（`0b11`）显示为 `\x00`，且**玩家无法放置**（只能放 `X`=2，或由 AI 镜像产生 `O`=1）。这意味着任何要在棋盘上编码的地址或值，其 2 bit 分解中都不得出现 `0b11` 位对。这是利用不可靠的主要来源——若堆基址含这类位对，就必须重试。

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
# BSS addresses (No PIE)
g_input       = 0x60943C   # scanf input buffer
g_input_plus4 = 0x609440   # usable vtable target
g_history     = 0x609460   # history array start
g_cur_state   = 0x609FC0   # board bitmap start

# libc offsets
main_arena+88 = 0x3c3b78   # unsorted bin leak marker
one_gadgets   = [0xf0567, 0xf1247, 0x4527a]
system        = 0x45390
setcontext+87 = ...         # for setcontext-based exploits
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `59.md` | A（镜像） | 镜像围棋 + 伪造 fastbin + 虚表 | 使用外部落子文件；对局策略详尽 |
| `821.md` | A | 打劫溢出 + regret 泄漏 + fastbin | 干净的题解，附编码辅助函数 |
| `2121.md` | A | 填盘 + 泄漏 + fastbin | 简洁；直接填充 |
| `2311.md` | B | 操纵 stdin 缓冲区 + setcontext | 替代棋盘编码；也有 one_gadget 变体 |
| `2972.md` | A | 打劫 + regret + 伪造块 | 详细的 bug 描述 |
| `5586.md` | A | 填充 + regret + House of Spirit | 两份利用脚本（one_gadget 与 setcontext 变体） |
| `6247.md` | A | 整行填充 + 编码地址 | 简单干净的实现 |
| `6748.md` | A | 基于打劫的溢出，含 Pos 类 | 结构化 OOP 写法 |
| `8153.md` | A（镜像） | 镜像围棋自动化 | 大量 oracle/镜像策略；利用脚本极长 |
| `11954.md` | A | 直接填充 + stdin 填充 | 用 stdin 缓冲区放伪造块头 |
| `14523.md` | A | 打劫循环 + 编码 | 直接实现 |
| `22319.md` | A | 填充 + 溢出 + 虚表 | 带注释的分步说明清晰 |
| `26957.md` | C | House of Orange | unsorted bin attack + 伪造 _IO_FILE |
| `34817.md` | A | 打劫 + 填充 + 虚表 | 干净收尾，附 DECODE 辅助函数 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用利用脚本 |
| `desc.txt` | 题目描述 |
| `flag.txt` | 已捕获的 flag |
| `artifacts/omegago` | 题目二进制（strip 的 ELF x86-64） |
| `artifacts/libc_64.so.6` | 远端 libc（glibc 2.23） |
| `solution/*.md` | 社区题解文章（14 个解法） |
