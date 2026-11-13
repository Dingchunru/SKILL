---
tags:
  - use-after-free
  - type-confusion
  - fastbin-dup
platform: pwnable.tw
points: 350
arch: x86-64
libc: glibc-2.23
relro: full
canary: no
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "在 C++ 键值对的编辑流程中复用悬垂的对象指针会引发堆上类型混淆，从而破坏 fastbin 并覆盖伪造的 vtable。"
proof-of-concept: no
---

# CAOV — pwnable.tw（350 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10306`
>
> Flag：`FLAG{CAOV_stands_f0r_C0py_Ass1gnment_Operat0r_Vuln3rabil1ty_r3memb3r_alway5_r3turn_r3ference_typ3}`

## 题目概览

一个 C++ 键值数据库程序（x86-64，Full RELRO、NX、No PIE、No Canary），用 g++ 编译，链接 glibc 2.23。程序通过全局指针 `D` 在堆上管理单个 `Data` 对象。用户可以设置名字（存放在 160 字节的 BSS 缓冲区中）、创建键值对，并最多编辑 10 次。“CAOV”这个名字代表 **Copy Assignment Operator Vulnerability**（拷贝赋值运算符漏洞）。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT not writable
  Stack:    No canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
```

题目提供了源码（`caov.cpp`）。

## 漏洞

### V1 —— 拷贝赋值运算符按值返回（主要，可利用）

**根因：** `Data::operator=` **按值**返回一个 `Data` 对象，而不是按引用（`Data&`）。这会创建一个临时副本，该副本随后立刻被析构，对**新分配的** key 指针调用 `delete[] key`——实际上造成 **use-after-free/double-free** 局面。

```cpp
// BUG: Returns Data by value, not Data&
Data operator=(const Data &rhs)
{
    key = new char[strlen(rhs.key)+1];  // allocates new key
    strcpy(key, rhs.key);
    value = rhs.value;
    // ... copies all fields
}   // <-- returned by value: temp copy created, then ~Data() called on temp
```

在 `edit()` 函数中：

```cpp
void edit() {
    Data old;                // default-constructed, key=NULL
    old = *D;                // operator= returns by value → creates temp
                             // temp.~Data() frees temp.key (same ptr as old.key)
    D->edit_data();
    old.info();              // old.key is dangling (freed by temp's destructor)
    D->info();
}   // old.~Data() double-frees old.key
```

**影响：** 每次调用 `edit()` 都会对旧的 key 缓冲区产生一次 **double free**。

### V2 —— 通过 `set_name` 的栈复用 / 未初始化析构（主要，可利用）

**根因：** `set_name()` 与 `edit()` 共用重叠的栈帧。`set_name()` 会向位于 `[rbp-0xb0]` 的栈缓冲区最多写入 150 字节。随后 `edit()` 在同一栈位置创建 `Data old` 对象。未初始化的 `old.key` 字段会继承 `set_name` 留在栈上的内容。当 `old.~Data()` 运行时，它对这个受控的陈旧指针调用 `delete[]` → **任意释放**。

```cpp
void set_name() {
    char tmp[160] = {};           // [rbp-0xb0] on stack
    // ... reads up to 150 bytes into tmp
    memcpy(name, tmp, cnt);       // copies to BSS
}

void edit() {
    Data old;                     // overlaps set_name's stack frame
    // old.key is uninitialized → contains whatever set_name wrote at [rbp-0x50]
    old = *D;                     // operator= allocates new key, writes to old
    // ...
}   // ~Data() calls delete[] old.key
    //   BUT old.key was set by the previous assignment's return-by-value temp
    //   AND the stack residue from set_name controls the INITIAL old.key
```

具体来说，位于栈偏移 `[rbp-0x50]` 的 `old.key` 对应 `set_name` 中的 `tmp[0x60]`。只要把指针放在 `name[0x60]`（150 字节名字输入中的字节偏移 96），攻击者就能控制被释放的地址。

**影响：** 对攻击者放在名字缓冲区偏移 0x60 处的任意地址执行 `free()`。

### V3 —— 缩小时复用 key（使能点）

```cpp
void edit_data() {
    int old_len = strlen(key);
    unsigned int new_len = 0;
    // ...
    if (new_len > old_len) key = new char[new_len+1];  // only reallocates if LARGER
    set_data(new_len);  // writes new_len+1 bytes into OLD key buffer
}
```

当 `new_len <= old_len` 时，旧的 key 缓冲区会被复用而不重新分配。这一点很重要，因为它意味着 key 指针能在多次编辑后存活，使攻击者能在把伪造 chunk 释放进该位置之后，继续保持对 `D->key` 指向何处的控制。

## 关键数据结构

### Data 类（堆上 0x40 字节）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00` | `key` | `char *`（堆分配） |
| `0x08` | `value` | `long` |
| `0x10` | `change_count` | `long` |
| `0x18` | `year` | `int` |
| `0x1c` | `month` | `int` |
| `0x20` | `day` | `int` |
| `0x24` | `hour` | `int` |
| `0x28` | `min` | `int` |
| `0x2c` | `sec` | `int` |

### 全局 BSS 布局

| 地址 | 符号 | 大小 |
|---------|--------|------|
| `0x6032A0` | `D`（全局 Data 指针） | 8 字节 |
| `0x6032C0` | `name`（全局名字缓冲区） | 160 字节 |
| `0x603280` | `stderr`（FILE 指针） | 8 字节 |
| `0x603288` | `stdout`（FILE 指针） | 8 字节 |

位于 `0x60328d` 的 `0x7f` 字节（来自 BSS 中的 `stderr`/`stdout` 指针）在很多利用中充当伪造的 fastbin 大小头。

## 利用路径

所有解法都利用 V1+V2（拷贝赋值运算符 bug + 栈复用）实现任意释放，然后在如何把它转成代码执行上各异。

---

### 路径 A —— 任意释放 → House of Spirit → fastbin 投毒 → 覆盖 `D` → 泄露 libc → 覆盖 `__malloc_hook`

**使用者：** 解法 81、194、331、1316、1351、3480、3851、5586、6748、8153、32305、34817、36134、exp.py

**步骤：**

1. **通过栈复用实现任意释放（V2）：** 在 BSS 的 `name` 缓冲区（`name+0x10` = `0x6032D0`）中伪造一个 fastbin chunk。把 `name[0x60]` 设为指向这个伪造 chunk。调用 `edit()` → `set_name` 植入该指针 → `~Data()` 把伪造 chunk 释放进 fastbin。

2. **fastbin 投毒：** 被释放伪造 chunk 的 `fd` 现在可通过 `name` 缓冲区写入。把 `fd` 设为 `0x603285`（那里 `stderr` 指针带来的 `0x7f` 字节让它看起来像 0x70 fastbin chunk 的合法大小）。连续触发两次同尺寸分配，使第二次分配落在 `0x603295`，与 `0x6032A0` 处的 `D` 指针重叠。

3. **覆盖 `D`：** 通过位于 `0x603295` 的已分配 chunk 写入，把 `D`（`0x6032A0`）覆盖为指向 `name` 缓冲区。现在 `D->key` 可通过 `name[0x00]` 控制。

4. **泄露 libc：** 把 `D->key` 设为某个 GOT 表项（例如 `strlen@GOT`、`read@GOT`），或 BSS 中的 `stderr`/`stdout` 指针。调用 `show()`，或等待 edit 之后的 `info()` 输出——key 会通过 `cout << key` 被打印，泄露 libc 地址。

5. **第二次 fastbin 攻击：** 重复 House of Spirit + fastbin 投毒，这次把 `fd` 设为 `__malloc_hook - 0x23`（libc 中那里有个 `0x7f` 字节可充当伪造大小）。分配两次，让某个 chunk 与 `__malloc_hook` 重叠。

6. **写入 one-gadget：** 用 one-gadget 地址覆盖 `__malloc_hook`。下一次 `malloc`（由任意 key 分配触发）就会执行 `execve("/bin/sh")`。

**关键地址（无 PIE）：**
- name 中的伪造 chunk：`0x6032D0`
- `stderr` 的 0x7f 伪造大小：`0x603285`
- `D` 指针：`0x6032A0`
- `name` 缓冲区：`0x6032C0`

---

### 路径 B —— 任意释放 → 释放 Data 对象 → key 与 Data 重叠 → 任意读写 → `__malloc_hook`

**使用者：** 解法 821、1220、13019

**步骤：**

1. **堆泄露：** 从 BSS 释放一个伪造 chunk，安排 fastbin，使某个堆地址被写入 `name` 缓冲区（作为被释放 chunk 的 fd）。通过 `show()` 读回。

2. **释放 Data 对象：** 用堆泄露算出 `Data` 对象的地址。通过任意释放把它释放。

3. **在 Data 之上分配 key：** 分配一个与 Data 对象 chunk 尺寸相符的 key。该 key 现在与 Data 对象重叠，可以直接控制 `D->key`、`D->value`、`D->change_count`。

4. **任意读：** 把 `D->key` 设为任意地址 → `show()` 打印该地址的内容。通过 GOT 表项泄露 libc。

5. **任意写：** 把 `D->key` 设为目标地址 → `edit()` 把新 key 内容写到该地址。把 one-gadget 写到 `__malloc_hook`。

---

### 路径 C —— 任意释放 → unsorted bin → libc 泄露 → `__malloc_hook`

**使用者：** 解法 375、3851

**步骤：**

1. **构造更大的伪造 chunk：** 在 BSS 中伪造一个大小为 `0xC1` 或更大（超出 fastbin 范围）的 chunk，并配好正确的 next-chunk 头。

2. **释放进 unsorted bin：** 任意释放这个伪造的大 chunk → libc 的 main_arena 指针（fd/bk）被写入 BSS 的 name 缓冲区。

3. **泄露 libc：** 通过 `show()` 从 name 缓冲区读取 unsorted bin 指针。

4. **fastbin 攻击：** 接着做 fastbin 投毒，用 one-gadget 覆盖 `__malloc_hook`。

---

### 路径 D —— 对 stdout/stderr 进行 FSOP / vtable 劫持

**使用者：** 解法 331、1316、11954、exp.py

**步骤：**

1. 通过路径 A 或 B **泄露 libc**。

2. **覆盖 `_IO_2_1_stdout_` 或 `_IO_2_1_stderr_`：** 用任意写破坏 FILE 结构的 vtable 指针，使其指向 BSS `name` 缓冲区中的伪造 vtable。

3. **填充伪造 vtable：** 在伪造 vtable 中填入 `system` 地址。把 FILE 的 flags/name 字段设为 `"/bin/sh"`。

4. **触发：** 任何 I/O 操作（例如 `cout <<`）都会经过被破坏的 vtable 调用 → `system("/bin/sh")`。

这条路径更复杂，但能绕过 one-gadget 约束不满足的情况。

---

### 路径 E —— 通过 `__environ` 泄露栈 → 覆盖返回地址

**使用者：** 解法 821

**步骤：**

1. 通过路径 A 或 B **泄露 libc**。

2. **泄露栈：** 把 `D->key` 设为 libc 中的 `__environ` → `show()` 打印栈地址。

3. **覆盖返回地址：** 算出栈上返回地址的位置。把 `D->key` 设为该地址，写入 one-gadget 或 ROP 链。

4. **触发：** 在菜单中选择 “Exit” → `main()` 返回 → one-gadget 执行。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 任意释放 | V1+V2：operator= 按值返回 + 栈复用 | 确定性 |
| fastbin 投毒 | BSS 中的伪造 chunk + 来自 stderr 的 `0x7f` | 确定性 |
| 覆盖全局 `D` 指针 | 在 `0x603295` 处 fastbin 分配 | 确定性 |
| 任意读（通过 key） | 控制 `D->key` → `cout << key` | 确定性 |
| 任意写（通过 key 编辑） | 控制 `D->key` → `cin.getline(key, n)` | 确定性 |
| 覆盖 `__malloc_hook` | 在 `__malloc_hook - 0x23` 附近的 fastbin 攻击 | 确定性 |
| 代码执行 | 通过 `__malloc_hook` 的 one-gadget 或 FSOP | 确定性 |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
# libc offsets
_IO_2_1_stderr_ = 0x3C4540
_IO_2_1_stdout_ = 0x3C4620
__malloc_hook    = 0x3C3B10
__free_hook      = 0x3C57A8
system           = 0x45390
stdin_fileno     = 0x3C38E0

# one_gadgets
one_gadgets = [0x45216, 0x4526a, 0xef6c4, 0xf0567]

# BSS addresses (no PIE)
D_ptr       = 0x6032A0
name_buf    = 0x6032C0
stderr_ptr  = 0x603280
stdout_ptr  = 0x603288
fake_size   = 0x603285  # 0x7f byte from stderr pointer
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `81.md` | A | House of Spirit + fastbin 投毒 → 通过时间泄露使用 one_gadget | 用日期字段泄露 libc |
| `194.md` | B | 任意释放 → 释放 Data 对象 → GOT 泄露 → `__malloc_hook` | 清晰的结构化思路 |
| `331.md` | A+D | fastbin 投毒 → 覆盖 `D` → 劫持 stdout vtable | FSOP 收尾 |
| `375.md` | A | fastbin 投毒 → 覆盖 `D` → 泄露 stderr → fastbin 打 `__malloc_hook` | 多轮 fastbin |
| `821.md` | A+E | fastbin → 覆盖 `D` → 泄露 environ → 栈上 ROP | 覆盖返回地址 |
| `1220.md` | B | 释放 Data 对象 → key 重叠 → GOT 泄露 → 经 fastbin 打 `__malloc_hook` | 计算堆地址 |
| `1316.md` | A+D | fastbin → 泄露 stderr → 覆盖 stderr vtable → `system` | 通过 stderr 做 FSOP |
| `1351.md` | A | fastbin → 泄露 read GOT → `__malloc_hook` + one_gadget | 直接且干净 |
| `1763.md` | A | fastbin 投毒 → 泄露并覆盖 `__malloc_hook` | 使用 malloc_hook+0x48 |
| `3480.md` | A | fastbin + 大 key 分配 → GOT 泄露 → `__malloc_hook` | 使用 0x40 大小的伪造 chunk |
| `3851.md` | A+C | 多轮 fastbin + unsorted bin → libc 泄露 | 复杂的堆布局 |
| `5586.md` | A | 紧凑的 fastbin 链 → 泄露 stderr → `__malloc_hook` | 操作极少 |
| `6748.md` | A | fastbin → 泄露 exit GOT → `__malloc_hook` | 带分析的中文题解 |
| `8153.md` | A | fastbin → 泄露 stderr → `__malloc_hook` | 干净的利用 |
| `11954.md` | A+D | fastbin → GOT 泄露 → stdout vtable + one_gadget | FSOP 兜底 |
| `13019.md` | B+E | 释放 Data → GOT 泄露 → environ → 覆盖栈返回地址 | 堆 + 栈结合 |
| `32305.md` | A | House of Spirit → fastbin → 泄露 stderr → `__malloc_hook` | 详细的堆布局 |
| `34817.md` | B+C | 释放 Data → unsorted bin → libc 泄露 → `__malloc_hook` | 大量依赖堆的方案 |
| `36134.md` | A | House of Spirit → fastbin 投毒 → `__malloc_hook` | 步骤记录详实 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `artifacts/caov.cpp` | 题目源码（作者提供） |
| `artifacts/caov` | 题目二进制（x86-64，Full RELRO，No PIE） |
| `artifacts/libc_64.so.6` | 远程 libc（glibc 2.23） |
| `exp.py` | 可用的利用脚本 |
| `desc.txt` | 题目描述 |
| `solution/*.md` | 社区题解（52 篇） |
