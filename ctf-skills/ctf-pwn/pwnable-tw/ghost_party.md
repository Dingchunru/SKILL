---
tags:
  - type-confusion
  - use-after-free
  - vtable-hijack
platform: pwnable.tw
points: 400
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "把不匹配的 C++ 派生类对象重新分配到已释放的槽位，会造成类型混淆，从而可将虚表重定向到 system。"
proof-of-concept: no
---

# Ghost Party — pwnable.tw（400 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10401`
>
> Flag: `FLAG{D0n7_f0g07_7H3_c0pY_c0Ns7Ruc70R}`

## 题目概览

一个 C++ 幽灵管理程序（x86-64，PIE，Full RELRO，NX，栈 Canary），链接 glibc 2.23。题目提供源码（`ghostparty.cpp`）。玩家管理一个 `vector<Ghost*> ghostlist` 的多态幽灵对象——共 10 个幽灵子类（Werewolf、Devil、Zombie、Skull、Mummy、Dullahan、Vampire、Yuki-onna、Kasa-obake、Alan）。每个子类都有虚表、虚函数（`speak`、`changemsg`、`ghostinfo`、析构函数）以及类专属字段（有的是裸 `char*`，有的是 `std::string`）。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## 漏洞

### V1 — Vampire 缺少拷贝构造函数（主漏洞，use-after-free / double-free）

**根因：** `Vampire` 类有一个用 `new char[]` 分配的裸指针成员 `blood`，但**没有定义拷贝构造函数**。编译器生成的默认拷贝构造函数对 `blood` 做**浅拷贝**（只复制指针，不复制数据）。而 `~Vampire()` 会调用 `delete[] blood`。

```cpp
class Vampire : public Ghost {
    // NO copy constructor defined!
    // Compiler generates: Vampire(const Vampire &v) { blood = v.blood; ... }
    ~Vampire() { delete[] blood; }  // frees the shared pointer
private:
    char *blood;
};
```

`smalllist<T>()` 的选项 3（"Join and hear what the ghost say"）调用 `speaking(*ghost)`，而该函数是**按值**传参的：

```cpp
template <class T>
void speaking(T ghost) {   // pass-by-value → copy constructor called
    ghost.speak();
};                          // temporary destroyed → ~Vampire() → delete[] blood

// In smalllist(), option 3:
case 3:
    ghostlist.push_back(ghost);   // ghost added to list (original pointer)
    speaking(*ghost);             // *ghost copied → shallow copy of blood
    // ~Vampire temporary dies → delete[] blood → UAF on original's blood!
```

**影响：** 执行 `smalllist(vampire, 3)` 之后，Vampire 的 `blood` 指针变成指向已释放堆内存的**悬垂指针**。通过 `ghostinfo()` 读取 `blood` 可泄漏堆/libc 数据。而原 Vampire 的 `~Vampire()` 之后还会对同一堆块二次释放。

### V2 — Alan 的 `lightsaber` 缺少析构处理（use-after-free）

**根因：** `Alan` 类把 `lightsaber` 存为 `char*`，赋值来源是临时 `std::string::c_str()`。`addlightsaber()` 返回时该 `std::string` 被销毁，`lightsaber` 就此悬垂。

```cpp
class Alan : public Ghost {
    void addlightsaber(string str) {
        lightsaber = (char*)str.c_str();  // points to temporary string's buffer
    }                                     // str destroyed → lightsaber dangles
    ~Alan() {};                           // no delete → no double-free, but UAF on read
private:
    char *lightsaber;
};
```

**影响：** 构造完成后，Alan 的 `lightsaber` 指向已释放的堆内存。通过 `ghostinfo()` 读取它，会泄漏此刻占用该堆块的数据——通常是 `stdout`（`_IO_2_1_stdout_`）地址或堆元数据（fd/bk 指针），从而得到 **libc 或堆泄漏**。

### V3 — Devil/Zombie/Werewolf 有正确的拷贝构造函数（不受影响）

这些类定义了显式拷贝构造函数，对其裸指针做深拷贝，正好与 Vampire 缺少拷贝构造函数形成对照。

```cpp
class Devil : public Ghost {
    Devil(const Devil &copyghost) {
        // ...
        power = new char[strlen(copyghost.power)+1];  // deep copy
        strcpy(power, copyghost.power);
    };
};
```

## 关键数据结构

### Ghost 对象布局（基类，约 0x68 字节）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00` | `vtable` | `void**`（编译器生成） |
| `0x08` | `age` | `int` |
| `0x10` | `name` | `char*`（堆分配） |
| `0x18` | `type` | `std::string`（SSO 内联或堆） |
| `0x38` | `msg` | `std::string`（SSO 内联或堆） |

### Vampire 对象（继承 Ghost，约 0x70 堆块 = 0x60 可用）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00`–`0x57` | Ghost 基类字段 | （vtable、age、name、type、msg） |
| `0x58` | `blood` | `char*` ← 有漏洞的字段 |

### Werewolf 对象（约 0x70 堆块）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00`–`0x57` | Ghost 基类字段 | |
| `0x58` | `trans` | `int`（满月标志） |

### Alan 对象（约 0x70 堆块）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00`–`0x57` | Ghost 基类字段 | |
| `0x58` | `lightsaber` | `char*` ← 构造后即悬垂 |

## 利用路径

所有解法先用 V1（Vampire 浅拷贝）和/或 V2（Alan 悬垂 lightsaber）完成初次泄漏，然后在代码执行策略上分道扬镳。

---

### 路径 A — Vampire UAF → 泄漏 + Fastbin Dup → 覆盖 `__malloc_hook`

**相关题解：** 185、821、1912、2972、34817 等

**步骤：**

1. **泄漏 libc**：借 Vampire 悬垂的 `blood`：
   - 创建一个 `blood` 较大的 Vampire（例如 `0x100` 字节 → unsorted bin 尺寸）。用选项 3 → `blood` 被释放。
   - 已释放堆块的 fd/bk 里是 main_arena 指针。`showinfo(vampire)` 打印 `Blood:` = libc 泄漏。

2. **借 Vampire 双释放做 Fastbin 重复**：
   - 创建一个 `blood` 大小为 0x60（→ 0x70 堆块，fastbin）的 Vampire。用选项 3 → blood 被释放（第一次释放）。
   - `rmghost(vampire)` → `~Vampire` 再次 `delete[] blood` → **双释放**同一个 0x70 堆块。

3. **Fastbin 投毒** → 分配到 `__malloc_hook - 0x23`：
   - 分配一个新对象，其 0x70 大小的分配从被破坏的 fastbin 取块，把 `__malloc_hook - 0x23` 写成下一个 fd 指针。
   - 再分配两次 0x70 → 第三次落到 `__malloc_hook - 0x23`。
   - 在偏移 +0x13 处写入 `one_gadget`（即 `__malloc_hook`）。

4. **触发 `malloc`** → `one_gadget` → shell。

**可靠性：** 确定性。Full RELRO 意味着 GOT 只读，因此对 glibc 2.23 而言 `__malloc_hook`/`__realloc_hook` 是标准目标。

---

### 路径 B — Vampire UAF → 经堆块重叠劫持虚表

**相关题解：** 59、568、786、6247、9251、31599、32858

**步骤：**

1. **泄漏 PIE 基址**：Vampire UAF + Werewolf：
   - 用选项 3 创建一个 `blood` 大小 0x60 的 Vampire → blood 被释放。
   - 创建一个同样 0x60 大小的 Werewolf → 复用了这块已释放的 blood 堆块。
   - `showinfo(vampire)` 打印 `Blood:` = Werewolf 的虚表指针 → **PIE 基址**。

2. **借任意读泄漏堆/libc**：
   - `rmghost(vampire)` → `~Vampire` 释放 blood = **释放了 Werewolf 对象**，而 `ghostlist[0]` 仍指向它（悬垂 `Ghost*`）。
   - 创建一个 Mummy/Kasa/Dullahan，其 `std::string` 数据与被释放的 Werewolf 堆块重叠 → 在 `ghostlist[0]` 处得到**伪造 Ghost 对象**。
   - 设 `fake.name = target_address`。`listghost()` 调用 `getname()`（非虚函数）→ 读取 target 处的字符串 → **任意读**。
   - 读 `GOT[__libc_start_main]` → libc 基址。读全局 `ghostlist` → 堆基址。

3. **劫持虚表**实现代码执行：
   - 构造最终伪造 Ghost 对象，`vtable` 指向堆上的伪造虚表。
   - 伪造虚表的 `ghostinfo` 槽（vtable+0x10）= `one_gadget`。
   - `showinfo(0)` 调用 `ghostlist[0]->ghostinfo()` → one_gadget → shell。

**可靠性：** 泄漏到地址后是确定性的。比路径 A 复杂，但不需操作 fastbin。

---

### 路径 C — Alan UAF → libc 泄漏 + Vampire 双释放 → `__malloc_hook`

**相关题解：** 331、821、1351、6247

**步骤：**

1. **泄漏 libc**：借 Alan 悬垂的 `lightsaber`：
   - 创建 Alan → `lightsaber` 指向堆上已释放的 `std::string` 缓冲区。
   - 该已释放堆块被 libc 内部其他分配复用。`showinfo(alan)` 打印 `Lightsaber:` = 占用该堆块的指针 → 往往是 libc 地址（`stdout`、main_arena）。
   - 或者创建第二个带大 lightsaber 字符串的 Alan，使其落入 unsorted bin。

2. **双释放 + fastbin 投毒**：经 Vampire（同路径 A 步骤 2-4）。

3. **用 one_gadget 覆盖 `__malloc_hook`** → 触发 → shell。

---

### 路径 D — FILE 结构体攻击（`_IO_list_all` / stdout 虚表）

**相关题解：** 278、331、1351、38838

**步骤：**

1. **经 V1 或 V2 泄漏 libc + 堆**。

2. **Fastbin 投毒**，分配到与 `stdout` 或 `_IO_list_all` 重叠的堆块：
   - 用 `_IO_list_all` 或 `stdout` 附近的 0x7f 字节充当伪造 fastbin 堆块的大小字段。
   - 覆盖 `stdout` 的虚表指针 → 指向堆上的伪造虚表。

3. **伪造虚表**中 `__overflow` 或 `xsputn` = `system` 或 `one_gadget`。
   - 当 `cout <<` 触发 `stdout` 虚表派发 → shell。

**可靠性：** 更脆弱；需要精细构造 FILE 结构体。

---

### 路径 E — Devil UAF → 泄漏 + 虚表重叠

**相关题解：** 59、32858

与路径 B 类似，但改用 Devil 的 `power`（同样是裸 `char*`）实现基于 UAF 的重叠。Devil 有正确的拷贝构造函数，但 `speaking()` 的按值传参在删除后仍会创造堆布局操作的机会。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 悬垂 `blood` 指针（UAF 读） | V1：Vampire 浅拷贝 | 确定性 |
| `blood` 堆块双释放 | V1：Vampire 析构 + 浅拷贝析构 | 确定性 |
| 悬垂 `lightsaber` 指针（UAF 读） | V2：Alan 对临时对象的 c_str() | 确定性 |
| libc 泄漏（unsorted bin fd/bk） | 释放后经悬垂指针读取 | 确定性 |
| PIE 泄漏（虚表指针） | Vampire 的 blood 与 Werewolf 虚表重叠 | 确定性 |
| 堆泄漏 | 从 fastbin 堆块读 fd 指针 | 确定性 |
| 任意读 | 伪造 Ghost 对象并控制 `name` | PIE+堆泄漏后 |
| `__malloc_hook` 覆盖 | Fastbin dup + 投毒（glibc 2.23） | 确定性 |
| 虚表劫持 | 堆上伪造虚表 → one_gadget | 确定性 |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
# libc offsets
main_arena_88   = 0x3c3b78
__malloc_hook   = 0x3c3b10
__free_hook     = 0x3c57a8
system          = 0x45390
__libc_start_main = 0x20740
stdout          = 0x3c4620
_IO_list_all    = 0x3c5520
one_gadgets     = [0x45216, 0x4526a, 0xef6c4, 0xf0567]

# binary offsets (PIE-relative)
Werewolf_vtable = 0x210b98
ghostlist_vector = 0x211030
GOT_libc_start_main = 0x210e90
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `59.md` | B | Vampire UAF → 虚表重叠链 | 串起 3 个 vampire；经 fastbin 重叠虚表 |
| `185.md` | A | Vampire UAF → fastbin dup → `__malloc_hook` | 干净的 fastbin dup 做法 |
| `278.md` | D | Vampire + fastbin → stdout 虚表劫持 | Ruby；覆盖 stdout 虚表 |
| `331.md` | D | Alan + Vampire → FILE 结构体 → system | 用 `system` 覆盖 stdout FILE 结构体 |
| `568.md` | B | Alan UAF → libc 泄漏 → 虚表劫持 | Ruby；Alan 负责泄漏，Vampire 负责劫持 |
| `786.md` | B | Vampire + Alan → 虚表劫持 | 用悬垂 blood → 虚表派发 |
| `821.md` | A+C | Alan UAF → libc，Vampire dup → `__malloc_hook` | Alan lightsaber 泄漏 + fastbin dup |
| `1172.md` | B | Vampire UAF → PIE → 任意读 → 虚表 | 经 Mummy 搭完整伪造 Ghost 链 |
| `1351.md` | D | Alan + Vampire → `_IO_list_all` | FILE 结构体攻击 |
| `1912.md` | A | Vampire + Alan → fastbin → `__malloc_hook` | 堆 + libc 双重泄漏 |
| `2972.md` | A | Alan → 堆+libc → Vampire dup → `__malloc_hook` | Alan 负责泄漏，Vampire 负责破坏 |
| `6247.md` | A+C | Alan → libc，Vampire dup → `__malloc_hook` | 简洁做法 |
| `8153.md` | A | Vampire → libc，双释放 → `__malloc_hook` | 干净；使用 `__realloc_hook` 变体 |
| `9251.md` | B | Alan → libc+PIE，Vampire → 虚表劫持 | 完整泄漏链，伪造虚表派发 |
| `24887.md` | B+E | Devil UAF → PIE → Vampire 虚表喷射 | C++ 利用脚本（！）；使用 pwntools C++ 绑定 |
| `31599.md` | B | Vampire → PIE，Kasa msg → 伪造 Ghost → 任意读 | 用 Kasa-obake 造伪造对象 |
| `32858.md` | B+E | Devil UAF → 堆+libc，Vampire → 虚表 | 向 blood 堆块喷射 one_gadget |
| `34817.md` | A | Vampire → unsorted bin 泄漏 libc → fastbin dup | 极简做法；“违反 rule of three” |
| `38838.md` | D | Alan → libc，Vampire → `_IO_list_all` fastbin | 经 `_IO_list_all` 的 FileStructure 攻击 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `artifacts/ghostparty.cpp` | 题目源码（题目作者提供） |
| `artifacts/ghostparty` | 题目二进制（x86-64，PIE，Full RELRO） |
| `artifacts/libc_64.so.6` | 远端 libc（glibc 2.23） |
| `exp.py` | 可用利用脚本（路径 B：经伪造 Ghost 劫持虚表） |
| `desc.txt` | 题目描述 |
| `solution/*.md` | 社区题解文章（51 个解法） |
