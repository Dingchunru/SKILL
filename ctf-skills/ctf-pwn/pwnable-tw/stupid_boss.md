---
tags:
  - use-after-free
  - type-confusion
  - got-overwrite
platform: pwnable.tw
points: 500
arch: x86-64
libc: glibc-2.23
relro: full
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "员工类结构中的 use-after-free 漏洞可篡改函数指针，把执行流劫持到 system。"
proof-of-concept: no
---

# Stupid Boss — pwnable.tw（500 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10409`
>
> Flag：`FLAG{My_5+up1d_B0s5es_ar3_s0_dumb_th3y_Thlnk_J4v4_&_J4v45cripT_4r3_th3_s4m3}`

## 题目概况

一个 C++11 的"程序员 RPG"（x86-64，PIE、Full RELRO、NX、Canary），链接 glibc 2.23。玩家通过猜拳式战斗打史莱姆，累积各语言的 EXP。技能达标后"蠢老板"会派两个项目（Trojan 和 Web），每个项目有两个 `Language*` 槽位，可以查看和更换。题目提供了源码（`stupid.cpp`）。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Full RELRO           # GOT read-only
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## 关键数据结构

### Language 派生类布局（所有派生类，64 字节）

| 偏移 | 字段 | 备注 |
|--------|-------|-------|
| `0x00` | `vptr` | 虚表指针（`info()` 是虚函数） |
| `0x08` | `LANG lang` | 枚举值 |
| `0x10` | `std::string name` | 32 字节（SSO） |
| `0x30` | `unsigned long ratio` | `basic_info()` 以 `"Ratio: <ratio> %"` 原样打印 |
| `0x38` | `version` | `L_C` / `L_Javascript` 是 **`char*`**；`L_Python` / `L_Java` / `L_Ruby` 是 **`double`** |

`info()` 是虚函数（经 vptr 分发）；`set_version()` **不是虚函数**（在 `set_lang()` 里按静态类型分发）。

### 项目

- **Trojan**：语言为 ASM、C、Python（Python 在技能 500 时解锁）
- **Web**：语言为 Ruby、Java、Javascript（Javascript 在技能 500 时解锁）

## 漏洞

### V1 — `compatible()` 引起的类型混淆（主要，可 Exploit）

**根因：** `change_language()` 依据 `compatible()` 的返回值决定是*原地修改*还是*替换对象*。判定为"兼容"时，`set_lang()` 会用 `reinterpret_cast`，在**旧对象**上调用**新类型的**非虚函数 `set_version()` —— vptr 和内存布局都不变。

```cpp
if (compatible(new_lang, lang_list[i]->get_lang())) {
    lang_list[i]->set_ratio(r);
    set_lang(&lang_list[i], new_lang, r, /*just_edit=*/true);  // reinterpret_cast!
} else {
    delete lang_list[i];
    set_lang(&lang_list[i], new_lang, r, /*just_edit=*/false); // new object
}
```

两个有问题的 `compatible()` 实现：

```cpp
// Web::compatible — "I hate my stupid Boss A" — SUBSTRING test
bool Web::compatible(LANG l1, LANG l2) {
    return strstr(LANG_NAME[l2].c_str(), LANG_NAME[l1].c_str());
}
// "Java" is a substring of "Javascript" => treating L_Javascript as L_Java is "compatible"

// Trojan::compatible — "Stupid Boss B thinks C and Python are pretty similar"
bool Trojan::compatible(LANG l1, LANG l2) {
    ...
    if (big == "Python" && small == "C") return true;
    ...
}
// C <-> Python confusion is explicitly allowed
```

**影响 —— 任意读（Trojan：C ↔ Python）：**
1. 槽里先放一个 `L_C` 对象（偏移 `0x38` 是 `char* version`）。
2. "换成"Python（判定为兼容）→ 调用 `L_Python::set_version()` = `scanf("%lf", &version)` → 用一个 `double`（8 字节，编码了目标地址）覆盖那个 `char*`。
3. vptr 仍然是 `L_C` 的 → `L_C::info()` 执行 `cout << "C standard version: " << (char*)version` → **打印任意地址处的字符串**。

```python
# Encode address as double, read back as C string
addr_as_double = struct.unpack('<d', p64(target_addr))[0]
set_python(ratio, repr(addr_as_double))
show()  # "C standard version: <bytes at target_addr>"
```

**影响 —— 任意写（Web：Javascript ↔ Java）：**
1. 槽里先放一个 `L_Javascript` 对象（偏移 `0x38` 是 `char* version`）。
2. "换成"Java（因为 `"Java" ⊂ "Javascript"` 判定为兼容）→ 调用 `L_Java::set_version()` = `scanf("%lf", &version)` → 用目标地址（编码成 double）覆盖 `char*`。
3. 再"换回"Javascript → 调用 `L_Javascript::set_version()` = `read(0, version, 20)` → **向任意地址写 20 字节**。

### V2 — `scanf` 未初始化变量导致的泄漏（可 Exploit）

**根因：** `create()` 和 `change_language()` 用 `scanf("%lu", &r)` 读取 ratio。如果输入不是数字（例如 `"+"`、`"-"`、`".5"`），`scanf` 会失败且不写 `r`，`r` 保持**未初始化**。这个残留的栈值就成了对象的 `ratio`，之后被 `basic_info()` 原样打印。

```cpp
unsigned long r;          // uninitialized
scanf("%lu", &r);         // "+" → conversion fails → r untouched
set_lang(&lang_list[i], lang, r, false);  // r = stale stack pointer
// Later: basic_info() prints "Ratio: <stale_value> %"
```

**影响：** 在 `create()` 期间（调用链很深：`main → fight_slime → boss → make_web → create`），未初始化的 `r` 里是**残留的栈指针**。这个确切的指针会被当作十进制整数打印出来，于是得到毫无歧义的栈地址泄漏。

### V3 — `read()` 遇非法地址不崩溃（次要，助攻）

**根因：** `L_Javascript::set_version()` 用 `read(0, version, 20)`。如果 `version` 指向未映射的地址，`read()` 返回 `-1`（EFAULT），但进程**不会崩**，输入也仍留在 stdin 缓冲区里没被消耗。

**影响：** 可以当**地址预言机** —— 发一段探测数据，看输入是被消耗了还是留着（分别对应地址合法/非法）。这样一来，即使不用 V2 的 `scanf` 泄漏，也能爆破堆基址。

### V4 — 史莱姆战斗的可预测随机数（助攻）

**根因：** Minion 史莱姆用 `srand(0x44444444 + 4444 * k)`，种子是确定性的静态值；King 史莱姆则用 `srand(time(NULL))`。

```cpp
// SlimeMinion::genNum()
static int seed = 0x44444444;
seed += 4444;
srand(seed);
for (int i = 0; i < 5; i++) number[i] = rand() % 5;

// SlimeKing::fight()
srand(time(NULL));
number = rand() % 5;
```

**影响：** 用 `ctypes.CDLL` 复现 glibc 的 `rand()`，就能预测所有史莱姆的数值、稳赢每一场，自动化刷到 4 门语言各 500 EXP（约 15–30 场战斗）。

## 利用路径

### 路径 A — `scanf` 泄漏栈 → 类型混淆读写 → `__free_hook = system`（最常见）

**使用范围：** 解法 370、821、2311、3148、7905、22319、5586、6748、18331，以及随题提供的 `exp.py`

1. **刷经验：** 预测随机数并连胜，直到 Trojan 和 Web 两个项目都建好。在 `create()` 时给 ratio 喂 `"+"` / `"-"` → V2 泄漏一个栈指针。

2. **取出栈指针：** 对项目调 `show_info()`，会把泄漏的栈地址打印成 `"Ratio: <十进制> %"`。

3. **任意读（Trojan）：** 槽里放一个 `L_C`，再"换成"Python 并把 `version` 设为 `addr_as_double` → 经 `show_info()` 读出目标地址处的 C 字符串。
   - 从泄漏的栈区域读一个 **PIE 指针**（通常是 `binary_base + 0x20d048`）。
   - 从二进制的 GOT 或 BSS 读一个 **libc 指针**（例如 `GOT[read]`、`GOT[scanf]`，或 `stdin`）。

4. **任意写（Web）：** 槽里放一个 `L_Javascript`，再"换成"Java 并把 `version` 设为 `addr_as_double` → 覆盖 `char*`。然后"换回"Javascript → `read(0, version, 20)` 向目标地址写 20 字节。

5. **拿 shell：** 把 `system` 写进 `__free_hook`，把 `"/bin/sh\0"` 放在一个已知的可写地址。把一个 Javascript 槽换成不兼容的语言（Ruby），触发 `delete` → `~L_Javascript()` → `free(version)` → `system("/bin/sh")`。

   `~L_Javascript` 析构函数在 `delete[] version` 之前会先执行 `memset(version, 0, malloc_usable_size(version))`。为避免 `/bin/sh` 被清零，伪造的 chunk 要让 `malloc_usable_size()` 返回 0（下一个 chunk 的 `PREV_INUSE` 位 = 0）。

**可靠性：** 每次连接约 95% 以上（只有泄漏的栈值异常时才失败）。

---

### 路径 B — `scanf` 泄漏 → 类型混淆 → 经 `__malloc_hook` / `__realloc_hook` 打 one-gadget

**使用范围：** 解法 821、6748、34817

泄漏链与路径 A 相同，但不是 `__free_hook + system`，而是把 `one_gadget` 地址写进 `__malloc_hook`（或用 `__realloc_hook` + `realloc` 跳板来调栈对齐）。之后任意 `new` / `malloc` 调用都会触发。

**注意：** C++ 的 `new`/`delete` 调用点上，`one_gadget` 的约束（`[rsp+X]==NULL`、`rax==NULL`）常常不满足。不少解法提到要仔细挑选触发点，或用 `realloc` 跳板。

---

### 路径 C — `scanf` 泄漏 → 类型混淆 → 栈上 ROP

**使用范围：** 解法 2311、18331

1. 按路径 A 泄漏栈 + libc。
2. 从 libc 读 `__environ`，得到确切的栈帧指针。
3. 用任意写把 ROP 链（`pop rdi; ret; "/bin/sh"; system`）铺到 `manage_project()` 或其他函数的返回地址处。
4. 该函数返回 → ROP 触发 → shell。

---

### 路径 D — `stdout` vtable 劫持（FSOP）

**使用范围：** 解法 9251

1. 经类型混淆读泄漏 PIE 基址和 libc。
2. 把 `one_gadget` 写进 `stdout` vtable 的 `__xsputn` 槽。
3. 之后任意 `cout <<` 都会走被污染的 vtable → shell。

**注意：** 仅在 glibc 2.23 上有效（尚未校验 vtable）。

---

### 路径 E — 爆破堆地址（不用 `scanf` 泄漏）

**使用范围：** 解法 8153、9251、564（发现 V2 之前）、1351

有些解题者没发现 `scanf` 未初始化变量这一手，于是改为：
1. 借 Python→C 混淆泄漏堆地址的约 16 位（打印 `double` 会丢失指针精度，但能看出高位）。
2. **用 V3 的 `read()` 预言机爆破剩余位**：把 `L_Javascript::version` 指向候选地址，看 `read()` 成功还是失败。
3. 找到堆基址后，在堆里扫 vtable 指针 → PIE 基址 → GOT → libc。

**可靠性：** 慢得多（数百次探测），有解法报告成功率 1/1500；也有解法通过优化（用大段 ASM 字符串扩大堆、二分查找）做到约 1 分钟。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 栈指针泄漏 | V2：对 `"+"` 时 `scanf` 失败 | 确定性 |
| 任意读（C 字符串） | V1：C↔Python 混淆 | 泄漏后确定性 |
| 任意写（20 字节） | V1：Java↔Javascript 混淆 | 泄漏后确定性 |
| 地址预言机 | V3：`read()` EFAULT 不崩 | 确定性但慢 |
| 预测随机数 | V4：复现 glibc `rand()` | 确定性 |
| 代码执行 | `__free_hook`/`__malloc_hook`/栈上 ROP | 任意读写后确定性 |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
__free_hook  = 0x3c57a8
__malloc_hook = 0x3c3b10
system       = 0x45390
one_gadgets  = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
stdin        = 0x3c48e0
environ      = 0x3c5f38
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `370.md` | A | scanf 泄漏 → C↔Python 读 → Java↔JS 写 → `__free_hook` | 两套完整脚本 |
| `821.md` | A + B | scanf 泄漏 → 读栈/PIE/libc → `__malloc_hook` one_gadget | 远端随机数服务做预测 |
| `2311.md` | A + C | scanf `"++"` 泄漏 → 从栈读 libc → 把 one_gadget 写栈 | 漏洞描述简洁 |
| `3148.md` | A | scanf `"+"` 泄漏 → 读 GOT → `__free_hook` + system | 有点乱但可用 |
| `564.md` | E | Python→C 部分堆泄漏 → `read()` 爆破 → 扫堆 | 报告成功率 1/1500 |
| `7905.md` | A | scanf `"+"` 泄漏 → 含伪造 chunk 的完整 writeup | 分析最详尽 |
| `8153.md` | E | 不用 scanf 技巧；`read()` 预言机爆破 + 扫堆 | 自带 IEEE754 转换器 |
| `9251.md` | E + D | 爆破堆 → 扫 vtable → 劫持 `stdout` vtable | 未使用 scanf 泄漏 |
| `34817.md` | E + B | Python→C 泄漏 → 爆破堆 → PIE → `__malloc_hook` | 长二分查找做法 |
| `31599.md` | — | 自述是"最糟做法，成功率 1/1500" | 细节很少 |
| `375.md` | E | 经 `read()` 预言机爆破堆 → PIE → libc → `__free_hook` | 用循环堆喷涂加速扫描 |
| `1351.md` | E | `read()` 预言机 + 遍历堆 → vtable → PIE → `__free_hook` | 用 ASM 堆喷涂扩大目标 |
| `10128.md` | A | scanf `"++"` → 搜堆 → vtable → `__free_hook` | 在堆区间上二分 |
| `14523.md` | A | scanf `"+"` → 栈 → 经 GOT 得 PIE → libc → `__free_hook` | 干净的做法 |
| `18331.md` | A | scanf `"+"` → 栈 → 兜底用 `read()` 爆破 | 不预测史莱姆（直接重试） |
| `22319.md` | A | scanf `"+"` → 栈 → PIE → libc → `__free_hook` | 不预测史莱姆 |
| `5586.md` | A | scanf `"+"` → 栈 → libc → `__free_hook` | 只打 King 史莱姆的策略 |
| `6748.md` | A + B | scanf `"+"` → 栈 → `__realloc_hook` + `realloc` 跳板 | 栈对齐技巧 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `artifacts/stupid.cpp` | 题目源码（作者提供） |
| `artifacts/stupid` | 题目二进制（stripped，PIE） |
| `artifacts/libc_64.so.6` | 远端 libc（glibc 2.23） |
| `exp.py` | 可用 exploit（路径 A：scanf 泄漏 + 类型混淆读写 + `__free_hook`） |
| `desc.txt` | 题目描述 |
| `solution/*.md` | 社区 writeup（27 份解法） |
