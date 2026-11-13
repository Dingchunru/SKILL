---
tags:
  - io-file-exploit
  - vtable-hijack
  - arbitrary-write
platform: pwnable.tw
points: 400
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "在 BSS 段伪造 _IO_FILE 结构，fclose 时劫持文件 vtable 指针，把执行流重定向到 system。"
proof-of-concept: no
---

# seethefile — pwnable.tw（400 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10200`
>
> Flag：`FLAG{F1l3_Str34m_is_4w3s0m3}`

## 题目概况

一个 32 位文件查看器（i386，No PIE、Partial RELRO、NX、栈 canary），链接 glibc 2.23。程序提供打开、读取、打印、关闭文件的菜单。退出时会要求输入名字，并对全局 FILE 指针调用 `fclose(fp)`。flag 文件无法直接打开（文件名过滤会拦下"flag"）。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)   # fixed addresses in .bss
```

### 二进制布局（BSS）

```python
0x804B080  filename[64]     — stores the filename from openfile()
0x804B0C0  magicbuf[400]    — fread() destination buffer
0x804B260  name[32]         — scanf("%s", name) destination on exit
0x804B280  fp               — global FILE* pointer
```

### 菜单函数（IDA 反编译）

```c
// main loop
while (1) {
    menu();
    scanf("%s", v8);          // stack buffer, reads menu choice
    switch (atoi(v8)) {
    case 1: openfile(); break;
    case 2: readfile(); break;
    case 3: writefile(); break;
    case 4: closefile(); break;
    case 5:
        printf("Leave your name :");
        scanf("%s", name);    // <-- V1: unbounded write to BSS
        printf("Thank you %s ,see you next time\n", name);
        if (fp) fclose(fp);   // <-- V2: fclose on attacker-controlled fp
        exit(0);
    }
}

void openfile() {
    scanf("%63s", filename);
    if (strstr(filename, "flag")) { puts("Danger !"); exit(0); }
    fp = fopen(filename, "r");
}

void readfile() {
    memset(magicbuf, 0, 400);
    fread(magicbuf, 399, 1, fp);
}

void writefile() {
    if (strstr(filename, "flag") || strstr(magicbuf, "FLAG") || strchr(magicbuf, '}'))
        { puts("you can't see it"); exit(1); }
    puts(magicbuf);
}

void closefile() {
    if (fp) fclose(fp);
    fp = 0;
}
```

## 漏洞

### V1 — BSS 上 `scanf("%s", name)` 的缓冲区溢出（主要）

**根因：** 退出流程用 `scanf("%s", name)` 读取用户名字，`name` 是位于 `0x804B260` 的 32 字节 BSS 缓冲区。`scanf("%s")` **没有长度限制** —— 会一直写到空白字符为止。

```c
// Exit path in main
printf("Leave your name :");
scanf("%s", name);    // name = 0x804B260, 32 bytes
// ...
if (fp) fclose(fp);   // fp = 0x804B280 = name + 0x20
```

**影响：** 写入超过 32 字节就会覆盖位于 `0x804B280` 的全局 `FILE *fp`。攻击者可以把 `fp` 指向任意地址 —— 包括 BSS 中它自己后面，溢出载荷在那边继续布置一个伪造的 **`_IO_FILE_plus` 结构**。

### V2 — 对攻击者控制的 `FILE*` 调用 `fclose()`（FSOP）

**根因：** 溢出之后，`fclose(fp)` 操作的是攻击者伪造的 `FILE*`。在 glibc 2.23（尚未校验 vtable）中，`fclose` 会经结构体的 vtable 指针分发。伪造一个带假 vtable 的 `_IO_FILE_plus`，就能把某个虚调用（通常是 `_IO_FINISH` 或 `__close`）重定向到 `system()`。

glibc 2.23 的 `_IO_new_fclose` 流程：

```c
int _IO_new_fclose(FILE *fp) {
    if (_IO_vtable_offset(fp) != 0)     // fp+0x46 must be 0
        return _IO_old_fclose(fp);
    if (fp->_flags & _IO_IS_FILEBUF)    // clear bit 0x2000 to skip
        _IO_un_link(fp);
    _IO_acquire_lock(fp);               // fp->_lock (fp+0x48) dereferenced
    // ...
    _IO_FINISH(fp);                     // *(*(fp+0x94) + 0x8)(fp)
    // ...
}
```

**伪造结构体的关键约束：**
- `fp+0x46`（`_vtable_offset`）必须为 `0` —— 否则走 `_IO_old_fclose` 分支
- `fp->_flags` 的 `_IO_IS_FILEBUF`（0x2000）必须清零 —— 跳过 `_IO_un_link` 和 `_IO_file_close_it`
- `fp+0x48`（`_lock`）必须指向一块已清零的可写内存 —— 加锁时会解引用它
- `fp+0x94`（`vtable`）必须指向假 vtable，且其中偏移 `+0x8`（`__finish`）= `system`

`_IO_FINISH(fp)` 触发时会调用 `system(fp)`。由于 `fp` 指向伪造结构体的开头，把 `";/bin/sh;"` 放在最前面，`system` 就会执行它（`;` 之前的乱码只会报个无害的错）。

### V3 — 经 `/proc/self/maps` 的信息泄漏

**根因：** 文件名过滤只拦 `"flag"`，不拦 `/proc/self/maps`。打开并读取这个文件就能得到完整的内存映射，包括 libc 基址。

```c
if (strstr(filename, "flag")) { ... }  // only blocks "flag"
// /proc/self/maps is allowed
```

**影响：** 确定性地泄漏 libc 基址。`writefile` 还会过滤读到的缓冲区里是否含 `"FLAG"` 和 `}`，而 `/proc/self/maps` 的输出不含这些字符串。

## 关键数据结构

### `_IO_FILE`（glibc 2.23，i386 —— 0x94 字节 + vtable 指针）

| 偏移 | 字段 | 利用要点 |
|--------|-------|-------------------|
| `0x00` | `_flags` | 设成 `0xFFFFDFFF`（清掉 `_IO_IS_FILEBUF` 位 0x2000） |
| `0x04` | `_IO_read_ptr` | 作为 `";/bin/sh;"` 命令串的一部分 |
| `0x08` | `_IO_read_end` | shell 命令的延续 |
| `0x0C` | `_IO_read_base` | 可为 0，或继续放命令 |
| `0x10`–`0x30` | I/O 缓冲区指针 | 一般置 0 |
| `0x34` | `_chain` | 可为 0 |
| `0x38` | `_fileno` | 可为 0 |
| `0x44` | `_cur_column` / `_vtable_offset` | **`+0x46` 处的 `_vtable_offset` 必须为 0** |
| `0x48` | `_lock` | **必须指向已清零的可写内存** |
| `0x4C` | `_offset` | 可为 `0xFFFFFFFF` |
| `0x94` | `vtable` | **指向假 vtable** |

### 假 vtable（`_IO_jump_t`）

| 偏移 | 字段 | 取值 |
|--------|-------|-------|
| `0x00` | `__dummy` | 0 |
| `0x04` | `__dummy2` | 0 |
| `0x08` | `__finish` | **`system`** ← 由 `_IO_FINISH(fp)` 调用 |
| `0x0C+` | 其余表项 | `system`（整片铺满以提高可靠性） |

## 利用路径

146 份解法思路基本一致，只是伪造结构体的布局略有差异。

---

### 路径 A — `/proc/self/maps` 泄漏 → FSOP `fclose` → `system("/bin/sh")`（标准）

**使用范围：** 几乎所有解法（370、385、654、799、823、1395、1689、1922、2903、9418、9871、14605、16806、26585、28356、34604、36233、37983 等）

**步骤：**

1. **泄漏 libc 基址：** 打开 `/proc/self/maps`，读取并打印到屏幕，解析出 libc 映射行的基址。有些解法要读两次（399 字节的 `fread` 缓冲区一次读不到 libc 那一行）。

2. **算出 `system` 地址：** `system = libc_base + 0x3A940`（本题所用 glibc 2.23）。

3. **构造 FSOP 载荷：** 退出时 `scanf("%s", name)` 从 `0x804B260` 开始写：

```text
+0x00: padding (32 bytes) — fills name[32]
+0x20: p32(fake_fp_addr)  — overwrites fp to point to fake struct
+0x24: fake _IO_FILE_plus  — starts here (or at +0x24)
  +0x00: flags = 0xFFFFDFFF (or similar, _IO_IS_FILEBUF cleared)
  +0x04: ";/bin/sh;" (system argument via fp pointer)
  ...
  +0x48: _lock → zeroed BSS (e.g. 0x804B0A0 or 0x804B260+offset)
  ...
  +0x94: vtable → fake_vtable_addr
fake_vtable:
  +0x08: system address
```

4. **触发：** `scanf` 返回后，`fclose(fp)` 处理伪造结构体，最终调用 `_IO_FINISH(fp)`，解析为 `system(fp)`。由于 `fp` 指向的内存以 `";/bin/sh;"` 开头，shell 就此启动。

5. **取 flag：** `echo 'Give me the flag' | /home/seethefile/get_flag`

**可靠性：** 约 100% 确定。唯一的失败情形是 `system` 的地址里含有空白字节（`\x09`、`\x0a`、`\x0b`、`\x0c`、`\x0d`、`\x20`），那会提前终止 `scanf("%s")`。这取决于 ASLR，重连即可。

---

### 路径 A 变体 — 改打 `__close` 而不是 `__finish`

**使用范围：** 解法 799、1236、1902

有些解法打的是另一个 vtable 槽位：不走 `_IO_FINISH`（vtable+0x08），而是把伪造结构体安排成让 `_IO_SYSCLOSE` 经 `__close` 槽（vtable+0x44）调到 `system`。原理完全相同，只是假 vtable 的偏移不同。

---

### 路径 A 变体 — 借假 `fread` 触发格式化字符串

**使用范围：** 解法 331、1006

一个有创意的两阶段做法：
1. 第一次退出：伪造 FILE 结构让 `fread` → `printf`（把 vtable 的读入口重定向到 printf），用格式化字符串（`%6$x`）从栈上泄漏一个 libc 地址。
2. 回到 `main`（把 vtable 的 finish/close 项设成 `main`）。
3. 第二次退出：此时已知 libc，构造真正的 FSOP 载荷打 `system`。

这样就不必借 `/proc/self/maps` 泄漏，但更复杂。

---

### 路径 A 变体 — `add_esp` gadget → 栈迁移

**使用范围：** 解法 1236

不直接经 vtable 调 `system`，而是用 libc 里的 `add esp, X; ret` gadget 把执行流迁到 BSS 的载荷区，再用 ROP 风格串联 `system("/bin/sh")`。实现更复杂，但说明 vtable 劫持提供的是任意代码执行，而非只能打一发 `system`。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| libc 基址泄漏 | 经 open/read/write 读 `/proc/self/maps` | 确定性 |
| 堆基址泄漏 | `/proc/self/maps`（附带，非必需） | 确定性 |
| 栈地址泄漏 | `/proc/self/stat`（第 28 个字段） | 确定性 |
| BSS 溢出 → 覆盖 `fp` | 用超过 32 字节的 `scanf("%s", name)` | 确定性 |
| BSS 中的假 `_IO_FILE_plus` | 载荷放在 name 缓冲区之后 | 确定性 |
| 经 vtable 劫持执行 `system` | `fclose(fake_fp)` → `_IO_FINISH` | 约 100%（地址含 scanf 终止字节时重试） |

## 偏移（pwnable.tw `libc_32.so.6`，glibc 2.23）

```python
system      = 0x3A940
exit        = 0x2E7B0
bin_sh      = 0x158E8B
_IO_file_jumps = <libc_base + offset>  # real vtable (for reference)
```

## BSS 地址（无 PIE）

```python
filename    = 0x0804B080   # 64 bytes
magicbuf    = 0x0804B0C0   # 400 bytes
name        = 0x0804B260   # 32 bytes — overflow source
fp          = 0x0804B280   # FILE* — overflow target
# Fake struct typically at 0x804B284 or 0x804B290
```

## 题解文章

| 文件 | 变体 | 关键技术 | 备注 |
|------|---------|---------------|-------|
| `370.md` | 标准 | maps 泄漏 → FSOP `__finish` → system | 干净简洁 |
| `331.md` | 格式化字符串 | 假 fread→printf 做泄漏，再 FSOP | 两阶段，避开 /proc |
| `385.md` | 标准 | maps 泄漏 → FSOP → system | 用 ELF 符号偏移 |
| `654.md` | 标准 | maps + 堆泄漏 → FSOP | 结构体布局更复杂 |
| `799.md` | 标准 | maps 泄漏 → FSOP `__close` 路径 | 打的是另一个 vtable 槽 |
| `823.md` | 标准 | maps 泄漏 → FSOP → get_flag | 自动取 flag |
| `1006.md` | 格式化字符串 | fread→printf 泄漏，两次退出 | 有创意的 vtable 替换 |
| `1236.md` | 栈迁移 | maps 泄漏 → add_esp gadget → ROP | 用 gadget 而非直接 system |
| `1395.md` | 标准 | maps 泄漏 → FSOP | 直截了当 |
| `1689.md` | 标准 | maps 泄漏 → FSOP | 载荷最小 |
| `1902.md` | 标准 | maps 泄漏 → FSOP | 打 __close 的 vtable 偏移 |
| `1922.md` | 标准 | maps 泄漏 → FSOP `__finish` | 结构布局干净 |
| `2903.md` | 标准 | maps 泄漏 → FSOP | 注释完善 |
| `9418.md` | 标准 | maps 泄漏 → 带 gdb 分析的 FSOP | 含 FILE 结构体逐字段讲解 |
| `9871.md` | 标准 | maps 泄漏 → FSOP | 顺带用 /proc 泄漏堆和栈 |
| `14605.md` | 标准 | maps 泄漏 → FSOP | 顺带经 /proc/self/stat 泄漏栈 |
| `26585.md` | 标准 | maps 泄漏 → FSOP | 走 _IO_old_fclose 路径变体 |
| `28356.md` | 标准 | maps 泄漏 → FSOP | 简单干净 |
| `34604.md` | 标准 | maps 泄漏 → 详细分析的 FSOP | 文档最全；含 glibc 源码走读 |
| `36233.md` | 标准 | maps 泄漏 → 带 vtable 详解的 FSOP | 含 vtable 结构布局与 fclose 源码 |
| `37983.md` | 标准 | maps 泄漏 → _IO_old_fclose 变体 | 用 fsop_fclose_old 的 flat() 布局 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `exp.py` | 可用 exploit（纯 socket，不用 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/seethefile` | 题目二进制（i386，No PIE） |
| `artifacts/libc_32.so.6` | 远端 libc（glibc 2.23，i386） |
| `solution/*.md` | 社区 writeup（146 份解法） |
