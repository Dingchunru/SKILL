# CTF Reverse - Radare2 脚本化与 r2pipe 自动化

面向 CTF 逆向的脚本化 radare2：批处理单行命令、字节打补丁、用 r2ghidra 就地反编译、
ESIL 单函数模拟、JSON 输出解析，以及基于 xref 的校验函数定位。当任务需要可重复自动化
—— 改写分支、爆破校验函数、模拟解密例程 —— 而不是交互式会话时，就用它。
交互式 GDB 流程见 [tools.md](tools.md) 和 [tools-dynamic.md](tools-dynamic.md)；
本文全部内容已在 radare2 `6.2.2 +37863 abi:142`（linux-x86-64）、r2pipe `1.9.8`、
用 `cc -O0` 编译的 PIE x86-64 ELF 上验证。

<a id="when-to-script-radare2"></a>
## 何时该脚本化 radare2

Radare2 是自动化后端，不只是交互式反汇编器：每条命令都能通过 `-c` 无头执行，
而 JSON 命令族（`aflj`、`pdfj`、`axtj`……）把分析结果变成普通数据结构 ——
这正是脚本化能成立的根本原因。需要给人看的 r2 文本输出时用 `cmd()`，
需要解析结果时用 `cmdj()`。r2pipe 1.9.8 的 `cmd()` **并不会**像文档字符串
说的那样自动 strip（`.cmd('?e hi')` 返回 `'hi\n'`），所以永远自己调 `.strip()`。

```python
import r2pipe

r2 = r2pipe.open('BINARY')
r2.cmd('aaa')             # '' —— 所有 INFO/WARN 行都走 stderr
r2.cmd('afl~?').strip()   # '9' —— cmd() 不 strip，必须你自己处理
fns = r2.cmdj('aflj')     # JSON 进，普通 python 对象出 —— 永远用 cmdj()，绝不用 cmdJ()
r2.quit()                 # None
```

**关键要点：** 带 `j` 后缀的命令就是脚本化的全部 —— 文本命令供人眼看，JSON 命令供代码用。

<a id="batch-mode-without-an-interactive-shell"></a>
## 不进入交互 shell 的批处理模式

当你只想从一个二进制拿到一个答案（函数数量、一段字节、一次反编译）而不想坐在提示符前时，
用 `-c` 单行命令。分析不是自动的：在运行分析之前函数根本不存在，所以裸 `afl`
在 stdout 上什么都不打印，却仍以 0 退出。`-A` 与 `aaa` 等价（两者下 `afl~?` 都返回 `9`），
`~?` 是行数统计的 grep 修饰符（不是"帮助"），重复的 `-c` 按顺序执行。

```bash
r2 -q -c 'afl' FILE 2>/dev/null                       # stdout 无输出，退出码 0

r2 -q -A -c 'afl~?' FILE 2>/dev/null                  # -> 9
r2 -q -c 'aaa;afl~?' FILE 2>/dev/null | tail -1       # -> 9（等价于 -A）

r2 -q -A -c 'echo STEP1' -c 'afl~?' FILE 2>/dev/null  # STEP1，然后 9
```

两个坑。第一，`-0c` / `-q0c` / `-q0qc` 都能解析，但在 6.2.2 的批处理模式下
文档所说的 NUL 字节**并不会**输出，所以把 `-0c` 当作 `-c` 的别名看待：

```bash
r2 -q0c 'p8 32 @ entry0' FILE 2>/dev/null | radiff2 - FILE   # ERROR: Cannot open '-'
```

`radiff2` 根本没有 stdin 模式。第二，stderr 噪音是正常的：r2 会把
`WARN: Relocs has not been applied...` 和分析 `INFO:` 行写到 stderr，
所以下面每条 r2 单行命令都带 `2>/dev/null`。

**关键要点：** 批处理模式就是 `-A` 加 `2>/dev/null` —— 分析跑起来之前函数不存在，
而 stderr 上的唠叨是信息性的，不是错误。

<a id="patching-bytes-with-wx-in-batch-mode"></a>
## 在批处理模式下用 wx 打字节补丁

需要强制走某个分支、废掉一个检查、或 NOP 掉反调试陷阱时，用批处理打补丁。
可用形式是 `r2 -w -q -c 'wx <hexbytes> @ <vaddr>' FILE`。所有选项必须放在文件名**之前**：
`r2 -q -c 'wx 90 @ 0x1162' FILE -w` 会打印 `ERROR: Cannot open '-w'`、退出码 1，
并且什么都没打上。省略 `-w` 会**静默失败** —— 错误只是 stderr 上的
``ERROR: Cannot write. Use `omp`, `io.cache` or reopen the file in rw with `oo+` ``，
退出码仍是 0。

已验证的打补丁案例：`0x1169` 处的 `sete al`（`0f 94 c0`）改成
`mov al, 1 ; nop`（`b0 01 90`），目标程序的退出码从 0（任意输入）变成 1（任意输入）：

```bash
r2 -w -q -c 'wx b00190 @ 0x1169' t_true 2>/dev/null

# 通过重新读取字节来验证 —— rabin2 -S 只打印节表，无法确认这几字节
r2 -q -c 'p8 3 @ 0x1169' t_true 2>/dev/null      # -> b00190
xxd -s 0x1169 -l 3 t_true
radiff2 -q orig patched
```

对符号目标打补丁需要先分析：`r2 -w -q -c 'wx b00190 @ dbg.check+0x50' t`
会失败并报 `ERROR: Invalid tmpseek address 'dbg.check+0x50'`，加上 `-A` 就能解决。
数字 vaddr 不需要 `-A`，纯算术（`@ 0x1119+0x50`）也不需要。永远不要相信 r2 的退出码：
命令失败和写入失败时它都返回 0，只有输入文件缺失才返回 1。在这个 PIE x86-64 ELF 上
`.text` 的 paddr == vaddr，但这一点**绝不能**推广 —— 同一二进制里
`.init_array` 与 `.data` 的 paddr != vaddr。

**关键要点：** 所有选项放在文件名前，不加 `-w` 补丁就会被丢掉，
唯一可信的确认方式是用 `p8`、`xxd` 或 `radiff2` 重新读取补丁后的字节。

<a id="decompiling-in-place-with-r2ghidra"></a>
## 用 r2ghidra 就地反编译

r2ghidra 与 radare2 版本 ABI 强绑定，所以先检查版本：预编译的
`r2ghidra-6.2.4-linux-x86-64.zip` 面向 ABI 152，在 r2 6.2.2（`abi:142`）上会拒绝加载并报
`WARN: ABI mismatch: Expect 142 vs 152 from '.../core_ghidra.so'`，
随后给出通常那句 `You need to install the plugin with r2pm -ci r2ghidra` 的建议。
**没有** `r2ghidra-6.2.2-*-linux-x86-64.zip` 这个资产（所有变体都 404）；6.2.2 标签只提供
macos/w64 的 zip、一个通用 zip、一个 tar.xz 和 `r2ghidra_6.2.2_amd64.deb`，
全部列在 [github.com/radareorg/r2ghidra/releases](https://github.com/radareorg/r2ghidra/releases)。
要选与你自己 r2 版本和 ABI 匹配的资产，而不是最新的那个。已验证的安装方式是版本匹配的 `.deb`，
在没有 root 的情况下解包（因为缺少 `dpkg-deb`）—— 其中附带的 `.so` 是原生 C++
（NEEDED: libr_core.so, libr_anal.so, libstdc++, libm, libc，不需要 libjvm），
所以这条路径不需要 JDK：

```bash
ar x r2ghidra_6.2.2_amd64.deb
tar xJf data.tar.xz
cp usr/lib/radare2/6.2.2/core_ghidra.so ~/.local/share/radare2/plugins/
cp -r usr/lib/radare2/6.2.2/r2ghidra_sleigh/ ~/.local/share/radare2/plugins/
```

在 6.2.2 上 `r2pm -ci r2ghidra` 也是可行的替代方案，但它走源码路径 ——
`./preconfigure`、`./configure`、`make -C src` —— 要编译 ghidra-native 的 C++，耗时数分钟。
加载成功后，在 `aaa` 之后：

```bash
r2 -q -A -c 'pdg @ sym.check' FILE 2>/dev/null
```

即可打印伪代码。`pdg @ sym.check` 的原文：

```c
bool sym.check(int64_t arg1)

{
    int64_t var_18h;
    uint32_t var_8h;
    int32_t var_4h;

    var_8h = 0;
    for (var_4h = 0; *(arg1 + var_4h) != '\0'; var_4h = var_4h + 1) {
        var_8h = var_8h + (*(arg1 + var_4h) ^ 0x5a);
    }
    return var_8h == 0x4d2;
}
```

同一二进制上 `pdg @ main`：

```c
void main(int argc,char **argv)

{
    char **var_10h;
    int32_t var_4h;

    sym.check(argv[1]);
    return;
}
```

`pdgj @ sym.check` 返回 JSON，反编译文本在 `code` 键下：

```json
{"code":"\nbool sym.check(int64_t arg1)\n\n{...}\n","annotations":[{"start":1,"end":5,"type":"syntax_highlight","syntax_highlight":"datatype"},...]}
```

**关键要点：** 让插件 ABI 与你的 r2 版本匹配 —— 预编译的 6.2.4 zip 加载不进 6.2.2，
而版本匹配的 `.deb` 用 `ar` + `tar` 就能干净解包。

<a id="emulating-a-single-function-with-esil"></a>
## 用 ESIL 模拟单个函数

ESIL 在进程内模拟单个函数，不需要调试器也不需要 unicorn —— 足以运行自包含的变换循环，
并从临时缓冲区读出结果。对于只触及自身参数和静态数据的小型解密/校验例程，
这是最快的方法。用 `cc -O0 -o dec dec.c` 构建目标。`aaa` 之后：
`sym.decrypt = 0x1119`、`ret` 位于 `0x1163`、`obj.enc = 0x2020`（.rodata）、
`obj.plain = 0x4040`（.bss）。明文为 `ESIL emulation recovered the plaintext!!`。

```c
#include <stddef.h>
#include <stdint.h>

/* 密文：每个字节是下面明文字符 ^ 0x5a */
static const uint8_t enc[40] = {
    0x1f, 0x09, 0x13, 0x16, 0x7a, 0x3f, 0x37, 0x2f, 0x36, 0x3b, 0x2e, 0x33,
    0x35, 0x34, 0x7a, 0x28, 0x3f, 0x39, 0x35, 0x2c, 0x3f, 0x28, 0x3f, 0x3e,
    0x7a, 0x2e, 0x32, 0x3f, 0x7a, 0x2a, 0x36, 0x3b, 0x33, 0x34, 0x2e, 0x3f,
    0x22, 0x2e, 0x7b, 0x7b,
};

uint8_t plain[40];

/* dst = src ^ 0x5a，n 字节   （SysV x86-64: rdi, rsi, rdx） */
void decrypt(uint8_t *dst, const uint8_t *src, size_t n)
{
    for (size_t i = 0; i < n; i++)
        dst[i] = src[i] ^ 0x5a;
}

int main(void)
{
    decrypt(plain, enc, sizeof enc);
    return 0;
}
```

以下会话逐字执行，在不用 unicorn、不用调试器的情况下恢复了明文：

```text
$ r2 -q -A dec
[0x00001140]> s sym.decrypt
[0x00001119]> aei                     # 初始化 ESIL VM
[0x00001119]> aeim                    # 初始化栈（无 size 参数）
[0x00001119]> aeip                    # PC = 当前 seek = 0x1119
[0x00001119]> aer rdi=0x177800        # dst  -> 栈映射内的临时区
[0x00001119]> aer rsi=obj.enc         # src  = 0x2020（.rodata）
[0x00001119]> aer rdx=40              # n
[0x00001119]> aesu sym.decrypt+0x4a   # == 0x1163，即 `ret`
[0x00001163]> ps @ 0x177800
ESIL emulation recovered the plaintext!!
```

`0x177800` 就是 `rsp (0x178000) - 0x800`，位于映射 `mem.0x100000_0xf0000`
（`0x100000-0x1effff`，rw）内 —— 用临时区而非真正的 `.bss` 全局变量作为目标。
以下每条注意事项都已验证：

- **绝不能**跳过 `aeim`。没有它 `rsp = 0`，序言的 `push rbp` 和帧存储会回绕到 `0xffff...`，
  帧读回为 0，第一次迭代 `i < n` 就为假，输出缓冲区保持全零，且**不打印任何错误**。
- 在 6.2.2 上 `aeim` **不接受**参数。它使用 `esil.stack.addr = 0x00100000`、
  `esil.stack.size = 0x000f0000`，并设置 `rsp = 0x178000`。传 `aeim 0x1000` 会**静默失败**：
  它映射 `0x1000-0xf0fff`，遮蔽二进制自身的 LOAD 段，所有 ESIL 写入被丢弃，
  而 `rip` 仍会走到 `ret`。
- 写入真正的 `.bss`/`.data` 全局变量（`aer rdi=0x4040`）需要在模拟**之前**
  设置 `e io.cache=true`。否则写入会被静默丢弃，运行后再设 `io.cache` 也无济于事。
- `aesu <addr>` 在 `rip == addr` 处停止，但**不**执行该地址的指令。要停在 `ret` 处，
  绝不越过它：`aesu 0x1164` 会沿垃圾返回地址走下去并覆盖第一个明文字节
  （`ESIL` 变成 `&SIL`）。
- `aei` 已经把 `rip` 设为当前 seek，所以在 6.2.2 上 `aeip` 是无害的空操作 ——
  但保留它作为文档化惯用法。
- `aer` 与 `ar` 都能读写 ESIL 寄存器，且 r2 的 flag 在其中能被解析：
  `aer rsi=obj.enc` 得到 `0x00002020`。

**关键要点：** `aei` + `aeim` + `aeip` + `aer` + `aesu <ret>` 就是全部配方；
每一步被跳过或参数错误时，都是静默失败而不是报错。

<a id="r2pipe-session-lifecycle"></a>
## r2pipe 会话生命周期

一个句柄就是一整个 radare2 进程，所以要提前规划会话里的工作。
`r2pipe.open(path)` 给你 `.cmd()` 用于执行命令，`.quit()`（返回 `None`）用于关闭；
`.cmd('aaa')` 返回 `''`，因为所有 INFO/WARN 行都走 stderr。调试会话传 `flags=['-d']` ——
已验证可用，子进程是 `radare2 -d -q0 <bin>`，`db`、`dc`、`dr rip`、`ds 2` 在其下均正常：

```python
import r2pipe

r2 = r2pipe.open('BINARY', flags=['-d'])   # 调试会话；子进程为 `radare2 -d -q0 <bin>`
r2.cmd('aaa')
r2.cmd('db 0x1119')                        # 断点
r2.cmd('dc')                               # 继续
print(r2.cmd('dr rip').strip())            # strip() —— cmd() 从不 strip
print(r2.cmd('ds 2').strip())              # 单步
r2.quit()                                  # None
```

规划时要考虑的几条生命周期事实：

- 同一进程内的两个活句柄**都**存活且相互独立；关掉一个，另一个照常工作。
  也已用两个真实线程验证过。这推翻了常见的"每进程只能一个 r2"说法。
- 成本：5 次连续的 open+aaa+quit 测得 23.5 / 22.5 / 22.4 / 21.8 / 22.1 ms ——
  平均每轮 22.5 ms，约 45 轮/秒。应按句柄批量处理工作，而不是每字节重开一次。
- 孤儿进程检查：`/usr/bin/r2` 是指向 `radare2` 的符号链接，所以用 `pgrep -x radare2`，
  而不是 `r2`。在 4 次运行中有 1 次在 `quit()` 后立刻残留了被调试进程 PID，
  所以不要承诺零孤儿。
- **反模式：** 在 `-d` 会话上执行 `dcs` 会进入无界的 SIGSEGV 循环，60 秒产生
  188 万行 / 80.7 MB。只用 `db` + `dc` + `dr rip`。

**关键要点：** 每个句柄的建立与拆除约 22 ms，所以把全部分析放在同一个会话里完成 ——
并且把调试循环限制在 `db`/`dc`/`dr`，避免 SIGSEGV 失控。

<a id="parsing-r2-json-output-with-cmdj"></a>
## 用 cmdj 解析 r2 的 JSON 输出

在 r2pipe 1.9.8 上 `cmdj()` 与 `cmdJ()` 行为不同，所以要始终选 `cmdj()`。
`cmdj()` 返回普通 dict；`cmdJ()` 通过
`collections.namedtuple("X", d.keys(), rename=True)` 解析，会把 r2 的连字符键弄坏 ——
`aflj` 元素里的 `is-pure` 会变成属性 `_3`。用 `isinstance` 和 `None` 检查做防护，
不要用异常：`.cmdj('notacommand')` 返回 `{}` 而不抛错（源码把空输出替换成 `"{}"`），
而 `.cmdj('pi')` 返回 `None`，同时向 stderr 写
`r2pipe.cmdj.Error: Expecting value: line 1 column 1 (char 0)`。

```python
import r2pipe

r2 = r2pipe.open('BINARY')
r2.cmd('aaa')

fns = r2.cmdj('aflj')             # 永远 cmdj() —— 绝不用 cmdJ()（'is-pure' -> '_3'）
if not isinstance(fns, list):     # 未知命令给 {}，非 JSON 输出给 None
    fns = []
print(len(fns))

pdf = r2.cmdj('pdfj @ main')      # 含 'name' 与 'size' 的 dict；main 处有 12 条 op
if pdf is None:
    pdf = {}
r2.quit()
```

JSON 命令族（`aaa` 之前 / 之后）：

| 命令 | 返回 | 需要 aaa | 备注 |
|---|---|---|---|
| `aflj` | list | 是 | 键 `addr`、`name`；分析前它是字符串 `'[]'` |
| `pdfj` | dict | 是 | 键 `name`、`size`；`@ main` 的 `len(ops) == 12`；分析前是空字符串 |
| `agj` | list | 是 | 键 `name`、`addr`；分析前是空字符串 |
| `izj` | list | — | 在这个 ELF 上是**空的**（0 条）；字面量要用 `izzj`（74 条，键 `vaddr`、`paddr`、`ordinal`、`size`） |
| `axtj` | list | 是 | 键 `from`、`type`；还需要 seek —— 在 entry0 处静默返回 `[]` |
| `iiij` | list | 否 | 键 `ordinal`、`bind` |

非 JSON 输出对 `cmdj` 与 `cmdJ` 都返回 `None`，空输出（`cdj`、`aE`）则给出
`cmdj={}` / `cmdJ=None`。

**关键要点：** 永远 `cmdj()`，绝不用 `cmdJ()` —— 并把 `{}` 和 `None` 当作"没有数据"，
而不是用 `try/except` 包住调用。

<a id="mapping-checkers-with-xrefs-and-aflj"></a>
## 用 xref 与 aflj 定位校验函数

`axt` 的意思是"指向某地址的引用" —— 即**调用者**，而不是被调用者（常见误解；
`axff @ <fn>` 给出某函数的被调用者，`axf @ <instr>` 给出某条指令的引用）。
正是这个方向性，让你找到给校验函数喂输入的代码：

```bash
r2 -q -A -c 'axt @ sym.check' FILE 2>/dev/null
# dbg.main 0x118e [CALL:--x] call dbg.check

# 要对调用的目标地址查询，而不是调用点：axtj @ 0x118e 得到 []
r2 -q -A -c 'axtj @ sym.check' FILE 2>/dev/null

r2 -q -A -c 'axff @ main' FILE 2>/dev/null        # main 的被调用者
r2 -q -A -c 'axlq' FILE 2>/dev/null               # 所有 xref；axlc 计数（测试二进制上为 28）
```

`axtj` 返回顶层的对象数组，所有数字都是**十进制**（`4494` == `0x118e`）：

```json
[{'from':4494,'type':'CALL','perm':'--x','opcode':'call sym.check','fcn_addr':4465,'fcn_name':'main','flag':'sym.main','realname':'main','refname':'sym.check'}]
```

会咬到脚本的几个细节：在 6.2.2 上 `aef` **不是** xref 命令（它是 ESIL 的"模拟函数"，
什么都不打印）；空结果对 `axtj` 是 `[]`，对 `axt` 则完全为空，而退出码无法区分两者，
所以要按 `[]` 解析。批量枚举时，只需 shell 出去一次，让 JSON 干活：

```python
import json, subprocess
out = subprocess.run(
    ["r2", "-q", "-A", "-c", "aflj", "BINARY"],
    capture_output=True, text=True)
fns = json.loads(out.stdout)
for f in fns:
    print(f"{f['addr']:#08x}  {f['realsz']:>4}  {f['name']}")
print(f"-- {len(fns)} functions")
```

关于 `aflj` 输出：数值字段是十进制；顺序是分析顺序而非地址顺序，需要有序输出就自己排序；
`aflj` 同时带 `size` 与 `realsz`，而 `afl` 的 size 列对应 `realsz`
（tm_clones 那一对在 `afl` 显示 34/51，而 `aflj` 中 `size` 为 41/57、`realsz` 为 34/51）；
`is-pure` 是字符串 `"false"`，而其他布尔值是真 JSON 的 `false`/`true`。

**关键要点：** `axt` 回答"谁调用它"，而校验函数的输入恰好来自某个调用者时，这正是你要问的问题 ——
然后用单个批处理进程通过 `aflj` 批量枚举函数。

<a id="script-safe-config-and-stderr-noise"></a>
## 脚本安全的配置与 stderr 噪音

两条约定让 r2 输出保持可解析。第一，每次调用都丢弃 stderr：r2 会把
`WARN: Relocs has not been applied...` 和分析 `INFO:` 行写到那里，
所以 shell 里 `2>/dev/null`（或 `subprocess` 里 `capture_output=True`）是默认做法。
第二，显式关闭颜色 —— `e scr.color=1` 会让 `afl` 输出含 18 个 ANSI 转义，
`e scr.color=0` 则为 0；虽然 r2pipe 已默认 `-q0`（它把 `scr.color` 默认为 0），
但自己设一遍才是安全保证。长分析可以用 `e anal.timeout` 在 N 秒后停止分析
（默认 `'0'` = 不超时），且该设置可读回验证：

```bash
r2 -q -A -c 'afl' FILE 2>/dev/null

r2 -q -c 'e scr.color=0' -c 'afl' FILE 2>/dev/null            # 0 个 ANSI 转义（scr.color=1 -> 18）

r2 -q -c 'e anal.timeout=5' -c 'e anal.timeout' FILE 2>/dev/null   # -> '5'
```

**关键要点：** 只要丢弃 stderr 并固定 `scr.color=0`，任何吵闹的 r2 调用都变得脚本安全 ——
`anal.timeout` 通常是你唯一需要动的旋钮。
