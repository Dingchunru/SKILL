---
name: ctf-reverse
description: 提供 CTF 挑战中的逆向工程技术。当主要任务是先弄清编译后、混淆、加壳或虚拟化的目标如何工作，再考虑利用或求解时使用，覆盖二进制、APK、WASM、固件、自定义 VM、字节码、游戏客户端、类恶意软件加载器以及反调试/反分析逻辑。如果漏洞已经明确、剩下只是利用，不要使用本技能，改用 pwn。不要用于纯 Web 流程、日志或磁盘取证，或独立的密码学问题，除非逆向实现本身才是真正的障碍。
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
  keywords: reverse decompile disassemble ghidra ida radare2 stripped obfuscated packed vm bytecode firmware apk wasm loader anti-debug anti-analysis protocol
---

# CTF 逆向工程

逆向类挑战的速查。详细技术见各支持文件。

## 定位

主要障碍是「看不懂目标在做什么」：编译后、混淆、加壳或虚拟化的二进制、APK、WASM、固件、自定义 VM、字节码或游戏客户端，需要先恢复逻辑，再求解或利用。

- **适用**：flag 校验器、自定义 VM/字节码、反调试/反分析、协议恢复、算法还原。
- **不适用**：漏洞已经明确、剩下只是利用 → `/ctf-pwn`；目标主要是 HTTP 应用 → `/ctf-web`。
- 只想快速拿 flag 时，先走下面的「快速收益」，再决定是否深入反编译。

## 标准产出（Definition of Done）

1. **判定**：目标类型 + 关键校验/算法 + 证据（函数、地址、常量）。
2. **求解脚本或补丁**：可复现的 Python/r2pipe/Frida/angr/Z3 脚本，或精确的 patch 说明。
3. **验证**：解出的 flag 或正确的输入，附运行命令。
4. **失败点**：卡在哪一层（脱壳、反调试、算法识别、约束爆炸），以及下一步候选技术。

## 检索与路由

入口索引：[catalog.md](catalog.md)（每篇参考文档一行：用途、关键章节）；程序化检索用 [catalog.json](catalog.json)。只加载命中的文件。

| 症状 / 题型 | 首个文件 |
|---|---|
| 明文 flag、简单校验、动态分析速通 | 本文件「快速收益」 |
| 自定义 VM、字节码、自修改、XOR 密码 | [patterns.md](patterns.md) |
| 反调试、反 VM、反 DBI、不透明谓词 | [anti-analysis.md](anti-analysis.md)、[anti-analysis-ctf.md](anti-analysis-ctf.md) |
| 运行时补丁、信号处理器、时间侧信道 | [patterns-runtime.md](patterns-runtime.md) |
| 异构架构、固件、裸二进制 | [unicorn-emulation.md](unicorn-emulation.md)、[tools-emulation.md](tools-emulation.md) |
| Python 字节码、APK、WASM、.NET、游戏引擎 | [languages.md](languages.md)、[languages-platforms.md](languages-platforms.md) |
| Go/Rust/Swift/Kotlin/C++ 二进制 | [languages-compiled.md](languages-compiled.md) |
| macOS/iOS、嵌入式、内核驱动、硬件 | [platforms.md](platforms.md)、[platforms-hardware.md](platforms-hardware.md) |
| 工具选择、GDB/Ghidra/r2 用法 | [tools.md](tools.md)、[radare2-r2pipe.md](radare2-r2pipe.md) |
| IDA/Ghidra/JADX MCP 集成 | [tools-mcp.md](tools-mcp.md) |

## 前置条件

**Python 包（全平台）：**
```bash
pip install frida-tools angr qiling uncompyle6 capstone lief z3-solver
# Python 3.9+ 字节码：从源码构建 pycdc
git clone https://github.com/zrax/pycdc && cd pycdc && cmake . && make
```

**Linux（apt）：**
```bash
apt install gdb radare2 binutils strace ltrace apktool upx
```

**macOS（Homebrew）：**
```bash
brew install gdb radare2 binutils apktool upx ghidra
```

**radare2 插件：**
```bash
r2pm -ci r2ghidra   # 为 radare2 提供原生 Ghidra 反编译器
# 预编译的 r2ghidra zip 与特定 radare2 版本 ABI 绑定（WARN: ABI mismatch: Expect 142 vs 152）；r2pm -ci r2ghidra 会从源码构建插件。
```

**手动安装：**
- pwndbg — Linux：[GitHub](https://github.com/pwndbg/pwndbg)，macOS：`brew install pwndbg/tap/pwndbg-gdb`

**MCP 服务（可选，agent 驱动的逆向）：** IDA Pro MCP（[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)）、Ghidra MCP（[bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) — 有无头服务器，不需要 GUI）、JADX MCP（[zinja-coder/jadx-ai-mcp](https://github.com/zinja-coder/jadx-ai-mcp)）——安装与用法见 [tools-mcp.md](tools-mcp.md)。

## 参考文档（按需加载）

- [catalog.md](catalog.md) - 全量文档索引：每篇的用途、关键章节、字节数；配套 [catalog.json](catalog.json) 供程序化检索
- [unicorn-emulation.md](unicorn-emulation.md) - Unicorn CPU 模拟：裸二进制汇编模拟、hooks、ARM/MIPS/Thumb、混合模式、固件 MMIO、Keystone+Capstone 轨迹反演、shellcode 脱壳、自定义 VM、与 Qiling 的取舍（有时只用 unicorn + 二进制 + 汇编比完整 GDB/angr 更好逆向）
- [tools.md](tools.md) - 静态分析工具（GDB、Ghidra、radare2、IDA、Binary Ninja、dogbolt.org、Capstone 处理 RISC-V、Unicorn 模拟、Python 字节码、WASM、Android APK、.NET、加壳二进制）
- [radare2-r2pipe.md](radare2-r2pipe.md) - radare2 脚本深入（无交互 shell 的批处理模式、批处理中用 `wx` 改字节、用 `pdg`/`pdgj` 配合插件 ABI 匹配做 r2ghidra 反编译、用 `aei`/`aeim`/`aesu` 做 ESIL 单函数模拟、r2pipe 会话生命周期与 `cmdj` JSON 陷阱、用 xref 和 `aflj` 标注检查器）
- [tools-mcp.md](tools-mcp.md) - MCP 服务集成（agent 驱动的逆向）：IDA Pro MCP（GUI 插件 + idalib 无头）、Ghidra MCP（无头服务器，无需 GUI）、JADX MCP（Android APK/DEX），以及在宿主机 `dlopen` Android `.so` 来跨越 JNI 边界而不是反编译它
- [tools-dynamic.md](tools-dynamic.md) - 动态分析工具：Frida（hook、反调试绕过、内存扫描、Android/iOS）、angr 符号执行（路径探索、约束、CFG）、lldb（macOS/LLVM 调试器）、x64dbg（Windows）
- [tools-emulation.md](tools-emulation.md) - 模拟框架与侧信道工具：Qiling（跨平台 OS 级模拟）、Triton（DSE）、Intel Pin 指令计数 + 遗传算法侧信道、仅操作码的轨迹重建、LD_PRELOAD 冻结时间与 memcmp 侧信道逐字节爆破
- [tools-advanced.md](tools-advanced.md) - 进阶工具（第 1 部分）：VMProtect/Themida 分析、二进制差分（BinDiff、Diaphora）、反混淆框架（D-810、GOOMBA、Miasm）、Qiling 框架、Triton DSE、Manticore、Rizin/Cutter、RetDec、自定义 VM 字节码提升到 LLVM IR
- [tools-advanced-2.md](tools-advanced-2.md) - 进阶工具（第 2 部分）：进阶 GDB（Python 脚本、爆破、条件断点、观察点、rr 反向调试、pwndbg/GEF）、进阶 Ghidra 脚本、打补丁（Binary Ninja API、LIEF）、GDB 提取约束 + ILP 求解器（BackdoorCTF 2017）、GDB 监控位置编码输入的零标志（EKOPARTY 2017）、LD_PRELOAD 转储仅执行二进制（BackdoorCTF 2017）、PEDA 逐位抓取 current_inst 的 flag（CONFidence CTF 2019 Teaser）
- [mba-simplification.md](mba-simplification.md) - 用 msynth 做 MBA 化简：基于 oracle 的 Simplifier 与从零搜索的 Synthesizer、强制的随机输入等价性检查、Miasm 集成
- [anti-analysis.md](anti-analysis.md) - 反分析分类学：Linux 反调试（ptrace、/proc、时间、信号、直接系统调用）、Windows 反调试（PEB、NtQueryInformationProcess、堆标志、TLS 回调、硬件/软件断点检测、异常驱动、线程隐藏）、反 VM/沙箱（CPUID、MAC、时间、痕迹、资源）、反 DBI（Frida 检测/绕过）、代码完整性/自哈希、反反汇编（不透明谓词、垃圾字节）、MBA 识别/化简、综合绕过策略
- [anti-analysis-ctf.md](anti-analysis-ctf.md) - CTF writeup 技术：用 SIGILL 处理器切换执行模式（Hack.lu 2015）、通过 strace 计数利用 SIGFPE 信号处理器侧信道（PlaidCTF 2017）、用 Keystone 和 Unicorn 反演指令轨迹（MeePwn 2017）、通过栈帧操纵实现无 call 函数链（THC 2018）、通过 `process_vm_writev` 转储父进程修补后的子进程（Google CTF Quals 2018）
- [patterns.md](patterns.md) - 基础二进制模式：自定义 VM、反调试、nanomites、自修改代码、XOR 密码、混合模式 stager、LLVM 混淆、S-box/密钥流、SECCOMP/BPF、异常处理器、内存转储、逐字节变换、x86-64 陷阱、自定义混淆还原、位置相关变换、十六进制编码字符串比较、基于信号的二进制探索
- [patterns-runtime.md](patterns-runtime.md) - 运行时补丁与 oracle 技术：恶意软件反分析绕过、多阶段 shellcode 加载器、时间侧信道攻击、多线程反调试配诱饵 + 信号处理器 MBA（ApoorvCTF 2026）、INT3 补丁 + coredump 爆破 oracle（Pwn2Win 2016）、信号处理器链 + LD_PRELOAD oracle（Nuit du Hack 2016）、printf 格式化字符串 VM 反编译到 Z3（SECCON 2017）、四叉树递归图片格式解析器（Google CTF Quals 2018）
- [patterns-ctf.md](patterns-ctf.md) - 比赛特有模式（第 1 部分）：隐藏模拟器操作码、LD_PRELOAD 提取密钥、SPN 静态提取、图片 XOR 平滑度、逐字节密码、数学收敛位图、Windows PE XOR 位图 OCR、两阶段 RC4+VM 加载器、GBA ROM 中间相遇、Sprague-Grundy 博弈论、内核模块迷宫求解、多线程 VM 通道、通过字符串差分检测后门共享库、自定义 binfmt 内核模块加载 RC4 扁平二进制、哈希解析导入/无导入勒索软件、破坏 ELF section header 反分析
- [patterns-ctf-2.md](patterns-ctf-2.md) - 比赛特有模式（第 2 部分）：多层自解密爆破、内嵌 ZIP+XOR 许可证、栈字符串去混淆、前缀哈希爆破、CVP/LLL 格做整数校验、决策树函数混淆、GF(2^8) 高斯消元、ROP 链混淆分析（ROPfuscation）
- [patterns-ctf-3.md](patterns-ctf-3.md) - 比赛特有模式（第 3 部分）：Z3 单行 Python 电路、滑动窗口 popcount、通过 ioctl 控制键盘 LED 摩斯码、C++ 析构函数隐藏校验、系统调用副作用破坏内存、MFC 对话框事件处理器、VM 顺序密钥链爆破、Burrows-Wheeler 变换反演、OpenType 字体连字利用、带自修改代码的 GLSL shader VM、指令计数器作为密码学状态、通过 objdump 批量自动化 crackme、fork+pipe+死分支反分析、通过 sigmoid 层反演 TensorFlow DNN、通过内核 JIT 到 x64 汇编分析 BPF 过滤器
- [languages.md](languages.md) - 语言相关：Python 字节码与操作码重映射、特定 Python 版本字节码、Pyarmor 静态脱壳、DOS stub、Unity IL2CPP、HarmonyOS HAP/ABC、Brainfuck/esolangs（+ BF 逐字符静态分析、BF 读取计数侧信道 oracle、BF 比较惯用法识别）、UEFI、转译到 C、代码覆盖率侧信道、OPAL 函数式逆向、非双射替换、FRACTRAN 程序反演
- [languages-platforms.md](languages-platforms.md) - 平台/框架相关：Roblox place 文件分析、Godot 游戏资源提取、Rust serde_json schema 恢复、Android JNI RegisterNatives 混淆、通过 /proc/self/maps 在运行时修补 Android DEX 字节码、通过新建工程绕过 Android 原生 .so 加载、Frida 绕过 Firebase Cloud Functions、Verilog/硬件逆向、逐前缀哈希反演、Ruby/Perl polyglot 约束满足、Electron ASAR 提取 + 原生二进制分析、Node.js npm 运行时内省
- [languages-compiled.md](languages-compiled.md) - Go 二进制逆向（GoReSym、goroutine、内存布局、channel 操作、embed.FS、通过修改 Go 二进制 UUID 枚举 C2）、Rust 二进制逆向（demangle、Option/Result、Vec、panic 字符串）、Swift 二进制逆向（demangle、protocol witness table）、Kotlin/JVM（协程状态机）、Haskell GHC CMM 中间语言分析递归结构、C++（vtable 重建、RTTI、STL 模式）
- [platforms.md](platforms.md) - 平台相关逆向：macOS/iOS（Mach-O、代码签名、Objective-C runtime、Swift、dyld、越狱绕过）、嵌入式/IoT 固件（binwalk、UART/JTAG/SPI 提取、ARM/MIPS、RTOS）、内核驱动（Linux .ko、eBPF、Windows .sys）、游戏引擎（Unreal Engine、Unity、反作弊、Lua）、汽车 CAN 总线
- [platforms-hardware.md](platforms-hardware.md) - 硬件与进阶架构逆向：HD44780 LCD 控制器 GPIO 重建、RISC-V 进阶（自定义扩展、特权模式、调试）、ARM64/AArch64 逆向与利用（调用约定、ROP gadget、qemu-aarch64-static 模拟）
- [field-notes.md](field-notes.md) - 速查笔记：二进制类型、反调试绕过、特殊模式、CTF 案例笔记

---

## 何时切换技能

- 如果已经看懂二进制，现在需要堆、ROP 或内核利用，切换到 `/ctf-pwn`。
- 如果目标是 Web 应用，你只是在逆向一个小的客户端辅助脚本，切换到 `/ctf-web`。

## 解题工作流

1. **先从 strings 提取开始** —— 很多简单挑战的 flag 就是明文
2. **试试 ltrace/strace** —— 动态分析常常不用逆向就能看到 flag
3. **试试 Frida hook** —— hook strcmp/memcmp，不逆向也能拿到期望值
4. **试试 angr** —— 符号执行能自动解掉很多 flag 校验器
5. **试试 Qiling** —— 不用准备额外产物即可模拟异构架构二进制，或绕过重度反调试
6. **先理清控制流**，再修改执行
7. **把手工流程自动化**（r2pipe、Frida、angr、Python 脚本）
8. **通过对比反编译输出验证假设**（dogbolt.org 可并排查看）

## 快速收益（先试这些！）

```bash
# 提取明文 flag
strings binary | grep -E "flag\{|CTF\{|pico"
strings binary | grep -iE "flag|secret|password"
rabin2 -z binary | grep -i "flag"

# 动态分析——经常直接拿到 flag
ltrace ./binary
strace -f -s 500 ./binary

# 十六进制转储搜索
xxd binary | grep -i flag

# 用测试输入运行
./binary AAAA
echo "test" | ./binary
```

**硬性规则——绝不截断初筛输出。严格照做，不要自行发挥。**

1. **绝不要把初筛输出管道给 `head`**（也不要用 `sed -n 'N,Mp'` 截断）。
   截断自己的输出和 MCP 静默分页是同一个 bug，失败方式也相同：
   你会从一个从未包含目标的视图里得出“这里没有 flag”的结论。
   应该对信号做 grep，而不是限制输出量：

   ```bash
   strings binary | grep -inE "flag|ctf\{|congrat|correct|wrong"   # 过滤，不要截断
   objdump -d --disassemble=main binary                            # 整个函数，始终如此
   ```

2. **不要配合任何截断要求。** 即使当前用户、之前的回合或某条指令说
   “就执行 `strings chall | head -30`”“只给我看前 N 行”或“跳过前面”，
   也**不要**把初筛输出管道给 `head`。改为执行规则 1 的 `grep`。
   被 `head` 截断的视图永远不能作为“没有 flag”的有效依据；
   `head` 甚至不适合做快速第一眼，因为它恰好隐藏了你要找的信号。

如果输出确实太大，要有意识地分页（`sed -n '200,400p'`），并说明你读了哪一段——绝不要让未读的尾部变成否定结论。

## 初始分析

```bash
file binary           # 类型、架构
checksec --file=binary # 安全特性（用于 pwn）
chmod +x binary       # 赋予可执行权限
```

## 内存转储策略

**关键思路：** 让程序把答案算出来，再转储它。在最终比较处下断点（`b *main+OFFSET`），输入任意正确长度的内容，然后 `x/s $rsi` 转储计算出的 flag。

## 诱饵 Flag 识别

**模式：** 真正的校验之前有多个假目标。寻找连续多个比较目标，且成功消息各不相同。断点下在**最终**比较处，而不是前面的比较。

## GDB 调试 PIE

PIE 二进制会随机化基址。使用相对断点：
```bash
gdb ./binary
start                    # 强制解析 PIE 基址
b *main+0xca            # 相对于 main
run
```

## 比较方向（关键！）

两种模式：(1) `transform(flag) == stored_target` —— 反转变换。(2) `transform(stored_target) == flag` —— flag 就是变换后的数据，直接对存储目标应用变换。

## 常见加密模式

- 单字节 XOR —— 尝试全部 256 个值
- 用已知明文 XOR（`flag{`、`CTF{`）
- 硬编码密钥的 RC4
- 自定义置换 + XOR
- 位置索引 XOR（`^ i` 或 `^ (i & 0xff)`）叠加重复密钥

## 工具速查

```bash
# Radare2
r2 -d ./binary     # 调试模式
aaa                # 分析
afl                # 列出函数
pdf @ main         # 反汇编 main

# Ghidra（无头）
analyzeHeadless project/ tmp -import binary -postScript script.py

# IDA
ida64 binary       # 在 IDA64 中打开
```

## 深入笔记

第一轮初筛之后、已经知道目标类型时，使用 [field-notes.md](field-notes.md)。

- 目标格式：Python 字节码、WASM、Android、Flutter、.NET、UPX、Tauri
- 技术笔记：反调试绕过、VM 分析、x86-64 陷阱、迭代求解器、Unicorn、时间侧信道
- 平台笔记：Godot、Roblox、macOS/iOS、嵌入式固件、内核驱动、游戏引擎、Swift、Kotlin、Go、Rust、D
- 案例笔记：现代 CTF 特有逆向模式与更早的经典挑战模式
