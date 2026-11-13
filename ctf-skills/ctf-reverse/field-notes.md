# 逆向工程实战笔记

支撑 [`SKILL.md`](SKILL.md) 的详细速查笔记。请在完成初筛之后再读本文件。

## 目录

- [二进制类型](#二进制类型)
  - [Python .pyc](#python-pyc)
  - [WASM](#wasm)
  - [Android APK](#android-apk)
  - [Flutter APK（Dart AOT）](#flutter-apkdart-aot)
  - [.NET](#net)
  - [加壳（UPX）](#加壳upx)
  - [Tauri 打包的桌面应用](#tauri-打包的桌面应用)
- [反调试绕过](#反调试绕过)
- [专用模式](#专用模式)
  - [S-Box / 密钥流模式](#s-box--密钥流模式)
  - [自定义 VM 分析](#自定义-vm-分析)
  - [Python 字节码逆向](#python-字节码逆向)
  - [基于信号的二进制探索](#基于信号的二进制探索)
  - [通过打补丁绕过恶意样本反分析](#通过打补丁绕过恶意样本反分析)
  - [期望值表](#期望值表)
  - [x86-64 坑点](#x86-64-坑点)
  - [迭代求解模式](#迭代求解模式)
  - [Unicorn 模拟（复杂状态）](#unicorn-模拟复杂状态)
  - [多阶段 Shellcode 加载器](#多阶段-shellcode-加载器)
  - [时序侧信道攻击](#时序侧信道攻击)
  - [Godot 游戏资源提取](#godot-游戏资源提取)
  - [Roblox place 文件分析](#roblox-place-文件分析)
  - [未 strip 二进制的信息泄漏](#未-strip-二进制的信息泄漏)
  - [自定义 mangle 函数逆向](#自定义-mangle-函数逆向)
  - [Rust serde_json 结构恢复](#rust-serde_json-结构恢复)
  - [基于位置的变换逆向](#基于位置的变换逆向)
  - [十六进制编码字符串比较](#十六进制编码字符串比较)
- [CTF 案例笔记](#ctf-案例笔记)
  - [内嵌 ZIP + XOR 许可证解密](#内嵌-zip--xor-许可证解密)
  - [栈字符串去混淆（.rodata XOR 数据块）](#栈字符串去混淆rodata-xor-数据块)
  - [前缀哈希爆破](#前缀哈希爆破)
  - [数学收敛位图](#数学收敛位图)
  - [RISC-V 二进制分析](#risc-v-二进制分析)
  - [Sprague-Grundy 博弈论二进制](#sprague-grundy-博弈论二进制)
  - [内核模块迷宫求解](#内核模块迷宫求解)
  - [带通道的多线程 VM](#带通道的多线程-vm)
  - [CVP/LLL 格方法求解带约束整数校验](#cvplll-格方法求解带约束整数校验)
  - [决策树函数混淆](#决策树函数混淆)
  - [Android JNI RegisterNatives 混淆](#android-jni-registernatives-混淆)
  - [多层自解密二进制](#多层自解密二进制)
  - [带自修改代码的 GLSL 着色器 VM](#带自修改代码的-glsl-着色器-vm)
  - [GF(2^8) 高斯消元恢复 flag](#gf28-高斯消元恢复-flag)
  - [用 Z3 求解单行 Python 布尔电路](#用-z3-求解单行-python-布尔电路)
  - [滑动窗口 popcount 差分传播](#滑动窗口-popcount-差分传播)
  - [Ruby/Perl 多语言文件约束满足](#rubyperl-多语言文件约束满足)
  - [Verilog/硬件逆向](#verilog硬件逆向)
  - [自定义 binfmt 内核模块与 RC4 扁平二进制](#自定义-binfmt-内核模块与-rc4-扁平二进制)
  - [哈希解析导入 / 无导入勒索软件](#哈希解析导入--无导入勒索软件)
  - [ELF 节头损坏作为反分析](#elf-节头损坏作为反分析)
  - [Brainfuck 逐字符静态分析](#brainfuck-逐字符静态分析)
  - [Brainfuck 通过读取计数 oracle 的侧信道](#brainfuck-通过读取计数-oracle-的侧信道)
  - [Brainfuck 比较惯用法识别](#brainfuck-比较惯用法识别)
  - [被植入后门的共享库检测](#被植入后门的共享库检测)
  - [Go 二进制逆向](#go-二进制逆向)
  - [修改 Go 二进制 UUID 以枚举 C2](#修改-go-二进制-uuid-以枚举-c2)
  - [D 语言二进制逆向](#d-语言二进制逆向)
  - [Rust 二进制逆向](#rust-二进制逆向)
  - [Frida 动态插桩](#frida-动态插桩)
  - [Frida 绕过 Firebase Cloud Functions](#frida-绕过-firebase-cloud-functions)
  - [angr 符号执行](#angr-符号执行)
  - [Qiling 模拟](#qiling-模拟)
  - [VMProtect / Themida 分析](#vmprotect--themida-分析)
  - [二进制差分](#二进制差分)
  - [进阶 GDB（pwndbg、rr）](#进阶-gdbpwndbgrr)
  - [macOS / iOS 逆向](#macos--ios-逆向)
  - [嵌入式 / IoT 固件逆向](#嵌入式--iot-固件逆向)
  - [内核驱动逆向](#内核驱动逆向)
  - [游戏引擎逆向](#游戏引擎逆向)
  - [Swift / Kotlin 二进制逆向](#swift--kotlin-二进制逆向)
  - [INT3 补丁 + coredump 爆破 Oracle](#int3-补丁--coredump-爆破-oracle)
  - [信号处理器链 + LD_PRELOAD Oracle](#信号处理器链--ld_preload-oracle)
  - [字体连字利用](#字体连字利用)
  - [指令计数器作为密码学状态](#指令计数器作为密码学状态)
  - [Burrows-Wheeler 变换求逆](#burrows-wheeler-变换求逆)
  - [FRACTRAN 程序求逆](#fractran-程序求逆)
  - [仅凭操作码重建轨迹](#仅凭操作码重建轨迹)
  - [线程竞争导致有符号整数溢出](#线程竞争导致有符号整数溢出)
  - [ESP32/Xtensa 固件逆向](#esp32xtensa-固件逆向)
  - [自定义 VM 字节码提升到 LLVM IR](#自定义-vm-字节码提升到-llvm-ir)
  - [SIGFPE 信号处理器侧信道](#sigfpe-信号处理器侧信道)
  - [通过 objdump 批量自动化 crackme](#通过-objdump-批量自动化-crackme)
  - [Android DEX 运行时字节码打补丁](#android-dex-运行时字节码打补丁)
  - [Fork + Pipe + 死分支反分析](#fork--pipe--死分支反分析)

<a id="binary-types"></a>
## 二进制类型

<a id="python-pyc"></a>
### Python .pyc
用 `marshal.load()` + `dis.dis()` 反汇编。文件头：8 字节（2.x）、12（3.0-3.6）、16（3.7+）。见 [languages.md](languages.md#python-字节码逆向disdis-输出)。

<a id="wasm"></a>
### WASM
```bash
wasm2c checker.wasm -o checker.c
gcc -O3 checker.c wasm-rt-impl.c -o checker

# WASM 打补丁（游戏类挑战）：
wasm2wat main.wasm -o main.wat    # 二进制 → 文本
# 编辑 WAT：翻转比较、修改常量
wat2wasm main.wat -o patched.wasm # 文本 → 二进制
```

**WASM 游戏打补丁（Tac Tic Toe，Pragyan 2026）：** 如果证明生成与落子质量无关，
可以给 minimax 打补丁（把 `i64.lt_s` 改成 `i64.gt_s`、改变 bestScore 的符号），
让 AI 下得很差而证明仍然有效。

<a id="android-apk"></a>
### Android APK
资源用 `apktool d app.apk -o decoded/`；Java 反编译用 `jadx app.apk`。
在 `decoded/res/values/strings.xml` 里找 flag。见 [tools.md](tools.md#android-apk)。

<a id="flutter-apk-dart-aot"></a>
### Flutter APK（Dart AOT）
如果存在 `lib/arm64-v8a/libapp.so` + `libflutter.so`，使用
[Blutter](https://github.com/worawit/blutter)：`python3 blutter.py path/to/app/lib/arm64-v8a out_dir`。
它会输出重建的 Dart 符号和 Frida 脚本。见 [tools.md](tools.md#flutter-apkblutter)。

<a id="net"></a>
### .NET
- dnSpy —— 调试 + 反编译
- ILSpy —— 反编译器

<a id="packed-upx"></a>
### 加壳（UPX）
```bash
upx -d packed -o unpacked
```
如果脱壳失败，先检查 UPX 元数据：确认 UPX 节名、头部字段和版本标记是否完好。
如果元数据看起来被篡改或不确定，去 GitHub 上查阅 UPX 源码，定位可能的修改点。

<a id="tauri-packed-desktop-apps"></a>
### Tauri 打包的桌面应用
Tauri 会把 Brotli 压缩的前端资源嵌入可执行文件。找到 `index.html` 的 xref 以定位资源索引表，
dump 数据块，再做 Brotli 解压。参考：`tauri-codegen/src/embedded_assets.rs`。

<a id="anti-debugging-bypass"></a>
## 反调试绕过

常见检查：
- `IsDebuggerPresent()` / PEB.BeingDebugged / NtQueryInformationProcess（Windows）
- `ptrace(PTRACE_TRACEME)` / `/proc/self/status` 中的 TracerPid（Linux）
- TLS 回调（在 main 之前运行 —— 检查 PE TLS Directory）
- 计时检查（`rdtsc`、`clock_gettime`、`GetTickCount`）
- 硬件断点检测（通过 GetThreadContext 读 DR0-DR3）
- INT3 扫描 / 代码自哈希（对 .text 节做 CRC）
- 基于信号：SIGTRAP 处理器、SIGALRM 超时、用 SIGSEGV 承载真实逻辑
- Frida/DBI 检测：扫描 `/proc/self/maps`、27042 端口、inline hook 检查

绕过：在检查处下断点，改寄存器跳过条件分支。pwntools 补丁：
`elf.asm(elf.symbols.ptrace, 'ret')` 把函数替换成立即返回。
见 [patterns.md](patterns.md#pwntools-二进制打补丁crypto-cat)。

完整的反分析技巧与绕过（30+ 种方法附代码）见 [anti-analysis.md](anti-analysis.md)。

<a id="specialized-patterns"></a>
## 专用模式

<a id="s-box--keystream-patterns"></a>
### S-Box / 密钥流模式
**Xorshift32：** 移位 13、17、5  
**Xorshift64：** 移位 12、25、27  
**魔数常量：** `0x2545f4914f6cdd1d`、`0x9e3779b97f4a7c15`

<a id="custom-vm-analysis"></a>
### 自定义 VM 分析
1. 识别结构：寄存器、内存、IP
2. 逆向 `executeIns` 搞清操作码含义
3. 写一个把操作码映射到助记符的反汇编器
4. 通常爆破比完整逆向更容易
5. 找通过命令行参数加载的字节码文件

VM 工作流、操作码表与状态机 BFS 见 [patterns.md](patterns.md#自定义-vm-逆向)。

**顺序密钥链爆破：** 当 VM 分小块校验输入（例如 3 字节 = 2^24 个候选），
且每块的输出密钥喂给下一块时，用 OpenMP 并行逐块顺序爆破。
求解器用 `gcc -O3 -march=native -fopenmp` 编译。
见 [patterns-ctf-3.md](patterns-ctf-3.md#vm-顺序密钥链暴力midnight-flag-2026)。

<a id="python-bytecode-reversing"></a>
### Python 字节码逆向
带奇偶交错表的 XOR flag 校验很常见。字节码分析技巧与逆向模式见
[languages.md](languages.md#python-字节码逆向disdis-输出)。

<a id="signal-based-binary-exploration"></a>
### 基于信号的二进制探索
二进制把 UNIX 信号当作二叉树导航；通过 `LD_PRELOAD` hook `sigaction`，靠发送信号做 DFS。
见 [patterns.md](patterns.md#基于信号的二进制探索)。

<a id="malware-anti-analysis-bypass-via-patching"></a>
### 通过打补丁绕过恶意样本反分析
在 Ghidra 中翻转 `JNZ`/`JZ`（0x75/0x74）、修改 sleep 值、给环境检查打补丁（`Ctrl+Shift+G`）。
见 [patterns-runtime.md](patterns-runtime.md#通过打补丁绕过恶意样本的反分析)。

<a id="expected-values-tables"></a>
### 期望值表
用 `objdump -s -j .rodata binary | less` 定位 —— 在比较指令附近找，大小与 flag 长度一致。

<a id="x86-64-gotchas"></a>
### x86-64 坑点
符号扩展与 32 位截断陷阱。细节与代码示例见 [patterns.md](patterns.md#x86-64-易错点)。

<a id="iterative-solver-pattern"></a>
### 迭代求解模式
逐位置尝试每个字节（0-255），与期望输出比对。
**均匀变换捷径：** 如果一个输入字节只影响一个输出字节，先建 0..255 映射再求逆。
完整实现见 [patterns.md](patterns.md)。

<a id="unicorn-emulation-complex-state"></a>
### Unicorn 模拟（复杂状态）
`from unicorn import *` —— 映射段、搭好栈、加 hook 做跟踪。
**混合模式陷阱：** 64 位桩代码通过 `retf` 跳到 32 位时，需要切到 `UC_MODE_32`，
并拷贝通用寄存器 + EFLAGS + XMM 寄存器。见 [tools.md](tools.md#unicorn-模拟执行)。

<a id="multi-stage-shellcode-loaders"></a>
### 多阶段 Shellcode 加载器
嵌套 shellcode 配 XOR 解码循环；在 `call rax` 下断，用 `set $rax=0` 绕过 ptrace，
从 `mov` 指令中提取 flag。见 [patterns-runtime.md](patterns-runtime.md#多阶段-shellcode-加载器)。

<a id="timing-side-channel-attack"></a>
### 时序侧信道攻击
校验耗时随正确字符变化；测量每个候选的耗时即可逐字节恢复 flag。
见 [patterns-runtime.md](patterns-runtime.md#时序侧信道攻击)。

<a id="godot-game-asset-extraction"></a>
### Godot 游戏资源提取
先用 KeyDot 从可执行文件中提取加密密钥，再用 gdsdecomp 解包 .pck 包。
见 [languages-platforms.md](languages-platforms.md#godot-游戏资源提取)。

<a id="roblox-place-file-analysis"></a>
### Roblox place 文件分析
通过 Asset Delivery API 查询版本历史；解析 `.rbxlbin` 的块（INST/PROP/PRNT），
跨版本差分脚本源码。见 [languages-platforms.md](languages-platforms.md#roblox-place-文件分析)。

<a id="unstripped-binary-information-leaks"></a>
### 未 strip 二进制的信息泄漏
**模式：** 调试信息与文件路径泄漏作者身份。快速检查：
`strings binary | grep "/home/"`（主目录）、`file binary`（是否 stripped）、
`readelf -S binary | grep debug`（调试节）。

<a id="custom-mangle-function-reversing"></a>
### 自定义 mangle 函数逆向
二进制每次 2 字节、带滚动状态地变换输入；从 `.rodata` 提取目标值，写一个逆函数。
见 [patterns.md](patterns.md#自定义-mangle-函数逆向)。

<a id="rust-serde_json-schema-recovery"></a>
### Rust serde_json 结构恢复
反汇编 serde 的 `Visitor` 实现以恢复期望的 JSON 结构；字段名连同顺序即揭示 flag。
见 [languages-platforms.md](languages-platforms.md#rust-serde_json-结构恢复)。

<a id="position-based-transformation-reversing"></a>
### 基于位置的变换逆向
二进制按位置索引加减；逆向时逐索引把偏移减回去。
见 [patterns.md](patterns.md#基于位置的变换逆向)。

<a id="hex-encoded-string-comparison"></a>
### 十六进制编码字符串比较
输入被转成十六进制再与常量比较。用 `xxd -r -p` 解码。
见 [patterns.md](patterns.md#十六进制编码字符串比较)。

<a id="ctf-case-notes"></a>
## CTF 案例笔记

<a id="embedded-zip--xor-license-decryption"></a>
### 内嵌 ZIP + XOR 许可证解密
`.rodata` 里有具名符号（`EMBEDDED_ZIP`、`ENCRYPTED_MESSAGE`）的二进制 →
提取内含许可证的 ZIP，用许可证字节与加密消息做 XOR 恢复 flag。无需执行。
见 [patterns-ctf-2.md](patterns-ctf-2.md#内嵌-zip--xor-许可证解密-metactf-2026)。

<a id="stack-string-deobfuscation-rodata-xor-blob"></a>
### 栈字符串去混淆（.rodata XOR 数据块）
二进制 mmap 出 `.rodata` 数据块、XOR 去混淆、再用来校验输入。
用 pyelftools 重新实现校验循环并提取数据块。留意 `0x9E3779B9`、`0x85EBCA6B`
常量与 `rol32()`。见 [patterns-ctf-2.md](patterns-ctf-2.md#从-rodata-xor-数据块还原栈字符串-nullcon-2026)。

<a id="prefix-hash-brute-force"></a>
### 前缀哈希爆破
二进制对每个前缀独立哈希。通过匹配前缀哈希，一次恢复一个字符。
见 [patterns-ctf-2.md](patterns-ctf-2.md#前缀哈希爆破-nullcon-2026)。

<a id="mathematical-convergence-bitmap"></a>
### 数学收敛位图
**模式：** 二进制按牛顿法收敛性对坐标点分类（例如 z^3-1=0）。
通过/失败网格拼出 ASCII 艺术 flag。关键：二进制是分类器而不是校验器 ——
逆向其数学并可视化。见 [patterns-ctf.md](patterns-ctf.md#数学收敛位图ehax-2026)。

<a id="risc-v-binary-analysis"></a>
### RISC-V 二进制分析
静态链接、已 strip 的 RISC-V ELF。用 Capstone 的
`CS_MODE_RISCVC | CS_MODE_RISCV64` 处理混合压缩指令。用 `qemu-riscv64` 模拟。
注意假 flag，以及用递增密钥做 XOR 解密的情况。见 [tools.md](tools.md#risc-v-二进制分析-ehax-2026)。

<a id="sprague-grundy-game-theory-binary"></a>
### Sprague-Grundy 博弈论二进制
游戏二进制用 PRNG 玩有界 Nim，用来选择必败局面的走法。
识别博弈框架（Grundy 值 = 堆 % (k+1)，XOR 判定局面），
并通过用户输入的反馈追踪 PRNG 状态演化。
见 [patterns-ctf.md](patterns-ctf.md#sprague-grundy-博弈论二进制dicectf-2026)。

<a id="kernel-module-maze-solving"></a>
### 内核模块迷宫求解
Rust 内核模块通过设备 ioctl 实现迷宫。动态枚举命令，写带诱饵规避的 DFS 求解器，
以最小静态二进制部署（裸系统调用，不依赖 libc）。
见 [patterns-ctf.md](patterns-ctf.md#内核模块迷宫求解dicectf-2026)。

<a id="multi-threaded-vm-with-channels"></a>
### 带通道的多线程 VM
自定义 VM 有 16+ 线程，通过 futex 通道通信。跨线程边界追踪数据流，
从 GDB 提取常量，留意被反转的有效性逻辑，用 BFS 状态空间搜索求解。
见 [patterns-ctf.md](patterns-ctf.md#多线程-vm-与通道同步dicectf-2026)。

<a id="cvplll-lattice-for-constrained-integer-validation"></a>
### CVP/LLL 格方法求解带约束整数校验
二进制用 64 位系数矩阵乘法校验 flag；解必须落在可打印 ASCII 范围内。
在 SageMath 中用 LLL 归约 + CVP 找出约束范围内的最近格点。
两阶段模式：阶段 1 恢复 AES 密钥，阶段 2 用另一个线性系统（mod 2^32）解密自定义 VM 字节码。
见 [patterns-ctf-2.md](patterns-ctf-2.md#约束整数校验的-cvplll-格求解-htb-shadowlabyrinth)。

<a id="decision-tree-function-obfuscation"></a>
### 决策树函数混淆
约 200+ 个自动生成的函数，用多项式比较把输入层层路由。
用 Ghidra headless 脚本化提取，而不是逐个手工逆向。
从已知输出格式出发做约束传播，可沿算术约束级联求解。
见 [patterns-ctf-2.md](patterns-ctf-2.md#决策树函数混淆-htb-wondersms)。

<a id="android-jni-registernatives-obfuscation"></a>
### Android JNI RegisterNatives 混淆
`JNI_OnLoad` 中的 `RegisterNatives` 隐藏了每个 Java native 方法由哪个 C++ 函数处理
（没有标准的 `Java_com_pkg_Class_method` 符号）。
沿 `JNI_OnLoad` → `RegisterNatives` → `fnPtr` 追踪真正的处理函数。
用 APK 里的 x86_64 `.so` 可获得最好的 Ghidra 反编译效果。
见 [languages-platforms.md](languages-platforms.md#android-jni-registernatives-混淆-htb-wondersms)。

<a id="multi-layer-self-decrypting-binary"></a>
### 多层自解密二进制
N 层二进制，每一层用用户提供的密钥字节 + SHA-NI 解密下一层。
用 oracle 判定（正确密钥 → 得到带预期模式的合法代码）。
用 fork-per-candidate 的 COW 隔离做 JIT 执行以提速。
见 [patterns-ctf-2.md](patterns-ctf-2.md#多层自解密二进制-dicectf-2026)。

<a id="glsl-shader-vm-with-self-modifying-code"></a>
### 带自修改代码的 GLSL 着色器 VM
**模式：** WebGL2 片元着色器在 256x256 RGBA 纹理（程序内存 + 显存）上实现图灵完备 VM。
自修改代码（STORE 操作码）会改写绘图指令。GPU 并行会导致写冲突 ——
改用 Python 顺序模拟以恢复完整输出。
见 [patterns-ctf-3.md](patterns-ctf-3.md#带自修改代码的-glsl-shader-vmapoorvctf-2026)。

<a id="gf28-gaussian-elimination-for-flag-recovery"></a>
### GF(2^8) 高斯消元恢复 flag
**模式：** 二进制在 GF(2^8) 上、用 AES 多项式（0x11b）做高斯消元。
`.rodata` 中有矩阵与增广向量；解向量即 flag。在反汇编里找常量 `0x1b`。
加法是 XOR，乘法走多项式约简。
见 [patterns-ctf-2.md](patterns-ctf-2.md#gf28-高斯消元恢复-flag-apoorvctf-2026)。

<a id="z3-for-single-line-python-boolean-circuit"></a>
### 用 Z3 求解单行 Python 布尔电路
**模式：** 单行 Python（2000+ 个分号）用海象运算符链，把 flag 当作大端整数做布尔电路校验。
判断式为混淆过的 XOR `(a | b) & ~(a & b)`。按分号拆分，符号化翻译成 Z3，一秒内求解。
见 [patterns-ctf-3.md](patterns-ctf-3.md#用-z3-求解单行-python-布尔电路bearcatctf-2026)。

<a id="sliding-window-popcount-differential-propagation"></a>
### 滑动窗口 popcount 差分传播
**模式：** 二进制按 16 位滑动窗口每个位置的期望 popcount 校验输入。
popcount 之差构成递推：`bit[i+16] = bit[i] + (data[i+1] - data[i])`。
爆破约 4000-8000 个合法的初始 16 位窗口；每个窗口即确定整条比特序列。
见 [patterns-ctf-3.md](patterns-ctf-3.md#滑动窗口-popcount-差分递推bearcatctf-2026)。

<a id="rubyperl-polyglot-constraint-satisfaction"></a>
### Ruby/Perl 多语言文件约束满足
**模式：** 同一份文件在 Ruby 和 Perl 中都是合法程序，各自对密钥施加不同约束。
利用 `=begin`/`=end`（Ruby 块注释）与 `=begin`/`=cut`（Perl POD）的差异，
让不同解释器运行不同代码。求两种语言约束的交集即可恢复唯一密钥。
见 [languages-platforms.md](languages-platforms.md#rubyperl-多语言同源约束求解-bearcatctf-2026)。

<a id="veriloghardware-re"></a>
### Verilog/硬件逆向
**模式：** 给出状态机的 Verilog HDL 源码，隐藏条件取决于移位寄存器历史。
分析 `always @(posedge clk)` 块与 `case` 语句，找出正确的输入序列。
见 [languages-platforms.md](languages-platforms.md#verilog硬件逆向-srdnlenctf-2026)。

<a id="custom-binfmt-kernel-module-with-rc4-flat-binaries"></a>
### 自定义 binfmt 内核模块与 RC4 扁平二进制
**模式：** 内核模块为加密的扁平二进制注册 binfmt 处理器。
逆向 `.ko` 找出 RC4 密钥（藏在 `movabs` 立即数里），解密扁平二进制，
再按模块 `vm_mmap` 调用中给出的固定虚拟地址导入。
见 [patterns-ctf.md](patterns-ctf.md#自定义-binfmt-内核模块--rc4-扁平二进制bsidessf-2026)。

<a id="hash-resolved-imports--no-import-ransomware"></a>
### 哈希解析导入 / 无导入勒索软件
**模式：** 二进制没有任何可见导入，运行时通过符号名哈希解析 API。
不必逆向哈希 —— 在 Docker 里用 `LD_PRELOAD` hook OpenSSL 函数，直接截获 AES 密钥。
见 [patterns-ctf.md](patterns-ctf.md#哈希解析导入--无导入勒索软件bsidessf-2026)。

<a id="elf-section-header-corruption-for-anti-analysis"></a>
### ELF 节头损坏作为反分析
**模式：** 损坏的节头会让分析工具崩溃，但程序头完好，所以二进制仍能正常运行。
把 `e_shoff` 补丁为 0，或只用 `readelf -l`（仅程序头）。
flag 藏在损坏节之后，带魔数标记 + XOR。
见 [patterns-ctf.md](patterns-ctf.md#elf-节头表损坏反分析bsidessf-2026)。

<a id="brainfuck-character-by-character-static-analysis"></a>
### Brainfuck 逐字符静态分析
**模式：** 校验输入的 BF 程序里，`,`（读字符）后面跟的 `+` 操作次数 = 期望的 ASCII 值。
按输入位置提取增量计数，不执行即可恢复期望输入。
见 [languages.md](languages.md#brainfuck-逐字符静态分析-bsidessf-2026)。

<a id="brainfuck-side-channel-via-read-count-oracle"></a>
### Brainfuck 通过读取计数 oracle 的侧信道
**模式：** BF 输入校验器在字符正确时会读取更多字节。
统计每个候选对应的 `,` 操作次数 —— 读取次数最多的就是正确字节。可逐字符恢复。
见 [languages.md](languages.md#brainfuck-读取次数侧信道-oracle-bsidessf-2026)。

<a id="brainfuck-comparison-idiom-detection"></a>
### Brainfuck 比较惯用法识别
**模式：** 编译后的 BF 用固定惯用法做相等比较（`<[-<->] +<[>-<[-]]>[-<+>]`）。
给解释器加插桩以识别这些模式，直接提取比较操作数（期望的 flag 字节）。
见 [languages.md](languages.md#brainfuck-比较惯用法识别-bsidessf-2026)。

<a id="backdoored-shared-library-detection"></a>
### 被植入后门的共享库检测
二进制在 GDB 里正常、直接运行（suid）却失败？用 `ldd` 检查是否有非常规 libc 路径，
然后对可疑库与系统库做 `strings | diff`，找出注入的代码/口令。
见 [patterns-ctf.md](patterns-ctf.md#通过字符串比对发现被植入后门的共享库hacklu-ctf-2012)。

<a id="go-binary-reversing"></a>
### Go 二进制逆向
大型静态二进制、带 `go.buildid`？用 GoReSym 恢复函数名（对 stripped 二进制也有效）。
Go 的字符串是 `{ptr, len}` 对，不以 null 结尾。找 `main.main`、`runtime.gopanic`、
通道操作（`runtime.chansend1`/`chanrecv1`）。最佳效果用 Ghidra 的 golang-loader 插件。
见 [languages-compiled.md](languages-compiled.md#go-二进制逆向)。

<a id="go-binary-uuid-patching-for-c2-enumeration"></a>
### 修改 Go 二进制 UUID 以枚举 C2
**模式：** Go 写的 C2 客户端，UUID 来自 `-ldflags -X`。
在二进制中原地打补丁替换 UUID 字节（等长），注册到 C2，再通过 API 枚举客户端/文件。
见 [languages-compiled.md](languages-compiled.md#go-二进制-uuid-打补丁遍历-c2-客户端bsidessf-2026)。

<a id="d-language-binary-reversing"></a>
### D 语言二进制逆向
D 语言二进制的符号修饰独成一派（不是 C++ 风格）。模板用得很多，函数变体众多。
在符号中找 `_D` 前缀。
见 [languages-compiled.md](languages-compiled.md#d-语言二进制逆向csaw-ctf-2016)。

<a id="rust-binary-reversing"></a>
### Rust 二进制逆向
出现 `core::panicking` 字符串与 `_ZN` 修饰符号？用 `rustfilt` 还原。
panic 消息包含源码路径与行号 —— `strings binary | grep "panicked"` 是最快的方法。
Option/Result 枚举用判别字节（0=None/Err，1=Some/Ok）。
见 [languages-compiled.md](languages-compiled.md#rust-二进制逆向)。

<a id="frida-dynamic-instrumentation"></a>
### Frida 动态插桩
不改二进制即可 hook 运行时函数。`frida -f ./binary -l hook.js` 以插桩方式启动。
hook `strcmp`/`memcmp` 截获期望值，替换 `ptrace` 返回值绕过反调试，
扫描内存中的 flag 模式，替换校验函数。
见 [tools-dynamic.md](tools-dynamic.md#frida动态插桩)。

<a id="frida-firebase-cloud-functions-bypass"></a>
### Frida 绕过 Firebase Cloud Functions
**模式：** Android 应用通过 Firebase Cloud Functions 做校验。
登录后用 Frida hook 构造合法 payload（UID + 值 + 时间戳）并直接调用 Cloud Function，
绕过二维码/支付校验。见 [languages-platforms.md](languages-platforms.md#frida-绕过-firebase-cloud-functions-bsidessf-2026)。

<a id="angr-symbolic-execution"></a>
### angr 符号执行
自动探索路径以找出满足约束的输入。用 `angr.Project` 加载二进制，
设置 find/avoid 地址，调用 `simgr.explore()`。
把输入约束为可打印 ASCII 并给出已知前缀可加速求解。
hook 耗时函数（加密、I/O）以避免路径爆炸。
见 [tools-dynamic.md](tools-dynamic.md#angr符号执行)。

<a id="qiling-emulation"></a>
### Qiling 模拟
带 OS 层支持（系统调用、文件系统）的跨平台二进制模拟。可在任意主机上模拟
Linux/Windows/ARM/MIPS 二进制。没有调试器痕迹 —— 默认绕过所有反调试。
用 Python API hook 系统调用与地址。
见 [tools-emulation.md](tools-emulation.md#qiling-框架跨平台模拟)。

<a id="vmprotect--themida-analysis"></a>
### VMProtect / Themida 分析
VMProtect 把代码虚拟化成自定义字节码。识别 VM 入口（类似 pushad）、
定位 handler 表（大型间接跳转）、动态跟踪 handler。
CTF 中重点关注对输入的操作，而不是完整脱虚拟化。
Themida：用 ScyllaHide + Scylla 在 OEP 处 dump。见 [tools-advanced.md](tools-advanced.md#vmprotect-分析)。

<a id="binary-diffing"></a>
### 二进制差分
BinDiff 与 Diaphora 可比较两个二进制并高亮差异。题目给出打过补丁/原始版本时必备。
从 IDA/Ghidra 导出，做差分以找出漏洞或隐藏功能。见 [tools-advanced.md](tools-advanced.md#二进制差异对比)。

<a id="advanced-gdb-pwndbg-rr"></a>
### 进阶 GDB（pwndbg、rr）
pwndbg：`context`、`vmmap`、`search -s "flag{"`、`telescope $rsp`。GEF 是替代品。
用 `rr record`/`rr replay` 做反向调试 —— 可倒着单步执行。
用 Python 脚本做爆破与自动化跟踪。见 [tools-advanced-2.md](tools-advanced-2.md#高级-gdb-技巧)。

<a id="macos--ios-reversing"></a>
### macOS / iOS 逆向
Mach-O 二进制：`otool -l` 看 load command，`class-dump` 导出 Objective-C 头文件。
Swift：`swift demangle` 还原符号。iOS 应用：用 frida-ios-dump 解密 FairPlay DRM，
用 Frida hook 绕过越狱检测。打补丁后的二进制用 `codesign -f -s -` 重签名。
见 [platforms.md](platforms.md#macos--ios-逆向)。

<a id="embedded--iot-firmware-re"></a>
### 嵌入式 / IoT 固件逆向
`binwalk -Me firmware.bin` 递归提取。硬件层面：UART/JTAG/SPI flash 读取固件。
文件系统：SquashFS（`unsquashfs`）、JFFS2、UBI。
用 QEMU 模拟：`qemu-arm -L /usr/arm-linux-gnueabihf/ ./binary`。
见 [platforms.md](platforms.md#嵌入式--iot-固件逆向)。

<a id="kernel-driver-reversing"></a>
### 内核驱动逆向
Linux `.ko`：通过 `file_operations` 结构找 ioctl 处理函数，跟踪
`copy_from_user`/`copy_to_user`。用 QEMU+GDB（`-s -S`）调试。
eBPF：`bpftool prog dump xlated`。Windows `.sys`：找
`DriverEntry` → `IoCreateDevice` → IRP 处理函数。
见 [platforms.md](platforms.md#内核驱动逆向)。

<a id="game-engine-reversing"></a>
### 游戏引擎逆向
Unreal：用 UnrealPakTool 解包 .pak，用 FModel 逆向 Blueprint 字节码。
Unity Mono：用 dnSpy 反编译 Assembly-CSharp.dll。
反作弊（EAC、BattlEye、VAC）：先识别系统，再针对具体检查绕过。
Lua 游戏：用 `luadec`/`unluac` 处理字节码。见 [platforms.md](platforms.md#游戏引擎逆向)。

<a id="swift--kotlin-binary-reversing"></a>
### Swift / Kotlin 二进制逆向
Swift：`swift demangle` 还原符号，协议 witness table 负责分派，关注 `__swift5_*` 节。
Kotlin/JVM：协程会编译成 `invokeSuspend` 中的状态机，`jadx` 开 Kotlin 模式反编译效果最好。
Kotlin/Native：LLVM 后端，反汇编看起来像 C++。
见 [languages-compiled.md](languages-compiled.md#swift-二进制逆向)。

<a id="int3-patch--coredump-brute-force-oracle"></a>
### INT3 补丁 + coredump 爆破 Oracle
在变换输出之后补上 `0xCC`（INT3），开启 core dump，
用 `strings` 从 coredump 中取出计算后的状态，逐字符爆破输入。免去完整逆向变换。
见 [patterns-runtime.md](patterns-runtime.md#int3-补丁--coredump-爆破-oraclepwn2win-2016)。

<a id="signal-handler-chain--ld_preload-oracle"></a>
### 信号处理器链 + LD_PRELOAD Oracle
二进制用信号处理器链逐字符校验口令。用 LD_PRELOAD hook `signal()` ——
安装下一个处理器的调用本身就证明当前字符正确。
见 [patterns-runtime.md](patterns-runtime.md#信号处理器链--ld_preload-oraclenuit-du-hack-2016)。

<a id="font-ligature-exploitation"></a>
### 字体连字利用
自定义 OpenType 字体把多字符连字序列映射到单个字形；逆向 GSUB 表即可解出隐藏消息。
见 [patterns-ctf-3.md](patterns-ctf-3.md#利用-opentype-字体连字隐藏信息hack-the-vote-2016)。

<a id="instruction-counter-as-cryptographic-state"></a>
### 指令计数器作为密码学状态
**模式：** 手写汇编用一个专用寄存器（例如 `r12`）作为指令计数器，几乎每条指令后自增。
该计数器参与对输入字节的 XOR/ROL/乘法变换，使变换路径相关。
用 Unicorn 模拟做逐字节爆破即可恢复 flag。
见 [patterns-ctf-3.md](patterns-ctf-3.md#以指令计数器作为密码学状态metactf-flash-2026)。

<a id="burrows-wheeler-transform-inversion"></a>
### Burrows-Wheeler 变换求逆
没有终结符时，遍历所有可能的行索引来求 BWT 的逆。可用标准 `bwtool`，或手工按列排序重建。
见 [patterns-ctf-3.md](patterns-ctf-3.md#无终止符的-burrows-wheeler-逆变换asis-ctf-finals-2016)。

<a id="fractran-program-inversion"></a>
### FRACTRAN 程序求逆
这种神秘语言靠反复做分数乘法运算。求逆方法：把分数表中的分子/分母互换，倒着运行输出。
输入输出编码为质因数分解的指数。
见 [languages.md](languages.md#fractran-程序反演-boston-key-party-2016)。

<a id="opcode-only-trace-reconstruction"></a>
### 仅凭操作码重建轨迹
只有操作码（没有数据值）的执行轨迹仍会通过分支决策泄漏信息。
排序算法的比较会揭示元素顺序。对轨迹去重、切分为基本块即可重建。
见 [tools-emulation.md](tools-emulation.md#仅凭操作码重建轨迹0ctf-2016)。

<a id="thread-race-signed-integer-overflow"></a>
### 线程竞争导致有符号整数溢出
游戏二进制的技能锁不是线程安全的。技能选择与伤害计算之间存在竞争；
`cdqe` 把 0xFFFFFFFF 符号扩展成 -1（有符号），导致扣血时 HP 溢出。
见 [patterns-ctf-3.md](patterns-ctf-3.md#带符号整数溢出的线程竞争codegate-2017)。

<a id="esp32xtensa-firmware-reversing"></a>
### ESP32/Xtensa 固件逆向
IDA 不支持 —— 改用 radare2 + ESP-IDF ROM 链接脚本（`esp32.rom.ld`）做符号解析。
与公开的 ESP-IDF HTTP server 示例交叉比对以识别应用逻辑。
见 [patterns-ctf-3.md](patterns-ctf-3.md#借助-rom-符号表逆向-esp32xtensa-固件insomnihack-2017)。

<a id="custom-vm-bytecode-lifting-to-llvm-ir"></a>
### 自定义 VM 字节码提升到 LLVM IR
把自定义 VM 字节码转译成 LLVM IR，再用 `opt -O3` 化简（内联、常量折叠、死代码消除）。
可从 1300 行降到约 150 行，显出底层算法。
见 [tools-advanced.md](tools-advanced.md#自定义-vm-字节码提升到-llvm-ir-google-ctf-2017)。

<a id="sigfpe-signal-handler-side-channel"></a>
### SIGFPE 信号处理器侧信道
SIGFPE 信号处理器制造了静态分析看不见的隐式控制流。
用 `strace -e signal=SIGFPE` 统计每个候选字符的信号数 —— 正确字符会产生更多信号。
见 [anti-analysis-ctf.md](anti-analysis-ctf.md#通过-strace-计数利用-sigfpe-信号处理器侧信道plaidctf-2017)。

<a id="batch-crackme-automation-via-objdump"></a>
### 通过 objdump 批量自动化 crackme
结构性一致的批量 crackme（上百个二进制）：脚本化 `objdump` 提取 CMP 立即数与 add/sub 算术序列，
再用代数方法反推密钥，全程不执行。
见 [patterns-ctf-3.md](patterns-ctf-3.md#用-objdump-模式提取批量破解-crackmedef-con-2017)。

<a id="android-dex-runtime-bytecode-patching"></a>
### Android DEX 运行时字节码打补丁
原生 JNI 库通过 `/proc/self/maps` + `mprotect` + XOR 在内存中改写 Dalvik 字节码。
仅做 APK 静态分析不够 —— 需要从原生 `.so` 中提取 XOR 密钥与偏移，重建运行时 DEX。
见 [languages-platforms.md](languages-platforms.md#通过-procselfmaps-在运行时修补-android-dex-字节码-google-ctf-2017)。

<a id="fork--pipe--dead-branch-anti-analysis"></a>
### Fork + Pipe + 死分支反分析
fork/pipe 进程间通信：父进程写数据后退出，子进程读取并继续。
真正的校验藏在死分支里（恒假比较）。`strace` 能揭示 fork/pipe 模式；
修改比较常量即可到达隐藏代码。
见 [patterns-ctf-3.md](patterns-ctf-3.md#fork--管道--死分支反分析rctf-2017)。
