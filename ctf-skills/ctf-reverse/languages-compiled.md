# CTF Reverse - 编译型语言逆向（Go、Rust）

## 目录
- [Go 二进制逆向](#go-二进制逆向)
  - [识别](#识别)
  - [符号恢复](#符号恢复)
  - [Go 内存布局](#go-内存布局)
  - [Goroutine 与并发分析](#goroutine-与并发分析)
  - [反编译中常见的 Go 模式](#反编译中常见的-go-模式)
  - [Go 二进制逆向流程](#go-二进制逆向流程)
  - [Go 二进制 UUID 打补丁遍历 C2 客户端（BSidesSF 2026）](#go-二进制-uuid-打补丁遍历-c2-客户端bsidessf-2026)
- [Rust 二进制逆向](#rust-二进制逆向)
  - [Rust 识别](#rust-识别)
  - [符号反修饰](#符号反修饰)
  - [反编译中常见的 Rust 模式](#反编译中常见的-rust-模式)
  - [Rust 专用分析工具](#rust-专用分析工具)
  - [利用编译器 bug #25860 延长 Rust 生命周期（Hack.lu 2018）](#利用编译器-bug-25860-延长-rust-生命周期hacklu-2018)
  - [Rust #[no_mangle] 覆盖 libc 绕过 seccomp（Hack.lu 2018）](#rust-no_mangle-libc-override-for-seccomp-bypass-hacklu-2018)
  - [用 IDAPython 提取 Rust xmmword 常量（Insomnihack 2019）](#用-idapython-提取-rust-xmmword-常量insomnihack-2019)
- [Nuitka 编译的 Python — 模块桩注入（X-MAS CTF 2018）](#nuitka-编译的-python--模块桩注入x-mas-ctf-2018)
- [Swift 二进制逆向](#swift-二进制逆向)
- [Kotlin / JVM 二进制逆向](#kotlin--jvm-二进制逆向)
  - [JVM 字节码（Android/服务端）](#jvm-字节码android服务端)
  - [Kotlin/Native](#kotlinnative)
- [D 语言二进制逆向（CSAW CTF 2016）](#d-语言二进制逆向csaw-ctf-2016)
- [通过 STG 闭包与 hsdecomp 逆向 Haskell 二进制（hxp CTF 2017、Codegate 2018）](#通过-stg-闭包与-hsdecomp-逆向-haskell-二进制hxp-ctf-2017codegate-2018)
- [通过 GHC CMM 中间语言逆向 Haskell 二进制（N1CTF 2018）](#通过-ghc-cmm-中间语言逆向-haskell-二进制n1ctf-2018)
- [C++ 二进制逆向（速查）](#c-二进制逆向速查)
  - [vtable 重建](#vtable-重建)
  - [RTTI（运行时类型信息）](#rtti运行时类型信息)
  - [标准库模式](#标准库模式)

---

<a id="go-binary-reversing"></a>
## Go 二进制逆向

由于 Go 在 CLI 工具、网络服务和恶意软件中很流行，Go 二进制在 CTF 题目中越来越常见。

<a id="recognition"></a>
### 识别

```bash
# Detect Go binary
file binary | grep -i "go"
strings binary | grep "go.buildid"
strings binary | grep "runtime.gopanic"

# Go version embedded in binary
strings binary | grep "^go1\."
```

**关键特征：**
- 静态二进制体积很大（连 "hello world" 都约 2MB）
- 内嵌 `go.buildid` 字符串
- 存在 `runtime.*` 符号（即使去符号，也会残留一部分）
- 入口点是 `main.main`（不是 `main`）
- 出现 `GOROOT`、`GOPATH`、`/usr/local/go/src/` 之类的字符串

<a id="symbol-recovery"></a>
### 符号恢复

Go 即使在去符号的二进制中也保留丰富的类型与函数信息：

```bash
# GoReSym - recovers function names, types, interfaces from Go binaries
# https://github.com/mandiant/GoReSym
./GoReSym -d binary > symbols.json

# Parse output
python3 -c "
import json
with open('symbols.json') as f:
    data = json.load(f)
for fn in data.get('UserFunctions', []):
    print(f\"{fn['Start']:#x}  {fn['FullName']}\")
"
```

**搭配 golang-loader 使用 Ghidra：**
```bash
# Install: Ghidra → Window → Script Manager → search "golang"
# Recovers function names, string references, interface tables
```

**redress（Go 二进制分析）：**
```bash
# https://github.com/goretk/redress
redress -src binary         # Reconstruct source tree
redress -pkg binary         # List packages
redress -type binary        # List types and methods
redress -interface binary   # List interfaces
```

<a id="go-memory-layout"></a>
### Go 内存布局

在反编译中理解 Go 的数据结构：

```c
# String: {pointer, length} (16 bytes on 64-bit)
# NOT null-terminated! Length field is critical.
struct GoString {
    char *ptr;    // pointer to UTF-8 data
    int64 len;    // byte length
};

# Slice: {pointer, length, capacity} (24 bytes on 64-bit)
struct GoSlice {
    void *ptr;    // pointer to backing array
    int64 len;    // current length
    int64 cap;    // allocated capacity
};

# Interface: {type_descriptor, data_pointer} (16 bytes)
struct GoInterface {
    void *type;   // points to type metadata (itab for non-empty interface)
    void *data;   // points to actual value
};

# Map: pointer to runtime.hmap struct
# Channel: pointer to runtime.hchan struct
```

**在 Ghidra/IDA 中：** 看到一个函数接收 `(ptr, int64)`——多半是 Go 字符串。三字段 `(ptr, int64, int64)` 则是 slice。

<a id="goroutine-and-concurrency-analysis"></a>
### Goroutine 与并发分析

```bash
# Identify goroutine spawns in disassembly
strings binary | grep "runtime.newproc"
# newproc1 is the internal goroutine creation function

# In GDB with Go support:
gdb ./binary
(gdb) source /usr/local/go/src/runtime/runtime-gdb.py
(gdb) info goroutines          # List all goroutines
(gdb) goroutine 1 bt          # Backtrace for goroutine 1
```

**反汇编中的通道操作：**
- `runtime.chansend1` → `ch <- value`
- `runtime.chanrecv1` → `value = <-ch`
- `runtime.selectgo` → `select { case ... }`
- `runtime.closechan` → `close(ch)`

<a id="common-go-patterns-in-decompilation"></a>
### 反编译中常见的 Go 模式

**defer 机制：**
- `runtime.deferproc` → 注册延迟函数
- `runtime.deferreturn` → 在函数退出时执行延迟函数
- 延迟调用按 LIFO 顺序执行——对清理逻辑、加密密钥擦除有意义

**错误处理（`if err != nil` 模式）：**
```text
# In disassembly, this appears as:
# call some_function        → returns (result, error) as two values
# test rax, rax             → check if error (second return value) is nil
# jne error_handler
```

**字符串拼接：**
- `runtime.concatstrings` → `s1 + s2 + s3`
- `fmt.Sprintf` → 格式化构建字符串
- 在 `.rodata` 中查找格式串：`"%s%d"`、`"%x"`

**CTF 中常见的标准库模式：**
```go
// Crypto operations → look for these in strings/imports:
// "crypto/aes", "crypto/cipher", "crypto/sha256", "encoding/hex", "encoding/base64"

// Network operations:
// "net/http", "net.Dial", "bufio.NewReader"

// File operations:
// "os.Open", "io.ReadAll", "os.ReadFile"
```

<a id="go-binary-reversing-workflow"></a>
### Go 二进制逆向流程

```bash
1. file binary                          # Confirm Go, get arch
2. GoReSym -d binary > syms.json       # Recover symbols
3. strings binary | grep -i flag        # Quick win check
4. Load in Ghidra with golang-loader    # Apply recovered symbols
5. Find main.main                       # Entry point
6. Identify string comparisons          # GoString {ptr, len} pairs
7. Trace crypto operations              # crypto/* package usage
8. Check for embedded resources         # embed.FS in Go 1.16+
```

**Go embed.FS（Go 1.16+）：** 二进制可在编译期嵌入文件：
```bash
# Look for embedded file data
strings binary | grep "embed"
# Embedded files appear as raw data in the binary
# Search for known file signatures (PK for zip, PNG header, etc.)
```

**关键点：** Go 运行时即使在去符号的二进制中也内嵌大量元数据。先跑 GoReSym 再做人工分析——它通常能恢复 90%+ 的函数名，让反编译轻松许多。Go 字符串是 `{ptr, len}` 元组而非以 NUL 结尾——没有 golang-loader 插件时，Ghidra 默认的字符串分析会漏掉它们。

**检测：** 大型静态二进制（简单程序也有 2MB+）、`go.buildid`、`runtime.gopanic`、`/home/user/go/src/` 这类源码路径。

<a id="go-binary-uuid-patching-for-c2-client-enumeration-bsidessf-2026"></a>
### Go 二进制 UUID 打补丁遍历 C2 客户端（BSidesSF 2026）

**模式（see-two）：** 一个 Go 编译的 C2 客户端通过 `-ldflags -X` 内嵌了 UUID。C2 服务端用 mTLS 做认证。要枚举其他客户端及其文件，把 UUID 打补丁改掉，以新客户端身份注册，再用 C2 API 列出所有客户端并下载它们外传的文件。

**思路：**
1. 从 Go 构建信息中提取内嵌 UUID：`go version -m client_binary`
2. 二进制打补丁替换 UUID（简单字节替换——Go 字符串底层是定长数组）
3. 用打过补丁的二进制向 C2 服务端注册（mTLS 证书内嵌在程序中或在 distfiles 里）
4. 通过 API 枚举客户端：`GET /api/clients` 或遍历已知端点
5. 列出并下载每个客户端 GCS bucket 或文件存储中的文件
6. 在下载的文件中 grep flag

```bash
# Extract Go build info
go version -m ./client_binary | grep ldflags
# Output shows: -X main.clientUUID=<uuid>

# Patch UUID in binary (replace old UUID bytes with new UUID)
python3 -c "
import sys
data = open('client_binary', 'rb').read()
old_uuid = b'original-uuid-value-here'
new_uuid = b'attacker-uuid-value-here'
patched = data.replace(old_uuid, new_uuid)
open('client_patched', 'wb').write(patched)
"
chmod +x client_patched
./client_patched --register
```

**关键点：** Go 二进制把 `-ldflags -X` 传入的字符串值直接嵌入数据段。由于 Go 字符串是 `{ptr, len}` 且指向底层字节数组，只要替换后的 UUID 长度相同，补丁后的二进制依然有效。mTLS 证书只用于向服务端认证客户端，并没有绑定到特定 UUID。

**参考：** BSidesSF 2026 "see-two"

---

<a id="rust-binary-reversing"></a>
## Rust 二进制逆向

Rust 二进制在现代 CTF 中很常见，尤其是密码学、系统编程和安全工具类题目。

<a id="rust-recognition"></a>
### Rust 识别

```bash
# Detect Rust binary
strings binary | grep -c "rust"
strings binary | grep "rustc"             # Compiler version
strings binary | grep "/rustc/"           # Source paths
strings binary | grep "core::panicking"   # Panic infrastructure
```

**关键特征：**
- 字符串中出现 `core::panicking::panic`
- 以 `_ZN` 开头（Itanium ABI）的修饰符号——例如 `_ZN4main4main17h...`
- ELF 中存在 `.rustc` 节
- 引用 `/rustc/<commit_hash>/library/` 路径
- 二进制体积大（Rust 默认静态链接）

<a id="symbol-demangling"></a>
### 符号反修饰

```bash
# Rust uses Itanium ABI mangling (same as C++)
# rustfilt demangles Rust-specific symbols
cargo install rustfilt
nm binary | rustfilt | grep "main"

# Or use c++filt (works for most Rust symbols)
nm binary | c++filt | grep "main"

# In Ghidra: Window → Script Manager → search "Demangler"
# Enable "DemangleAllScript" for automatic demangling
```

<a id="common-rust-patterns-in-decompilation"></a>
### 反编译中常见的 Rust 模式

**Option/Result 枚举：**
```text
# Option<T> in memory: {discriminant (0=None, 1=Some), value}
# Result<T, E>: {discriminant (0=Ok, 1=Err), union{ok_val, err_val}}

# In disassembly:
# cmp byte [rbp-0x10], 0    → check if None/Err
# je handle_none_case
```

**Vec<T>（与 Go slice 相同）：**
```c
struct RustVec {
    void *ptr;      // heap pointer
    uint64 len;     // length
    uint64 cap;     // capacity
};
// NOTE: field order (ptr, len, cap) vs (ptr, cap, len) is NOT
// guaranteed by the Rust ABI and varies by compiler version —
// confirm against the Vec constructor and its callers in
// disassembly before trusting offsets.
```

**String / &str：**
```text
# String (owned): {ptr, length, capacity} — 24 bytes, heap-allocated
# (same caveat as Vec: field order is compiler-dependent, verify in disassembly)
# &str (borrowed): {ptr, length} — 16 bytes, can point anywhere

# In decompilation, look for:
# alloc::string::String::from    → String creation
# core::str::from_utf8           → byte slice to str
```

**迭代器链：**
```text
# .iter().map().filter().collect() compiles to loop fusion
# In disassembly: tight loop with inlined closures
# Look for: core::iter::adapters::map, filter, etc.
```

**Panic 展开：**
```bash
# Panic strings reveal source locations and error messages
strings binary | grep "panicked at"
strings binary | grep "called .unwrap().. on"
# These often contain file paths, line numbers, and variable names
```

<a id="rust-specific-analysis-tools"></a>
### Rust 专用分析工具

```bash
# cargo-bloat: analyze binary size by function
cargo install cargo-bloat
cargo bloat --release -n 50

# Ghidra Rust helper scripts
```

**关键点：** Rust 的 panic 信息是金矿——即使在 release 构建中，也包含源文件路径、行号和描述性错误字符串。第一件事永远是 `strings binary | grep "panicked"`。Rust 的单态化意味着泛型函数会按类型复制多份——预期会看到很多长得相似的函数。

**检测：** `core::panicking`、`.rustc` 节、`/rustc/` 路径、带 Rust 风格模块路径的 `_ZN` 修饰符号。

---

<a id="swift-binary-reversing"></a>
## Swift 二进制逆向

完整的 Swift 逆向指南（含符号反修饰、运行时结构、Ghidra 集成）见 [platforms.md](platforms.md#swift-二进制逆向)。以下是速查：

```bash
# Detect Swift binary
strings binary | grep "swift"
otool -l binary | grep "swift"

# Demangle Swift symbols
swift demangle 's14MyApp0A8ClassC10checkInput6resultSbSS_tF'
# → MyApp.MyAppClass.checkInput(result: String) -> Bool

# Key runtime functions: swift_allocObject, swift_release, swift_once
# String: small (≤15 bytes inline) or large (heap pointer + length)
# Protocol witness tables = dynamic dispatch (like vtables)
```

**检测：** Mach-O 中的 `__swift5_*` 节、`swift_` 运行时符号、修饰名中的 `s` 前缀。

---

<a id="kotlin--jvm-binary-reversing"></a>
## Kotlin / JVM 二进制逆向

Kotlin 可编译为 JVM 字节码，或经 Kotlin/Native 编译为原生代码。在 Android 和服务端 CTF 中常见。

<a id="jvm-bytecode-androidserver"></a>
### JVM 字节码（Android/服务端）

```bash
# Detect Kotlin
strings classes.dex | grep "kotlin"
# Look for: kotlin.Metadata annotation, kotlin/jvm/internal/*

# Decompile
jadx classes.dex                     # Best for Kotlin bytecode
cfr classes.jar --kotlin             # CFR with Kotlin mode
fernflower classes.jar output/       # IntelliJ's decompiler

# Kotlin-specific patterns in decompiled output:
# - Companion objects: ClassName$Companion
# - Data classes: copy(), component1(), component2(), toString()
# - Coroutines: ContinuationImpl, invokeSuspend, state machine
# - Null checks: Intrinsics.checkNotNull() everywhere
# - When expression: compiled as tableswitch/lookupswitch
# - Sealed classes: instanceof checks in chain
```

**反汇编中的 Kotlin 协程：**
```text
# Coroutines compile to state machines:
# invokeSuspend(result) {
#     switch (this.label) {
#         case 0: this.label = 1; return suspendFunction();
#         case 1: processResult(result); return Unit;
#     }
# }
# Each suspend point becomes a state in the switch.
# Follow the state machine to understand async flow.
```

<a id="kotlinnative"></a>
### Kotlin/Native

```bash
# Kotlin/Native produces platform binaries (no JVM)
# Recognize by: konan, kotlin.native strings
strings binary | grep "konan"

# Much harder to reverse — no reflection metadata
# Uses LLVM backend, looks similar to C/C++ in disassembly
# Key functions: InitRuntime, DeinitRuntime, CreateStablePointer
# Memory management: automatic reference counting (not GC)
```

**检测：** `kotlin.Metadata` 注解（JVM）、`konan` 字符串（Native）、`kotlin/` 包路径。

---

<a id="d-language-binary-reversing-csaw-ctf-2016"></a>
## D 语言二进制逆向（CSAW CTF 2016）

D 语言二进制有独特的符号修饰规则，与 C++ 不同。编译期模板实例化会产生大量函数变体。

```bash
# Recognition: D binaries use different mangling than C++
# Symbols contain "_D" prefix and numeric length-prefixed names
# Example: _D4mainQaFNaNbNfZv

# Symbol demangling:
# GDB: set language d
# Radare2: export names show demangled D symbols
# Online: dlang.org/phobos/core_demangle.html

# Common D binary patterns:
# - Templates instantiated at compile-time: enc!("111"), enc!("222"), ...
# - Garbage collector references (GC.malloc, GC.free)
# - Phobos standard library functions (_D3std...)
# - String processing: std.string, std.conv.to

# Reversing a D cipher (XOR with cycling key):
def reverse_d_cipher(encrypted, num_functions=500):
    """D binaries may chain multiple transformation functions.
    Each function XORs with key character, then XORs with key length.
    Process in reverse order."""
    result = encrypted[:]
    for i in range(num_functions - 1, -1, -1):
        key = str(i) * 3  # e.g., "499499499" for function enc!("499")
        key_len = len(key)
        for j in range(len(result)):
            result[j] ^= key_len
            result[j] ^= ord(key[j % key_len])
    return bytes(result)
```

**关键点：** D 语言二进制在 CTF 中很罕见，但可通过 `_D` 符号前缀和 Phobos 库引用识别。编译期模板系统意味着同一函数可能按不同参数复制出上百份——留意 `enc!("N")` 这类模式，其中 N 各不相同。

---

<a id="haskell-binary-reversing-via-stg-closures-and-hsdecomp-hxp-ctf-2017-codegate-2018"></a>
### 通过 STG 闭包与 hsdecomp 逆向 Haskell 二进制（hxp CTF 2017、Codegate 2018）

GHC 编译的 Haskell 二进制采用 STG（Spineless Tagless G-machine）执行模型，由于惰性求值、闭包和 thunk，逆向难度极高。STG 机器把一切变成闭包调用，而不是直接函数调用。

**识别：**
- 共享库：`libHSbase-*`、`libHSrts-*`
- 入口符号：`hs_main`（取代标准的 `main`）
- 修饰符号使用 Z 编码：`z` = 前缀、`Z` = 大写、`zd` = `.`、`zi` = `$`
- GHC 调用约定的寄存器映射：`rbx` = R1，`r14` = R2

**闭包结构：**
闭包是结构体，其第一个 qword 指向 info table/代码。info table 位于代码指针之前，包含元数据（闭包类型、布局信息、SRT）。

```bash
# Identify Haskell binary
ldd ./binary | grep libHS
readelf -s ./binary | grep hs_main

# Decompile with hsdecomp (github.com/gereeter/hsdecomp)
# Recovers closure structure and pattern matching into pseudo-Haskell
python2 hsdecomp ./binary

# Compile reference for monkey-patching
ghc -O0 reference.hs -o reference
objcopy --dump-section .text=main_code reference
```

**猴子补丁手法：**
当反编译失败或闭包不可读时，用同一 GHC 版本编译一个最小的 Haskell 程序，取出编译后的 `Main_main_info` 闭包代码，补进题目二进制。这样，把主入口替换成已知的求值器，就能强制求值隐藏的闭包并打印其结果。

```haskell
-- reference.hs: minimal program that evaluates and prints the target closure
module Main where
main :: IO ()
main = print targetClosure  -- replace with the closure you want to evaluate
```

**关键点：** Haskell 二进制因惰性求值、闭包与 thunk 而极难逆向。STG 机器把一切变成闭包调用而非直接函数调用。`hsdecomp` 能恢复闭包结构与模式匹配。反编译失败时，用参考二进制中已知的 `Main_main_info` 做猴子补丁，可强制求值隐藏闭包并打印结果。

**检测：** `libHSbase-*` 共享库、`hs_main` 入口、Z 编码符号（如 `MainZCmain`）、GHC 版本字符串。

**参考：** hxp CTF 2017、Codegate 2018

---

<a id="haskell-binary-re-via-ghc-cmm-intermediate-language-n1ctf-2018"></a>
### 通过 GHC CMM 中间语言逆向 Haskell 二进制（N1CTF 2018）

由于 STG 执行模型，用 IDA 反编译 GHC 编译的 Haskell 二进制几乎不可能。当能拿到或能恢复 `.cmm`（C-- 中间语言）文件时，读它来理解 thunk、闭包与惰性求值语义。对于指数级增长的递归结构，用记忆化计算各段长度，再二分查找，而不是真正把整个字符串构造出来。

**模式：** 二进制构造递归字符串结构 `f(n) = s1 + f(n-1) + s2 + f(n-1) + s3`。直接求值在时间和空间上都是 `O(2^n)`。改为用记忆化计算每层递归的长度，再按段边界二分查找目标字符下标。

```python
# Haskell recursive string: f(n) = s1 + f(n-1) + s2 + f(n-1) + s3
# Direct evaluation is O(2^n) -- use size memoization:
from functools import lru_cache

@lru_cache(maxsize=None)
def fsize(n):
    if n == 0: return len(s0)
    return len(s1) + fsize(n-1) + len(s2) + fsize(n-1) + len(s3)

def char_at(n, offset):
    if n == 0: return s0[offset]
    if offset < len(s1): return s1[offset]
    offset -= len(s1)
    if offset < fsize(n-1): return char_at(n-1, offset)
    offset -= fsize(n-1)
    if offset < len(s2): return s2[offset]
    offset -= len(s2)
    return char_at(n-1, offset)
```

**关键点：** GHC 的 CMM（C minus minus）中间表示保留了足够多的结构信息来识别算法。对每层长度翻倍的递归字符串构造，用记忆化算各段长度并二分查找目标下标，而不是把指数级增长的字符串实际展开。

**检测：** Haskell 二进制（识别方法见上）且题目附件中包含 `.cmm` 文件。留意产生指数级增长字符串类数据的递归闭包调用。

**参考：** N1CTF 2018

---

<a id="c-binary-reversing-quick-reference"></a>
## C++ 二进制逆向（速查）

C++ 逆向的通用工具已很成熟，以下是与 CTF 特别相关的模式：

<a id="vtable-reconstruction"></a>
### vtable 重建

```text
# Virtual function tables (vtables):
# First 8 bytes of object → pointer to vtable
# vtable entries: [typeinfo_ptr, destructor, method1, method2, ...]
# In Ghidra: Data → Create Pointer at vtable address

# Identify polymorphic dispatch:
# mov rax, [rdi]           # Load vtable from this pointer
# call [rax + 0x18]        # Call 4th virtual method (0x18/8 = 3rd after typeinfo+dtor)
```

<a id="rtti-run-time-type-information"></a>
### RTTI（运行时类型信息）

```bash
# If not stripped, RTTI reveals class hierarchy
strings binary | grep -E "^[0-9]+[A-Z]"   # Mangled type names
c++filt _ZTI7MyClass                        # → typeinfo for MyClass

# In Ghidra: search for vtable references, follow typeinfo pointer
# typeinfo struct: {vtable_for_typeinfo, name_string, base_class_ptr}
```

<a id="standard-library-patterns"></a>
### 标准库模式

```text
std::string (libstdc++):
  SSO (Small String Optimization): inline buffer for ≤15 chars
  Layout: {char* ptr, size_t size, union{size_t cap, char buf[16]}}

std::vector<T>:
  {T* begin, T* end, T* capacity_end}

std::map<K,V>:
  Red-black tree: each node has {left, right, parent, color, key, value}

std::unordered_map<K,V>:
  Hash table: {bucket_array, size, load_factor_max, ...}
```

---

<a id="rust-lifetime-escape-via-compiler-bug-25860-hacklu-2018"></a>
### 利用编译器 bug #25860 延长 Rust 生命周期（Hack.lu 2018）

**模式：** Rust 编译器 bug rust-lang/rust#25860——高阶生命周期变异的检查有误，导致闭包可以“重借用”引用，并不可靠地把它延长到 `'static`。在一个只运行安全代码（无 `unsafe` 块）的纯 Rust 沙箱中，该 bug 可提供 UAF 原语：把 `Vec<u8>` 的堆缓冲区按 `(usize, usize, usize)` 元组别名解释，进而越界读写。

```rust
// Triggering pattern — safe Rust only
fn extend<'a, 'b, T>(_: &'a &'b (), v: &'b T) -> &'a T { v }

fn bad<T>(v: T) -> &'static T {
    // Closure infers 'a = 'static because of the variance bug
    let f: fn(&'_ &'_ (), &'_ T) -> &'_ T = extend;
    f(&&(), &v) // returned ref now outlives v
}

fn main() {
    let aliased: &'static Vec<u8> = bad(vec![1u8, 2, 3]);
    // Reinterpret the Vec as its raw header (field order is
    // compiler-dependent — NOT guaranteed by the Rust ABI;
    // confirm against the constructor/callers for this toolchain)
    let header: &(usize, usize, usize) =
        unsafe { std::mem::transmute(aliased) };
    println!("ptr={:#x} len={} cap={}", header.0, header.1, header.2);
}
```

**关键点：** 借用检查器中的一个健全性 bug，就能把沙箱化的 Rust playground 变成任意读写原语——无需 `unsafe`。当 Rust 题目禁用 `unsafe` 并锁定特定编译器版本时，去 rust-lang 的 issue tracker 里搜该版本之后修复的 `soundness` bug：每一个都是可利用候选。只有在拿到被延长生命周期的引用之后，才能用 `std::mem::transmute` 复现这类漏洞；构造别名才是难点。

**参考：** Hack.lu CTF 2018 — Rusty CodePad，writeup 11859

---

<a id="rust-no_mangle-libc-override-for-seccomp-bypass-hacklu-2018"></a>
### Rust #[no_mangle] 覆盖 libc 绕过 seccomp（Hack.lu 2018）

**模式：** 沙箱化的 Rust 二进制在 `main` 早期调用 `prctl(PR_SET_SECCOMP, ...)`，然后进入用户代码。由于被沙箱的 crate 与 libc *静态链接*在一起，定义一个 `extern "C"` 且带 `#[no_mangle]` 的 `prctl` 函数会在链接期遮蔽 libc 的符号。让覆盖函数返回 `0` 就等于禁用了 seccomp，攻击者代码中所有系统调用都能用了。

```rust
// User-supplied code — linked into the same binary as the sandbox harness
#[no_mangle]
pub extern "C" fn prctl(_a: i64, _b: i64) -> i64 {
    0 // pretend success, do not install any filter
}

// When main() calls prctl(PR_SET_SECCOMP, ...) it hits our override
fn main() {
    // The real program runs without seccomp filtering
}
```

**关键点：** Rust 默认静态链接，因此 `extern "C"` + `#[no_mangle]` 实质上相当于编译期的动态钩子——沙箱框架调用的任何 libc 符号（`prctl`、`chroot`、`seteuid`、`read`）都能被随同一二进制一起链接的攻击者 crate 代码重定义。防御方式：把系统调用改为直接走 `libc::syscall(SYS_prctl, ...)`（绕过符号表），或使用 `-Wl,-Bsymbolic` 优先采用预期的定义。

**参考：** Hack.lu CTF 2018 — Rusty CodePad seccomp 变种，writeup 11864

<a id="rust-xmmword-constant-extraction-via-idapython-insomnihack-2019"></a>
### 用 IDAPython 提取 Rust xmmword 常量（Insomnihack 2019）

**模式：** Rust 会把字面量字节缓冲区（期望的 flag 值、XOR 表）以 16 字节 xmmword 常量形式存放在 `.rodata`。IDA 将其显示为 `xmmword_xxxx` 记号。用 IDAPython 遍历 `.rodata` 范围，读取每个 xmmword，逆向简单混淆（例如 `(dword >> 2) ^ 0xA`），导出明文。

```python
import idc, idaapi
start, end = 0x4A1000, 0x4A1100
for ea in range(start, end, 4):
    d = idc.get_wide_dword(ea)
    print(chr((d >> 2) ^ 0xA), end='')
```

**关键点：** Rust 二进制难以反编译，但扫描字面量数据非常容易。任何 `input == const_buf` 形式的校验都会把期望值原样留在 `.rodata` 中。grep `mov reg, xmmword [rip+offset]` 找到对应槽位，直接导出即可。

**参考：** Insomnihack teaser 2019 — beginner_reverse，writeup 12910

---

<a id="nuitka-compiled-python--module-stub-injection-x-mas-ctf-2018"></a>
## Nuitka 编译的 Python — 模块桩注入（X-MAS CTF 2018）

**模式：** Nuitka 把 Python 源码编译成单体原生二进制，但运行时仍使用标准的 Python 导入机制。在运行二进制前，把假的 `base64.py` / `midi.py` / `whatever_module.py` 放到当前工作目录；模块系统会优先加载 CWD，于是你的桩替换掉内嵌实现。记录每次属性访问，逐步拼出该二进制所用的 API 影子实现。

```python
# base64.py next to the binary
class _Trace:
    def __getattr__(self, name):
        def f(*a, **k):
            print(f'base64.{name}({a!r}, {k!r})')
            return b''
        return f
import sys; sys.modules[__name__] = _Trace()
```

运行 `./target_bin`；打印出的调用序列就能揭示算法，无需反编译 Nuitka 的输出。

**关键点：** 任何仍在运行时通过 `sys.path` 解析模块名的方案（Nuitka、带 `--onefile` 的 PyInstaller、关闭 `--bundle_files=1` 的 Py2Exe、冻结的 CPython），都能被 CWD 中的桩在导入期劫持。先从 `strings` 输出中 grep 模块名，挑选合适的钩子目标。

**参考：** X-MAS CTF 2018 — A Christmas Carol，writeup 12667
