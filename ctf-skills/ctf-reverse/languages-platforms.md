# CTF Reverse - 平台与框架相关技巧

## 目录
- [Roblox Place 文件分析](#roblox-place-文件分析)
- [Godot 游戏资源提取](#godot-游戏资源提取)
- [Rust serde_json 结构恢复](#rust-serde_json-结构恢复)
- [Android JNI RegisterNatives 混淆 (HTB WonderSMS)](#android-jni-registernatives-混淆-htb-wondersms)
- [通过 /proc/self/maps 在运行时修补 Android DEX 字节码 (Google CTF 2017)](#通过-procselfmaps-在运行时修补-android-dex-字节码-google-ctf-2017)
- [在新工程中绕过 Android 原生 .so 加载 (Codegate CTF 2018)](#在新工程中绕过-android-原生-so-加载-codegate-ctf-2018)
- [Frida 绕过 Firebase Cloud Functions (BSidesSF 2026)](#frida-绕过-firebase-cloud-functions-bsidessf-2026)
- [Verilog/硬件逆向 (srdnlenCTF 2026)](#verilog硬件逆向-srdnlenctf-2026)
- [逐前缀哈希反推 (Nullcon 2026)](#逐前缀哈希反推-nullcon-2026)
- [Ruby/Perl 多语言同源约束求解 (BearCatCTF 2026)](#rubyperl-多语言同源约束求解-bearcatctf-2026)
- [Electron 应用 + 原生二进制逆向 (RootAccess2026)](#electron-应用--原生二进制逆向-rootaccess2026)
- [Node.js npm 包运行时内省 (RootAccess2026)](#nodejs-npm-包运行时内省-rootaccess2026)
- [Frida 绕过 Android 证书固定 (h1702ctf 2017)](#frida-绕过-android-证书固定-h1702ctf-2017)
- [Android 反调试：TracerPid、su 二进制、系统属性 (h1702ctf 2017)](#android-反调试tracerpidsu-二进制系统属性-h1702ctf-2017)
- [基于 Android 日志的密钥提取 (HackIT 2017)](#基于-android-日志的密钥提取-hackit-2017)
- [内存 dump + smali 补丁提取原生 JNI 密钥 (HackIT 2017)](#内存-dump--smali-补丁提取原生-jni-密钥-hackit-2017)
- [IBM AS/400 SAVF 文件 EBCDIC 解码 (EKOPARTY 2017)](#ibm-as400-savf-文件-ebcdic-解码-ekoparty-2017)
- [Intel SGX Enclave 逆向 (Pwn2Win 2017)](#intel-sgx-enclave-逆向-pwn2win-2017)
- [Glulx 互动小说字节码矩阵校验 (PlaidCTF 2018)](#glulx-互动小说字节码矩阵校验-plaidctf-2018)
- [用 Smali 注入击败 LocalBroadcastManager (TAMUctf 2019)](#用-smali-注入击败-localbroadcastmanager-tamuctf-2019)

关于核心语言逆向（Python、BF/深奥语言、DOS、Unity、OPAL），见 [languages.md](languages.md)。
关于 Go 与 Rust 二进制逆向，见 [languages-compiled.md](languages-compiled.md)。

---

<a id="roblox-place-file-analysis"></a>
## Roblox Place 文件分析

**模式（MazeRunna, 0xFun 2026）：** Roblox 游戏的 flag 藏在旧版本中，最新版本只放诱饵。

**通过 Asset Delivery API 查版本历史：**
```bash
# Extract placeId and universeId from game page HTML
# Query each version (requires .ROBLOSECURITY cookie):
curl -H "Cookie: .ROBLOSECURITY=..." \
  "https://assetdelivery.roblox.com/v2/assetId/{placeId}/version/1"
# Download location URL → place_v1.rbxlbin
```

**二进制格式解析：** `.rbxlbin` 文件由若干区块（chunk）组成：
- **INST** —— 类分桶与引用 ID
- **PROP** —— 每个实例的字段（包括 `Script.Source`）
- **PRNT** —— 父子关系（对象树）

解码各区块的载荷，遍历 PROP 条目中的 `Source` 字段，逐版本导出 `Script.Source` / `LocalScript.Source`，再做差异对比。

**核心经验：** 永远检查版本历史。最新版本可能只含诱饵 flag，真 flag 在旧版本里。要跨版本对比脚本源码。

---

<a id="godot-game-asset-extraction"></a>
## Godot 游戏资源提取

**模式（Steal the Xmas）：** 加密的 Godot `.pck` 包。

**工具：**
- [gdsdecomp](https://github.com/GDRETools/gdsdecomp) —— 提取 Godot 包
- [KeyDot](https://github.com/Titoot/KeyDot) —— 从 Godot 可执行文件中提取加密密钥

**流程：**
1. 对游戏可执行文件运行 KeyDot → 提取加密密钥
2. 把密钥填入 gdsdecomp
3. 提取并用 Godot 编辑器打开工程
4. 在脚本/资源中搜索 flag 数据

---

<a id="rust-serde_json-schema-recovery"></a>
## Rust serde_json 结构恢复

**模式（Curly Crab, PascalCTF 2026）：** Rust 二进制从 stdin 读取 JSON，通过 serde_json 反序列化，然后打印成功/失败表情。

**方法：**
1. 反汇编 serde 生成的 `Visitor` 实现
2. 每个 visitor 的 `visit_map` / `visit_seq` 会暴露期望的键与类型
3. 在反序列化代码中寻找字符串字面量（字段名如 `"pascal"`、`"CTF"`）
4. 依 visitor 调用层级重建嵌套 JSON 结构
5. 从 visitor 方法名判断值类型：`visit_str` = 字符串，`visit_u64` = 数字，`visit_bool` = 布尔，`visit_seq` = 数组

```json
{"pascal":"CTF","CTF":2026,"crab":{"I_":true,"cr4bs":1337,"crabby":{"l0v3_":["rust"],"r3vv1ng_":42}}}
```

**关键点：** flag 就是按结构顺序把这些 JSON 键拼接起来。按顺序读出字段名即得 flag。

---

<a id="android-jni-registernatives-obfuscation-htb-wondersms"></a>
## Android JNI RegisterNatives 混淆 (HTB WonderSMS)

**模式：** Android 应用用 `System.loadLibrary()` 加载原生库，但在 `JNI_OnLoad` 里使用 `RegisterNatives`，而不是标准的 JNI 命名约定（`Java_com_pkg_Class_method`）。这样就隐藏了每个 Java native 方法实际由哪个 C++ 函数处理。

**识别：**
```java
// In decompiled Java (jadx):
static { System.loadLibrary("audio"); }
private final native ProcessedMessage processMessage(SmsMessage msg);
```
标准 JNI 会有符号 `Java_com_rloura_wondersms_SmsReceiver_processMessage`。如果 `.so` 中没有该符号，说明使用了 `RegisterNatives`。

**在 Ghidra 中定位真正的 handler：**
1. 找到 `JNI_OnLoad`（导出符号，必定存在）
2. 追踪到 `RegisterNatives(env, clazz, methods, count)` 调用
3. `methods` 数组中是 `{name, signature, fnPtr}` 结构
4. 顺着 `fnPtr` 找到真正的原生函数

```c
// JNI_OnLoad registers functions manually:
static JNINativeMethod methods[] = {
    {"processMessage", "(Landroid/telephony/SmsMessage;)LProcessedMessage;", (void*)real_handler}
};
(*env)->RegisterNatives(env, clazz, methods, 1);
```

**分析时选择架构：**
```bash
# x86_64 gives best Ghidra decompilation (most similar to desktop code)
# Extract from APK:
unzip WonderSMS.apk -d extracted/
ls extracted/lib/x86_64/  # Prefer this over arm64-v8a for static analysis
```

**关键点：** `RegisterNatives` 是一种刻意的混淆手法 —— 它让 Java 方法名与原生符号名解耦，因此仅靠字符串搜索找不到 handler。逆向符号已被剥离的 Android 原生库时，务必先看 `JNI_OnLoad`。

**识别：** Java 中声明了 native 方法 + `.so` 中没有对应的 JNI 符号 + 存在 `JNI_OnLoad`。这类库通常已被 strip（无调试符号）。

---

<a id="android-dex-runtime-bytecode-patching-via-procselfmaps-google-ctf-2017"></a>
## 通过 /proc/self/maps 在运行时修补 Android DEX 字节码 (Google CTF 2017)

原生 JNI 库在运行时修改内存中的 Dalvik 字节码：读取 `/proc/self/maps` 找到已加载的 DEX，用 `mprotect` 改为可写，然后按偏移对特定字节码做 XOR 修补。

```python
# Reconstruct the patched DEX offline:
# 1. Extract the embedded DEX from the APK
# 2. Find the XOR key and patch offsets in the native .so (IDA/Ghidra)
# 3. Apply the same patches to the static DEX
import struct

with open('classes.dex', 'rb') as f:
    dex = bytearray(f.read())

# Patch 144 bytes starting at offset found in .so
xor_key = 0x5A
for i in range(patch_offset, patch_offset + 144):
    dex[i] ^= xor_key

# 4. Recompute DEX checksum and SHA-1 hash
# 5. Decompile with jadx or baksmali
```

**关键点：** 原生库可以通过 `/proc/self/maps` + `mprotect` 修改内存中的 DEX 字节码，仅对 APK 做静态分析是不够的。必须从原生 `.so` 中提取 XOR 密钥和补丁偏移，才能重建运行时真正的 DEX。此手法只适用于 Dalvik（API < 21），不适用于 ART。

---

<a id="android-native-so-loading-bypass-in-new-project-codegate-ctf-2018"></a>
### 在新工程中绕过 Android 原生 .so 加载 (Codegate CTF 2018)

**模式：** 与其逆向复杂的 JNI 校验逻辑，不如新建一个 Android Studio 工程，使用相同的包名、类名和 native 方法签名，加载原始 `.so` 并直接调用原生函数，从而完全绕过所有 Java 层检查（随机数校验、PIN 输入、root 检测等）。

```java
// Create new project with same package: com.example.puing.a2018codegate
package com.example.puing.a2018codegate;
public class Main4Activity extends AppCompatActivity {
    static { System.loadLibrary("hello-libs"); }
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String flag = stringFromJNI();  // call native directly, skip all Java validation
        Log.d("FLAG", flag);
    }
    public native String stringFromJNI();
}
```

**关键点：** JNI 函数名编码了包路径与类名。新建一个包名/类名/方法名都匹配的 Android 工程，引入原始 `.so`，直接调用原生函数即可。所有 Java 层校验（随机检查、PIN 输入、root 检测）都被整体绕过。

**识别：** APK 带有原生 `.so` 库，flag 或机密在原生代码中计算后返回给 Java。Java 层在调用 native 方法之前有多道校验门（EditText 检查、随机数比较、设备检查）。

**参考：** Codegate CTF 2018

---

<a id="frida-firebase-cloud-functions-bypass-bsidessf-2026"></a>
## Frida 绕过 Firebase Cloud Functions (BSidesSF 2026)

**模式（vinyl-drop, doremi）：** Android 应用通过 Firebase Cloud Functions 校验操作（二维码、购买）。期望的载荷格式包含 Firebase UID、一个数值和时间戳。用 Frida 在登录后 hook 应用，构造合法载荷并直接调用 Cloud Function。

```javascript
// Frida hook to bypass QR validation
Java.perform(function() {
    var FirebaseFunctions = Java.use('com.google.firebase.functions.FirebaseFunctions');
    var FirebaseAuth = Java.use('com.google.firebase.auth.FirebaseAuth');

    // Get current user UID after login
    var auth = FirebaseAuth.getInstance();
    var uid = auth.getCurrentUser().getUid();

    // Construct valid payload: uid + amount + timestamp
    var unixMs = Java.use('java.lang.System').currentTimeMillis();
    var payload = uid + "+100+" + unixMs;

    // Call the Cloud Function directly
    var functions = FirebaseFunctions.getInstance();
    var data = Java.use('java.util.HashMap').$new();
    data.put("payload", payload);
    functions.getHttpsCallable("validateScanPayload").call(data);
});
```

**关键点：** Firebase AppCheck 与 Cloud Functions 依赖客户端来构造合法载荷。登录之后，Frida 可以 hook 应用，用任意参数调用任何 Cloud Function，从而绕过客户端校验（二维码扫描、支付处理等）。

**识别时机：** Android 应用含 `google-services.json`、`build.gradle` 中有 Firebase 依赖、反编译代码中出现 Cloud Function 调用。

**参考：** BSidesSF 2026 "vinyl-drop"

---

<a id="veriloghardware-reverse-engineering-srdnlenctf-2026"></a>
## Verilog/硬件逆向 (srdnlenCTF 2026)

**模式（Rev Juice）：** 自动售货机的 Verilog HDL 源码，需要特定的投币与选择序列才能解锁隐藏商品。

**方法：**
1. 分析 Verilog 模块，理解状态机与历史追踪
2. 找出隐藏条件（例如只有当 `COINS_HISTORY` 数组在特定抽头上取特定值时，商品 8 才可用）
3. 为每种动作类型建立时序模型（每个操作耗时多少时钟周期）
4. 从所需的历史值倒推，构造正确的输入序列

**构建时序模型：**
```python
# Map each action to its cycle count (determined from Verilog state machines)
TIMING = {
    "insert_coin": 3,       # 3 cycles per coin insertion
    "select_success": 7,    # 7 cycles for successful product selection
    "select_fail": 5,       # 5 cycles for failed selection attempt
    "cancel_with_coins": 4, # 4 cycles for cancel when coins > 0
    "cancel_at_zero": 2,    # 2 cycles for cancel when coins = 0
}

# COINS_HISTORY is a shift register updated each cycle
# History tap requirements (from Verilog conditions):
# H[0]=1, H[7]=4, H[28]=H[33]=H[38]=6
# H[63]=H[73]=2, H[80]=9
# (H[19]+H[21]+H[56]+H[69]) mod 32 = 0
```

**关键点：** 硬件题需要理解精确的时序模型 —— 每个操作占用确定的时钟周期数，移位寄存器在固定抽头位置记录历史。从所需的抽头值倒推每个周期必须发生什么动作。答案通常是一种特定的序列记号（例如 `I9C_SP6_CNL_I2C_SP2_I6C_SP6_SP6_SP5_CNL_I4C_SP1`）。

**识别：** 寻找 `.v` 或 `.sv`（Verilog/SystemVerilog）文件、`always @(posedge clk)` 块、移位寄存器模式，以及带历史值门控条件的 `case` 状态机。

---

<a id="prefix-by-prefix-hash-reversal-nullcon-2026"></a>
## 逐前缀哈希反推 (Nullcon 2026)

完整技术见 [patterns-ctf-2.md](patterns-ctf-2.md#前缀哈希爆破-nullcon-2026)。本节只补充语言相关的注意点。

**语言相关注意点：**
- 哈希算法可能很冷门（MD2、自定义）—— 不需要识别它，运行二进制比对输出即可
- 用 `subprocess.run()` 并设置 `timeout=2`，以应对坏输入导致挂死的二进制
- 对 strip 过的二进制，检查 `ltrace` 是否能暴露哈希函数名（例如 `MD2_Update`）

---

<a id="rubyperl-polyglot-constraint-satisfaction-bearcatctf-2026"></a>
## Ruby/Perl 多语言同源约束求解 (BearCatCTF 2026)

**模式（Polly's Key）：** 一个文件同时在 Ruby 和 Perl 下合法。两种语言对 50 字符密钥施加不同的校验约束。同时满足两者即可解密 flag。

**多语言同源结构利用：**
- Ruby：`=begin`...`=end` 是块注释
- Perl：`=begin`...`=cut` 是 POD（Plain Old Documentation），`=end` 会被忽略
- 基于注释块边界，两种语言执行不同的代码

**典型约束：**
- **Ruby：** 字符集必须满足某个数学性质（例如除 `^` 外的所有 50 个可打印 ASCII 字符各使用一次，且每个都满足 `XOR(val, (val-16) % 257)` 是模 257 的原根）
- **Perl：** 通过插入排序的逆序数施加顺序约束（硬编码的逆序表决定确切的排列）

**解题思路：**
1. 先确定合法的字符集（来自其中一种语言的数学约束）
2. 再用顺序约束（来自另一种语言）确定确切排列
3. 计算密钥哈希（例如 MD5）并解密

```python
# Determine character ordering from inversion counts
def reconstruct_from_inversions(chars, inv_counts):
    result = []
    remaining = sorted(chars)
    for i in range(len(chars) - 1, -1, -1):
        # inv_counts[i] = number of elements to the left that are greater
        idx = inv_counts[i]
        result.insert(idx, remaining.pop(i))
    return result
```

**关键点：** 多语言同源文件利用各语言特有的注释/块语法，在每个解释器中执行不同代码。两种语言给出的约束取交集就能唯一确定密钥。用两个解释器分别运行该文件并对比行为，即可判断哪段代码在哪种语言下生效。

**识别：** 文件可在多个解释器下运行（`ruby file && perl file`）。题目提到 "polyglot"，或提供了一个 `.rb` 结尾但看起来也像 Perl 的文件。

---

<a id="electron-app--native-binary-reversing-rootaccess2026"></a>
## Electron 应用 + 原生二进制逆向 (RootAccess2026)

**模式（Rootium Browser）：** Electron 桌面应用内置一个原生 ELF/DLL 二进制来处理敏感操作（保险库、加密、认证）。Electron 层只是包装，真正的 flag 逻辑在原生二进制中。

**提取流程：**
1. **解包 Electron ASAR 归档：**
```bash
# Install ASAR tool
npm install -g @electron/asar

# Extract the app.asar archive
asar extract resources/app.asar app_extracted/
ls app_extracted/
```

2. **定位原生二进制：** 搜索 JavaScript 中调用的 ELF/DLL 文件：
```bash
# Find native binaries
find app_extracted/ -name "*.node" -o -name "*.so" -o -name "*vault*" -o -name "*auth*"

# Check JS for child_process.spawn or ffi-napi calls
grep -r "spawn\|execFile\|ffi\|require.*native" app_extracted/
```

3. **逆向原生二进制**（XOR + 循环移位密码示例）：
```python
def decrypt_password(encrypted_bytes, key):
    """Common pattern: XOR with constant + bit rotation + key XOR."""
    result = []
    for i, byte in enumerate(encrypted_bytes):
        decrypted = ((byte ^ 0x42) >> 3) ^ key[i % len(key)]
        result.append(chr(decrypted))
    return ''.join(result)

def decrypt_flag(encrypted_flag, password):
    """Flag uses password as key with position-dependent rotation."""
    result = []
    for i, byte in enumerate(encrypted_flag):
        key_byte = ord(password[i % len(password)])
        decrypted = ((byte ^ 0x7E) >> (i % 8)) ^ key_byte
        result.append(chr(decrypted))
    return ''.join(result)
```

**关键点：** Electron 应用本质是 JavaScript 包裹原生代码。先用 `asar` 提取，然后集中分析原生二进制。JS 层往往明文包含口令校验流程，能提示原生二进制期望什么。注意查看 ELF 的 `.data` 或 `.rodata` 段中的加密数据。

**识别：** `resources/` 目录下有 `.asar` 文件、Electron 框架文件、`package.json` 中带 electron 依赖。

---

<a id="nodejs-npm-package-runtime-introspection-rootaccess2026"></a>
## Node.js npm 包运行时内省 (RootAccess2026)

**模式（RootAccess CLI）：** 混淆的 npm 包，使用 RC4 编码、控制流平坦化，flag 被拆分到多个片段。静态分析不现实 —— 改用运行时内省。

**动态分析思路：**
```javascript
#!/usr/bin/env node

// 1. Load obfuscated modules
const cryptoMod = require('target-package/dist/lib/crypto.js');
const vaultMod = require('target-package/dist/lib/vault.js');

// 2. Enumerate all exported properties
for (const mod of [cryptoMod, vaultMod]) {
    for (const key of Object.keys(mod)) {
        const obj = mod[key];
        console.log(`Export: ${key}`);
        // List all methods including hidden ones
        const props = Object.getOwnPropertyNames(obj);
        const proto = Object.getOwnPropertyNames(obj.prototype || {});
        console.log('  Own:', props);
        console.log('  Proto:', proto);
    }
}

// 3. Extract flag fragments
const Engine = cryptoMod.CryptoEngine;
const total = Engine.getTotalFragments();
let flag = '';
for (let i = 1; i <= total; i++) {
    flag += Engine.getFragment(i);
}
console.log('Flag:', flag);

// 4. Check for hidden methods (common: __getFullFlag__, _debug, _raw)
const hidden = Object.getOwnPropertyNames(Engine)
    .filter(p => p.startsWith('__') || p.startsWith('_'));
console.log('Hidden methods:', hidden);
```

**关键点：** 重度混淆的 JavaScript（控制流平坦化、RC4 字符串编码、死代码）会让静态分析慢到不可接受。用 `Object.getOwnPropertyNames()` 做运行时内省，能列出所有方法（包括隐藏的）。模块加载时自身的解密逻辑会自动执行 —— 直接调用解码后的函数即可。

**识别：** npm 包的 `dist/` 目录经过了压缩/混淆，题目说"逆向这个 CLI 工具"，`package.json` 中有自定义命令。

---

<a id="frida-android-certificate-pinning-bypass-h1702ctf-2017"></a>
## Frida 绕过 Android 证书固定 (h1702ctf 2017)

APK 使用 OkHttp 的 `CertificatePinner` 做 SSL 证书固定。与其搭建 MITM 代理或修补 APK，不如用 Frida 直接在已加载的类上调用 native JNI 方法。

```javascript
Java.perform(function() {
    var Requestor = Java.use("com.h1702ctf.ctfone.Requestor");
    console.log("hName: " + Requestor.hName());
    console.log("hVal: " + Requestor.hVal());
});
```

调用 `hName()` 和 `hVal()` 会返回绕过服务端检查所需的 HTTP 头名与值 —— 完全不需要绕过证书固定，因为机密就在类方法本身里。

**关键点：** Frida 可以直接在已加载的类上调用 native JNI 方法 —— 既不必在网络层绕过证书固定，也不必完整逆向原生二进制。

**参考：** h1702ctf 2017

---

<a id="android-anti-debug-tracerpid-su-binary-system-properties-h1702ctf-2017"></a>
## Android 反调试：TracerPid、su 二进制、系统属性 (h1702ctf 2017)

原生 ARM 代码实现了三道依次执行的反分析检查：
1. 读取 `/proc/self/status`，查找非零的 `TracerPid`（有调试器附加）
2. 检查 `su` 二进制是否存在（root 检测）
3. 通过 `__system_property_get` 读取自定义系统属性

这些检查控制着某个必需寄存器值的计算。绕过方式：静态分析 —— 用 IDA 的图视图追踪控制流，找出通过三道检查的"happy path"，然后推算每个分支处寄存器应取什么值。

**关键点：** Android 原生代码中的反调试检查（TracerPid、su、系统属性）可以通过静态图分析找到正确的寄存器取值来绕过，无需运行调试器。

**参考：** h1702ctf 2017

---

<a id="android-log-based-key-extraction-hackit-2017"></a>
## 基于 Android 日志的密钥提取 (HackIT 2017)

一个安全通讯应用通过 Android 的 `Log.d()` 记录了密码学材料：
- Curve25519 基础协商值
- 每条消息的临时共享密钥
- 消息 ID 与移位计数器

AES-CBC 的 IV 由记录中的临时/共享值派生；密钥由记录的基础协商值与累计移位计数器派生。用 `adb logcat` 收集全部日志，再重建 AES-CBC 参数以解密截获的消息。

```bash
adb logcat | grep -E "(agreement|ephemeral|shared|key)" > crypto_log.txt
# Parse log entries to reconstruct: key = f(base_agreement, shift_counter)
#                                   iv  = f(ephemeral_shared)
```

**关键点：** 安全敏感应用里过度冗长的日志会泄漏足够的状态，从而在完全不接触私钥的情况下重建加密参数。

**参考：** HackIT CTF 2017

---

<a id="native-jni-key-extraction-via-memory-dump-and-smali-patching-hackit-2017"></a>
## 内存 dump + smali 补丁提取原生 JNI 密钥 (HackIT 2017)

一个 JNI 原生库用 XOR 混淆的密钥（存放在 `.data` 段）处理请求签名，密钥在即将使用前才于运行时被还原。

**流程：**
1. 在已 root 的设备上通过 GDB stub 把库加载进 IDA
2. 在 XOR 解密例程之后下断点
3. dump 包含解密后密钥的内存区域
4. 用 `baksmali` 反汇编 APK 的 DEX，找到构造签名 POST 请求的 smali 文件
5. 修改 smali，改变被签名的参数，然后用 `apktool` 重建并重装

```bash
# Decompile APK
apktool d target.apk -o target_decompiled/
# Edit smali: change signed parameter from original to desired value
# Rebuild
apktool b target_decompiled/ -o target_patched.apk
# Sign and install
```

**关键点：** 对付 JNI 签名：执行期间通过内存 dump 拿到解密后的密钥区域，再修改 smali 对目标参数签名 —— 从而避免完整逆向原生签名算法。

**参考：** HackIT CTF 2017

---

<a id="ibm-as400-savf-file-ebcdic-decoding-ekoparty-2017"></a>
## IBM AS/400 SAVF 文件 EBCDIC 解码 (EKOPARTY 2017)

IBM AS/400 的 SAVF（Save File）二进制文件使用 EBCDIC 而非 ASCII 编码。flag 与干扰文本以"取 2 跳 2"的模式交错排列。

```python
import codecs

with open('savefile.savf', 'rb') as f:
    data = f.read()

# Convert EBCDIC to ASCII
ascii_data = data.decode('cp500')  # cp500 is IBM EBCDIC International

# Filter: keep uppercase letters and underscores (flag charset)
flag_chars = [c for c in ascii_data if c.isupper() or c == '_']
# Or apply take-2-skip-2 pattern after decoding
flag = ''.join(ascii_data[i] for i in range(0, len(ascii_data), 4)
               if ascii_data[i].isupper() or ascii_data[i] == '_')
```

**关键点：** EBCDIC 是 IBM 大型机的原生编码。解码后观察字符分布即可识别交错模式。对 CTF flag 格式而言，只保留大写字母与下划线是很有效的捷径。

**参考：** EKOPARTY CTF 2017

---

<a id="intel-sgx-enclave-reverse-engineering-pwn2win-2017"></a>
## Intel SGX Enclave 逆向 (Pwn2Win 2017)

Intel SGX enclave 的 `.so` 文件会暴露 ECALL 分派表。由于 SGX 代码就是标准 x86-64，enclave 逻辑（包括密钥派生）完全可以用 IDA 逆向。

**流程：**
1. 定位 `.so` 中的 ECALL 表 —— 一个以 ECALL 编号为下标的函数指针数组
2. 用 IDA 反编译各 ECALL，识别远程认证协议
3. 用 `sgx_crypto_wrapper` 在 Python 中手工实现该认证协议
4. 密钥派生：P-256 上的 ECDH，随后用 CMAC-AES-128 派生会话密钥（SK）
5. 用派生出的 SK 解密 AES-128-GCM 加密的 flag 数据块

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import cmac, ciphers

# ECDH: derive shared secret from server's P-256 public key
private_key = ec.generate_private_key(ec.SECP256R1())
shared_secret = private_key.exchange(ec.ECDH(), server_pub_key)

# CMAC-AES-128 key derivation (per SGX attestation spec)
c = cmac.CMAC(ciphers.algorithms.AES(b'\x00' * 16))
c.update(shared_secret[:16])
sk = c.finalize()

# Decrypt flag with AES-128-GCM using derived SK
```

**关键点：** 给定 enclave 度量值后，SGX 远程认证的密钥派生是确定性的 —— 在 Python 中复现协议即可得到同一会话密钥。

**参考：** Pwn2Win CTF 2017

---

<a id="glulx-interactive-fiction-bytecode-matrix-validation-plaidctf-2018"></a>
## Glulx 互动小说字节码矩阵校验 (PlaidCTF 2018)

**模式：** 题目是一个 Glulx 互动小说（`.ulx`/`.blorb`），接受玩家输入，在 VM 内通过矩阵乘法打乱，再与硬编码向量比较。一个隐藏的 `xyzzy` 类命令可开启调试房间，其侧出口会泄漏目标向量与常量矩阵。

**流程：**
1. 用 `glulxd`（Glulx 工具链）反汇编，或在 `glulxe`/`git` 解释器下运行并在每条 VM 指令处 dump 内存。
2. 定位矩阵常量（寻找与比较例程相邻的对齐 32 位整数）以及比较所引用的目标向量。
3. 输入隐藏命令的触发词进入调试房间 —— Glulx 游戏常对 `xyzzy`、`plugh` 或仍保留在字典表（`.DictTable`）里的开发者动词作出响应。
4. 在 Python 中求逆：在 `Z_{2^32}` 上计算 `input_vec = target_vec * matrix.inverse()`（Glulx 整数是无符号 32 位）。

```python
from sage.all import matrix, Zmod

M = matrix(Zmod(2**32), rows)       # rows[i] = extracted matrix row
target = vector(Zmod(2**32), output)
answer = M.solve_right(target)      # required player input as 32-bit words
print(bytes(answer.list()).decode())
```

**关键点：** 冒险游戏 VM 总会把原始故事文本保留在字典和对象表中 —— 在字节码中 grep 开发者动词（`xyzzy`、`debug`、`god`、`plugh`）往往能在逆向校验本身之前先发现隐藏房间。Glulx 的校验例程通常是 32 位整数上的线性运算，用 Sage 做矩阵求逆比符号执行更快。

**参考：** PlaidCTF 2018 — writeup 10019

---

<a id="android-smali-injection-to-defeat-localbroadcastmanager-tamuctf-2019"></a>
## 用 Smali 注入击败 LocalBroadcastManager (TAMUctf 2019)

**模式（Local News）：** APK 通过 `LocalBroadcastManager.getInstance(this).registerReceiver(...)` 注册了一个 `BroadcastReceiver`，它只在被应用自身触发时才解码 flag。外部 `adb shell am broadcast` 会被静默丢弃，因为本地广播从不离开进程：

```bash
$ adb shell cmd package query-receivers --brief -a com.tamu.ctf.START
# No receivers found
```

把注册方式换成 `Context.registerReceiver` 会导致应用强制崩溃（manifest 不匹配）。改为把 `onReceive` 的函数体复制出来，内联到 `onCreate` 中，使反混淆器（例如 Paranoid 的 `Deobfuscator$app$Debug.getString(0)`）在启动时运行，明文 flag 就出现在 `logcat` 里了。

反编译、打补丁、重建、用调试密钥签名、安装、抓 logcat：

```smali
# Inside MainActivity.smali, inserted before the final return of onCreate():
const/4 v1, 0x0
invoke-static {v1}, Lio/michaelrocks/paranoid/Deobfuscator$app$Debug;->getString(I)Ljava/lang/String;
move-result-object v1
invoke-static {v1, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
```

```bash
apktool d app.apk -o app
# patch MainActivity.smali ...
apktool b app -o app/dist/app.apk
jarsigner -keystore ~/.android/debug.keystore -storepass android \
  app/dist/app.apk androiddebugkey
adb install -r app/dist/app.apk
adb logcat | grep -i flag
```

**关键点：** 通过 `LocalBroadcastManager` 注册的接收器无法从 `adb` 触发，所以"自己发 intent"这个显而易见的思路行不通；而对 Paranoid 字符串做静态反混淆又很痛苦。Smali 补丁同时绕开两者：把反混淆调用搬到会自动执行的路径上，并把输出重定向到 `Log.d()`，从而把一个本地专属接收器变成 logcat 可见的原语。

**参考：** TAMUctf 2019 — Local News，writeup 13565
