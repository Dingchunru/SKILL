# CTF Reverse - 平台相关逆向

macOS/iOS、嵌入式/IoT 固件、内核驱动、汽车以及游戏引擎逆向。

## 目录
- [macOS / iOS 逆向](#macos--ios-逆向)
  - [Mach-O 二进制格式](#mach-o-二进制格式)
  - [代码签名与 Entitlements](#代码签名与-entitlements)
  - [Objective-C 运行时逆向](#objective-c-运行时逆向)
  - [Swift 二进制逆向](#swift-二进制逆向)
  - [iOS 应用分析](#ios-应用分析)
  - [dyld / 动态链接](#dyld--动态链接)
- [嵌入式 / IoT 固件逆向](#嵌入式--iot-固件逆向)
  - [固件提取](#固件提取)
  - [固件解包](#固件解包)
  - [架构相关笔记](#架构相关笔记)
  - [RTOS 分析](#rtos-分析)
- [内核驱动逆向](#内核驱动逆向)
  - [Linux 内核模块](#linux-内核模块)
  - [eBPF 程序](#ebpf-程序)
  - [Windows 内核驱动](#windows-内核驱动)
- [游戏引擎逆向](#游戏引擎逆向)
  - [Unreal Engine](#unreal-engine)
  - [Unity（IL2CPP 之外）](#unityil2cpp-之外)
  - [反作弊分析](#反作弊分析)
  - [Lua 脚本驱动的游戏](#lua-脚本驱动的游戏)
- [汽车 / CAN 总线逆向](#汽车--can-总线逆向)
- [RISC-V 在 QEMU 下运行：给 GLIBC 符号版本打补丁 (Pwn2Win 2018)](#risc-v-在-qemu-下运行给-glibc-符号版本打补丁-pwn2win-2018)
- [用 APK 证书 SHA-256 作为 AES 密钥 (ASIS Finals 2018)](#用-apk-证书-sha-256-作为-aes-密钥-asis-finals-2018)
- [Moxie ISA 自定义 opcode 发现 (SECCON 2018)](#moxie-isa-自定义-opcode-发现-seccon-2018)
- [Unity APK Assembly-CSharp.dll 运行时打补丁 (SECCON 2018)](#unity-apk-assembly-csharpdll-运行时打补丁-seccon-2018)
- [用 Il2CppDumper 恢复 Unity IL2CPP 元数据 (SECCON 2018)](#用-il2cppdumper-恢复-unity-il2cpp-元数据-seccon-2018)

---

<a id="macos--ios-reversing"></a>
## macOS / iOS 逆向

<a id="mach-o-binary-format"></a>
### Mach-O 二进制格式

```bash
# File identification
file binary                    # "Mach-O 64-bit executable arm64" or "x86_64"
otool -l binary               # Load commands (segments, dylibs, entry point)
otool -L binary               # Linked dynamic libraries

# Universal (fat) binaries — multiple architectures in one file
lipo -info universal_binary    # List architectures
lipo universal_binary -thin arm64 -output binary_arm64  # Extract one arch

# Segments and sections
otool -l binary | grep -A5 "segment\|section"
# Key segments: __TEXT (code), __DATA (globals), __LINKEDIT (symbols)
# Key sections: __text (instructions), __cstring (C strings), __objc_methname
```

**Mach-O 关键概念：**
- Load command 驱动态链接器（`dyld`）
- `LC_MAIN` → 入口点（取代 `LC_UNIXTHREAD`）
- `LC_LOAD_DYLIB` → 共享库依赖
- `LC_CODE_SIGNATURE` → 代码签名数据块
- `__DATA_CONST.__got` → 全局偏移表
- `__DATA.__la_symbol_ptr` → 惰性符号指针（类似 PLT）

<a id="code-signing--entitlements"></a>
### 代码签名与 Entitlements

```bash
# Check code signature
codesign -dvvv binary
codesign --verify binary

# Extract entitlements (capability permissions)
codesign -d --entitlements - binary
# Key entitlements: com.apple.security.app-sandbox, com.apple.security.network.client

# Remove code signature (for patching)
codesign --remove-signature binary

# Re-sign (ad-hoc, for testing)
codesign -f -s - binary
```

**与 CTF 的关系：** 被打过补丁的二进制必须重新签名才能在 macOS 上运行。临时签名（`-s -`）可用于本地测试。

<a id="objective-c-runtime-re"></a>
### Objective-C 运行时逆向

```bash
# Dump Objective-C class info
class-dump binary > classes.h
# Shows: @interface, @protocol, method signatures with types

# Runtime inspection with lldb
(lldb) expression -l objc -O -- [NSClassFromString(@"ClassName") new]
(lldb) expression -l objc -O -- [[ClassName alloc] init]

# Method swizzling detection (anti-tamper)
# Look for: method_exchangeImplementations, class_replaceMethod
```

**反汇编中的 Objective-C：**
```text
# objc_msgSend(receiver, selector, ...) is THE dispatch mechanism
# RDI = self (receiver), RSI = selector (char* method name)

# In Ghidra/IDA, look for:
objc_msgSend(obj, "checkPassword:", input)
# Selector strings are in __objc_methname section
# Cross-reference selectors to find implementations
```

**class-dump 替代品：**
- `dsdump` —— 更快，支持 Swift + Objective-C
- `otool -oV binary` —— 导出 Objective-C 段
- Ghidra：在 Analysis Options 中启用 "Objective-C" 分析器

<a id="swift-binary-reversing"></a>
### Swift 二进制逆向

```bash
# Detect Swift
strings binary | grep "swift"
otool -l binary | grep "swift"   # __swift5_* sections

# Swift demangling
swift demangle 's14MyApp0A8ClassC10checkInput6resultSbSS_tF'
# → MyApp.MyAppClass.checkInput(result: String) -> Bool

# xcrun swift-demangle < mangled_names.txt
```

**反汇编中的 Swift：**
```text
# Swift uses value witness tables (VWT) for type operations
# Protocol witness tables (PWT) for dynamic dispatch (like vtables)

# Key runtime functions to watch:
swift_allocObject          → heap allocation
swift_release             → reference count decrement
swift_bridgeObjectRetain  → bridged (ObjC ↔ Swift) retain
swift_once                → lazy initialization (like dispatch_once)

# String layout:
# Small strings (≤15 bytes): inline in 16-byte buffer, tagged pointer
# Large strings: heap-allocated, pointer + length + flags

# Array<T>: pointer to ContiguousArrayStorage (header + elements)
# Dictionary<K,V>: hash table with open addressing
```

**用 Ghidra 处理 Swift：** 启用 "Swift" 语言模块。Swift 元数据段（`__swift5_types`、`__swift5_proto`）包含类型描述符，Ghidra 可以解析。

<a id="ios-app-analysis"></a>
### iOS 应用分析

```bash
# Extract IPA (iOS app package)
unzip app.ipa -d extracted/
ls extracted/Payload/*.app/

# Check if encrypted (App Store encryption / FairPlay DRM)
otool -l extracted/Payload/*.app/binary | grep -A4 "LC_ENCRYPTION_INFO"
# cryptid = 1 means encrypted, 0 means decrypted

# Decrypt with frida-ios-dump (requires jailbroken device)
# Or use Clutch / bfdecrypt on device
frida-ios-dump -H jailbroken_ip -p 22 "App Name"

# Analyze decrypted binary
class-dump decrypted_binary > headers.h
```

**越狱检测与绕过：**
```javascript
// Common jailbreak checks:
// 1. Check for Cydia/Sileo
// 2. Check /private/var/lib/apt
// 3. fork() succeeds (sandboxed apps can't fork)
// 4. Open /etc/apt, /bin/sh with write
// 5. Check for substrate/substitute libraries

// Frida bypass:
var paths = ["/Applications/Cydia.app", "/bin/sh", "/etc/apt",
             "/private/var/lib/apt", "/usr/bin/ssh"];
Interceptor.attach(Module.findExportByName(null, "access"), {
    onEnter(args) {
        this.path = Memory.readUtf8String(args[0]);
    },
    onLeave(retval) {
        if (paths.some(p => this.path && this.path.includes(p))) {
            retval.replace(-1);  // File not found
        }
    }
});
```

<a id="dyld--dynamic-linking"></a>
### dyld / 动态链接

```bash
# DYLD environment variables (for analysis, blocked in hardened runtime)
DYLD_PRINT_LIBRARIES=1 ./binary       # Print loaded dylibs
DYLD_INSERT_LIBRARIES=hook.dylib ./binary  # Inject dylib (like LD_PRELOAD)
# Note: SIP (System Integrity Protection) blocks this for system binaries

# Inspect dyld shared cache (contains all system frameworks)
dyld_shared_cache_util -list /System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```

---

<a id="embedded--iot-firmware-re"></a>
## 嵌入式 / IoT 固件逆向

<a id="firmware-extraction"></a>
### 固件提取

```bash
# binwalk — firmware analysis and extraction
binwalk firmware.bin                        # Identify embedded filesystems, compressed data
binwalk -e firmware.bin                     # Extract all identified components
binwalk -Me firmware.bin                    # Recursive extraction (matryoshka)
binwalk --dd='.*' firmware.bin              # Extract everything raw

# Manual extraction by signature
strings firmware.bin | head -50             # Look for version strings, filesystem markers
hexdump -C firmware.bin | grep "hsqs"       # SquashFS magic
hexdump -C firmware.bin | grep "UBI#"       # UBI magic
```

**硬件提取方法（需要物理接触）：**
```text
UART:  Serial console — often gives root shell or bootloader access
       Tools: USB-UART adapter, baudrate detection (usually 115200)
       Identify: 4 pins (GND, TX, RX, VCC), use multimeter

JTAG:  Direct CPU debug — read/write flash, halt CPU, set breakpoints
       Tools: OpenOCD, J-Link, Bus Pirate
       Identify: 10/14/20-pin header, use JTAGulator for auto-detection

SPI Flash: Direct chip read — dump entire firmware
           Tools: flashrom, CH341A programmer
           Identify: 8-pin SOIC chip (Winbond, Macronix, etc.)

eMMC:  Embedded MMC — common in routers, phones
       Tools: eMMC reader, direct solder to test pads
```

<a id="firmware-unpacking"></a>
### 固件解包

```bash
# SquashFS (most common in routers)
unsquashfs -d output/ squashfs-root.sqfs
# If custom compression: try different compressors (-comp xz|lzma|lzo|gzip)

# JFFS2
jefferson -d output/ jffs2.img

# UBI/UBIFS
ubireader_extract_images firmware.ubi
ubireader_extract_files ubifs.img

# CPIO (initramfs)
cpio -idv < initramfs.cpio

# Device tree blob
dtc -I dtb -O dts -o output.dts device_tree.dtb

# Kernel extraction
binwalk -e firmware.bin
# Look for: zImage, uImage, vmlinux
# Extract vmlinux from compressed: vmlinux-to-elf tool
```

<a id="architecture-specific-notes"></a>
### 架构相关笔记

**ARM（IoT 中最常见）：**
```bash
# Cross-toolchain
apt install gcc-arm-linux-gnueabihf gdb-multiarch

# QEMU emulation
qemu-arm -L /usr/arm-linux-gnueabihf/ ./arm_binary
qemu-arm -g 1234 ./arm_binary    # Start GDB server on port 1234
gdb-multiarch -ex 'target remote :1234' ./arm_binary

# ARM vs Thumb: ARM instructions are 4 bytes, Thumb are 2 bytes
# LSB of function pointer indicates mode: 0=ARM, 1=Thumb
# Ghidra: Right-click → Processor Options → ARM/Thumb mode
```

**ARM64/AArch64：** 调用约定、ROP gadget 以及 qemu-aarch64-static 模拟见 [platforms-hardware.md](platforms-hardware.md#arm64aarch64-逆向与利用)。

**MIPS（路由器、嵌入式）：**
```bash
# Big-endian vs little-endian — check ELF header or file command
file binary    # "MIPS, MIPS32 rel2 (MIPS-II), big-endian" or "little-endian"

# Emulation
qemu-mips -L /usr/mips-linux-gnu/ ./mips_binary         # Big-endian
qemu-mipsel -L /usr/mipsel-linux-gnu/ ./mipsel_binary   # Little-endian

# Key MIPS patterns:
# Branch delay slots — instruction AFTER branch always executes
# $gp (global pointer) — used for PIC, points to .got
# lui + addiu pair — loads 32-bit constant (upper 16 + lower 16)
```

**RISC-V：** Capstone 反汇编见主 [tools.md](tools.md#risc-v-二进制分析-ehax-2026)；高级扩展与调试见 [platforms-hardware.md](platforms-hardware.md#risc-v进阶)。

<a id="rtos-analysis"></a>
### RTOS 分析

```text
FreeRTOS:
  - Tasks (like threads): xTaskCreate → function pointer + stack
  - Strings: "IDLE", "Tmr Svc", task names
  - xQueueSend/xQueueReceive → inter-task communication
  - Look for vTaskDelay() for timing, xSemaphoreTake() for sync

Zephyr:
  - k_thread_create → kernel thread creation
  - k_msgq_put/k_msgq_get → message queues
  - CONFIG_* symbols reveal kernel configuration

Bare metal (no OS):
  - Interrupt vector table at address 0x0 or 0x08000000 (STM32)
  - main loop pattern: while(1) { read_input(); process(); output(); }
  - Peripheral registers at memory-mapped addresses (check datasheet)
```

---

<a id="kernel-driver-reversing"></a>
## 内核驱动逆向

<a id="linux-kernel-modules"></a>
### Linux 内核模块

```bash
# Identify kernel module
file module.ko                      # "ELF 64-bit LSB relocatable"
modinfo module.ko                   # Module info (description, author, license)

# List module symbols
nm module.ko | grep -v " U "       # Exported symbols

# Strings for quick recon
strings module.ko | grep -i "flag\|secret\|ioctl\|device"

# Find ioctl handler
# Key pattern: .unlocked_ioctl = my_ioctl_handler in file_operations struct
# In Ghidra: find struct with function pointers, identify by position

# Load in Ghidra
# Language: x86:LE:64:default
# Base address: doesn't matter for .ko (relocatable)
# Look for init_module / cleanup_module entry points
```

**常见内核模块 CTF 套路：**
```c
// Device creation (creates /dev/challenge)
alloc_chrdev_region(&dev, 0, 1, "challenge");
cdev_init(&cdev, &fops);

// ioctl handler (main interface)
long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case CUSTOM_CMD_1: /* operation */ break;
        case CUSTOM_CMD_2: /* operation */ break;
    }
}

// copy_from_user / copy_to_user — data transfer with userspace
copy_from_user(kernel_buf, (void __user *)arg, size);
copy_to_user((void __user *)arg, kernel_buf, size);
```

**调试内核模块：**
```bash
# QEMU + GDB for kernel debugging
qemu-system-x86_64 -kernel bzImage -initrd initrd.cpio -s -S \
  -append "console=ttyS0 nokaslr" -nographic

# In another terminal
gdb vmlinux
(gdb) target remote :1234
(gdb) lx-symbols           # Load module symbols (requires scripts)
(gdb) add-symbol-file module.ko 0x<loaded_address>
```

<a id="ebpf-programs"></a>
### eBPF 程序

```bash
# Dump eBPF programs from running system
bpftool prog list
bpftool prog dump xlated id <N>    # Disassemble
bpftool prog dump jited id <N>     # JIT'd machine code

# eBPF bytecode analysis
# eBPF has 11 registers (r0-r10), 64-bit
# r0 = return value, r1-r5 = arguments, r10 = frame pointer
# Instructions are 8 bytes each

# Disassemble .o file containing eBPF
llvm-objdump -d ebpf_prog.o

# Key eBPF patterns:
# bpf_map_lookup_elem → read from map
# bpf_map_update_elem → write to map
# bpf_probe_read → read kernel memory
# bpf_trace_printk → debug output
```

<a id="windows-kernel-drivers"></a>
### Windows 内核驱动

```bash
# .sys files are PE format — load in IDA/Ghidra as normal PE
# Entry point: DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)

# Key patterns:
# IoCreateDevice → creates device object
# IRP_MJ_DEVICE_CONTROL → ioctl handler
# MmMapIoSpace → memory-mapped I/O
# ObReferenceObjectByHandle → get kernel object from handle
# ZwCreateFile/ZwReadFile → kernel-mode file operations
```

---

<a id="game-engine-reversing"></a>
## 游戏引擎逆向

<a id="unreal-engine"></a>
### Unreal Engine

```bash
# Pak file extraction
# UnrealPakTool or quickbms with unreal_tournament_4.bms
unrealpak.exe extract GameName.pak -output extracted/

# UE4/UE5 asset formats:
# .uasset — serialized UObject (meshes, textures, blueprints)
# .umap — level/map data
# .ushaderbytecode — compiled shader
# FModel (https://fmodel.app/) — GUI asset viewer/extractor
```

**蓝图逆向：**
```text
Blueprints compile to bytecode in .uasset files.
- UAssetGUI / FModel to browse Blueprint assets
- Kismet bytecode → visual scripting logic
- Look for: K2_SetTimer, DoOnce, Branch, Custom Events
- Flag logic often in Blueprint event graphs, not C++
```

**UE4/UE5 C++ 逆向：**
```bash
# Key engine classes:
# UObject → base class for everything
# AActor → entities in the world
# UGameInstance → game state
# APlayerController → player input handling

# Reflection system — UCLASS(), UPROPERTY(), UFUNCTION() macros
# Generates metadata accessible at runtime
# In Ghidra: look for UClass::StaticClass() calls → type identification

# String handling: FString (UTF-16), FName (hashed identifier), FText (localized)
# In memory: FString = {TCHAR* Data, int32 ArrayNum, int32 ArrayMax}
```

<a id="unity-beyond-il2cpp"></a>
### Unity（IL2CPP 之外）

IL2CPP 基础见 [languages.md](languages.md#unity-il2cpp-游戏)。

**基于 Mono 的 Unity（非 IL2CPP）：**
```bash
# Managed assemblies in Data/Managed/ directory
# Assembly-CSharp.dll contains game logic
dnspy Assembly-CSharp.dll       # Full decompilation + debugging
ilspy Assembly-CSharp.dll       # Decompilation only

# Common Unity patterns:
# MonoBehaviour.Start() → initialization
# MonoBehaviour.Update() → per-frame logic
# PlayerPrefs.GetString("key") → stored data
# SceneManager.LoadScene("level") → scene transitions
```

**Unity 资源提取：**
```bash
# AssetStudio — extract textures, models, audio, scripts
# AssetRipper — comprehensive Unity asset extraction
# UABE (Unity Asset Bundle Extractor) — low-level asset editing

# Search for flags in:
# - Text assets (.txt, .json)
# - TextMesh / UI Text components
# - Shader source code
# - ScriptableObject assets
# - PlayerPrefs save files
```

<a id="anti-cheat-analysis"></a>
### 反作弊分析

```text
For CTF challenges involving game anti-cheat:

EasyAntiCheat (EAC):
- Kernel driver (EasyAntiCheat_EOS.sys)
- User-mode module injected into game
- Integrity checks on game memory
- Bypass: kernel-level memory R/W (for research only)

BattlEye:
- BEService.exe → BEClient.dll injected
- Communication via encrypted channel
- Screenshot capture, process scanning
- Module: BEClient2.dll

Valve Anti-Cheat (VAC):
- User-mode only (no kernel driver)
- Module hashing, memory scanning
- Network-based detection (server-side)
- Delayed bans (not immediate)

CTF approach:
1. Identify which anti-cheat (strings, loaded modules)
2. For CTF: usually need to bypass specific check, not full anti-cheat
3. Memory patching: find game state in memory, modify values
4. Save file manipulation: often easier than runtime cheating
```

<a id="lua-scripted-games"></a>
### Lua 脚本驱动的游戏

```bash
# Many games embed Lua for scripting
# Look for: lua51.dll, luajit.dll, .lua files in assets

# Luac bytecode decompilation
luadec bytecode.luac > decompiled.lua      # Lua 5.1-5.3
unluac bytecode.luac > decompiled.lua      # Alternative

# LuaJIT bytecode
luajit -bl bytecode.lua                     # Disassemble
# ljd (LuaJIT decompiler): python3 ljd bytecode.lua

# Embedded Lua: strings binary | grep "lua_\|luaL_\|LUA_"
# Hook lua_pcall to intercept script execution
```

---

<a id="automotive--can-bus-re"></a>
## 汽车 / CAN 总线逆向

```bash
# CAN bus interface setup
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0

# Capture CAN traffic
candump can0                               # Live capture
candump -l can0                            # Log to file
cansniffer can0                            # Filter/highlight changes

# Replay CAN messages
canplayer -I logfile.log can0
cansend can0 7DF#0201000000000000          # Send single frame (OBD-II request)

# UDS (Unified Diagnostic Services) — common in automotive CTF
# Service 0x27: Security Access (seed-key authentication)
# Service 0x2E: Write Data By Identifier
# Service 0x31: Routine Control

# Decode CAN frames
# ID: 11-bit or 29-bit identifier
# DLC: Data Length Code (0-8 bytes)
# Data: up to 8 bytes payload
```

**汽车 CTF 常见套路：**
- Seed-key 绕过：从 ECU 固件中逆向密钥派生算法
- CAN 报文重放：抓取合法命令并重放以解锁功能
- 通过 UDS/KWP2000 从 ECU 提取固件

---

<a id="risc-v-qemu-execution-with-glibc-symbol-version-patching-pwn2win-2018"></a>
## RISC-V 在 QEMU 下运行：给 GLIBC 符号版本打补丁 (Pwn2Win 2018)

**模式：** 题目二进制面向某个本机不存在的 RISC-V Debian。提取 Debian 的 libc6 与动态链接器，然后在十六进制编辑器中把二进制要求的 GLIBC 符号版本（例如 `GLIBC_2.25` → `GLIBC_2.27`）改掉，让现成的 libc 能提供这些符号。用 `qemu-riscv64 -L <sysroot>` 运行。

```bash
ar x libc6_2.27-5_riscv64.deb && tar xf data.tar.xz
sed 's@GLIBC_2.25@GLIBC_2.27@g' -i binary
# Patch the symbol version hash too
objdump -p binary   # note old hash
# replace bytes with xxd / hexedit
qemu-riscv64 -L ./sysroot ./binary
```

**关键点：** `ld.so` 的符号版本控制依赖每个符号旁带的一个哈希标识。同时改掉版本字符串和它的哈希即可绕过检查，无需重建 libc；`objdump -p` 会显示需要覆盖的哈希槽。

**参考：** Pwn2Win CTF 2018 — Too Slow，writeup 12501+

---

<a id="apk-certificate-sha-256-as-aes-key-asis-finals-2018"></a>
## 用 APK 证书 SHA-256 作为 AES 密钥 (ASIS Finals 2018)

**模式：** Android 应用从 `SHA-256(packageInfo.signatures[0].toByteArray())` 派生 AES 密钥并截断到 16 字节。由于签名证书就嵌在 APK 中，密钥可以离线恢复 —— 完全不需要逆向原生代码。

```python
from hashlib import sha256
import base64, zipfile

cert = zipfile.ZipFile('app.apk').read('META-INF/CERT.RSA')
key  = base64.b64encode(sha256(cert).digest())[:16]
# Decrypt config resources with AES-ECB using this key
```

**关键点：** "从公开指纹派生确定性密钥"是 Android 上反复出现的反模式。审计 `getSignature`、`getPackageInfo` 和 MessageDigest 的用法，看是否有这种形态；正确做法是把真正的机密存在服务端。

**参考：** ASIS CTF Finals 2018 — Gunshop，writeup 12420

---

<a id="moxie-isa-custom-opcode-discovery-seccon-2018"></a>
## Moxie ISA 自定义 opcode 发现 (SECCON 2018)

**模式：** 二进制为 Moxie（一种冷门 CPU 架构）编译。对 ELF 执行 `strings` 会发现一段帮助文本，声明了自定义 opcode `SETRSEED (0x16)` 和 `GETRAND (0x17)`，以及一个非标准的 xorshift32 实现。在 Python 中模拟这些 opcode 以恢复 PRNG 序列，再用该序列 XOR 密文。

```python
def xorshift32(s):
    s ^= (s << 13) & 0xffffffff
    s ^= (s >> 17)
    s ^= (s << 15) & 0xffffffff     # Note: *not* standard (<< 5)
    return s & 0xffffffff
```

**关键点：** 冷门 ISA 常常会为内联实现加密而添加少量自定义指令。在二进制中 grep 人类可读的 opcode 说明 —— 出题人为了自己调试，经常把它留在帮助文本里。

**参考：** SECCON 2018 — Special Instructions，writeup 12001

---

<a id="unity-apk-assembly-csharpdll-runtime-patch-seccon-2018"></a>
## Unity APK Assembly-CSharp.dll 运行时打补丁 (SECCON 2018)

**模式：** Unity 游戏把编译好的 C# 游戏逻辑放在 `assets/bin/Data/Managed/Assembly-CSharp.dll`。用 dnSpy/ILSpy 反编译，修改 `Update()` 或 `Start()` 方法（例如去掉遮住 flag 的旋转动画），重新编译，用 `apktool` 重打包 APK，用 `jarsigner` 重签名，再装到模拟器上。

```bash
apktool d game.apk -o game_src
# Replace game_src/assets/bin/Data/Managed/Assembly-CSharp.dll with patched version
apktool b game_src -o patched.apk
jarsigner -keystore debug.keystore -storepass android patched.apk androiddebugkey
adb install -r patched.apk
```

**关键点：** 只要打开 DLL，Unity 游戏"就是 C#"。任何因为角度不对或被覆盖层遮挡的隐藏 flag，都可以通过删掉动画代码曝光出来。

**参考：** SECCON 2018 — block，writeup 12001

---

<a id="il2cppdumper-for-unity-il2cpp-metadata-recovery-seccon-2018"></a>
## 用 Il2CppDumper 恢复 Unity IL2CPP 元数据 (SECCON 2018)

**模式：** 现代 Unity 游戏编译为 IL2CPP（原生代码 + 元数据），不再附带 `Assembly-CSharp.dll`。用 `Il2CppDumper` 处理 `libil2cpp.so` 加 `assets/bin/Data/Managed/Metadata/global-metadata.dat` 得到伪 C#，然后在输出中 grep 端点字符串、API 路径或加密常量。

```bash
Il2CppDumper libil2cpp.so global-metadata.dat out/
grep -r "https://" out/  # find hardcoded endpoints
```

**关键点：** IL2CPP 看起来不透明，但元数据文件携带了所有类型名、方法名和字符串字面量。这已经足够逆向 CTF 级别的逻辑，完全不必碰原生反汇编。

**参考：** SECCON 2018 — shooter，writeup 12001
