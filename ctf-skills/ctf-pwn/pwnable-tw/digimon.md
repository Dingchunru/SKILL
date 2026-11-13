---
tags:
  - use-after-free
  - race-condition
  - vtable-hijack
platform: pwnable.tw
points: 600
arch: x86-64
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: yes
references:
  - https://pwnable.tw/challenge/
description: "并发战斗线程之间的竞态在 Digimon 对象上造成 use-after-free，从而可以覆盖虚函数表指针。"
proof-of-concept: no
---

# Digimon — pwnable.tw（600 分）

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10501`
>
> Flag: `FLAG{You_have_conquered_the_world_of_digimon!}`

## 题目概览

一个多线程的 Digimon “游戏”二进制（x86-64，PIE，Partial RELRO，NX，栈 Canary），链接 glibc 2.23。玩家在 20x20 的地图上移动，遭遇野生数码兽，与其战斗/结盟，管理伙伴阵容，通过 `pthread` 工作线程执行任务，逛商店，还能招募一个隐藏 boss（Toolmon）。游戏用 `strtok` 从 stdin 解析命令。

```bash
checksec:
  Arch:     amd64-64-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      PIE enabled
```

## 漏洞

### V1 — `strtok` 覆盖栈变量（主漏洞，可利用）

**根因：** 主循环通过 `read_line(buf, 0x68)` 把命令读入一个 `0x68` 字节的栈缓冲区，而该函数在缓冲区被填满时**不会**补 NUL 终止符。栈上紧邻其后的是 `task` 命令使用的 `partner_index` 变量。

```c
// main_loop (simplified)
char command_buf[0x68];    // +0x00
// uint32_t partner_idx;   // +0x68  (immediately after buffer on stack)
// uint32_t task_type;     // +0x6c

memset(command_buf, 0, sizeof(command_buf));
read_line(command_buf, sizeof(command_buf));  // NO NUL terminator if full
strtok(command_buf, " ");                    // first token = command

if (!strncmp(command_buf, "task", 4)) {
    char *s1 = strtok(NULL, " ");   // partner index token
    arg1 = atoi(s1);                // parsed as partner index
    if (arg1 < num_partners && !partners[arg1].is_busy) {
        char *s2 = strtok(NULL, " ");  // <-- THIS strtok walks off buffer
        arg2 = atoi(s2);              //     and NUL-overwrites arg1
        add_task(arg1, arg2);          //     now arg1 == 0, not 32
    }
}
```

**触发：** 发送 `'task 32'.ljust(0x66, '_') + ' 3n   '`（共 0x6c 字节）。解析流程如下：
1. `strtok` 找到 `"task"`，把空格替换为 NUL → `"task\x0032..."`。
2. 第二次 `strtok` 找到 `"32"` → `arg1 = 32`。伙伴 32 的忙碌检查通过。
3. 第三次 `strtok` 在栈上越过 `arg1` 继续找，并把它的最低字节 NUL 覆盖 → `arg1` 变成 **0**。
4. `add_task(0, task_type)` 执行——任务被追加到**伙伴 0**（它确实处于忙碌状态），绕过了忙碌检查。

**影响：** 对伙伴 0 的 `task_queue[4]` 数组进行无边界写入，溢出到**下一个堆分配的 Partner 结构体**，写入的字节是 `\x01`、`\x02` 或 `\x03`（任务类型值）。

```c
// enqueue_task — no bounds check on task_count
partner->task_queue[partner->task_count] = task;  // OOB write
partner->task_count++;
```

### V2 — Toolmon `scanf` 未初始化变量泄漏（可利用）

**根因：** Toolmon 菜单使用 `scanf("%u", &action)` / `scanf("%u", &amount)` / `scanf("%u %u", &x, &y)`。如果用户输入 `"+"` 或 `"-"`，`scanf` 失败且不写该变量，随后打印出**未初始化的栈数据**。

```c
// talk_toolmon
scanf("%u", &action);
printf("%u is not available, sir:(\n", action);  // leaks stack garbage
```

**影响：**
- **PIE 基址泄漏**：在动作菜单输入 `"+"` → 泄漏低 32 位；再在“多少钱”提示处输入 `"+"` → 泄漏高 32 位。拼起来得到一个代码指针，减去已知偏移 → PIE 基址。
- **栈 cookie 泄漏**：当 Toolmon 与商店 NPC 相邻时，NPC 选择函数会把 canary 留在栈上，而最后 Toolmon 菜单读取未初始化数据的位置正好覆盖它。在坐标处输入 `"+ +"` → 以 `(低32位, 高32位)` 的形式泄漏 canary。

### V3 — 物品索引越界读（次要，视情况而定）

**根因：** `use_item()` 会检查 `item_id >= ITEM_COUNT`，但 `show_bag` 风格代码中“你什么都没有”的错误路径却直接用索引读取 `g_item_names`，未做完整校验。

```c
printf("You don't have any %s!\n", g_item_names[item_idx]);
// if item_idx is large, reads OOB from .rodata/.data/.bss
```

**影响：** 从物品名数组进行任意越界读。若被索引的内存恰好可映射（不可靠，约 1/0x2000 概率），可泄漏 BSS/GOT 中的指针。

### V4 — `read_line` 缺少 NUL 终止符（使能条件）

```c
// read_line: reads up to max_len bytes, NO NUL termination
static uint32_t read_line(char *buf, uint32_t max_len) {
    // ... reads byte-by-byte, returns on '\n' or max_len
    // never appends '\0'
}
```

这是 V1 的根本使能条件——因为没有 NUL 终止符标记用户输入的结束，`strtok` 才会越过缓冲区边界继续走。

### V5 — 战斗状态中 `sprintf` 栈溢出（不可利用）

```c
static void print_battle_status(...) {
    char line_buf[24];
    sprintf(line_buf, "%.2lf / %.2lf", partner->hp, partner->max_hp);
    // Large trained stats can overflow the 24-byte buffer
}
```

**影响：** 会溢出栈缓冲区，但写入的字节是浮点数字字符——无法控制它们来绕过栈 canary。

### V6 — 进化过程中的竞态（不可利用）

同时通过任务线程训练并使用贤者之石物品会触发双重进化，使 `stage > 3`，导致对图像指针数组的越界读，程序崩溃。

### V7 — Toolmon “为我而死”的陈旧索引（不可利用）

通过“为我而死”杀掉 Toolmon 时用 `memmove` 压缩伙伴数组，但没有更新 `g_active_partner_index`。由此产生的越界索引不指向任何有用位置。

### V8 — 任务线程中 `strncat` 导致的栈溢出（可利用但不实用）

```c
// task_worker
char notification_buf[1024];
strncat(notification_buf, line_buf, 0x100);  // repeated per task
```

如果 `task_count` 被（V1）破坏成一个很大的值，线程会处理上百个任务，每次 `strncat` 把约 256 字节拼进 1024 字节的栈缓冲区 → 工作线程栈溢出。但这需要先泄漏 canary，并等所有任务跑完（可能耗时数小时）。

## 关键数据结构

### Partner 结构体（0xa0 字节）

| 偏移 | 字段 | 类型 |
|--------|-------|------|
| `0x00` | `name` | `char[24]`（内联，来自种族数据库） |
| `0x18` | `species_id` | `uint16_t` |
| `0x1a` | `stage` | `uint8_t`（0=Rookie，3=Mega） |
| `0x1b` | `charge_count` | `uint8_t` |
| `0x20` | `speed` | `uint32_t` |
| `0x24` | `luck` | `uint32_t` |
| `0x28` | `max_hp` | `double` |
| `0x30` | `hp` | `double` |
| `0x38` | `atk` | `double` |
| `0x40` | `potential` | `double` |
| `0x50` | `notification` | `char *`（realloc 得到的） |
| `0x58` | **`nickname`** | `char *`（malloc(0x80)） |
| `0x60` | `pending_money` | `uint32_t` |
| `0x64` | `away`（忙碌标志） | `uint8_t` |
| `0x68` | `mutex` | `pthread_mutex_t` |
| `0x90` | `task_thread` | `pthread_t *`（malloc(8)） |
| `0x98` | `task_count` | `uint32_t` |
| `0x9c` | `task_queue` | `uint8_t[4]` ← 溢出从此处开始 |

## 利用路径

所有已知解法共用同一个核心 bug（V1：strtok 溢出），区别在于泄漏策略和写-任意地址目标。

---

### 路径 A — 堆溢出 → 昵称指针破坏 → 任意读/写 → `__free_hook`/`__malloc_hook`

**相关题解：** 370（exp.py）、821、2311、3148、3498、7905、8153、15989、31599、34817

**前提：**
- 33 个伙伴（以便存在索引 32 = ASCII 空格，strtok 技巧所需）
- 购买命名文档（以使用 `nick` 命令）

**步骤：**

1. **刷游戏：** 结盟足够多的数码兽，训练提升世界等级，凑齐 33 个伙伴（含 Toolmon）。

2. **触发堆溢出（V1）：** 反复发送 `'task 32'.ljust(0x66, '_') + ' 3'`。每轮在伙伴 0 的 `task_queue[4]` 之后追加一个字节（`\x01`、`\x02` 或 `\x03`），溢出到相邻的 Partner 结构体（伙伴 1）。

3. **破坏伙伴 1 的昵称指针：** 溢出先经伙伴 1 的 `name[24]` 写 `\x01`/`\x02`/`\x03` 字节（由于 `mons` 会读回名字，这就泄漏了一个堆指针），最终破坏 **`partner[1].nickname` 的最低字节**（偏移 `+0x58`）。

4. **制造重叠：** 如果被破坏的昵称指针最低字节恰好指向另一个 Partner 结构体，则写伙伴 1 的昵称就等于写那个结构体的字段——由此控制另一个伙伴的 `notification` 和 `nickname` 指针 → **任意读/写**。

5. **泄漏链：**
   - **堆：** 读伙伴 1 被溢出的名字，取得原始昵称指针值。
   - **libc：** 把假昵称指向某处已知堆偏移（含 `pthread_t` 地址，mmap 区），或指向 GOT 项（若已知 PIE 基址），或利用 notification 释放技巧让已释放堆块的 fd 指针落入 unsorted bin → libc main_arena。
   - **栈（可选）：** 从 libc 读 `__environ` 取得栈地址。

6. **劫持控制流：**
   - **`__free_hook` = `system`**：把 `system` 写入 `__free_hook`，再把某伙伴昵称设为 `"/bin/sh"` 并释放它（例如“为我而死”杀 Toolmon，内部会 `free(toolmon->nickname)` 然后 `free(toolmon)`）。
   - **`__malloc_hook` = one_gadget**：把 one-gadget 写入 `__malloc_hook`，然后触发 `malloc`（例如 `nick <新伙伴>` 会分配 0x80 字节）。
   - **栈上 ROP**：把 ROP 链（`pop rdi; ret; "/bin/sh"; system`）写到主线程 `nick()` 的返回地址处。

**可靠性：** 每个连接约 50%，因为堆布局有随机性（昵称最低字节必须正好落在另一个 Partner 结构体内）。多数解题者在循环中重试。

---

### 路径 B — 堆溢出 + Toolmon `scanf` 泄漏 → PIE/Canary → `__free_hook`

**相关题解：** 370（第二份脚本）、2311、9251

该变体在 V1 之外还使用 V2（Toolmon scanf 泄漏）：

1. **泄漏 PIE 基址**：借 Toolmon 的 `scanf` 失败——动作处输入 `"+"` 打印未初始化的低 32 位栈值；金额处输入 `"+"` 打印高 32 位。拼合并减去偏移 → PIE 基址。

2. **泄漏栈 canary**（可选）：在与商店相邻时与 Toolmon 对话 → NPC 选择函数把 canary 留在栈上 → Toolmon 的 `scanf("%u %u", &x, &y)` 配合 `"+ +"` 会把它当作坐标打印出来。

3. **已知 PIE 基址后**，直接把被破坏的昵称指向 GOT 项，无需在堆上“找彩蛋”就能泄漏 libc。

4. **收尾同路径 A**：`__free_hook = system` + 释放一个 `"/bin/sh"` 昵称。

---

### 路径 C — 堆溢出 + 任务线程栈溢出

**相关题解：** 2311（标注为主路径）

1. **触发 V1** 把伙伴 0 的 `task_count` 破坏成很大的值。
2. **大幅提升伙伴 0 的 potential**（买并用大量潜力激发器），使每个训练任务产生的 HP 增益字符串足够长（约 133 字符），从而在任务线程中经 `strncat` 溢出 `notification_buf[1024]`。
3. **泄漏 canary**：经 V2（Toolmon scanf）。
4. **把 ROP payload 写入伙伴 0 的昵称缓冲区**。当线程的 `notification_buf` 溢出时，会覆盖该线程的栈帧；昵称内容（含 ROP 链）最终覆盖返回地址。
5. **恢复 canary 的 NUL 字节**：缩短昵称。
6. **等待约 1 小时**让所有排队任务完成、线程返回 → ROP 触发 → shell。

**缺点：** 极慢（约 3500 秒等待）。作者指出相比路径 A 不实用。

---

### 路径 D — 物品越界读（V3）+ 堆溢出

**相关题解：** 2311（提到过替代方案）、15989（注释掉的代码）

1. **泄漏代码/堆指针**：`item <大索引>` 会从 `g_item_names` 越界读。仅当目标内存可映射时才有效（约 1/0x2000）。
2. **接着走路径 A**，用泄漏到的指针跳过堆上“找彩蛋”阶段。

**缺点：** 因映射条件限制，非常不可靠。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|-----------|--------|-------------|
| 堆溢出（字节值 1-3） | V1：strtok + 任务队列越界 | 确定性 |
| 昵称指针破坏 | V1 溢出到达 `+0x58` | 约 50% 对齐率 |
| PIE 基址泄漏 | V2：Toolmon scanf | 确定性（获得 Toolmon 后） |
| 栈 canary 泄漏 | V2：Toolmon scanf + NPC 相邻 | 确定性 |
| 任意读/写 | 被破坏昵称 → 重叠结构体 | 对齐成功后 |
| GOT/libc 泄漏 | 对 GOT 或堆指针任意读 | 任意读写后确定性 |
| 代码执行 | `__free_hook`/`__malloc_hook` 或栈 ROP | 任意读写后确定性 |

## 偏移（pwnable.tw `libc_64.so.6`，glibc 2.23）

```python
environ     = 0x3c5f38
system      = 0x45390
__free_hook = 0x3c57a8
__malloc_hook = 0x3c3b10
bin_sh      = 0x18c177
pop_rdi     = 0x21102   # pop rdi; ret
one_gadgets = [0x4526a, 0xef6c4, 0xf0567]
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|-------------|---------------|-------|
| `370.md` | A + B | strtok → 堆上找彩蛋 → 栈 ROP | 两份完整脚本；详尽题解 |
| `821.md` | A + B | strtok → `__free_hook` | 经 scanf 泄漏 PIE、canary，大量游戏自动化 |
| `2311.md` | A（+ C） | strtok → 堆重叠 → `__malloc_hook` | 最详细的 bug 分析；也描述了线程溢出路径 |
| `3148.md` | A + B | strtok → `__free_hook` | 简洁；经 scanf 泄漏 PIE；覆盖 free_hook → system |
| `3498.md` | A | strtok → 堆重叠 → `__free_hook` | 详细数据结构分析；堆喷射 + 枚举 N |
| `7905.md` | A | strtok → 堆重叠 → `__malloc_hook` | 条理清晰；给所有伙伴改名以控制堆布局 |
| `8153.md` | A + B | strtok → `__free_hook` | 经 scanf 泄漏 PIE；经 GOT 泄漏 libc |
| `9251.md` | A + B | strtok → `__malloc_hook`（+ 线程溢出） | 记录了线程溢出路径（等 1 小时）；经图像缓存 + pthread 泄漏 |
| `15989.md` | A | strtok → 扫堆 → libc 泄漏 → `__free_hook` | 简单思路；在堆上扫 libc 指针 |
| `31599.md` | A + B | strtok → 任意读写 → `__malloc_hook` | 带数码兽追踪的大量游戏自动化 |
| `34817.md` | A | strtok → 堆重叠 → libc 泄漏 → `__malloc_hook` | 代码干净；使用 one_gadget |

## 文件

| 文件 | 说明 |
|------|-------------|
| `digimon.c` | 还原的 C 源码（逻辑等价，来自 Ghidra） |
| `exp.py` | 可用利用脚本 |
| `desc.txt` | 题目描述 |
| `artifacts/digimon.tar.gz` | 原始题目二进制 |
| `artifacts/libc_64.so.6` | 远端 libc（glibc 2.23） |
| `solution/*.md` | 社区题解文章（11 个解法） |
