# CTF Web - 认证与访问控制攻击（第二部分）

2018 年代补充内容：哈希桶碰撞认证绕过、Unicode 同形用户名碰撞、SRP A=0/A=N 绕过、ArangoDB AQL MERGE 提权。基础认证/访问控制技巧见 [auth-and-access.md](auth-and-access.md)。JWT 攻击见 [auth-jwt.md](auth-jwt.md)。OAuth/OIDC/SAML/CI-CD 见 [auth-infra.md](auth-infra.md)。

## 目录
- [std::unordered_set 哈希桶碰撞认证绕过（Hackover 2018）](#stdunordered_set-哈希桶碰撞认证绕过hackover-2018)
- [nodeprep.prepare 同形用户名碰撞（HCTF 2018）](#nodeprepprepare-同形用户名碰撞hctf-2018)
- [SRP A=0、A=N 认证绕过（OTW Advent 2018）](#srp-a0an-认证绕过otw-advent-2018)
- [ArangoDB AQL MERGE 注入提权（P.W.N. CTF 2018）](#arangodb-aql-merge-注入提权pwn-ctf-2018)

---

<a id="stdunordered_set-bucket-collision-auth-bypass-hackover-2018"></a>
## std::unordered_set 哈希桶碰撞认证绕过（Hackover 2018）

**模式：** C++ 后端把凭据哈希存在 `std::unordered_set<std::string>` 中。集合的桶索引只由 SHA-512 摘要的前几个字节派生（截断成 `size_t` 哈希）。查找循环在有限次桶探测后就提前中止（`MAX_LOOKUPS = 1000`）。用 1000+ 条与 `root` 账号落在同一桶的条目灌满该桶 —— 正确条目的比较永远不会执行，调用会用攻击者选的密码返回"找到"。

```cpp
// Vulnerable shape
std::unordered_set<std::string> users;
auto it = users.find(login_key);           // probes at most MAX_LOOKUPS
if (it != users.end()) { /* accepted */ }
```

```python
# Flood registration: every entry collides in root's bucket
import requests
for i in range(1100):
    requests.post("http://target/register",
                  data={"name": f"ro{i:04d}", "password": "ot1"})
# Log in as root with an arbitrary password — loop gives up before compare
requests.post("http://target/login", data={"name": "root", "password": "anything"})
```

**关键点：** 把摘要截断成桶索引的哈希表实现，暴露了第二原像攻击面：攻击者只需撞桶，不必撞完整哈希。若该数据结构还有探测次数上限（DoS 防护），灌满桶就能把认证检查变成无条件通过。任何以用户输入的低熵派生值为键的 `unordered_map`/`unordered_set` 都值得怀疑 —— 留意那些用 XOR 折叠压缩成 `size_t` 的 `std::hash<std::string>` 实现。

**参考：** Hackover CTF 2018 — secure-hash，writeup 11502

---

<a id="nodeprepprepare-homograph-username-collision-hctf-2018"></a>
## nodeprep.prepare 同形用户名碰撞（HCTF 2018）

**模式：** 注册流程调用 Node `node-xmpp-server` 的 `nodeprep.prepare(username)`，执行 RFC-3491/Stringprep 规范化。`ᴬ`（U+1D2C，修饰字母大写 A）这类 Unicode 字符会规范化成 ASCII `A`，于是既有的用户查找会命中已注册的 `admin`。用任意密码注册 `ᴬdmin`，查找返回真正的 admin 记录 —— 再通过密码重置流程改掉它的密码。

```text
username: \u1D2Cdmin   # ᴬdmin
nodeprep.prepare("ᴬdmin") == "admin"
```

**关键点：** 任何"查找前规范化用户名，却另外保存规范化前形式"的流水线都有问题。写入时只规范化一次，并拒绝规范化前形式与既有记录冲突的用户。需审计的库：`nodeprep`、`icu.normalize`、`unicodedata.normalize`、`golang.org/x/text/secure/precis`。

**参考：** HCTF 2018 — admin，writeup 12132

---

<a id="srp-a0-an-auth-bypass-otw-advent-2018"></a>
## SRP A=0、A=N 认证绕过（OTW Advent 2018）

**模式：** 未校验 `A % N != 0` 的 SRP（Secure Remote Password）实现，允许客户端发送 `A = 0`（或 `A = k*N`）。服务端算出 `S = (A * v^u)^b mod N = 0`，于是会话密钥为 `H(0)` —— 攻击者已知。无需密码即可登录。

```text
Client: sends A = 0
Server: computes S = 0
Session key: K = H(0)   # attacker knows this
```

**关键点：** SRP、DH 等基于群的协议必须显式校验公值非平凡。符合规范的 SRP 会拒绝 `A % N == 0`；有缺陷的实现不会。`A = N, 2N, ...` 同样有效。

**参考：** OverTheWire Advent Bonanza 2018 — writeup 12750

---

<a id="arangodb-aql-merge-injection-for-privilege-escalation-pwn-ctf-2018"></a>
## ArangoDB AQL MERGE 注入提权（P.W.N. CTF 2018）

**模式：** ArangoDB 的 AQL 接受拼接进 `FILTER` 子句的用户片段。注入 `' || 1 == 1 LET newitem = MERGE(u, {'role':'admin'}) RETURN newitem //`，就能把登录检查变成内存中的角色升级 —— 服务端返回改造后的用户对象，而不触碰真实记录。

```text
username: x' || 1 == 1 LET newitem = MERGE(u, {'role':'admin'}) RETURN newitem //
password: anything
```

**关键点：** 每种 NoSQL 数据库都有自己的注入语法。AQL 的 `MERGE` 会新建一个继承所查记录字段的文档，从而绕过只检查持久化存储的 ACL。始终使用参数化绑定变量。

**参考：** P.W.N. CTF 2018 — H!pster Startup，writeup 12067
