---
name: exchange-owa-attack
description: 存在邮件子域时，对 Exchange/OWA 进行 NTLM AD 泄漏与喷洒攻击。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, exchange, OWA, NTLM, ActiveDirectory, password-spray]
  category: recon
  related_skills:
    - port-service-discovery
    - zimbra-attack
    - subdomain-enumeration
---

# Exchange/OWA 攻击技能

Exchange Outlook Web Access 侦察，涵盖端点测绘、NTLM Type-2 元数据、认证控制与
版本证据。密码或锁定策略测试需要明确授权与经批准的身份。

## When to Use

- 目标拥有 `owa.`、`mail.`、`webmail.`、`exchange.` 或 `autodiscover.` 子域。
- crt.sh 揭示与 Exchange 相关的 SAN 名称（`mail.domain.com`、`autodiscover.domain.com`）。
- 443 端口返回 NTLM `WWW-Authenticate: Negotiate` 或 `WWW-Authenticate: NTLM`。
- 在 `subdomain-enumeration` 发现与邮件相关的主机之后。
- 在 `port-service-discovery` 发现 443 端口上的 HTTPS 且带有 Exchange 指纹之后。

## Prerequisites

- 带 curl、python3 的 `terminal`。
- 目标 Exchange/OWA URL。
- 若要执行密码喷洒：用户名列表（来自侦察）与口令候选。

## How to Run

```bash
# Quick Exchange detection
curl --max-time 30 --connect-timeout 10 -skI "https://TARGET/owa/" | grep -iE "x-owa-version|x-feserver|exchange|microsoft"

# NTLM challenge capture (AD domain leak)
curl --max-time 30 --connect-timeout 10 -skI "https://TARGET/owa/" -H "Authorization: Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" | grep -i "www-authenticate"
```

## 快速参考

| 技术 | 揭示内容 | 严重级别 |
|-----------|---------------|---------|
| NTLM Type-2 解码 | AD 域、NetBIOS 名称、计算机名、AD 时间戳 | 高 |
| OWA 版本响应头 | Exchange 版本、CU 级别、补丁状态 | 中 |
| `/owa/auth/logon.aspx` | 登录页面、暴力破解攻击面 | 中 |
| `/ecp/` | Exchange 管理中心（管理员） | 高 |
| `/ews/` | Exchange Web Services（SOAP API） | 中 |
| `/autodiscover/` | Autodiscover 配置 | 中 |
| `/mapi/` | MAPI over HTTP | 低 |
| `/Microsoft-Server-ActiveSync` | 移动设备同步 | 中 |
| `/rpc/` | Outlook Anywhere（RPC over HTTP） | 低 |

## Procedure

### 阶段 1 — Exchange 检测与指纹识别

```bash
TARGET="$1"
OUTDIR="$OUTDIR/exchange"
mkdir -p "$OUTDIR"

echo "[*] Exchange detection on $TARGET"

# OWA probe
OWA_RESP=$(curl -skI --max-time 10 --connect-timeout 10 "https://$TARGET/owa/" 2>/dev/null)
echo "$OWA_RESP" > "$OUTDIR/owa_headers.txt"

# Version extraction
X_OWA=$(echo "$OWA_RESP" | grep -i "x-owa-version" | sed 's/.*: //')
X_FE=$(echo "$OWA_RESP" | grep -i "x-feserver" | sed 's/.*: //')

if [[ -n "$X_OWA" ]]; then
  echo "[+] Exchange confirmed — OWA Version: $X_OWA"
  echo "  Frontend server: ${X_FE:-unknown}"

  # Map version to CU
  # 15.1.x = Exchange 2016, 15.2.x = Exchange 2019
  MAJOR=$(echo "$X_OWA" | cut -d. -f1-2)
  if [[ "$MAJOR" == "15.1" ]]; then
    echo "  Product: Exchange 2016"
  elif [[ "$MAJOR" == "15.2" ]]; then
    echo "  Product: Exchange 2019"
  fi
else
  echo "[-] No OWA version header — may not be Exchange"
fi

# Key endpoints probe
declare -A EX_ENDPOINTS
EX_ENDPOINTS["/owa/auth/logon.aspx"]="Login page"
EX_ENDPOINTS["/ecp/"]="Exchange Control Panel (admin)"
EX_ENDPOINTS["/ews/exchange.asmx"]="Exchange Web Services (SOAP)"
EX_ENDPOINTS["/autodiscover/autodiscover.xml"]="Autodiscover"
EX_ENDPOINTS["/mapi/emsmdb/"]="MAPI over HTTP"
EX_ENDPOINTS["/Microsoft-Server-ActiveSync/"]="ActiveSync"
EX_ENDPOINTS["/rpc/rpcproxy.dll"]="Outlook Anywhere"
EX_ENDPOINTS["/owa/healthcheck.htm"]="Health check"

echo ""
echo "[*] Endpoint probe:"
for ep in "${!EX_ENDPOINTS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "https://$TARGET$ep")
  [[ "$code" == "200" ]] && echo "  [OPEN] $ep — ${EX_ENDPOINTS[$ep]}"
  [[ "$code" == "302" ]] && echo "  [REDIR] $ep — ${EX_ENDPOINTS[$ep]}"
  [[ "$code" == "401" ]] && echo "  [AUTH] $ep — ${EX_ENDPOINTS[$ep]}"
done
```

### 阶段 2 — NTLM Type-2 挑战捕获与解码

```bash
TARGET="$1"

echo "[*] NTLM challenge capture from $TARGET"

# Send NTLM Type-1 (Negotiate) message via Authorization header
NTLM_RESP=$(curl -skI --max-time 10 --connect-timeout 10 "https://$TARGET/owa/" \
  -H "Authorization: Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" 2>/dev/null)

WWW_AUTH=$(echo "$NTLM_RESP" | grep -i "www-authenticate: negotiate" | sed 's/.*negotiate //i' | tr -d '\r\n ')

if [[ -n "$WWW_AUTH" ]]; then
  echo "[+] NTLM Type-2 challenge received!"
  echo "  Raw: ${WWW_AUTH:0:80}..."

  # Decode with Python (extract AV_PAIRS structure)
  echo "$WWW_AUTH" | python3 -c "
import base64, struct, sys

data = base64.b64decode(sys.stdin.read().strip())

# NTLM Type-2 message structure:
# Offset 12: Target Name
# Offset 16: Negotiate Flags
# Offset 20: Server Challenge
# Offset 28: Reserved
# Offset 32: Target Info (AV_PAIRS)

# Parse Target Info
if len(data) > 40:
    target_info_offset = struct.unpack_from('<I', data, 40)[0]
    target_info_len = struct.unpack_from('<I', data, 44)[0]
    av_pairs = data[target_info_offset:target_info_offset + target_info_len]

    print()
    print('=== NTLM Type-2 Decoded ===')
    pos = 0
    while pos < len(av_pairs) - 4:
        av_type = struct.unpack_from('<H', av_pairs, pos)[0]
        av_len = struct.unpack_from('<H', av_pairs, pos + 2)[0]
        av_value = av_pairs[pos + 4:pos + 4 + av_len]

        # AV_PAIR types
        types = {
            1: 'NetBIOS Computer Name',
            2: 'NetBIOS Domain Name',
            3: 'DNS Computer Name',
            4: 'DNS Domain Name',
            5: 'DNS Tree Name',
            6: 'Product Version',
            7: 'Timestamp',
        }
        label = types.get(av_type, f'Unknown({av_type})')
        if av_type in (1, 2, 3, 4, 5):
            value = av_value.decode('utf-16-le', errors='replace')
            print(f'  {label}: {value}')
        elif av_type == 7:
            ts = struct.unpack_from('<Q', av_value)[0]
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(ts / 10000000 - 11644473600, tz=timezone.utc)
            print(f'  Timestamp: {dt}')
        else:
            print(f'  {label}: {av_value.hex()}')

        pos += 4 + av_len
else:
    print('  No AV_PAIRS in response')
"
fi
```

### 阶段 3 — 密码喷洒攻击面评估

```bash
TARGET="$1"

echo "[*] Password spray surface assessment"

# Check for account lockout by testing rapid logins with invalid password
echo "[*] Rate limiting test (5 rapid attempts with wrong password)..."
for i in $(seq 1 5); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 --connect-timeout 10 \
    -X POST "https://$TARGET/owa/auth.owa" \
    -d "destination=https://$TARGET/owa/&username=testuser$i@domain.com&password=WrongPass123!" 2>/dev/null)
  echo "  Attempt $i: HTTP $code"
done

# Check if Basic Auth is enabled (rare post-2022, but exists)
BASIC_AUTH=$(curl -skI --max-time 5 --connect-timeout 5 "https://$TARGET/owa/" \
  -H "Authorization: Basic dGVzdDp0ZXN0" 2>/dev/null | grep -i "www-authenticate.*basic")
if [[ -n "$BASIC_AUTH" ]]; then
  echo "  [!] Basic Auth ENABLED — easier brute force vector"
fi

# Check healthcheck endpoint (sometimes exposes version/config)
HEALTH=$(curl -sk --max-time 5 --connect-timeout 5 "https://$TARGET/owa/healthcheck.htm" 2>/dev/null)
if [[ -n "$HEALTH" ]] && echo "$HEALTH" | grep -qi "200 ok"; then
  echo "  [+] Healthcheck accessible — server status exposed"
fi
```

### 阶段 4 — ADFS/Office 365 侦察（混合环境）

```bash
TARGET_DOMAIN="$1"  # e.g., company.com

echo "[*] ADFS/Office 365 recon on $TARGET_DOMAIN"

# Check for ADFS
ADFS_URL="https://sts.$TARGET_DOMAIN/adfs/ls/IdpInitiatedSignOn.aspx"
ADFS_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "$ADFS_URL")
[[ "$ADFS_CODE" == "200" || "$ADFS_CODE" == "302" ]] && echo "  [+] ADFS: $ADFS_URL (HTTP $ADFS_CODE)"

# Check Office 365 tenant
O365_XML=$(curl -sk --max-time 5 --connect-timeout 5 "https://login.microsoftonline.com/getuserrealm.srf?login=user@$TARGET_DOMAIN&xml=1" 2>/dev/null)
if echo "$O365_XML" | grep -qi "Federated\|Managed"; then
  echo "  [+] Office 365 tenant: $(echo "$O365_XML" | grep -Po '<NameSpaceType>\K[^<]+')"
  echo "  $(echo "$O365_XML" | grep -Po '<DomainName>\K[^<]+')"
fi

# Autodiscover (leaks internal server names)
AUTODISCOVER=$(curl -sk --max-time 10 --connect-timeout 10 "https://autodiscover.$TARGET_DOMAIN/autodiscover/autodiscover.xml" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>user@'$TARGET_DOMAIN'</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>' 2>/dev/null)
if echo "$AUTODISCOVER" | grep -qi "server\|internal"; then
  echo "  [+] Autodiscover response — internal server names leaked"
  echo "$AUTODISCOVER" | grep -Po '(?:<Server>|<InternalRpcClientServer>|<ASUrl>)[^<]+' | head -5
fi
```

## Pitfalls

- **NTLM 中继需要特定的网络位置。** 除非你控制一台 Exchange 服务器可访问的机器，否则 NTLM 中继无法远程利用。
- **现代 Exchange（Exchange Online、2019+）默认阻止 Basic Auth。** 如果 Basic 被阻止，请用现代认证（OAuth2）测试。
- **账户锁定策略各不相同。** 在喷洒前先用一个已知错误的口令进行测试。
- **ADFS 不是 Exchange。** ADFS 是拥有自身攻击面（SAML、WS-Trust）的独立服务。

## Verification

- NTLM Type-2 必须至少能解码出 DNS Domain Name 与 NetBIOS Domain Name。
- OWA 版本必须从 `X-OWA-Version` 响应头中提取。
- 密码喷洒攻击面：确认没有速率限制（5 次快速尝试均返回相同的 HTTP 状态码）。
- Autodiscover 必须返回内部服务器名称（而不仅是外部 URL）。
- 记录：Exchange 版本、AD 域、NetBIOS 名称、计算机名、速率限制状态。

---

## 相关技能

- **`password-spray-methodology`** — 跨所有协议的通用密码喷洒流程 + 错误码差异对比
