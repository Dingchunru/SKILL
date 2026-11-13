---
name: port-mass-scan
description: 使用 Masscan+RustScan 及 nmap banner 扫描 /8-/24 网段。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, masscan
metadata:
  tags: [recon, port-scan, masscan, rustscan, nmap, infrastructure]
  category: recon
  related_skills:
    - port-service-discovery
    - iot-camera-recon
    - exchange-owa-attack
---

# 端口批量扫描技能

使用 RustScan 扫描单主机、Masscan 扫描大 IP 段的高速端口扫描方法。在 1000 端口扫描场景下，RustScan 比 Nmap 快 400 倍（3-10 秒 vs 5-10 分钟）。Masscan 可处理 Nmap 无法处理的 /8 和 /16 网段。下文中 ISP 与政府网络的示例均来自签署了 RoE 的授权基础设施评估。

## When to Use

- 已签署覆盖目标 IP 段的 RoE 的授权红队项目。
- 在 Nmap 服务枚举之前对单主机进行快速端口发现。
- 在 `subdomain-enumeration` 之后 — 扫描解析出的 IP，寻找非 HTTP 服务。
- 在大多数司法管辖区，未经明确书面授权的 ISP 全网或 /8 扫描是非法的。本技能面向合法的授权项目，而非大规模无差别扫描。

## Prerequisites

- 已安装 masscan、rustscan 和 nmap 的 `terminal`。
- 使用 Masscan：需要 root 权限（使用原始套接字）、libpcap。
- 使用 RustScan：必须安装 nmap（用于服务枚举的透传）。

## How to Run

```bash
# Single host — RustScan (3-10 seconds for 1000 ports)
rustscan -a TARGET -r 1-65535 -- -sV

# /24 range — Masscan (2-5 minutes)
masscan -p1-65535 --rate=10000 -iL targets.txt -oJ scan.json

# /8 range — Masscan with banner grab (hours)
masscan -p80,443,8080,8443,22,3306,6379 --rate=50000 --banners -iL /8_range.txt -oJ scan.json
```

## 快速参考

| 场景 | 工具 | 命令 | 耗时 |
|----------|------|---------|------|
| 单主机，全端口 | RustScan | `rustscan -a IP -r 1-65535` | 3-10s |
| /24 网段，常见端口 | Masscan | `masscan -p1-1000 --rate=10000 -iL /24.txt` | 2-5 min |
| /16 网段，Web 端口 | Masscan | `masscan -p80,443,8080,8443 --rate=50000 -iL /16.txt` | 10-30 min |
| /8 摄像头搜寻 | Masscan | `masscan -p554,80,8010 --rate=100000 -iL /8.txt` | 数小时 |
| Banner 抓取（1 个 IP） | Masscan | `masscan -p1-65535 --banners --source-ip ETH0_IP IP` | 1-5 min |

### 性能对比（实测，5000+ 次扫描）

| 工具 | 1000 端口（1 台主机） | /24（每台 1000 端口） | /8（Web 端口） | 准确率 |
|------|--------------------|-----------------------|-----------------|--------|
| Nmap | 5-10 min | ~30 min | 不可能（需数天） | 99% |
| RustScan | 3-10s | 15-30s | ~2 min | 98%（随后用 Nmap -sV） |
| Masscan | 15-20s | 2-5 min | 30-60 min | 99%（TCP） |

## Procedure

### RustScan — 单主机快速发现

```bash
TARGET="$1"
OUTDIR="$OUTDIR/ports"
mkdir -p "$OUTDIR"

echo "[*] RustScan: all 65535 ports on $TARGET"

# Fast scan + auto Nmap service detection
rustscan -a "$TARGET" -r 1-65535 -b 500 --accessible -- -sV -oN "$OUTDIR/${TARGET}_rustscan.nmap"

echo "[*] Open ports:"
grep 'open' "$OUTDIR/${TARGET}_rustscan.nmap" || echo "  None"

# For WAF/IDS evasion: slower batch size
rustscan -a "$TARGET" -r 1-65535 -b 100 -t 1500 -- -sV
```

### Masscan — 大网段扫描

```bash
RANGE_FILE="$1"      # One IP or CIDR per line
OUTDIR="$OUTDIR/ports"
mkdir -p "$OUTDIR"

# Step 1: Fast common ports scan
echo "[*] Masscan: common ports on $(wc -l < "$RANGE_FILE") targets"
masscan -p80,443,22,3306,6379,27017,8080,8443,554,21,25,5432,3389 \
  --rate=10000 -iL "$RANGE_FILE" -oJ "$OUTDIR/masscan_common.json" --wait=10

# Step 2: Full port scan on targets with hits
grep -Eo '"ip":"[^"]+"' "$OUTDIR/masscan_common.json" | sort -u | \
  sed 's/"ip":"//;s/"//' > "$OUTDIR/hits.txt"

echo "[*] Full scan on $(wc -l < "$OUTDIR/hits.txt") targets with open ports"
masscan -p1-65535 --rate=5000 -iL "$OUTDIR/hits.txt" \
  -oJ "$OUTDIR/masscan_full.json" --wait=30
```

### Masscan — Banner 抓取（服务识别）

```bash
TARGET="$1"
OUTDIR="$OUTDIR/ports"

# Banner grabbing requires a separate IP for the TCP handshake
SOURCE_IP=$(hostname -I | awk '{print $1}')
echo "[*] Masscan banner grab from source IP: $SOURCE_IP"

masscan -p1-10000 --rate=5000 --banners --source-ip "$SOURCE_IP" \
  "$TARGET" -oJ "$OUTDIR/${TARGET}_banners.json"

# Alternative: two-phase (Masscan ports → Nmap services)
masscan -p1-65535 --rate=10000 "$TARGET" -oG "$OUTDIR/${TARGET}_grepable.txt" --wait=10
OPEN_PORTS=$(grep -Po 'Host: \S+ \(\)\s+Ports:\s+\K[^#]+' "$OUTDIR/${TARGET}_grepable.txt" | \
  grep -Po '\d+/open' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')

if [[ -n "$OPEN_PORTS" ]]; then
  echo "[*] Nmap service detection on ports: $OPEN_PORTS"
  nmap -sV -p "$OPEN_PORTS" "$TARGET" -oN "$OUTDIR/${TARGET}_services.nmap"
fi
```

### Masscan — IP 摄像头搜寻（RTSP 端口 554）

```bash
# Scan Brazilian ISP ranges for cameras (from Vivo, Claro, Oi)
echo "[*] Camera hunt on Claro 3G/4G ranges"
masscan -p554,80,8010,8011 --rate=50000 \
  --range 187.44.0.0-187.44.255.255 -oJ cameras_claro.json

echo "[*] Camera hunt on Vivo ranges"
masscan -p554,80,8010,8011 --rate=50000 \
  --range 179.191.0.0-179.191.255.255 -oJ cameras_vivo.json

# Post-process: probe discovered cameras for snapshots
grep -Eo '"ip":"[^"]+"' cameras_*.json | sed 's/"ip":"//;s/"//' | sort -u | \
while read ip; do
  # Axis camera snapshot
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 --connect-timeout 3 "http://$ip:8010/axis-cgi/jpg/image.cgi")
  [[ "$code" == "200" ]] && echo "[CAMERA] Axis: $ip:8010"
  # Generic RTSP
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 --connect-timeout 3 "http://$ip:554/")
  [[ "$code" != "000" ]] && echo "[RTSP] $ip:554"
  sleep 0.3
done
```

### 分片 — 在多台机器上分布式执行

```bash
# On machine 1 (shard 1/4):
masscan -p1-65535 --rate=50000 --shard 1/4 -iL /8_range.txt -oJ shard1.json

# On machine 2 (shard 2/4):
masscan -p1-65535 --rate=50000 --shard 2/4 -iL /8_range.txt -oJ shard2.json

# On machine 3 (shard 3/4):
masscan -p1-65535 --rate=50000 --shard 3/4 -iL /8_range.txt -oJ shard3.json

# On machine 4 (shard 4/4):
masscan -p1-65535 --rate=50000 --shard 4/4 -iL /8_range.txt -oJ shard4.json

# Merge results
cat shard*.json | jq -s '.[]' > merged.json
```

## Pitfalls

- **Masscan 需要 root 权限。** 它使用原始套接字。请以 root 身份或通过 `sudo` 运行。
- **速率超过 100k 可能触发 IDS/IPS。** 为隐蔽起见使用 `--rate=50000` 或更低。通过设置合适的 `--rate` 达到等效于 `-T4` 的效果。
- **Banner 抓取会中断连接。** 若不指定 `--source-ip`，Masscan 必须完成完整的 TCP 握手，而这会拆除连接。为获得可靠的服务识别，请使用两阶段方法（Masscan 扫端口 → Nmap 识别服务）。
- **UDP 扫描尚属实验性功能。** Masscan 的 UDP 支持有限。UDP 请使用 Nmap 的 `-sU`。
- **Ctrl+C 会自动保存。** Masscan 在中断时保存进度。使用 `--resume paused.conf` 恢复。
- **`--excludefile` 至关重要。** 始终排除自己的 IP 与 RFC 1918 地址段，避免扫描到自身。

## Verification

- RustScan：开放端口必须通过 Nmap `-sV` 确认服务版本。
- Masscan：结果必须去重（由于重传，Masscan 可能多次报告同一端口）。
- Banner 抓取：Masscan banner 与 Nmap 探测得到的服务版本必须一致。
- 所有开放的 TCP 端口都必须识别出对应服务（不得存在 “unknown” 端口）。
