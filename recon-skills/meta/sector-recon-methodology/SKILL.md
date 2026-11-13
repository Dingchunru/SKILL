---
name: sector-recon-methodology
description: 选择行业板块、汇总目标、为行动批量执行侦察。
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [meta, sector, methodology, target-selection, us-companies]
  category: meta
  related_skills:
    - recon-playbook
    - wp-mass-recon
    - attack-patterns-reference
    - subdomain-enumeration
    - cross-wave-delta-analysis
    - source-leak-hunt
---

# 行业板块侦察方法论技能

用于在已授权评估中选择 WordPress 漏洞率最高的非监管行业板块、汇总公司域名列表并执行批量侦察的方法论。内容提炼自漏洞赏金与授权测试项目下对 28 个板块、600 多个美国公司域名的调研。

## When to Use

- 规划新的侦察行动且需要选择行业板块。
- 从已测试的板块扩展到新的板块。
- 通过 crt.sh 依据板块关键词构建目标列表。
- 在 `recon-playbook` 的 Phase 0 之后使用 —— 本技能提供板块情报。
- 将你的发现与各板块的基线漏洞率进行对比。

## Prerequisites

- `curl`、`jq`、`httpx` 和 `subfinder`。
- 了解美国监管格局（HIPAA、GLBA、PCI-DSS）—— 受监管板块的漏洞率接近于零。
- 具备明确并发数与速率限制的执行环境。

## How to Run

```bash
# Generate targets for a sector
SECTOR="landscaping"
curl --max-time 30 --connect-timeout 10 -sk "https://crt.sh/?q=%25.${SECTOR}%25&output=json" | jq -r '.[].name_value' | \
  sed 's/\*\.//g' | sed 's/^www\.//' | sort -u > ${SECTOR}_targets.txt
```

**脚本**：`scripts/parallel_sector_probe.py` —— OPSEC 可控的批量探测，带随机延迟，按域名生成发现文件。运行 `python3 scripts/parallel_sector_probe.py targets.txt output_dir/` 可执行完整的 WP/CORS/XMLRPC/泄漏扫描。

## 快速参考

| 层级 | 板块 | 典型 WP 率 | 最佳模式 | 备注 |
|------|---------|----------------|--------------|-------|
| 1 | 法律、园林绿化、泳池、除虫、屋顶、牙科、健身房、房地产、暖通空调、物业管理、汽修、摄影 | 30-50% | CORS + WP users | WAF 防护少，GoDaddy/Bluehost |
| 2 | 保洁、搬家、会计、化粪池、窗户、洗车、烘焙、锁匠、太阳能、烟囱、消防、宠物美容 | 20-40% | Source leaks、CORS | 混合托管，部分有 WAF |
| 3 | 汽车经销商、保险、旅游、银行、医疗 | 0-5% | N/A | 企业级 WAF，受监管，无 WP |

## 板块漏洞排名

### 第 1 层 —— 高产出（漏洞率 15-25%）

| 板块 | 漏洞率 | 主要模式 | WordPress 率 | WAF 防护 | 最佳目标 |
|--------|-----------|-------------|----------------|----------------|-------------|
| 律师事务所 | 25% | P-06 (CORS auth) | ~30% | 极少 | 独立/小型律所，GoDaddy 托管 |
| 园林绿化 | 20% | WP-01 (user enum) | ~50% | 极少 | 本地中小企业，加盟模式 |
| 泳池服务 | 20% | WP-01 (user enum) | ~45% | 极少 | 夏季季节性商家 |
| 除虫服务 | 20% | P-02 (CORS) | ~40% | 极少 | 加盟店密集 |
| 屋顶工程 | 15% | WP-01, P-17 | ~45% | 极少 | 本地承包商 |
| 牙科诊所 | 15% | WP-01 (user enum) | ~35% | 部分 | 单人牙医诊所 |
| 健身房/健身 | 15% | WP-01 (user enum) | ~40% | 部分 | CrossFit、瑜伽、武术 |
| 房地产 | 15% | P-02 (CORS) | ~40% | 部分 | 独立经纪公司 |
| 暖通空调/水管 | 14% | WP-01, P-02 | ~35% | 部分 | 加盟店密集，常见测试站（staging） |
| 物业管理 | 15% | P-02 (CORS) | ~30% | 部分 | 重 PII 板块 |\n| 汽修 | 11% | WP-01 | ~30% | 部分 | 独立门店 |
| 摄影 | 10% | WP-01 (user enum) | ~50% | 部分 | 作品集站点，多为 WP |
| 殡葬服务 | 10% | WP-01 (user enum) | ~33% | 极少 | WordPress + 在 2 个目标上发现用户枚举（funeral.example.com、memorial.example.com） |
| 养老社区 | 17% | P-02 (CORS) + XMLRPC | ~33% | Cloudflare | senior-living.example.com（80 个 XMLRPC 方法 + CORS + multicall），senior-living2.example.com（CORS）—— 测试 2/12 = 严重（CRITICAL）发现 |\n

**在已授权评估中优先考虑这些板块。** 中小型企业，通常在共享主机上自行管理 WordPress。

### 第 2 层 —— 中等产出（漏洞率 5-14%）

| 板块 | 漏洞率 | 备注 |
|--------|-----------|-------|
| 保洁服务 | 13% | 地毯、窗户、霉菌治理 |
| 搬家公司 | 6% | WP 较少，更多 SaaS 平台 |
| 会计/注册会计师 | 5% | 部分受监管、部分不受监管 —— 财务数据面临风险 |
| 化粪池服务 | 25% 源码泄漏 | 源码泄漏率极高（.env、.git、wp-config） |
| 窗户清洁 | 25% CORS | 小规模经营，DIY WP |
| 洗车 | 20% 源码泄漏 | Dockerfile、swagger、actuator 端点常见 |
| 烘焙店 | 18% CORS 通配符 | 单个目标泄漏 28 个文件 |
| 锁匠 | 20% WP users + XMLRPC | 单个目标有 38 个子域 |
| 太阳能安装商 | 极少 | 大品牌使用企业级平台 |
| 烟囱清扫 | ~10% CORS + XMLRPC | 小型家族企业，WP 常见 |
| 火灾修复 | ~10% | 加盟模式（Servpro、Belfor） |
| 宠物美容 | 20% WP users | Dogtopia、Camp Bow Wow —— 检出 WP |

### 严重发现示例（来自 248 个目标的新板块扩展）

**pool-company.example.com —— 严重（评分 9）：**
- 通过 REST API 暴露 3 个用户（wpadmin ID=1 —— 默认管理员账号）
- 已确认 CORS 凭据反射
- XMLRPC `system.multicall` 处于启用状态
- **利用链：** CORS 钓鱼 → 窃取用户数据 → 通过 XMLRPC multicall 暴力破解 wpadmin → 完全接管站点

### 第 3 层 —— 零/低产出（漏洞率 0-3%）

| 板块 | 漏洞率 | 原因 |
|--------|-----------|-----|
| 汽车经销商 | 0% | 企业级 CDK/Dealertrack 平台，非 WordPress |\n| 家具零售 | 0% | 大品牌（Ashley、Wayfair、Crate&Barrel、Pottery Barn）位于 Cloudflare/WAF 之后 —— 11/15 返回 403/429 |
| 保险 | 0% | 企业级门户，WAF 防护严密 |
| 旅行社 | 0% | SaaS（Sabre、Amadeus），非自托管 |
| 银行/信用社 | 0% | 受 GLBA 监管，强制安全要求 |
| 大型医疗 | 0% | 受 HIPAA 监管，HITRUST 认证 |
| 家政服务 | 0% | Angi/Thumbtack 平台，非自托管 |

**跳过这些板块**，除非你有特定情报表明其使用 WordPress。

## Procedure

### 第 1 步 —— 板块选择

```bash
OUTDIR="$OUTDIR/sectors"
mkdir -p "$OUTDIR"

echo "[*] Sector vulnerability potential assessment:"
echo ""

# Run quick sector probe: crt.sh → httpx → WP detection → user count
probe_sector() {
  local sector="$1"
  local file="$OUTDIR/${sector}_probe.txt"

  echo "[*] Probing sector: $sector"

  # Get domains from crt.sh
  curl -sk --max-time 20 --connect-timeout 10 "https://crt.sh/?q=%25.${sector}%25&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sed 's/^www\.//' | \
    grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | sort -u | head -50 > "$OUTDIR/${sector}_domains.txt"

  # Option C: Manual known-company list (when crt.sh/subfinder time out)
  if [[ ! -s "$OUTDIR/${sector}_domains.txt" ]]; then
    echo "  crt.sh empty — using manual known-company list"
    # Generate known US companies in this sector
    # Example: for "vet" or "pet_care" sector, known chains include:
    cat > "$OUTDIR/${sector}_domains.txt" << 'EOF'
[VET_CLINIC]
[VET_CHAIN]
[PET_RETAILER]
[VET_CORPORATE]
[VET_HOSPITAL]
[VET_SPECIALIST]
[ANIMAL_CLINIC]
[VET_CLINIC]
[TRADE_PUBLICATION]
EOF
  fi

  local total=$(wc -l < "$OUTDIR/${sector}_domains.txt")
  echo "  Domains: $total"

  # Probe with httpx
  httpx -silent -l "$OUTDIR/${sector}_domains.txt" -threads 30 -status-code -tech-detect \
    -o "$OUTDIR/${sector}_alive.txt" 2>/dev/null

  local alive=$(wc -l < "$OUTDIR/${sector}_alive.txt")
  echo "  Live: $alive"

  # WordPress count
  local wp=$(grep -ci 'wordpress' "$OUTDIR/${sector}_alive.txt" 2>/dev/null || echo 0)
  echo "  WordPress: $wp"

  # Quick user enumeration on WP targets
  local users=0
  grep -i 'wordpress' "$OUTDIR/${sector}_alive.txt" 2>/dev/null | awk '{print $1}' | head -10 | while read -r url; do
    ucount=$(curl -sk --max-time 5 --connect-timeout 5 "$url/wp-json/wp/v2/users" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo 0)
    [[ "$ucount" -gt 0 ]] && echo "    $url: $ucount users" >> "$OUTDIR/${sector}_users.txt"
  done

  local user_targets=$(wc -l < "$OUTDIR/${sector}_users.txt" 2>/dev/null || echo 0)
  echo "  User leaks: $user_targets"

  # Score the sector
  echo "$sector | domains=$total | alive=$alive | wp=$wp | user_leaks=$user_targets" >> "$OUTDIR/sector_scores.txt"
}

# Probe top candidate sectors
for sector in "landscaping" "roofing" "hvac" "pools" "plumbing" "lawn-care" \
  "pest-control" "law-firm" "dentist" "gym" "real-estate" "auto-repair" \
  "moving-company" "photography" "cleaning-service" "church"; do
  probe_sector "$sector"
  sleep 3  # Rate limit
done

echo ""
echo "[*] Sector scores:"
sort -t'|' -k5 -rn "$OUTDIR/sector_scores.txt" 2>/dev/null | head -15
```

### 第 2 步 —— 目标列表汇总

```bash
OUTDIR="$OUTDIR/sectors"

# For selected high-yield sectors, compile full target lists
SELECTED_SECTORS=("landscaping" "roofing" "pools" "plumbing" "pest-control" "law-firm")

echo "[*] Compiling target lists for selected sectors..."

> "$OUTDIR/all_targets.txt"

for sector in "${SELECTED_SECTORS[@]}"; do
  echo "  Sector: $sector"

  # crt.sh wildcard search
  curl -sk --max-time 20 --connect-timeout 10 "https://crt.sh/?q=%25.${sector}%25&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sed 's/^www\.//' | \
    grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | sort -u > "$OUTDIR/${sector}_all.txt"

  # Also try subfinder
  subfinder -d "${sector}.com" -silent 2>/dev/null >> "$OUTDIR/${sector}_all.txt"

  # Add to master list with sector label
  while read -r domain; do
    echo "$domain|$sector" >> "$OUTDIR/all_targets.txt"
  done < "$OUTDIR/${sector}_all.txt"

  sleep 2
done

# Clean: remove CDN domains, parking pages, known false positives
echo "[*] Cleaning target list..."

# Remove common false positives
grep -viE 'cloudflare|akamai|fastly|awsdns|googleusercontent|azurewebsites' "$OUTDIR/all_targets.txt" | \
  sort -u > "$OUTDIR/all_targets_clean.txt"

total=$(wc -l < "$OUTDIR/all_targets_clean.txt")
echo "[+] $total clean targets across ${#SELECTED_SECTORS[@]} sectors"
```

### 第 3 步 —— 板块基线统计

完成批量侦察后（使用 `recon-playbook`），按板块计算统计：

```bash
OUTDIR="$OUTDIR/sectors"
FINDINGS_DIR="$OUTDIR/playbook/phase2_findings"

echo "[*] Computing sector statistics..."

# Extract sector from target list
declare -A SECTOR_WP
declare -A SECTOR_CORS
declare -A SECTOR_XMLRPC
declare -A SECTOR_LEAKS
declare -A SECTOR_TOTAL

# Read target list
while IFS='|' read -r domain sector; do
  [[ -z "$sector" ]] && continue
  ((SECTOR_TOTAL[$sector]++))

  findings_file="$FINDINGS_DIR/${domain}_p2.md"
  if [[ -f "$findings_file" ]]; then
    grep -q "WordPress:" "$findings_file" && ((SECTOR_WP[$sector]++))
    grep -q "CORS:" "$findings_file" && ((SECTOR_CORS[$sector]++))
    grep -q "XMLRPC:" "$findings_file" && ((SECTOR_XMLRPC[$sector]++))
    grep -q "Source leak:" "$findings_file" && ((SECTOR_LEAKS[$sector]++))
  fi
done < "$OUTDIR/all_targets_clean.txt"

# Print sector report
echo ""
echo "## Sector Vulnerability Report"
echo ""
echo "| Sector | Targets | WP | CORS | XMLRPC | Leaks | Rate |"
echo "|--------|---------|-----|------|--------|-------|------|"

for sector in "${!SECTOR_TOTAL[@]}"; do
  total=${SECTOR_TOTAL[$sector]}
  wp=${SECTOR_WP[$sector]:-0}
  cors=${SECTOR_CORS[$sector]:-0}
  xmlrpc=${SECTOR_XMLRPC[$sector]:-0}
  leaks=${SECTOR_LEAKS[$sector]:-0}
  vulns=$((cors + xmlrpc + leaks))
  rate=$(python3 -c "print(f'{$vulns/$total*100:.1f}%')" 2>/dev/null || echo "0%")

  echo "| $sector | $total | $wp | $cors | $xmlrpc | $leaks | $rate |"
done
```

### 第 4 步 —— 板块侦察技能模板

创建新的板块专用侦察技能时，使用以下模板：

```markdown
---
name: recon-SECTORNAME
description: Reconnaissance workflow for SECTOR NAME companies.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
tags: [recon, sector, SECTORNAME]
category: recon
---

# SECTOR NAME Recon Skill

[2-3 sentence description of sector-specific attack surface]

## When to Use

- Targeting SECTOR NAME companies for recon.
- [Sector-specific trigger]

## Quick Reference

| Attack Surface | Expected Prevalence | Top Pattern |
|----------------|---------------------|-------------|
| WordPress | XX% | WP-01 |
| CORS | XX% | V1 |
| XMLRPC | XX% | WP-05 |
| Source leaks | XX% | P-17 |

## Attack Surface Signals

- [Sector-specific CMS/platform signals]
- [Common third-party integrations]
- [Typical infrastructure patterns]
- [PII/regulated data vectors]

## Sector-Specific Bypasses

- [WAF/CDN patterns for this sector]
- [Rate limiting characteristics]
- [Common security gaps]

## Real Examples

- [Target name]: [finding] (severity)
- [Target name]: [finding] (severity)

## Related Skills

- wp-mass-recon
- cors-credential-wordpress
- xmlrpc-exploitation
- source-leak-hunt
```

## Pitfalls

- **板块关键词重叠。** `pest control` 可能返回 `pest-control.example.com`（该 SaaS 服务，而非除虫公司）。按中小企业典型的域名模式进行过滤。
- **来自 CDN/云的 crt.sh 噪声。** `*.cloudfront.net` 或 `*.awsdns-*.org` 之类的域名会出现在板块的 crt.sh 查询结果中。要积极地过滤。
- **crt.sh / subfinder 超时。** 对于低流量板块或在高需求时段，这两个工具经常卡住或返回空结果。当它们失败时，退回到手工汇总该板块已知的美国公司：使用排名靠前的全国连锁品牌、加盟商目录和行业协会会员名单。对于长尾板块，已知公司名单往往比稀疏的 API 结果更有产出。
- **板块饱和。** 每个板块扫描 50 个以上目标后，你会看到相同模式。一旦基线建立，就转向新板块。
- **企业总部与加盟店。** 某些板块（暖通空调、除虫）同时存在企业母公司域名和独立的加盟店域名。加盟店域名是更容易的目标。

## Verification

- 板块漏洞率应基于至少 20 个已扫描目标。
- 每个板块至少应有一项 WordPress 检出、CORS 发现或源码泄漏，才算“有产出”。
- 零产出板块在彻底放弃之前，应使用不同的方法论重新验证。
- 板块报告应包含：目标总数、存活主机数、检出的 WP 数、发现的漏洞数、主要模式以及代表性示例。
