# 工作流地图

> 此文件由 scripts/build_index.py 生成，请勿手工编辑。

## 阶段模型

| 阶段 | 目的 | 技能数 |
|---|---|---|
| 阶段 0 — 规划与方法论 | `phase-0-planning` | 7 |
| 阶段 1 — 资产发现与枚举 | `phase-1-discovery` | 37 |
| 阶段 2 — 漏洞验证与利用 | `phase-2-validation` | 85 |
| 阶段 3 — 攻击链与基础设施利用 | `phase-3-chaining` | 3 |
| 阶段 4 — 证据与报告 | `phase-4-reporting` | 4 |

## 入口技能

先读这些，再按阶段推进：

- `attack-patterns-reference` — `meta/attack-patterns-reference/SKILL.md`
- `cross-wave-delta-analysis` — `meta/cross-wave-delta-analysis/SKILL.md`
- `evasion-stack-guide` — `meta/evasion-stack-guide/SKILL.md`
- `google-dorks-catalog` — `meta/google-dorks-catalog/SKILL.md`
- `pentest-playbook` — `meta/pentest-playbook/SKILL.md`
- `recon-playbook` — `meta/recon-playbook/SKILL.md`
- `sector-recon-methodology` — `meta/sector-recon-methodology/SKILL.md`
- `bb-methodology` — `redteam/bb-methodology/SKILL.md`
- `osint-methodology` — `redteam/osint-methodology/SKILL.md`
- `password-spray-methodology` — `redteam/password-spray-methodology/SKILL.md`
- `redteam-mindset` — `redteam/redteam-mindset/SKILL.md`
- `wstg-web-pentest` — `redteam/wstg-web-pentest/SKILL.md`

## 各阶段技能

### 阶段 0 — 规划与方法论

- `attack-patterns-reference`
- `cross-wave-delta-analysis`
- `evasion-stack-guide`
- `google-dorks-catalog`
- `pentest-playbook`
- `recon-playbook`
- `sector-recon-methodology`

### 阶段 1 — 资产发现与枚举

- `401-403-bypass-techniques`
- `api-noauth-hunt`
- `asn-infrastructure-mapping`
- `cms-detection`
- `cors-credential-wordpress`
- `deep-invade`
- `email-security`
- `error-log-mining`
- `exchange-owa-attack`
- `flask-werkzeug-attack`
- `github-secret-hunting`
- `gitlab-public-recon`
- `hardcoded-credential-hunt`
- `http2-header-impersonation`
- `humanize-automation`
- `iot-camera-recon`
- `js-secrets-extraction`
- `jwt-attack`
- `origin-ip-discovery`
- `phpinfo-to-rce`
- `port-mass-scan`
- `port-service-discovery`
- `s3-minio-content-type-xss`
- `scada-hikvision-isapi`
- `source-leak-hunt`
- `staging-subdomain-hunt`
- `stealth-browser-launch`
- `subdomain-enumeration`
- `subdomain-takeover-hunt`
- `tls-fingerprint-impersonation`
- `unauth-api-flow-hijack`
- `vhost-enumeration`
- `visual-recon`
- `wordpress-plugin-hunt`
- `wp-mass-recon`
- `wp-plugin-rest-auth-bypass`
- `zimbra-attack`

### 阶段 2 — 漏洞验证与利用

- `apk-redteam-pipeline`
- `bb-methodology`
- `bug-bounty`
- `cloud-iam-deep`
- `cors-chain-automation`
- `enterprise-vpn-attack`
- `hunt-api-misconfig`
- `hunt-aspnet`
- `hunt-ato`
- `hunt-auth-bypass`
- `hunt-brute-force`
- `hunt-business-logic`
- `hunt-cache-poison`
- `hunt-cicd`
- `hunt-cloud-misconfig`
- `hunt-cors`
- `hunt-csrf`
- `hunt-deserialization`
- `hunt-dispatch`
- `hunt-dom`
- `hunt-file-upload`
- `hunt-firebase`
- `hunt-frameworks`
- `hunt-graphql`
- `hunt-grpc`
- `hunt-host-header`
- `hunt-http-smuggling`
- `hunt-idor`
- `hunt-information-disclosure`
- `hunt-k8s`
- `hunt-ldap`
- `hunt-lfi`
- `hunt-llm-ai`
- `hunt-mass-assignment`
- `hunt-mcp-security`
- `hunt-metrics-exposure`
- `hunt-mfa-bypass`
- `hunt-misc`
- `hunt-nestjs`
- `hunt-nextjs`
- `hunt-nosqli`
- `hunt-ntlm-info`
- `hunt-oauth`
- `hunt-open-redirect`
- `hunt-prototype-pollution`
- `hunt-race-condition`
- `hunt-rce`
- `hunt-saml`
- `hunt-schema-enumeration`
- `hunt-session`
- `hunt-sharepoint`
- `hunt-source-leak`
- `hunt-springboot`
- `hunt-sqli`
- `hunt-ssrf`
- `hunt-ssti`
- `hunt-subdomain`
- `hunt-supabase`
- `hunt-tls-network`
- `hunt-websocket`
- `hunt-wordpress`
- `hunt-write-gap`
- `hunt-xss`
- `hunt-xxe`
- `llm-prompt-injection`
- `m365-entra-attack`
- `meme-coin-audit`
- `mid-engagement-ir-detection`
- `offensive-osint`
- `okta-attack`
- `ops-proxyns`
- `osint-methodology`
- `password-spray-methodology`
- `recon-sector`
- `recon-sector-expansion`
- `redteam-mindset`
- `security-arsenal`
- `supply-chain-attack-recon`
- `triage-validation`
- `vmware-vcenter-attack`
- `web2-recon`
- `web3-audit`
- `wordpress-cors-xmlrpc-rce-chain`
- `wp-plugin-cve-hunt`
- `wstg-web-pentest`

### 阶段 3 — 攻击链与基础设施利用

- `cross-attack-chains`
- `docker-privesc`
- `wordpress-full-compromise`

### 阶段 4 — 证据与报告

- `bugcrowd-reporting`
- `evidence-hygiene`
- `redteam-report-template`
- `report-writing`

## 技能后续步骤

来自 frontmatter 的 `related_skills`：

- `cross-attack-chains` → `attack-patterns-reference`, `evidence-hygiene`, `report-writing`, `triage-validation`, `wordpress-full-compromise`
- `wordpress-full-compromise` → `cross-attack-chains`, `hunt-wordpress`, `triage-validation`, `wordpress-cors-xmlrpc-rce-chain`, `wordpress-plugin-hunt`, `xmlrpc-exploitation`
- `docker-privesc` → `port-service-discovery`, `api-noauth-hunt`
- `attack-patterns-reference` → `cors-credential-wordpress`, `cross-attack-chains`, `error-log-mining`, `js-secrets-extraction`, `phpinfo-to-rce`, `port-service-discovery`, `source-leak-hunt`, `staging-subdomain-hunt`, `wordpress-plugin-hunt`, `wp-mass-recon`, `xmlrpc-exploitation`
- `cross-wave-delta-analysis` → `recon-playbook`, `cross-attack-chains`, `cors-credential-wordpress`, `xmlrpc-exploitation`, `attack-patterns-reference`
- `evasion-stack-guide` → `tls-fingerprint-impersonation`, `http2-header-impersonation`, `stealth-browser-launch`, `humanize-automation`, `ops-proxyns`
- `pentest-playbook` → `recon-playbook`, `port-mass-scan`, `hunt-cache-poison`, `hunt-firebase`, `hunt-supabase`, `api-noauth-hunt`
- `recon-playbook` → `attack-patterns-reference`, `evidence-hygiene`, `offensive-osint`, `port-service-discovery`, `report-writing`, `subdomain-enumeration`, `triage-validation`, `source-leak-hunt`, `web2-recon`
- `sector-recon-methodology` → `recon-playbook`, `wp-mass-recon`, `attack-patterns-reference`, `subdomain-enumeration`, `cross-wave-delta-analysis`, `source-leak-hunt`
- `401-403-bypass-techniques` → `hunt-auth-bypass`, `hunt-http-smuggling`, `hunt-ssrf`, `hunt-idor`
- `api-noauth-hunt` → `hunt-firebase`, `hunt-supabase`, `js-secrets-extraction`, `port-service-discovery`, `source-leak-hunt`
- `asn-infrastructure-mapping` → `subdomain-enumeration`, `origin-ip-discovery`, `vhost-enumeration`, `port-mass-scan`
- `cms-detection` → `source-leak-hunt`, `wordpress-plugin-hunt`, `visual-recon`, `wp-mass-recon`
- `cors-credential-wordpress` → `wp-mass-recon`, `xmlrpc-exploitation`, `cross-attack-chains`, `wordpress-full-compromise`
- `deep-invade` → `wp-mass-recon`, `xmlrpc-exploitation`, `error-log-mining`, `js-secrets-extraction`, `staging-subdomain-hunt`, `wordpress-plugin-hunt`, `port-service-discovery`, `cors-credential-wordpress`, `source-leak-hunt`, `phpinfo-to-rce`
- `error-log-mining` → `deep-invade`, `source-leak-hunt`, `phpinfo-to-rce`, `wordpress-full-compromise`
- `exchange-owa-attack` → `port-service-discovery`, `zimbra-attack`, `subdomain-enumeration`
- `github-secret-hunting` → `js-secrets-extraction`, `hardcoded-credential-hunt`, `source-leak-hunt`
- `gitlab-public-recon` → `js-secrets-extraction`, `source-leak-hunt`, `api-noauth-hunt`
- `hardcoded-credential-hunt` → `api-noauth-hunt`, `js-secrets-extraction`, `source-leak-hunt`
- `http2-header-impersonation` → `tls-fingerprint-impersonation`, `stealth-browser-launch`, `evasion-stack-guide`
- `humanize-automation` → `stealth-browser-launch`, `tls-fingerprint-impersonation`, `evasion-stack-guide`
- `iot-camera-recon` → `port-mass-scan`, `port-service-discovery`
- `jwt-attack` → `api-noauth-hunt`, `js-secrets-extraction`, `hunt-firebase`, `hunt-supabase`
- `origin-ip-discovery` → `subdomain-enumeration`, `vhost-enumeration`, `port-mass-scan`
- `phpinfo-to-rce` → `source-leak-hunt`, `xmlrpc-exploitation`, `wordpress-full-compromise`, `cross-attack-chains`, `error-log-mining`
- `port-mass-scan` → `port-service-discovery`, `iot-camera-recon`, `exchange-owa-attack`
- `port-service-discovery` → `deep-invade`, `wp-mass-recon`, `cross-attack-chains`, `staging-subdomain-hunt`, `xmlrpc-exploitation`
- `s3-minio-content-type-xss` → `hunt-xss`, `hunt-cloud-misconfig`, `hunt-firebase`, `hunt-supabase`, `js-secrets-extraction`
- `scada-hikvision-isapi` → `port-service-discovery`, `hunt-ssrf`, `iot-camera-recon`, `js-secrets-extraction`
- `source-leak-hunt` → `wp-mass-recon`, `js-secrets-extraction`, `error-log-mining`, `phpinfo-to-rce`, `deep-invade`
- `staging-subdomain-hunt` → `wp-mass-recon`, `deep-invade`, `subdomain-enumeration`, `wordpress-plugin-hunt`, `js-secrets-extraction`, `source-leak-hunt`, `phpinfo-to-rce`
- `stealth-browser-launch` → `humanize-automation`, `tls-fingerprint-impersonation`, `http2-header-impersonation`, `ops-proxyns`, `evasion-stack-guide`
- `subdomain-enumeration` → `wp-mass-recon`, `staging-subdomain-hunt`, `deep-invade`, `recon-playbook`
- `subdomain-takeover-hunt` → `subdomain-enumeration`, `origin-ip-discovery`, `port-service-discovery`
- `tls-fingerprint-impersonation` → `http2-header-impersonation`, `stealth-browser-launch`, `humanize-automation`, `evasion-stack-guide`
- `unauth-api-flow-hijack` → `api-noauth-hunt`, `hardcoded-credential-hunt`, `hunt-write-gap`, `hunt-idor`
- `vhost-enumeration` → `subdomain-enumeration`, `origin-ip-discovery`, `source-leak-hunt`
- `visual-recon` → `subdomain-enumeration`, `source-leak-hunt`, `cms-detection`, `port-service-discovery`
- `wordpress-plugin-hunt` → `wp-mass-recon`, `deep-invade`, `cross-attack-chains`, `wordpress-full-compromise`, `staging-subdomain-hunt`, `xmlrpc-exploitation`
- `wp-mass-recon` → `cors-credential-wordpress`, `xmlrpc-exploitation`, `source-leak-hunt`, `wordpress-plugin-hunt`, `staging-subdomain-hunt`, `wordpress-full-compromise`, `deep-invade`, `recon-playbook`, `port-service-discovery`
- `wp-plugin-rest-auth-bypass` → `hunt-firebase`, `hunt-supabase`, `js-secrets-extraction`, `hunt-api-misconfig`, `source-leak-hunt`
- `zimbra-attack` → `exchange-owa-attack`, `port-service-discovery`, `subdomain-enumeration`
- `hunt-frameworks` → `hunt-prototype-pollution`, `hunt-mass-assignment`, `hunt-api-misconfig`, `hunt-idor`, `hunt-rce`, `hunt-ssti`, `hunt-source-leak`
- `hunt-information-disclosure` → `source-leak-hunt`, `js-secrets-extraction`, `error-log-mining`, `source-leak-hunt`
- `hunt-mass-assignment` → `hunt-api-misconfig`, `hunt-idor`, `hunt-write-gap`
- `hunt-mcp-security` → `hunt-llm-ai`, `hunt-api-misconfig`, `hunt-auth-bypass`
- `hunt-nestjs` → `hunt-graphql`, `hunt-api-misconfig`, `hunt-idor`, `hunt-write-gap`
- `hunt-prototype-pollution` → `hunt-frameworks`, `hunt-xss`, `hunt-api-misconfig`
- `hunt-wordpress` → `cors-credential-wordpress`, `error-log-mining`, `source-leak-hunt`, `staging-subdomain-hunt`, `wordpress-plugin-hunt`, `wp-plugin-rest-auth-bypass`, `xmlrpc-exploitation`
- `llm-prompt-injection` → `js-secrets-extraction`, `source-leak-hunt`, `hunt-llm-ai`, `hunt-api-misconfig`, `hunt-ssrf`
- `recon-sector` → `wp-mass-recon`, `cors-credential-wordpress`, `xmlrpc-exploitation`, `source-leak-hunt`, `error-log-mining`, `deep-invade`, `recon-playbook`
- `wordpress-cors-xmlrpc-rce-chain` → `cross-attack-chains`, `hunt-cors`, `hunt-wordpress`, `triage-validation`, `xmlrpc-exploitation`
- `wstg-web-pentest` → `web2-recon`, `hunt-idor`, `hunt-xss`, `hunt-sqli`, `hunt-ssrf`, `hunt-cors`, `hunt-session`, `hunt-mfa-bypass`, `hunt-oauth`, `hunt-saml`, `hunt-graphql`, `hunt-file-upload`, `hunt-business-logic`, `hunt-websocket`, `hunt-source-leak`, `hunt-tls-network`, `hunt-subdomain`, `hunt-brute-force`, `triage-validation`, `report-writing`, `evidence-hygiene`

## 关联缺口

以下技能既未声明 `related_skills`，也没有被任何技能引用。补全关联可提升工作流可导航性：

- `apk-redteam-pipeline`
- `bb-methodology`
- `bug-bounty`
- `bugcrowd-reporting`
- `cloud-iam-deep`
- `cors-chain-automation`
- `email-security`
- `enterprise-vpn-attack`
- `flask-werkzeug-attack`
- `google-dorks-catalog`
- `hunt-aspnet`
- `hunt-ato`
- `hunt-cicd`
- `hunt-csrf`
- `hunt-deserialization`
- `hunt-dispatch`
- `hunt-dom`
- `hunt-grpc`
- `hunt-host-header`
- `hunt-k8s`
- `hunt-ldap`
- `hunt-lfi`
- `hunt-metrics-exposure`
- `hunt-misc`
- `hunt-nextjs`
- `hunt-nosqli`
- `hunt-ntlm-info`
- `hunt-open-redirect`
- `hunt-race-condition`
- `hunt-schema-enumeration`
- `hunt-sharepoint`
- `hunt-springboot`
- `hunt-xxe`
- `m365-entra-attack`
- `meme-coin-audit`
- `mid-engagement-ir-detection`
- `okta-attack`
- `osint-methodology`
- `password-spray-methodology`
- `recon-sector-expansion`
- `redteam-mindset`
- `redteam-report-template`
- `security-arsenal`
- `supply-chain-attack-recon`
- `vmware-vcenter-attack`
- `web3-audit`
- `wp-plugin-cve-hunt`
