## Summary

<!-- What changed and why? 1-3 sentences. -->

## Library

<!-- Which part of the repo does this touch? -->

- [ ] `ctf-skills/`
- [ ] `recon-skills/`
- [ ] 仓库级（`.github/`、`AGENTS.md`）

## Source

<!-- If adding techniques from writeups, link them here. Remove if not applicable. -->

-

## Checklist

ctf-skills（在 `ctf-skills/` 下执行）：

- [ ] `python scripts/build_skill_catalog.py --check`
- [ ] `python -m pytest tests/ -v`
- [ ] `python3 scripts/skill_security_auditor.py <skill-dir> --strict`

recon-skills（在 `recon-skills/` 下执行）：

- [ ] `python3 scripts/validate_skills.py`
- [ ] `python3 scripts/build_index.py --check`

通用：

- [ ] 生成物与源文件同一次提交（`ctf-skills/*/catalog.*`、`recon-skills/dist/`）
- [ ] 内容变更已递增 `version`、刷新 `revision_date`、记录 `CHANGELOG.md`（recon）
- [ ] 无凭据、真实 IP、客户证据、非 `example.com` 域名
