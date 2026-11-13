# SKILL 仓库维护规范

> 作用域：`D:\SKILL` 根仓（GitHub `Dingchunru/SKILL`）及其两个子库 `recon-skills`、`ctf-skills`。
> 定位：本仓是 skill 的**源仓库**，不是 agent 运行时配置仓库。
> 安全边界：仅用于授权安全测试、CTF 竞赛与教学研究。禁止提交真实凭据、客户证据、线上资产清单、私有网络拓扑。各库的授权声明不得删除或弱化。

本文件只补充"两个 skill 库如何在一个仓库里共存"的规则。单个 skill 怎么写，以子库自己的契约文档为准。

---

## 0. 文档地图与优先级

| 文档 | 管什么 | 何时读 |
|---|---|---|
| `AGENTS.md`（本文件） | 跨库边界、git、发布、四端同步、冲突裁决 | 每次改仓库前 |
| `recon-skills/AGENTS.md` | recon 库的范围、目录、贡献流程 | 新增/修改 recon skill |
| `recon-skills/STYLE.md` | recon `SKILL.md` 质量基线、frontmatter、命令规范 | 写 recon `SKILL.md` |
| `recon-skills/README.md` | recon 目录导览、入口 skill、`dist/` 用法 | 选型、发布 |
| `recon-skills/SOUL.md`、`STUDY.md` | 方法论与学习材料 | 需要背景时 |
| `ctf-skills/CONTRIBUTING.md` | ctf 技术文档格式、frontmatter 字段、测试与 PR 流程 | 新增/修改 ctf 内容 |
| `ctf-skills/README.md` | ctf 三个分类的能力清单与安装方式 | 选型、发布 |
| `ctf-skills/SECURITY.md` | 负责任使用与漏洞披露 | 任何 ctf 内容变更 |
| 各 skill 的 `SKILL.md` | 具体技术与验证方法 | 执行任务时 |

优先级：

1. 技术与格式细节：子库文档 > 本文件。
2. git、发布、四端同步、跨库引用：本文件 > 子库文档。
3. 两边冲突且无法按前两条裁决时，停下来问维护者，不要自行统一。

---

## 1. 两个子库的分工

| 维度 | `recon-skills` | `ctf-skills` |
|---|---|---|
| 场景 | 授权目标的外部侦察、漏洞验证、证据与报告 | CTF 题目环境下的解题 |
| 顶层分类 | `chains/` `infra/` `meta/` `recon/` `redteam/` | `ctf-web/` `ctf-pwn/` `ctf-reverse/` |
| skill 形态 | 每个目录一个 `SKILL.md`（当前 136 个） | 每个分类一个 `SKILL.md` + 大量技术参考文档（当前 3 个分类） |
| 消费方式 | 按需读取；`dist/` 提供机器可读路由 | `SKILL.md` 做入口，`catalog.md/json` 按需加载 |
| 自带校验 | `scripts/validate_skills.py`、`scripts/build_index.py` | `pytest`、`scripts/build_skill_catalog.py`、pre-commit；原 GitHub Actions 在 vendoring 后不再触发 |
| 上游来源 | `uphiago/recon-skills`（本仓已汉化） | `ljagiello/ctf-skills`（本仓已汉化并裁剪） |

边界规则：

- 同一漏洞技术（SQLi、SSRF、JWT 等）可以两边都有，但写法必须分工：recon 写"真实目标上的发现 → 验证 → 证据 → 报告"；ctf 写"题目环境下的最短解题路径 → flag"。
- 不要把 CTF 的取巧 payload 当成生产环境验证方法，也不要把客户报告流程塞进 CTF 参考文档。
- 两库需要互相指路时，在正文写相对链接或文字说明；不要建立跨库 `related_skills`（见第 7 节）。

---

## 2. 目录与文件规则

```text
D:\SKILL\
|-- AGENTS.md                  # 本文件
|-- recon-skills\
|   |-- AGENTS.md  STYLE.md  README.md  SOUL.md  STUDY.md  CHANGELOG.md
|   |-- <category>\<skill-name>\SKILL.md
|   |-- <category>\<skill-name>\references|scripts|templates\...
|   |-- scripts\               # validate_skills.py / build_index.py / find_skill.py
|   `-- dist\                  # 生成物，禁止手改
`-- ctf-skills\                # 已去嵌套，普通目录，随根仓提交
    |-- CONTRIBUTING.md  README.md  SECURITY.md
    |-- ctf-web|ctf-pwn|ctf-reverse\
    |   |-- SKILL.md
    |   |-- catalog.md  catalog.json          # 生成物，禁止手改
    |   `-- <technique>.md ...
    |-- scripts\               # build_skill_catalog.py / install_ctf_tools.sh / skill_security_auditor.py
    |-- tests\  evals\
    `-- .github\workflows\     # CI
```

- 一个 skill 必须是一个独立目录，目录名与 frontmatter `name` 一致（kebab-case）。
- 支撑材料放 skill 同目录：`references/`、`scripts/`、`templates/`。`SKILL.md` 用相对链接引用它们，保证整个目录可复制、可移植。
- 生成物与源文件分离。recon 的 `dist/*`、ctf 的 `<skill>/catalog.md`、`<skill>/catalog.json`、`ctf-pwn/pwnable-tw/README.md` 都由脚本生成，禁止手工编辑。
- 不提交大体积 payload、工具副本、虚拟环境、评测产物、扫描输出。遵循各子库 `.gitignore`。
- 内容中不得出现私有主机名、内网 IP、容器名、挂载路径、运行时控制 API；工具名、协议名、公开域名除外。

---

## 3. `SKILL.md` 契约

### 3.1 两库共同要求

- YAML frontmatter 必须以 `---` 开始并以 `---` 结束。
- `name`：kebab-case，尽量全局唯一；与所在目录名一致。
- `description`：写"何时用、何时不用"，包含触发条件和边界，不写营销词。
- 命令必须可执行、有超时、有输出目录、声明依赖、权限和副作用。
- 必须有验证标准。未在真实目标或真实题目上验证过的结论，要明确标注。
- 正文用中文（本仓现状）；字段名、工具名、命令、路径、HTTP 头保持英文原样；上游作者与来源信息保留。
- 不复制大段 payload 目录，链接到拥有该内容的 skill 或本地参考文件。

### 3.2 recon 专用契约

以 `recon-skills/STYLE.md` 为准，要点：

| 字段/章节 | 要求 |
|---|---|
| `name` | kebab-case，唯一 |
| `description` | 一句话，不超过 60 字符，句号结尾 |
| `version` | 语义化版本，内容变更时递增 |
| `revision_date` | `YYYY-MM-DD` |
| `license` | `MIT` |
| `platforms` | 如 `[linux]` |
| `compatibility` | 依赖的工具 |
| `metadata.tags` | 检索标签 |
| `metadata.category` | 必须与所在顶层目录一致：`meta`/`recon`/`redteam`/`chains`/`infra` |
| `metadata.related_skills` | 只写本库已存在的 skill `name` |

固定章节，缺一不可：

1. `## When to Use`
2. `## Prerequisites`
3. `## How to Run`
4. `## Procedure`
5. `## Pitfalls`
6. `## Verification`

### 3.3 ctf 专用契约

以 `ctf-skills/CONTRIBUTING.md` 和 `tests/test_skill_frontmatter.py` 为准。**测试实际强制**的项：

| 字段 | 强制规则 |
|---|---|
| `name` | 必须与目录名完全一致 |
| `description` | 长度大于 20 字符 |
| `license` | 必须为 `MIT` |
| `compatibility` | 必填，自由文本 |
| `allowed-tools` | 空格分隔，只能出现 `Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill` |
| `metadata.user-invocable` | 必须为字符串 `"true"` 或 `"false"` |
| `metadata.argument-hint` | 当 `user-invocable: "true"` 时必填 |

`CONTRIBUTING.md` 里的"description 以第三人称动词开头"目前只是写作约定，测试并未强制；新增内容仍按约定写。

章节结构按 CTF 工作流组织，不要套用 recon 的六段式：

- 定位（适用/不适用）
- 标准产出（Definition of Done）
- 解题工作流
- 检索与路由
- 参考文档（按需加载）

新增技术文档时：

1. 选对主题文件；没有合适文件再新建。
2. 技术用 `##` 二级标题，代码块带语言标记，主机名用 `example.com` / `attacker.com` 等占位。
3. 标注来源 CTF/年份（已知时）。
4. 更新 `SKILL.md` 的参考文档列表。
5. 更新 `README.md` 对应分类的 Files 数与描述。
6. 重新生成 catalog（见 4.2）。

### 3.4 差异速查

| 项 | recon | ctf |
|---|---|---|
| 新增粒度 | 新目录 + `SKILL.md` | 通常是往已有分类加技术文档 |
| 章节 | 固定六段 | CTF 解题工作流 |
| 版本字段 | `version` + `revision_date` | 无 per-skill 版本 |
| 工具声明 | `compatibility` 文本 | `allowed-tools` 白名单 |
| 生成物 | `dist/` | `<skill>/catalog.md`、`catalog.json`、pwnable README |
| 校验 | Python 脚本 | pytest + pre-commit + CI |

---

## 4. 变更流程

### 4.1 recon 库

```bash
cd recon-skills
# 新增或修改 SKILL.md 后
python3 scripts/validate_skills.py
python3 scripts/build_index.py
python3 scripts/build_index.py --check
python3 scripts/find_skill.py <关键词>
git diff --check
git diff --stat
```

- `SKILL.md` 与 `dist/` 生成物必须同一次提交。
- 内容变更同时递增 `version`、更新 `revision_date`，并在 `CHANGELOG.md` 记录。

### 4.2 ctf 库

```bash
cd ctf-skills
# 新增或修改技术文档后
python scripts/build_skill_catalog.py
python scripts/build_skill_catalog.py --check
python -m pytest tests/ -v
pre-commit run --all-files
python3 scripts/skill_security_auditor.py <skill> --strict --json
```

新增分类还必须同步：

- 根级目录与 `SKILL.md`；
- `README.md` 的 Skills 表；
- `.opencode/opencode.json` 的 `references`；
- `.opencode/agents/ctf-<name>.md`；
- `.github/labeler.yml`（如有分类标签）；
- `CONTRIBUTING.md`（如涉及新约定）；
- `scripts/install_ctf_tools.sh`（如需新工具）。

删除或裁剪分类时，反向执行上述清单，并 `grep` 旧分类名确认没有悬空引用（`tests/`、`SKILL.md` 交叉引用、catalog 都要覆盖）。

### 4.3 生成物规则

| 源 | 生成物 | 生成命令 | 校验 |
|---|---|---|---|
| recon 各 `SKILL.md` | `recon-skills/dist/index.json`、`routing.json`、`workflows.json`、`CATALOG.md`、`WORKFLOWS.md`、`llms.txt` | `python3 scripts/build_index.py` | `--check` |
| ctf 各分类内容 | `<skill>/catalog.md`、`<skill>/catalog.json`、`ctf-pwn/pwnable-tw/README.md` | `python scripts/build_skill_catalog.py` | `--check`（CI 强制执行） |

生成物必须与源文件在同一次提交里。禁止手改；需要改内容就改源文件再重新生成。

---

## 5. 证据与结论标准

### 5.1 recon

HTTP 状态码、版本号、banner 通常不构成漏洞证明。必须给出语义证据：

| 场景 | 最低验证标准 |
|---|---|
| CORS 带凭据 | 同时满足 `Access-Control-Allow-Origin` 回显可信/反射源 + `Access-Control-Allow-Credentials: true` + 凭据化数据访问场景 |
| XML-RPC | 响应体包含 `methodResponse` |
| 目录列表 | 响应体包含 `Index of` |
| 源码/配置泄露 | 包含敏感内容模式（`DB_`、`APP_`、`_KEY`、`_SECRET` 等），空 200 不算 |
| 暴露路径 | 有实际有意义的内容，不能只看 200 |
| 停放域名 | `/robots.txt` 与 `/.env` 都 200 且内容相同，按停放处理 |
| 配置缺陷 | 与"已证明影响"分开写，不得混为一谈 |

### 5.2 ctf

每篇可交付内容必须有 Definition of Done：

1. **判定**：漏洞类型 + 根因（函数、地址、偏移）。
2. **利用脚本**：可直接运行的 `exp.py`，含目标地址、libc 版本/偏移、工具版本。
3. **验证**：实际拿到的 flag；失败时给出精确失败点（崩溃地址、缺失的泄露或原语）。
4. **复现说明**：保护机制、seccomp 策略、依赖文件与运行命令。

静态信号（`checksec` 结果、可疑函数、旧版本号）只能作为线索，不能当成可利用结论。

### 5.3 两库通用红线

- 不把"配置弱点"写成"已利用"；不把"疑似"写成"确认"。
- 未复现的结论必须标注验证状态。
- 记录请求、响应、时间、范围、工具版本与脱敏决策；原始证据留在仓库外。

---

## 6. 命令与安全规范

- 所有 `curl` 加 `--max-time`；循环里加 `sleep`；必要时 `2>/dev/null`。
- DNS 批量解析优先用 `dnsx` 等批处理工具，不要 `while read` 里逐条 `dig`。
- 生成文件统一放 `${OUTPUT_DIR:-./output}`。
- 扫描与请求要控制并发和速率，声明是否 root、是否需要 raw socket、浏览器、代理或凭据。
- 任何创建、修改、删除、发送、上传、购买或改变认证状态的操作，都必须在命令旁明确写出"需要授权确认"。
- 只测试自己拥有或获得书面授权的目标；CTF 内容只在比赛、靶场或教学环境使用。
- 不提交真实凭据、PII、客户证据、线上恶意基础设施链接。

---

## 7. 跨库引用与命名

- `related_skills` 只写**本库内**已存在的 `name`；校验器按单库解析。
- 跨库指路写在正文里，例如"需要 CTF 视角见 `ctf-skills/ctf-web/SKILL.md`"；不要写进 `related_skills`。
- 同一能力两边都有时，各自独立维护，不互相复制大段内容；需要共享的 payload 目录保持外置并链接。
- 全局命名优先唯一。确实需要同名时，用 `recon-` / `ctf-` 前缀区分。
- 不为了"看起来统一"把两库的 `SKILL.md` 结构改成一样；两套契约是刻意保留的。

---

## 8. 校验与 CI

### recon（本地校验，无 CI）

```bash
cd recon-skills
python3 scripts/validate_skills.py      # 结构错误、重复 name、断链、运行时耦合
python3 scripts/build_index.py --check  # 生成物是否过期
```

`validate_skills.py` 的错误必须修复；历史风格债以 warning 输出，可增量改进，但新增内容不得新增 warning。

### ctf（本地生效，CI 需迁移）

`ctf-skills/.github/workflows/` 只有在独立仓库里才会触发；并入根仓后，根级没有 `.github`，这些 workflow 不会运行。当前必须本地执行：

```bash
cd ctf-skills
python scripts/build_skill_catalog.py --check
python -m pytest tests/ -v
pre-commit run --all-files
```

原 CI 检查项（供迁移时参考）：

| 工作流 | 检查内容 |
|---|---|
| Tests | `build_skill_catalog.py --check` + `pytest tests/` |
| Markdown Lint | markdownlint-cli2 |
| Skill Security Audit | 危险模式扫描，Critical 失败 |
| Link Checker | lychee 检查 URL |
| Lint Scripts | ruff + shellcheck |

如果要把 CI 恢复到根仓，需把相关 workflow 移到根级 `.github/workflows/` 并调整路径；迁移前不要假设 PR 检查会自动运行。

- 不得通过修改 workflow、放宽 lint 配置或跳过 pre-commit 来让检查通过。
- `<!-- audit-ok -->` 只用于有意保留的攻击技术说明，并需在 PR 中说明理由。

---

## 9. Git 规范（当前最重要）

### 9.1 现状（2026-11-13）

- 根仓 `Dingchunru/SKILL`，分支 `main`。
- `recon-skills/` 是根仓普通文件，直接随根仓提交。
- `ctf-skills/` 的嵌套 `.git` 已被移除，工作区是普通目录。
- 2026-11-13 已执行 `git rm --cached ctf-skills` 并把整个目录作为普通文件暂存（204 个文件），根索引中不再有 gitlink。**下一次根仓提交后彻底完成。**
- 原嵌套仓的 remote 是 `Dingchunru/CTF`（上游来源 `ljagiello/ctf-skills`）；本地 `.git` 删除后，历史只能从该 remote 重新克隆。

### 9.2 收尾记录与同类问题处理

本次收尾已执行（尚未提交）：

```bash
cd /d/SKILL
git rm --cached ctf-skills        # 移除索引中的 gitlink，不动工作区文件
git add ctf-skills                # 以普通文件暂存整个目录
git status                        # 复核：应出现大量 ctf-skills/** 新增
# 下一步由维护者确认后提交
git commit -m "chore: vendor ctf-skills into root repo"
```

如果以后再遇到 gitlink 或 submodule 残留，按同样步骤转换；转换前先确认子库没有未提交改动，否则会丢失那部分工作。

### 9.3 日常提交

```bash
cd /d/SKILL
git status
git add <具体路径>                 # 例如 recon-skills/recon/xxx/SKILL.md
git commit -m "..."
```

规则：

- 一个逻辑变更尽量只涉及一个子库；同时改两库时，提交信息要写明两边。
- `git add` 用具体路径，不用 `git add -A` / `git add .`；提交前用 `git status` 复核暂存内容。
- 不自动 commit、push、发布，除非维护者明确要求。

### 9.4 禁止操作

- 不要恢复 `ctf-skills/.git`、不要重新引入 gitlink 或 submodule（除非明确决定改回 submodule 方案）。
- 不要在 gitlink 收尾完成前提交根仓并认为 ctf 改动已入库。
- 不要用 `git reset --hard`、`git checkout --` 清理未提交内容；先确认是否是他人的在途工作。
- 不要执行 `git submodule update --remote` 覆盖本地的汉化和裁剪。

### 9.5 根仓卫生

- `.idea/` 当前未被跟踪也未被忽略；根仓暂无 `.gitignore`。建议后续补根级 `.gitignore`（本条只是待办，未执行）。
- 任何提交前检查是否混入凭据、客户数据、扫描输出、虚拟环境或大文件。

---

## 10. 四端 agent 发布

本仓是唯一真源。不要在 agent 的 skill 目录里直接改内容。

本机四个目标目录：

```text
C:\Users\admin\.qoder\skills\<name>\
C:\Users\admin\.dsh\skills\<name>\
C:\Users\admin\.claude\skills\<name>\
C:\Users\admin\.trae-cn\skills\<name>\
```

发布规则：

1. 以 skill 目录为单位整体复制，不能只拷 `SKILL.md`；`SKILL.md` 通过相对链接引用同目录的 `references/`、`scripts/`，只拷入口会断链。
2. 四个目录各一份，内容必须完全一致。
3. 用 md5 校验四份的 `SKILL.md` 以及被引用的文件：

```bash
find . -type f -not -path "*/.git/*" -exec md5sum {} + | sort -k2
```

4. 发布时记录来源：仓库、分支、commit、日期。改动后先提交源仓，再同步四端。
5. 不要同步 `evals/`、`tests/`、`.github/`、`node_modules/`、`output/` 等运行与评测产物；recon 的 `dist/` 是否需要取决于目标 agent，至少保证 `SKILL.md` 引用的文件都在。

---

## 11. 提交前检查清单

- [ ] 只改了申请范围内的文件；没有顺手重构其他 skill。
- [ ] 两库的目录与命名规则符合第 2 节。
- [ ] frontmatter 符合对应子库契约（recon: 3.2；ctf: 3.3）。
- [ ] 必填章节齐全，命令可执行，含超时与输出目录。
- [ ] 结论有验证证据；未验证项已标注。
- [ ] 没有真实凭据、客户证据、内网地址、私有拓扑。
- [ ] 生成物已重新生成，且与源文件同一次提交。
- [ ] recon：`validate_skills.py` 通过、`build_index.py --check` 通过。
- [ ] ctf：`build_skill_catalog.py --check`、`pytest`、`pre-commit` 通过。
- [ ] 删除分类/文件时，README、CONTRIBUTING、catalog、测试、opencode 配置、CI 标签均已同步。
- [ ] ctf-skills 已按 9.2 完成去嵌套收尾；日常改动作为普通文件随根仓提交。
- [ ] 需要发布时，四端目录已同步并校验一致。

---

## 12. 已知债务

以下是当前仓库的已知问题，记录在此避免重复发现；修复需维护者确认：

1. ~~`ctf-skills` gitlink 未收尾~~：2026-11-13 已转为普通文件并暂存，待根仓提交后关闭。
2. 根仓无 `.gitignore`，`.idea/` 处于未跟踪状态。
3. `ctf-skills/README.md` 的 Files 计数会随文件增减漂移，改动后需人工复核。
4. `ctf-skills/CONTRIBUTING.md` 要求 description 以第三人称动词开头，但测试只校验长度大于 20 字符。
5. `recon-skills` 没有 CI，校验依赖本地脚本；`dist/` 是否过期只能靠 `--check` 手工发现。
6. `recon-skills/` 已汉化，但与上游 `uphiago/recon-skills` 的差异没有独立记录；后续若合并上游需先做差异审计。
7. `ctf-skills/.github/workflows/` 在并入根仓后不再触发；根仓当前没有 CI，所有 ctf 检查需本地手动执行，或把 workflow 迁移到根 `.github/workflows/`。
