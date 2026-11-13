#!/usr/bin/env python3
"""Compile the skill catalog into machine-readable artifacts under ``dist/``.

The generated files are the agent-facing surface of this repository:

- ``dist/index.json``     full manifest, one record per skill
- ``dist/routing.json``   tag/category/trigger routing data
- ``dist/workflows.json`` phase model and related-skill graph
- ``dist/CATALOG.md``     human-readable catalog
- ``dist/WORKFLOWS.md``   phase map, entry points, next-step index, gaps
- ``dist/llms.txt``       compact entry document for language agents

Run ``python3 scripts/build_index.py`` after editing a SKILL.md.
Use ``--check`` in CI to fail when the artifacts are stale.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

SCHEMA_VERSION = 1
CATEGORY_ORDER = ("meta", "recon", "redteam", "chains", "infra")
REQUIRED_SECTIONS = (
    "When to Use",
    "Prerequisites",
    "How to Run",
    "Procedure",
    "Pitfalls",
    "Verification",
)
REPORTING_TAGS = {"report", "reporting"}
ENTRY_TAGS = {"methodology", "playbook", "workflow"}
GENERATED_NOTE = "此文件由 scripts/build_index.py 生成，请勿手工编辑。"

TOP_KEY = re.compile(r"^([A-Za-z_][\w-]*):\s*(.*)$")
SUB_KEY = re.compile(r"^\s+([A-Za-z_][\w-]*):\s*(.*)$")
BULLET = re.compile(r"^(?:[-*+]|\d+\.)\s+(.*)$")
SENTENCE = re.compile(r"(?<=[。！？；.!?;])\s*")


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        inner = value[1:-1]
        if value[0] == '"':
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    return value


def inline_list(value: str) -> list[str] | None:
    value = value.strip()
    if not (value.startswith("[") and value.endswith("]")):
        return None
    inner = value[1:-1].strip()
    if not inner:
        return []
    return [unquote(item.strip()) for item in inner.split(",") if item.strip()]


def split_frontmatter(text: str) -> tuple[str, str]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return "", text
    try:
        end = lines.index("---", 1)
    except ValueError:
        return "", text
    return "\n".join(lines[1:end]), "\n".join(lines[end + 1 :])


def parse_frontmatter(block: str) -> dict[str, object]:
    data: dict[str, object] = {}
    current_top = ""
    list_key = ""
    for raw in block.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if indent == 0:
            match = TOP_KEY.match(stripped)
            if not match:
                current_top, list_key = "", ""
                continue
            key, value = match.group(1), match.group(2)
            if value:
                as_list = inline_list(value)
                data[key] = as_list if as_list is not None else unquote(value)
                current_top, list_key = "", ""
            else:
                data[key] = {}
                current_top, list_key = key, ""
            continue

        container = data.get(current_top)
        if not isinstance(container, dict):
            continue
        if stripped.startswith("- ") and list_key:
            bucket = container.get(list_key)
            if isinstance(bucket, list):
                bucket.append(unquote(stripped[2:].strip()))
            continue
        match = SUB_KEY.match(raw)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        if not value:
            container[key] = []
            list_key = key
            continue
        as_list = inline_list(value)
        container[key] = as_list if as_list is not None else unquote(value)
        list_key = ""
    return data


def as_text(value: object) -> str:
    return value if isinstance(value, str) else ""


def as_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, str) and value:
        return [value]
    return []


def extract_sections(body: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current = ""
    buffer: list[str] = []
    for line in body.splitlines():
        match = re.match(r"^##\s+(.+?)\s*$", line)
        if match:
            if current:
                sections[current] = "\n".join(buffer).strip()
            current = match.group(1).strip()
            buffer = []
        elif current:
            buffer.append(line)
    if current:
        sections[current] = "\n".join(buffer).strip()
    return sections


def clean_markup(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def extract_triggers(section: str, limit: int = 6) -> list[str]:
    triggers: list[str] = []
    for raw in section.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "|", "```", ">")):
            continue
        bullet = BULLET.match(line)
        if bullet:
            candidates = [bullet.group(1)]
        else:
            candidates = SENTENCE.split(line)
        for candidate in candidates:
            item = clean_markup(candidate).strip(" :-—")
            if len(item) < 8:
                continue
            if len(item) > 160:
                item = item[:157].rstrip() + "..."
            if item not in triggers:
                triggers.append(item)
        if len(triggers) >= limit:
            break
    return triggers[:limit]


def collect_assets(skill_dir: Path) -> list[str]:
    assets: list[str] = []
    for folder in ("references", "scripts", "templates"):
        base = skill_dir / folder
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file():
                assets.append(path.relative_to(skill_dir).as_posix())
    return assets


def load_skill(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    block, body = split_frontmatter(text)
    meta = parse_frontmatter(block)
    metadata = meta.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    rel = path.relative_to(ROOT)
    category = as_text(metadata.get("category")) or rel.parts[0]
    sections = extract_sections(body)
    when = sections.get("When to Use", "")

    return {
        "name": as_text(meta.get("name")) or path.parent.name,
        "path": rel.as_posix(),
        "category": category,
        "description": as_text(meta.get("description")),
        "version": as_text(meta.get("version")),
        "platforms": as_list(meta.get("platforms")),
        "tags": as_list(metadata.get("tags")),
        "related_skills": as_list(metadata.get("related_skills")),
        "when_to_use": when[:800],
        "triggers": extract_triggers(when),
        "sections": {name: name in sections for name in REQUIRED_SECTIONS},
        "assets": collect_assets(path.parent),
        "line_count": len(text.splitlines()),
    }


def load_skills() -> list[dict[str, object]]:
    skills = [load_skill(path) for path in sorted(ROOT.glob("**/SKILL.md"))]
    return sorted(skills, key=lambda item: (item["category"], item["name"]))


def dump_json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def build_index(skills: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": "scripts/build_index.py",
        "count": len(skills),
        "categories": [name for name in CATEGORY_ORDER if any(s["category"] == name for s in skills)],
        "skills": skills,
    }


def build_routing(skills: list[dict[str, object]]) -> dict[str, object]:
    by_tag: dict[str, list[str]] = {}
    by_category: dict[str, list[str]] = {}
    for skill in skills:
        by_category.setdefault(skill["category"], []).append(skill["name"])
        for tag in skill["tags"]:
            by_tag.setdefault(tag.lower(), []).append(skill["name"])
    rules = [
        {
            "name": skill["name"],
            "path": skill["path"],
            "category": skill["category"],
            "tags": skill["tags"],
            "triggers": skill["triggers"],
        }
        for skill in skills
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "by_category": {key: sorted(value) for key, value in sorted(by_category.items())},
        "by_tag": {key: sorted(value) for key, value in sorted(by_tag.items())},
        "rules": rules,
    }


def build_workflows(skills: list[dict[str, object]]) -> dict[str, object]:
    names = {skill["name"] for skill in skills}
    edges = [
        {"from": skill["name"], "to": target}
        for skill in skills
        for target in skill["related_skills"]
        if target in names
    ]
    inbound = {edge["to"] for edge in edges}
    entry_points = [
        {"name": skill["name"], "path": skill["path"], "category": skill["category"]}
        for skill in skills
        if skill["category"] == "meta" or ENTRY_TAGS & set(tag.lower() for tag in skill["tags"])
    ]
    assigned: dict[str, list[str]] = {key: [] for key, _, _ in PHASES}
    for skill in skills:
        for key, _, predicate in PHASE_PRIORITY:
            if predicate(skill):
                assigned[key].append(skill["name"])
                break
    phases = [
        {"key": key, "title": title, "skills": sorted(assigned[key])}
        for key, title, _ in PHASES
    ]
    unlinked = [
        skill["name"]
        for skill in skills
        if not skill["related_skills"] and skill["name"] not in inbound
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "entry_points": entry_points,
        "phases": phases,
        "edges": edges,
        "nodes": [
            {"name": skill["name"], "path": skill["path"], "category": skill["category"]}
            for skill in skills
        ],
        "unlinked": sorted(unlinked),
    }


def is_reporting(skill: dict[str, object]) -> bool:
    return bool(REPORTING_TAGS & set(tag.lower() for tag in skill["tags"]))


PHASES = (
    ("phase-0-planning", "阶段 0 — 规划与方法论", None),
    ("phase-1-discovery", "阶段 1 — 资产发现与枚举", None),
    ("phase-2-validation", "阶段 2 — 漏洞验证与利用", None),
    ("phase-3-chaining", "阶段 3 — 攻击链与基础设施利用", None),
    ("phase-4-reporting", "阶段 4 — 证据与报告", None),
)

PHASE_PRIORITY = (
    (
        "phase-0-planning",
        "阶段 0 — 规划与方法论",
        lambda skill: skill["category"] == "meta",
    ),
    (
        "phase-1-discovery",
        "阶段 1 — 资产发现与枚举",
        lambda skill: skill["category"] == "recon",
    ),
    (
        "phase-3-chaining",
        "阶段 3 — 攻击链与基础设施利用",
        lambda skill: skill["category"] in {"chains", "infra"},
    ),
    ("phase-4-reporting", "阶段 4 — 证据与报告", is_reporting),
    (
        "phase-2-validation",
        "阶段 2 — 漏洞验证与利用",
        lambda skill: skill["category"] == "redteam",
    ),
)


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def render_catalog(skills: list[dict[str, object]]) -> str:
    lines = [
        "# 技能目录",
        "",
        f"> {GENERATED_NOTE}",
        f"> 共 {len(skills)} 个技能。机器可读版本见 `dist/index.json`。",
        "",
    ]
    for category in CATEGORY_ORDER:
        group = [skill for skill in skills if skill["category"] == category]
        if not group:
            continue
        lines.append(f"## {category}（{len(group)}）")
        lines.append("")
        lines.append("| 技能 | 说明 | 标签 | 路径 |")
        lines.append("|---|---|---|---|")
        for skill in group:
            lines.append(
                "| `{name}` | {desc} | {tags} | `{path}` |".format(
                    name=skill["name"],
                    desc=cell(skill["description"]),
                    tags=cell(", ".join(skill["tags"])),
                    path=skill["path"],
                )
            )
        lines.append("")
    return "\n".join(lines)


def render_workflows(skills: list[dict[str, object]], workflows: dict[str, object]) -> str:
    lines = [
        "# 工作流地图",
        "",
        f"> {GENERATED_NOTE}",
        "",
        "## 阶段模型",
        "",
        "| 阶段 | 目的 | 技能数 |",
        "|---|---|---|",
    ]
    for phase in workflows["phases"]:
        lines.append(f"| {phase['title']} | `{phase['key']}` | {len(phase['skills'])} |")

    lines += ["", "## 入口技能", "", "先读这些，再按阶段推进：", ""]
    for entry in workflows["entry_points"]:
        lines.append(f"- `{entry['name']}` — `{entry['path']}`")

    lines += ["", "## 各阶段技能", ""]
    for phase in workflows["phases"]:
        if not phase["skills"]:
            continue
        lines.append(f"### {phase['title']}")
        lines.append("")
        for name in phase["skills"]:
            lines.append(f"- `{name}`")
        lines.append("")

    lines += ["## 技能后续步骤", "", "来自 frontmatter 的 `related_skills`：", ""]
    linked = [skill for skill in skills if skill["related_skills"]]
    if not linked:
        lines.append("（暂无显式关联）")
    for skill in linked:
        targets = ", ".join(f"`{name}`" for name in skill["related_skills"])
        lines.append(f"- `{skill['name']}` → {targets}")

    lines += [
        "",
        "## 关联缺口",
        "",
        "以下技能既未声明 `related_skills`，也没有被任何技能引用。补全关联可提升工作流可导航性：",
        "",
    ]
    unlinked = workflows["unlinked"]
    if unlinked:
        for name in unlinked:
            lines.append(f"- `{name}`")
    else:
        lines.append("（无）")
    lines.append("")
    return "\n".join(lines)


def render_llms(skills: list[dict[str, object]], workflows: dict[str, object]) -> str:
    lines = [
        "# Recon Skills",
        "",
        f"> 授权安全测试技能库：外部侦察、Web/API 侦察、漏洞验证、认证与云身份、"
        f"攻击链与报告。共 {len(skills)} 个技能。",
        "",
        "## 使用方式",
        "",
        "1. 用本文件、`dist/routing.json` 或 `python3 scripts/find_skill.py <关键词>` 选择技能。",
        "2. 读取 `dist/index.json` 中对应 `path` 的 SKILL.md 全文，不要只依赖摘要。",
        "3. 按固定章节执行：When to Use → Prerequisites → How to Run → Procedure → Pitfalls → Verification。",
        "4. 只在授权范围内、以最小副作用执行；任何改变状态的请求先取得操作者确认。",
        "5. 证据写入 `${OUTPUT_DIR:-./output}`，不要回写本仓库。",
        "",
        "## 阶段与入口",
        "",
    ]
    for phase in workflows["phases"]:
        lines.append(f"- {phase['title']}（{len(phase['skills'])} 个技能）")
    lines += ["", "入口技能：" + "、".join(f"`{e['name']}`" for e in workflows["entry_points"])]
    lines += ["", "## 技能清单", ""]
    for category in CATEGORY_ORDER:
        group = [skill for skill in skills if skill["category"] == category]
        if not group:
            continue
        lines.append(f"### {category}")
        lines.append("")
        for skill in group:
            lines.append(
                "- `{name}` — `{path}` — {desc}".format(
                    name=skill["name"],
                    path=skill["path"],
                    desc=truncate(skill["description"], 140),
                )
            )
        lines.append("")
    return "\n".join(lines)


def render_all(skills: list[dict[str, object]]) -> dict[str, str]:
    workflows = build_workflows(skills)
    return {
        "index.json": dump_json(build_index(skills)),
        "routing.json": dump_json(build_routing(skills)),
        "workflows.json": dump_json(workflows),
        "CATALOG.md": render_catalog(skills),
        "WORKFLOWS.md": render_workflows(skills, workflows),
        "llms.txt": render_llms(skills, workflows),
    }


def write_text(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def main(argv: list[str]) -> int:
    check = "--check" in argv
    skills = load_skills()
    outputs = render_all(skills)

    if check:
        stale = [
            name
            for name, content in outputs.items()
            if not (DIST / name).exists()
            or (DIST / name).read_text(encoding="utf-8") != content
        ]
        if stale:
            print("Artifacts are stale: " + ", ".join(sorted(stale)))
            print("Run: python3 scripts/build_index.py")
            return 1
        print(f"Artifacts up to date ({len(outputs)} files, {len(skills)} skills).")
        return 0

    DIST.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        write_text(DIST / name, content)
    print(f"Built {len(outputs)} artifacts for {len(skills)} skills in {DIST.name}/.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
