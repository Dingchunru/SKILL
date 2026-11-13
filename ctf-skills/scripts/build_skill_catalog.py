#!/usr/bin/env python3
"""Build agent-facing skill catalogs from repository sources.

This is the compile step for the skills. It reads the routing bullets in each
SKILL.md, the frontmatter and headings of every reference document, and emits:

    <skill>/catalog.md            compact index for agents (human-readable)
    <skill>/catalog.json          machine-readable index
    ctf-pwn/pwnable-tw/README.md  regenerated challenge index

Usage:
    python scripts/build_skill_catalog.py
    python scripts/build_skill_catalog.py --check   # fail if outputs are stale
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_NAMES = ("ctf-pwn", "ctf-web", "ctf-reverse")
CHALLENGE_DIR = "pwnable-tw"
GENERATED_NOTE = "本文件由 `scripts/build_skill_catalog.py` 生成，请勿手工编辑。"
SUMMARY_LIMIT = 240
SECTION_LIMIT = 8

BULLET_RE = re.compile(r"^- \[([^\]]+)\]\(([^)]+)\)\s*[—-]\s*(.+)$")


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Return (frontmatter dict, body) for a markdown document."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text

    end = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = i
            break
    if end is None:
        return {}, text

    data: dict = {}
    current_list: str | None = None
    for line in lines[1:end]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") and current_list:
            data[current_list].append(stripped[2:].strip().strip('"'))
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if not value:
            data[key] = []
            current_list = key
        else:
            data[key] = value.strip('"')
            current_list = None

    return data, "\n".join(lines[end + 1 :])


def outside_fences(text: str):
    """Yield (line, inside_fence) pairs."""
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            yield line, True
            continue
        yield line, in_fence


def clean_inline(text: str) -> str:
    # Keep underscores: they are part of identifiers such as tty_struct.
    text = re.sub(r"[`*~]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def extract_title(body: str, fallback: str) -> str:
    for line, fenced in outside_fences(body):
        if not fenced and line.startswith("# "):
            return clean_inline(line[2:])
    return fallback


def extract_sections(body: str) -> list[str]:
    sections: list[str] = []
    for line, fenced in outside_fences(body):
        if fenced or not line.startswith("## "):
            continue
        title = clean_inline(line[3:])
        if title in {"目录", "Table of Contents"}:
            continue
        if title and title not in sections:
            sections.append(title)
    return sections[:SECTION_LIMIT]


def extract_skill_bullets(skill_text: str) -> dict[str, str]:
    """Map document basename to its one-line summary in SKILL.md."""
    bullets: dict[str, str] = {}
    for line, fenced in outside_fences(skill_text):
        if fenced:
            continue
        match = BULLET_RE.match(line.strip())
        if not match:
            continue
        target = match.group(2).split("#", 1)[0]
        name = Path(target).name
        if name.endswith(".md"):
            bullets[name] = clean_inline(match.group(3))
    return bullets


def first_paragraph(body: str) -> str:
    for line, fenced in outside_fences(body):
        text = line.strip()
        if fenced or not text:
            continue
        if text[0] in "#>|-[*!" or text.startswith("```"):
            continue
        return clean_inline(text)
    return ""


def truncate(text: str, limit: int = SUMMARY_LIMIT) -> str:
    if len(text) <= limit:
        return text
    cut = text[: limit - 1].rsplit(" ", 1)[0]
    return f"{cut}…"


def cell(text: str) -> str:
    return truncate(text).replace("|", "\\|")


def protections(fm: dict) -> str:
    labels = []
    relro = str(fm.get("relro", "")).lower()
    if relro:
        labels.append("No RELRO" if relro == "none" else f"{relro.title()} RELRO")
    canary = str(fm.get("canary", "")).lower()
    if canary:
        labels.append("Canary" if canary == "yes" else "No Canary")
    nx = str(fm.get("nx", "")).lower()
    if nx:
        labels.append("NX" if nx == "yes" else "NX off")
    pie = str(fm.get("pie", "")).lower()
    if pie:
        labels.append("PIE" if pie == "yes" else "No PIE")
    return " / ".join(labels)


def module_summary(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r'"""(.+?)"""', text, re.S)
    if not match:
        return ""
    for line in match.group(1).splitlines():
        line = line.strip()
        if line:
            return clean_inline(line)
    return ""


def describe_doc(skill_dir: Path, path: Path, bullets: dict[str, str]) -> dict:
    text = path.read_text(encoding="utf-8")
    fm, body = parse_frontmatter(text)
    name = path.name
    summary = fm.get("description") or bullets.get(name) or first_paragraph(body)
    entry = {
        "path": path.relative_to(skill_dir).as_posix(),
        "kind": "technique",
        "title": extract_title(body, path.stem),
        "summary": truncate(clean_inline(summary)),
        "sections": extract_sections(body),
        "bytes": len(text.encode("utf-8")),
    }
    tags = fm.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    if tags:
        entry["tags"] = tags
    for key in ("platform", "points", "arch", "libc"):
        if fm.get(key):
            entry[key] = fm[key]
    prot = protections(fm)
    if prot:
        entry["protections"] = prot
    return entry


def collect_docs(skill_dir: Path) -> tuple[list[dict], list[dict], dict]:
    skill_text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    bullets = extract_skill_bullets(skill_text)
    generated = {"SKILL.md", "catalog.md"}

    docs: list[dict] = []
    for path in sorted(skill_dir.glob("*.md")):
        if path.name in generated:
            continue
        entry = describe_doc(skill_dir, path, bullets)
        entry["kind"] = "index" if path.name == "README.md" else "technique"
        docs.append(entry)

    tools: list[dict] = []
    scripts_dir = skill_dir / "scripts"
    if scripts_dir.is_dir():
        for path in sorted(scripts_dir.iterdir()):
            if path.is_file() and path.suffix in {".py", ".sh"}:
                tools.append(
                    {
                        "path": path.relative_to(skill_dir).as_posix(),
                        "summary": truncate(module_summary(path)),
                    }
                )

    challenges: dict = {}
    challenge_dir = skill_dir / CHALLENGE_DIR
    if challenge_dir.is_dir():
        items = []
        for path in sorted(challenge_dir.glob("*.md")):
            if path.name == "README.md":
                continue
            items.append(describe_doc(skill_dir, path, bullets))
        items.sort(key=lambda item: (int(item.get("points", 0)), item["path"]))
        challenges = {
            "index": f"{CHALLENGE_DIR}/README.md",
            "count": len(items),
            "items": items,
        }

    return docs, tools, challenges


def render_catalog_md(
    skill: str, docs: list[dict], tools: list[dict], chall: dict
) -> str:
    lines = [
        f"# {skill} 文档索引",
        "",
        f"> {GENERATED_NOTE}",
        ">",
        "> 用法：按「用途」定位候选文件，只加载命中的那一篇；同名 `catalog.json`",
        "> 提供相同信息的机器可读版本（含路径、摘要、标签、章节、字节数）。",
        "",
        "## 技术参考",
        "",
        "| 文档 | 用途 | 关键章节 |",
        "|---|---|---|",
    ]
    for doc in docs:
        sections = "、".join(cell(s) for s in doc["sections"][:5])
        lines.append(
            f"| [{doc['path']}]({doc['path']}) | {cell(doc['summary'])} | {sections} |"
        )

    if tools:
        lines += ["", "## 辅助工具", "", "| 脚本 | 用途 |", "|---|---|"]
        for tool in tools:
            lines.append(f"| `{tool['path']}` | {cell(tool['summary'])} |")

    if chall:
        lines += [
            "",
            "## 题库",
            "",
            f"- [{CHALLENGE_DIR} 题目索引]({chall['index']}) — "
            f"{chall['count']} 道题，按分数、保护机制和标签路由。",
        ]

    return "\n".join(lines) + "\n"


def render_readme(challenges: dict) -> str:
    items = challenges["items"]
    lines = [
        "# pwnable.tw 题目目录",
        "",
        f"> {GENERATED_NOTE}",
        ">",
        f"> 共 {len(items)} 道题。每行给出目标环境、保护机制、标签和一句话根因；",
        "> 完整分析、利用链与偏移见各题链接。按标签检索见文末。",
        "",
        "## 题目一览",
        "",
        "| 题目 | 分数 | 架构 | Libc | 保护机制 | 标签 | 一句话根因 |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in items:
        name = Path(item["path"]).stem
        tags = " ".join(f"`{tag}`" for tag in item.get("tags", []))
        lines.append(
            f"| [{name}]({name}.md) | {item.get('points', '')} | "
            f"{item.get('arch', '')} | {item.get('libc', '')} | "
            f"{item.get('protections', '')} | {tags} | {cell(item['summary'])} |"
        )

    tag_map: dict[str, list[str]] = {}
    for item in items:
        name = Path(item["path"]).stem
        for tag in item.get("tags", []):
            tag_map.setdefault(tag, []).append(name)

    if tag_map:
        lines += ["", "## 标签索引", "", "| 标签 | 题目 |", "|---|---|"]
        for tag in sorted(tag_map):
            names = "、".join(sorted(tag_map[tag]))
            lines.append(f"| `{tag}` | {names} |")

    return "\n".join(lines) + "\n"


def build_outputs() -> dict[Path, str]:
    outputs: dict[Path, str] = {}
    for skill in SKILL_NAMES:
        skill_dir = REPO_ROOT / skill
        if not (skill_dir / "SKILL.md").exists():
            continue
        docs, tools, chall = collect_docs(skill_dir)
        payload = {
            "skill": skill,
            "generated_by": "scripts/build_skill_catalog.py",
            "docs": docs,
            "tools": tools,
        }
        if chall:
            payload["challenges"] = chall
        outputs[skill_dir / "catalog.json"] = (
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        )
        catalog_md = render_catalog_md(skill, docs, tools, chall)
        outputs[skill_dir / "catalog.md"] = catalog_md
        if chall:
            outputs[skill_dir / CHALLENGE_DIR / "README.md"] = render_readme(chall)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if any generated file is missing or stale",
    )
    args = parser.parse_args()

    stale = []
    for path, content in build_outputs().items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            continue
        stale.append(path)
        if not args.check:
            path.write_text(content, encoding="utf-8", newline="\n")
            print(f"wrote {path.relative_to(REPO_ROOT).as_posix()}")

    if args.check:
        for path in stale:
            print(f"stale: {path.relative_to(REPO_ROOT).as_posix()}", file=sys.stderr)
        return 1 if stale else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
