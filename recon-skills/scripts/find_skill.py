#!/usr/bin/env python3
"""Search the compiled skill index produced by ``scripts/build_index.py``.

Examples::

    python3 scripts/find_skill.py ssrf
    python3 scripts/find_skill.py oauth jwt --category redteam
    python3 scripts/find_skill.py wordpress --tag wordpress --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "dist" / "index.json"

FIELD_WEIGHTS = (
    ("name", 6),
    ("tags", 4),
    ("triggers", 3),
    ("description", 2),
    ("when_to_use", 1),
)


def load_skills() -> list[dict[str, object]]:
    if not INDEX.exists():
        sys.exit("dist/index.json 不存在，请先运行: python3 scripts/build_index.py")
    return json.loads(INDEX.read_text(encoding="utf-8"))["skills"]


def haystack(skill: dict[str, object], field: str) -> str:
    value = skill.get(field, "")
    if isinstance(value, list):
        return " ".join(str(item) for item in value).lower()
    return str(value).lower()


def score(skill: dict[str, object], terms: list[str]) -> int:
    total = 0
    for term in terms:
        for field, weight in FIELD_WEIGHTS:
            if term in haystack(skill, field):
                total += weight
    return total


def matches_filters(skill: dict[str, object], args: argparse.Namespace) -> bool:
    if args.category and skill["category"] != args.category:
        return False
    if args.tag:
        tags = {tag.lower() for tag in skill["tags"]}
        if args.tag.lower() not in tags:
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="检索技能索引并输出匹配的 SKILL.md")
    parser.add_argument("query", nargs="*", help="关键词，可多个")
    parser.add_argument("--category", help="限定分类: meta/recon/redteam/chains/infra")
    parser.add_argument("--tag", help="限定标签，精确匹配")
    parser.add_argument("--limit", type=int, default=10, help="返回条数，默认 10")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args()

    skills = [skill for skill in load_skills() if matches_filters(skill, args)]
    terms = [term.lower() for term in args.query if term.strip()]

    if terms:
        ranked = [(score(skill, terms), skill) for skill in skills]
        ranked = [item for item in ranked if item[0] > 0]
        ranked.sort(key=lambda item: (-item[0], item[1]["name"]))
        skills = [skill for _, skill in ranked]

    skills = skills[: args.limit]

    if args.json:
        print(json.dumps(skills, ensure_ascii=False, indent=2))
        return 0

    if not skills:
        print("没有匹配的技能。尝试更宽泛的关键词，或先运行 scripts/build_index.py。")
        return 0

    for skill in skills:
        print(f"{skill['name']}  [{skill['category']}]  {skill['path']}")
        print(f"  标签: {', '.join(skill['tags'])}")
        print(f"  说明: {skill['description']}")
        if skill["related_skills"]:
            print(f"  后续: {', '.join(skill['related_skills'])}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
