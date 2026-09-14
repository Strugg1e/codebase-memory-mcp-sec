#!/usr/bin/env python3
"""Validate product documentation locally. Never fetch URLs or run target code."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOTS = (
    "README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md",
    "MAINTAINERS.md", "CODE_OF_CONDUCT.md", "security/README.md",
    "tests/README.md", "pkg/README.md",
)


def owned_markdown(root: Path) -> list[Path]:
    paths = {root / name for name in PRODUCT_ROOTS}
    paths.update(p for p in (root / "docs").rglob("*.md")
                 if "upstream" not in p.relative_to(root / "docs").parts)
    paths.update((root / "skills/cbm-sec-evidence").rglob("*.md"))
    paths.update((root / "hooks").glob("*.md"))
    return sorted(paths)


def validate(root: Path = ROOT) -> dict:
    root = root.resolve()
    errors: list[str] = []
    links = 0
    paths = owned_markdown(root)
    for path in paths:
        relative = path.relative_to(root).as_posix()
        if not path.is_file():
            errors.append(f"missing product document: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        # Markdown examples are not actual navigation links.
        prose = re.sub(r"^```[^\n]*\n.*?^```\s*$", "", text,
                       flags=re.MULTILINE | re.DOTALL)
        for target in re.findall(r"\]\(([^\s)]+)\)", prose):
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = (path.parent / unquote(parsed.path)).resolve()
            links += 1
            if not destination.is_relative_to(root):
                errors.append(f"link escapes repository: {relative}: {target}")
            elif not destination.exists():
                errors.append(f"broken link: {relative}: {target}")

    readme = (root / "README.md").read_text(encoding="utf-8")
    if not readme.startswith("# CBM Sec\n"):
        errors.append("README product title is not CBM Sec")
    if len(re.findall(r"[\u4e00-\u9fff]", readme)) < 200:
        errors.append("README is missing the Chinese product introduction")
    if re.search(r"curl[^\n]*DeusData[^\n]*\|\s*(ba)?sh", readme):
        errors.append("README still installs the upstream product")
    metadata = json.loads((root / "cbm-sec.json").read_text(encoding="utf-8"))
    if metadata.get("product") != "CBM Sec" or metadata.get("package_registry_status") != "not_declared":
        errors.append("repository metadata must not claim an unpublished package")
    if (root / "server.json").exists() or (root / "glama.json").exists():
        errors.append("upstream registry metadata is still exposed at repository root")
    for key in ("build", "version_source", "documentation", "capabilities_source", "upstream_metadata"):
        if not (root / metadata.get(key, "__missing__")).is_file():
            errors.append(f"invalid repository metadata path: {key}")

    source = (root / "security/mcp.c").read_text(encoding="utf-8")
    block = source.split("static const tool tools[] = {", 1)[1].split("\n};", 1)[0]
    actual = set(re.findall(r'\{"([a-z_]+)",\s*"', block))
    documented = set(re.findall(r"^\| `([a-z_]+)` \|", (root / "docs/tools.md").read_text(), re.M))
    if not actual or actual != documented:
        errors.append(f"tool catalog mismatch: actual={sorted(actual)}, docs={sorted(documented)}")

    migration = json.loads((root / "docs/development/migration.json").read_text())
    for old, new in migration["moves"].items():
        if not (root / new).is_file():
            errors.append(f"missing moved file: {old} -> {new}")
        # The website landing files are deliberately replaced by product pages.
        if old not in ("docs/index.html", "docs/llms.txt", "docs/.nojekyll") and (root / old).exists():
            errors.append(f"old path not retired: {old}")
    checked_hashes = dict(migration["archived_sha256"])
    checked_hashes.update(migration["unchanged_files"])
    for name, expected in checked_hashes.items():
        path = root / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            errors.append(f"preserved original changed: {name}")
    return {"passed": not errors, "documents_checked": len(paths),
            "local_link_targets_checked": links, "mcp_tools_checked": len(actual),
            "preserved_hashes_checked": len(checked_hashes), "errors": errors}


def main() -> int:
    try:
        result = validate()
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(f"documentation check could not finish: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
