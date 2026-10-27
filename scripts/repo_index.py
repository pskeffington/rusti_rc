#!/usr/bin/env python3
"""Offline deterministic repository index; metadata only, no network or secrets.

The curated source of truth is index/catalog.json. This produces
index/MACHINE_INDEX.json and docs/INDEX.md. Requires Python 3.8+ and git.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CATALOG = "index/catalog.json"
MACHINE = "index/MACHINE_INDEX.json"
DOCS = "docs/INDEX.md"
SCHEMA = "rusti_rc.machine_index.v1"
EXTENSIONS = {".rs", ".md", ".py", ".sh", ".toml", ".json", ".yaml", ".yml"}
ROOT_FILES = {"README.md", "SECURITY.md", "CONTRIBUTING.md", "AGENTS.md",
              "Cargo.toml", "LICENSE", ".gitignore"}
BLOCKED_EXT = {".key", ".pem", ".p12", ".pfx", ".age", ".db", ".sqlite",
               ".sqlite3", ".log", ".bin"}
BLOCKED_DIR = {"target", ".git", "__pycache__", "node_modules", "dist",
               "coverage", ".venv", "release-bundles"}
MODULE_KEYS = {"id", "prefix", "kind", "maturity", "summary", "entrypoints",
               "docs", "topics", "trust_boundary"}
ROUTE_KEYS = {"id", "terms", "primary", "related"}


class IndexProblem(Exception):
    pass


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IndexProblem("duplicate JSON key: " + key)
        result[key] = value
    return result


def safe_path(path):
    if not isinstance(path, str) or not path or len(path) > 240 or "\\" in path:
        raise IndexProblem("invalid path")
    parts = PurePosixPath(path)
    if parts.is_absolute() or any(part in ("", ".", "..") for part in path.split("/")):
        raise IndexProblem("unsafe path: " + path)
    if any(part in BLOCKED_DIR for part in parts.parts):
        raise IndexProblem("build directory in path: " + path)
    if parts.name.startswith(".env") or parts.suffix.lower() in BLOCKED_EXT:
        raise IndexProblem("secret-like file path: " + path)


def load_catalog(root):
    data = json.loads((root / CATALOG).read_text(encoding="utf-8"),
                      object_pairs_hook=unique_pairs)
    if not isinstance(data, dict) or set(data) != {"schema", "project", "modules", "routes"}:
        raise IndexProblem("catalog schema mismatch")
    if type(data["schema"]) is not int or data["schema"] != 1 or data["project"] != "rusti_rc":
        raise IndexProblem("unsupported catalog version")
    modules, routes = data["modules"], data["routes"]
    if not isinstance(modules, list) or not isinstance(routes, list) or not modules or not routes:
        raise IndexProblem("missing modules/routes")
    seen_ids, seen_prefixes = set(), set()
    for module in modules:
        if not isinstance(module, dict) or set(module) != MODULE_KEYS:
            raise IndexProblem("invalid module fields")
        mid, prefix = module["id"], module["prefix"]
        if not isinstance(mid, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,40}", mid):
            raise IndexProblem("invalid module id")
        if not isinstance(prefix, str) or (prefix and
            (not prefix.endswith("/") or prefix.startswith("/") or
             any(part in ("", ".", "..") for part in prefix[:-1].split("/")))):
            raise IndexProblem("unsafe module prefix")
        if mid in seen_ids or prefix in seen_prefixes:
            raise IndexProblem("duplicate module id/prefix")
        seen_ids.add(mid)
        seen_prefixes.add(prefix)
        for key in ("kind", "maturity", "summary", "trust_boundary"):
            if not isinstance(module[key], str) or not 1 <= len(module[key]) <= 300:
                raise IndexProblem("invalid module " + key)
        for key in ("entrypoints", "docs", "topics"):
            values = module[key]
            if not isinstance(values, list) or not values or any(
                not isinstance(v, str) for v in values
            ) or len(values) != len(set(values)):
                raise IndexProblem("invalid or duplicate " + key)
            for item in values:
                if key == "topics":
                    if not re.fullmatch(r"[a-z][a-z0-9-]{1,40}", item):
                        raise IndexProblem("invalid topic")
                else:
                    safe_path(item)
                    if key == "entrypoints" and ((prefix and not item.startswith(prefix))
                        or (not prefix and "/" in item)):
                        raise IndexProblem("entrypoint outside module: " + item)
    if "" not in seen_prefixes:
        raise IndexProblem("root metadata scope missing")
    seen_routes = set()
    for route in routes:
        if not isinstance(route, dict) or set(route) != ROUTE_KEYS:
            raise IndexProblem("invalid route fields")
        rid = route["id"]
        if not isinstance(rid, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,40}", rid) or rid in seen_routes:
            raise IndexProblem("invalid/duplicate route id")
        seen_routes.add(rid)
        terms, related = route["terms"], route["related"]
        if not isinstance(terms, list) or not terms or any(
            not isinstance(t, str) or not re.fullmatch(r"[a-z0-9][a-z0-9 ._-]{1,50}", t)
            for t in terms
        ) or len(terms) != len(set(terms)):
            raise IndexProblem("invalid route terms")
        if not isinstance(related, list) or len(related) != len(set(related)):
            raise IndexProblem("invalid route related paths")
        for path in [route["primary"]] + related:
            safe_path(path)
    return data


def tracked_paths(root):
    try:
        output = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=str(root), check=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15,
        ).stdout
        paths = [item.decode("utf-8", "strict") for item in output.split(b"\0") if item]
        return sorted(set(paths))
    except (OSError, UnicodeError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise IndexProblem("cannot enumerate UTF-8 tracked source paths from git")


def module_for(path, modules):
    matches = [m for m in modules if m["prefix"] and path.startswith(m["prefix"])]
    if matches:
        return max(matches, key=lambda m: len(m["prefix"]))["id"]
    if "/" not in path:
        return next(m["id"] for m in modules if m["prefix"] == "")
    raise IndexProblem("unindexed source directory: " + path)


def kind_for(path):
    if path.startswith(".github/workflows/"):
        return "ci-workflow"
    if path.endswith(".md"):
        return "documentation"
    if path.startswith("fuzz/fuzz_targets/"):
        return "fuzz-target"
    if "/tests/" in path or PurePosixPath(path).name.startswith("test_"):
        return "test"
    if path.endswith(".rs"):
        return "rust-source"
    if path.endswith((".py", ".sh")):
        return "script"
    if path.endswith("Cargo.toml") or path.endswith(".schema.json"):
        return "manifest"
    return "metadata"


def headings(root, path):
    if path == DOCS:
        return "Repository navigation", []
    try:
        content = (root / path).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise IndexProblem("unreadable documentation: " + path)
    if len(content) > 256000:
        raise IndexProblem("documentation over size limit: " + path)
    title, sections, fenced = None, [], False
    for line in content.splitlines():
        if line.strip().startswith((chr(96) * 3, "~" * 3)):
            fenced = not fenced
            continue
        if fenced:
            continue
        hit = re.match(r"^(#{1,2})[ \t]+(.+?)\s*#*\s*$", line)
        if not hit:
            continue
        value = hit.group(2).strip()
        if len(value) > 120:
            continue
        if hit.group(1) == "#" and title is None:
            title = value
        elif hit.group(1) == "##" and len(sections) < 24:
            sections.append(value)
    return title or PurePosixPath(path).name, sections


def assemble(root, catalog, paths):
    files = []
    for path in paths:
        safe_path(path)
        if path == MACHINE:
            continue   # index cannot contain itself as a source document
        if path not in ROOT_FILES and PurePosixPath(path).suffix.lower() not in EXTENSIONS:
            raise IndexProblem("unclassified tracked path: " + path)
        item = root / path
        if item.is_symlink() or not item.is_file():
            raise IndexProblem("missing or symlinked source: " + path)
        entry = {"path": path, "module": module_for(path, catalog["modules"]),
                 "kind": kind_for(path)}
        if path.endswith(".md"):
            title, sections = headings(root, path)
            entry["title"], entry["sections"] = title, sections
        files.append(entry)
    # When first creating this generated docs file it is not yet tracked.
    if DOCS not in paths:
        files.append({"path": DOCS, "module": module_for(DOCS, catalog["modules"]),
                      "kind": "documentation", "title": "Repository navigation",
                      "sections": []})
    files.sort(key=lambda e: e["path"])
    known = {f["path"] for f in files} | {MACHINE}
    for module in catalog["modules"]:
        for path in module["entrypoints"] + module["docs"]:
            if path not in known:
                raise IndexProblem("dangling catalog module reference: " + path)
    for route in catalog["routes"]:
        for path in [route["primary"]] + route["related"]:
            if path not in known:
                raise IndexProblem("dangling task-route reference: " + path)
    modules = []
    for m in catalog["modules"]:
        obj = dict(m)
        obj["files"] = [f["path"] for f in files if f["module"] == m["id"]]
        modules.append(obj)
    modules.sort(key=lambda m: m["id"])
    return {
        "schema": SCHEMA,
        "catalog": CATALOG,
        "generator": "scripts/repo_index.py",
        "counts": {
            "modules": len(modules), "routes": len(catalog["routes"]),
            "files": len(files) + 1,
            "documents": sum(f["kind"] == "documentation" for f in files),
        },
        "modules": modules,
        "routes": sorted(catalog["routes"], key=lambda r: r["id"]),
        "files": files,
    }


def link(path):
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", path):
        raise IndexProblem("unsupported docs link: " + path)
    return "../" + path


def docs_text(index):
    lines = [
        "# Repository navigation", "",
        "> Generated from index/catalog.json by scripts/repo_index.py. "
        "Do not edit; update the catalog or source and regenerate.", "",
        "Start with [AGENTS.md](../AGENTS.md) for agent safety rules, "
        "[README](../README.md) for scope, and "
        "[MACHINE_INDEX.json](../index/MACHINE_INDEX.json) for machine retrieval.", "",
        "**Status:** Experimental IRC communications module. TLS/SASL are not "
        "Rust Boy organizational authority; field deployment remains gated.", "",
        "## Task routing", "",
        "| Search terms | Primary source | Related source |",
        "| --- | --- | --- |",
    ]
    for route in index["routes"]:
        primary = route["primary"]
        related = route["related"][0] if route["related"] else primary
        lines.append("| " + ", ".join(route["terms"][:3])
                     + " | [" + primary + "](" + link(primary) + ")"
                     + " | [" + related + "](" + link(related) + ") |")
    lines.extend(["", "## Module ownership and boundaries", "",
                  "| Module | Maturity | Entry point | Trust boundary |",
                  "| --- | --- | --- | --- |"])
    for mod in index["modules"]:
        entry = mod["entrypoints"][0]
        lines.append("| " + mod["id"] + " | " + mod["maturity"]
                     + " | [" + entry + "](" + link(entry) + ") | "
                     + mod["trust_boundary"].replace("|", "/") + " |")
    lines.extend(["", "## Documentation", ""])
    groups = {}
    for item in index["files"]:
        if item["kind"] == "documentation" and item["path"] != DOCS:
            folder = str(PurePosixPath(item["path"]).parent)
            groups.setdefault(folder, []).append(item)
    for folder in sorted(groups):
        lines.extend(["### " + folder, ""])
        for item in groups[folder]:
            clean = item["title"].replace("[", "").replace("]", "")
            lines.append("- [" + clean + "](" + link(item["path"]) + ")")
        lines.append("")
    lines.extend(["## Maintain the index", "",
                  "From the repository root:", "",
                  "    python3 scripts/repo_index.py --write",
                  "    python3 scripts/repo_index.py --check",
                  "    python3 scripts/repo_index.py --query 'SASL authentication'", "",
                  "CI rejects stale output, missing links in curated routes, "
                  "unindexed directories, and sensitive file extensions. "
                  "The index is a navigation aid, never a security approval.", ""])
    return "\n".join(lines)


def generate(root):
    index = assemble(root, load_catalog(root), tracked_paths(root))
    return {
        MACHINE: json.dumps(index, indent=2, ensure_ascii=False) + "\n",
        DOCS: docs_text(index),
    }, index


def search(index, text):
    tokens = set(re.findall(r"[a-z0-9]+", text.casefold()))
    result = []
    for route in index["routes"]:
        words = route["id"].replace("-", " ") + " " + " ".join(route["terms"])
        matches = len(tokens & set(re.findall(r"[a-z0-9]+", words.casefold())))
        if matches:
            result.append({"route": route["id"], "score": matches,
                           "primary": route["primary"], "related": route["related"]})
    return sorted(result, key=lambda v: (-v["score"], v["route"]))[:10]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--query")
    args = parser.parse_args(argv)
    try:
        files, index = generate(ROOT)
        if args.query is not None:
            print(json.dumps({"query": args.query, "matches": search(index, args.query)}, indent=2))
        elif args.check:
            drift = [path for path, content in files.items()
                     if not (ROOT / path).is_file() or
                     (ROOT / path).read_text(encoding="utf-8") != content]
            if drift:
                raise IndexProblem("stale generated index: " + ", ".join(drift)
                                   + "; run python3 scripts/repo_index.py --write")
            print("machine_index=clean files=" + str(index["counts"]["files"]))
        else:
            for path, content in files.items():
                dst = ROOT / path
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(content, encoding="utf-8")
            print("machine_index=written files=" + str(index["counts"]["files"]))
        return 0
    except (IndexProblem, OSError, ValueError, json.JSONDecodeError) as exc:
        print("machine_index=refused: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
