"""Build/query a private, revision-stamped Python module dependency map."""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def _module_name(source: Path, path: Path) -> str:
    parts = path.relative_to(source).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def internal_imports(tree: ast.AST, module: str, is_package: bool, known: set[str]) -> list[str]:
    package = module if is_package else module.rpartition(".")[0]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in known:
                    found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")
                if node.level > len(parts):
                    continue
                base = ".".join(parts[: len(parts) - node.level + 1])
                if node.module:
                    base = f"{base}.{node.module}"
            else:
                base = node.module or ""
            for alias in node.names:
                child = f"{base}.{alias.name}" if base else alias.name
                if child in known:
                    found.add(child)
                elif base in known:
                    found.add(base)
    return sorted(found - {module})


def build(repo: Path, output: Path) -> None:
    source = repo / "src"
    paths = sorted((source / "systemsense").rglob("*.py"))
    by_module = {_module_name(source, path): path for path in paths}
    known = set(by_module)
    modules: dict[str, dict[str, object]] = {}
    parse_errors: dict[str, str] = {}
    for module, path in sorted(by_module.items()):
        relative = path.relative_to(repo).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (SyntaxError, UnicodeError) as error:
            parse_errors[relative] = str(error)
            continue
        definitions = [
            {"name": node.name, "line": node.lineno, "kind": type(node).__name__}
            for node in tree.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        modules[module] = {
            "file": relative,
            "definitions": definitions,
            "imports": internal_imports(tree, module, path.name == "__init__.py", known),
        }
    imported_by: dict[str, list[str]] = {name: [] for name in modules}
    for module, entry in modules.items():
        for dependency in entry["imports"]:
            if dependency in imported_by:
                imported_by[dependency].append(module)
    for module, entry in modules.items():
        entry["imported_by"] = sorted(imported_by[module])
    payload = {
        "schema": 1,
        "head": _git(repo, "rev-parse", "HEAD"),
        "source_dirty": bool(_git(repo, "status", "--porcelain=v1", "--", "src")),
        "analyzer": "Python stdlib ast",
        "limits": (
            "Static imports and top-level definitions only; dynamic imports/calls are not inferred."
        ),
        "parse_errors": parse_errors,
        "modules": modules,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Mapped {len(modules)}/{len(paths)} modules at {payload['head']} to {output}")
    if parse_errors:
        print(f"WARNING: {len(parse_errors)} files could not be parsed; map is incomplete.")


def find(map_path: Path, query: str) -> None:
    payload = json.loads(map_path.read_text(encoding="utf-8"))
    if payload.get("schema") != 1:
        raise ValueError("Unsupported code map schema")
    print(f"Map HEAD: {payload['head']} (source_dirty={payload['source_dirty']})")
    matches = 0
    for module, entry in payload["modules"].items():
        definitions = [d for d in entry["definitions"] if query.casefold() in d["name"].casefold()]
        if query.casefold() not in module.casefold() and not definitions:
            continue
        print(f"{module} [{entry['file']}]")
        print(f"  imports: {', '.join(entry['imports'][:12])}")
        print(f"  imported by: {', '.join(entry['imported_by'][:12])}")
        for definition in definitions[:12]:
            print(f"  {entry['file']}:{definition['line']} {definition['name']}")
        matches += 1
        if matches == 20:
            print("Only the first 20 modules are shown; narrow the query.")
            return
    if not matches:
        print("No match. Confirm with source search; dynamic references are not indexed.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build_command = commands.add_parser("build")
    build_command.add_argument("--repo", type=Path, required=True)
    build_command.add_argument("--output", type=Path, required=True)
    find_command = commands.add_parser("find")
    find_command.add_argument("--map", type=Path, required=True)
    find_command.add_argument("--query", required=True)
    args = parser.parse_args()
    if args.command == "build":
        build(args.repo.resolve(), args.output.resolve())
    else:
        find(args.map.resolve(), args.query)


if __name__ == "__main__":
    main()
