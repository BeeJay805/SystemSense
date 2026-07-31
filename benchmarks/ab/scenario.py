"""Load a scenario and bind its manifest to every executable byte."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from benchmarks.ab.contracts import ScenarioManifest

REQUIRED_SCRIPTS = (
    "inject",
    "verify_broken",
    "verify_fixed",
    "repair_reference",
)


@dataclass(frozen=True, slots=True)
class LoadedScenario:
    root: Path
    manifest: ScenarioManifest
    script_paths: dict[str, Path]
    asset_paths: tuple[Path, ...]
    content_hash: str


def load_scenario(path: Path) -> LoadedScenario:
    manifest_path = path if path.name == "manifest.json" else path / "manifest.json"
    manifest_path = manifest_path.resolve()
    if not manifest_path.is_file():
        raise ValueError(f"scenario manifest is missing: {manifest_path}")
    root = manifest_path.parent
    manifest = ScenarioManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    scripts = {
        name: _resolve_member(root, str(getattr(manifest.scripts, name)))
        for name in REQUIRED_SCRIPTS
    }
    assets = tuple(_resolve_member(root, member) for member in manifest.assets)
    members = (manifest_path, *scripts.values(), *assets)
    missing = [str(member) for member in members if not member.is_file()]
    if missing:
        raise ValueError("scenario files are missing: " + ", ".join(missing))
    return LoadedScenario(
        root=root,
        manifest=manifest,
        script_paths=scripts,
        asset_paths=assets,
        content_hash=_content_hash(root, members),
    )


def _resolve_member(root: Path, member: str) -> Path:
    candidate = (root / member).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("scenario files must stay inside the scenario directory")
    return candidate


def _content_hash(root: Path, members: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for member in sorted(members, key=lambda item: item.relative_to(root).as_posix()):
        relative = member.relative_to(root).as_posix().encode("utf-8")
        content = member.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()
