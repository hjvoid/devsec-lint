from __future__ import annotations

from pathlib import Path
from typing import List

from devsec_lint.constants import SUPPORTED_EXTENSIONS, WORKFLOW_DIR_PARTS

def _is_yaml_file(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS

def discover_workflow_files(target: str) -> List[Path]:
    path = Path(target).expanduser().resolve()

    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")

    if path.is_file():
        return [path] if _is_yaml_file(path) else []

    direct_matches = sorted(
        p for p in path.iterdir() if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS
    )

    if direct_matches:
        return direct_matches

    workfow_dir = path.joinpath(*WORKFLOW_DIR_PARTS)
    if workfow_dir.exists() and workfow_dir.is_dir():
        return sorted(
            p for p in workfow_dir.iterdir()
            if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS
        )

    return []