from __future__ import annotations

from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from devsec_lint.models import WorkflowDocument

_yaml = YAML(typ="safe")

class WorkflowParseError(Exception):
    pass

def load_workflow(path: Path) -> WorkflowDocument:
    raw_text = path.read_text(encoding="utf-8")
    try:
        parsed = _yaml.load(raw_text) or {}
    except YAMLError as exc:
        raise WorkflowParseError(f"Failed to parse YAML: {path}") from exc

    if not isinstance(parsed, dict):
        raise WorkflowParseError(f"Workflow route must be a mapping: {path}")

    return WorkflowDocument(
        path=path,
        raw_text=raw_text,
        data=parsed,
    )
