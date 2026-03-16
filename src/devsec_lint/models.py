from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

@dataclass(slots=True)
class WorkflowDocument:
    path: Path
    raw_text: str
    data: dict[str, Any]

@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    file_path: str
    line: int | None = None
    column: int | None = None
    snippet: str | None = None
    remediation: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)