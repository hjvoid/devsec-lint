from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict

from src.devsec_lint.models import Finding

def format_json(findings: list[Finding], errors: list[str]) -> str:
    counts = Counter(f.severity for f in findings)
    payload = {
        "summary": {
            "HIGH": counts.get("HIGH", 0),
            "MEDIUM": counts.get("MEDIUM", 0),
            "LOW": counts.get("LOW", 0),
        },
        "errors": errors,
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(payload, indent=2)
