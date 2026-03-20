from __future__ import annotations

from devsec_lint.models import Finding, WorkflowDocument
from devsec_lint.rules.base import Rule

class MissingPermissionsRule(Rule):
    rule_id = "workflows/missing-permissions"
    title = "Workflow does not define explicit permissions"
    severity = "MEDIUM"
    description = "Github Actions workflows should define least-privilege GITHUB_TOKEN permissions."

    def check(self, document: WorkflowDocument) -> list[Finding]:
        data = document.data
        if not isinstance(data, dict):
            return []

        if "permissions" in data:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=(
                    "The workflow does not define a top-level 'permissions' block."
                    "Default token permissions may be broader than necessary."
                ),
                file_path=str(document.path),
                line=self._find_line(document.raw_text),
                snippet=None,
                remediation=(
                    "Add a top-level permissions block, for example:\n"
                    "permisssions:\n"
                    "  contents: read"
                ),
                metadata={},
            )
        ]

    def _find_line(self, raw_text: str) -> str | None:
        for i, line in enumerate(raw_text.splitlines(), start=1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                return i
        return None