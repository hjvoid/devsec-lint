from __future__ import annotations

import re

from src.devsec_lint.models import Finding, WorkflowDocument
from src.devsec_lint.rules.base import Rule

FULL_SHA_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")

class UnpinnedAction(Rule):
    rule_id = "actions/unpinned-version"
    title = "Action is not pinned to a full commit SHA"
    severity = "HIGH"
    description = "Github Actions should be pinned to immutable commit SHA."

    def check(self, document: WorkflowDocument) -> list[Finding]:
        findings: list[Finding] = []

        jobs = document.data.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue

            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                uses_value = step.get("uses")
                if not isinstance(uses_value, str):
                    continue

                if self._is_pinned(uses_value):
                    continue

                step_name = step.get("name", f"step #{idx + 1}")
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=(
                            f"Step '{step_name}' in job '{job_name}' uses a mutable action ref: "
                            f"{uses_value}"
                        ),
                        file_path=str(document.path),
                        line=self._find_line(document.raw_text, uses_value),
                        snippet=f"uses: {uses_value}",
                        remediation=(
                            "Replace the tag or branch with a full 40-character commit SHA."
                        ),
                        metadata={
                            "job": job_name,
                            "step": step_name,
                            "uses": uses_value,
                        },
                    )
                )

        return findings

def _is_pinned(self, uses_value: str) -> bool:
    if "@" not in uses_value:
        return False
    _, ref = uses_value.split("@", 1)
    return bool(FULL_SHA_REGEX.fullmatch(ref))

def _find_line(self, raw_text: str, needle: str) -> int | None:
    for i, line in enumerate(raw_text.splitlines(), start=1):
        if needle in line:
            return i
    return None