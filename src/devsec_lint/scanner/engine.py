from __future__ import annotations

from pathlib import Path

from devsec_lint.models import Finding, WorkflowDocument
from devsec_lint.rules.base import Rule
from devsec_lint.scanner.parser import load_workflow, WorkflowParseError


def run_rule(document: WorkflowDocument, rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(rule.check(document))
    return findings

def scan_files(paths: list[Path], rules: list[Rule]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []

    for path in paths:
        try:
            document = load_workflow(path)
            findings.extend(run_rule(document, rules))
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    return findings, errors