from __future__ import annotations

from collections import Counter

from src.devsec_lint.models import Finding

def format_text(findings: list[Finding], errors: list[str]) -> str:
    lines: list[str] = []

    counts = Counter(f.severity for f in findings)

    summary = (
        f"Scan complete: "
        f"{counts.get('HIGH', 0)} HIGH, "
        f"{counts.get('MEDIUM', 0)} MEDIUM, "
        f"{counts.get('LOW', 0)} LOW"
    )

    lines.append(summary)

    if errors:
        lines.append("")
        lines.append("Errors:")
        for error in errors:
            lines.append(f"- {error}")

    if findings:
        lines.append("")
        for finding in findings:
            lines.append(f"[{finding.severity}] {finding.rule_id}")
            location = finding.file_path
            if finding.line is not None:
                location += f": {finding.line}"
            lines.append(f"File: {location}")
            lines.append(f"Issue: {finding.title}")
            lines.append(f"Why: {finding.description}")
            if finding.snippet:
                lines.append(f"Snippet: {finding.snippet}")
            if finding.remediation:
                lines.append(f"Fix: {finding.remediation}")
            lines.append("")

    return "\n".join(lines)