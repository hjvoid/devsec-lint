from __future__ import annotations

import sys
from typing import Annotated

import typer

from src.devsec_lint.constants import DEFAULT_SEVERITY, SEVERITIES
from src.devsec_lint.exit_codes import SUCCESS, USAGE_ERROR, FAILURE_FOUND
from src.devsec_lint.formatters import format_json, format_text
from src.devsec_lint.rules import ALL_RULES
from src.devsec_lint.scanner.discover import discover_workflow_files
from src.devsec_lint.scanner.engine import scan_files
from src.devsec_lint.utils.severity import meets_threshold

app = typer.Typer(help="Static security linting for Github Actions pipelines")

@app.command()
def scan(
        path: str = typer.Argument(..., help="Repo root, workflow directory, or workflow file."),
        format: Annotated[str, typer.Option("--format", help="Output format: text or json.")] = "text",
        severity: Annotated[
            str, typer.Option("--severity", help="Minimum severity threshold.")
        ] = DEFAULT_SEVERITY,
) -> None:
    fmt = format.lower()
    sev = severity.upper()

    if fmt not in ("text", "json"):
        typer.echo("Invalid --format. Use 'text' or 'json'.", err=True)
        raise typer.Exit(USAGE_ERROR)

    if sev not in SEVERITIES:
        typer.echo("Invalid --severity. Use LOW, MEDIUM, HIGH.", err=True)
        raise typer.Exit(USAGE_ERROR)

    try:
        files = discover_workflow_files(path)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(FAILURE_FOUND)

    if not files:
        typer.echo("No workflow YAML files found.", err=True)
        raise typer.Exit(FAILURE_FOUND)

    findings, errors = scan_files(files, ALL_RULES)
    findings = [f for f in findings if meets_threshold(f.severity, sev)]

    output = format_text(findings, errors) if fmt == "text" else format_json(findings, errors)
    typer.echo(output)

    if findings:
        raise typer.Exit(SUCCESS)

    raise typer.Exit(SUCCESS)

def main() -> None:
    app()

if __name__ == "__main__":
    main()

