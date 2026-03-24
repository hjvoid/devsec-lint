from pathlib import Path

from devsec_lint.rules.github_actions.missing_permissions import MissingPermissionsRule
from devsec_lint.scanner.parser import load_workflow

def test_flags_missing_top_level_permissions(tmp_path) -> None:
    workflow = tmp_path / "test.yml"
    workflow.write_text(
        """
        name: CI
        on: push
        jobs:
            build:
                runs-on: ubuntu-latest
                steps:
                    - run: echo "hello"
        """.strip(),
        encoding="utf-8",
    )

    doc = load_workflow(workflow)
    rule = MissingPermissionsRule()

    findings = rule.check(doc)
    assert len(findings) == 1
    assert findings[0].rule_id == "workflow/missing-permissions"
    assert findings[0].severity == "MEDIUM"

def test_allows_explicit_top_level_permissions(tmp_path: Path) -> None:
    workflow = tmp_path / "test.yml"
    workflow.write_text(
        """
            name: CI
            on: push
            permissions:
                contents: read
            jobs:
                build:
                    runs-on: ubuntu-latest
                    steps:
                        - run: echo "hello
        """.strip(),
        encoding="utf-8",
    )

    doc = load_workflow(workflow)
    rule = MissingPermissionsRule()

    findings = rule.check(doc)

    assert findings == []