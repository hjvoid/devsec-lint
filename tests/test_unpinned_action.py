from pathlib import Path

from textwrap import dedent

from devsec_lint.rules.github_actions.unpinned_action import UnpinnedActionRule
from devsec_lint.scanner.parser import load_workflow

def test_flags_unpinned_action(tmp_path: Path) -> None:
    workflow = tmp_path / "test.yml"
    workflow.write_text(
        dedent(
        """
        name: CI
        on: push
        jobs: 
            build:
                runs-on: ubuntu-latest
                steps:
                    - uses: actions/checkout@v4
                    - run: echo "hello"
        """).strip(),
        encoding="utf-8",
    )

    doc = load_workflow(workflow)
    rule = UnpinnedActionRule()

    findings = rule.check(doc)

    assert len(findings) == 1
    assert findings[0].rule_id == "actions/unpinned-version"
    assert findings[0].severity == "HIGH"

def test_allows_sha_pinned_action(tmp_path: Path) -> None:
    workflow = tmp_path / "test.yml"
    workflow.write_text(
        dedent(
        """
        name: CI
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
              - run: echo "hello"
        """).strip(),encoding="utf-8",
    )
    doc = load_workflow(workflow)
    rule = UnpinnedActionRule()

    findings = rule.check(doc)

    assert findings == []