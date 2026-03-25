from pathlib import Path

from devsec_lint.rules.github_actions.latest_tag import LatestTagRule
from devsec_lint.scanner.parser import load_workflow

def test_flags_latest_tag_in_service_image(tmp_path: Path) -> None:
    workflow = tmp_path / "test.yml"
    workflow.write_text(
        """
        name: CI
        on: push
        jobs: 
            test:
                runs-on: ubuntu-latest
                services:
                    redis:
                        image: redis:latest
                    steps:
                        - run: echo "hello"
        """.strip(),
        encoding="utf-8",
    )

    doc = load_workflow(workflow)
    rule = LatestTagRule()

    findings = rule.check(doc)

    assert len(findings) == 1
    assert findings[0].rule_id == "containers/latest-tag"
    assert findings[0].severity == "MEDIUM"

def test_ignores_non_latest_tags(tmp_path: Path) -> None:
    workflow = tmp_path / "test.yml"
    workflow.write_text(
        """
        name: CI
        on: push
        jobs:
            test:
            runs-on: ubuntu-latest
            services:
                redis:
                    image: redis:7
            steps:
                - run: echo "hello"
        """.strip(),
        encoding="utf-8",
    )

    doc = load_workflow(workflow)
    rule = LatestTagRule()

    findings = rule.check(doc)

    assert findings == []