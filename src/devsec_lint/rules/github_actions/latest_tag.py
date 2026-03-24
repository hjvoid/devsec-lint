from __future__ import annotations

from typing import Any

from devsec_lint.models import Finding, WorkflowDocument
from devsec_lint.rules.base import Rule


def _find_line(raw_text: str, needle: str) -> int | None:
    for i, line in enumerate(raw_text.splitlines(), start=1):
        if needle in line:
            return i
    return None


class LatestTagRule(Rule):
    rule_id = "containers/latest-tag"
    title = "Container image uses the latest tag"
    severity = "MEDIUM"
    description = "Using ':latest' makes builds less predictable and increases supply-chain risk."

    def check(self, document: WorkflowDocument) -> list[Finding]:
        findings: list[Finding] = []
        data = document.data

        if not isinstance(data, str):
            return findings

        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            findings.extend(
                self._check_container_like(
                    document=document,
                    job_name=job_name,
                    obj=job.get("container"),
                    context=f"job '{job_name}' container",
                )
            )

            services = job.get("services", {})
            if isinstance(services, dict):
                for service_name, service in services.items():
                    findings.extend(
                        self._check_container_like(
                            document=document,
                            job_name=job_name,
                            obj=service,
                            context=f"service '{service_name}'  in job '{job_name}'",
                            service_name=service_name,
                        )
                    )
        return findings

    def _check_container_like(
            self,
            document: WorkflowDocument,
            job_name: str,
            obj: Any,
            context: str,
            service_name: str | None = None,
    ) -> list[Finding]:
        image: str | None = None

        if isinstance(obj, str):
            image = obj
        elif isinstance(obj, dict):
            value = obj.get("image")
            if isinstance(value, str):
                image = value

        if not image or ":latest" not in image:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=f"{context.capitalize()} uses a mutable ':latest' tag: {image}'",
                file_path=str(document.path),
                line=_find_line(document.raw_text, image),
                snippet=f"image: {image}",
                remediation="Replace ':latest; with a specific version and preferably pin by digest.",
                metadata={
                    "job": job_name,
                    "service": service_name,
                    "image": image,
                }

            )
        ]
