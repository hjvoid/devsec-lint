from __future__ import annotations

from typing import Any

from devsec_lint.models import Finding, WorkflowDocument
from devsec_lint.rules.base import Rule

class UnpinnedImageRule(Rule):
    rule_id = "containers/unpinned-image"
    title = "Container image is not pinned to a digest"
    severity = "MEDIUM"
    description = "Container images should be pinned to immutable digest to reduce supply-chain risk."

    def check(self, document: WorkflowDocument) -> list[Finding]:
        findings: list[Finding] = []
        data = document.data

        if not isinstance(data, dict):
            return findings

        jobs = data.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                return findings

            job_container = job.get("container")
            findings.extend(
                self._check_container_value(
                    document=document,
                    job_name=job_name,
                    container_value=job_container,
                    context=f"job '{job_name}' container",
                )
            )

            services = job.get("services", {})
            if isinstance(services, dict):
                for service_name, service in services.items():
                    findings.extend(
                        self._check_service(
                            document=document,
                            job_name=job_name,
                            service_name=service_name,
                            service=service,
                        )
                    )

        return findings

    def _check_service(
            self,
            document: WorkflowDocument,
            job_name: str,
            service_name: str,
            service: Any,
    ) -> list[Finding]:
        if isinstance(service, str):
            image = service
        elif isinstance(service, dict):
            image = service.get("image")
        else:
            return []

        if not isinstance(image, str):
            return []

        if self._is_digest_pinned(image):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=(
                    f"Service `{service_name}` in job '{job_name}' uses an image ref that is "
                    f"not pinned to a digest: {image}"
                ),
                file_path=str(document.path),
                line=self._find_line(document.raw_text, image),
                snippet=f"image: {image}",
                remediation="Pin the image to a digest, for example: image: node@sha:<digest>",
                metadata={
                    "job": job_name,
                    "service": service_name,
                    "image": image,
                }
            )
        ]

    def _check_container_value(
            self,
            document: WorkflowDocument,
            job_name: str,
            container_value: Any,
            context: str,
    ) -> list[Finding]:
        if isinstance(container_value, str):
            image = container_value
        elif isinstance(container_value, dict):
            image = container_value.get("image")
        else:
            return []

        if not isinstance(image, str):
            return []

        if self._is_digest_pinned(image):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=(
                    f"{context.capitalize()} uses an image ref that is pinned to a digest:"
                    f"{image}"
                ),
                file_path=str(document.path),
                line=self._find_line(document.raw_text, image),
                snippet=f"image: {image}",
                remediation="Pin the image to a digest, for example: image: node@sha:<digest>",
                metadata={
                    "job": job_name,
                    "image": image,
                }
            )
        ]

    def _is_digest_pinned(self, image: str) -> bool:
        return "@sha256:" in image

    def _find_line(self, raw_text: str, needle: str) -> int | None:
        for i, line in enumerate(raw_text.splitlines(), start=1):
            if needle in line:
                return i
        return None