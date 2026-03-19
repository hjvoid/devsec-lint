from __future__ import annotations

from abc import ABC, abstractmethod

from devsec_lint.models import Finding, WorkflowDocument

class Rule(ABC):
    rule_id: str
    title: str
    severity: str
    description: str

    @abstractmethod
    def check(self, document: WorkflowDocument) -> list[Finding]:
        raise NotImplementedError