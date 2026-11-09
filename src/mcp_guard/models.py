from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class RuleAction(str, Enum):
    SIGNAL = "signal"
    REVIEW = "review"
    BLOCK = "block"


@dataclass(frozen=True)
class ToolRegistration:
    server_name: str
    namespace: str
    tool_name: str
    description: str
    source: str
    schema_hash: str | None = None


@dataclass(frozen=True)
class InspectionFinding:
    code: str
    severity: Severity
    message: str
    marker: str
    stage: str
    action: RuleAction = RuleAction.SIGNAL
    evidence: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class GuardDecision:
    verdict: Verdict
    findings: tuple[InspectionFinding, ...] = field(default_factory=tuple)
    b_scores: tuple[dict[str, object], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        result = {
            "verdict": self.verdict.value,
            "findings": [
                {
                    "code": finding.code,
                    "severity": finding.severity.value,
                    "action": finding.action.value,
                    "marker": finding.marker,
                    "stage": finding.stage,
                    "message": finding.message,
                    "evidence": finding.evidence,
                    "metadata": finding.metadata,
                }
                for finding in self.findings
            ],
        }
        if self.b_scores:
            result["b_scores"] = list(self.b_scores)
        return result

