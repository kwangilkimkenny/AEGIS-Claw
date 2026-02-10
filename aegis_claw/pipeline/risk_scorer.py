"""
Risk Scorer — Confidence calculation from rule matches.

Computes a confidence score based on:
  - Primary match severity
  - Number of additional matches (multi-match bonus)

Ported from AEGIS Risk Scorer (src/aegis/services/risk_scorer.py).
"""

from __future__ import annotations

from aegis_claw.core.config import AegisClawConfig
from aegis_claw.core.types import Severity
from aegis_claw.core.schemas import RuleMatch, RiskInfo


class RiskScore:
    """Computed risk score."""

    __slots__ = ("confidence", "severity", "risk_label", "description")

    def __init__(
        self,
        confidence: float = 0.95,
        severity: Severity | None = None,
        risk_label: str | None = None,
        description: str | None = None,
    ) -> None:
        self.confidence = confidence
        self.severity = severity
        self.risk_label = risk_label
        self.description = description

    def to_risk_info(self) -> RiskInfo | None:
        """Convert to a RiskInfo schema object."""
        if self.severity is None:
            return None
        return RiskInfo(
            label=self.risk_label or "unknown",
            severity=self.severity,
            description=self.description,
        )


class RiskScorer:
    """Calculates confidence scores from rule matches (~1ms)."""

    def __init__(self, config: AegisClawConfig | None = None) -> None:
        self._config = config or AegisClawConfig()
        self._severity_confidence: dict[Severity, float] = {
            Severity.CRITICAL: self._config.confidence_critical,
            Severity.HIGH: self._config.confidence_high,
            Severity.MEDIUM: self._config.confidence_medium,
            Severity.LOW: self._config.confidence_low,
        }

    def calculate(self, matches: list[RuleMatch]) -> RiskScore:
        """Compute risk score from matched rules."""

        if not matches:
            return RiskScore(confidence=0.95, severity=None)

        primary = matches[0]

        # Base confidence from severity
        base_confidence = self._severity_confidence.get(primary.severity, 0.50)

        # Multi-match bonus: configurable per-match bonus with max cap
        bonus = self._config.multi_match_bonus
        max_bonus = self._config.multi_match_max_bonus
        match_bonus = min(max_bonus, (len(matches) - 1) * bonus)
        confidence = min(0.99, base_confidence + match_bonus)

        return RiskScore(
            confidence=round(confidence, 2),
            severity=primary.severity,
            risk_label=primary.risk_label,
            description=primary.description,
        )
