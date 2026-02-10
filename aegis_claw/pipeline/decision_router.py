"""
Decision Router — Maps severity to final decisions.

Converts rule matches into actionable decisions:
  CRITICAL → BLOCK
  HIGH     → MODIFY (or BLOCK if no rewrite available)
  MEDIUM   → ESCALATE
  LOW      → APPROVE (log only)

Ported from AEGIS Decision Router (src/aegis/services/decision_router.py).
"""

from __future__ import annotations

from aegis_claw.core.config import AegisClawConfig
from aegis_claw.core.types import Decision, Severity
from aegis_claw.core.schemas import RuleMatch


# ---------------------------------------------------------------------------
# Severity → Decision mapping
# ---------------------------------------------------------------------------

_SEVERITY_DECISION_MAP: dict[Severity, Decision] = {
    Severity.CRITICAL: Decision.BLOCK,
    Severity.HIGH: Decision.MODIFY,
    Severity.MEDIUM: Decision.ESCALATE,
    Severity.LOW: Decision.APPROVE,
}


class RoutingResult:
    """Output of the Decision Router."""

    __slots__ = ("decision", "confidence", "rewrite", "message", "primary_match")

    def __init__(
        self,
        decision: Decision = Decision.APPROVE,
        confidence: float = 0.95,
        rewrite: str | None = None,
        message: str | None = None,
        primary_match: RuleMatch | None = None,
    ) -> None:
        self.decision = decision
        self.confidence = confidence
        self.rewrite = rewrite
        self.message = message
        self.primary_match = primary_match


class DecisionRouter:
    """Routes rule matches to final decisions (~1ms)."""

    def __init__(self, config: AegisClawConfig | None = None) -> None:
        self._config = config or AegisClawConfig()

    def route(self, matches: list[RuleMatch]) -> RoutingResult:
        """Convert sorted rule matches into a routing decision."""

        # No matches → safe
        if not matches:
            return RoutingResult(
                decision=Decision.APPROVE,
                confidence=self._config.approve_confidence,
            )

        primary = matches[0]  # Already sorted by severity

        # Handle explicit REASK decision
        if primary.decision == Decision.REASK:
            return RoutingResult(
                decision=Decision.REASK,
                confidence=self._config.reask_confidence,
                message=f"Clarification needed: {primary.risk_label}",
                primary_match=primary,
            )

        # Use rule-specified decision if it differs from the default BLOCK,
        # otherwise fall back to severity-based mapping.
        severity_decision = _SEVERITY_DECISION_MAP.get(primary.severity, Decision.ESCALATE)
        if primary.decision != Decision.BLOCK:
            # Rule explicitly specifies a non-default decision — respect it
            decision = primary.decision
        else:
            decision = severity_decision

        # For MODIFY: verify rewrite is available
        if decision == Decision.MODIFY:
            if primary.rewrite:
                return RoutingResult(
                    decision=Decision.MODIFY,
                    confidence=self._config.modify_confidence,
                    rewrite=primary.rewrite,
                    message=f"Modified: {primary.risk_label}",
                    primary_match=primary,
                )
            else:
                # No rewrite available → escalate to BLOCK
                return RoutingResult(
                    decision=Decision.BLOCK,
                    confidence=self._config.block_confidence - 0.10,
                    message=f"Blocked: {primary.risk_label} (no rewrite available)",
                    primary_match=primary,
                )

        # BLOCK or ESCALATE
        conf = (
            self._config.block_confidence
            if decision == Decision.BLOCK
            else self._config.escalate_confidence
        )
        return RoutingResult(
            decision=decision,
            confidence=conf,
            message=f"{decision.value.title()}: {primary.risk_label}",
            primary_match=primary,
        )
