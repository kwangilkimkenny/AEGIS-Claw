"""Tests for the Decision Router."""

from aegis_claw.core.types import Decision, Severity
from aegis_claw.core.schemas import RuleMatch
from aegis_claw.pipeline.decision_router import DecisionRouter


class TestDecisionRouter:
    def setup_method(self):
        self.router = DecisionRouter()

    def test_no_matches_approve(self):
        result = self.router.route([])
        assert result.decision == Decision.APPROVE
        assert result.confidence >= 0.9

    def test_critical_blocks(self):
        matches = [RuleMatch(
            rule_id="r1", decision=Decision.BLOCK,
            severity=Severity.CRITICAL, risk_label="injection",
        )]
        result = self.router.route(matches)
        assert result.decision == Decision.BLOCK

    def test_high_with_rewrite_modifies(self):
        matches = [RuleMatch(
            rule_id="r1", decision=Decision.MODIFY,
            severity=Severity.HIGH, risk_label="pii",
            rewrite="[REDACTED]",
        )]
        result = self.router.route(matches)
        assert result.decision == Decision.MODIFY
        assert result.rewrite == "[REDACTED]"

    def test_high_no_rewrite_blocks(self):
        matches = [RuleMatch(
            rule_id="r1", decision=Decision.MODIFY,
            severity=Severity.HIGH, risk_label="pii",
        )]
        result = self.router.route(matches)
        assert result.decision == Decision.BLOCK  # fallback when no rewrite

    def test_medium_escalates(self):
        matches = [RuleMatch(
            rule_id="r1", decision=Decision.ESCALATE,
            severity=Severity.MEDIUM, risk_label="suspicious",
        )]
        result = self.router.route(matches)
        assert result.decision == Decision.ESCALATE

    def test_reask(self):
        matches = [RuleMatch(
            rule_id="r1", decision=Decision.REASK,
            severity=Severity.MEDIUM, risk_label="unclear",
        )]
        result = self.router.route(matches)
        assert result.decision == Decision.REASK

    def test_severity_mapping_high_default_block_uses_modify(self):
        """HIGH severity with default BLOCK decision should use severity mapping (MODIFY)."""
        matches = [RuleMatch(
            rule_id="r1", decision=Decision.BLOCK,  # default
            severity=Severity.HIGH, risk_label="test",
            rewrite="[REDACTED]",
        )]
        result = self.router.route(matches)
        # With the fix: default BLOCK + HIGH severity → MODIFY (from severity map)
        assert result.decision == Decision.MODIFY

    def test_severity_mapping_medium_default_block_uses_escalate(self):
        """MEDIUM severity with default BLOCK decision should use severity mapping (ESCALATE)."""
        matches = [RuleMatch(
            rule_id="r1", decision=Decision.BLOCK,
            severity=Severity.MEDIUM, risk_label="suspicious",
        )]
        result = self.router.route(matches)
        assert result.decision == Decision.ESCALATE

    def test_severity_mapping_low_default_block_uses_approve(self):
        """LOW severity with default BLOCK decision should use severity mapping (APPROVE)."""
        matches = [RuleMatch(
            rule_id="r1", decision=Decision.BLOCK,
            severity=Severity.LOW, risk_label="minor",
        )]
        result = self.router.route(matches)
        assert result.decision == Decision.APPROVE

    def test_explicit_escalate_respected(self):
        """Explicit ESCALATE decision should override severity mapping."""
        matches = [RuleMatch(
            rule_id="r1", decision=Decision.ESCALATE,
            severity=Severity.HIGH, risk_label="needs_review",
        )]
        result = self.router.route(matches)
        assert result.decision == Decision.ESCALATE
