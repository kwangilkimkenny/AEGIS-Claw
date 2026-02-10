"""Tests for core type enums."""

from aegis_claw.core.types import (
    ContentCategory,
    Decision,
    JailbreakType,
    SafetyCategory,
    Severity,
)


class TestDecision:
    def test_values(self):
        assert Decision.APPROVE.value == "approve"
        assert Decision.BLOCK.value == "block"
        assert Decision.MODIFY.value == "modify"
        assert Decision.ESCALATE.value == "escalate"
        assert Decision.REASK.value == "reask"

    def test_from_string(self):
        assert Decision("block") == Decision.BLOCK
        assert Decision("approve") == Decision.APPROVE


class TestSeverity:
    def test_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"


class TestJailbreakType:
    def test_nine_types(self):
        """AEGIS defines exactly 9 jailbreak types."""
        assert len(JailbreakType) == 9

    def test_key_types(self):
        assert JailbreakType.DAN_MODE.value == "dan_mode"
        assert JailbreakType.ENCODING_ATTACK.value == "encoding_attack"
        assert JailbreakType.INSTRUCTION_OVERRIDE.value == "instruction_override"


class TestContentCategory:
    def test_values(self):
        assert ContentCategory.JAILBREAK.value == "jailbreak"
        assert ContentCategory.PROMPT_INJECTION.value == "prompt_injection"


class TestSafetyCategory:
    def test_values(self):
        assert SafetyCategory.DANGEROUS.value == "dangerous"
        assert SafetyCategory.HARASSMENT.value == "harassment"
        assert SafetyCategory.SAFE.value == "safe"
