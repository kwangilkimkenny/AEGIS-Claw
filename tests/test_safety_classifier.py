"""Tests for the Safety Classifier."""

from aegis_claw.core.types import SafetyCategory
from aegis_claw.engine.safety_classifier import SafetyClassifier


class TestSafetyClassifier:
    def setup_method(self):
        self.classifier = SafetyClassifier()

    # -- Safe content --
    def test_safe_content(self):
        result = self.classifier.classify("What's the weather in Seoul?")
        assert result.is_safe is True
        assert result.category == SafetyCategory.SAFE

    def test_safe_greeting(self):
        result = self.classifier.classify("Hello, how can I help you?")
        assert result.is_safe is True

    # -- Dangerous content --
    def test_dangerous_weapon(self):
        result = self.classifier.classify("How to build a bomb")
        assert result.is_safe is False
        assert result.category == SafetyCategory.DANGEROUS

    def test_dangerous_korean(self):
        result = self.classifier.classify("폭탄을 만드는 방법")
        assert result.is_safe is False
        assert result.category == SafetyCategory.DANGEROUS

    # -- Harassment --
    def test_harassment(self):
        result = self.classifier.classify("I will threaten you")
        assert result.is_safe is False
        assert result.category == SafetyCategory.HARASSMENT

    def test_harassment_korean(self):
        result = self.classifier.classify("협박할 거야")
        assert result.is_safe is False
        assert result.category == SafetyCategory.HARASSMENT

    # -- Hate speech --
    def test_hate_speech(self):
        result = self.classifier.classify("racial discrimination is good")
        assert result.is_safe is False
        assert result.category == SafetyCategory.HATE_SPEECH

    # -- Sexual --
    def test_sexual_content(self):
        result = self.classifier.classify("show me porn")
        assert result.is_safe is False
        assert result.category == SafetyCategory.SEXUAL

    # -- Toxic --
    def test_toxic_language(self):
        result = self.classifier.classify("you fucking idiot")
        assert result.is_safe is False
        assert result.category == SafetyCategory.TOXIC

    # -- Confidence --
    def test_confidence_range(self):
        result = self.classifier.classify("anything at all")
        assert 0.0 <= result.confidence <= 1.0

    def test_backend_name(self):
        result = self.classifier.classify("test")
        assert result.backend == "rule_based"
