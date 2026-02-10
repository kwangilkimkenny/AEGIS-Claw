"""
Pydantic schemas for guard requests and responses.

Adapted from AEGIS judgment pipeline data models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from .types import (
    ContentCategory,
    Decision,
    JailbreakType,
    SafetyCategory,
    Severity,
)


# ---------------------------------------------------------------------------
# Internal match models
# ---------------------------------------------------------------------------


class RuleMatch(BaseModel):
    """A single rule engine match."""
    rule_id: str
    decision: Decision
    severity: Severity
    risk_label: str
    description: str | None = None
    matched_text: str | None = None
    rewrite: str | None = None


class JailbreakMatch(BaseModel):
    """A single jailbreak detector match."""
    type: JailbreakType
    pattern: str
    matched_text: str | None = None
    confidence: float = 0.0
    metadata: dict[str, Any] | None = None


class SafetyScore(BaseModel):
    """Safety classifier result."""
    is_safe: bool
    category: SafetyCategory = SafetyCategory.SAFE
    confidence: float = 0.0
    backend: str = "rule_based"


# ---------------------------------------------------------------------------
# Pipeline stage tracking
# ---------------------------------------------------------------------------


class PipelineStage(BaseModel):
    """Tracks a single stage in the guard pipeline."""
    name: str
    latency_ms: float = 0.0
    passed: bool = True
    detail: str | None = None


# ---------------------------------------------------------------------------
# Public request / response models
# ---------------------------------------------------------------------------


class GuardRequest(BaseModel):
    """Input to the guard pipeline."""
    text: str
    source: str = "user"  # "user" | "external" | "command" | "output"
    scenario: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] | None = None


class RiskInfo(BaseModel):
    """Risk information attached to a guard response."""
    label: str
    severity: Severity
    description: str | None = None


class EvidenceItem(BaseModel):
    """A piece of evidence supporting the decision."""
    rule_id: str
    reason: str
    matched_text: str | None = None


class GuardResponse(BaseModel):
    """Output of the guard pipeline."""
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    decision: Decision = Decision.APPROVE
    confidence: float = 0.95
    risk: RiskInfo | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    rewrite: str | None = None
    message: str | None = None
    pipeline_stages: list[PipelineStage] = Field(default_factory=list)
    total_latency_ms: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Content categories → decision mapping (from AEGIS V2)
# ---------------------------------------------------------------------------

CATEGORY_TO_DECISION: dict[ContentCategory, Decision] = {
    ContentCategory.SAFE: Decision.APPROVE,
    ContentCategory.HARMFUL: Decision.BLOCK,
    ContentCategory.SENSITIVE: Decision.MODIFY,
    ContentCategory.JAILBREAK: Decision.BLOCK,
    ContentCategory.PROMPT_INJECTION: Decision.BLOCK,
    ContentCategory.UNKNOWN: Decision.ESCALATE,
}

CATEGORY_TO_SEVERITY: dict[ContentCategory, Severity] = {
    ContentCategory.SAFE: Severity.LOW,
    ContentCategory.HARMFUL: Severity.CRITICAL,
    ContentCategory.SENSITIVE: Severity.HIGH,
    ContentCategory.JAILBREAK: Severity.CRITICAL,
    ContentCategory.PROMPT_INJECTION: Severity.CRITICAL,
    ContentCategory.UNKNOWN: Severity.MEDIUM,
}
