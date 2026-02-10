"""
AEGIS-Claw Configuration — Centralized settings.

All hardcoded thresholds and tunables are extracted here so they can
be adjusted per environment without touching engine code.

Usage:
    from aegis_claw.core.config import AegisClawConfig

    # Use defaults
    config = AegisClawConfig()

    # Override specific values
    config = AegisClawConfig(max_input_length=5000, log_level="DEBUG")

    # Pass to guard
    guard = AegisClaw(config=config)

Environment variable overrides (optional):
    AEGIS_CLAW_LOG_LEVEL          - "DEBUG" | "INFO" | "WARNING" (default: "WARNING")
    AEGIS_CLAW_MAX_INPUT_LENGTH   - int (default: 50000)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AegisClawConfig:
    """Immutable configuration for the AEGIS-Claw guard pipeline."""

    # -- General ---------------------------------------------------------------
    log_level: str = field(
        default_factory=lambda: os.environ.get("AEGIS_CLAW_LOG_LEVEL", "WARNING")
    )
    max_input_length: int = field(
        default_factory=lambda: int(os.environ.get("AEGIS_CLAW_MAX_INPUT_LENGTH", "50000"))
    )

    # -- Safety Classifier -----------------------------------------------------
    safety_threshold: float = 0.5
    """Score >= this value is classified as unsafe."""

    # -- Jailbreak Detector ----------------------------------------------------
    anomaly_threshold: float = 0.5
    """Anomaly score >= this value triggers a structural anomaly match."""

    anomaly_special_char_ratio: float = 0.4
    """Ratio of special chars above which anomaly score increases."""

    anomaly_zero_width_min: int = 2
    """Minimum zero-width characters to trigger anomaly scoring."""

    # -- Risk Scorer -----------------------------------------------------------
    confidence_critical: float = 0.95
    confidence_high: float = 0.85
    confidence_medium: float = 0.70
    confidence_low: float = 0.50
    multi_match_bonus: float = 0.02
    multi_match_max_bonus: float = 0.10

    # -- Decision Router -------------------------------------------------------
    approve_confidence: float = 0.95
    block_confidence: float = 0.90
    modify_confidence: float = 0.85
    escalate_confidence: float = 0.70
    reask_confidence: float = 0.70

    # -- Rate Limiter ----------------------------------------------------------
    rate_limit_enabled: bool = False
    rate_limit_max_requests: int = 60
    """Maximum requests per window per session."""

    rate_limit_window_seconds: int = 60
    """Sliding window duration in seconds."""

    rate_limit_block_seconds: int = 300
    """How long to block a session that exceeds the rate limit."""
