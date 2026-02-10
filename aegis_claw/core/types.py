"""
Core type definitions for AEGIS-Claw.

Extracted and adapted from AEGIS AI Engine for Guardrail & Inspection System.
"""

from enum import Enum


class Decision(str, Enum):
    """Final judgment decision."""
    APPROVE = "approve"
    BLOCK = "block"
    MODIFY = "modify"
    ESCALATE = "escalate"
    REASK = "reask"


class Severity(str, Enum):
    """Risk severity level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class JailbreakType(str, Enum):
    """Jailbreak attack classification (9 types)."""
    DAN_MODE = "dan_mode"
    ROLE_PLAY = "role_play"
    INSTRUCTION_OVERRIDE = "instruction_override"
    DEVELOPER_MODE = "developer_mode"
    HYPOTHETICAL = "hypothetical"
    FILTER_BYPASS = "filter_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PROMPT_EXTRACTION = "prompt_extraction"
    ENCODING_ATTACK = "encoding_attack"


class SafetyCategory(str, Enum):
    """Safety classification categories."""
    SAFE = "safe"
    DANGEROUS = "dangerous"
    HARASSMENT = "harassment"
    HATE_SPEECH = "hate_speech"
    SEXUAL = "sexual"
    TOXIC = "toxic"


class ContentCategory(str, Enum):
    """Content classification for the guard pipeline."""
    SAFE = "safe"
    HARMFUL = "harmful"
    SENSITIVE = "sensitive"
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    UNKNOWN = "unknown"
