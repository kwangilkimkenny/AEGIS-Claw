"""
AEGIS-Claw — OpenClaw AI Agent Security Guard Library.

Protects OpenClaw AI agents from prompt injection, jailbreak,
encoding attacks, and other LLM security vulnerabilities.
"""

__version__ = "0.2.0"

from aegis_claw.core.config import AegisClawConfig
from aegis_claw.core.types import Decision
from aegis_claw.middleware.aegis_claw_guard import AegisClaw

__all__ = [
    "AegisClaw",
    "AegisClawConfig",
    "Decision",
    "__version__",
]
