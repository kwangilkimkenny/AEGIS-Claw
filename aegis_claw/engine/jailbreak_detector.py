"""
Jailbreak Detector — 3-layer jailbreak detection.

Detects 9 types of jailbreak attacks using:
  1. Pattern detection (multilingual regex)
  2. Encoding attack detection (Base64, ROT13, Homoglyph)
  3. Perplexity analysis (anomaly scoring)

Ported from AEGIS Jailbreak Detector (src/aegis/services/jailbreak_detector.py).
"""

from __future__ import annotations

import base64
import codecs
import logging
import re
from typing import Any

from aegis_claw.core.config import AegisClawConfig
from aegis_claw.core.types import JailbreakType
from aegis_claw.core.schemas import JailbreakMatch

logger = logging.getLogger("aegis_claw.engine.jailbreak_detector")


# ---------------------------------------------------------------------------
# Jailbreak patterns — multilingual (English + Korean)
# Pre-compiled at module load time for performance.
# ---------------------------------------------------------------------------

_JAILBREAK_PATTERNS: dict[JailbreakType, list[tuple[re.Pattern[str], str, float]]] = {
    JailbreakType.DAN_MODE: [
        (re.compile(r"(?i)\bDAN\s*(mode)?\b"), "dan_mode", 0.95),
        (re.compile(r"(?i)do\s*anything\s*now"), "dan_explicit", 0.95),
        (re.compile(r"(?i)지금부터\s*너는\s*DAN"), "dan_korean", 0.95),
        (re.compile(r"(?i)무엇이든\s*할\s*수\s*있"), "dan_korean_alt", 0.90),
    ],
    JailbreakType.INSTRUCTION_OVERRIDE: [
        (re.compile(r"(?i)ignore\s*(all\s*)?(previous|prior)\s*instructions?"), "ignore_prev", 0.95),
        (re.compile(r"(?i)disregard\s*(your\s*)?(safety|ethical)\s*guidelines?"), "disregard_safety", 0.95),
        (re.compile(r"(?i)forget\s*(all\s*)?(your\s*)?(rules|instructions|guidelines)"), "forget_rules", 0.90),
        (re.compile(r"(?i)이전\s*지시.*무시"), "ignore_korean", 0.95),
        (re.compile(r"(?i)안전\s*지침.*무시"), "safety_ignore_korean", 0.95),
        (re.compile(r"(?i)규칙.{0,6}(잊어|무시|버려)"), "forget_rules_korean", 0.90),
    ],
    JailbreakType.ROLE_PLAY: [
        (re.compile(r"(?i)you\s*are\s*(now\s*)?(an?\s*)?(evil|unrestricted|unfiltered)"), "evil_ai", 0.90),
        (re.compile(r"(?i)pretend\s*(to\s*be|you\s*are)\s*(an?\s*)?evil"), "pretend_evil", 0.90),
        (re.compile(r"(?i)act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored)"), "act_unrestricted", 0.90),
        (re.compile(r"(?i)너는\s*이제\s*(악한|제한없는|필터없는)"), "evil_korean", 0.90),
    ],
    JailbreakType.DEVELOPER_MODE: [
        (re.compile(r"(?i)(developer|admin|debug|maintenance)\s*(mode|access)"), "dev_mode", 0.90),
        (re.compile(r"(?i)enable\s*(developer|debugging|admin)\s*(mode|access)"), "enable_dev", 0.90),
        (re.compile(r"(?i)(개발자|관리자|디버그)\s*모드"), "dev_mode_korean", 0.90),
    ],
    JailbreakType.HYPOTHETICAL: [
        (re.compile(r"(?i)(hypothetically|in\s*theory|let's\s*say|imagine\s*if|what\s*if)\s*.*(no\s*rules|no\s*restrictions|anything)"), "hypothetical", 0.80),
        (re.compile(r"(?i)(소설|시나리오|가상|가설).{0,20}(제한\s*없|규칙\s*없)"), "hypothetical_korean", 0.80),
    ],
    JailbreakType.FILTER_BYPASS: [
        (re.compile(r"(?i)(bypass|circumvent|evade|disable)\s*(the\s*)?(safety|content)?\s*(filter|restriction|guardrail)"), "filter_bypass", 0.90),
        (re.compile(r"(?i)(필터|제한|가드레일).{0,6}(우회|비활성|무력화|해제)"), "filter_bypass_korean", 0.90),
    ],
    JailbreakType.PRIVILEGE_ESCALATION: [
        (re.compile(r"(?i)(grant|give)\s*(me\s*)?(admin|root|elevated|superuser)\s*(access|privilege|permission)"), "priv_escalation", 0.90),
        (re.compile(r"(?i)/elevated\s+(on|enable|activate)"), "openclaw_elevated", 0.95),
        (re.compile(r"(?i)(관리자|루트|최고)\s*권한.{0,6}(부여|활성|줘)"), "priv_escalation_korean", 0.90),
    ],
    JailbreakType.PROMPT_EXTRACTION: [
        (re.compile(r"(?i)(show|print|display|output|reveal|repeat)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt)"), "prompt_extract", 0.90),
        (re.compile(r"(?i)what\s*(is|are)\s+your\s+(system\s+)?instructions?"), "what_instructions", 0.85),
        (re.compile(r"(?i)(시스템\s*프롬프트|초기\s*지시|원래\s*프롬프트).{0,10}(보여|출력|알려|말해)"), "prompt_extract_korean", 0.90),
    ],
    JailbreakType.ENCODING_ATTACK: [
        # Detected via _detect_encoding_attacks, not pattern alone
    ],
}


# Keywords that indicate harmful intent (used for decoded content checks)
_HARMFUL_KEYWORDS = [
    "ignore instructions", "system prompt", "bypass", "override",
    "delete all", "rm -rf", "drop table", "exec(", "eval(",
    "무시", "시스템 프롬프트", "우회", "삭제", "파괴",
]


# Unicode confusable mappings (common Cyrillic→Latin substitutions)
_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u043d": "h", "\u0422": "T", "\u041c": "M",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041d": "H",
    "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0425": "X",
}


class JailbreakDetector:
    """Detects jailbreak attempts using a 3-layer defense (~20ms)."""

    def __init__(self, config: AegisClawConfig | None = None) -> None:
        self._patterns = _JAILBREAK_PATTERNS
        self._config = config or AegisClawConfig()

    # -- Public API -----------------------------------------------------------

    def detect(self, text: str) -> list[JailbreakMatch]:
        """Run all detection layers and return combined matches."""
        matches: list[JailbreakMatch] = []

        # Layer 1: Pattern detection
        matches.extend(self._detect_patterns(text))

        # Layer 2: Encoding attack detection
        matches.extend(self._detect_encoding_attacks(text))

        # Layer 3: Perplexity / anomaly analysis
        anomaly = self._detect_anomalies(text)
        if anomaly:
            matches.append(anomaly)

        # Sort by confidence descending
        matches.sort(key=lambda m: m.confidence, reverse=True)

        if matches:
            logger.warning(
                "JailbreakDetector: %d match(es) — top: %s (conf=%.2f)",
                len(matches),
                matches[0].pattern,
                matches[0].confidence,
            )

        return matches

    def is_jailbreak(self, text: str) -> bool:
        """Quick check: does the text contain any jailbreak attempt?"""
        return len(self.detect(text)) > 0

    # -- Layer 1: Pattern Detection -------------------------------------------

    def _detect_patterns(self, text: str) -> list[JailbreakMatch]:
        matches: list[JailbreakMatch] = []
        matched_types: set[JailbreakType] = set()

        for jb_type, patterns in self._patterns.items():
            if jb_type in matched_types:
                continue
            for compiled_re, pattern_name, confidence in patterns:
                match = compiled_re.search(text)
                if match:
                    matches.append(JailbreakMatch(
                        type=jb_type,
                        pattern=pattern_name,
                        matched_text=match.group(0)[:80],
                        confidence=confidence,
                    ))
                    matched_types.add(jb_type)
                    break  # one match per type

        return matches

    # -- Layer 2: Encoding Attack Detection -----------------------------------

    def _detect_encoding_attacks(self, text: str) -> list[JailbreakMatch]:
        matches: list[JailbreakMatch] = []

        b64 = self._detect_base64(text)
        if b64:
            matches.append(b64)

        rot13 = self._detect_rot13(text)
        if rot13:
            matches.append(rot13)

        homoglyph = self._detect_homoglyphs(text)
        if homoglyph:
            matches.append(homoglyph)

        return matches

    def _detect_base64(self, text: str) -> JailbreakMatch | None:
        """Detect Base64-encoded harmful content."""
        for match in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", text):
            try:
                decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
                if self._contains_harmful(decoded):
                    logger.warning(
                        "Base64 harmful content detected: '%s...'",
                        decoded[:40],
                    )
                    return JailbreakMatch(
                        type=JailbreakType.ENCODING_ATTACK,
                        pattern="base64_harmful",
                        matched_text=match.group(0)[:50] + "...",
                        confidence=0.90,
                        metadata={"decoded_preview": decoded[:100]},
                    )
            except Exception as exc:
                logger.debug("Base64 decode failed for segment: %s", exc)
        return None

    def _detect_rot13(self, text: str) -> JailbreakMatch | None:
        """Detect ROT13-encoded harmful content."""
        # Only check if text has unusual letter distribution
        if len(text) < 20:
            return None
        decoded = codecs.decode(text, "rot_13")
        if self._contains_harmful(decoded) and not self._contains_harmful(text):
            logger.warning("ROT13 harmful content detected")
            return JailbreakMatch(
                type=JailbreakType.ENCODING_ATTACK,
                pattern="rot13_harmful",
                matched_text=text[:50] + "...",
                confidence=0.80,
                metadata={"decoded_preview": decoded[:100]},
            )
        return None

    def _detect_homoglyphs(self, text: str) -> JailbreakMatch | None:
        """Detect Unicode homoglyph substitution attacks."""
        normalized = self._normalize_homoglyphs(text)
        if normalized == text:
            return None

        # Check if the normalized version reveals harmful content
        if self._contains_harmful(normalized) and not self._contains_harmful(text):
            logger.warning("Homoglyph attack detected")
            return JailbreakMatch(
                type=JailbreakType.ENCODING_ATTACK,
                pattern="homoglyph_attack",
                matched_text=text[:50],
                confidence=0.85,
                metadata={"normalized_preview": normalized[:100]},
            )

        # Also check if normalized form matches any jailbreak patterns
        pattern_matches = self._detect_patterns(normalized)
        if pattern_matches and not self._detect_patterns(text):
            return JailbreakMatch(
                type=JailbreakType.ENCODING_ATTACK,
                pattern="homoglyph_jailbreak",
                matched_text=text[:50],
                confidence=0.85,
                metadata={
                    "normalized_preview": normalized[:100],
                    "hidden_type": pattern_matches[0].type.value,
                },
            )

        return None

    # -- Layer 3: Anomaly Detection -------------------------------------------

    def _detect_anomalies(self, text: str) -> JailbreakMatch | None:
        """Detect suspicious structural anomalies."""
        score = 0.0
        cfg = self._config

        # Check for excessive special characters (possible obfuscation)
        special_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
        if special_ratio > cfg.anomaly_special_char_ratio:
            score += 0.3

        # Check for zero-width characters (invisible injection)
        zw_chars = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"]
        zw_count = sum(text.count(c) for c in zw_chars)
        if zw_count > cfg.anomaly_zero_width_min:
            score += 0.4

        # Check for RTL override characters
        if "\u202e" in text or "\u202d" in text or "\u200f" in text:
            score += 0.5

        # Check for repeated delimiter-like patterns (role injection)
        if re.search(r"(---+|===+|####+|\*{4,}){2,}", text):
            score += 0.2

        if score >= cfg.anomaly_threshold:
            logger.warning(
                "Structural anomaly detected (score=%.2f, threshold=%.2f)",
                score,
                cfg.anomaly_threshold,
            )
            return JailbreakMatch(
                type=JailbreakType.ENCODING_ATTACK,
                pattern="structural_anomaly",
                matched_text=text[:50],
                confidence=min(score, 0.95),
                metadata={"anomaly_score": round(score, 2)},
            )

        return None

    # -- Helpers --------------------------------------------------------------

    def _contains_harmful(self, text: str) -> bool:
        """Check if text contains known harmful keywords."""
        text_lower = text.lower()
        return any(kw in text_lower for kw in _HARMFUL_KEYWORDS)

    def _normalize_homoglyphs(self, text: str) -> str:
        """Replace known homoglyph characters with Latin equivalents."""
        result = []
        for char in text:
            if char in _HOMOGLYPH_MAP:
                result.append(_HOMOGLYPH_MAP[char])
            else:
                result.append(char)
        return "".join(result)
