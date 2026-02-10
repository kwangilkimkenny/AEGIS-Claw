"""
Safety Classifier — Rule-based content safety classification.

Classifies content into safety categories using pattern matching.
This is the always-available fallback backend from AEGIS Safety Classifier.

Ported from AEGIS Safety Classifier rule-based backend
(src/aegis/services/safety_classifier.py).
"""

from __future__ import annotations

import logging
import re

from aegis_claw.core.config import AegisClawConfig
from aegis_claw.core.types import SafetyCategory
from aegis_claw.core.schemas import SafetyScore

logger = logging.getLogger("aegis_claw.engine.safety_classifier")


# ---------------------------------------------------------------------------
# Multilingual safety patterns (English + Korean) — pre-compiled
# ---------------------------------------------------------------------------

_SAFETY_PATTERNS: dict[SafetyCategory, list[tuple[re.Pattern[str], float]]] = {
    SafetyCategory.DANGEROUS: [
        (re.compile(r"(?i)\b(kill|murder|assassinate)\b"), 0.90),
        (re.compile(r"(?i)\b(bomb|explosive|detonate)\b"), 0.95),
        (re.compile(r"(?i)\b(suicide|self[.\-\s]?harm)\b"), 0.95),
        (re.compile(r"(?i)\b(weapon|firearm|gun)\b"), 0.70),
        (re.compile(r"(?i)\b(poison|poisoning|cyanide)\b"), 0.90),
        (re.compile(r"(?i)(죽이|살인|살해|암살)"), 0.90),
        (re.compile(r"(?i)(폭탄|폭발물|기폭)"), 0.95),
        (re.compile(r"(?i)(자살|자해|극단적\s*선택)"), 0.95),
        (re.compile(r"(?i)(무기|총기|화기)"), 0.70),
        (re.compile(r"(?i)(독약|독극물|청산가리)"), 0.90),
    ],
    SafetyCategory.HARASSMENT: [
        (re.compile(r"(?i)\b(threat|threaten|threatening)\b"), 0.85),
        (re.compile(r"(?i)\b(bully|bullying|intimidat)"), 0.80),
        (re.compile(r"(?i)\b(stalk|stalking|harass)\b"), 0.85),
        (re.compile(r"(?i)(협박|위협|공갈)"), 0.85),
        (re.compile(r"(?i)(괴롭히|왕따|따돌림)"), 0.80),
        (re.compile(r"(?i)(스토킹|미행)"), 0.85),
    ],
    SafetyCategory.HATE_SPEECH: [
        (re.compile(r"(?i)(racial\s*discrimination|race\s*superiority)"), 0.90),
        (re.compile(r"(?i)\b(n[i1]gg[ae3]r|k[i1]ke|sp[i1]c|ch[i1]nk)\b"), 0.95),
        (re.compile(r"(?i)(인종\s*차별|민족\s*비하|혐오\s*발언)"), 0.90),
    ],
    SafetyCategory.SEXUAL: [
        (re.compile(r"(?i)\b(porn|pornograph)"), 0.90),
        (re.compile(r"(?i)\b(nude|naked|nsfw)\b"), 0.85),
        (re.compile(r"(?i)\b(explicit\s*sexual|sexual\s*content)\b"), 0.85),
        (re.compile(r"(?i)(포르노|음란물|야동)"), 0.90),
        (re.compile(r"(?i)(나체|알몸|노출)"), 0.85),
    ],
    SafetyCategory.TOXIC: [
        (re.compile(r"(?i)\b(fuck|fucking|stfu|gtfo)\b"), 0.70),
        (re.compile(r"(?i)\b(shit|bullshit|asshole)\b"), 0.65),
        (re.compile(r"(?i)(씨발|시발|씨빨|개새끼|병신)"), 0.70),
        (re.compile(r"(?i)(지랄|닥쳐|꺼져)"), 0.60),
    ],
}


class SafetyClassifier:
    """Rule-based safety classifier (~1ms fallback backend)."""

    def __init__(self, config: AegisClawConfig | None = None) -> None:
        self._patterns = _SAFETY_PATTERNS
        self._config = config or AegisClawConfig()

    def classify(self, text: str) -> SafetyScore:
        """Classify text safety using pattern matching."""
        max_score = 0.0
        max_category = SafetyCategory.SAFE
        scores: dict[str, float] = {}

        for category, patterns in self._patterns.items():
            category_score = 0.0
            for compiled_re, weight in patterns:
                if compiled_re.search(text):
                    category_score = max(category_score, weight)

            scores[category.value] = category_score
            if category_score > max_score:
                max_score = category_score
                max_category = category

        threshold = self._config.safety_threshold
        is_safe = max_score < threshold

        if not is_safe:
            logger.warning(
                "SafetyClassifier: unsafe — category=%s, score=%.2f (threshold=%.2f)",
                max_category.value,
                max_score,
                threshold,
            )

        return SafetyScore(
            is_safe=is_safe,
            category=SafetyCategory.SAFE if is_safe else max_category,
            confidence=1 - max_score if is_safe else max_score,
            backend="rule_based",
        )
