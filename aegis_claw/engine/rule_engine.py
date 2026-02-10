"""
Rule Engine — Pattern-based content evaluation.

Loads YAML rules and evaluates content against them using
contains_any, contains_all, matches_pattern, and not_contains conditions.
Ported from AEGIS Rule Engine (src/aegis/services/rule_engine.py).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aegis_claw.core.types import Decision, Severity
from aegis_claw.core.schemas import RuleMatch

logger = logging.getLogger("aegis_claw.engine.rule_engine")


# ---------------------------------------------------------------------------
# Rule data class
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    id: str
    description: str = ""
    scenario: str | None = None
    # conditions
    contains_any: list[str] = field(default_factory=list)
    contains_all: list[str] = field(default_factory=list)
    matches_pattern: str | None = None
    not_contains: list[str] = field(default_factory=list)
    # result
    decision: Decision = Decision.BLOCK
    severity: Severity = Severity.HIGH
    risk_label: str = ""
    rewrite: str | None = None
    # pre-compiled regex (set after init)
    _compiled_pattern: re.Pattern[str] | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Pre-compile the regex pattern if present."""
        if self.matches_pattern:
            try:
                self._compiled_pattern = re.compile(
                    self.matches_pattern, re.IGNORECASE
                )
            except re.error as exc:
                logger.error(
                    "Invalid regex in rule '%s': %s — rule will be skipped",
                    self.id,
                    exc,
                )
                self._compiled_pattern = None
                self.matches_pattern = None  # disable this condition


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

# Severity ordering for sorting (lower number = more severe)
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class RuleEngine:
    """Evaluates content against a set of YAML-defined rules (~5ms)."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules: list[Rule] = rules or []
        logger.debug("RuleEngine initialized with %d rules", len(self._rules))

    # -- Loading ---------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str | Path) -> "RuleEngine":
        """Load rules from a YAML file."""
        path = Path(path)
        logger.info("Loading rules from %s", path)
        with path.open("r", encoding="utf-8") as fh:
            data: dict[str, Any] = yaml.safe_load(fh) or {}

        rules: list[Rule] = []
        skipped = 0
        for raw in data.get("rules", []):
            when = raw.get("when", {})
            then = raw.get("then", {})
            try:
                rule = Rule(
                    id=raw["id"],
                    description=raw.get("description", ""),
                    scenario=when.get("scenario"),
                    contains_any=when.get("contains_any", {}).get("phrases", []),
                    contains_all=when.get("contains_all", {}).get("phrases", []),
                    matches_pattern=when.get("matches_pattern"),
                    not_contains=when.get("not_contains", {}).get("phrases", []),
                    decision=Decision(then.get("decision", "block").lower()),
                    severity=Severity(then.get("severity", "high").lower()),
                    risk_label=then.get("risk_label", ""),
                    rewrite=then.get("rewrite"),
                )
                rules.append(rule)
            except Exception as exc:
                skipped += 1
                logger.error(
                    "Failed to load rule '%s': %s — skipping",
                    raw.get("id", "unknown"),
                    exc,
                )

        if skipped:
            logger.warning("Skipped %d invalid rules from %s", skipped, path)

        logger.info("Loaded %d rules from %s", len(rules), path)
        return cls(rules)

    @classmethod
    def default(cls) -> "RuleEngine":
        """Load the bundled OpenClaw security rules."""
        rules_path = Path(__file__).resolve().parent.parent / "rules" / "openclaw_rules.yaml"
        if rules_path.exists():
            return cls.from_yaml(rules_path)
        logger.warning("Default rules file not found at %s", rules_path)
        return cls()

    # -- Evaluation ------------------------------------------------------------

    def _evaluate_rule(self, rule: Rule, content: str) -> RuleMatch | None:
        """Evaluate a single rule — all conditions are AND-combined."""
        content_lower = content.lower()
        matched_text: str | None = None

        # 1. contains_any: at least one phrase must match (OR)
        if rule.contains_any:
            found = False
            for phrase in rule.contains_any:
                if phrase.lower() in content_lower:
                    found = True
                    matched_text = phrase
                    break
            if not found:
                return None

        # 2. contains_all: every phrase must match (AND)
        if rule.contains_all:
            for phrase in rule.contains_all:
                if phrase.lower() not in content_lower:
                    return None

        # 3. matches_pattern: pre-compiled regex must match
        if rule._compiled_pattern:
            match = rule._compiled_pattern.search(content)
            if not match:
                return None
            matched_text = match.group(0)

        # 4. not_contains: none of these may match (NAND / exception)
        if rule.not_contains:
            for phrase in rule.not_contains:
                if phrase.lower() in content_lower:
                    return None

        logger.debug(
            "Rule '%s' matched (severity=%s, matched='%s')",
            rule.id,
            rule.severity.value,
            matched_text,
        )

        return RuleMatch(
            rule_id=rule.id,
            decision=rule.decision,
            severity=rule.severity,
            risk_label=rule.risk_label,
            description=rule.description,
            matched_text=matched_text,
            rewrite=rule.rewrite,
        )

    def evaluate(self, content: str, scenario: str | None = None) -> list[RuleMatch]:
        """Evaluate all rules and return matches sorted by severity."""
        matches: list[RuleMatch] = []

        for rule in self._rules:
            # Skip rules bound to a different scenario
            if rule.scenario and rule.scenario != scenario:
                continue
            match = self._evaluate_rule(rule, content)
            if match:
                matches.append(match)

        # Sort by severity (CRITICAL first)
        matches.sort(key=lambda m: _SEVERITY_ORDER.get(m.severity, 99))

        if matches:
            logger.warning(
                "RuleEngine: %d match(es) — top: %s (%s)",
                len(matches),
                matches[0].rule_id,
                matches[0].severity.value,
            )

        return matches
