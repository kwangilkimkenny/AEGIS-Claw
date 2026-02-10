"""
Guard Pipeline — V2 Smart Routing.

Orchestrates the full security pipeline:
  1. Rule Engine (~5ms)
  2. Jailbreak Detector (~20ms)
  3. Safety Classifier (~1ms for rule-based)
  4. Decision Router + Risk Scorer (~1ms)

90% of requests resolve in ~25ms without LLM.

Adapted from AEGIS V2 Judgment Pipeline (judgment_service_v2.py).
"""

from __future__ import annotations

import logging
import time

from aegis_claw.core.config import AegisClawConfig
from aegis_claw.core.types import Decision, Severity, ContentCategory
from aegis_claw.core.schemas import (
    CATEGORY_TO_DECISION,
    CATEGORY_TO_SEVERITY,
    EvidenceItem,
    GuardRequest,
    GuardResponse,
    PipelineStage,
    RuleMatch,
)
from aegis_claw.engine.rule_engine import RuleEngine
from aegis_claw.engine.jailbreak_detector import JailbreakDetector
from aegis_claw.engine.safety_classifier import SafetyClassifier
from aegis_claw.pipeline.decision_router import DecisionRouter
from aegis_claw.pipeline.risk_scorer import RiskScorer

logger = logging.getLogger("aegis_claw.pipeline.guard")


class GuardPipeline:
    """V2 Smart Routing Guard Pipeline."""

    def __init__(
        self,
        config: AegisClawConfig | None = None,
        rule_engine: RuleEngine | None = None,
        jailbreak_detector: JailbreakDetector | None = None,
        safety_classifier: SafetyClassifier | None = None,
        decision_router: DecisionRouter | None = None,
        risk_scorer: RiskScorer | None = None,
    ) -> None:
        self._config = config or AegisClawConfig()
        self._rule_engine = rule_engine or RuleEngine.default()
        self._jailbreak_detector = jailbreak_detector or JailbreakDetector(self._config)
        self._safety_classifier = safety_classifier or SafetyClassifier(self._config)
        self._decision_router = decision_router or DecisionRouter(self._config)
        self._risk_scorer = risk_scorer or RiskScorer(self._config)
        logger.info("GuardPipeline initialized (max_input=%d)", self._config.max_input_length)

    def evaluate(self, request: GuardRequest) -> GuardResponse:
        """Run the full guard pipeline on a request."""
        pipeline_start = time.perf_counter()
        stages: list[PipelineStage] = []
        all_matches: list[RuleMatch] = []
        evidence: list[EvidenceItem] = []

        text = request.text
        scenario = request.scenario

        # -- Input validation --------------------------------------------------
        if not text or not text.strip():
            logger.debug("Empty input — auto-approve")
            return GuardResponse(decision=Decision.APPROVE, confidence=0.95)

        max_len = self._config.max_input_length
        if len(text) > max_len:
            logger.warning(
                "Input too long (%d chars, max %d) — blocking",
                len(text),
                max_len,
            )
            return GuardResponse(
                decision=Decision.BLOCK,
                confidence=0.99,
                message=f"Input exceeds maximum length ({len(text):,} > {max_len:,} chars)",
                evidence=[EvidenceItem(
                    rule_id="system.input_too_long",
                    reason=f"Input length {len(text):,} exceeds limit {max_len:,}",
                )],
                total_latency_ms=round((time.perf_counter() - pipeline_start) * 1000, 2),
            )

        # ================================================================
        # Stage 1: Rule Engine (~5ms)
        # ================================================================
        t0 = time.perf_counter()
        rule_matches = self._rule_engine.evaluate(text, scenario)
        stage_ms = (time.perf_counter() - t0) * 1000

        stages.append(PipelineStage(
            name="rule_engine",
            latency_ms=round(stage_ms, 2),
            passed=len(rule_matches) == 0,
            detail=f"{len(rule_matches)} rule(s) matched",
        ))
        all_matches.extend(rule_matches)

        for m in rule_matches:
            evidence.append(EvidenceItem(
                rule_id=m.rule_id,
                reason=m.description or m.risk_label,
                matched_text=m.matched_text,
            ))

        # Early exit: critical rule match → immediate BLOCK
        if rule_matches and rule_matches[0].severity == Severity.CRITICAL:
            logger.info("Early exit: critical rule match (%.2fms)", stage_ms)
            return self._build_response(
                all_matches, evidence, stages, pipeline_start,
            )

        # ================================================================
        # Stage 2: Jailbreak Detector (~20ms)
        # ================================================================
        t0 = time.perf_counter()
        jailbreak_matches = self._jailbreak_detector.detect(text)
        stage_ms = (time.perf_counter() - t0) * 1000

        stages.append(PipelineStage(
            name="jailbreak_detector",
            latency_ms=round(stage_ms, 2),
            passed=len(jailbreak_matches) == 0,
            detail=f"{len(jailbreak_matches)} jailbreak(s) detected",
        ))

        for jb in jailbreak_matches:
            rm = RuleMatch(
                rule_id=f"jailbreak.{jb.type.value}",
                decision=Decision.BLOCK,
                severity=Severity.CRITICAL,
                risk_label=f"jailbreak_{jb.type.value}",
                description=f"Jailbreak detected: {jb.pattern}",
                matched_text=jb.matched_text,
            )
            all_matches.append(rm)
            evidence.append(EvidenceItem(
                rule_id=rm.rule_id,
                reason=rm.description or "",
                matched_text=rm.matched_text,
            ))

        # Early exit: jailbreak detected → immediate BLOCK
        if jailbreak_matches:
            logger.info("Early exit: jailbreak detected (%.2fms)", stage_ms)
            return self._build_response(
                all_matches, evidence, stages, pipeline_start,
            )

        # ================================================================
        # Stage 3: Safety Classifier (~1ms rule-based)
        # ================================================================
        t0 = time.perf_counter()
        safety_result = self._safety_classifier.classify(text)
        stage_ms = (time.perf_counter() - t0) * 1000

        stages.append(PipelineStage(
            name="safety_classifier",
            latency_ms=round(stage_ms, 2),
            passed=safety_result.is_safe,
            detail=f"category={safety_result.category.value}, confidence={safety_result.confidence:.2f}",
        ))

        if not safety_result.is_safe:
            # Map safety category to content category
            safety_content_cat = self._map_safety_to_content_category(safety_result.category.value)
            decision = CATEGORY_TO_DECISION.get(safety_content_cat, Decision.ESCALATE)
            severity = CATEGORY_TO_SEVERITY.get(safety_content_cat, Severity.MEDIUM)

            rm = RuleMatch(
                rule_id=f"safety.{safety_result.category.value}",
                decision=decision,
                severity=severity,
                risk_label=f"safety_{safety_result.category.value}",
                description=f"Safety violation: {safety_result.category.value}",
            )
            all_matches.append(rm)
            evidence.append(EvidenceItem(
                rule_id=rm.rule_id,
                reason=rm.description or "",
                matched_text=None,
            ))

        # ================================================================
        # Stage 4-5: Decision Router + Risk Scorer (~1ms)
        # ================================================================
        response = self._build_response(
            all_matches, evidence, stages, pipeline_start,
        )

        logger.debug(
            "Pipeline complete: decision=%s, confidence=%.2f, latency=%.2fms",
            response.decision.value,
            response.confidence,
            response.total_latency_ms,
        )

        return response

    def _build_response(
        self,
        matches: list[RuleMatch],
        evidence: list[EvidenceItem],
        stages: list[PipelineStage],
        pipeline_start: float,
    ) -> GuardResponse:
        """Build final response from accumulated matches."""

        # Sort matches by severity
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        matches.sort(key=lambda m: severity_order.get(m.severity, 99))

        # Decision routing
        routing = self._decision_router.route(matches)

        # Risk scoring
        risk_score = self._risk_scorer.calculate(matches)

        total_ms = (time.perf_counter() - pipeline_start) * 1000

        return GuardResponse(
            decision=routing.decision,
            confidence=risk_score.confidence if matches else 0.95,
            risk=risk_score.to_risk_info(),
            evidence=evidence,
            rewrite=routing.rewrite,
            message=routing.message,
            pipeline_stages=stages,
            total_latency_ms=round(total_ms, 2),
        )

    @staticmethod
    def _map_safety_to_content_category(safety_cat: str) -> ContentCategory:
        """Map SafetyCategory values to ContentCategory."""
        mapping = {
            "safe": ContentCategory.SAFE,
            "dangerous": ContentCategory.HARMFUL,
            "harassment": ContentCategory.HARMFUL,
            "hate_speech": ContentCategory.HARMFUL,
            "sexual": ContentCategory.SENSITIVE,
            "toxic": ContentCategory.SENSITIVE,
        }
        return mapping.get(safety_cat, ContentCategory.UNKNOWN)
