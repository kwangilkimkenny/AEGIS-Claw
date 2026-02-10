# AEGIS-Claw Development Report

## 1. Project Overview

| Item | Details |
| --- | --- |
| **Project** | AEGIS-Claw |
| **Purpose** | Extract AEGIS core security engine to defend OpenClaw AI agents against critical vulnerabilities |
| **Type** | Standalone Python library |
| **Dependencies** | `pydantic>=2.0`, `pyyaml>=6.0` (no external ML models required) |
| **Python** | 3.10+ |

---

## 2. Target Vulnerability Analysis

**6 critical vulnerabilities** identified from OpenClaw security audit, with AEGIS-based defenses:

| # | Vulnerability | Current OpenClaw Response | AEGIS-Claw Defense | Result |
| --- | --- | --- | --- | --- |
| V1 | Prompt Injection | ❌ Declared "Out of Scope" | Jailbreak Detector (9 types) + Rule Engine | ✅ BLOCK |
| V2 | Indirect Prompt Injection | △ 12 patterns (external-content.ts) | Content Sanitizer (19 patterns) + boundary marking | ✅ BLOCK |
| V3 | Unrestricted Shell Execution | △ skill-scanner static analysis only | Rule Engine (rm -rf, curl\|bash, reverse shell) | ✅ BLOCK |
| V4 | Privilege Escalation (/elevated) | △ Audit log only | Jailbreak Detector + Rule Engine | ✅ ESCALATE |
| V5 | PII/Credential Exposure | ❌ None | Rule Engine (MODIFY + auto-masking) | ✅ REDACT |
| V6 | Harmful Content Generation | ❌ None | Safety Classifier (6 categories, EN/KR) | ✅ BLOCK |

---

## 3. Architecture

AEGIS V2 Smart Routing Pipeline re-implemented — **90% of requests processed within ~25ms**.

```
User Input
    │
    ▼
┌──────────────┐   Critical Match?
│  Rule Engine │──── Yes ──→ Immediate BLOCK (~5ms)
│  (24 rules)  │
└──────┬───────┘
       │ No
       ▼
┌──────────────┐   Jailbreak Detected?
│  Jailbreak   │──── Yes ──→ Immediate BLOCK (~20ms)
│  Detector    │
└──────┬───────┘
       │ No
       ▼
┌──────────────┐   Unsafe?
│   Safety     │──── Yes ──→ BLOCK/MODIFY (~1ms)
│  Classifier  │
└──────┬───────┘
       │ No
       ▼
┌──────────────┐
│  Decision    │──→ GuardResponse
│  Router      │    (APPROVE/BLOCK/MODIFY/ESCALATE)
└──────────────┘
```

---

## 4. Implementation Modules

### 4.1 Core Layer

| File | Description |
| --- | --- |
| `core/types.py` | 5 Enums (Decision, Severity, JailbreakType, SafetyCategory, ContentCategory) |
| `core/schemas.py` | 8 Pydantic models (GuardRequest, GuardResponse, RuleMatch, JailbreakMatch, etc.) |

### 4.2 Engine Layer

| File | AEGIS Source | Key Features |
| --- | --- | --- |
| `engine/rule_engine.py` | `rule_engine.py` | YAML rule loading, 4 condition types, scenario filtering, severity sorting |
| `engine/jailbreak_detector.py` | `jailbreak_detector.py` | 9 jailbreak type pattern detection, Base64/ROT13/Homoglyph decoding, structural anomaly detection |
| `engine/safety_classifier.py` | `safety_classifier.py` | 6-category pattern classification (DANGEROUS, HARASSMENT, HATE_SPEECH, SEXUAL, TOXIC, SAFE) |
| `engine/content_sanitizer.py` | Enhanced `external-content.ts` | 19 injection patterns, boundary marker folding, security wrapping |

### 4.3 Pipeline Layer

| File | AEGIS Source | Key Features |
| --- | --- | --- |
| `pipeline/decision_router.py` | `decision_router.py` | Severity→decision mapping, REASK/MODIFY handling |
| `pipeline/risk_scorer.py` | `risk_scorer.py` | Severity-based confidence calculation, multi-match correction |
| `pipeline/guard.py` | V2 Pipeline | 4-stage sequential evaluation, early termination, per-stage latency tracking |

### 4.4 Integration Layer

| File | Key Features |
| --- | --- |
| `middleware/openclaw_guard.py` | `AegisClaw` unified API (6 methods) |
| `rules/openclaw_rules.yaml` | 24 OpenClaw-specific security rules (7 categories) |

---

## 5. Security Rules (openclaw_rules.yaml)

24 rules organized into 7 categories:

| Category | Rule Count | Examples |
| --- | --- | --- |
| Prompt Injection | 6 | Instruction override, role reassignment, system tag injection (EN/KR) |
| Dangerous Shell Commands | 7 | `rm -rf`, `curl\|bash`, reverse shell, crypto mining |
| Privilege Escalation | 2 | `/elevated on`, `sudo su` |
| Data Exfiltration | 3 | HTTP POST transmission, environment variable collection, file read+send |
| PII/Credentials | 2 | API key exposure, plaintext password (auto-masking) |
| Harmful Content | 2 | Malware creation, weapon manufacturing requests |
| Prompt Extraction | 2 | System prompt extraction, training data extraction |

---

## 6. Test Results

```
187 passed in ~3.7s
```

| Test File | Count | Coverage |
| --- | --- | --- |
| `test_types.py` | 7 | All enum values, string conversion |
| `test_rule_engine.py` | 13 | YAML loading, 4 conditions, scenario filter, severity sorting, bundled rules |
| `test_jailbreak_detector.py` | 18 | 9 patterns (EN/KR), Base64/ROT13, anomaly detection, safe content |
| `test_safety_classifier.py` | 11 | 6 categories (EN/KR), confidence, backend identification |
| `test_decision_router.py` | 6 | All decision paths (APPROVE/BLOCK/MODIFY/ESCALATE/REASK) |
| `test_guard_pipeline.py` | 29 | Full pipeline + AegisClaw middleware (6 methods) |
| `test_v2_*.py` | 70 | v0.2 features: config, rate limiter, async, content sanitizer, logging |
| `test_server.py` | 33 | HTTP microservice integration (7 endpoints) |

---

## 7. Design Decisions

| Decision | Rationale |
| --- | --- |
| Exclude ML models (ShieldGemma, ToxicBERT) | Zero-dependency installation, usable anywhere immediately |
| Rule-based pattern approach | ~25ms low latency, no GPU required, extensible by adding rules |
| YAML rule externalization | Update security policies without code changes |
| Multi-language patterns (EN/KR) | Support Korean usage scenarios in OpenClaw |
| Pydantic schemas | Type safety, serialization, API compatibility |
