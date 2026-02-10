# AEGIS-Claw 개발 결과 보고서

## 1. 프로젝트 개요

| 항목           | 내용                                                                      |
| -------------- | ------------------------------------------------------------------------- |
| **프로젝트명** | AEGIS-Claw                                                          |
| **목적**       | AEGIS 핵심 보안 엔진을 추출하여 OpenClaw AI 에이전트의 치명적 취약점 방어 |
| **유형**       | 독립형 Python 라이브러리                                                  |
| **의존성**     | `pydantic>=2.0`, `pyyaml>=6.0` (외부 ML 모델 불필요)                      |
| **Python**     | 3.10+                                                                     |

---

## 2. 대상 취약점 분석

OpenClaw 보안 감사 결과 식별된 **6대 치명적 취약점**과 AEGIS 기반 방어:

| #   | 취약점                | 기존 OpenClaw 대응                | AEGIS-Claw 방어                           | 결과        |
| --- | --------------------- | --------------------------------- | ----------------------------------------------- | ----------- |
| V1  | 프롬프트 인젝션       | ❌ "Out of Scope" 선언            | Jailbreak Detector (9유형) + Rule Engine        | ✅ BLOCK    |
| V2  | 간접 프롬프트 인젝션  | △ 12개 패턴 (external-content.ts) | Content Sanitizer (19패턴) + 경계 마킹          | ✅ BLOCK    |
| V3  | 비제한 셸 명령 실행   | △ skill-scanner 정적 분석만       | Rule Engine (rm -rf, curl\|bash, reverse shell) | ✅ BLOCK    |
| V4  | 권한 상승 (/elevated) | △ 감사 로그만                     | Jailbreak Detector + Rule Engine                | ✅ ESCALATE |
| V5  | PII/자격증명 노출     | ❌ 없음                           | Rule Engine (MODIFY + 자동 마스킹)              | ✅ REDACT   |
| V6  | 유해 콘텐츠 생성      | ❌ 없음                           | Safety Classifier (6카테고리, EN/KR)            | ✅ BLOCK    |

---

## 3. 아키텍처

AEGIS V2 Smart Routing Pipeline을 재구현하여 **90%의 요청이 ~25ms 내에 처리**됩니다.

```
사용자 입력
    │
    ▼
┌──────────────┐   Critical Match?
│  Rule Engine │──── Yes ──→ 즉시 BLOCK (~5ms)
│  (24 규칙)   │
└──────┬───────┘
       │ No
       ▼
┌──────────────┐   Jailbreak Detected?
│  Jailbreak   │──── Yes ──→ 즉시 BLOCK (~20ms)
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

## 4. 구현 모듈

### 4.1 Core Layer

| 파일              | 설명                                                                          |
| ----------------- | ----------------------------------------------------------------------------- |
| `core/types.py`   | 5개 Enum (Decision, Severity, JailbreakType, SafetyCategory, ContentCategory) |
| `core/schemas.py` | 8개 Pydantic 모델 (GuardRequest, GuardResponse, RuleMatch, JailbreakMatch 등) |

### 4.2 Engine Layer

| 파일                           | AEGIS 원본                 | 핵심 기능                                                                     |
| ------------------------------ | -------------------------- | ----------------------------------------------------------------------------- |
| `engine/rule_engine.py`        | `rule_engine.py`           | YAML 규칙 로딩, 4가지 조건 평가, 시나리오 필터링, 심각도 정렬                 |
| `engine/jailbreak_detector.py` | `jailbreak_detector.py`    | 9가지 탈옥 유형 패턴 탐지, Base64/ROT13/Homoglyph 디코딩, 구조적 이상 탐지    |
| `engine/safety_classifier.py`  | `safety_classifier.py`     | 6카테고리 패턴 분류 (DANGEROUS, HARASSMENT, HATE_SPEECH, SEXUAL, TOXIC, SAFE) |
| `engine/content_sanitizer.py`  | `external-content.ts` 강화 | 19개 인젝션 패턴, 경계 마커 폴딩, 보안 래핑                                   |

### 4.3 Pipeline Layer

| 파일                          | AEGIS 원본           | 핵심 기능                                        |
| ----------------------------- | -------------------- | ------------------------------------------------ |
| `pipeline/decision_router.py` | `decision_router.py` | 심각도→결정 매핑, REASK/MODIFY 처리              |
| `pipeline/risk_scorer.py`     | `risk_scorer.py`     | 심각도 기반 신뢰도 계산, 다중 매치 보정          |
| `pipeline/guard.py`           | V2 Pipeline          | 4단계 순차 평가, 조기 종료, 단계별 레이턴시 추적 |

### 4.4 Integration Layer

| 파일                           | 핵심 기능                                   |
| ------------------------------ | ------------------------------------------- |
| `middleware/openclaw_guard.py` | `AegisClaw` 통합 API (6개 메서드)       |
| `rules/openclaw_rules.yaml`    | 24개 OpenClaw 특화 보안 규칙 (7개 카테고리) |

---

## 5. 보안 규칙 (openclaw_rules.yaml)

24개 규칙을 7개 카테고리로 분류:

| 카테고리        | 규칙 수 | 예시                                                 |
| --------------- | ------- | ---------------------------------------------------- |
| 프롬프트 인젝션 | 6       | 지시 무시, 역할 재배정, 시스템 태그 주입 (EN/KR)     |
| 위험 셸 명령    | 7       | `rm -rf`, `curl\|bash`, reverse shell, 암호화폐 채굴 |
| 권한 상승       | 2       | `/elevated on`, `sudo su`                            |
| 데이터 유출     | 3       | HTTP POST 전송, 환경변수 수집, 파일 읽기+전송        |
| PII/자격증명    | 2       | API 키 노출, 평문 패스워드 (자동 마스킹)             |
| 유해 콘텐츠     | 2       | 악성코드 생성, 무기 제조 요청                        |
| 프롬프트 추출   | 2       | 시스템 프롬프트 추출, 학습 데이터 추출               |

---

## 6. 테스트 결과

```
84 passed in 0.50s
```

| 테스트 파일                  | 테스트 수 | 검증 범위                                                    |
| ---------------------------- | --------- | ------------------------------------------------------------ |
| `test_types.py`              | 7         | 모든 Enum 값, 문자열 변환                                    |
| `test_rule_engine.py`        | 13        | YAML 로딩, 4가지 조건, 시나리오 필터, 심각도 정렬, 번들 규칙 |
| `test_jailbreak_detector.py` | 18        | 9가지 패턴 (EN/KR), Base64/ROT13, 이상탐지, 안전 컨텐츠      |
| `test_safety_classifier.py`  | 11        | 6카테고리 (EN/KR), 신뢰도, 백엔드 식별                       |
| `test_decision_router.py`    | 6         | 모든 결정 경로 (APPROVE/BLOCK/MODIFY/ESCALATE/REASK)         |
| `test_guard_pipeline.py`     | 29        | 전체 파이프라인 + AegisClaw 미들웨어 (6개 메서드)        |

---

## 7. 설계 결정 사항

| 결정                                  | 이유                                           |
| ------------------------------------- | ---------------------------------------------- |
| ML 모델 제외 (ShieldGemma, ToxicBERT) | 무의존성 설치, 어디서든 즉시 사용 가능         |
| Rule-Based 패턴 방식                  | ~25ms 저지연, GPU 불필요, 규칙 추가만으로 확장 |
| YAML 규칙 외부화                      | 코드 수정 없이 보안 정책 업데이트 가능         |
| 다국어 패턴 (EN/KR)                   | OpenClaw 한국어 사용 시나리오 대응             |
| Pydantic 스키마                       | 타입 안전성, 직렬화, API 호환성                |
