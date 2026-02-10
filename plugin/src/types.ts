/**
 * AEGIS-Claw Type Definitions
 *
 * Mirrors the Python aegis_claw.core.types enums and schemas.
 */

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export type AegisDecision =
  | "approve"
  | "block"
  | "modify"
  | "escalate"
  | "reask";

export type AegisSeverity = "critical" | "high" | "medium" | "low";

// ---------------------------------------------------------------------------
// Response structures
// ---------------------------------------------------------------------------

export interface AegisEvidence {
  rule_id: string;
  reason: string;
  matched_text: string | null;
}

export interface AegisRisk {
  label: string;
  severity: AegisSeverity;
  description: string | null;
}

export interface AegisPipelineStage {
  name: string;
  latency_ms: number;
  passed: boolean;
  detail: string | null;
}

export interface AegisResponse {
  request_id: string;
  decision: AegisDecision;
  confidence: number;
  risk: AegisRisk | null;
  evidence: AegisEvidence[];
  rewrite: string | null;
  message: string | null;
  pipeline_stages: AegisPipelineStage[];
  total_latency_ms: number;
  /** Present only on /guard/external responses */
  injection_patterns?: string[];
}

export interface AegisSanitizeResponse {
  sanitized: string;
}

export interface AegisPatternResponse {
  patterns: string[];
}

export interface AegisHealthResponse {
  status: string;
  version: string;
}
