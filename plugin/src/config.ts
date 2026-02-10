/**
 * AEGIS-Claw Plugin Configuration
 */

export interface AegisPluginConfig {
  /** Operating mode: enforcing blocks threats, auditing only logs, disabled turns off */
  mode: "enforcing" | "auditing" | "disabled";

  /** URL of the AEGIS-Claw Python microservice */
  pythonServiceUrl: string;

  /** Block requests that have critical severity */
  blockOnCritical: boolean;

  /** Escalate requests that have high severity */
  escalateOnHigh: boolean;

  /** Redact secrets (API keys, passwords, tokens) in tool results */
  redactSecrets: boolean;

  /** Enable per-session rate limiting */
  rateLimitEnabled: boolean;

  /** Max requests per 60-second window */
  rateLimitMaxRequests: number;

  /** Timeout for AEGIS service calls in ms */
  timeoutMs: number;

  /** Log level */
  logLevel: "debug" | "info" | "warn" | "error";
}

export const DEFAULT_CONFIG: AegisPluginConfig = {
  mode: "enforcing",
  pythonServiceUrl: "http://127.0.0.1:5050",
  blockOnCritical: true,
  escalateOnHigh: true,
  redactSecrets: true,
  rateLimitEnabled: true,
  rateLimitMaxRequests: 60,
  timeoutMs: 5000,
  logLevel: "info",
};

export function resolveConfig(
  pluginConfig: Record<string, unknown> | undefined,
): AegisPluginConfig {
  return { ...DEFAULT_CONFIG, ...(pluginConfig as Partial<AegisPluginConfig>) };
}
