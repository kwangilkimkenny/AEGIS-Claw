/**
 * AEGIS-Claw TypeScript Bridge
 *
 * HTTP client that communicates with the Python AEGIS-Claw microservice.
 * All hook handlers call through this bridge to perform security checks.
 */

import type {
  AegisResponse,
  AegisHealthResponse,
} from "./types.js";

export interface AegisBridgeConfig {
  /** Base URL of the AEGIS-Claw Python service (e.g. http://127.0.0.1:5050) */
  serviceUrl: string;
  /** Request timeout in milliseconds (default: 5000) */
  timeoutMs?: number;
  /** Number of retry attempts on failure (default: 1) */
  retries?: number;
}

export class AegisBridge {
  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly retries: number;

  constructor(config: AegisBridgeConfig) {
    this.url = config.serviceUrl.replace(/\/$/, "");
    this.timeoutMs = config.timeoutMs ?? 5000;
    this.retries = config.retries ?? 1;
  }

  // -------------------------------------------------------------------
  // Guard methods — mirror the Python AegisClaw middleware
  // -------------------------------------------------------------------

  /** Check inbound user message for injection, jailbreak, safety. */
  async guardInput(
    text: string,
    opts?: { scenario?: string; sessionId?: string },
  ): Promise<AegisResponse> {
    return this.post<AegisResponse>("/guard/input", {
      text,
      scenario: opts?.scenario,
      session_id: opts?.sessionId,
    });
  }

  /** Check a shell command for dangerous operations. */
  async guardCommand(
    command: string,
    opts?: { sessionId?: string },
  ): Promise<AegisResponse> {
    return this.post<AegisResponse>("/guard/command", {
      command,
      session_id: opts?.sessionId,
    });
  }

  /** Check an AI-generated response for safety violations, PII leaks. */
  async guardOutput(
    text: string,
    opts?: { scenario?: string; sessionId?: string },
  ): Promise<AegisResponse> {
    return this.post<AegisResponse>("/guard/output", {
      text,
      scenario: opts?.scenario,
      session_id: opts?.sessionId,
    });
  }

  /** Check external content (email, webhook, web) for indirect injection. */
  async guardExternal(
    content: string,
    opts?: {
      source?: string;
      sender?: string;
      subject?: string;
      sessionId?: string;
    },
  ): Promise<AegisResponse> {
    return this.post<AegisResponse>("/guard/external", {
      content,
      source: opts?.source ?? "unknown",
      sender: opts?.sender,
      subject: opts?.subject,
      session_id: opts?.sessionId,
    });
  }

  /** Wrap external content with security boundaries (Content Sanitizer). */
  async sanitizeExternal(
    content: string,
    opts?: { source?: string; sender?: string; subject?: string },
  ): Promise<string> {
    const res = await this.post<{ sanitized: string }>("/sanitize/external", {
      content,
      source: opts?.source ?? "unknown",
      sender: opts?.sender,
      subject: opts?.subject,
    });
    return res.sanitized;
  }

  /** Quick scan for injection patterns without full pipeline. */
  async detectPatterns(content: string): Promise<string[]> {
    const res = await this.post<{ patterns: string[] }>("/detect/patterns", {
      content,
    });
    return res.patterns;
  }

  /** Service health check. */
  async healthCheck(): Promise<AegisHealthResponse | null> {
    try {
      const res = await fetch(`${this.url}/health`, {
        method: "GET",
        signal: AbortSignal.timeout(2000),
      });
      if (!res.ok) return null;
      return (await res.json()) as AegisHealthResponse;
    } catch {
      return null;
    }
  }

  /** Returns true if the service is reachable. */
  async isHealthy(): Promise<boolean> {
    const health = await this.healthCheck();
    return health?.status === "ok";
  }

  // -------------------------------------------------------------------
  // Internal HTTP
  // -------------------------------------------------------------------

  private async post<T>(path: string, body: unknown): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const res = await fetch(`${this.url}${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(this.timeoutMs),
        });

        if (!res.ok) {
          const errBody = await res.text().catch(() => "");
          throw new Error(
            `AEGIS service ${path} returned ${res.status}: ${errBody}`,
          );
        }

        return (await res.json()) as T;
      } catch (err) {
        lastError = err as Error;
        if (attempt < this.retries) {
          // brief pause before retry
          await new Promise((r) => setTimeout(r, 100 * (attempt + 1)));
        }
      }
    }

    throw new Error(
      `AEGIS service unavailable (${this.retries + 1} attempts): ${lastError?.message}`,
    );
  }
}
