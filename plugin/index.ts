/**
 * AEGIS-Claw Plugin for OpenClaw
 *
 * Security guard plugin that protects OpenClaw AI agents from:
 *   - Prompt injection (multi-language)
 *   - Jailbreak attacks (9 types)
 *   - Encoding attacks (Base64, ROT13, Homoglyph)
 *   - Dangerous shell commands
 *   - PII / credential leaks
 *   - Indirect injection via external content
 *   - Safety violations (harmful, harassment, hate speech)
 *
 * Registers 4 hooks into the OpenClaw pipeline:
 *   ① before_agent_start  (priority 900) — Input guard
 *   ② before_tool_call    (priority 800) — Tool/command guard
 *   ③ tool_result_persist  (synchronous)  — Secret redaction
 *   ④ message_sending     (priority 700) — Output guard
 *
 * Architecture:
 *   OpenClaw (TypeScript) ──HTTP──► AEGIS Python Service (port 5050)
 *                                       │
 *                                   AegisClaw Pipeline
 *                                   ├── Rule Engine
 *                                   ├── Jailbreak Detector
 *                                   ├── Safety Classifier
 *                                   ├── Decision Router
 *                                   └── Content Sanitizer
 *
 * Setup:
 *   1. Start Python service:  python -m server.aegis_server --port 5050
 *   2. Add to OpenClaw config.json5:
 *      plugins.entries.aegis-claw = { enabled: true, source: "...", config: {...} }
 *   3. Restart OpenClaw gateway
 *
 * @module @openclaw/plugin-aegis-claw
 * @version 0.2.0
 */

import { AegisBridge } from "./src/aegis-bridge.js";
import { resolveConfig } from "./src/config.js";
import { createInputGuard } from "./src/hooks/input-guard.js";
import { createToolGuard } from "./src/hooks/tool-guard.js";
import { createResultGuard } from "./src/hooks/result-guard.js";
import { createOutputGuard } from "./src/hooks/output-guard.js";

/**
 * OpenClaw Plugin API type — provided by OpenClaw at registration time.
 *
 * This is a minimal type declaration for the plugin API surface we use.
 * In an actual OpenClaw environment, the full type is imported from
 * "openclaw/plugin-sdk".
 */
interface OpenClawPluginApi {
  id: string;
  name: string;
  config: unknown;
  pluginConfig?: Record<string, unknown>;
  logger: {
    debug: (msg: string) => void;
    info: (msg: string) => void;
    warn: (msg: string) => void;
    error: (msg: string) => void;
  };
  on: (
    hookName: string,
    handler: (...args: any[]) => any,
    opts?: { priority?: number },
  ) => void;
  registerHook: (
    events: string[],
    handler: (...args: any[]) => any,
    opts?: { name?: string },
  ) => void;
  registerHttpRoute: (params: {
    path: string;
    handler: (req: any, res: any) => Promise<void> | void;
  }) => void;
}

/**
 * Plugin entry point — called by OpenClaw's plugin loader.
 */
export default function register(api: OpenClawPluginApi): void {
  const cfg = resolveConfig(api.pluginConfig);
  const log = api.logger;

  // --- Disabled mode ---
  if (cfg.mode === "disabled") {
    log.info("[AEGIS] Plugin disabled by configuration");
    return;
  }

  // --- Create bridge to Python service ---
  const bridge = new AegisBridge({
    serviceUrl: cfg.pythonServiceUrl,
    timeoutMs: cfg.timeoutMs,
    retries: 1,
  });

  log.info(
    `[AEGIS] Initializing v0.2.0 — mode=${cfg.mode}, ` +
      `service=${cfg.pythonServiceUrl}`,
  );

  // --- Hook ①: Input Guard (before_agent_start) ---
  api.on("before_agent_start", createInputGuard(bridge, cfg, log), {
    priority: 900,
  });

  // --- Hook ②: Tool Guard (before_tool_call) ---
  api.on("before_tool_call", createToolGuard(bridge, cfg, log), {
    priority: 800,
  });

  // --- Hook ③: Result Guard (tool_result_persist) ---
  // NOTE: This hook MUST be synchronous — no async, no await.
  api.registerHook(
    ["tool_result_persist"],
    createResultGuard(cfg, log),
    { name: "aegis-result-guard" },
  );

  // --- Hook ④: Output Guard (message_sending) ---
  api.on("message_sending", createOutputGuard(bridge, cfg, log), {
    priority: 700,
  });

  // --- Session lifecycle logging ---
  api.on(
    "session_start",
    async (_event: unknown, ctx: { sessionKey?: string }) => {
      log.debug(`[AEGIS] Session started: ${ctx.sessionKey ?? "unknown"}`);
    },
  );

  api.on(
    "agent_end",
    async (_event: unknown, ctx: { sessionKey?: string }) => {
      log.debug(`[AEGIS] Agent completed: ${ctx.sessionKey ?? "unknown"}`);
    },
  );

  // --- HTTP status endpoint (available via Gateway) ---
  api.registerHttpRoute({
    path: "/api/aegis/status",
    handler: async (_req: any, res: any) => {
      const healthy = await bridge.isHealthy();
      res.json({
        plugin: "aegis-claw",
        version: "0.2.0",
        mode: cfg.mode,
        serviceUrl: cfg.pythonServiceUrl,
        serviceHealthy: healthy,
        config: {
          blockOnCritical: cfg.blockOnCritical,
          escalateOnHigh: cfg.escalateOnHigh,
          redactSecrets: cfg.redactSecrets,
          rateLimitEnabled: cfg.rateLimitEnabled,
        },
      });
    },
  });

  log.info("[AEGIS] Plugin registered — 4 hooks active");
}
