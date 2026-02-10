/**
 * Hook ④: Output Guard — message_sending
 *
 * Intercepts AI-generated responses BEFORE they are sent to the user.
 * Checks for: PII leaks, credential exposure, safety violations.
 *
 * On BLOCK:  Replaces the message with a security warning.
 * On MODIFY: Replaces with the rewritten (sanitized) text.
 * On APPROVE: No modification.
 *
 * OpenClaw Hook: message_sending (sequential, async)
 * Priority: 700
 */

import type { AegisBridge } from "../aegis-bridge.js";
import type { AegisPluginConfig } from "../config.js";
import { shouldBlock, formatAegisLog } from "../utils.js";

interface MessageSendingEvent {
  text?: string;
  [key: string]: unknown;
}

interface MessageSendingContext {
  agentId?: string;
  sessionKey?: string;
  channel?: string;
  target?: string;
}

interface MessageSendingResult {
  text?: string;
}

/** Minimum text length to warrant an output check. */
const MIN_CHECK_LENGTH = 10;

export function createOutputGuard(bridge: AegisBridge, cfg: AegisPluginConfig, log: any) {
  const isEnforcing = cfg.mode === "enforcing";

  return async (
    event: MessageSendingEvent,
    ctx: MessageSendingContext,
  ): Promise<MessageSendingResult> => {
    const text = event.text;

    // Skip empty or very short messages
    if (!text || text.length < MIN_CHECK_LENGTH) return {};

    const sessionKey = ctx.sessionKey ?? "unknown";

    try {
      const result = await bridge.guardOutput(text, {
        sessionId: sessionKey,
      });

      // Only log non-approve decisions to reduce noise
      if (result.decision !== "approve") {
        log.info(formatAegisLog("OUTPUT", text.slice(0, 100), result));
      }

      // BLOCK: replace with security warning
      if (shouldBlock(result, cfg) && isEnforcing) {
        const riskDetail = result.risk
          ? ` (${result.risk.severity}: ${result.risk.label})`
          : "";
        return {
          text:
            `⚠️ This response was blocked by security policy.${riskDetail}\n` +
            `Reason: ${result.message ?? "Security violation detected."}`,
        };
      }

      // MODIFY: use the rewritten content
      if (result.decision === "modify" && result.rewrite) {
        log.info(
          `[AEGIS] OUTPUT modified: ` +
            `${result.evidence.map((e) => e.rule_id).join(", ")}`,
        );
        return { text: result.rewrite };
      }
    } catch (err) {
      log.warn(`[AEGIS] Output guard error: ${err}`);
      // Fail-open: allow the message when service is unavailable
    }

    return {};
  };
}
