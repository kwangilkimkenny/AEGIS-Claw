/**
 * Hook ①: Input Guard — before_agent_start
 *
 * Intercepts user messages BEFORE the agent processes them.
 * Checks for: prompt injection, jailbreak, encoding attacks, safety violations.
 *
 * On BLOCK:  Injects a security notice into system prompt telling the agent
 *            to refuse the request.
 * On ESCALATE: Injects a warning telling the agent to proceed with caution.
 * On APPROVE: No modification.
 *
 * OpenClaw Hook: before_agent_start (sequential, async)
 * Priority: 900 (runs early in the hook chain)
 */

import type { AegisBridge } from "../aegis-bridge.js";
import type { AegisPluginConfig } from "../config.js";
import {
  extractLatestUserMessage,
  shouldBlock,
  buildBlockNotice,
  buildEscalateNotice,
  formatAegisLog,
} from "../utils.js";

interface BeforeAgentStartEvent {
  prompt: string;
  messages?: unknown[];
}

interface BeforeAgentStartContext {
  agentId?: string;
  sessionKey?: string;
  workspaceDir?: string;
  messageProvider?: string;
}

interface BeforeAgentStartResult {
  systemPrompt?: string;
  prependContext?: string;
}

export function createInputGuard(bridge: AegisBridge, cfg: AegisPluginConfig, log: any) {
  const isEnforcing = cfg.mode === "enforcing";

  return async (
    event: BeforeAgentStartEvent,
    ctx: BeforeAgentStartContext,
  ): Promise<BeforeAgentStartResult> => {
    const userMessage = extractLatestUserMessage(event.messages);
    if (!userMessage) return {};

    const sessionKey = ctx.sessionKey ?? "unknown";

    try {
      const result = await bridge.guardInput(userMessage, {
        sessionId: sessionKey,
      });

      log.info(formatAegisLog("INPUT", userMessage, result));

      // BLOCK: inject refusal notice
      if (shouldBlock(result, cfg) && isEnforcing) {
        return {
          prependContext: buildBlockNotice(result, userMessage),
        };
      }

      // ESCALATE: inject caution notice
      if (result.decision === "escalate") {
        return {
          prependContext: buildEscalateNotice(result, userMessage),
        };
      }

      // APPROVE / MODIFY / REASK: pass through
    } catch (err) {
      log.warn(`[AEGIS] Input guard service error: ${err}`);
      // Fail-open: allow the request when service is unavailable
    }

    return {};
  };
}
