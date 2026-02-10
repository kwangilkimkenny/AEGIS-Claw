/**
 * Hook ③: Result Guard — tool_result_persist
 *
 * Intercepts tool results BEFORE they are persisted to session history.
 * Redacts secrets (API keys, passwords, tokens, private keys, connection strings)
 * from tool outputs to prevent credential leakage.
 *
 * IMPORTANT: This hook is SYNCHRONOUS. It cannot call the Python service.
 * All detection is done locally via regex patterns.
 *
 * OpenClaw Hook: tool_result_persist (synchronous, sequential)
 */

import type { AegisPluginConfig } from "../config.js";
import { redactSecrets } from "../utils.js";

interface AgentMessage {
  role: string;
  content: unknown;
  [key: string]: unknown;
}

interface ContentBlock {
  type: string;
  text?: string;
  [key: string]: unknown;
}

interface ToolResultPersistEvent {
  message: AgentMessage;
  isSynthetic?: boolean;
}

interface ToolResultPersistContext {
  agentId?: string;
  sessionKey?: string;
  toolName?: string;
  toolCallId?: string;
}

interface ToolResultPersistResult {
  message?: AgentMessage;
}

export function createResultGuard(cfg: AegisPluginConfig, log: any) {
  return (
    event: ToolResultPersistEvent,
    ctx: ToolResultPersistContext,
  ): ToolResultPersistResult => {
    if (!cfg.redactSecrets) {
      return { message: event.message };
    }

    const msg = event.message;

    // Only process tool results with array content
    if (!msg || !Array.isArray(msg.content)) {
      return { message: msg };
    }

    let totalRedacted = 0;
    const newContent = (msg.content as ContentBlock[]).map((block) => {
      if (block.type !== "text" || typeof block.text !== "string") {
        return block;
      }

      const result = redactSecrets(block.text);
      if (result.count > 0) {
        totalRedacted += result.count;
        return { ...block, text: result.text };
      }

      return block;
    });

    if (totalRedacted > 0) {
      log.info(
        `[AEGIS] Redacted ${totalRedacted} secret(s) in ` +
          `${ctx.toolName ?? "unknown"} result` +
          (ctx.toolCallId ? ` (${ctx.toolCallId})` : ""),
      );
      return { message: { ...msg, content: newContent } };
    }

    return { message: msg };
  };
}
