/**
 * Hook ②: Tool Guard — before_tool_call
 *
 * Intercepts tool invocations BEFORE execution.
 * Specifically guards:
 *   - exec: checks shell commands via guard_command
 *   - write/edit: checks file content via guard_output
 *   - message (send): checks outbound message content
 *
 * On BLOCK: returns { block: true, blockReason: "..." }
 * On APPROVE: returns {} (no modification)
 *
 * OpenClaw Hook: before_tool_call (sequential, async)
 * Priority: 800
 */

import type { AegisBridge } from "../aegis-bridge.js";
import type { AegisPluginConfig } from "../config.js";
import { shouldBlock, formatAegisLog } from "../utils.js";

interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

interface BeforeToolCallContext {
  agentId?: string;
  sessionKey?: string;
  toolName: string;
}

interface BeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
}

/** Tools whose execution involves running shell commands. */
const COMMAND_TOOLS = new Set(["exec", "process"]);

/** Tools whose content should be checked for safety. */
const CONTENT_TOOLS = new Set(["write", "edit", "apply_patch"]);

/** Tools that send messages to external parties. */
const MESSAGING_TOOLS = new Set(["message"]);

export function createToolGuard(bridge: AegisBridge, cfg: AegisPluginConfig, log: any) {
  const isEnforcing = cfg.mode === "enforcing";

  return async (
    event: BeforeToolCallEvent,
    ctx: BeforeToolCallContext,
  ): Promise<BeforeToolCallResult> => {
    const { toolName, params } = event;
    const sessionKey = ctx.sessionKey ?? "unknown";

    // --- exec / process: guard the command ---
    if (COMMAND_TOOLS.has(toolName) && params.command) {
      const command = String(params.command);

      try {
        const result = await bridge.guardCommand(command, {
          sessionId: sessionKey,
        });

        log.info(formatAegisLog("COMMAND", command, result));

        if (shouldBlock(result, cfg) && isEnforcing) {
          return {
            block: true,
            blockReason:
              `[AEGIS] Command blocked: ${result.message} ` +
              `(${result.risk?.severity ?? "unknown"} severity, ` +
              `${result.evidence.map((e) => e.rule_id).join(", ")})`,
          };
        }
      } catch (err) {
        log.warn(`[AEGIS] Command guard error: ${err}`);
      }
    }

    // --- write / edit: guard file content ---
    if (CONTENT_TOOLS.has(toolName)) {
      const content = params.content ?? params.patch ?? params.text;
      if (content && typeof content === "string" && content.length > 0) {
        try {
          const result = await bridge.guardOutput(content, {
            sessionId: sessionKey,
          });

          if (shouldBlock(result, cfg) && isEnforcing) {
            log.info(formatAegisLog("WRITE", content.slice(0, 100), result));
            return {
              block: true,
              blockReason: `[AEGIS] File content blocked: ${result.message}`,
            };
          }
        } catch (err) {
          log.warn(`[AEGIS] Content guard error: ${err}`);
        }
      }
    }

    // --- message (send): guard outbound messages ---
    if (MESSAGING_TOOLS.has(toolName)) {
      const text = params.body ?? params.text ?? params.message;
      if (text && typeof text === "string") {
        try {
          const result = await bridge.guardOutput(text, {
            sessionId: sessionKey,
          });

          if (shouldBlock(result, cfg) && isEnforcing) {
            log.info(formatAegisLog("MESSAGE", text.slice(0, 100), result));
            return {
              block: true,
              blockReason: `[AEGIS] Outbound message blocked: ${result.message}`,
            };
          }
        } catch (err) {
          log.warn(`[AEGIS] Message guard error: ${err}`);
        }
      }
    }

    return {};
  };
}
