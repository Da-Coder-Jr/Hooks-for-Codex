"use strict";

const fs = require("fs");
const path = require("path");
const { HooksEngine } = require("./engine");

/**
 * CodexAdapter integrates the hooks engine with the Codex CLI agent loop.
 *
 * Codex CLI (codex-rs) processes tool calls in its agent loop and currently
 * only emits hook events for the Bash/shell tool.  This adapter provides a
 * wrapper layer that can be used to:
 *
 *   1. Intercept ALL tool calls (shell, apply_patch, web search, MCP tools)
 *   2. Map Codex-native tool names to normalized names
 *   3. Provide a drop-in integration for the Codex config system
 *   4. Enable the full hooks feature flag and configuration
 *
 * Integration approaches:
 *   A. Wrapper script — wraps the Codex binary and intercepts I/O
 *   B. Config injection — generates hooks.json in the right locations
 *   C. Direct API — import and call from a Node.js integration layer
 */

/** Map of Codex-internal tool names to normalized hook tool names */
const TOOL_NAME_MAP = {
  "container.exec": "shell",
  shell: "shell",
  apply_patch: "apply_patch",
  update_plan: "update_plan",
  web_search: "web_search",
  // MCP tools keep their original names
};

function normalizeToolName(raw) {
  return TOOL_NAME_MAP[raw] || raw;
}

class CodexAdapter {
  /**
   * @param {object} [options]
   * @param {string} [options.projectDir]
   * @param {boolean} [options.debug]
   * @param {object} [options.llmEvaluator]
   */
  constructor(options = {}) {
    this.engine = new HooksEngine(options);
    this.sessionId = `codex-${Date.now()}`;
    this.turnCount = 0;
  }

  /**
   * Call at the start of a Codex session.
   */
  async onSessionStart(source = "startup", model = "") {
    return this.engine.fire("SessionStart", {
      session_id: this.sessionId,
      source,
      model,
    });
  }

  /**
   * Call when the session ends.
   */
  async onSessionEnd(reason = "other") {
    return this.engine.fire("SessionEnd", {
      session_id: this.sessionId,
      reason,
    });
  }

  /**
   * Call when a user submits a prompt. Returns whether to proceed.
   */
  async onUserPrompt(prompt) {
    this.turnCount++;
    const result = await this.engine.fire("UserPromptSubmit", {
      session_id: this.sessionId,
      prompt,
    });
    return {
      allowed: !result.blocked,
      reason: result.blockReason,
      systemMessage: result.systemMessage,
    };
  }

  /**
   * Call BEFORE a tool executes. Returns permission decision.
   *
   * @param {string} toolName - Raw Codex tool name (e.g. "container.exec", "apply_patch")
   * @param {object} toolInput - Tool input parameters
   * @param {string} [toolUseId]
   */
  async onPreToolUse(toolName, toolInput, toolUseId) {
    const normalized = normalizeToolName(toolName);
    return this.engine.preToolUse(normalized, toolInput, toolUseId);
  }

  /**
   * Call AFTER a tool executes successfully.
   */
  async onPostToolUse(toolName, toolInput, toolOutput, toolUseId) {
    const normalized = normalizeToolName(toolName);
    return this.engine.postToolUse(normalized, toolInput, toolOutput, toolUseId);
  }

  /**
   * Call AFTER a tool execution fails.
   */
  async onPostToolUseFailure(toolName, toolInput, error, isInterrupt = false, toolUseId) {
    const normalized = normalizeToolName(toolName);
    return this.engine.fire("PostToolUseFailure", {
      session_id: this.sessionId,
      tool_name: normalized,
      tool_input: toolInput,
      error: typeof error === "string" ? error : error.message,
      is_interrupt: isInterrupt,
      tool_use_id: toolUseId || "",
    });
  }

  /**
   * Call when the agent stops. Returns whether to force continuation.
   */
  async onStop(stopHookActive = false) {
    const result = await this.engine.stop(stopHookActive);
    return {
      shouldContinue: result.blocked,
      reason: result.blockReason,
      systemMessage: result.systemMessage,
    };
  }

  /**
   * Call when a permission dialog would be shown.
   */
  async onPermissionRequest(toolName, toolInput) {
    const normalized = normalizeToolName(toolName);
    const result = await this.engine.fire("PermissionRequest", {
      session_id: this.sessionId,
      tool_name: normalized,
      tool_input: toolInput,
    });
    return {
      decision: result.permissionDecision || "defer",
      reason: result.permissionDecisionReason,
      updatedInput: result.updatedInput,
    };
  }

  /**
   * Call when a file changes on disk.
   */
  async onFileChanged(filePath, changeType = "modified") {
    return this.engine.fire("FileChanged", {
      session_id: this.sessionId,
      file_path: filePath,
      change_type: changeType,
    });
  }

  /**
   * Get the hooks engine for direct access.
   */
  getEngine() {
    return this.engine;
  }
}

/**
 * Enable hooks in the Codex config.toml by ensuring the feature flag is set.
 * @param {string} configPath - Path to config.toml
 */
function enableHooksFeatureFlag(configPath) {
  let content = "";
  if (fs.existsSync(configPath)) {
    content = fs.readFileSync(configPath, "utf-8");
  }

  if (content.includes("codex_hooks")) {
    // Replace existing value
    content = content.replace(/codex_hooks\s*=\s*\w+/, "codex_hooks = true");
  } else {
    // Add feature flag section
    if (content.includes("[features]")) {
      content = content.replace("[features]", "[features]\ncodex_hooks = true");
    } else {
      content += "\n[features]\ncodex_hooks = true\n";
    }
  }

  const dir = path.dirname(configPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(configPath, content);
}

/**
 * Generate the Codex-compatible hooks.json from an enhanced config.
 * Strips fields that Codex's native parser doesn't understand, keeping
 * only what the Codex Rust runtime can parse.
 *
 * @param {object} enhancedConfig - Full hooks-for-codex config
 * @returns {object} Codex-compatible hooks.json
 */
function toCodexNativeFormat(enhancedConfig) {
  const native = { hooks: {} };

  const codexEvents = ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"];

  for (const [eventName, rules] of Object.entries(enhancedConfig)) {
    if (!codexEvents.includes(eventName)) continue;

    native.hooks[eventName] = rules.map((rule) => ({
      matcher: rule.matcher || "",
      hooks: (rule.hooks || [])
        .filter((h) => h.type === "command") // Codex native only supports command hooks
        .map((h) => ({
          type: "command",
          command: h.command,
          timeout: h.timeout || 5,
        })),
    }));
  }

  return native;
}

module.exports = {
  CodexAdapter,
  TOOL_NAME_MAP,
  normalizeToolName,
  enableHooksFeatureFlag,
  toCodexNativeFormat,
};
