"use strict";

/**
 * Hook event definitions for Codex CLI.
 *
 * Modeled after Claude Code's 26 hook events, adapted for the Codex agent
 * loop.  Each event declares:
 *   - description  – human-readable purpose
 *   - scope        – "session" | "turn" | "tool"
 *   - blocking     – whether exit-code 2 can block the action
 *   - matcherField – what the matcher filters on (null = no matcher)
 *   - inputFields  – extra fields sent to the hook on stdin
 */

const HookEvent = Object.freeze({
  // ── Once per session ──────────────────────────────────────────────
  SessionStart: {
    description: "Fires when a Codex session begins or resumes",
    scope: "session",
    blocking: false,
    matcherField: "source",
    inputFields: ["source", "model"],
  },
  SessionEnd: {
    description: "Fires when a Codex session terminates",
    scope: "session",
    blocking: false,
    matcherField: "reason",
    inputFields: ["reason"],
  },

  // ── Once per turn ─────────────────────────────────────────────────
  UserPromptSubmit: {
    description: "Fires when the user submits a prompt, before processing",
    scope: "turn",
    blocking: true,
    matcherField: null,
    inputFields: ["prompt"],
  },
  Stop: {
    description: "Fires when the agent finishes responding",
    scope: "turn",
    blocking: true,
    matcherField: null,
    inputFields: ["stop_hook_active"],
  },
  StopFailure: {
    description: "Fires when a turn ends due to an API error",
    scope: "turn",
    blocking: false,
    matcherField: "error_type",
    inputFields: ["error_type", "error_message"],
  },

  // ── Per tool call ─────────────────────────────────────────────────
  PreToolUse: {
    description: "Fires before a tool executes (shell, apply_patch, etc.)",
    scope: "tool",
    blocking: true,
    matcherField: "tool_name",
    inputFields: ["tool_name", "tool_input", "tool_use_id"],
  },
  PostToolUse: {
    description: "Fires after a tool executes successfully",
    scope: "tool",
    blocking: false,
    matcherField: "tool_name",
    inputFields: ["tool_name", "tool_input", "tool_output", "tool_use_id"],
  },
  PostToolUseFailure: {
    description: "Fires after a tool execution fails",
    scope: "tool",
    blocking: false,
    matcherField: "tool_name",
    inputFields: ["tool_name", "tool_input", "error", "is_interrupt", "tool_use_id"],
  },
  PermissionRequest: {
    description: "Fires when the approval dialog appears for a tool",
    scope: "tool",
    blocking: true,
    matcherField: "tool_name",
    inputFields: ["tool_name", "tool_input"],
  },
  PermissionDenied: {
    description: "Fires when a tool is denied by the approval policy",
    scope: "tool",
    blocking: false,
    matcherField: "tool_name",
    inputFields: ["tool_name", "tool_input", "reason"],
  },

  // ── Notification ──────────────────────────────────────────────────
  Notification: {
    description: "Fires when Codex emits a notification to the user",
    scope: "session",
    blocking: false,
    matcherField: "notification_type",
    inputFields: ["message", "title", "notification_type"],
  },

  // ── File watching ─────────────────────────────────────────────────
  FileChanged: {
    description: "Fires when a watched file changes on disk",
    scope: "session",
    blocking: false,
    matcherField: "file_path",
    inputFields: ["file_path", "change_type"],
  },

  // ── Configuration ─────────────────────────────────────────────────
  ConfigChange: {
    description: "Fires when a configuration file changes",
    scope: "session",
    blocking: true,
    matcherField: null,
    inputFields: ["config_path", "changes"],
  },

  // ── Working directory ─────────────────────────────────────────────
  CwdChanged: {
    description: "Fires when the working directory changes",
    scope: "session",
    blocking: false,
    matcherField: null,
    inputFields: ["old_cwd", "new_cwd"],
  },
});

/** All valid event names */
const EVENT_NAMES = Object.keys(HookEvent);

/** Only the events that support blocking (exit 2) */
const BLOCKING_EVENTS = EVENT_NAMES.filter((e) => HookEvent[e].blocking);

/** Only the events that use a matcher */
const MATCHABLE_EVENTS = EVENT_NAMES.filter((e) => HookEvent[e].matcherField !== null);

module.exports = { HookEvent, EVENT_NAMES, BLOCKING_EVENTS, MATCHABLE_EVENTS };
