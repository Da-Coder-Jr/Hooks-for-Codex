"use strict";

/**
 * Hook event definitions for the Codex app (desktop + CLI).
 *
 * TWO TIERS of events:
 *
 *   TIER 1 — Native hooks (hooks.json, codex_hooks feature flag required)
 *     These fire inside the Codex Rust runtime. Requires:
 *       [features]
 *       codex_hooks = true
 *     in ~/.codex/config.toml or .codex/config.toml.
 *     Source: codex-rs/hooks/src/schema.rs
 *
 *   TIER 2 — Extended hooks (codex-hooks-daemon, App Server JSON-RPC)
 *     These fire via the Codex App Server JSON-RPC API, which exposes a
 *     richer event stream. The daemon connects to the App Server and fires
 *     hooks for events the native system misses (apply_patch, long-running
 *     commands, sub-agent events, file approvals, etc.).
 *     Source: codex-rs/app-server/README.md
 *
 * Known native limitations (as of April 2026):
 *   - apply_patch does NOT fire PreToolUse/PostToolUse (issue #16732)
 *   - tool_name is hardcoded as "Bash" in hook_runtime.rs
 *   - No sub-agent distinction in hook payloads (issue #16226)
 *   - PostToolUse missing for long-running commands (issue #16246)
 *   - No TaskCompleted event (issue #17333)
 *   - No PermissionRequest hook for external approval UIs (issue #15311)
 *
 * Fields per event (stdin JSON):
 *   All native events share: session_id, transcript_path, cwd,
 *   hook_event_name, model, permission_mode
 */

const HookTier = Object.freeze({
  NATIVE: "native",   // hooks.json, codex_hooks feature flag
  EXTENDED: "extended", // codex-hooks-daemon, App Server JSON-RPC
});

const HookEvent = Object.freeze({
  // ── TIER 1: Native hooks ─────────────────────────────────────────
  //   Configure in ~/.codex/hooks.json or .codex/hooks.json
  //   Requires: [features] codex_hooks = true

  SessionStart: {
    tier: HookTier.NATIVE,
    description: "Fires when a Codex session begins",
    scope: "session",
    blocking: false,
    matcherField: null,
    // Extra stdin fields: source ("startup"|"resume"), model
    inputFields: ["session_id", "transcript_path", "cwd", "model", "permission_mode", "source"],
  },

  UserPromptSubmit: {
    tier: HookTier.NATIVE,
    description: "Fires when the user submits a prompt — can block it (exit 2)",
    scope: "turn",
    blocking: true,
    matcherField: null,
    // Extra stdin fields: turn_id, prompt
    inputFields: ["session_id", "turn_id", "transcript_path", "cwd", "model", "permission_mode", "prompt"],
  },

  PreToolUse: {
    tier: HookTier.NATIVE,
    description: "Fires before a shell/Bash command executes — can block it (exit 2)",
    scope: "tool",
    blocking: true,
    matcherField: "tool_name",
    // Extra stdin fields: turn_id, tool_name, tool_input, tool_use_id
    inputFields: ["session_id", "turn_id", "transcript_path", "cwd", "model", "permission_mode",
                  "tool_name", "tool_input", "tool_use_id"],
    // NOTE: tool_name is currently hardcoded as "Bash" in Codex runtime (issue #16732)
    // apply_patch does NOT fire this event natively — use PreFilePatch (Tier 2) instead
  },

  PostToolUse: {
    tier: HookTier.NATIVE,
    description: "Fires after a shell/Bash command completes",
    scope: "tool",
    blocking: false,
    matcherField: "tool_name",
    // Extra stdin fields: turn_id, tool_name, tool_input, tool_response, tool_use_id
    inputFields: ["session_id", "turn_id", "transcript_path", "cwd", "model", "permission_mode",
                  "tool_name", "tool_input", "tool_response", "tool_use_id"],
    // NOTE: Missing for long-running commands that complete via polling (issue #16246)
  },

  Stop: {
    tier: HookTier.NATIVE,
    description: "Fires when the agent finishes a turn — exit 2 forces the agent to continue",
    scope: "turn",
    blocking: true,
    matcherField: null,
    // Extra stdin fields: turn_id, stop_hook_active, last_assistant_message
    inputFields: ["session_id", "turn_id", "transcript_path", "cwd", "model", "permission_mode",
                  "stop_hook_active", "last_assistant_message"],
    // IMPORTANT: Check stop_hook_active === true before exiting 2, or you create an infinite loop
  },

  // ── TIER 2: Extended hooks (via codex-hooks-daemon) ──────────────
  //   These require `codex-hooks-daemon` to be running.
  //   The daemon connects to the Codex App Server JSON-RPC API and
  //   synthesises hook events for the gaps in the native system.

  PreFilePatch: {
    tier: HookTier.EXTENDED,
    description: "Fires before apply_patch writes a file (native system misses this — issue #16732)",
    scope: "tool",
    blocking: true,
    matcherField: "file_path",
    inputFields: ["session_id", "turn_id", "cwd", "file_path", "patch_content", "operation"],
    // operation: "create" | "update" | "delete"
  },

  PostFilePatch: {
    tier: HookTier.EXTENDED,
    description: "Fires after apply_patch writes a file",
    scope: "tool",
    blocking: false,
    matcherField: "file_path",
    inputFields: ["session_id", "turn_id", "cwd", "file_path", "patch_content", "operation"],
  },

  CommandApproval: {
    tier: HookTier.EXTENDED,
    description: "Fires when Codex is waiting for user approval of a shell command",
    scope: "tool",
    blocking: true,
    matcherField: "tool_name",
    inputFields: ["session_id", "turn_id", "cwd", "tool_name", "tool_input", "item_id", "thread_id"],
  },

  FileChangeApproval: {
    tier: HookTier.EXTENDED,
    description: "Fires when Codex is waiting for user approval of a file change",
    scope: "tool",
    blocking: true,
    matcherField: "file_path",
    inputFields: ["session_id", "turn_id", "cwd", "file_path", "diff", "item_id", "thread_id"],
  },

  TurnStarted: {
    tier: HookTier.EXTENDED,
    description: "Fires when an agent turn begins",
    scope: "turn",
    blocking: false,
    matcherField: null,
    inputFields: ["session_id", "turn_id", "thread_id", "cwd"],
  },

  TurnCompleted: {
    tier: HookTier.EXTENDED,
    description: "Fires when an agent turn completes (richer than native Stop)",
    scope: "turn",
    blocking: false,
    matcherField: null,
    inputFields: ["session_id", "turn_id", "thread_id", "cwd", "last_message"],
  },

  ThreadStarted: {
    tier: HookTier.EXTENDED,
    description: "Fires when a new conversation thread is created",
    scope: "session",
    blocking: false,
    matcherField: null,
    inputFields: ["thread_id", "cwd"],
  },
});

/** All valid event names */
const EVENT_NAMES = Object.keys(HookEvent);

/** Only native hook events (hooks.json) */
const NATIVE_EVENT_NAMES = EVENT_NAMES.filter((e) => HookEvent[e].tier === HookTier.NATIVE);

/** Only extended hook events (daemon) */
const EXTENDED_EVENT_NAMES = EVENT_NAMES.filter((e) => HookEvent[e].tier === HookTier.EXTENDED);

/** Events that can block via exit code 2 */
const BLOCKING_EVENTS = EVENT_NAMES.filter((e) => HookEvent[e].blocking);

/** Events that support a matcher field */
const MATCHABLE_EVENTS = EVENT_NAMES.filter((e) => HookEvent[e].matcherField !== null);

module.exports = {
  HookTier,
  HookEvent,
  EVENT_NAMES,
  NATIVE_EVENT_NAMES,
  EXTENDED_EVENT_NAMES,
  BLOCKING_EVENTS,
  MATCHABLE_EVENTS,
};
