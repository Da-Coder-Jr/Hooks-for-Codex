"use strict";

/**
 * hooks-for-codex
 *
 * Lifecycle hooks for the OpenAI Codex desktop app.
 * Brings Claude Code-level hook power to Codex.
 *
 * TWO TIERS:
 *   Tier 1 — Native hooks via hooks.json (5 events, shell commands only)
 *   Tier 2 — Extended hooks via App Server daemon (file patches, approvals, turn events)
 *
 * Quick usage:
 *   const { HooksEngine } = require("hooks-for-codex");
 *   const engine = new HooksEngine({ projectDir: "/path/to/project" });
 *
 *   // Fire a hook event manually
 *   const result = await engine.fire("PreToolUse", {
 *     tool_name: "Bash",
 *     tool_input: { command: "rm -rf /" }
 *   });
 *   if (result.blocked) console.log("Blocked:", result.blockReason);
 *
 *   // Start extended hooks daemon
 *   const { AppServerDaemon } = require("hooks-for-codex");
 *   const daemon = new AppServerDaemon({ engine, wsUrl: "ws://127.0.0.1:4500" });
 *   daemon.start();
 */

const { HooksEngine, HookResult } = require("./engine");
const { AppServerClient, AppServerDaemon } = require("./app-server");
const {
  HookTier, HookEvent, EVENT_NAMES,
  NATIVE_EVENT_NAMES, EXTENDED_EVENT_NAMES,
  BLOCKING_EVENTS, MATCHABLE_EVENTS,
} = require("./events");
const { compileMatcher, matchesPattern, evaluateIf } = require("./matchers");
const { loadConfig, validateFile, initConfig, discoverConfigFiles } = require("./config");
const { runHook, runCommandHook, runHttpHook, runPromptHook } = require("./runner");
const {
  CODEX_HOME, PATHS,
  enableHooksFeatureFlag, isHooksEnabled, ensureCodexDir, readToml,
} = require("./codex-adapter");

module.exports = {
  // Core engine
  HooksEngine,
  HookResult,

  // App Server daemon (Tier 2 / extended hooks)
  AppServerClient,
  AppServerDaemon,

  // Event definitions
  HookTier,
  HookEvent,
  EVENT_NAMES,
  NATIVE_EVENT_NAMES,
  EXTENDED_EVENT_NAMES,
  BLOCKING_EVENTS,
  MATCHABLE_EVENTS,

  // Matchers
  compileMatcher,
  matchesPattern,
  evaluateIf,

  // Configuration
  loadConfig,
  validateFile,
  initConfig,
  discoverConfigFiles,

  // Hook runners
  runHook,
  runCommandHook,
  runHttpHook,
  runPromptHook,

  // Codex desktop app utilities
  CODEX_HOME,
  PATHS,
  enableHooksFeatureFlag,
  isHooksEnabled,
  ensureCodexDir,
  readToml,
};
