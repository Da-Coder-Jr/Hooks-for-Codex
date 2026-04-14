"use strict";

/**
 * hooks-for-codex
 *
 * A comprehensive hooks system for OpenAI Codex CLI, inspired by
 * Claude Code's lifecycle hooks.  Provides deterministic control over
 * the Codex agent loop through user-defined shell commands, HTTP
 * endpoints, and LLM prompt evaluations.
 *
 * Usage:
 *
 *   const { HooksEngine } = require("hooks-for-codex");
 *
 *   const engine = new HooksEngine({ projectDir: "/path/to/project" });
 *
 *   // Before a tool runs
 *   const result = await engine.preToolUse("shell", { command: "rm -rf /" });
 *   if (!result.allowed) {
 *     console.log("Blocked:", result.reason);
 *   }
 *
 *   // After a tool runs
 *   await engine.postToolUse("shell", { command: "npm test" }, { exit_code: 0 });
 *
 *   // When agent stops
 *   const stopResult = await engine.stop();
 *   if (stopResult.blocked) {
 *     // Force agent to continue
 *   }
 */

const { HooksEngine, HookResult } = require("./engine");
const { HookEvent, EVENT_NAMES, BLOCKING_EVENTS, MATCHABLE_EVENTS } = require("./events");
const { compileMatcher, matchesPattern, evaluateIf } = require("./matchers");
const { loadConfig, validateFile, initConfig, discoverConfigFiles } = require("./config");
const {
  runHook,
  runCommandHook,
  runHttpHook,
  runPromptHook,
} = require("./runner");

module.exports = {
  // Core
  HooksEngine,
  HookResult,

  // Events
  HookEvent,
  EVENT_NAMES,
  BLOCKING_EVENTS,
  MATCHABLE_EVENTS,

  // Matchers
  compileMatcher,
  matchesPattern,
  evaluateIf,

  // Config
  loadConfig,
  validateFile,
  initConfig,
  discoverConfigFiles,

  // Runners
  runHook,
  runCommandHook,
  runHttpHook,
  runPromptHook,
};
