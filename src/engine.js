"use strict";

const { HookEvent, EVENT_NAMES } = require("./events");
const { compileMatcher, evaluateIf } = require("./matchers");
const { runHook } = require("./runner");
const { loadConfig } = require("./config");

/**
 * The HooksEngine is the central coordinator.  It:
 *   1. Loads and merges configuration from all hooks.json files
 *   2. Matches incoming events against configured rules
 *   3. Runs matching hooks in parallel
 *   4. Aggregates results (most restrictive decision wins)
 *   5. Returns a unified result to the caller
 */
class HooksEngine {
  /**
   * @param {object} [options]
   * @param {string} [options.projectDir]   - Project root directory
   * @param {object} [options.env]          - Extra environment variables for hooks
   * @param {object} [options.llmEvaluator] - LLM evaluator for prompt hooks
   * @param {boolean} [options.debug]       - Enable debug logging
   * @param {function} [options.logger]     - Custom logger function
   */
  constructor(options = {}) {
    this.projectDir = options.projectDir || process.cwd();
    this.env = {
      CODEX_PROJECT_DIR: this.projectDir,
      ...(options.env || {}),
    };
    this.llmEvaluator = options.llmEvaluator || null;
    this.debug = options.debug || false;
    this.logger = options.logger || console.error.bind(console);

    /** @type {object} Loaded hooks config keyed by event name */
    this.config = {};
    /** @type {string[]} Paths of loaded config files */
    this.configFiles = [];
    /** @type {Map<string, Set<string>>} Session-scoped "once" tracker */
    this._firedOnce = new Map();
    /** @type {boolean} Whether hooks are globally disabled */
    this.disabled = false;

    this.reload();
  }

  /**
   * Reload configuration from disk.
   */
  reload() {
    const { hooks, files } = loadConfig(this.projectDir);
    this.config = hooks;
    this.configFiles = files;
    if (this.debug) {
      this.logger(`[codex-hooks] Loaded ${files.length} config file(s): ${files.join(", ")}`);
      const total = Object.values(hooks).reduce((sum, rules) => sum + rules.length, 0);
      this.logger(`[codex-hooks] ${total} rule group(s) across ${Object.keys(hooks).length} event(s)`);
    }
  }

  /**
   * Fire an event and run all matching hooks.
   *
   * @param {string} eventName - One of EVENT_NAMES
   * @param {object} payload   - Event-specific data
   * @returns {Promise<HookResult>}
   */
  async fire(eventName, payload = {}) {
    if (this.disabled) {
      return HookResult.passthrough();
    }

    if (!EVENT_NAMES.includes(eventName)) {
      if (this.debug) this.logger(`[codex-hooks] Unknown event: ${eventName}`);
      return HookResult.passthrough();
    }

    const eventDef = HookEvent[eventName];
    const ruleGroups = this.config[eventName] || [];
    if (ruleGroups.length === 0) {
      return HookResult.passthrough();
    }

    // Build the input payload
    const input = {
      session_id: payload.session_id || process.env.CODEX_SESSION_ID || "",
      cwd: this.projectDir,
      hook_event_name: eventName,
      ...payload,
    };

    // Find matching rule groups
    const matchingHooks = [];
    for (const ruleGroup of ruleGroups) {
      // Check matcher
      if (eventDef.matcherField && ruleGroup.matcher) {
        const matcherFn = compileMatcher(ruleGroup.matcher);
        const value = input[eventDef.matcherField] || "";
        if (!matcherFn(value)) continue;
      }

      for (const hook of ruleGroup.hooks || []) {
        // Check `if` field (tool events only)
        if (hook.if && eventDef.scope === "tool") {
          if (!evaluateIf(hook.if, input)) continue;
        }

        // Check `once` flag
        if (hook.once) {
          const key = `${eventName}:${hook.command || hook.url || hook.prompt}`;
          if (!this._firedOnce.has(eventName)) {
            this._firedOnce.set(eventName, new Set());
          }
          if (this._firedOnce.get(eventName).has(key)) continue;
          this._firedOnce.get(eventName).add(key);
        }

        matchingHooks.push(hook);
      }
    }

    if (matchingHooks.length === 0) {
      return HookResult.passthrough();
    }

    if (this.debug) {
      this.logger(`[codex-hooks] ${eventName}: running ${matchingHooks.length} hook(s)`);
    }

    // Deduplicate identical command hooks
    const seen = new Set();
    const uniqueHooks = matchingHooks.filter((h) => {
      const key = `${h.type}:${h.command || h.url || h.prompt}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Separate async hooks from sync hooks
    const asyncHooks = uniqueHooks.filter((h) => h.async);
    const syncHooks = uniqueHooks.filter((h) => !h.async);

    // Fire async hooks (don't wait for them)
    for (const hook of asyncHooks) {
      runHook(hook, input, this.env, { llmEvaluator: this.llmEvaluator }).catch((err) => {
        if (this.debug) this.logger(`[codex-hooks] Async hook error: ${err.message}`);
      });
    }

    // Run sync hooks in parallel and aggregate
    const results = await Promise.all(
      syncHooks.map((hook) =>
        runHook(hook, input, this.env, { llmEvaluator: this.llmEvaluator }).catch((err) => ({
          exitCode: 1,
          stdout: "",
          stderr: err.message,
          parsed: null,
        }))
      )
    );

    return HookResult.aggregate(results, eventName, eventDef.blocking);
  }

  /**
   * Convenience: fire PreToolUse and return the permission decision.
   *
   * @param {string} toolName
   * @param {object} toolInput
   * @param {string} [toolUseId]
   * @returns {Promise<{ allowed: boolean, reason: string, updatedInput: object|null, context: string }>}
   */
  async preToolUse(toolName, toolInput, toolUseId) {
    const result = await this.fire("PreToolUse", {
      tool_name: toolName,
      tool_input: toolInput,
      tool_use_id: toolUseId || "",
    });

    if (result.blocked) {
      return {
        allowed: false,
        reason: result.blockReason,
        updatedInput: null,
        context: "",
      };
    }

    const decision = result.permissionDecision || "defer";
    const allowed = decision === "allow" || decision === "defer";
    return {
      allowed,
      reason: result.permissionDecisionReason || "",
      updatedInput: result.updatedInput || null,
      context: result.additionalContext || "",
    };
  }

  /**
   * Convenience: fire PostToolUse.
   */
  async postToolUse(toolName, toolInput, toolOutput, toolUseId) {
    return this.fire("PostToolUse", {
      tool_name: toolName,
      tool_input: toolInput,
      tool_output: toolOutput,
      tool_use_id: toolUseId || "",
    });
  }

  /**
   * Convenience: fire Stop and check if agent should continue.
   */
  async stop(stopHookActive = false) {
    return this.fire("Stop", { stop_hook_active: stopHookActive });
  }

  /**
   * Convenience: fire UserPromptSubmit.
   */
  async userPromptSubmit(prompt) {
    return this.fire("UserPromptSubmit", { prompt });
  }

  /**
   * Get a summary of all loaded hooks for display.
   * @returns {object[]}
   */
  listHooks() {
    const list = [];
    for (const [eventName, ruleGroups] of Object.entries(this.config)) {
      for (const ruleGroup of ruleGroups) {
        for (const hook of ruleGroup.hooks || []) {
          list.push({
            event: eventName,
            matcher: ruleGroup.matcher || "*",
            type: hook.type,
            target: hook.command || hook.url || hook.prompt || "(unknown)",
            timeout: hook.timeout,
            async: hook.async || false,
          });
        }
      }
    }
    return list;
  }
}

/**
 * Aggregated result from running hooks for a single event.
 */
class HookResult {
  constructor() {
    this.blocked = false;
    this.blockReason = "";
    this.continue_ = true;
    this.stopReason = "";
    this.suppressOutput = false;
    this.systemMessage = "";
    this.permissionDecision = null;
    this.permissionDecisionReason = "";
    this.updatedInput = null;
    this.additionalContext = "";
    this.outputs = [];
    this.errors = [];
  }

  /** Create a passthrough (no hooks ran) result */
  static passthrough() {
    return new HookResult();
  }

  /**
   * Aggregate multiple hook execution results.
   *
   * Decision priority (most restrictive wins):
   *   deny > block > ask > defer > allow
   *
   * @param {object[]} results - Array of { exitCode, stdout, stderr, parsed }
   * @param {string} eventName
   * @param {boolean} canBlock
   * @returns {HookResult}
   */
  static aggregate(results, eventName, canBlock) {
    const agg = new HookResult();

    const decisionPriority = { deny: 0, block: 1, ask: 2, defer: 3, allow: 4 };
    let bestDecision = null;
    let bestDecisionPriority = 999;

    for (const r of results) {
      // Exit code 2 = blocking
      if (r.exitCode === 2 && canBlock) {
        agg.blocked = true;
        agg.blockReason = r.stderr || "Blocked by hook";
      }

      // Non-zero, non-2 exit = non-blocking error
      if (r.exitCode !== 0 && r.exitCode !== 2) {
        agg.errors.push(r.stderr || `Hook exited with code ${r.exitCode}`);
      }

      // Collect output
      if (r.stdout) {
        agg.outputs.push(r.stdout);
      }

      // Process parsed JSON output
      if (r.parsed) {
        const p = r.parsed;

        if (p.continue === false) {
          agg.continue_ = false;
          agg.stopReason = p.stopReason || "";
        }

        if (p.suppressOutput) agg.suppressOutput = true;
        if (p.systemMessage) agg.systemMessage = p.systemMessage;

        // Decision field (Stop, PostToolUse, etc.)
        if (p.decision === "block" && canBlock) {
          agg.blocked = true;
          agg.blockReason = p.reason || "Blocked by hook";
        }

        // hookSpecificOutput for PreToolUse
        const hso = p.hookSpecificOutput;
        if (hso) {
          if (hso.permissionDecision) {
            const d = hso.permissionDecision;
            const pri = decisionPriority[d] ?? 999;
            if (pri < bestDecisionPriority) {
              bestDecision = d;
              bestDecisionPriority = pri;
              agg.permissionDecisionReason = hso.permissionDecisionReason || "";
            }
          }
          if (hso.updatedInput) agg.updatedInput = hso.updatedInput;
          if (hso.additionalContext) agg.additionalContext = hso.additionalContext;
        }
      }
    }

    if (bestDecision) {
      agg.permissionDecision = bestDecision;
      if (bestDecision === "deny") {
        agg.blocked = true;
        if (!agg.blockReason) agg.blockReason = agg.permissionDecisionReason || "Denied by hook";
      }
    }

    return agg;
  }
}

module.exports = { HooksEngine, HookResult };
