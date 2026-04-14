"use strict";

/**
 * Matcher evaluation for hook rules.
 *
 * A matcher string is evaluated as follows:
 *   ""  / "*" / undefined  → match everything
 *   Only [A-Za-z0-9_|]    → exact match or pipe-separated list
 *   Anything else          → treated as a JavaScript RegExp
 *
 * This mirrors the Claude Code matcher semantics.
 */

const SIMPLE_RE = /^[A-Za-z0-9_|]+$/;

/**
 * Compile a matcher string into a predicate function.
 * @param {string|undefined} pattern
 * @returns {(value: string) => boolean}
 */
function compileMatcher(pattern) {
  if (pattern === undefined || pattern === null || pattern === "" || pattern === "*") {
    return () => true;
  }

  if (SIMPLE_RE.test(pattern)) {
    const values = new Set(pattern.split("|"));
    return (v) => values.has(v);
  }

  // Regex matcher
  try {
    const re = new RegExp(pattern);
    return (v) => re.test(v);
  } catch {
    // If the pattern is invalid regex, fall back to exact match
    return (v) => v === pattern;
  }
}

/**
 * Check whether a matcher pattern matches a given value.
 * @param {string|undefined} pattern - The matcher pattern from config
 * @param {string} value - The value to test (e.g. tool name, event source)
 * @returns {boolean}
 */
function matchesPattern(pattern, value) {
  return compileMatcher(pattern)(value);
}

/**
 * Evaluate the `if` field — a simple expression-based filter for tool events.
 * Supports patterns like:
 *   "Bash(git *)"        → tool_name == "Bash" && tool_input.command matches "git *"
 *   "Write(*.ts)"        → tool_name == "Write" && first arg matches "*.ts"
 *   "shell(npm *)"       → tool_name == "shell" && command matches "npm *"
 *
 * @param {string} ifExpr - The if expression
 * @param {object} context - { tool_name, tool_input }
 * @returns {boolean}
 */
function evaluateIf(ifExpr, context) {
  if (!ifExpr) return true;

  const match = ifExpr.match(/^(\w+)\((.+)\)$/);
  if (!match) return true; // Unparseable → pass through

  const [, toolName, argPattern] = match;

  if (context.tool_name !== toolName) return false;

  // Extract the primary argument to match against
  const input = context.tool_input || {};
  const primaryArg = input.command || input.file_path || input.pattern || "";

  return globMatch(argPattern, primaryArg);
}

/**
 * Simple glob matching (supports * and **).
 */
function globMatch(pattern, value) {
  // Convert glob to regex
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "<<GLOBSTAR>>")
    .replace(/\*/g, "[^/]*")
    .replace(/<<GLOBSTAR>>/g, ".*");
  const re = new RegExp(`^${escaped}$`);
  return re.test(value);
}

module.exports = { compileMatcher, matchesPattern, evaluateIf, globMatch };
