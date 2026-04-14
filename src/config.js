"use strict";

const fs = require("fs");
const path = require("path");
const { EVENT_NAMES } = require("./events");

/**
 * Configuration loader for Codex hooks.
 *
 * Discovery order (all layers are merged, NOT replaced):
 *   1. ~/.codex/hooks.json           (global / user-level)
 *   2. <repo>/.codex/hooks.json      (project-level, committable)
 *   3. <repo>/.codex/hooks.local.json (project-level, gitignored)
 *
 * The merged result is an object keyed by event name, each holding an array
 * of rule groups: { matcher, hooks[] }.
 */

const GLOBAL_DIR = path.join(process.env.HOME || process.env.USERPROFILE || "~", ".codex");
const GLOBAL_HOOKS_FILE = path.join(GLOBAL_DIR, "hooks.json");
const PROJECT_HOOKS_FILE = ".codex/hooks.json";
const PROJECT_HOOKS_LOCAL_FILE = ".codex/hooks.local.json";

/** Default timeout per hook type (seconds) */
const DEFAULT_TIMEOUTS = {
  command: 600,
  http: 30,
  prompt: 30,
};

/**
 * Locate all hooks.json files that apply to the given project directory.
 * @param {string} [projectDir] - Project root (defaults to cwd)
 * @returns {string[]} Paths to hooks.json files, ordered by precedence
 */
function discoverConfigFiles(projectDir) {
  const dir = projectDir || process.cwd();
  const files = [];

  // Global
  if (fs.existsSync(GLOBAL_HOOKS_FILE)) {
    files.push(GLOBAL_HOOKS_FILE);
  }

  // Project
  const projectFile = path.join(dir, PROJECT_HOOKS_FILE);
  if (fs.existsSync(projectFile)) {
    files.push(projectFile);
  }

  // Project local (gitignored)
  const localFile = path.join(dir, PROJECT_HOOKS_LOCAL_FILE);
  if (fs.existsSync(localFile)) {
    files.push(localFile);
  }

  return files;
}

/**
 * Read and parse a single hooks.json file.
 * @param {string} filePath
 * @returns {object} Parsed hooks configuration
 */
function readConfigFile(filePath) {
  try {
    const raw = fs.readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    return parsed.hooks || parsed;
  } catch (err) {
    console.error(`[codex-hooks] Warning: failed to read ${filePath}: ${err.message}`);
    return {};
  }
}

/**
 * Merge multiple hooks config objects. Rules from all layers accumulate.
 * @param {object[]} configs
 * @returns {object} Merged config keyed by event name
 */
function mergeConfigs(configs) {
  const merged = {};

  for (const config of configs) {
    for (const [eventName, rules] of Object.entries(config)) {
      if (!EVENT_NAMES.includes(eventName)) {
        console.error(`[codex-hooks] Warning: unknown event "${eventName}", skipping`);
        continue;
      }
      if (!merged[eventName]) {
        merged[eventName] = [];
      }
      if (Array.isArray(rules)) {
        merged[eventName].push(...rules);
      }
    }
  }

  return merged;
}

/**
 * Load the full merged hooks configuration for a project.
 * @param {string} [projectDir]
 * @returns {{ hooks: object, files: string[] }}
 */
function loadConfig(projectDir) {
  const files = discoverConfigFiles(projectDir);
  const configs = files.map(readConfigFile);
  const hooks = mergeConfigs(configs);
  return { hooks, files };
}

/**
 * Validate a hooks.json file and report errors.
 * @param {string} filePath
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateFile(filePath) {
  const errors = [];

  let parsed;
  try {
    const raw = fs.readFileSync(filePath, "utf-8");
    parsed = JSON.parse(raw);
  } catch (err) {
    return { valid: false, errors: [`Parse error: ${err.message}`] };
  }

  const hooks = parsed.hooks || parsed;

  for (const [eventName, rules] of Object.entries(hooks)) {
    if (!EVENT_NAMES.includes(eventName)) {
      errors.push(`Unknown event: "${eventName}"`);
      continue;
    }

    if (!Array.isArray(rules)) {
      errors.push(`Event "${eventName}": expected an array of rule groups`);
      continue;
    }

    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      if (!rule.hooks || !Array.isArray(rule.hooks)) {
        errors.push(`Event "${eventName}" rule #${i + 1}: missing "hooks" array`);
        continue;
      }

      for (let j = 0; j < rule.hooks.length; j++) {
        const hook = rule.hooks[j];
        if (!hook.type) {
          errors.push(`Event "${eventName}" rule #${i + 1} hook #${j + 1}: missing "type"`);
        } else if (!["command", "http", "prompt"].includes(hook.type)) {
          errors.push(`Event "${eventName}" rule #${i + 1} hook #${j + 1}: unknown type "${hook.type}"`);
        }

        if (hook.type === "command" && !hook.command) {
          errors.push(`Event "${eventName}" rule #${i + 1} hook #${j + 1}: command type requires "command" field`);
        }
        if (hook.type === "http" && !hook.url) {
          errors.push(`Event "${eventName}" rule #${i + 1} hook #${j + 1}: http type requires "url" field`);
        }
        if (hook.type === "prompt" && !hook.prompt) {
          errors.push(`Event "${eventName}" rule #${i + 1} hook #${j + 1}: prompt type requires "prompt" field`);
        }
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Initialize a hooks.json file at the given path with a starter template.
 * @param {string} filePath
 * @param {string} [templateName] - "basic" | "security"
 */
function initConfig(filePath, templateName) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  let templatePath;
  if (templateName === "security") {
    templatePath = path.join(__dirname, "..", "templates", "security-hooks.json");
  } else {
    templatePath = path.join(__dirname, "..", "templates", "basic-hooks.json");
  }

  if (fs.existsSync(templatePath)) {
    fs.copyFileSync(templatePath, filePath);
  } else {
    // Fallback: write a minimal config
    const minimal = {
      hooks: {
        PreToolUse: [],
        PostToolUse: [],
        Stop: [],
      },
    };
    fs.writeFileSync(filePath, JSON.stringify(minimal, null, 2) + "\n");
  }
}

module.exports = {
  GLOBAL_DIR,
  GLOBAL_HOOKS_FILE,
  PROJECT_HOOKS_FILE,
  PROJECT_HOOKS_LOCAL_FILE,
  DEFAULT_TIMEOUTS,
  discoverConfigFiles,
  readConfigFile,
  mergeConfigs,
  loadConfig,
  validateFile,
  initConfig,
};
