"use strict";

const fs = require("fs");
const path = require("path");

/**
 * Utilities for integrating hooks-for-codex with the Codex desktop app.
 *
 * The Codex app (desktop + CLI) stores config at:
 *   - Global:        ~/.codex/config.toml  +  ~/.codex/hooks.json
 *   - Project:       .codex/config.toml    +  .codex/hooks.json
 *   - Project local: .codex/config.toml    +  .codex/hooks.local.json  (gitignored)
 *
 * The hooks feature flag must be enabled in config.toml:
 *   [features]
 *   codex_hooks = true
 *
 * The App Server (for extended/Tier-2 hooks) must be started with:
 *   codex app-server --listen ws://127.0.0.1:4500
 *
 * On macOS this is done automatically when the desktop app is running.
 * On Windows (v0.120.0+) it is also available.
 * On Linux (community build) it may need manual configuration.
 */

const CODEX_HOME = process.env.CODEX_HOME || path.join(process.env.HOME || "~", ".codex");

const PATHS = {
  globalConfig: path.join(CODEX_HOME, "config.toml"),
  globalHooks: path.join(CODEX_HOME, "hooks.json"),
  globalAgentsMd: path.join(CODEX_HOME, "AGENTS.md"),
  projectConfig: (dir) => path.join(dir, ".codex", "config.toml"),
  projectHooks: (dir) => path.join(dir, ".codex", "hooks.json"),
  projectHooksLocal: (dir) => path.join(dir, ".codex", "hooks.local.json"),
};

/**
 * Enable the codex_hooks feature flag in a config.toml file.
 * Creates the file if it doesn't exist.
 *
 * @param {string} [configPath] - Defaults to ~/.codex/config.toml
 */
function enableHooksFeatureFlag(configPath) {
  const target = configPath || PATHS.globalConfig;
  const dir = path.dirname(target);

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  let content = "";
  if (fs.existsSync(target)) {
    content = fs.readFileSync(target, "utf-8");
  }

  if (content.includes("codex_hooks = true")) {
    return { changed: false, path: target };
  }

  if (/codex_hooks\s*=\s*\w+/.test(content)) {
    content = content.replace(/codex_hooks\s*=\s*\w+/, "codex_hooks = true");
  } else if (content.includes("[features]")) {
    content = content.replace(/\[features\]/, "[features]\ncodex_hooks = true");
  } else {
    content += (content.endsWith("\n") ? "" : "\n") + "\n[features]\ncodex_hooks = true\n";
  }

  fs.writeFileSync(target, content, "utf-8");
  return { changed: true, path: target };
}

/**
 * Check if the codex_hooks feature flag is enabled.
 * @param {string} [projectDir]
 * @returns {{ enabled: boolean, path: string|null }}
 */
function isHooksEnabled(projectDir) {
  const paths = [
    PATHS.globalConfig,
    projectDir ? PATHS.projectConfig(projectDir) : null,
  ].filter(Boolean);

  for (const p of paths) {
    if (fs.existsSync(p)) {
      const content = fs.readFileSync(p, "utf-8");
      if (content.includes("codex_hooks = true")) {
        return { enabled: true, path: p };
      }
    }
  }
  return { enabled: false, path: null };
}

/**
 * Ensure the .codex directory exists for a project.
 * @param {string} [projectDir]
 */
function ensureCodexDir(projectDir) {
  const dir = projectDir
    ? path.join(projectDir, ".codex")
    : CODEX_HOME;
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

/**
 * Read the Codex config.toml as a plain object (basic TOML parser).
 * Only handles simple key=value and [section] tables.
 * @param {string} filePath
 * @returns {object}
 */
function readToml(filePath) {
  if (!fs.existsSync(filePath)) return {};

  const lines = fs.readFileSync(filePath, "utf-8").split("\n");
  const result = {};
  let currentSection = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const sectionMatch = line.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1];
      const parts = currentSection.split(".");
      let obj = result;
      for (const part of parts) {
        if (!obj[part]) obj[part] = {};
        obj = obj[part];
      }
      continue;
    }

    const kvMatch = line.match(/^([^=]+)=(.*)$/);
    if (kvMatch) {
      const key = kvMatch[1].trim();
      let val = kvMatch[2].trim();
      // Strip quotes
      if ((val.startsWith('"') && val.endsWith('"')) ||
          (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      } else if (val === "true") {
        val = true;
      } else if (val === "false") {
        val = false;
      } else if (!isNaN(val)) {
        val = Number(val);
      }

      if (currentSection) {
        const parts = currentSection.split(".");
        let obj = result;
        for (const part of parts) {
          if (!obj[part]) obj[part] = {};
          obj = obj[part];
        }
        obj[key] = val;
      } else {
        result[key] = val;
      }
    }
  }

  return result;
}

module.exports = {
  CODEX_HOME,
  PATHS,
  enableHooksFeatureFlag,
  isHooksEnabled,
  ensureCodexDir,
  readToml,
};
