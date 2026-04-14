#!/usr/bin/env node
"use strict";

/**
 * codex-hooks CLI — manage hooks for the Codex desktop app
 *
 * Usage: codex-hooks <command> [options]
 */

const fs = require("fs");
const path = require("path");

const { loadConfig, validateFile, initConfig, discoverConfigFiles } = require("../src/config");
const { HooksEngine } = require("../src/engine");
const { EVENT_NAMES, NATIVE_EVENT_NAMES, EXTENDED_EVENT_NAMES, HookEvent, HookTier } = require("../src/events");
const { enableHooksFeatureFlag, isHooksEnabled, CODEX_HOME, PATHS } = require("../src/codex-adapter");

const args = process.argv.slice(2);
const command = args[0];

const HELP = `
codex-hooks — lifecycle hooks for the OpenAI Codex desktop app

USAGE
  codex-hooks <command> [options]

COMMANDS
  init [--global] [--template=basic|security]
      Create a hooks.json file in the current project (.codex/hooks.json)
      or globally (~/.codex/hooks.json).

  list
      Show all active hooks from all loaded hooks.json files.

  validate [file]
      Validate a hooks.json file and report any errors.

  events
      List all available hook events with descriptions.

  test <event> [--payload=<json>]
      Fire a test event and display the result.

  enable [--global | --project]
      Enable the codex_hooks feature flag in config.toml.

  doctor
      Check your entire hooks setup for common problems.

  files
      Show which hooks.json files are discovered and loaded.

OPTIONS
  --global            Use global config (~/.codex/)
  --project           Use project config (.codex/)
  --template=NAME     "basic" (default) or "security"
  --debug             Verbose output
  -h, --help          This message

QUICK START
  1. codex-hooks enable               # turn on the feature flag
  2. codex-hooks init                 # create .codex/hooks.json
  3. edit .codex/hooks.json           # add your hook scripts
  4. codex-hooks validate             # check for errors
  5. codex-hooks list                 # confirm hooks are loaded

  For apply_patch / file-change hooks (the native system misses these):
  6. npm install ws                   # install WebSocket dependency
  7. codex app-server --listen ws://127.0.0.1:4500   # in one terminal
  8. codex-hooks-daemon               # in another terminal

DOCS
  See README.md or https://github.com/Da-Coder-Jr/Hooks-for-Codex
`;

async function main() {
  if (!command || command === "--help" || command === "-h") {
    console.log(HELP);
    process.exit(0);
  }

  switch (command) {
    case "init":      cmdInit(); break;
    case "list":      cmdList(); break;
    case "validate":  cmdValidate(); break;
    case "events":    cmdEvents(); break;
    case "test":      await cmdTest(); break;
    case "enable":    cmdEnable(); break;
    case "doctor":    cmdDoctor(); break;
    case "files":     cmdFiles(); break;
    default:
      console.error(`Unknown command: ${command}`);
      console.log(`Run "codex-hooks --help" for usage.`);
      process.exit(1);
  }
}

// ── Commands ────────────────────────────────────────────────────────

function cmdInit() {
  const isGlobal = args.includes("--global");
  const templateArg = args.find((a) => a.startsWith("--template="));
  const template = templateArg ? templateArg.split("=")[1] : "basic";

  const targetPath = isGlobal
    ? PATHS.globalHooks
    : path.join(process.cwd(), ".codex", "hooks.json");

  if (fs.existsSync(targetPath)) {
    console.error(`Already exists: ${targetPath}`);
    console.error('Run "codex-hooks validate" to check it, or delete it to reinitialise.');
    process.exit(1);
  }

  initConfig(targetPath, template);
  console.log(`Created: ${targetPath}  (template: ${template})`);
  console.log("");

  const { enabled } = isHooksEnabled(process.cwd());
  if (!enabled) {
    console.log('Hooks feature flag is NOT enabled yet. Run "codex-hooks enable" next.');
  } else {
    console.log("Hooks feature flag is already enabled. You're ready to go!");
  }
}

function cmdList() {
  const engine = new HooksEngine({ debug: args.includes("--debug") });
  const hooks = engine.listHooks();

  if (hooks.length === 0) {
    console.log("No hooks configured.");
    console.log('Run "codex-hooks init" to get started.');
    return;
  }

  const grouped = {};
  for (const h of hooks) {
    (grouped[h.event] = grouped[h.event] || []).push(h);
  }

  console.log(`${hooks.length} hook(s) loaded from ${engine.configFiles.length} file(s):\n`);

  for (const [event, eventHooks] of Object.entries(grouped)) {
    const tier = HookEvent[event]?.tier === HookTier.EXTENDED ? " [extended/daemon]" : " [native]";
    console.log(`  ${event}${tier}`);
    for (const h of eventHooks) {
      const matcher = (!h.matcher || h.matcher === "*") ? "(all)" : h.matcher;
      const flags = [
        h.async && "async",
        h.timeout && `${h.timeout}s`,
        h.once && "once",
      ].filter(Boolean).join(", ");
      const flagStr = flags ? ` (${flags})` : "";
      console.log(`    [${h.type}] ${matcher} → ${h.target}${flagStr}`);
    }
    console.log("");
  }
}

function cmdValidate() {
  const filePath = args[1] || path.join(process.cwd(), ".codex", "hooks.json");

  if (!fs.existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    process.exit(1);
  }

  const { valid, errors } = validateFile(filePath);
  if (valid) {
    console.log(`✓ ${filePath} — valid`);
  } else {
    console.error(`✗ ${filePath} — ${errors.length} error(s):\n`);
    for (const e of errors) console.error(`  • ${e}`);
    process.exit(1);
  }
}

function cmdEvents() {
  console.log("Available hook events:\n");
  console.log("  NATIVE events  (hooks.json, requires codex_hooks = true)");
  console.log("  ─────────────────────────────────────────────────────────\n");

  for (const name of NATIVE_EVENT_NAMES) {
    _printEvent(name);
  }

  console.log("  EXTENDED events  (codex-hooks-daemon + App Server JSON-RPC)");
  console.log("  ─────────────────────────────────────────────────────────────\n");

  for (const name of EXTENDED_EVENT_NAMES) {
    _printEvent(name);
  }
}

function _printEvent(name) {
  const e = HookEvent[name];
  const blocking = e.blocking ? "BLOCKING" : "non-blocking";
  const matcher = e.matcherField ? `matcher: ${e.matcherField}` : "no matcher";
  console.log(`  ${name}`);
  console.log(`    ${e.description}`);
  console.log(`    [${e.scope}] [${blocking}] [${matcher}]`);
  console.log("");
}

async function cmdTest() {
  const eventName = args[1];
  if (!eventName || !EVENT_NAMES.includes(eventName)) {
    console.error("Usage: codex-hooks test <EventName> [--payload=<json>]");
    console.error(`Valid events: ${EVENT_NAMES.join(", ")}`);
    process.exit(1);
  }

  const payloadArg = args.find((a) => a.startsWith("--payload="));
  let payload = {};
  if (payloadArg) {
    try {
      payload = JSON.parse(payloadArg.slice("--payload=".length));
    } catch {
      console.error("Invalid JSON in --payload");
      process.exit(1);
    }
  }

  const engine = new HooksEngine({ debug: true });
  console.log(`Firing test event: ${eventName}\n`);
  const result = await engine.fire(eventName, payload);

  console.log("Result:");
  console.log(`  blocked:    ${result.blocked}`);
  console.log(`  continue:   ${result.continue_}`);
  console.log(`  decision:   ${result.permissionDecision || "(none)"}`);
  if (result.blockReason)    console.log(`  reason:     ${result.blockReason}`);
  if (result.systemMessage)  console.log(`  sysMessage: ${result.systemMessage}`);
  if (result.outputs.length) {
    console.log(`\n  Hook output:`);
    for (const o of result.outputs) console.log(`    ${o.slice(0, 300)}`);
  }
  if (result.errors.length) {
    console.log(`\n  Errors:`);
    for (const e of result.errors) console.log(`    ${e}`);
  }
}

function cmdEnable() {
  const useGlobal = args.includes("--global") || !args.includes("--project");
  const configPath = useGlobal
    ? PATHS.globalConfig
    : path.join(process.cwd(), ".codex", "config.toml");

  const { changed, path: p } = enableHooksFeatureFlag(configPath);
  if (changed) {
    console.log(`Enabled codex_hooks = true in: ${p}`);
    console.log("Restart Codex for the change to take effect.");
  } else {
    console.log(`Already enabled in: ${p}`);
  }
}

function cmdDoctor() {
  console.log("Codex Hooks Doctor\n");
  let issues = 0;

  // 1. Check feature flag
  const { enabled, path: flagPath } = isHooksEnabled(process.cwd());
  if (enabled) {
    console.log(`  ✓ codex_hooks feature flag: enabled (${flagPath})`);
  } else {
    console.log(`  ✗ codex_hooks feature flag: NOT enabled`);
    console.log(`    Run: codex-hooks enable`);
    issues++;
  }

  // 2. Check for hooks.json files
  const files = discoverConfigFiles(process.cwd());
  if (files.length === 0) {
    console.log(`  ✗ No hooks.json files found`);
    console.log(`    Run: codex-hooks init`);
    issues++;
  } else {
    for (const f of files) {
      const { valid, errors } = validateFile(f);
      if (valid) {
        console.log(`  ✓ ${f}`);
      } else {
        console.log(`  ✗ ${f}  (${errors.length} error(s))`);
        for (const e of errors) console.log(`      • ${e}`);
        issues++;
      }
    }
  }

  // 3. Check Node.js version
  const nodeVer = parseInt(process.version.slice(1), 10);
  if (nodeVer >= 18) {
    console.log(`  ✓ Node.js ${process.version}`);
  } else {
    console.log(`  ✗ Node.js ${process.version} — version 18+ required`);
    issues++;
  }

  // 4. Check ws package (needed for daemon)
  let wsAvailable = false;
  try { require.resolve("ws"); wsAvailable = true; } catch {}
  if (wsAvailable) {
    console.log(`  ✓ 'ws' package available (daemon ready)`);
  } else {
    console.log(`  ! 'ws' package not installed — extended hooks (daemon) unavailable`);
    console.log(`    Install with: npm install ws`);
  }

  // 5. Check CODEX_HOME
  if (fs.existsSync(CODEX_HOME)) {
    console.log(`  ✓ Codex config home: ${CODEX_HOME}`);
  } else {
    console.log(`  ! Codex config home not found: ${CODEX_HOME}`);
    console.log(`    Have you installed and run Codex at least once?`);
  }

  console.log("");
  if (issues === 0) {
    console.log("  All checks passed!");
  } else {
    console.log(`  ${issues} issue(s) found. See above for fixes.`);
    process.exit(1);
  }
}

function cmdFiles() {
  const files = discoverConfigFiles(process.cwd());
  console.log("Hooks file discovery:\n");
  console.log(`  Codex config home: ${CODEX_HOME}`);
  console.log(`  Global hooks:      ${PATHS.globalHooks}  ${fs.existsSync(PATHS.globalHooks) ? "(found)" : "(not found)"}`);
  const proj = path.join(process.cwd(), ".codex", "hooks.json");
  const projLocal = path.join(process.cwd(), ".codex", "hooks.local.json");
  console.log(`  Project hooks:     ${proj}  ${fs.existsSync(proj) ? "(found)" : "(not found)"}`);
  console.log(`  Project local:     ${projLocal}  ${fs.existsSync(projLocal) ? "(found)" : "(not found)"}`);
  console.log("");
  if (files.length > 0) {
    console.log(`  Loaded (${files.length}):`);
    for (const f of files) console.log(`    ${f}`);
  } else {
    console.log("  No hooks.json files loaded.");
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
