#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { loadConfig, validateFile, initConfig, discoverConfigFiles, GLOBAL_HOOKS_FILE } = require("../src/config");
const { HooksEngine } = require("../src/engine");
const { EVENT_NAMES, HookEvent } = require("../src/events");
const { enableHooksFeatureFlag } = require("../src/codex-adapter");

const args = process.argv.slice(2);
const command = args[0];

const HELP = `
codex-hooks - Manage hooks for OpenAI Codex CLI

USAGE
  codex-hooks <command> [options]

COMMANDS
  init [--global] [--template=basic|security]
      Initialize a hooks.json file in the current project or globally.

  list
      List all loaded hooks and their configuration.

  validate [file]
      Validate a hooks.json file for correctness.

  events
      List all available hook events and their properties.

  test <event> [--payload=<json>]
      Fire a test event and show what hooks would run and their results.

  enable
      Enable the codex_hooks feature flag in your Codex config.toml.

  doctor
      Check your hooks setup for common issues.

  files
      Show which hooks.json files are discovered and loaded.

OPTIONS
  --global          Apply to global (~/.codex/) configuration
  --template=NAME   Template to use: "basic" (default) or "security"
  --debug           Enable debug output
  --help, -h        Show this help message

EXAMPLES
  codex-hooks init                          # Create .codex/hooks.json
  codex-hooks init --global --template=security
  codex-hooks list                          # Show all active hooks
  codex-hooks validate .codex/hooks.json    # Check config for errors
  codex-hooks test PreToolUse --payload='{"tool_name":"shell","tool_input":{"command":"rm -rf /"}}'
  codex-hooks enable                        # Turn on hooks in config.toml
  codex-hooks doctor                        # Check for problems
`;

function main() {
  if (!command || command === "--help" || command === "-h") {
    console.log(HELP);
    process.exit(0);
  }

  switch (command) {
    case "init":
      cmdInit();
      break;
    case "list":
      cmdList();
      break;
    case "validate":
      cmdValidate();
      break;
    case "events":
      cmdEvents();
      break;
    case "test":
      cmdTest();
      break;
    case "enable":
      cmdEnable();
      break;
    case "doctor":
      cmdDoctor();
      break;
    case "files":
      cmdFiles();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      console.log(HELP);
      process.exit(1);
  }
}

function cmdInit() {
  const isGlobal = args.includes("--global");
  const templateArg = args.find((a) => a.startsWith("--template="));
  const template = templateArg ? templateArg.split("=")[1] : "basic";

  let targetPath;
  if (isGlobal) {
    targetPath = GLOBAL_HOOKS_FILE;
  } else {
    targetPath = path.join(process.cwd(), ".codex", "hooks.json");
  }

  if (fs.existsSync(targetPath)) {
    console.error(`File already exists: ${targetPath}`);
    console.error('Use "validate" to check it, or delete it and re-run init.');
    process.exit(1);
  }

  initConfig(targetPath, template);
  console.log(`Created ${targetPath} (template: ${template})`);
  console.log("");
  console.log('Run "codex-hooks enable" to activate hooks in your Codex config.');
}

function cmdList() {
  const engine = new HooksEngine({ debug: args.includes("--debug") });
  const hooks = engine.listHooks();

  if (hooks.length === 0) {
    console.log("No hooks configured.");
    console.log('Run "codex-hooks init" to get started.');
    return;
  }

  console.log(`Found ${hooks.length} hook(s):\n`);

  // Group by event
  const grouped = {};
  for (const h of hooks) {
    if (!grouped[h.event]) grouped[h.event] = [];
    grouped[h.event].push(h);
  }

  for (const [event, eventHooks] of Object.entries(grouped)) {
    console.log(`  ${event}:`);
    for (const h of eventHooks) {
      const matcher = h.matcher === "*" ? "(all)" : h.matcher;
      const asyncTag = h.async ? " [async]" : "";
      const timeout = h.timeout ? ` (${h.timeout}s)` : "";
      console.log(`    [${h.type}] ${matcher} -> ${h.target}${timeout}${asyncTag}`);
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
    console.log(`${filePath}: valid`);
  } else {
    console.error(`${filePath}: ${errors.length} error(s) found:\n`);
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }
}

function cmdEvents() {
  console.log("Available hook events:\n");
  const maxLen = Math.max(...EVENT_NAMES.map((n) => n.length));

  for (const name of EVENT_NAMES) {
    const e = HookEvent[name];
    const blocking = e.blocking ? "BLOCKING" : "non-blocking";
    const matcher = e.matcherField ? `matcher: ${e.matcherField}` : "no matcher";
    console.log(`  ${name.padEnd(maxLen + 2)} [${e.scope}] [${blocking}] [${matcher}]`);
    console.log(`  ${"".padEnd(maxLen + 2)} ${e.description}`);
    console.log("");
  }
}

async function cmdTest() {
  const eventName = args[1];
  if (!eventName || !EVENT_NAMES.includes(eventName)) {
    console.error(`Usage: codex-hooks test <event>`);
    console.error(`Valid events: ${EVENT_NAMES.join(", ")}`);
    process.exit(1);
  }

  const payloadArg = args.find((a) => a.startsWith("--payload="));
  let payload = {};
  if (payloadArg) {
    try {
      payload = JSON.parse(payloadArg.slice("--payload=".length));
    } catch {
      console.error("Invalid JSON payload");
      process.exit(1);
    }
  }

  const engine = new HooksEngine({ debug: true });
  console.log(`Firing test event: ${eventName}\n`);
  const result = await engine.fire(eventName, payload);

  console.log("\nResult:");
  console.log(`  blocked:    ${result.blocked}`);
  console.log(`  continue:   ${result.continue_}`);
  console.log(`  decision:   ${result.permissionDecision || "(none)"}`);
  console.log(`  outputs:    ${result.outputs.length}`);
  console.log(`  errors:     ${result.errors.length}`);

  if (result.blockReason) console.log(`  reason:     ${result.blockReason}`);
  if (result.systemMessage) console.log(`  sysMessage: ${result.systemMessage}`);
  if (result.outputs.length > 0) {
    console.log("\n  Output:");
    for (const o of result.outputs) {
      console.log(`    ${o.slice(0, 200)}`);
    }
  }
}

function cmdEnable() {
  const globalConfig = path.join(
    process.env.HOME || process.env.USERPROFILE || "~",
    ".codex",
    "config.toml"
  );
  const projectConfig = path.join(process.cwd(), ".codex", "config.toml");

  // Prefer project config if .codex dir exists, otherwise global
  const target = fs.existsSync(path.dirname(projectConfig)) ? projectConfig : globalConfig;

  enableHooksFeatureFlag(target);
  console.log(`Enabled codex_hooks feature flag in: ${target}`);
}

function cmdDoctor() {
  console.log("Codex Hooks Doctor\n");
  let issues = 0;

  // Check for hooks.json files
  const files = discoverConfigFiles();
  if (files.length === 0) {
    console.log("  [!] No hooks.json files found");
    console.log('      Run "codex-hooks init" to create one.\n');
    issues++;
  } else {
    for (const f of files) {
      const { valid, errors } = validateFile(f);
      if (valid) {
        console.log(`  [OK] ${f}`);
      } else {
        console.log(`  [!!] ${f} has ${errors.length} error(s):`);
        for (const e of errors) console.log(`        - ${e}`);
        issues++;
      }
    }
    console.log("");
  }

  // Check Codex feature flag
  const globalToml = path.join(process.env.HOME || "~", ".codex", "config.toml");
  const projectToml = path.join(process.cwd(), ".codex", "config.toml");

  let flagFound = false;
  for (const toml of [globalToml, projectToml]) {
    if (fs.existsSync(toml)) {
      const content = fs.readFileSync(toml, "utf-8");
      if (content.includes("codex_hooks = true")) {
        console.log(`  [OK] codex_hooks feature flag enabled in ${toml}`);
        flagFound = true;
      }
    }
  }
  if (!flagFound) {
    console.log("  [!] codex_hooks feature flag not found");
    console.log('      Run "codex-hooks enable" to activate hooks.\n');
    issues++;
  }

  // Check Node.js version
  const nodeVersion = parseInt(process.version.slice(1), 10);
  if (nodeVersion < 18) {
    console.log(`  [!] Node.js ${process.version} detected. Version 18+ recommended.\n`);
    issues++;
  } else {
    console.log(`  [OK] Node.js ${process.version}`);
  }

  console.log("");
  if (issues === 0) {
    console.log("  All checks passed!");
  } else {
    console.log(`  ${issues} issue(s) found.`);
  }
}

function cmdFiles() {
  const files = discoverConfigFiles();
  if (files.length === 0) {
    console.log("No hooks.json files discovered.");
    console.log("");
    console.log("Searched locations:");
    console.log(`  Global:        ${GLOBAL_HOOKS_FILE}`);
    console.log(`  Project:       ${path.join(process.cwd(), ".codex", "hooks.json")}`);
    console.log(`  Project local: ${path.join(process.cwd(), ".codex", "hooks.local.json")}`);
  } else {
    console.log(`Discovered ${files.length} hooks file(s):\n`);
    for (const f of files) {
      console.log(`  ${f}`);
    }
  }
}

main();
