#!/usr/bin/env node
"use strict";

/**
 * codex-hooks-daemon — extended hooks daemon for the Codex desktop app
 *
 * Connects to the Codex App Server JSON-RPC WebSocket and fires hooks
 * for events that the native hooks.json system misses:
 *
 *   • apply_patch file edits   → PreFilePatch / PostFilePatch
 *   • Command approval UI      → CommandApproval
 *   • File change approval UI  → FileChangeApproval
 *   • Turn lifecycle           → TurnStarted / TurnCompleted
 *   • Thread lifecycle         → ThreadStarted
 *
 * PREREQUISITES
 *   1. Start the Codex App Server in WebSocket mode:
 *        codex app-server --listen ws://127.0.0.1:4500
 *      (The desktop app does this automatically when running.)
 *   2. Install the ws package:
 *        npm install ws
 *
 * USAGE
 *   codex-hooks-daemon [options]
 *
 * OPTIONS
 *   --url=ws://host:port   App Server WebSocket URL (default: ws://127.0.0.1:4500)
 *   --token=<token>        Bearer token for --ws-auth signed-bearer-token mode
 *   --project=<dir>        Project directory (default: cwd)
 *   --debug                Verbose output
 *   -h, --help             This message
 */

const path = require("path");
const args = process.argv.slice(2);

if (args.includes("-h") || args.includes("--help")) {
  console.log(module.exports?.HELP || require("fs").readFileSync(__filename, "utf-8").match(/\/\*\*([\s\S]+?)\*\//)[1].replace(/^ \* ?/gm, ""));
  process.exit(0);
}

const debug = args.includes("--debug");

function getArg(name) {
  const a = args.find((a) => a.startsWith(`--${name}=`));
  return a ? a.split("=").slice(1).join("=") : null;
}

const wsUrl = getArg("url") || "ws://127.0.0.1:4500";
const authToken = getArg("token") || null;
const projectDir = getArg("project") || process.cwd();

const { HooksEngine } = require("../src/engine");
const { AppServerDaemon } = require("../src/app-server");

const logger = (msg) => {
  const ts = new Date().toISOString().replace("T", " ").replace(/\..+/, "");
  console.error(`[${ts}] ${msg}`);
};

logger("codex-hooks-daemon starting");
logger(`App Server URL: ${wsUrl}`);
logger(`Project dir:    ${projectDir}`);

const engine = new HooksEngine({
  projectDir,
  debug,
  logger,
});

const loaded = engine.listHooks();
const extendedEvents = loaded.filter((h) => {
  const { HookEvent, HookTier } = require("../src/events");
  return HookEvent[h.event]?.tier === HookTier.EXTENDED;
});

logger(`Loaded ${loaded.length} hook(s) total, ${extendedEvents.length} extended hook(s)`);

if (extendedEvents.length === 0) {
  logger("No extended hooks configured. Add PreFilePatch, PostFilePatch, CommandApproval,");
  logger("FileChangeApproval, TurnStarted, TurnCompleted, or ThreadStarted to your hooks.json.");
}

const daemon = new AppServerDaemon({
  engine,
  wsUrl,
  authToken,
  debug,
  logger,
});

daemon.start();

// Graceful shutdown
function shutdown(signal) {
  logger(`Received ${signal}, shutting down…`);
  daemon.stop();
  process.exit(0);
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// Keep alive
process.stdin.resume();
