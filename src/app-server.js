"use strict";

/**
 * app-server.js — Codex App Server JSON-RPC client
 *
 * The Codex desktop app runs an internal App Server exposing a JSON-RPC
 * 2.0 API.  The daemon connects to it via WebSocket (default port 4500).
 *
 * This module connects to the App Server and translates its server-push
 * notifications into hooks-for-codex events, firing them through the
 * HooksEngine.  This fills the gaps in the native hooks.json system:
 *
 *   Native gap                    → Extended event
 *   ─────────────────────────────────────────────────────────────────
 *   apply_patch not hooked        → PreFilePatch / PostFilePatch
 *   Command approval UI           → CommandApproval
 *   File change approval UI       → FileChangeApproval
 *   turn/started notification     → TurnStarted
 *   turn/completed notification   → TurnCompleted
 *   thread/started notification   → ThreadStarted
 *
 * References:
 *   codex-rs/app-server/README.md
 *   https://developers.openai.com/codex/app-server
 */

const net = require("net");
const { EventEmitter } = require("events");

/** WebSocket states (minimal constants, no ws dependency required) */
const WS_CONNECTING = 0;
const WS_OPEN = 1;

class AppServerClient extends EventEmitter {
  /**
   * @param {object} options
   * @param {string} [options.wsUrl]      - WebSocket URL, e.g. "ws://127.0.0.1:4500"
   * @param {string} [options.authToken]  - HMAC bearer token (if --ws-auth signed-bearer-token)
   * @param {boolean} [options.debug]
   * @param {function} [options.logger]
   */
  constructor(options = {}) {
    super();
    this.wsUrl = options.wsUrl || "ws://127.0.0.1:4500";
    this.authToken = options.authToken || null;
    this.debug = options.debug || false;
    this.logger = options.logger || (() => {});
    this._ws = null;
    this._pendingRequests = new Map();
    this._nextId = 1;
    this._connected = false;
    this._reconnectDelay = 1000;
    this._reconnectTimer = null;
    this._stopping = false;
  }

  /**
   * Connect to the App Server WebSocket endpoint.
   * Retries with exponential backoff on failure.
   */
  connect() {
    if (this._stopping) return;
    this._log(`Connecting to ${this.wsUrl}…`);

    // Dynamically require 'ws' — optional peer dependency
    let WebSocket;
    try {
      WebSocket = require("ws");
    } catch {
      this.emit("error", new Error(
        "The 'ws' package is required for the App Server daemon.\n" +
        "Install it with: npm install ws"
      ));
      return;
    }

    const headers = {};
    if (this.authToken) {
      headers["Authorization"] = `Bearer ${this.authToken}`;
    }

    const ws = new WebSocket(this.wsUrl, { headers });
    this._ws = ws;

    ws.on("open", () => {
      this._connected = true;
      this._reconnectDelay = 1000;
      this._log("Connected to Codex App Server");
      this.emit("connected");
    });

    ws.on("message", (data) => {
      this._handleMessage(data.toString());
    });

    ws.on("close", (code, reason) => {
      this._connected = false;
      this._log(`Disconnected (${code}): ${reason}`);
      this.emit("disconnected", { code, reason: reason.toString() });
      this._scheduleReconnect();
    });

    ws.on("error", (err) => {
      this._log(`WebSocket error: ${err.message}`);
      // Don't emit error if it's just a connection refused — we'll reconnect
      if (err.code !== "ECONNREFUSED") {
        this.emit("error", err);
      }
    });
  }

  /**
   * Disconnect and stop reconnecting.
   */
  disconnect() {
    this._stopping = true;
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    if (this._ws) {
      this._ws.close();
      this._ws = null;
    }
  }

  /**
   * Send a JSON-RPC request and return the result.
   * @param {string} method
   * @param {object} params
   * @returns {Promise<any>}
   */
  request(method, params = {}) {
    return new Promise((resolve, reject) => {
      if (!this._connected || !this._ws) {
        return reject(new Error("Not connected to App Server"));
      }

      const id = this._nextId++;
      const message = JSON.stringify({ jsonrpc: "2.0", id, method, params });

      this._pendingRequests.set(id, { resolve, reject });
      this._ws.send(message);

      // Timeout
      setTimeout(() => {
        if (this._pendingRequests.has(id)) {
          this._pendingRequests.delete(id);
          reject(new Error(`Request timed out: ${method}`));
        }
      }, 30000);
    });
  }

  // ── App Server methods ────────────────────────────────────────────

  /** Approve a pending command execution */
  approveCommand(itemId, threadId) {
    return this.request("item/commandExecution/approve", { itemId, threadId });
  }

  /** Deny a pending command execution */
  denyCommand(itemId, threadId, reason = "") {
    return this.request("item/commandExecution/deny", { itemId, threadId, reason });
  }

  /** Approve a pending file change */
  approveFileChange(itemId, threadId) {
    return this.request("item/fileChange/approve", { itemId, threadId });
  }

  /** Deny a pending file change */
  denyFileChange(itemId, threadId, reason = "") {
    return this.request("item/fileChange/deny", { itemId, threadId, reason });
  }

  /** Read app server config */
  readConfig() {
    return this.request("config/read", {});
  }

  /** List active threads */
  listThreads() {
    return this.request("thread/list", {});
  }

  // ── Internal ──────────────────────────────────────────────────────

  _handleMessage(raw) {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      this._log(`Invalid JSON from server: ${raw.slice(0, 100)}`);
      return;
    }

    // JSON-RPC response (to our requests)
    if (msg.id !== undefined && !msg.method) {
      const pending = this._pendingRequests.get(msg.id);
      if (pending) {
        this._pendingRequests.delete(msg.id);
        if (msg.error) {
          pending.reject(new Error(`RPC error ${msg.error.code}: ${msg.error.message}`));
        } else {
          pending.resolve(msg.result);
        }
      }
      return;
    }

    // Server-push notification
    if (msg.method) {
      this._log(`Notification: ${msg.method}`);
      this.emit("notification", msg.method, msg.params || {});
      this.emit(msg.method, msg.params || {});
    }
  }

  _scheduleReconnect() {
    if (this._stopping) return;
    this._log(`Reconnecting in ${this._reconnectDelay}ms…`);
    this._reconnectTimer = setTimeout(() => {
      this._reconnectDelay = Math.min(this._reconnectDelay * 2, 30000);
      this.connect();
    }, this._reconnectDelay);
  }

  _log(msg) {
    if (this.debug) this.logger(`[app-server] ${msg}`);
  }
}

/**
 * AppServerDaemon — subscribes to App Server notifications and fires
 * extended hooks through a HooksEngine instance.
 *
 * Usage:
 *   const daemon = new AppServerDaemon({ engine, wsUrl: "ws://127.0.0.1:4500" });
 *   daemon.start();
 */
class AppServerDaemon {
  /**
   * @param {object} options
   * @param {import('./engine').HooksEngine} options.engine
   * @param {string} [options.wsUrl]
   * @param {string} [options.authToken]
   * @param {boolean} [options.debug]
   * @param {function} [options.logger]
   */
  constructor(options) {
    this.engine = options.engine;
    this.debug = options.debug || false;
    this.logger = options.logger || console.error.bind(console);

    this.client = new AppServerClient({
      wsUrl: options.wsUrl || "ws://127.0.0.1:4500",
      authToken: options.authToken || null,
      debug: this.debug,
      logger: this.logger,
    });

    this._setupHandlers();
  }

  start() {
    this.client.connect();
    this.logger("[codex-hooks-daemon] Starting. Waiting for Codex desktop app…");
    this.logger("[codex-hooks-daemon] Make sure the Codex desktop app is open.");
  }

  stop() {
    this.client.disconnect();
  }

  _setupHandlers() {
    this.client.on("connected", () => {
      this.logger("[codex-hooks-daemon] Connected. Extended hooks are active.");
    });

    this.client.on("disconnected", () => {
      this.logger("[codex-hooks-daemon] Disconnected. Waiting to reconnect…");
    });

    // ── item/commandExecution/requestApproval ─────────────────────
    // Fires when Codex pauses for approval of a shell command.
    // We fire CommandApproval hooks and auto-approve/deny based on result.
    this.client.on("item/commandExecution/requestApproval", async (params) => {
      const { itemId, threadId, toolName, toolInput, sessionId, turnId } = params;
      this._log(`CommandApproval: ${toolName} — ${JSON.stringify(toolInput).slice(0, 80)}`);

      const result = await this.engine.fire("CommandApproval", {
        session_id: sessionId || "",
        turn_id: turnId || "",
        cwd: this.engine.projectDir,
        tool_name: toolName || "shell",
        tool_input: toolInput || {},
        item_id: itemId,
        thread_id: threadId,
      }).catch((err) => {
        this._log(`CommandApproval hook error: ${err.message}`);
        return null;
      });

      if (!result) return; // Let Codex handle it natively

      try {
        if (result.blocked) {
          await this.client.denyCommand(itemId, threadId, result.blockReason);
          this._log(`CommandApproval: DENIED — ${result.blockReason}`);
        } else if (result.permissionDecision === "deny") {
          await this.client.denyCommand(itemId, threadId, result.permissionDecisionReason);
          this._log(`CommandApproval: DENIED by hook decision`);
        }
        // For allow/defer, let Codex show its normal approval UI
      } catch (err) {
        this._log(`Failed to send approval decision: ${err.message}`);
      }
    });

    // ── item/fileChange/requestApproval ───────────────────────────
    // Fires when apply_patch is waiting for approval — the native
    // PreToolUse hook misses this entirely (issue #16732).
    this.client.on("item/fileChange/requestApproval", async (params) => {
      const { itemId, threadId, filePath, diff, sessionId, turnId } = params;
      this._log(`FileChangeApproval: ${filePath}`);

      // Pre-change hook
      const preResult = await this.engine.fire("PreFilePatch", {
        session_id: sessionId || "",
        turn_id: turnId || "",
        cwd: this.engine.projectDir,
        file_path: filePath || "",
        patch_content: diff || "",
        operation: "update",
        item_id: itemId,
        thread_id: threadId,
      }).catch((err) => {
        this._log(`PreFilePatch hook error: ${err.message}`);
        return null;
      });

      if (!preResult) return;

      try {
        if (preResult.blocked) {
          await this.client.denyFileChange(itemId, threadId, preResult.blockReason);
          this._log(`FileChangeApproval: DENIED — ${preResult.blockReason}`);
        }
        // For allow/defer, let Codex show its normal approval UI
      } catch (err) {
        this._log(`Failed to send file approval decision: ${err.message}`);
      }
    });

    // ── item/completed (post-file-patch) ──────────────────────────
    // After a file change item completes, fire PostFilePatch.
    this.client.on("item/completed", async (params) => {
      const { itemType, filePath, diff, sessionId, turnId } = params;
      if (itemType !== "fileChange") return;

      await this.engine.fire("PostFilePatch", {
        session_id: sessionId || "",
        turn_id: turnId || "",
        cwd: this.engine.projectDir,
        file_path: filePath || "",
        patch_content: diff || "",
        operation: "update",
      }).catch((err) => {
        this._log(`PostFilePatch hook error: ${err.message}`);
      });
    });

    // ── turn/started ──────────────────────────────────────────────
    this.client.on("turn/started", async (params) => {
      const { turnId, threadId } = params;
      await this.engine.fire("TurnStarted", {
        turn_id: turnId || "",
        thread_id: threadId || "",
        cwd: this.engine.projectDir,
      }).catch((err) => {
        this._log(`TurnStarted hook error: ${err.message}`);
      });
    });

    // ── turn/completed ────────────────────────────────────────────
    this.client.on("turn/completed", async (params) => {
      const { turnId, threadId, lastMessage } = params;
      await this.engine.fire("TurnCompleted", {
        turn_id: turnId || "",
        thread_id: threadId || "",
        cwd: this.engine.projectDir,
        last_message: lastMessage || "",
      }).catch((err) => {
        this._log(`TurnCompleted hook error: ${err.message}`);
      });
    });

    // ── thread/started ────────────────────────────────────────────
    this.client.on("thread/started", async (params) => {
      const { threadId } = params;
      await this.engine.fire("ThreadStarted", {
        thread_id: threadId || "",
        cwd: this.engine.projectDir,
      }).catch((err) => {
        this._log(`ThreadStarted hook error: ${err.message}`);
      });
    });
  }

  _log(msg) {
    if (this.debug) this.logger(`[codex-hooks-daemon] ${msg}`);
  }
}

module.exports = { AppServerClient, AppServerDaemon };
