"use strict";

const { spawn } = require("child_process");
const http = require("http");
const https = require("https");
const { URL } = require("url");
const { DEFAULT_TIMEOUTS } = require("./config");

/** Maximum size of hook output injected into context (characters) */
const MAX_OUTPUT_SIZE = 10000;

/**
 * Execute a single command-type hook.
 *
 * @param {object} hook     - { type: "command", command, timeout, async, shell }
 * @param {object} input    - JSON payload to send on stdin
 * @param {object} env      - Extra environment variables
 * @returns {Promise<{ exitCode: number, stdout: string, stderr: string, parsed: object|null }>}
 */
function runCommandHook(hook, input, env = {}) {
  const timeout = (hook.timeout || DEFAULT_TIMEOUTS.command) * 1000;
  const shell = hook.shell || (process.platform === "win32" ? "powershell" : "bash");

  return new Promise((resolve) => {
    const child = spawn(shell, ["-c", hook.command], {
      cwd: env.CODEX_PROJECT_DIR || process.cwd(),
      env: {
        ...process.env,
        ...env,
        CODEX_HOOKS: "1",
        CODEX_HOOK_EVENT: input.hook_event_name || "",
      },
      stdio: ["pipe", "pipe", "pipe"],
      timeout,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });
    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    // Send the input payload on stdin
    try {
      child.stdin.write(JSON.stringify(input));
      child.stdin.end();
    } catch {
      // stdin may already be closed
    }

    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      resolve({
        exitCode: -1,
        stdout: "",
        stderr: `Hook timed out after ${hook.timeout || DEFAULT_TIMEOUTS.command}s`,
        parsed: null,
      });
    }, timeout);

    child.on("close", (code) => {
      clearTimeout(timer);
      const exitCode = code ?? 1;

      // Truncate output if too large
      if (stdout.length > MAX_OUTPUT_SIZE) {
        stdout = stdout.slice(0, MAX_OUTPUT_SIZE) + "\n... [truncated]";
      }

      // Try to parse stdout as JSON
      let parsed = null;
      if (exitCode === 0 && stdout.trim()) {
        try {
          parsed = JSON.parse(stdout.trim());
        } catch {
          // Not JSON — that's fine, treat as plain text
        }
      }

      resolve({ exitCode, stdout: stdout.trim(), stderr: stderr.trim(), parsed });
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({
        exitCode: 1,
        stdout: "",
        stderr: `Failed to spawn hook: ${err.message}`,
        parsed: null,
      });
    });
  });
}

/**
 * Execute a single HTTP-type hook.
 *
 * @param {object} hook  - { type: "http", url, headers, allowedEnvVars, timeout }
 * @param {object} input - JSON payload to POST
 * @returns {Promise<{ exitCode: number, stdout: string, stderr: string, parsed: object|null }>}
 */
function runHttpHook(hook, input) {
  const timeout = (hook.timeout || DEFAULT_TIMEOUTS.http) * 1000;

  return new Promise((resolve) => {
    let url;
    try {
      url = new URL(hook.url);
    } catch {
      return resolve({
        exitCode: 1,
        stdout: "",
        stderr: `Invalid URL: ${hook.url}`,
        parsed: null,
      });
    }

    // Interpolate env vars in headers
    const headers = { "Content-Type": "application/json", ...(hook.headers || {}) };
    const allowed = new Set(hook.allowedEnvVars || []);
    for (const [key, val] of Object.entries(headers)) {
      if (typeof val === "string") {
        headers[key] = val.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (_, name) => {
          if (allowed.has(name)) {
            return process.env[name] || "";
          }
          return "";
        });
      }
    }

    const body = JSON.stringify(input);
    const lib = url.protocol === "https:" ? https : http;

    const req = lib.request(
      url,
      {
        method: "POST",
        headers: { ...headers, "Content-Length": Buffer.byteLength(body) },
        timeout,
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          const statusOk = res.statusCode >= 200 && res.statusCode < 300;
          let parsed = null;
          if (statusOk && data.trim()) {
            try {
              parsed = JSON.parse(data.trim());
            } catch {
              // plain text response
            }
          }
          resolve({
            exitCode: statusOk ? 0 : 1,
            stdout: data.trim().slice(0, MAX_OUTPUT_SIZE),
            stderr: statusOk ? "" : `HTTP ${res.statusCode}`,
            parsed,
          });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      resolve({
        exitCode: -1,
        stdout: "",
        stderr: `HTTP hook timed out after ${hook.timeout || DEFAULT_TIMEOUTS.http}s`,
        parsed: null,
      });
    });

    req.on("error", (err) => {
      resolve({
        exitCode: 1,
        stdout: "",
        stderr: `HTTP hook error: ${err.message}`,
        parsed: null,
      });
    });

    req.write(body);
    req.end();
  });
}

/**
 * Execute a single prompt-type hook (LLM evaluation stub).
 *
 * This provides the interface for prompt hooks. In a full integration,
 * this would call the OpenAI API. Here it provides a passthrough that
 * can be wired to any LLM backend.
 *
 * @param {object} hook  - { type: "prompt", prompt, model, timeout }
 * @param {object} input - JSON payload (substituted into $ARGUMENTS)
 * @param {object} [options] - { llmEvaluator: async (prompt, model) => { ok, reason } }
 * @returns {Promise<{ exitCode: number, stdout: string, stderr: string, parsed: object|null }>}
 */
async function runPromptHook(hook, input, options = {}) {
  const promptText = (hook.prompt || "").replace(/\$ARGUMENTS/g, JSON.stringify(input));
  const model = hook.model || "gpt-4o-mini";

  if (options.llmEvaluator) {
    try {
      const result = await options.llmEvaluator(promptText, model);
      const ok = result && result.ok;
      return {
        exitCode: ok ? 0 : 2,
        stdout: JSON.stringify(result),
        stderr: ok ? "" : result.reason || "LLM evaluation rejected",
        parsed: result,
      };
    } catch (err) {
      return {
        exitCode: 1,
        stdout: "",
        stderr: `Prompt hook error: ${err.message}`,
        parsed: null,
      };
    }
  }

  // No evaluator — pass through (allow)
  return {
    exitCode: 0,
    stdout: JSON.stringify({ ok: true, reason: "No LLM evaluator configured — passing through" }),
    stderr: "",
    parsed: { ok: true },
  };
}

/**
 * Run a single hook of any type.
 *
 * @param {object} hook    - Hook definition object
 * @param {object} input   - Event payload
 * @param {object} [env]   - Extra environment variables
 * @param {object} [options] - { llmEvaluator }
 * @returns {Promise<{ exitCode: number, stdout: string, stderr: string, parsed: object|null }>}
 */
async function runHook(hook, input, env = {}, options = {}) {
  switch (hook.type) {
    case "command":
      return runCommandHook(hook, input, env);
    case "http":
      return runHttpHook(hook, input);
    case "prompt":
      return runPromptHook(hook, input, options);
    default:
      return {
        exitCode: 1,
        stdout: "",
        stderr: `Unknown hook type: ${hook.type}`,
        parsed: null,
      };
  }
}

module.exports = {
  MAX_OUTPUT_SIZE,
  runCommandHook,
  runHttpHook,
  runPromptHook,
  runHook,
};
