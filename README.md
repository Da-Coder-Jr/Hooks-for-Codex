# Hooks for Codex

Lifecycle hooks for the [OpenAI Codex desktop app](https://openai.com/index/introducing-the-codex-app/) — bringing Claude Code-level hook power to Codex.

---

## What this is

The Codex app has a basic hooks system that is disabled by default and has significant gaps:

| Capability | Codex native | hooks-for-codex |
|---|---|---|
| Feature flag required | Yes | Yes (same flag) |
| `PreToolUse` / `PostToolUse` for shell commands | Yes | Yes |
| `PreToolUse` / `PostToolUse` for **apply_patch** (file edits) | **No** ([#16732](https://github.com/openai/codex/issues/16732)) | **Yes** (daemon) |
| `UserPromptSubmit` / `SessionStart` / `Stop` | Yes | Yes |
| Command approval automation | No | **Yes** (daemon) |
| File change approval automation | No | **Yes** (daemon) |
| Turn & thread lifecycle events | No | **Yes** (daemon) |
| HTTP hooks | No | **Yes** |
| LLM prompt hooks | No | **Yes** |
| Config validation CLI | No | **Yes** |
| Ready-to-use example scripts | No | **Yes** |

This project gives you **two layers** of hooks:

- **Tier 1 — Native hooks** (`hooks.json`): Works directly with the Codex runtime. Requires the `codex_hooks` feature flag. Same as what Codex has built-in, but this repo gives you tooling, validation, templates, and examples.

- **Tier 2 — Extended hooks** (`codex-hooks-daemon`): A companion daemon that connects to the Codex App Server JSON-RPC API and fires hooks for all the events the native system misses — especially `apply_patch` file edits, which is the biggest gap.

---

## Quick start

```bash
# 1. Clone / install
git clone https://github.com/Da-Coder-Jr/Hooks-for-Codex
cd Hooks-for-Codex
npm install          # installs optional 'ws' dependency for the daemon

# 2. Enable the feature flag and create a starter config
bash install.sh

# 3. Or do it manually:
codex-hooks enable   # writes codex_hooks = true to ~/.codex/config.toml
codex-hooks init     # creates .codex/hooks.json in the current project

# 4. Edit your hooks
open .codex/hooks.json

# 5. Validate and list
codex-hooks validate
codex-hooks list

# 6. Restart Codex — native hooks are now active

# 7. For extended hooks (apply_patch, approvals, turn events):
codex app-server --listen ws://127.0.0.1:4500  # in one terminal
codex-hooks-daemon                              # in another terminal
```

---

## How hooks work

Hooks are **shell commands** (or HTTP endpoints, or LLM prompts) that fire at specific points in the Codex agent loop. Each hook receives a **JSON payload on stdin** and can write a **JSON decision on stdout**.

### hooks.json structure

Place `hooks.json` next to a `config.toml` in any of these locations (all are merged, not replaced):

| Location | Scope | Committable |
|---|---|---|
| `~/.codex/hooks.json` | Global, all projects | No |
| `.codex/hooks.json` | This project | Yes |
| `.codex/hooks.local.json` | This project, private | No (gitignore it) |

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "./scripts/check-command.sh",
            "timeout": 5
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "./scripts/log-output.sh",
            "timeout": 10,
            "async": true
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "./scripts/on-stop.sh",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

---

## Hook events

### Tier 1 — Native (hooks.json)

These fire inside the Codex Rust runtime. Require `codex_hooks = true`.

| Event | When | Blocking? | Matcher field |
|---|---|---|---|
| `SessionStart` | Session begins | No | — |
| `UserPromptSubmit` | User submits a prompt | **Yes** (exit 2 = block) | — |
| `PreToolUse` | Before a shell command runs | **Yes** (exit 2 = block) | `tool_name` |
| `PostToolUse` | After a shell command completes | No | `tool_name` |
| `Stop` | Agent finishes a turn | **Yes** (exit 2 = force continue) | — |

> **Note:** `PreToolUse`/`PostToolUse` only fire for Bash/shell commands. They do **not** fire for `apply_patch` (file edits). Use Tier 2 for that.

### Tier 2 — Extended (codex-hooks-daemon)

These fire via the App Server JSON-RPC API. Require the daemon to be running.

| Event | When | Blocking? | Matcher field |
|---|---|---|---|
| `PreFilePatch` | Before apply_patch writes a file | **Yes** | `file_path` |
| `PostFilePatch` | After apply_patch writes a file | No | `file_path` |
| `CommandApproval` | When Codex pauses for command approval | **Yes** | `tool_name` |
| `FileChangeApproval` | When Codex pauses for file change approval | **Yes** | `file_path` |
| `TurnStarted` | When an agent turn begins | No | — |
| `TurnCompleted` | When an agent turn completes | No | — |
| `ThreadStarted` | When a new conversation thread is created | No | — |

---

## Hook input (stdin JSON)

Every hook receives a JSON object on stdin. All events include:

```json
{
  "session_id": "abc123",
  "cwd": "/home/user/my-project",
  "hook_event_name": "PreToolUse",
  "model": "codex-1",
  "permission_mode": "default"
}
```

Additional fields by event:

**`PreToolUse` / `PostToolUse`**
```json
{
  "turn_id": "turn_xyz",
  "tool_name": "Bash",
  "tool_input": { "command": "npm test" },
  "tool_use_id": "toolu_abc",
  "tool_response": { "exit_code": 0, "stdout": "..." }
}
```

**`UserPromptSubmit`**
```json
{
  "turn_id": "turn_xyz",
  "prompt": "refactor the auth module"
}
```

**`Stop`**
```json
{
  "turn_id": "turn_xyz",
  "stop_hook_active": false,
  "last_assistant_message": "I've finished..."
}
```

**`PreFilePatch` / `PostFilePatch`** (daemon)
```json
{
  "turn_id": "turn_xyz",
  "file_path": "src/auth.js",
  "patch_content": "--- a/src/auth.js\n+++ b/src/auth.js\n...",
  "operation": "update"
}
```

---

## Hook output (stdout JSON)

Return JSON on stdout (exit 0) to influence Codex behavior.

### Block an action (exit 2)

Write an error message to **stderr** and exit with code **2**:

```bash
echo "Blocked: dangerous command" >&2
exit 2
```

### Return a decision (stdout JSON, exit 0)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "rm -rf is not allowed"
  }
}
```

Permission decisions: `"allow"` | `"deny"` | `"ask"` | `"defer"`

### Inject a system message

```json
{
  "systemMessage": "Warning: this command modifies a production database."
}
```

### Force the agent to stop or continue

```json
{ "continue": false, "stopReason": "Security policy violation" }
```

For `Stop` hooks: exit 2 forces the agent to continue generating.
**Always check `stop_hook_active` to avoid infinite loops:**

```bash
ACTIVE=$(cat | jq -r '.stop_hook_active // false')
if [ "$ACTIVE" = "true" ]; then exit 0; fi
# ... your logic ...
```

---

## Hook types

### command (default)

Runs a shell script. Receives JSON on stdin, writes JSON on stdout.

```json
{
  "type": "command",
  "command": "./scripts/my-hook.sh",
  "timeout": 10,
  "async": false,
  "once": false
}
```

- `timeout` — seconds before the hook is killed (default: 600)
- `async` — run in background, don't block the agent
- `once` — run only once per session

### http

POSTs the event JSON to an HTTP endpoint. Useful for logging services or approval systems.

```json
{
  "type": "http",
  "url": "http://localhost:8080/hooks/pre-tool",
  "headers": { "Authorization": "Bearer $MY_TOKEN" },
  "allowedEnvVars": ["MY_TOKEN"],
  "timeout": 10
}
```

A 2xx response with JSON in the same format as command output is parsed for decisions. Non-2xx is a non-blocking error.

### prompt

Sends the event to an LLM for evaluation. Requires a `llmEvaluator` function if used programmatically, or configure your own evaluator script.

```json
{
  "type": "prompt",
  "prompt": "Is this shell command safe to run? $ARGUMENTS",
  "model": "gpt-4o-mini",
  "timeout": 30
}
```

---

## Matchers

The `matcher` field in a rule group filters which events that group handles:

| Matcher value | Behavior |
|---|---|
| `""` or `"*"` or omitted | Match all |
| `"Bash"` | Exact match |
| `"Bash\|shell"` | Either "Bash" or "shell" |
| `"^mcp__"` | Regex — any MCP tool |
| `"src/.*\\.ts$"` | Regex — any .ts file in src/ |

The `if` field adds argument-level filtering for tool events:

```json
{ "if": "Bash(rm *)", "command": "./scripts/check-rm.sh" }
{ "if": "apply_patch(*.env)", "command": "./scripts/deny-env-files.sh" }
```

---

## Example hooks

See the [`examples/`](examples/) directory:

| Script | Purpose |
|---|---|
| `block-secrets.sh` | Block shell commands that contain API keys or passwords |
| `log-activity.sh` | Log all tool use to `codex-activity.log` |
| `auto-format.sh` | Run prettier/black/rustfmt after file edits |
| `notify-completion.sh` | Desktop notification when agent stops |
| `validate-patches.sh` | Block path traversal and sensitive file writes |

Use them in your `hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "./examples/block-secrets.sh", "timeout": 5 }]
      }
    ],
    "PostToolUse": [
      {
        "hooks": [{ "type": "command", "command": "./examples/log-activity.sh", "async": true }]
      }
    ],
    "PreFilePatch": [
      {
        "hooks": [{ "type": "command", "command": "./examples/validate-patches.sh", "timeout": 5 }]
      }
    ]
  }
}
```

---

## Templates

Run `codex-hooks init --template=<name>` to start from a template:

| Template | Contents |
|---|---|
| `basic` | Empty rule groups for the most common events |
| `security` | Blocks dangerous commands, secrets exposure, and prompt injection |

---

## CLI reference

```
codex-hooks init [--global] [--template=basic|security]
codex-hooks list
codex-hooks validate [file]
codex-hooks events
codex-hooks test <EventName> [--payload=<json>]
codex-hooks enable [--global|--project]
codex-hooks doctor
codex-hooks files
```

---

## Extended daemon reference

```
codex-hooks-daemon [--url=ws://127.0.0.1:4500] [--token=<token>] [--project=<dir>] [--debug]
```

The daemon connects to the Codex App Server and fires extended hooks. Start it alongside Codex:

```bash
# Terminal 1 — start Codex with App Server
codex app-server --listen ws://127.0.0.1:4500

# Terminal 2 — start extended hooks daemon
codex-hooks-daemon --debug
```

The daemon auto-reconnects if Codex restarts.

---

## Enabling the feature flag

The native hooks system requires a feature flag in `config.toml`:

```toml
[features]
codex_hooks = true
```

**Automatic:** `codex-hooks enable` or `bash install.sh`

**Manual:** edit `~/.codex/config.toml` (global) or `.codex/config.toml` (project)

Restart Codex after changing the flag.

---

## Configuration locations

| File | Scope | Notes |
|---|---|---|
| `~/.codex/config.toml` | Global | Feature flag here |
| `~/.codex/hooks.json` | Global | Applies to all projects |
| `.codex/config.toml` | Project | Can override global |
| `.codex/hooks.json` | Project | Committable |
| `.codex/hooks.local.json` | Project private | Gitignore this |

All discovered `hooks.json` files are **merged** — later layers add rules on top of earlier ones, they don't replace them.

---

## Known Codex limitations (native system)

These are open issues in the Codex repo that the extended daemon works around:

- [#16732](https://github.com/openai/codex/issues/16732) — `apply_patch` doesn't fire `PreToolUse`/`PostToolUse` → use `PreFilePatch`/`PostFilePatch`
- [#16246](https://github.com/openai/codex/issues/16246) — `PostToolUse` missing for long-running commands → use `TurnCompleted`
- [#16226](https://github.com/openai/codex/issues/16226) — No sub-agent vs main-agent distinction in hooks
- [#15311](https://github.com/openai/codex/issues/15311) — No `PermissionRequest` hook for external UIs → use `CommandApproval`
- [#17333](https://github.com/openai/codex/issues/17333) — No `TaskCompleted` event

---

## Platform notes

| Platform | Native hooks | Extended daemon |
|---|---|---|
| macOS | Yes | Yes |
| Windows | Yes (v0.120.0+, April 2026) | Yes |
| Linux (community build) | Yes | Yes (manual App Server) |
