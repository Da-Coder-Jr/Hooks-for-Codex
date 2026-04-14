# Hooks for Codex

Ready-to-use lifecycle hooks for the [Codex desktop app](https://openai.com/codex/).

The Codex desktop app has a built-in hooks system, but it is **disabled by default** and there are no hooks included. This project gives you a set of practical Python hook scripts and a one-command installer.

> **Confirmed working in the desktop app.** The hooks engine runs in the shared Rust core (`codex-rs/core`) — the same code powers the desktop app, the VS Code extension, and the CLI. [PR #16013](https://github.com/openai/codex/pull/16013) specifically fixed hook rendering in the desktop app's UI.

---

## What you get

| Hook | Event | What it does |
|---|---|---|
| `pre_tool_use_guard.py` | PreToolUse | **Blocks** dangerous commands (`rm -rf /`, `curl\|sh`, etc.) and commands that expose secrets |
| `user_prompt_filter.py` | UserPromptSubmit | **Blocks** prompts containing API keys, passwords, or prompt injection patterns |
| `post_tool_use_logger.py` | PostToolUse | **Logs** every Bash command to `~/.codex/hooks/activity.log` |
| `session_start.py` | SessionStart | **Injects context** from `.codex/NOTES.md` and detects project type |
| `stop_continue.py` | Stop | **Auto-continues** when the agent stops with failing tests |
| `stop_notify.py` | Stop | **Desktop notification** (macOS/Linux) when the agent finishes |

---

## Install

```bash
git clone https://github.com/Da-Coder-Jr/Hooks-for-Codex
cd Hooks-for-Codex
bash install.sh
```

That's it. The installer:
1. Enables `codex_hooks = true` in `~/.codex/config.toml`
2. Copies all hook scripts to `~/.codex/hooks/`
3. Installs `hooks.json` to `~/.codex/hooks.json`

**Restart the Codex desktop app** and hooks will fire.

### Presets

```bash
bash install.sh --preset=security   # only blocking hooks (guard + filter)
bash install.sh --preset=logging    # only logging hooks (logger + context)
```

---

## How it works

The Codex desktop app reads `hooks.json` from `~/.codex/hooks.json` (global) and/or `.codex/hooks.json` (per-project). Each hook is a shell command that:

1. Receives a **JSON object on stdin** with event details
2. Writes a **JSON response on stdout** (or nothing)
3. Exits with code **0** (allow), **2** (block), or other (error)

The hooks system must be enabled with this feature flag in `~/.codex/config.toml`:

```toml
[features]
codex_hooks = true
```

### The 5 hook events

| Event | When it fires | Can block? | Matcher |
|---|---|---|---|
| **SessionStart** | Session starts or resumes | No | `source` (startup, resume) |
| **PreToolUse** | Before a Bash command runs | **Yes** | `tool_name` (currently only Bash) |
| **PostToolUse** | After a Bash command runs | No (can give feedback) | `tool_name` (currently only Bash) |
| **UserPromptSubmit** | User submits a prompt | **Yes** | Not supported |
| **Stop** | Agent finishes a turn | **Yes** (forces continue) | Not supported |

### hooks.json format

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.codex/hooks/pre_tool_use_guard.py",
            "statusMessage": "Checking command safety",
            "timeout": 600
          }
        ]
      }
    ]
  }
}
```

- `type` must be `"command"` (the only type Codex supports)
- `timeout` is in seconds (default: 600)
- `statusMessage` shows in the Codex UI while the hook runs
- `matcher` is a regex — `"Bash"` matches Bash tools, `"startup|resume"` matches either

---

## Input format (stdin)

Every hook receives JSON on stdin. Common fields:

```json
{
  "session_id": "abc123",
  "cwd": "/Users/you/project",
  "hook_event_name": "PreToolUse",
  "model": "codex-1",
  "transcript_path": "/path/to/transcript.jsonl"
}
```

### PreToolUse extra fields

```json
{
  "turn_id": "turn_xyz",
  "tool_name": "Bash",
  "tool_input": { "command": "npm test" },
  "tool_use_id": "toolu_abc"
}
```

### PostToolUse extra fields

```json
{
  "turn_id": "turn_xyz",
  "tool_name": "Bash",
  "tool_input": { "command": "npm test" },
  "tool_response": "... output ...",
  "tool_use_id": "toolu_abc"
}
```

### UserPromptSubmit extra fields

```json
{
  "turn_id": "turn_xyz",
  "prompt": "refactor the auth module"
}
```

### Stop extra fields

```json
{
  "turn_id": "turn_xyz",
  "stop_hook_active": false,
  "last_assistant_message": "I've finished the refactor..."
}
```

### SessionStart extra fields

```json
{
  "source": "startup"
}
```

---

## Output format (stdout)

### Block a command (PreToolUse)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Blocked: destructive command."
  }
}
```

Or use exit code 2 with the reason on stderr:

```python
print("Blocked: destructive command.", file=sys.stderr)
sys.exit(2)
```

### Block a prompt (UserPromptSubmit)

```json
{
  "decision": "block",
  "reason": "Prompt contains an API key."
}
```

### Force the agent to continue (Stop)

```json
{
  "decision": "block",
  "reason": "Tests are still failing. Please fix them."
}
```

> For Stop hooks, `"decision": "block"` means **continue** — your `reason` becomes the new user prompt.

> **Always check `stop_hook_active`** to prevent infinite loops.

### Add context (SessionStart, UserPromptSubmit)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "This project uses pytest for testing."
  }
}
```

Or just print plain text on stdout (for SessionStart and UserPromptSubmit only).

### Do nothing

Exit 0 with no output. Codex continues normally.

---

## Customizing

### Edit hooks

All scripts live in `~/.codex/hooks/`. Edit them directly:

```bash
open ~/.codex/hooks/pre_tool_use_guard.py     # change blocked patterns
open ~/.codex/hooks/user_prompt_filter.py      # change secret detection
open ~/.codex/hooks/stop_continue.py           # change auto-continue rules
```

### Disable a hook

Edit `~/.codex/hooks.json` and remove the hook entry, or delete the entire event block.

### Per-project hooks

Create `.codex/hooks.json` in your project root. Both global and project hooks will run (they're merged, not replaced).

### Write your own hook

Create a Python (or any language) script that:

```python
import json, sys

data = json.load(sys.stdin)       # read the event
command = data.get("tool_input", {}).get("command", "")

if "something bad" in command:
    # Block it
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "Nope.",
        }
    }))
else:
    sys.exit(0)  # allow (no output needed)
```

Add it to `hooks.json`:

```json
{
  "matcher": "Bash",
  "hooks": [{ "type": "command", "command": "python3 ~/.codex/hooks/my_hook.py" }]
}
```

---

## Known limitations

These are Codex limitations, not bugs in this project:

- **PreToolUse/PostToolUse only fire for Bash commands** — not for file edits (`apply_patch`), web search, MCP tools, or Write ([#16732](https://github.com/openai/codex/issues/16732))
- **PostToolUse doesn't fire for long-running commands** that complete via polling ([#16246](https://github.com/openai/codex/issues/16246))
- **Hooks are disabled on Windows** (temporarily)
- **`tool_name` is always `"Bash"`** — future Codex versions may emit other tool names
- The hooks system is experimental and under active development

---

## File structure

```
~/.codex/
  config.toml           <- feature flag: codex_hooks = true
  hooks.json            <- hook configuration (which scripts run when)
  hooks/
    session_start.py    <- injects project context on startup
    pre_tool_use_guard.py  <- blocks dangerous commands + secrets
    post_tool_use_logger.py <- logs all commands to activity.log
    user_prompt_filter.py  <- blocks prompts with secrets/injection
    stop_continue.py    <- auto-continues on test failures
    stop_notify.py      <- desktop notification on completion
    activity.log        <- created automatically by the logger
    prompts.log         <- created automatically by the prompt filter
```

---

## Platforms

| Platform | Supported |
|---|---|
| macOS (desktop app) | Yes |
| Windows (desktop app) | Not yet (hooks temporarily disabled on Windows) |
| Linux (community build) | Yes |
