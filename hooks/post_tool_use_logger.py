#!/usr/bin/env python3
"""
PostToolUse hook for the Codex desktop app.

Fires after a Bash command completes. Cannot undo the command, but can:
  - Log the command and its output
  - Inject additionalContext for the model
  - Return decision: "block" to replace the tool result with feedback
  - Return continue: false to stop processing the original result

What this hook does:
  - Logs every command + exit status to ~/.codex/hooks/activity.log
  - Warns (via additionalContext) if a command modified sensitive files
"""

import json
import os
import sys
from datetime import datetime


LOG_FILE = os.path.expanduser("~/.codex/hooks/activity.log")

# File patterns worth flagging when they appear in command output
SENSITIVE_FILE_PATTERNS = [
    ".env",
    ".pem",
    ".key",
    "credentials",
    "secrets",
    "id_rsa",
    "id_ed25519",
]


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_input = data.get("tool_input", {})
    command = tool_input.get("command", "")
    tool_response = data.get("tool_response", "")
    session_id = data.get("session_id", "unknown")

    # Convert tool_response to string for inspection
    if isinstance(tool_response, dict):
        response_text = json.dumps(tool_response)
    else:
        response_text = str(tool_response) if tool_response else ""

    # Log the command
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] session={session_id} cmd={command!r}\n"

    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(log_line)
    except Exception:
        pass

    # Check if the command touched sensitive files
    warnings = []
    cmd_and_output = command + " " + response_text
    for pattern in SENSITIVE_FILE_PATTERNS:
        if pattern in cmd_and_output:
            warnings.append(f"Command may have involved sensitive file: *{pattern}*")

    if warnings:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": " | ".join(warnings),
            }
        }
        print(json.dumps(output))

    # Exit 0 with no output = success, Codex continues normally


if __name__ == "__main__":
    main()
