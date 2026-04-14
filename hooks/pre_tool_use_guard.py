#!/usr/bin/env python3
"""
PreToolUse hook for the Codex desktop app.

Fires before a Bash command executes. Can BLOCK dangerous commands.

Blocking methods (any of these works):
  1. Exit code 2 + reason on stderr
  2. JSON: {"hookSpecificOutput": {"permissionDecision": "deny", ...}}
  3. JSON: {"decision": "block", "reason": "..."}

What this hook does:
  - Blocks destructive commands (rm -rf /, mkfs, dd, etc.)
  - Blocks commands that would expose secrets/credentials
  - Blocks commands that modify system files outside the project
  - Allows everything else (exit 0 with no output)
"""

import json
import re
import sys


# Patterns that indicate destructive commands
DESTRUCTIVE_PATTERNS = [
    r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(/|~|\$HOME)\b",  # rm -rf / or ~ or $HOME
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/\b",                  # rm -r /
    r"\bmkfs\b",                                              # format filesystem
    r"\bdd\s+.*\bif=.*\bof=/dev/",                           # dd to device
    r":\(\)\{\s*:\|:\s*&\s*\}\s*;",                          # fork bomb
    r"\bchmod\s+(-[a-zA-Z]*\s+)?777\s+/",                   # chmod 777 on root
    r"\bshutdown\b",
    r"\breboot\b",
    r"\binit\s+0\b",
    r"\bsystemctl\s+(halt|poweroff)\b",
    r">\s*/dev/sd[a-z]",                                      # overwrite disk
    r"\bwget\b.*\|\s*(ba)?sh",                               # pipe URL to shell
    r"\bcurl\b.*\|\s*(ba)?sh",                               # pipe URL to shell
]

# Patterns that suggest secrets in commands
SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?key)\s*=\s*['\"]?\w{10,}",
    r"(?i)(password|passwd)\s*=\s*['\"]?\S+",
    r"(?i)token\s*=\s*['\"]?\S{10,}",
    r"(?i)AWS_SECRET_ACCESS_KEY\s*=",
    r"(?i)PRIVATE[_-]?KEY",
    r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----",
    r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*",
]


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_input = data.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        sys.exit(0)

    # Check for destructive commands
    for pattern in DESTRUCTIVE_PATTERNS:
        if re.search(pattern, command):
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Blocked: potentially destructive command.",
                }
            }
            print(json.dumps(output))
            return

    # Check for secrets exposure
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, command):
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "Blocked: command may expose secrets or credentials.",
                }
            }
            print(json.dumps(output))
            return

    # Allow the command (exit 0 with no output)
    sys.exit(0)


if __name__ == "__main__":
    main()
