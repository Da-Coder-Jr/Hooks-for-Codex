#!/usr/bin/env python3
"""
UserPromptSubmit hook for the Codex desktop app.

Fires when the user submits a prompt, before it is processed.
Can BLOCK prompts or inject additionalContext.

Blocking methods:
  1. Exit code 2 + reason on stderr
  2. JSON: {"decision": "block", "reason": "..."}

Plain text on stdout is added as developer context.

What this hook does:
  - Blocks prompts that contain API keys, passwords, or tokens
  - Blocks prompts with suspicious injection patterns
  - Logs all prompts to ~/.codex/hooks/prompts.log
"""

import json
import os
import re
import sys
from datetime import datetime


LOG_FILE = os.path.expanduser("~/.codex/hooks/prompts.log")

# Patterns that suggest the user accidentally pasted secrets
SECRET_PATTERNS = [
    r"(?i)(sk-[a-zA-Z0-9]{20,})",                            # OpenAI API key
    r"(?i)(ghp_[a-zA-Z0-9]{36})",                             # GitHub personal access token
    r"(?i)(AKIA[0-9A-Z]{16})",                                # AWS access key ID
    r"(?i)(xox[bpsa]-[a-zA-Z0-9-]+)",                         # Slack token
    r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----",       # Private key
    r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9\-._]{20,}", # Generic credential
]

# Prompt injection patterns (optional, can be removed if too aggressive)
INJECTION_PATTERNS = [
    r"(?i)ignore (all )?(previous|prior|above) (instructions|prompts|rules)",
    r"(?i)disregard (your|all|any) (instructions|rules|guidelines)",
    r"(?i)you are now",
    r"(?i)new (system )?instructions?:",
    r"(?i)forget (everything|your (instructions|rules))",
]


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    prompt = data.get("prompt", "")
    session_id = data.get("session_id", "unknown")

    if not prompt:
        sys.exit(0)

    # Log the prompt
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            # Truncate long prompts in the log
            logged = prompt[:500] + ("..." if len(prompt) > 500 else "")
            f.write(f"[{timestamp}] session={session_id} prompt={logged!r}\n")
    except Exception:
        pass

    # Check for accidentally pasted secrets
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, prompt):
            output = {
                "decision": "block",
                "reason": "Your prompt appears to contain a secret or API key. Please remove it before submitting.",
            }
            print(json.dumps(output))
            return

    # Check for prompt injection attempts (optional)
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, prompt):
            output = {
                "decision": "block",
                "reason": "Prompt blocked: contains a pattern that looks like prompt injection.",
            }
            print(json.dumps(output))
            return

    # Allow the prompt (exit 0 with no output)
    sys.exit(0)


if __name__ == "__main__":
    main()
