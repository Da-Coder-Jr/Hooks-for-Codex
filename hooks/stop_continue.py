#!/usr/bin/env python3
"""
Stop hook for the Codex desktop app — auto-continue on test failures.

Fires when the agent finishes a turn. Can force Codex to continue.

For Stop, "decision": "block" means CONTINUE (not reject). It tells Codex
to keep going and uses your reason as the new user prompt.

IMPORTANT: Always check stop_hook_active to prevent infinite loops.
If stop_hook_active is True, this Stop was triggered by a previous
continuation — let it finish.

What this hook does:
  - If the last message mentions failing tests, forces Codex to continue
  - Prevents infinite loops via stop_hook_active check
"""

import json
import re
import sys


# Patterns in the assistant's last message that suggest unfinished work
CONTINUE_PATTERNS = [
    r"(?i)(\d+)\s+(?:tests?\s+)?fail(?:ed|ing|ure)",
    r"(?i)error:.*(?:compilation|build)\s+failed",
    r"(?i)FAIL(?:ED)?\s+",
    r"(?i)npm\s+ERR!",
    r"(?i)exit\s+code\s+[1-9]",
]

# What to tell Codex when we force it to continue
CONTINUE_REASON = (
    "The previous output shows test failures or errors. "
    "Please fix them and run the tests again."
)


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    # CRITICAL: prevent infinite loops
    stop_hook_active = data.get("stop_hook_active", False)
    if stop_hook_active:
        # This turn was already continued by a Stop hook — let it finish
        sys.exit(0)

    last_message = data.get("last_assistant_message") or ""

    if not last_message:
        sys.exit(0)

    # Check if the last message indicates failures
    for pattern in CONTINUE_PATTERNS:
        if re.search(pattern, last_message):
            # Force Codex to continue
            output = {
                "decision": "block",
                "reason": CONTINUE_REASON,
            }
            print(json.dumps(output))
            return

    # Let the agent stop normally (exit 0 with no output)
    sys.exit(0)


if __name__ == "__main__":
    main()
