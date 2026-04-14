#!/usr/bin/env python3
"""
Stop hook for the Codex desktop app — desktop notification.

Fires when the agent finishes a turn. Sends a desktop notification
so you know the agent is done while you're in another window.

Supports:
  - macOS (osascript)
  - Linux (notify-send)

This hook does NOT block or force continuation — it just notifies.
"""

import json
import os
import platform
import subprocess
import sys


def notify(title, message):
    """Send a desktop notification on macOS or Linux."""
    system = platform.system()

    try:
        if system == "Darwin":
            # macOS
            script = f'display notification "{message}" with title "{title}"'
            subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                timeout=5,
            )
        elif system == "Linux":
            # Linux with notify-send (libnotify)
            subprocess.run(
                ["notify-send", title, message],
                capture_output=True,
                timeout=5,
            )
    except Exception:
        pass


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    # Don't notify on continuation turns
    stop_hook_active = data.get("stop_hook_active", False)
    if stop_hook_active:
        sys.exit(0)

    last_message = data.get("last_assistant_message") or ""

    # Build a short summary for the notification
    if last_message:
        summary = last_message[:120].replace('"', "'")
        if len(last_message) > 120:
            summary += "..."
    else:
        summary = "The agent has finished its turn."

    notify("Codex", summary)

    # Exit 0 with no output — don't interfere with the agent
    sys.exit(0)


if __name__ == "__main__":
    main()
