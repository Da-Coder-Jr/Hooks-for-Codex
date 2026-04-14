#!/usr/bin/env python3
"""
SessionStart hook for the Codex desktop app.

Fires when a session starts (source="startup") or resumes (source="resume").
Plain text on stdout is added as extra developer context.
JSON on stdout supports additionalContext in hookSpecificOutput.

What this hook does:
  - On startup: loads project notes from .codex/NOTES.md if it exists
  - On resume: reminds about the previous session
  - Outputs context that gets injected into the conversation
"""

import json
import os
import sys


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    source = data.get("source", "startup")
    cwd = data.get("cwd", os.getcwd())

    context_parts = []

    # Load project notes if they exist
    notes_path = os.path.join(cwd, ".codex", "NOTES.md")
    if os.path.isfile(notes_path):
        try:
            with open(notes_path, "r") as f:
                notes = f.read().strip()
            if notes:
                context_parts.append(f"Project notes:\n{notes}")
        except Exception:
            pass

    # Add session-type-specific context
    if source == "resume":
        context_parts.append("This is a resumed session. Check recent git log for what changed.")
    elif source == "startup":
        # Check for common project markers
        markers = {
            "package.json": "Node.js project",
            "Cargo.toml": "Rust project",
            "pyproject.toml": "Python project",
            "go.mod": "Go project",
            "Makefile": "Has Makefile",
        }
        detected = []
        for filename, label in markers.items():
            if os.path.isfile(os.path.join(cwd, filename)):
                detected.append(label)
        if detected:
            context_parts.append(f"Project type: {', '.join(detected)}")

    if context_parts:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": "\n\n".join(context_parts),
            }
        }
        print(json.dumps(output))
    # Exit 0 with no output = success, Codex continues


if __name__ == "__main__":
    main()
