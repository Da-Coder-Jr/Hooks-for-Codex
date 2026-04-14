#!/usr/bin/env bash
# auto-format.sh — PostToolUse hook that auto-formats files after edits
#
# Usage in hooks.json:
#   {
#     "matcher": "apply_patch",
#     "hooks": [{ "type": "command", "command": "./examples/auto-format.sh", "timeout": 30, "async": true }]
#   }

set -euo pipefail

INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')

if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
  exit 0
fi

EXT="${FILE##*.}"

case "$EXT" in
  js|jsx|ts|tsx|json|css|scss|md|yaml|yml)
    # Try prettier if available
    if command -v npx &>/dev/null && [ -f "node_modules/.bin/prettier" ]; then
      npx prettier --write "$FILE" 2>/dev/null || true
    fi
    ;;
  py)
    # Try black or ruff if available
    if command -v ruff &>/dev/null; then
      ruff format "$FILE" 2>/dev/null || true
    elif command -v black &>/dev/null; then
      black -q "$FILE" 2>/dev/null || true
    fi
    ;;
  rs)
    # Try rustfmt if available
    if command -v rustfmt &>/dev/null; then
      rustfmt "$FILE" 2>/dev/null || true
    fi
    ;;
  go)
    # Try gofmt if available
    if command -v gofmt &>/dev/null; then
      gofmt -w "$FILE" 2>/dev/null || true
    fi
    ;;
esac

echo "{\"systemMessage\":\"Auto-formatted: $FILE\"}"
