#!/usr/bin/env bash
# log-activity.sh — PostToolUse hook that logs all tool executions
#
# Usage in hooks.json:
#   {
#     "matcher": "",
#     "hooks": [{ "type": "command", "command": "./examples/log-activity.sh", "timeout": 5, "async": true }]
#   }

set -euo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // "unknown"')
EVENT=$(echo "$INPUT" | jq -r '.hook_event_name // "unknown"')
CWD=$(echo "$INPUT" | jq -r '.cwd // "."')

LOG_FILE="${CODEX_PROJECT_DIR:-$CWD}/codex-activity.log"

case "$TOOL" in
  shell)
    CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""')
    EXIT_CODE=$(echo "$INPUT" | jq -r '.tool_output.exit_code // "?"')
    echo "[$(date -Iseconds)] [$EVENT] shell (exit $EXIT_CODE): $CMD" >> "$LOG_FILE"
    ;;
  apply_patch)
    FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // "unknown"')
    echo "[$(date -Iseconds)] [$EVENT] apply_patch: $FILE" >> "$LOG_FILE"
    ;;
  *)
    echo "[$(date -Iseconds)] [$EVENT] $TOOL" >> "$LOG_FILE"
    ;;
esac
