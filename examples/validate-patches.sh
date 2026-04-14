#!/usr/bin/env bash
# validate-patches.sh — PreToolUse hook that validates file patches before applying
#
# Checks:
#   - Target file is within the project directory (no path traversal)
#   - File extension is not in the deny list (e.g., .env, .pem)
#   - File is not a binary
#
# Usage in hooks.json:
#   {
#     "matcher": "apply_patch",
#     "hooks": [{ "type": "command", "command": "./examples/validate-patches.sh", "timeout": 5 }]
#   }

set -euo pipefail

INPUT=$(cat)
FILE=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
PROJECT_DIR="${CODEX_PROJECT_DIR:-$(pwd)}"

if [ -z "$FILE" ]; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"defer"}}'
  exit 0
fi

# Resolve to absolute path
RESOLVED=$(realpath -m "$FILE" 2>/dev/null || echo "$FILE")

# Check: is the file within the project directory?
case "$RESOLVED" in
  "$PROJECT_DIR"/*)
    # OK - within project
    ;;
  *)
    echo "Path traversal blocked: $FILE resolves to $RESOLVED (outside $PROJECT_DIR)" >&2
    exit 2
    ;;
esac

# Check: deny-listed extensions
EXT="${FILE##*.}"
case "$EXT" in
  env|pem|key|p12|pfx|jks|keystore)
    echo "Modification of sensitive file type blocked: .$EXT" >&2
    exit 2
    ;;
esac

# Check: if file exists, is it binary?
if [ -f "$FILE" ]; then
  if file --mime "$FILE" 2>/dev/null | grep -q 'charset=binary'; then
    echo "Modification of binary file blocked: $FILE" >&2
    exit 2
  fi
fi

echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"defer"}}'
