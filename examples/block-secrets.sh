#!/usr/bin/env bash
# block-secrets.sh — PreToolUse hook that blocks commands containing secrets
#
# Usage in hooks.json:
#   {
#     "matcher": "shell",
#     "hooks": [{ "type": "command", "command": "./examples/block-secrets.sh", "timeout": 5 }]
#   }

set -euo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""')

# Patterns that suggest secrets or credentials in commands
SECRET_PATTERNS=(
  'api[_-]?key\s*='
  'secret\s*='
  'password\s*='
  'token\s*='
  'credential'
  'AWS_SECRET'
  'PRIVATE_KEY'
  'BEGIN RSA'
  'BEGIN OPENSSH'
)

for pattern in "${SECRET_PATTERNS[@]}"; do
  if echo "$CMD" | grep -qEi "$pattern"; then
    echo "Command appears to contain or expose secrets (matched: $pattern)" >&2
    exit 2
  fi
done

# Allow the command to proceed
echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"defer"}}'
