#!/usr/bin/env bash
# notify-completion.sh — Stop hook that sends a desktop notification
#
# Usage in hooks.json:
#   {
#     "matcher": "",
#     "hooks": [{ "type": "command", "command": "./examples/notify-completion.sh", "timeout": 5 }]
#   }

set -euo pipefail

INPUT=$(cat)
ACTIVE=$(echo "$INPUT" | jq -r '.stop_hook_active // false')

# Prevent infinite loop: if this hook already caused a continuation, let it stop
if [ "$ACTIVE" = "true" ]; then
  exit 0
fi

TITLE="Codex Agent Complete"
MESSAGE="The Codex agent has finished its task."

# macOS
if command -v osascript &>/dev/null; then
  osascript -e "display notification \"$MESSAGE\" with title \"$TITLE\"" 2>/dev/null || true
# Linux with notify-send
elif command -v notify-send &>/dev/null; then
  notify-send "$TITLE" "$MESSAGE" 2>/dev/null || true
# Windows (WSL)
elif command -v powershell.exe &>/dev/null; then
  powershell.exe -Command "[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); \$notification = New-Object System.Windows.Forms.NotifyIcon; \$notification.BalloonTipTitle = '$TITLE'; \$notification.BalloonTipText = '$MESSAGE'; \$notification.Visible = \$true; \$notification.ShowBalloonTip(3000)" 2>/dev/null || true
fi
