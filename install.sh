#!/usr/bin/env bash
# install.sh — Set up hooks-for-codex for the OpenAI Codex desktop app
#
# This script:
#   1. Detects your OS and Codex installation
#   2. Enables the codex_hooks feature flag in config.toml
#   3. Optionally installs a starter hooks.json
#   4. Optionally installs the 'ws' package for the extended daemon
#   5. Prints next steps

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[info]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}  $*"; }
error()   { echo -e "${RED}[error]${NC} $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; }

# ── Detect OS ────────────────────────────────────────────────────────

OS="$(uname -s)"
case "$OS" in
  Darwin)  PLATFORM="macOS" ;;
  Linux)   PLATFORM="Linux" ;;
  MINGW*|MSYS*|CYGWIN*)  PLATFORM="Windows" ;;
  *)       PLATFORM="Unknown" ;;
esac

# ── Detect CODEX_HOME ────────────────────────────────────────────────

if [ -n "${CODEX_HOME:-}" ]; then
  CODEX_DIR="$CODEX_HOME"
else
  CODEX_DIR="$HOME/.codex"
fi

section "hooks-for-codex installer"
info "Platform:   $PLATFORM"
info "Codex home: $CODEX_DIR"
info "Project:    $(pwd)"
echo ""

# ── 1. Check Codex is installed ──────────────────────────────────────

section "Step 1: Checking Codex installation"

if command -v codex &>/dev/null; then
  CODEX_VERSION=$(codex --version 2>/dev/null || echo "unknown")
  ok "Codex found: $CODEX_VERSION"
else
  warn "Codex CLI not found in PATH."
  warn "The desktop app does not require the CLI, but the feature flag must"
  warn "still be set in $CODEX_DIR/config.toml"
fi

if [ -d "$CODEX_DIR" ]; then
  ok "Codex config dir exists: $CODEX_DIR"
else
  info "Creating Codex config dir: $CODEX_DIR"
  mkdir -p "$CODEX_DIR"
  ok "Created $CODEX_DIR"
fi

# ── 2. Enable the feature flag ───────────────────────────────────────

section "Step 2: Enabling codex_hooks feature flag"

CONFIG_FILE="$CODEX_DIR/config.toml"

if [ -f "$CONFIG_FILE" ]; then
  if grep -q "codex_hooks = true" "$CONFIG_FILE" 2>/dev/null; then
    ok "codex_hooks = true already set in $CONFIG_FILE"
  else
    # Add feature flag
    if grep -q "\[features\]" "$CONFIG_FILE"; then
      # Insert after [features]
      sed -i.bak 's/\[features\]/[features]\ncodex_hooks = true/' "$CONFIG_FILE"
    else
      printf '\n[features]\ncodex_hooks = true\n' >> "$CONFIG_FILE"
    fi
    ok "Added codex_hooks = true to $CONFIG_FILE"
  fi
else
  printf '[features]\ncodex_hooks = true\n' > "$CONFIG_FILE"
  ok "Created $CONFIG_FILE with codex_hooks = true"
fi

# ── 3. Optionally create a project hooks.json ────────────────────────

section "Step 3: Project hooks.json"

PROJECT_HOOKS_DIR="$(pwd)/.codex"
PROJECT_HOOKS_FILE="$PROJECT_HOOKS_DIR/hooks.json"

if [ -f "$PROJECT_HOOKS_FILE" ]; then
  ok "Project hooks.json already exists: $PROJECT_HOOKS_FILE"
else
  read -rp "Create a starter hooks.json in .codex/hooks.json? [Y/n] " ANSWER
  ANSWER="${ANSWER:-Y}"
  if [[ "$ANSWER" =~ ^[Yy] ]]; then
    mkdir -p "$PROJECT_HOOKS_DIR"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    TEMPLATE="$SCRIPT_DIR/templates/basic-hooks.json"
    if [ -f "$TEMPLATE" ]; then
      cp "$TEMPLATE" "$PROJECT_HOOKS_FILE"
    else
      cat > "$PROJECT_HOOKS_FILE" << 'JSON'
{
  "hooks": {
    "PreToolUse": [],
    "PostToolUse": [],
    "Stop": [],
    "PreFilePatch": [],
    "PostFilePatch": []
  }
}
JSON
    fi
    ok "Created $PROJECT_HOOKS_FILE"
    info "Edit this file to add your hook commands."
  else
    info "Skipped. Run 'codex-hooks init' to create one later."
  fi
fi

# ── 4. Check Node.js and install ws ─────────────────────────────────

section "Step 4: Extended daemon (optional)"

NODE_VERSION=$(node --version 2>/dev/null || echo "")
if [ -z "$NODE_VERSION" ]; then
  warn "Node.js not found. The codex-hooks-daemon requires Node.js 18+."
else
  NODE_MAJOR=$(echo "$NODE_VERSION" | sed 's/v\([0-9]*\).*/\1/')
  if [ "$NODE_MAJOR" -ge 18 ]; then
    ok "Node.js $NODE_VERSION"
  else
    warn "Node.js $NODE_VERSION found, but version 18+ is required."
  fi

  # Check for ws
  if node -e "require('ws')" &>/dev/null 2>&1; then
    ok "'ws' package already installed"
  else
    read -rp "Install 'ws' package for extended hooks (apply_patch, file change approvals)? [Y/n] " WS_ANSWER
    WS_ANSWER="${WS_ANSWER:-Y}"
    if [[ "$WS_ANSWER" =~ ^[Yy] ]]; then
      npm install ws
      ok "Installed 'ws' package"
    else
      info "Skipped. Extended hooks (daemon) won't be available without 'ws'."
    fi
  fi
fi

# ── 5. Summary ───────────────────────────────────────────────────────

section "Done! Next steps:"
echo ""
echo "  NATIVE HOOKS (hooks.json — works now):"
echo "  ─────────────────────────────────────"
echo "  • Edit $PROJECT_HOOKS_FILE"
echo "  • Restart Codex for the feature flag to take effect"
echo "  • Run 'codex-hooks list' to see loaded hooks"
echo "  • Run 'codex-hooks validate' to check for errors"
echo ""
echo "  EXTENDED HOOKS (daemon — covers apply_patch + file approvals):"
echo "  ───────────────────────────────────────────────────────────────"
echo "  • Start App Server: codex app-server --listen ws://127.0.0.1:4500"
echo "  • Start daemon:     codex-hooks-daemon"
echo "  • Add PreFilePatch, PostFilePatch, or CommandApproval rules to hooks.json"
echo ""
echo "  DOCS: https://github.com/Da-Coder-Jr/Hooks-for-Codex"
echo ""
