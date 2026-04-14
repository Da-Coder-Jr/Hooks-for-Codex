#!/usr/bin/env bash
#
# install.sh — Set up hooks for the Codex desktop app
#
# This script:
#   1. Enables the codex_hooks feature flag in ~/.codex/config.toml
#   2. Copies hook scripts to ~/.codex/hooks/
#   3. Installs hooks.json (or a preset) to ~/.codex/hooks.json
#   4. Prints next steps
#
# Usage:
#   bash install.sh                  # install all hooks
#   bash install.sh --preset=security   # install only security hooks
#   bash install.sh --preset=logging    # install only logging hooks

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[info]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}  $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
HOOKS_DIR="$CODEX_HOME/hooks"
CONFIG_FILE="$CODEX_HOME/config.toml"
HOOKS_JSON="$CODEX_HOME/hooks.json"

# Parse --preset argument
PRESET=""
for arg in "$@"; do
  case "$arg" in
    --preset=*) PRESET="${arg#--preset=}" ;;
  esac
done

section "Hooks for Codex — Installer"
info "Codex home: $CODEX_HOME"
echo ""

# ── 1. Create directories ───────────────────────────────────────────

section "Step 1: Setting up directories"

mkdir -p "$CODEX_HOME"
mkdir -p "$HOOKS_DIR"
ok "Directories ready"

# ── 2. Enable the feature flag ──────────────────────────────────────

section "Step 2: Enabling codex_hooks feature flag"

if [ -f "$CONFIG_FILE" ]; then
  if grep -q "codex_hooks = true" "$CONFIG_FILE" 2>/dev/null; then
    ok "codex_hooks = true already set"
  elif grep -q "codex_hooks" "$CONFIG_FILE" 2>/dev/null; then
    # Flag exists but is false — flip it
    if [[ "$(uname)" == "Darwin" ]]; then
      sed -i '' 's/codex_hooks = false/codex_hooks = true/' "$CONFIG_FILE"
    else
      sed -i 's/codex_hooks = false/codex_hooks = true/' "$CONFIG_FILE"
    fi
    ok "Flipped codex_hooks to true"
  elif grep -q "\[features\]" "$CONFIG_FILE" 2>/dev/null; then
    # [features] section exists, add the flag
    if [[ "$(uname)" == "Darwin" ]]; then
      sed -i '' '/\[features\]/a\
codex_hooks = true' "$CONFIG_FILE"
    else
      sed -i '/\[features\]/a codex_hooks = true' "$CONFIG_FILE"
    fi
    ok "Added codex_hooks = true under [features]"
  else
    # No [features] section — append it
    printf '\n[features]\ncodex_hooks = true\n' >> "$CONFIG_FILE"
    ok "Added [features] section with codex_hooks = true"
  fi
else
  printf '[features]\ncodex_hooks = true\n' > "$CONFIG_FILE"
  ok "Created config.toml with codex_hooks = true"
fi

# ── 3. Copy hook scripts ────────────────────────────────────────────

section "Step 3: Installing hook scripts"

SCRIPTS=(
  session_start.py
  pre_tool_use_guard.py
  post_tool_use_logger.py
  user_prompt_filter.py
  stop_continue.py
  stop_notify.py
)

for script in "${SCRIPTS[@]}"; do
  src="$SCRIPT_DIR/hooks/$script"
  dst="$HOOKS_DIR/$script"
  if [ -f "$src" ]; then
    cp "$src" "$dst"
    chmod +x "$dst"
    ok "Installed $script"
  else
    warn "Script not found: $src"
  fi
done

# ── 4. Install hooks.json ───────────────────────────────────────────

section "Step 4: Installing hooks.json"

if [ -n "$PRESET" ]; then
  PRESET_FILE="$SCRIPT_DIR/presets/$PRESET.json"
  if [ -f "$PRESET_FILE" ]; then
    cp "$PRESET_FILE" "$HOOKS_JSON"
    ok "Installed preset: $PRESET"
  else
    warn "Preset not found: $PRESET_FILE"
    warn "Available presets: security, logging"
    info "Falling back to default hooks.json"
    cp "$SCRIPT_DIR/hooks.json" "$HOOKS_JSON"
    ok "Installed default hooks.json"
  fi
else
  if [ -f "$HOOKS_JSON" ]; then
    warn "hooks.json already exists at $HOOKS_JSON"
    read -rp "Overwrite? [y/N] " ANSWER
    if [[ "$ANSWER" =~ ^[Yy] ]]; then
      cp "$SCRIPT_DIR/hooks.json" "$HOOKS_JSON"
      ok "Overwritten"
    else
      info "Kept existing hooks.json"
    fi
  else
    cp "$SCRIPT_DIR/hooks.json" "$HOOKS_JSON"
    ok "Installed hooks.json"
  fi
fi

# ── 5. Summary ──────────────────────────────────────────────────────

section "Done!"
echo ""
echo "  Installed files:"
echo "    $CONFIG_FILE         (feature flag)"
echo "    $HOOKS_JSON   (hook configuration)"
echo "    $HOOKS_DIR/             (hook scripts)"
echo ""
echo "  Next steps:"
echo "    1. Restart the Codex desktop app"
echo "    2. Open a thread and try a command — hooks will fire!"
echo "    3. Check ~/.codex/hooks/activity.log for logged commands"
echo ""
echo "  To customize:"
echo "    Edit $HOOKS_JSON to enable/disable hooks"
echo "    Edit scripts in $HOOKS_DIR/ to change behavior"
echo ""
echo "  Presets available:"
echo "    bash install.sh --preset=security   (block dangerous commands + secrets)"
echo "    bash install.sh --preset=logging    (log everything, no blocking)"
echo ""
