#!/usr/bin/env bash
#
# install.sh — Set up hooks for the Codex desktop app
#
# This script:
#   1. Enables the codex_hooks feature flag in ~/.codex/config.toml
#   2. Copies 1100+ hook scripts (20 categories) to ~/.codex/hooks/
#   3. Installs hooks.json to ~/.codex/hooks.json
#   4. Verifies the installation
#
# Usage:
#   bash install.sh                     # install all hooks
#   bash install.sh --preset=security   # install only security hooks
#   bash install.sh --preset=logging    # install only logging hooks
#   bash install.sh --dry-run           # show what would be installed

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[info]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}  $*"; }
error()   { echo -e "${RED}[err]${NC}   $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
HOOKS_DIR="$CODEX_HOME/hooks"
CONFIG_FILE="$CODEX_HOME/config.toml"
HOOKS_JSON="$CODEX_HOME/hooks.json"

# Parse arguments
PRESET=""
DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --preset=*) PRESET="${arg#--preset=}" ;;
    --dry-run)  DRY_RUN=true ;;
  esac
done

# Hook categories (directories under hooks/)
CATEGORIES=(
  _lib
  security
  code_quality
  languages
  frameworks
  git
  devops
  testing
  documentation
  performance
  monitoring
  database
  api
  project
  notifications
  environment
  dependencies
  accessibility
  error_handling
  session
  auto_continue
)

section "Hooks for Codex — Installer"
info "Codex home: $CODEX_HOME"
info "Source:     $SCRIPT_DIR"
echo ""

# Count hooks
TOTAL_HOOKS=$(grep -rh '@registry.hook' "$SCRIPT_DIR/hooks/" --include="*.py" 2>/dev/null | wc -l | tr -d '[:space:]')
TOTAL_FILES=$(find "$SCRIPT_DIR/hooks" -name "*.py" -not -path "*__pycache__*" -not -name "__init__.py" | wc -l | tr -d '[:space:]')
info "Hooks: $TOTAL_HOOKS across $TOTAL_FILES files in ${#CATEGORIES[@]} categories"
echo ""

if $DRY_RUN; then
  warn "DRY RUN — no files will be modified"
  echo ""
fi

# ── 1. Create directories ───────────────────────────────────────────

section "Step 1: Setting up directories"

if ! $DRY_RUN; then
  mkdir -p "$CODEX_HOME"
  mkdir -p "$HOOKS_DIR"
  for cat in "${CATEGORIES[@]}"; do
    mkdir -p "$HOOKS_DIR/$cat"
  done
  ok "Created ${#CATEGORIES[@]} category directories"
else
  info "Would create ${#CATEGORIES[@]} category directories under $HOOKS_DIR/"
fi

# ── 2. Enable the feature flag ──────────────────────────────────────

section "Step 2: Enabling codex_hooks feature flag"

if ! $DRY_RUN; then
  if [ -f "$CONFIG_FILE" ]; then
    if grep -q "codex_hooks = true" "$CONFIG_FILE" 2>/dev/null; then
      ok "codex_hooks = true already set"
    elif grep -q "codex_hooks" "$CONFIG_FILE" 2>/dev/null; then
      if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' 's/codex_hooks = false/codex_hooks = true/' "$CONFIG_FILE"
      else
        sed -i 's/codex_hooks = false/codex_hooks = true/' "$CONFIG_FILE"
      fi
      ok "Flipped codex_hooks to true"
    elif grep -q "\[features\]" "$CONFIG_FILE" 2>/dev/null; then
      if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' '/\[features\]/a\
codex_hooks = true' "$CONFIG_FILE"
      else
        sed -i '/\[features\]/a codex_hooks = true' "$CONFIG_FILE"
      fi
      ok "Added codex_hooks = true under [features]"
    else
      printf '\n[features]\ncodex_hooks = true\n' >> "$CONFIG_FILE"
      ok "Added [features] section with codex_hooks = true"
    fi
  else
    printf '[features]\ncodex_hooks = true\n' > "$CONFIG_FILE"
    ok "Created config.toml with codex_hooks = true"
  fi
else
  info "Would enable codex_hooks = true in $CONFIG_FILE"
fi

# ── 3. Copy hook modules ───────────────────────────────────────────

section "Step 3: Installing hook modules"

INSTALLED_FILES=0
INSTALLED_HOOKS=0

for cat in "${CATEGORIES[@]}"; do
  src_dir="$SCRIPT_DIR/hooks/$cat"
  dst_dir="$HOOKS_DIR/$cat"
  if [ ! -d "$src_dir" ]; then
    continue
  fi

  file_count=0
  hook_count=0

  for src_file in "$src_dir"/*.py; do
    [ -f "$src_file" ] || continue
    filename=$(basename "$src_file")

    if ! $DRY_RUN; then
      cp "$src_file" "$dst_dir/$filename"
      chmod +x "$dst_dir/$filename"
    fi

    file_count=$((file_count + 1))
    hooks_in_file=$(grep -c '@registry.hook' "$src_file" 2>/dev/null) || hooks_in_file=0
    hook_count=$((hook_count + hooks_in_file))
  done

  INSTALLED_FILES=$((INSTALLED_FILES + file_count))
  INSTALLED_HOOKS=$((INSTALLED_HOOKS + hook_count))

  if [ $file_count -gt 0 ]; then
    if $DRY_RUN; then
      info "Would install $cat/ ($file_count files, $hook_count hooks)"
    else
      ok "Installed $cat/ ($file_count files, $hook_count hooks)"
    fi
  fi
done

# Also copy legacy root-level hook scripts
for script in session_start.py pre_tool_use_guard.py post_tool_use_logger.py user_prompt_filter.py stop_continue.py stop_notify.py; do
  src="$SCRIPT_DIR/hooks/$script"
  if [ -f "$src" ]; then
    if ! $DRY_RUN; then
      cp "$src" "$HOOKS_DIR/$script"
      chmod +x "$HOOKS_DIR/$script"
    fi
    INSTALLED_FILES=$((INSTALLED_FILES + 1))
  fi
done

echo ""
if $DRY_RUN; then
  info "Would install $INSTALLED_FILES files containing $INSTALLED_HOOKS hooks"
else
  ok "Installed $INSTALLED_FILES files containing $INSTALLED_HOOKS hooks"
fi

# ── 4. Install hooks.json ───────────────────────────────────────────

section "Step 4: Installing hooks.json"

if ! $DRY_RUN; then
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
else
  info "Would install hooks.json to $HOOKS_JSON"
fi

# ── 5. Verify installation ─────────────────────────────────────────

if ! $DRY_RUN; then
  section "Step 5: Verifying installation"

  # Test that Python can import the base module
  if PYTHONPATH="$HOOKS_DIR" python3 -c "from _lib.base import HookRegistry" 2>/dev/null; then
    ok "Base library imports successfully"
  else
    error "Failed to import base library"
  fi

  # Test dispatcher
  if echo '{}' | python3 "$HOOKS_DIR/_lib/dispatcher.py" PreToolUse >/dev/null 2>&1; then
    ok "Dispatcher runs correctly"
  else
    error "Dispatcher failed — check Python 3 installation"
  fi
fi

# ── 6. Summary ──────────────────────────────────────────────────────

section "Done!"
echo ""
echo "  Installed:"
echo "    $INSTALLED_HOOKS hooks across $INSTALLED_FILES files"
echo "    ${#CATEGORIES[@]} categories: security, code quality, languages,"
echo "      frameworks, git, devops, testing, docs, performance,"
echo "      monitoring, database, API, dependencies, accessibility,"
echo "      error handling, session management, auto-continue"
echo ""
echo "  Files:"
echo "    $CONFIG_FILE         (feature flag)"
echo "    $HOOKS_JSON   (hook dispatcher config)"
echo "    $HOOKS_DIR/             (hook modules)"
echo ""
echo "  Next steps:"
echo "    1. Restart the Codex desktop app"
echo "    2. Open a thread and try a command — hooks will fire!"
echo "    3. All 1100+ hooks run automatically via the dispatcher"
echo ""
echo "  To customize:"
echo "    Edit $HOOKS_JSON to enable/disable event types"
echo "    Edit scripts in $HOOKS_DIR/<category>/ for specific hooks"
echo "    Use --dry-run to preview changes before installing"
echo ""
