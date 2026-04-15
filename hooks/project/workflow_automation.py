#!/usr/bin/env python3
"""Hooks for workflow automation - reminders, suggestions, and activity detection."""
import json
import re
import sys
import os
import datetime
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import (
    HookRegistry, allow, post_tool_context, session_context,
    get_command, get_command_output, get_cwd, get_session_id
)
from _lib.utils import (
    log_event, is_test_command, is_build_command, is_lint_command,
    get_git_branch, get_git_modified_files, extract_file_paths
)

registry = HookRegistry()

TRACKING_DIR = os.path.expanduser("~/.codex/hooks/tracking")
WORKFLOW_STATE_FILE = os.path.join(TRACKING_DIR, "workflow_state.json")


def _load_workflow_state(session_id):
    """Load workflow state for the session."""
    os.makedirs(TRACKING_DIR, exist_ok=True)
    try:
        if os.path.isfile(WORKFLOW_STATE_FILE):
            with open(WORKFLOW_STATE_FILE, "r") as f:
                states = json.load(f)
                return states.get(session_id, {})
    except (json.JSONDecodeError, IOError):
        pass
    return {}


def _save_workflow_state(session_id, state):
    """Save workflow state for the session."""
    os.makedirs(TRACKING_DIR, exist_ok=True)
    try:
        all_states = {}
        if os.path.isfile(WORKFLOW_STATE_FILE):
            with open(WORKFLOW_STATE_FILE, "r") as f:
                all_states = json.load(f)
        all_states[session_id] = state
        # Keep only last 20 sessions
        if len(all_states) > 20:
            keys = sorted(all_states.keys())
            for k in keys[:-20]:
                del all_states[k]
        with open(WORKFLOW_STATE_FILE, "w") as f:
            json.dump(all_states, f, indent=2, default=str)
    except (IOError, json.JSONDecodeError):
        pass


def _get_file_extension(filepath):
    """Get file extension."""
    _, ext = os.path.splitext(filepath)
    return ext.lower()


def _count_uncommitted_changes(cwd):
    """Count uncommitted changes in git."""
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            lines = [l for l in result.stdout.strip().split("\n") if l.strip()]
            return len(lines)
    except Exception:
        pass
    return 0


def _count_unpushed_commits(cwd):
    """Count commits ahead of remote."""
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "@{u}..HEAD"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return len(result.stdout.strip().split("\n"))
    except Exception:
        pass
    return 0


@registry.hook("workflow_auto_format_on_save")
def workflow_auto_format_on_save(data):
    """Suggest auto-formatting after file edits."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    # Detect file write/edit operations
    files = extract_file_paths(command)
    if not files and not re.search(r'\b(write|edit|create|patch|sed|awk)\b', command, re.IGNORECASE):
        return allow()
    # Check file types and suggest formatters
    suggestions = {}
    for f in files:
        ext = _get_file_extension(f)
        if ext in ('.py',):
            suggestions['python'] = "Run 'black' or 'ruff format' to auto-format Python files"
        elif ext in ('.js', '.jsx', '.ts', '.tsx', '.css', '.json', '.html'):
            suggestions['js'] = "Run 'prettier --write' to auto-format"
        elif ext in ('.rs',):
            suggestions['rust'] = "Run 'cargo fmt' to auto-format Rust files"
        elif ext in ('.go',):
            suggestions['go'] = "Run 'gofmt -w' or 'goimports -w' to auto-format Go files"
        elif ext in ('.rb',):
            suggestions['ruby'] = "Run 'rubocop -a' to auto-format Ruby files"
    if suggestions and not is_lint_command(command):
        return post_tool_context(
            "FORMAT SUGGESTION: " + "; ".join(suggestions.values())
        )
    return allow()


@registry.hook("workflow_auto_lint_on_change")
def workflow_auto_lint_on_change(data):
    """Suggest linting after code changes."""
    command = get_command(data)
    session_id = get_session_id(data)
    cwd = get_cwd(data)
    if is_lint_command(command) or is_test_command(command):
        return allow()
    state = _load_workflow_state(session_id)
    changes_since_lint = state.get("changes_since_lint", 0) + 1
    state["changes_since_lint"] = changes_since_lint
    # Only suggest every 10 changes
    if changes_since_lint >= 10 and changes_since_lint % 10 == 0:
        files = extract_file_paths(command)
        exts = set(_get_file_extension(f) for f in files)
        linter = "your linter"
        if '.py' in exts:
            linter = "ruff/flake8/pylint"
        elif exts & {'.js', '.ts', '.jsx', '.tsx'}:
            linter = "eslint"
        elif '.rs' in exts:
            linter = "cargo clippy"
        elif '.go' in exts:
            linter = "golangci-lint"
        _save_workflow_state(session_id, state)
        return post_tool_context(
            f"LINT REMINDER: {changes_since_lint} changes since last lint. "
            f"Consider running {linter} to catch issues early."
        )
    _save_workflow_state(session_id, state)
    return allow()


@registry.hook("workflow_auto_test_on_change")
def workflow_auto_test_on_change(data):
    """Suggest running affected tests after changes."""
    command = get_command(data)
    output = get_command_output(data)
    if is_test_command(command):
        return allow()
    files = extract_file_paths(command)
    # Check if modified files have corresponding test files
    test_files = []
    for f in files:
        basename = os.path.basename(f)
        name, ext = os.path.splitext(basename)
        if ext in ('.py', '.js', '.ts', '.jsx', '.tsx', '.rb', '.go', '.rs'):
            # Common test file patterns
            test_patterns = [
                f"test_{name}{ext}",
                f"{name}_test{ext}",
                f"{name}.test{ext}",
                f"{name}.spec{ext}",
                f"{name}_spec{ext}",
            ]
            test_files.extend(test_patterns)
    if test_files:
        return post_tool_context(
            f"TEST SUGGESTION: Source files were modified. Consider running related tests: "
            f"{', '.join(test_files[:3])}"
        )
    return allow()


@registry.hook("workflow_auto_build_check")
def workflow_auto_build_check(data):
    """Suggest build verification after changes."""
    command = get_command(data)
    session_id = get_session_id(data)
    if is_build_command(command):
        state = _load_workflow_state(session_id)
        state["last_build"] = datetime.datetime.now().isoformat()
        state["changes_since_build"] = 0
        _save_workflow_state(session_id, state)
        return allow()
    state = _load_workflow_state(session_id)
    changes = state.get("changes_since_build", 0) + 1
    state["changes_since_build"] = changes
    _save_workflow_state(session_id, state)
    # Suggest build every 15 file changes
    if changes == 15:
        return post_tool_context(
            "BUILD SUGGESTION: 15 changes since last build. "
            "Consider running a build to catch compilation/bundling errors early."
        )
    return allow()


@registry.hook("workflow_auto_type_check")
def workflow_auto_type_check(data):
    """Suggest type checking after TypeScript/Python changes."""
    command = get_command(data)
    output = get_command_output(data)
    files = extract_file_paths(command)
    ts_files = [f for f in files if _get_file_extension(f) in ('.ts', '.tsx')]
    py_files = [f for f in files if _get_file_extension(f) == '.py']
    # Don't suggest if already type checking
    if re.search(r'\b(tsc|mypy|pyright|pytype)\b', command):
        return allow()
    if ts_files:
        return post_tool_context(
            f"TYPE CHECK: {len(ts_files)} TypeScript file(s) modified. "
            "Consider running 'tsc --noEmit' to check for type errors."
        )
    elif py_files and len(py_files) >= 3:
        return post_tool_context(
            f"TYPE CHECK: {len(py_files)} Python file(s) modified. "
            "Consider running 'mypy' or 'pyright' to check type annotations."
        )
    return allow()


@registry.hook("workflow_remind_commit")
def workflow_remind_commit(data):
    """Remind to commit after significant changes."""
    command = get_command(data)
    session_id = get_session_id(data)
    cwd = get_cwd(data)
    if re.search(r'\bgit\s+commit\b', command):
        state = _load_workflow_state(session_id)
        state["changes_since_commit"] = 0
        state["last_commit"] = datetime.datetime.now().isoformat()
        _save_workflow_state(session_id, state)
        return allow()
    state = _load_workflow_state(session_id)
    changes = state.get("changes_since_commit", 0) + 1
    state["changes_since_commit"] = changes
    _save_workflow_state(session_id, state)
    if changes == 20:
        uncommitted = _count_uncommitted_changes(cwd)
        if uncommitted > 0:
            return post_tool_context(
                f"COMMIT REMINDER: {uncommitted} uncommitted change(s) and {changes} commands since last commit. "
                "Consider committing your work to avoid losing changes."
            )
    return allow()


@registry.hook("workflow_remind_push")
def workflow_remind_push(data):
    """Remind to push after multiple local commits."""
    command = get_command(data)
    cwd = get_cwd(data)
    if not re.search(r'\bgit\s+commit\b', command):
        return allow()
    unpushed = _count_unpushed_commits(cwd)
    if unpushed >= 3:
        branch = get_git_branch(cwd)
        return post_tool_context(
            f"PUSH REMINDER: {unpushed} unpushed commit(s) on branch '{branch}'. "
            "Consider pushing to keep your remote backup up to date."
        )
    return allow()


@registry.hook("workflow_remind_pr")
def workflow_remind_pr(data):
    """Remind to create PR after pushing feature branch."""
    command = get_command(data)
    cwd = get_cwd(data)
    if not re.search(r'\bgit\s+push\b', command):
        return allow()
    branch = get_git_branch(cwd)
    if branch and branch not in ('main', 'master', 'develop', 'dev', 'staging'):
        return post_tool_context(
            f"PR REMINDER: Pushed to feature branch '{branch}'. "
            "Consider creating a pull request for code review."
        )
    return allow()


@registry.hook("workflow_remind_docs")
def workflow_remind_docs(data):
    """Remind to update docs after API changes."""
    command = get_command(data)
    output = get_command_output(data)
    files = extract_file_paths(command)
    api_files = [f for f in files if re.search(r'(route|controller|endpoint|handler|api|schema|openapi)', f, re.IGNORECASE)]
    if api_files:
        return post_tool_context(
            f"DOCS REMINDER: API-related file(s) modified ({', '.join(os.path.basename(f) for f in api_files[:3])}). "
            "Remember to update API documentation (README, OpenAPI spec, Swagger) if endpoints changed."
        )
    return allow()


@registry.hook("workflow_remind_changelog")
def workflow_remind_changelog(data):
    """Remind to update changelog after features/fixes."""
    command = get_command(data)
    output = get_command_output(data)
    # Trigger on git commit with feature/fix messages
    if not re.search(r'\bgit\s+commit\b', command):
        return allow()
    commit_msg = ""
    m = re.search(r'-m\s+["\'](.+?)["\']', command)
    if m:
        commit_msg = m.group(1).lower()
    if re.search(r'\b(feat|fix|breaking|deprecat)\b', commit_msg):
        return post_tool_context(
            "CHANGELOG REMINDER: Feature/fix commit detected. "
            "Update CHANGELOG.md if this project maintains one."
        )
    return allow()


@registry.hook("workflow_suggest_code_review")
def workflow_suggest_code_review(data):
    """Suggest code review for complex changes."""
    command = get_command(data)
    output = get_command_output(data)
    # Look for git diff stats showing large changes
    m = re.search(r'(\d+)\s+files?\s+changed.*?(\d+)\s+insertions?.*?(\d+)\s+deletions?', output)
    if m:
        files = int(m.group(1))
        insertions = int(m.group(2))
        deletions = int(m.group(3))
        total_changes = insertions + deletions
        if files >= 10 or total_changes >= 500:
            return post_tool_context(
                f"CODE REVIEW SUGGESTION: Large change detected ({files} files, "
                f"+{insertions}/-{deletions} lines). "
                "Changes of this size benefit from a thorough code review. "
                "Consider breaking into smaller, reviewable commits."
            )
    return allow()


@registry.hook("workflow_suggest_pair_programming")
def workflow_suggest_pair_programming(data):
    """Suggest pairing for difficult problems."""
    session_id = get_session_id(data)
    output = get_command_output(data)
    command = get_command(data)
    state = _load_workflow_state(session_id)
    # Track consecutive errors on similar commands
    if re.search(r'\b(error|Error|ERROR|failed|FAILED)\b', output):
        recent_errors = state.get("recent_errors", [])
        recent_errors.append({
            "time": datetime.datetime.now().isoformat(),
            "command": command[:100],
        })
        # Keep only errors from last 10 minutes
        cutoff = datetime.datetime.now() - datetime.timedelta(minutes=10)
        recent_errors = [
            e for e in recent_errors
            if datetime.datetime.fromisoformat(e["time"]) > cutoff
        ]
        state["recent_errors"] = recent_errors
        _save_workflow_state(session_id, state)
        if len(recent_errors) >= 8:
            state["recent_errors"] = []
            _save_workflow_state(session_id, state)
            return post_tool_context(
                f"PAIRING SUGGESTION: {len(recent_errors)} errors in the last 10 minutes. "
                "A fresh pair of eyes might help solve this problem faster. "
                "Consider asking a colleague for help or rubber-duck debugging."
            )
    else:
        state["recent_errors"] = state.get("recent_errors", [])
        _save_workflow_state(session_id, state)
    return allow()


@registry.hook("workflow_detect_yak_shaving")
def workflow_detect_yak_shaving(data):
    """Detect when deviating from original task."""
    session_id = get_session_id(data)
    command = get_command(data)
    state = _load_workflow_state(session_id)
    # Track tool/dependency installation chains
    install_patterns = [
        r'\b(npm|yarn|pnpm)\s+(install|add)\b',
        r'\bpip3?\s+install\b',
        r'\bbrew\s+install\b',
        r'\bapt(-get)?\s+install\b',
        r'\bcargo\s+install\b',
        r'\bgem\s+install\b',
    ]
    is_install = any(re.search(p, command) for p in install_patterns)
    if is_install:
        install_chain = state.get("install_chain", 0) + 1
        state["install_chain"] = install_chain
        _save_workflow_state(session_id, state)
        if install_chain >= 4:
            state["install_chain"] = 0
            _save_workflow_state(session_id, state)
            return post_tool_context(
                f"YAK SHAVING ALERT: {install_chain} consecutive dependency installations. "
                "You may be going down a rabbit hole of installing dependencies for dependencies. "
                "Consider whether there's a simpler approach to the original task."
            )
    else:
        if state.get("install_chain", 0) > 0:
            state["install_chain"] = 0
            _save_workflow_state(session_id, state)
    return allow()


@registry.hook("workflow_suggest_break")
def workflow_suggest_break(data):
    """Suggest taking a break after long sessions."""
    session_id = get_session_id(data)
    state = _load_workflow_state(session_id)
    now = datetime.datetime.now()
    session_start = state.get("session_start_time")
    last_break_reminder = state.get("last_break_reminder")
    if not session_start:
        state["session_start_time"] = now.isoformat()
        state["command_count"] = 0
        _save_workflow_state(session_id, state)
        return allow()
    state["command_count"] = state.get("command_count", 0) + 1
    try:
        start = datetime.datetime.fromisoformat(session_start)
        elapsed_minutes = (now - start).total_seconds() / 60
        # Remind every 90 minutes
        if elapsed_minutes >= 90:
            if last_break_reminder:
                last = datetime.datetime.fromisoformat(last_break_reminder)
                if (now - last).total_seconds() < 5400:  # 90 min
                    _save_workflow_state(session_id, state)
                    return allow()
            state["last_break_reminder"] = now.isoformat()
            _save_workflow_state(session_id, state)
            hours = int(elapsed_minutes // 60)
            mins = int(elapsed_minutes % 60)
            return post_tool_context(
                f"BREAK SUGGESTION: You've been working for {hours}h{mins}m with "
                f"{state.get('command_count', 0)} commands. "
                "Consider taking a short break to rest your eyes and clear your mind."
            )
    except (ValueError, TypeError):
        pass
    _save_workflow_state(session_id, state)
    return allow()


@registry.hook("workflow_generate_report")
def workflow_generate_report(data):
    """Generate end-of-day activity report."""
    command = get_command(data)
    if not re.search(r'\b(report|eod|end.of.day|wrap.?up)\b', command, re.IGNORECASE):
        return allow()
    cwd = get_cwd(data)
    session_id = get_session_id(data)
    state = _load_workflow_state(session_id)
    now = datetime.datetime.now()
    branch = get_git_branch(cwd)
    uncommitted = _count_uncommitted_changes(cwd)
    unpushed = _count_unpushed_commits(cwd)
    parts = [f"END-OF-DAY REPORT ({now.strftime('%Y-%m-%d %H:%M')}):"]
    parts.append(f"  Branch: {branch or 'N/A'}")
    parts.append(f"  Commands this session: {state.get('command_count', 0)}")
    parts.append(f"  Uncommitted changes: {uncommitted}")
    parts.append(f"  Unpushed commits: {unpushed}")
    if state.get("changes_since_lint", 0) > 0:
        parts.append(f"  Changes since last lint: {state['changes_since_lint']}")
    if state.get("changes_since_build", 0) > 0:
        parts.append(f"  Changes since last build: {state['changes_since_build']}")
    if uncommitted > 0:
        parts.append("  ACTION NEEDED: Commit your uncommitted changes")
    if unpushed > 0:
        parts.append("  ACTION NEEDED: Push your local commits")
    return post_tool_context("\n".join(parts))


if __name__ == "__main__":
    registry.main()
