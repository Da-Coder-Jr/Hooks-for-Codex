#!/usr/bin/env python3
"""PostToolUse and SessionStart hooks for task tracking and activity logging."""
import json
import re
import sys
import os
import time
import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import (
    HookRegistry, allow, post_tool_context, session_context,
    get_command, get_command_output, get_cwd, get_session_id, get_source
)
from _lib.utils import (
    log_event, is_test_command, is_build_command, extract_file_paths, get_git_branch
)

registry = HookRegistry()

TRACKING_DIR = os.path.expanduser("~/.codex/hooks/tracking")
SESSION_FILE_PREFIX = "session_"


def _ensure_tracking_dir():
    """Create the tracking directory if it doesn't exist."""
    os.makedirs(TRACKING_DIR, exist_ok=True)


def _session_file(session_id):
    """Get path to session tracking file."""
    _ensure_tracking_dir()
    safe_id = re.sub(r'[^\w-]', '_', session_id)
    return os.path.join(TRACKING_DIR, f"{SESSION_FILE_PREFIX}{safe_id}.json")


def _load_session_data(session_id):
    """Load session tracking data."""
    path = _session_file(session_id)
    try:
        if os.path.isfile(path):
            with open(path, "r") as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError):
        pass
    return {
        "session_id": session_id,
        "started_at": datetime.datetime.now().isoformat(),
        "commands": [],
        "files_changed": [],
        "errors": [],
        "tests": [],
        "builds": [],
        "dependencies_added": [],
        "activity_log": [],
        "last_activity": None,
        "context_switches": 0,
        "last_working_dir": "",
        "review_items": [],
    }


def _save_session_data(session_id, data):
    """Save session tracking data."""
    path = _session_file(session_id)
    _ensure_tracking_dir()
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
    except IOError:
        pass


def _timestamp():
    return datetime.datetime.now().isoformat()


@registry.hook("task_log_session_start")
def task_log_session_start(data):
    """Log session start with project context."""
    session_id = get_session_id(data)
    cwd = get_cwd(data)
    source = get_source(data)
    branch = get_git_branch(cwd)
    session_data = _load_session_data(session_id)
    session_data["started_at"] = _timestamp()
    session_data["cwd"] = cwd
    session_data["branch"] = branch
    session_data["source"] = source
    _save_session_data(session_id, session_data)
    log_event("sessions", f"START session={session_id} cwd={cwd} branch={branch} source={source}")
    project_name = os.path.basename(cwd)
    context_parts = [f"Session started for project '{project_name}'"]
    if branch:
        context_parts.append(f"on branch '{branch}'")
    context_parts.append(f"(source: {source})")
    return session_context(" ".join(context_parts))


@registry.hook("task_log_session_end")
def task_log_session_end(data):
    """Log session end with summary."""
    session_id = get_session_id(data)
    session_data = _load_session_data(session_id)
    session_data["ended_at"] = _timestamp()
    _save_session_data(session_id, session_data)
    cmd_count = len(session_data.get("commands", []))
    file_count = len(set(session_data.get("files_changed", [])))
    error_count = len(session_data.get("errors", []))
    test_count = len(session_data.get("tests", []))
    log_event("sessions", f"END session={session_id} commands={cmd_count} files={file_count} errors={error_count}")
    return post_tool_context(
        f"SESSION SUMMARY: {cmd_count} commands run, {file_count} files changed, "
        f"{test_count} test runs, {error_count} errors encountered."
    )


@registry.hook("task_track_files_changed")
def task_track_files_changed(data):
    """Track which files were modified."""
    session_id = get_session_id(data)
    command = get_command(data)
    output = get_command_output(data)
    # Detect file modifications from common commands
    file_modifying_cmds = [
        r'\b(cat|tee)\s+>\s*(\S+)',         # cat > file, tee file
        r'\b(echo|printf)\s+.*>\s*(\S+)',    # echo/printf > file
        r'\bsed\s+-i[^\s]*\s+.*\s+(\S+)',   # sed -i file
        r'\b(cp|mv)\s+\S+\s+(\S+)',         # cp/mv src dest
        r'\btouch\s+(\S+)',                  # touch file
        r'\bchmod\s+\S+\s+(\S+)',           # chmod mode file
    ]
    changed = extract_file_paths(command)
    for pattern in file_modifying_cmds:
        m = re.search(pattern, command)
        if m:
            changed.append(m.group(m.lastindex))
    # Check git diff for changes
    if re.search(r'\bgit\s+(add|commit|checkout|reset)\b', command):
        # Extract files from git output
        git_files = re.findall(r'(?:modified|new file|deleted|renamed):\s+(\S+)', output)
        changed.extend(git_files)
    if changed:
        session_data = _load_session_data(session_id)
        for f in changed:
            if f not in session_data["files_changed"]:
                session_data["files_changed"].append(f)
        _save_session_data(session_id, session_data)
    return allow()


@registry.hook("task_track_commands_run")
def task_track_commands_run(data):
    """Track command history for session."""
    session_id = get_session_id(data)
    command = get_command(data)
    if not command:
        return allow()
    session_data = _load_session_data(session_id)
    entry = {
        "timestamp": _timestamp(),
        "command": command[:500],
        "success": "error" not in get_command_output(data).lower()[:200],
    }
    session_data["commands"].append(entry)
    session_data["last_activity"] = _timestamp()
    # Keep only last 200 commands
    if len(session_data["commands"]) > 200:
        session_data["commands"] = session_data["commands"][-200:]
    _save_session_data(session_id, session_data)
    return allow()


@registry.hook("task_track_errors_encountered")
def task_track_errors_encountered(data):
    """Track errors encountered and resolutions."""
    session_id = get_session_id(data)
    command = get_command(data)
    output = get_command_output(data)
    error_patterns = [
        r'(?:Error|ERROR|error):\s*(.+?)(?:\n|$)',
        r'(?:FATAL|Fatal|fatal):\s*(.+?)(?:\n|$)',
        r'(?:Exception|exception):\s*(.+?)(?:\n|$)',
        r'(?:FAILED|Failed|failed)\s+(.+?)(?:\n|$)',
        r'(?:panic|PANIC):\s*(.+?)(?:\n|$)',
        r'Traceback \(most recent call last\)',
        r'command not found',
        r'No such file or directory',
        r'Permission denied',
    ]
    errors_found = []
    for pattern in error_patterns:
        matches = re.findall(pattern, output)
        for m in matches[:3]:
            msg = m if isinstance(m, str) else str(m)
            errors_found.append(msg.strip()[:200])
    if errors_found:
        session_data = _load_session_data(session_id)
        for err in errors_found:
            session_data["errors"].append({
                "timestamp": _timestamp(),
                "command": command[:200],
                "error": err,
            })
        # Keep only last 100 errors
        if len(session_data["errors"]) > 100:
            session_data["errors"] = session_data["errors"][-100:]
        _save_session_data(session_id, session_data)
        return post_tool_context(
            f"ERROR TRACKED: {len(errors_found)} error(s) logged for this session."
        )
    return allow()


@registry.hook("task_track_tests_run")
def task_track_tests_run(data):
    """Track test execution results."""
    command = get_command(data)
    if not is_test_command(command):
        return allow()
    session_id = get_session_id(data)
    output = get_command_output(data)
    # Parse test results from common frameworks
    result = {"timestamp": _timestamp(), "command": command[:200], "passed": 0, "failed": 0, "skipped": 0}
    # pytest format: "5 passed, 2 failed, 1 skipped"
    m = re.search(r'(\d+)\s+passed', output)
    if m:
        result["passed"] = int(m.group(1))
    m = re.search(r'(\d+)\s+failed', output)
    if m:
        result["failed"] = int(m.group(1))
    m = re.search(r'(\d+)\s+skipped', output)
    if m:
        result["skipped"] = int(m.group(1))
    # jest/mocha format: "Tests: 5 passed, 2 failed, 7 total"
    m = re.search(r'Tests?:\s*(\d+)\s+passed.*?(\d+)\s+failed', output)
    if m:
        result["passed"] = int(m.group(1))
        result["failed"] = int(m.group(2))
    # go test: "ok" or "FAIL"
    if re.search(r'^ok\s', output, re.MULTILINE):
        result["passed"] += 1
    if re.search(r'^FAIL\s', output, re.MULTILINE):
        result["failed"] += 1
    session_data = _load_session_data(session_id)
    session_data["tests"].append(result)
    _save_session_data(session_id, session_data)
    total = result["passed"] + result["failed"] + result["skipped"]
    if total > 0:
        return post_tool_context(
            f"TESTS TRACKED: {result['passed']} passed, {result['failed']} failed, "
            f"{result['skipped']} skipped (total: {total})"
        )
    return allow()


@registry.hook("task_track_builds_run")
def task_track_builds_run(data):
    """Track build results."""
    command = get_command(data)
    if not is_build_command(command):
        return allow()
    session_id = get_session_id(data)
    output = get_command_output(data)
    success = not bool(re.search(r'\b(error|failed|failure|fatal)\b', output, re.IGNORECASE))
    # Extract build time if available
    build_time = None
    m = re.search(r'(?:built?\s+in|completed?\s+in|time:?)\s+(\d+\.?\d*)\s*(?:s|ms|seconds)', output, re.IGNORECASE)
    if m:
        build_time = m.group(1) + m.group(0).split(m.group(1))[1].strip()
    result = {
        "timestamp": _timestamp(),
        "command": command[:200],
        "success": success,
        "build_time": build_time,
    }
    session_data = _load_session_data(session_id)
    session_data["builds"].append(result)
    _save_session_data(session_id, session_data)
    status = "SUCCESS" if success else "FAILURE"
    time_str = f" ({build_time})" if build_time else ""
    return post_tool_context(f"BUILD TRACKED: {status}{time_str}")


@registry.hook("task_estimate_progress")
def task_estimate_progress(data):
    """Estimate task progress from activity patterns."""
    session_id = get_session_id(data)
    session_data = _load_session_data(session_id)
    commands = session_data.get("commands", [])
    if len(commands) < 5:
        return allow()
    # Only report every 20 commands
    if len(commands) % 20 != 0:
        return allow()
    recent = commands[-20:]
    test_runs = sum(1 for c in recent if is_test_command(c.get("command", "")))
    build_runs = sum(1 for c in recent if is_build_command(c.get("command", "")))
    errors = len([c for c in recent if not c.get("success", True)])
    files = len(set(session_data.get("files_changed", [])))
    # Heuristic phase detection
    if test_runs > 5 and errors < 3:
        phase = "Testing/Validation phase - tests are mostly passing"
    elif test_runs > 3 and errors > 3:
        phase = "Debugging phase - iterating on failing tests"
    elif build_runs > 3:
        phase = "Build/Integration phase - verifying builds"
    elif errors > 5:
        phase = "Troubleshooting phase - many errors encountered"
    else:
        phase = "Development phase - writing and modifying code"
    return post_tool_context(
        f"PROGRESS ESTIMATE: {phase}. "
        f"Stats (last 20 cmds): {test_runs} test runs, {build_runs} builds, "
        f"{errors} errors. Total files touched: {files}."
    )


@registry.hook("task_generate_summary")
def task_generate_summary(data):
    """Generate session work summary."""
    session_id = get_session_id(data)
    command = get_command(data)
    # Only trigger on explicit summary requests or session end signals
    if not re.search(r'\b(summary|report|done|finish|wrap.?up)\b', command, re.IGNORECASE):
        return allow()
    session_data = _load_session_data(session_id)
    cmds = session_data.get("commands", [])
    files = list(set(session_data.get("files_changed", [])))
    errors = session_data.get("errors", [])
    tests = session_data.get("tests", [])
    builds = session_data.get("builds", [])
    parts = [f"SESSION WORK SUMMARY ({session_id}):"]
    parts.append(f"  Commands executed: {len(cmds)}")
    parts.append(f"  Files modified: {len(files)}")
    if files:
        parts.append(f"    {', '.join(files[:10])}" + (" ..." if len(files) > 10 else ""))
    parts.append(f"  Errors encountered: {len(errors)}")
    if tests:
        total_passed = sum(t.get("passed", 0) for t in tests)
        total_failed = sum(t.get("failed", 0) for t in tests)
        parts.append(f"  Test runs: {len(tests)} ({total_passed} passed, {total_failed} failed)")
    if builds:
        successful = sum(1 for b in builds if b.get("success"))
        parts.append(f"  Builds: {len(builds)} ({successful} successful)")
    return post_tool_context("\n".join(parts))


@registry.hook("task_track_time_spent")
def task_track_time_spent(data):
    """Track time spent on different activities."""
    session_id = get_session_id(data)
    command = get_command(data)
    session_data = _load_session_data(session_id)
    now = _timestamp()
    last = session_data.get("last_activity")
    if last:
        try:
            last_dt = datetime.datetime.fromisoformat(last)
            now_dt = datetime.datetime.fromisoformat(now)
            elapsed = (now_dt - last_dt).total_seconds()
            # Classify activity type
            if is_test_command(command):
                activity = "testing"
            elif is_build_command(command):
                activity = "building"
            elif re.search(r'\bgit\s', command):
                activity = "version_control"
            else:
                activity = "development"
            entry = {"activity": activity, "seconds": min(elapsed, 600)}  # Cap at 10 min per gap
            activity_log = session_data.get("activity_log", [])
            activity_log.append(entry)
            session_data["activity_log"] = activity_log[-500:]
        except (ValueError, TypeError):
            pass
    session_data["last_activity"] = now
    _save_session_data(session_id, session_data)
    return allow()


@registry.hook("task_detect_context_switch")
def task_detect_context_switch(data):
    """Detect when switching between tasks."""
    session_id = get_session_id(data)
    command = get_command(data)
    cwd = get_cwd(data)
    session_data = _load_session_data(session_id)
    last_cwd = session_data.get("last_working_dir", "")
    switched = False
    reason = ""
    # Detect directory change
    if last_cwd and cwd != last_cwd and not cwd.startswith(last_cwd) and not last_cwd.startswith(cwd):
        switched = True
        reason = f"Working directory changed from {os.path.basename(last_cwd)} to {os.path.basename(cwd)}"
    # Detect git branch switch
    if re.search(r'\bgit\s+(checkout|switch)\s+(?!-b\b)(\S+)', command):
        switched = True
        m = re.search(r'\bgit\s+(?:checkout|switch)\s+(?!-b\b)(\S+)', command)
        reason = f"Switched to branch '{m.group(1)}'" if m else "Branch switch detected"
    session_data["last_working_dir"] = cwd
    if switched:
        session_data["context_switches"] = session_data.get("context_switches", 0) + 1
        _save_session_data(session_id, session_data)
        return post_tool_context(
            f"CONTEXT SWITCH #{session_data['context_switches']}: {reason}. "
            "Note: Frequent context switches may reduce productivity."
        )
    _save_session_data(session_id, session_data)
    return allow()


@registry.hook("task_track_dependencies_added")
def task_track_dependencies_added(data):
    """Track new dependencies added."""
    session_id = get_session_id(data)
    command = get_command(data)
    deps = []
    # npm/yarn/pnpm
    m = re.search(r'\b(npm|yarn|pnpm)\s+(add|install|i)\s+(?!-)([\w@/\s.-]+)', command)
    if m:
        deps.extend(m.group(3).strip().split())
    # pip
    m = re.search(r'\bpip3?\s+install\s+(?!-r\b)([\w\s>=<.-]+)', command)
    if m:
        deps.extend(m.group(1).strip().split())
    # cargo
    m = re.search(r'\bcargo\s+add\s+([\w\s-]+)', command)
    if m:
        deps.extend(m.group(1).strip().split())
    # go
    m = re.search(r'\bgo\s+get\s+(\S+)', command)
    if m:
        deps.append(m.group(1))
    # gem
    m = re.search(r'\bgem\s+install\s+(\S+)', command)
    if m:
        deps.append(m.group(1))
    # composer
    m = re.search(r'\bcomposer\s+require\s+(\S+)', command)
    if m:
        deps.append(m.group(1))
    if deps:
        session_data = _load_session_data(session_id)
        for dep in deps:
            dep_clean = dep.strip()
            if dep_clean and not dep_clean.startswith('-'):
                session_data["dependencies_added"].append({
                    "timestamp": _timestamp(),
                    "package": dep_clean,
                    "command": command[:200],
                })
        _save_session_data(session_id, session_data)
        return post_tool_context(f"DEPENDENCY TRACKED: Added {', '.join(deps)}")
    return allow()


@registry.hook("task_track_code_metrics")
def task_track_code_metrics(data):
    """Track code metrics (lines added/removed)."""
    command = get_command(data)
    output = get_command_output(data)
    # Look for git diff stat output
    if not re.search(r'\bgit\s+(diff|log|show)\b', command):
        return allow()
    # Parse "X files changed, Y insertions(+), Z deletions(-)"
    m = re.search(r'(\d+)\s+files?\s+changed(?:,\s+(\d+)\s+insertions?\(\+\))?(?:,\s+(\d+)\s+deletions?\(-\))?', output)
    if m:
        files = int(m.group(1))
        insertions = int(m.group(2)) if m.group(2) else 0
        deletions = int(m.group(3)) if m.group(3) else 0
        session_id = get_session_id(data)
        log_event("metrics", f"session={session_id} files={files} +{insertions} -{deletions}")
        return post_tool_context(
            f"CODE METRICS: {files} files changed, +{insertions} lines, -{deletions} lines "
            f"(net: {'+' if insertions >= deletions else ''}{insertions - deletions})"
        )
    return allow()


@registry.hook("task_generate_standup")
def task_generate_standup(data):
    """Generate daily standup summary from logs."""
    session_id = get_session_id(data)
    command = get_command(data)
    # Trigger only when explicitly requested
    if not re.search(r'\b(standup|stand-up|daily)\b', command, re.IGNORECASE):
        return allow()
    # Gather all session files from today
    _ensure_tracking_dir()
    today = datetime.date.today().isoformat()
    all_commands = 0
    all_files = set()
    all_errors = 0
    all_tests_passed = 0
    all_tests_failed = 0
    all_deps = []
    try:
        for fname in os.listdir(TRACKING_DIR):
            if not fname.startswith(SESSION_FILE_PREFIX):
                continue
            fpath = os.path.join(TRACKING_DIR, fname)
            try:
                with open(fpath, "r") as f:
                    sdata = json.load(f)
                started = sdata.get("started_at", "")
                if today in started:
                    all_commands += len(sdata.get("commands", []))
                    all_files.update(sdata.get("files_changed", []))
                    all_errors += len(sdata.get("errors", []))
                    for t in sdata.get("tests", []):
                        all_tests_passed += t.get("passed", 0)
                        all_tests_failed += t.get("failed", 0)
                    all_deps.extend([d.get("package", "") for d in sdata.get("dependencies_added", [])])
            except (json.JSONDecodeError, IOError):
                continue
    except OSError:
        pass
    parts = [f"DAILY STANDUP ({today}):"]
    parts.append(f"  Commands executed: {all_commands}")
    parts.append(f"  Files touched: {len(all_files)}")
    if all_files:
        parts.append(f"    {', '.join(list(all_files)[:8])}" + (" ..." if len(all_files) > 8 else ""))
    if all_tests_passed + all_tests_failed > 0:
        parts.append(f"  Tests: {all_tests_passed} passed, {all_tests_failed} failed")
    parts.append(f"  Errors encountered: {all_errors}")
    if all_deps:
        parts.append(f"  Dependencies added: {', '.join(all_deps[:5])}")
    return post_tool_context("\n".join(parts))


@registry.hook("task_track_review_items")
def task_track_review_items(data):
    """Track items that need code review."""
    command = get_command(data)
    output = get_command_output(data)
    session_id = get_session_id(data)
    review_triggers = []
    # Detect TODO/FIXME/HACK comments in output
    todos = re.findall(r'(TODO|FIXME|HACK|XXX|REVIEW)[\s:]+(.+?)(?:\n|$)', output, re.IGNORECASE)
    for tag, msg in todos[:5]:
        review_triggers.append(f"[{tag.upper()}] {msg.strip()[:100]}")
    # Detect security-related changes
    if re.search(r'\b(auth|security|password|token|secret|permission|role)\b', command, re.IGNORECASE):
        review_triggers.append("Security-related file change - needs careful review")
    # Detect complex git operations
    if re.search(r'\bgit\s+(rebase|merge|cherry-pick)\b', command):
        review_triggers.append("Complex git operation - verify merge result")
    if review_triggers:
        session_data = _load_session_data(session_id)
        for item in review_triggers:
            session_data["review_items"].append({
                "timestamp": _timestamp(),
                "item": item,
                "command": command[:200],
            })
        # Keep only last 50
        session_data["review_items"] = session_data["review_items"][-50:]
        _save_session_data(session_id, session_data)
        return post_tool_context(
            "REVIEW ITEMS TRACKED:\n" + "\n".join(f"  - {r}" for r in review_triggers[:5])
        )
    return allow()


if __name__ == "__main__":
    registry.main()
