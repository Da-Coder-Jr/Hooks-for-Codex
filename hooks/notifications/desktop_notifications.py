#!/usr/bin/env python3
"""Stop hooks for desktop notifications using OS-native notification systems."""
import json
import re
import sys
import os
import platform
import subprocess
import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import (
    HookRegistry, allow, force_continue, get_command, get_command_output,
    get_session_id, get_cwd
)
from _lib.utils import log_event, is_test_command, is_build_command, get_git_branch

registry = HookRegistry()

TRACKING_DIR = os.path.expanduser("~/.codex/hooks/tracking")


def _notify(title, message):
    """Send a desktop notification on macOS or Linux."""
    system = platform.system()
    safe_title = str(title).replace('"', "'")[:100]
    safe_msg = str(message).replace('"', "'")[:300]
    try:
        if system == "Darwin":
            script = f'display notification "{safe_msg}" with title "{safe_title}"'
            subprocess.run(
                ["osascript", "-e", script],
                capture_output=True, timeout=5
            )
        elif system == "Linux":
            subprocess.run(
                ["notify-send", safe_title, safe_msg],
                capture_output=True, timeout=5
            )
    except Exception:
        pass


def _get_last_output(data):
    """Get last assistant message or tool output."""
    return (
        data.get("last_assistant_message", "") or
        data.get("tool_output", {}).get("stdout", "") +
        data.get("tool_output", {}).get("stderr", "")
    )


@registry.hook("notify_task_complete")
def notify_task_complete(data):
    """Notify when a long task completes."""
    output = _get_last_output(data)
    # Look for completion signals
    completion_patterns = [
        r'\b(complete|completed|done|finished|succeeded|success)\b',
        r'All \d+ tests? passed',
        r'Build succeeded',
        r'Deployment complete',
    ]
    for p in completion_patterns:
        if re.search(p, output, re.IGNORECASE):
            summary = output[:100].strip()
            _notify("Task Complete", summary)
            break
    return allow()


@registry.hook("notify_test_results")
def notify_test_results(data):
    """Notify with test results summary."""
    output = _get_last_output(data)
    # pytest format
    m = re.search(r'(\d+)\s+passed(?:.*?(\d+)\s+failed)?', output)
    if m:
        passed = m.group(1)
        failed = m.group(2) or "0"
        status = "PASS" if failed == "0" else "FAIL"
        _notify(f"Tests {status}", f"{passed} passed, {failed} failed")
        return allow()
    # jest/mocha format
    m = re.search(r'Tests?:\s*(\d+)\s+passed(?:.*?(\d+)\s+failed)?', output)
    if m:
        passed = m.group(1)
        failed = m.group(2) or "0"
        status = "PASS" if failed == "0" else "FAIL"
        _notify(f"Tests {status}", f"{passed} passed, {failed} failed")
        return allow()
    # Generic pass/fail
    if re.search(r'all tests? passed', output, re.IGNORECASE):
        _notify("Tests PASS", "All tests passed")
    elif re.search(r'tests? failed', output, re.IGNORECASE):
        _notify("Tests FAIL", "Some tests failed - check output")
    return allow()


@registry.hook("notify_build_status")
def notify_build_status(data):
    """Notify on build success/failure."""
    output = _get_last_output(data)
    if re.search(r'\b(build|compile|bundle)\s+(succeed|success|complete|done)\b', output, re.IGNORECASE):
        m = re.search(r'(?:in|time:?)\s+(\d+\.?\d*)\s*(?:s|ms|seconds)', output, re.IGNORECASE)
        time_str = f" in {m.group(1)}s" if m else ""
        _notify("Build Succeeded", f"Build completed successfully{time_str}")
    elif re.search(r'\b(build|compile|bundle)\s+(fail|error)\b', output, re.IGNORECASE):
        error_lines = re.findall(r'(?:error|Error|ERROR)[:\s]+(.+?)(?:\n|$)', output)
        msg = error_lines[0][:100] if error_lines else "Build failed - check output"
        _notify("Build Failed", msg)
    return allow()


@registry.hook("notify_error_occurred")
def notify_error_occurred(data):
    """Notify on error occurrence."""
    output = _get_last_output(data)
    # Detect fatal/critical errors
    fatal_patterns = [
        r'\b(FATAL|CRITICAL|PANIC)\b[:\s]+(.+?)(?:\n|$)',
        r'Segmentation fault',
        r'OutOfMemoryError',
        r'StackOverflowError',
        r'ENOMEM',
    ]
    for p in fatal_patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            msg = m.group(0)[:150] if m else "Critical error detected"
            _notify("Critical Error", msg)
            break
    return allow()


@registry.hook("notify_deployment_status")
def notify_deployment_status(data):
    """Notify on deployment events."""
    output = _get_last_output(data)
    deploy_patterns = [
        (r'deploy(?:ment|ed)?\s+(?:to\s+)?(\w+)?\s*(?:succeed|success|complete|done)', "success"),
        (r'deploy(?:ment|ed)?\s+(?:to\s+)?(\w+)?\s*(?:fail|error|abort)', "failure"),
        (r'published\s+to\s+(\S+)', "success"),
        (r'released?\s+(?:v[\d.]+\s+)?(?:to\s+)?(\w+)', "success"),
    ]
    for pattern, status in deploy_patterns:
        m = re.search(pattern, output, re.IGNORECASE)
        if m:
            env = m.group(1) or "unknown"
            icon = "Deployed" if status == "success" else "Deploy Failed"
            _notify(icon, f"Deployment to {env} {status}")
            break
    return allow()


@registry.hook("notify_security_alert")
def notify_security_alert(data):
    """Notify on security issues detected."""
    output = _get_last_output(data)
    security_patterns = [
        r'(\d+)\s+(?:high|critical)\s+(?:severity\s+)?vulnerabilit',
        r'security\s+(?:alert|warning|advisory)',
        r'CVE-\d{4}-\d+',
        r'\b(vulnerability|exploit|injection|xss|csrf)\b.*(?:found|detected)',
    ]
    for p in security_patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            msg = m.group(0)[:150]
            _notify("Security Alert", msg)
            break
    return allow()


@registry.hook("notify_long_running")
def notify_long_running(data):
    """Notify when command takes > 60 seconds."""
    output = _get_last_output(data)
    # Check for timing info in output
    m = re.search(r'(?:real|total|elapsed|time)\s+(?:(\d+)m)?(\d+\.?\d*)s', output)
    if m:
        minutes = int(m.group(1) or 0)
        seconds = float(m.group(2))
        total = minutes * 60 + seconds
        if total > 60:
            _notify("Long Running Command", f"Command took {minutes}m{int(seconds)}s to complete")
    return allow()


@registry.hook("notify_disk_space_low")
def notify_disk_space_low(data):
    """Notify when disk space is critically low."""
    output = _get_last_output(data)
    # Detect "No space left on device" or similar
    if re.search(r'No space left on device|ENOSPC|disk full|filesystem full', output, re.IGNORECASE):
        _notify("Disk Space Critical", "No space left on device - free up disk space immediately")
        return allow()
    # Check df output for low space
    m = re.search(r'(\d{2,3})%\s+(/\S*)', output)
    if m:
        usage = int(m.group(1))
        mount = m.group(2)
        if usage >= 95:
            _notify("Disk Space Critical", f"{mount} is {usage}% full - free up space")
        elif usage >= 90:
            _notify("Disk Space Low", f"{mount} is {usage}% full")
    return allow()


@registry.hook("notify_dependency_update")
def notify_dependency_update(data):
    """Notify when dependencies need updates."""
    output = _get_last_output(data)
    # npm outdated / yarn outdated
    m = re.search(r'(\d+)\s+packages?\s+(?:are\s+)?outdated', output, re.IGNORECASE)
    if m:
        count = m.group(1)
        _notify("Dependencies Outdated", f"{count} package(s) have available updates")
        return allow()
    # pip list --outdated
    outdated_lines = re.findall(r'^\S+\s+\S+\s+\S+\s+\S+\s*$', output, re.MULTILINE)
    if len(outdated_lines) > 3:  # Has a header + data
        _notify("Dependencies Outdated", f"{len(outdated_lines) - 2} Python package(s) can be updated")
    # cargo outdated
    if re.search(r'Name\s+Project\s+Compat\s+Latest', output):
        cargo_outdated = len(re.findall(r'^\S+\s+\S+\s+\S+\s+\S+', output, re.MULTILINE)) - 1
        if cargo_outdated > 0:
            _notify("Dependencies Outdated", f"{cargo_outdated} Rust crate(s) can be updated")
    return allow()


@registry.hook("notify_merge_conflict")
def notify_merge_conflict(data):
    """Notify about merge conflicts."""
    output = _get_last_output(data)
    if re.search(r'CONFLICT\s+\(', output) or re.search(r'merge conflict', output, re.IGNORECASE):
        conflict_files = re.findall(r'CONFLICT.*?:\s+(?:Merge conflict in\s+)?(\S+)', output)
        count = len(conflict_files) if conflict_files else "Unknown number of"
        _notify("Merge Conflict", f"{count} file(s) have merge conflicts that need resolution")
    return allow()


@registry.hook("notify_test_coverage_drop")
def notify_test_coverage_drop(data):
    """Notify when coverage drops."""
    output = _get_last_output(data)
    # Parse coverage percentage
    m = re.search(r'(?:total|overall|statements?)\s*(?:coverage)?[:\s]+(\d+\.?\d*)%', output, re.IGNORECASE)
    if m:
        coverage = float(m.group(1))
        if coverage < 50:
            _notify("Coverage Low", f"Test coverage is only {coverage:.1f}% - consider adding tests")
        elif coverage < 70:
            _notify("Coverage Notice", f"Test coverage at {coverage:.1f}%")
    # Detect coverage decrease
    m = re.search(r'coverage\s+(?:decreased|dropped|fell)\s+(?:by\s+)?(\d+\.?\d*)%', output, re.IGNORECASE)
    if m:
        drop = m.group(1)
        _notify("Coverage Drop", f"Test coverage decreased by {drop}%")
    return allow()


@registry.hook("notify_lint_errors")
def notify_lint_errors(data):
    """Notify about new lint errors."""
    output = _get_last_output(data)
    # ESLint format: "X problems (Y errors, Z warnings)"
    m = re.search(r'(\d+)\s+problems?\s+\((\d+)\s+errors?,\s*(\d+)\s+warnings?\)', output)
    if m:
        errors = int(m.group(2))
        warnings = int(m.group(3))
        if errors > 0:
            _notify("Lint Errors", f"{errors} error(s), {warnings} warning(s) found")
        return allow()
    # pylint/flake8 error count
    error_lines = re.findall(r'^\S+:\d+:\d+:\s+[EF]\d+', output, re.MULTILINE)
    if len(error_lines) > 0:
        _notify("Lint Errors", f"{len(error_lines)} lint error(s) found")
    return allow()


@registry.hook("notify_session_idle")
def notify_session_idle(data):
    """Notify after long idle period."""
    session_id = get_session_id(data)
    os.makedirs(TRACKING_DIR, exist_ok=True)
    state_file = os.path.join(TRACKING_DIR, f"idle_{session_id}.json")
    now = datetime.datetime.now()
    try:
        if os.path.isfile(state_file):
            with open(state_file, "r") as f:
                state = json.load(f)
            last_time = datetime.datetime.fromisoformat(state.get("last_activity", now.isoformat()))
            idle_seconds = (now - last_time).total_seconds()
            if idle_seconds > 1800:  # 30 minutes
                _notify("Session Idle", f"Session idle for {int(idle_seconds // 60)} minutes")
    except (json.JSONDecodeError, IOError, ValueError):
        pass
    # Update last activity
    try:
        with open(state_file, "w") as f:
            json.dump({"last_activity": now.isoformat()}, f)
    except IOError:
        pass
    return allow()


@registry.hook("notify_git_push_needed")
def notify_git_push_needed(data):
    """Notify about unpushed commits."""
    output = _get_last_output(data)
    cwd = get_cwd(data)
    # Only check after git commit
    if re.search(r'\bgit\s+commit\b', output) or re.search(r'^\[[\w/-]+\s+[a-f0-9]+\]', output, re.MULTILINE):
        try:
            result = subprocess.run(
                ["git", "log", "--oneline", "@{u}..HEAD"],
                cwd=cwd, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                count = len(result.stdout.strip().split("\n"))
                if count >= 5:
                    _notify("Push Needed", f"{count} commits ahead of remote - remember to push")
        except Exception:
            pass
    return allow()


@registry.hook("notify_review_requested")
def notify_review_requested(data):
    """Notify when PR review is needed."""
    output = _get_last_output(data)
    # Detect PR creation or review request
    if re.search(r'pull request.*created|review requested|assigned.*review', output, re.IGNORECASE):
        pr_url = re.search(r'https://github\.com/\S+/pull/\d+', output)
        url_str = f" - {pr_url.group(0)}" if pr_url else ""
        _notify("Review Requested", f"Pull request needs review{url_str}")
    # Also detect gh/hub CLI output
    if re.search(r'created pull request|Requesting a code review', output, re.IGNORECASE):
        _notify("PR Created", "Don't forget to request reviewers")
    return allow()


if __name__ == "__main__":
    registry.main()
