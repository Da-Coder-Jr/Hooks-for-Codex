#!/usr/bin/env python3
"""Auto-Continue: Smart continuation hooks for Codex. 15 Stop hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, force_continue, get_command_output
registry = HookRegistry()

@registry.hook("continue_on_test_failure")
def continue_on_test_failure(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(\d+)\s+(?:failed|failing)", output, re.IGNORECASE):
        match = re.search(r"(\d+)\s+(?:failed|failing)", output, re.IGNORECASE)
        if match and int(match.group(1)) <= 5:
            return force_continue(f"Tests had {match.group(1)} failures. Investigating and fixing...")
    return allow()

@registry.hook("continue_on_lint_errors")
def continue_on_lint_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"eslint|pylint|flake8|rubocop|clippy", output, re.IGNORECASE):
        errors = re.findall(r"(\d+)\s+errors?", output, re.IGNORECASE)
        if errors and int(errors[0]) <= 10:
            return force_continue(f"Linter found {errors[0]} errors. Auto-fixing...")
    return allow()

@registry.hook("continue_on_type_errors")
def continue_on_type_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    ts_errors = re.findall(r"TS\d+:", output)
    mypy_errors = re.findall(r"error:.*\[", output)
    if ts_errors and len(ts_errors) <= 5:
        return force_continue(f"TypeScript: {len(ts_errors)} type errors. Fixing...")
    if mypy_errors and len(mypy_errors) <= 5:
        return force_continue(f"mypy: {len(mypy_errors)} type errors. Fixing...")
    return allow()

@registry.hook("continue_on_build_failure")
def continue_on_build_failure(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"BUILD FAIL|Build error|Failed to compile|build.*failed", output, re.IGNORECASE):
        error_count = len(re.findall(r"\berror\b", output, re.IGNORECASE))
        if error_count <= 3:
            return force_continue(f"Build failed with {error_count} error(s). Diagnosing and fixing...")
    return allow()

@registry.hook("continue_on_missing_import")
def continue_on_missing_import(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Cannot find module|ModuleNotFoundError|Module not found|ImportError", output):
        match = re.search(r"(?:Cannot find module|ModuleNotFoundError|Module not found).*?['\"](\S+)['\"]", output)
        module = match.group(1) if match else "module"
        return force_continue(f"Missing module: {module}. Installing/fixing import...")
    return allow()

@registry.hook("continue_on_syntax_error")
def continue_on_syntax_error(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"SyntaxError|Unexpected token|Parse error", output):
        match = re.search(r"(?:SyntaxError|Unexpected token|Parse error).*?(?:at|in)\s+(\S+:\d+)", output)
        loc = match.group(1) if match else "file"
        return force_continue(f"Syntax error in {loc}. Fixing...")
    return allow()

@registry.hook("continue_on_formatting_issues")
def continue_on_formatting_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"prettier.*--check|Code style issues|Would reformat", output):
        files = re.findall(r"(\S+\.(?:js|ts|py|css|json))\s", output)
        if files and len(files) <= 10:
            return force_continue(f"Formatting issues in {len(files)} files. Auto-formatting...")
    return allow()

@registry.hook("continue_on_missing_dependency")
def continue_on_missing_dependency(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"ERESOLVE|peer dep.*required|Could not resolve dependencies", output):
        return force_continue("Dependency resolution issue. Attempting fix...")
    return allow()

@registry.hook("continue_on_migration_needed")
def continue_on_migration_needed(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"pending migration|unapplied migration|Migration needed|run.*migrate", output, re.IGNORECASE):
        return force_continue("Pending database migration detected. Running migration...")
    return allow()

@registry.hook("continue_on_permission_fix")
def continue_on_permission_fix(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"EACCES|Permission denied.*node_modules|permission denied.*\.cache", output):
        return force_continue("Permission issue detected. Attempting to fix...")
    return allow()

@registry.hook("continue_on_port_in_use")
def continue_on_port_in_use(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"EADDRINUSE|address already in use|port.*already.*in use", output, re.IGNORECASE):
        match = re.search(r"(?:port|:)\s*(\d+)", output)
        port = match.group(1) if match else "port"
        return force_continue(f"Port {port} in use. Finding alternative or clearing...")
    return allow()

@registry.hook("continue_on_lockfile_conflict")
def continue_on_lockfile_conflict(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"lockfile.*outdated|lock file.*not up to date|ELOCKVERIFY", output, re.IGNORECASE):
        return force_continue("Lockfile needs updating. Regenerating...")
    return allow()

@registry.hook("continue_on_env_missing")
def continue_on_env_missing(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"environment variable.*not set|env.*undefined|missing.*API_KEY|missing.*SECRET", output, re.IGNORECASE):
        match = re.search(r"(?:variable|env)\s+(\w+)\s+(?:not set|undefined|missing)", output, re.IGNORECASE)
        var = match.group(1) if match else "variable"
        return force_continue(f"Missing env variable: {var}. Checking .env configuration...")
    return allow()

@registry.hook("continue_on_git_conflict")
def continue_on_git_conflict(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"CONFLICT.*Merge conflict|Automatic merge failed", output):
        conflicts = len(re.findall(r"CONFLICT", output))
        if conflicts <= 3:
            return force_continue(f"{conflicts} merge conflict(s). Resolving...")
    return allow()

@registry.hook("continue_on_cache_clear_needed")
def continue_on_cache_clear_needed(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"stale cache|cache.*corrupt|clear.*cache|invalid cache", output, re.IGNORECASE):
        return force_continue("Cache issue detected. Clearing and retrying...")
    return allow()

if __name__ == "__main__":
    registry.main()
