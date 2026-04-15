#!/usr/bin/env python3
"""Language-Specific: Go hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("go_parse_compiler_errors")
def go_parse_compiler_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgo\s+(build|run|install)\b", cmd) or not output: return allow()
    errors = re.findall(r"\.go:\d+:\d+:.*$", output, re.MULTILINE)
    if errors:
        return post_tool_context(f"Go: {len(errors)} compiler errors")
    return allow()

@registry.hook("go_detect_vet_issues")
def go_detect_vet_issues(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgo\s+vet\b", cmd) or not output: return allow()
    issues = len(re.findall(r"\.go:\d+:\d+:", output))
    return post_tool_context(f"Go vet: {issues} issues") if issues else allow()

@registry.hook("go_check_unused_imports")
def go_check_unused_imports(data):
    output = get_command_output(data)
    if not output: return allow()
    unused = re.findall(r'"(\S+)" imported and not used', output)
    if unused:
        return post_tool_context(f"Go: Unused imports: {', '.join(unused[:5])}")
    return allow()

@registry.hook("go_detect_race_conditions")
def go_detect_race_conditions(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"DATA RACE|WARNING: DATA RACE", output):
        races = len(re.findall(r"DATA RACE", output))
        return post_tool_context(f"Go: {races} data races detected! Fix with mutexes, channels, or atomic operations.")
    return allow()

@registry.hook("go_check_error_handling")
def go_check_error_handling(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Error return value.*not checked|err.*not checked", output):
        return post_tool_context("Go: Unchecked error return values detected. Always check errors.")
    return allow()

@registry.hook("go_detect_goroutine_leaks")
def go_detect_goroutine_leaks(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"goroutine leak|too many goroutines|goroutine.*running\s+\d{4,}", output):
        return post_tool_context("Go: Goroutine leak detected. Ensure goroutines have exit conditions.")
    return allow()

@registry.hook("go_check_nil_pointer")
def go_check_nil_pointer(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"nil pointer dereference|invalid memory address", output):
        return post_tool_context("Go: Nil pointer dereference. Add nil checks before accessing pointers.")
    return allow()

@registry.hook("go_detect_deadlocks")
def go_detect_deadlocks(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"all goroutines are asleep.*deadlock|fatal error.*deadlock", output):
        return post_tool_context("Go: Deadlock detected! Review channel operations and mutex locking order.")
    return allow()

@registry.hook("go_check_mod_tidy")
def go_check_mod_tidy(data):
    cmd, output = get_command(data), get_command_output(data)
    if re.search(r"\bgo\s+(get|install)\b", cmd):
        return post_tool_context("Go: After adding dependencies, run 'go mod tidy' to clean up go.mod/go.sum.")
    return allow()

@registry.hook("go_detect_test_results")
def go_detect_test_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgo\s+test\b", cmd) or not output: return allow()
    passed = len(re.findall(r"--- PASS:", output))
    failed = len(re.findall(r"--- FAIL:", output))
    skipped = len(re.findall(r"--- SKIP:", output))
    if failed:
        return post_tool_context(f"Go test: {passed} passed, {failed} failed, {skipped} skipped")
    elif passed:
        return post_tool_context(f"Go test: {passed} passed, {skipped} skipped")
    return allow()

@registry.hook("go_check_build_constraints")
def go_check_build_constraints(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"build constraints exclude all Go files|no Go files", output):
        return post_tool_context("Go: Build constraints exclude all files. Check //go:build tags and GOOS/GOARCH.")
    return allow()

@registry.hook("go_detect_deprecated_apis")
def go_detect_deprecated_apis(data):
    output = get_command_output(data)
    if not output: return allow()
    deps = re.findall(r"SA1019|deprecated", output, re.IGNORECASE)
    if deps:
        return post_tool_context(f"Go: {len(deps)} deprecated API usages detected")
    return allow()

@registry.hook("go_check_interface_compliance")
def go_check_interface_compliance(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"does not implement|missing method", output):
        match = re.search(r"(\w+) does not implement (\w+).*missing method (\w+)", output)
        if match:
            return post_tool_context(f"Go: {match.group(1)} doesn't implement {match.group(2)} (missing {match.group(3)})")
    return allow()

@registry.hook("go_detect_shadow_variables")
def go_detect_shadow_variables(data):
    output = get_command_output(data)
    if not output: return allow()
    shadows = re.findall(r"shadows.*declaration|declaration of .(\w+). shadows", output)
    if shadows:
        return post_tool_context(f"Go: Variable shadowing detected. Rename to avoid confusion.")
    return allow()

@registry.hook("go_check_benchmark_results")
def go_check_benchmark_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgo\s+test\b.*-bench", cmd) or not output: return allow()
    benchmarks = re.findall(r"Benchmark(\w+)\s+(\d+)\s+(\d+(?:\.\d+)?)\s*ns/op", output)
    if benchmarks:
        summary = "; ".join(f"{n}: {ops}ops @ {ns}ns/op" for n, ops, ns in benchmarks[:5])
        return post_tool_context(f"Go benchmarks: {summary}")
    return allow()

if __name__ == "__main__":
    registry.main()
