#!/usr/bin/env python3
"""Testing: Test runner output parsing hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("parse_pytest_results")
def parse_pytest_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bpytest\b|python\s+-m\s+pytest", cmd) or not output: return allow()
    match = re.search(r"(\d+) passed(?:.*?(\d+) failed)?(?:.*?(\d+) error)?(?:.*?(\d+) skipped)?(?:.*?(\d+) warning)?", output)
    if match:
        parts = []
        if match.group(1): parts.append(f"{match.group(1)} passed")
        if match.group(2): parts.append(f"{match.group(2)} failed")
        if match.group(3): parts.append(f"{match.group(3)} errors")
        if match.group(4): parts.append(f"{match.group(4)} skipped")
        return post_tool_context(f"pytest: {', '.join(parts)}")
    return allow()

@registry.hook("parse_jest_results")
def parse_jest_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bjest\b|npx\s+jest", cmd) or not output: return allow()
    suites = re.search(r"Test Suites:\s*(.+)", output)
    tests = re.search(r"Tests:\s*(.+)", output)
    if suites or tests:
        msg = "Jest: "
        if suites: msg += f"Suites: {suites.group(1).strip()}. "
        if tests: msg += f"Tests: {tests.group(1).strip()}"
        return post_tool_context(msg.strip())
    return allow()

@registry.hook("parse_mocha_results")
def parse_mocha_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bmocha\b", cmd) or not output: return allow()
    match = re.search(r"(\d+) passing.*?(?:(\d+) failing)?(?:.*?(\d+) pending)?", output)
    if match:
        parts = [f"{match.group(1)} passing"]
        if match.group(2): parts.append(f"{match.group(2)} failing")
        if match.group(3): parts.append(f"{match.group(3)} pending")
        return post_tool_context(f"Mocha: {', '.join(parts)}")
    return allow()

@registry.hook("parse_rspec_results")
def parse_rspec_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\brspec\b", cmd) or not output: return allow()
    match = re.search(r"(\d+) examples?,\s*(\d+) failures?(?:,\s*(\d+) pending)?", output)
    if match:
        parts = [f"{match.group(1)} examples", f"{match.group(2)} failures"]
        if match.group(3): parts.append(f"{match.group(3)} pending")
        return post_tool_context(f"RSpec: {', '.join(parts)}")
    return allow()

@registry.hook("parse_junit_results")
def parse_junit_results(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)", output)
    if match:
        return post_tool_context(f"JUnit: {match.group(1)} run, {match.group(2)} failures, {match.group(3)} errors, {match.group(4)} skipped")
    return allow()

@registry.hook("parse_vitest_results")
def parse_vitest_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bvitest\b", cmd) or not output: return allow()
    match = re.search(r"Tests\s+(\d+)\s+(?:passed|failed)", output)
    if not match:
        match = re.search(r"(\d+)\s+passed.*?(?:(\d+)\s+failed)?", output)
    if match:
        return post_tool_context(f"Vitest: {match.group(0).strip()}")
    return allow()

@registry.hook("parse_phpunit_results")
def parse_phpunit_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"phpunit", cmd) or not output: return allow()
    match = re.search(r"Tests:\s*(\d+),\s*Assertions:\s*(\d+)(?:,\s*Failures:\s*(\d+))?", output)
    if match:
        parts = [f"{match.group(1)} tests", f"{match.group(2)} assertions"]
        if match.group(3): parts.append(f"{match.group(3)} failures")
        return post_tool_context(f"PHPUnit: {', '.join(parts)}")
    return allow()

@registry.hook("parse_dotnet_test_results")
def parse_dotnet_test_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"dotnet\s+test", cmd) or not output: return allow()
    match = re.search(r"Passed!\s+-\s+Failed:\s+(\d+),\s+Passed:\s+(\d+),\s+Skipped:\s+(\d+),\s+Total:\s+(\d+)", output)
    if match:
        return post_tool_context(f".NET test: {match.group(4)} total, {match.group(2)} passed, {match.group(1)} failed, {match.group(3)} skipped")
    return allow()

@registry.hook("detect_test_timeout")
def detect_test_timeout(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"timed out|Timeout.*exceeded|TIMEOUT|test.*timeout", output, re.IGNORECASE):
        match = re.search(r"(\w+)\s*(?:timed out|TIMEOUT)", output)
        return post_tool_context(f"Test timeout: {match.group(1) if match else 'test'} exceeded time limit. Check for infinite loops or slow I/O.")
    return allow()

@registry.hook("detect_test_segfault")
def detect_test_segfault(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Segmentation fault|SIGSEGV|core dumped|signal 11", output):
        return post_tool_context("Test crash: Segmentation fault. Check for null pointer dereference or buffer overflow.")
    return allow()

@registry.hook("parse_cargo_test_results")
def parse_cargo_test_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bcargo\s+test\b", cmd) or not output: return allow()
    match = re.search(r"test result:.*?(\d+) passed;\s*(\d+) failed;\s*(\d+) ignored", output)
    if match:
        return post_tool_context(f"Cargo test: {match.group(1)} passed, {match.group(2)} failed, {match.group(3)} ignored")
    return allow()

@registry.hook("detect_test_memory_leak")
def detect_test_memory_leak(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"--detectOpenHandles|memory leak|leaked|handle.*open after|unhandled.*after", output, re.IGNORECASE):
        return post_tool_context("Test runner: Open handles/memory leaks detected. Close connections and clear timers in teardown.")
    return allow()

@registry.hook("parse_pytest_markers")
def parse_pytest_markers(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"pytest.*-m\s+|pytest.*--markers", cmd) or not output: return allow()
    skipped = len(re.findall(r"SKIPPED", output))
    xfailed = len(re.findall(r"XFAIL", output))
    xpassed = len(re.findall(r"XPASS", output))
    if skipped or xfailed or xpassed:
        parts = []
        if skipped: parts.append(f"{skipped} skipped")
        if xfailed: parts.append(f"{xfailed} xfailed")
        if xpassed: parts.append(f"{xpassed} xpassed (unexpected!)")
        return post_tool_context(f"pytest markers: {', '.join(parts)}")
    return allow()

@registry.hook("detect_test_flakiness")
def detect_test_flakiness(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"flaky|intermittent|retry.*passed|rerun.*passed|RETRY", output, re.IGNORECASE):
        return post_tool_context("Test runner: Flaky test detected (passed on retry). Investigate root cause.")
    return allow()

@registry.hook("check_test_parallelism")
def check_test_parallelism(data):
    cmd, output = get_command(data), get_command_output(data)
    if not output: return allow()
    if re.search(r"-n\s+\d+|--workers|--parallel|--forked|maxWorkers", cmd):
        if re.search(r"FAILED|error|conflict|deadlock", output, re.IGNORECASE):
            return post_tool_context("Test runner: Failures in parallel mode. Tests may have shared state conflicts.")
    return allow()

if __name__ == "__main__":
    registry.main()
