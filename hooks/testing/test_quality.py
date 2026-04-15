#!/usr/bin/env python3
"""Testing: Test quality hooks for Codex. 20 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("detect_test_without_assertions")
def detect_test_without_assertions(data):
    output = get_command_output(data)
    if not output: return allow()
    test_funcs = re.findall(r"def test_\w+\(", output)
    assertions = re.findall(r"\b(assert|assertEqual|assertRaises|expect\(|should\.|toBe|toEqual)\b", output)
    if len(test_funcs) > len(assertions) and len(test_funcs) > 2:
        return post_tool_context(f"Test quality: {len(test_funcs)} tests but only {len(assertions)} assertions. Tests may be incomplete.")
    return allow()

@registry.hook("check_test_naming_convention")
def check_test_naming_convention(data):
    output = get_command_output(data)
    if not output: return allow()
    bad_names = re.findall(r"def (test\d+|test_\w{1,3})\(", output)
    if len(bad_names) > 2:
        return post_tool_context(f"Test quality: {len(bad_names)} poorly named tests. Use descriptive names: test_should_<behavior>.")
    return allow()

@registry.hook("detect_flaky_test_patterns")
def detect_flaky_test_patterns(data):
    output = get_command_output(data)
    if not output: return allow()
    flaky_patterns = []
    if re.search(r"time\.sleep|setTimeout|Thread\.sleep", output): flaky_patterns.append("sleep-based timing")
    if re.search(r"random\.|Math\.random|rand\(", output): flaky_patterns.append("random values")
    if re.search(r"datetime\.now|Date\.now|System\.currentTimeMillis", output): flaky_patterns.append("current time dependency")
    if flaky_patterns:
        return post_tool_context(f"Test quality: Flaky test patterns detected: {', '.join(flaky_patterns)}")
    return allow()

@registry.hook("check_test_isolation")
def check_test_isolation(data):
    output = get_command_output(data)
    if not output: return allow()
    shared_state = re.findall(r"global\s+\w+|class\s+\w+.*:\s*\n\s+\w+\s*=", output)
    if len(shared_state) > 3:
        return post_tool_context("Test quality: Shared mutable state in tests. Use setUp/tearDown for test isolation.")
    return allow()

@registry.hook("detect_test_anti_patterns")
def detect_test_anti_patterns(data):
    output = get_command_output(data)
    if not output: return allow()
    issues = []
    if re.search(r"except.*pass|catch.*\{\s*\}", output): issues.append("swallowed exceptions")
    if re.search(r"assertTrue\(True\)|assert True|expect\(true\)", output): issues.append("trivial assertions")
    if re.search(r"#.*skip|@skip|\.skip\(|xit\(", output): issues.append("skipped tests")
    if issues:
        return post_tool_context(f"Test quality: Anti-patterns: {', '.join(issues)}")
    return allow()

@registry.hook("check_mock_usage")
def check_mock_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    mocks = len(re.findall(r"\b(mock|Mock|MagicMock|patch|jest\.fn|sinon\.stub|vi\.fn)\b", output))
    if mocks > 10:
        return post_tool_context(f"Test quality: {mocks} mocks. Excessive mocking may indicate tests are too coupled to implementation.")
    return allow()

@registry.hook("detect_test_duplication")
def detect_test_duplication(data):
    output = get_command_output(data)
    if not output: return allow()
    test_bodies = re.findall(r"def test_\w+\([^)]*\):\s*\n((?:\s+.*\n){1,5})", output)
    if len(test_bodies) != len(set(test_bodies)) and len(test_bodies) > 3:
        return post_tool_context("Test quality: Duplicate test logic detected. Consider parameterized tests.")
    return allow()

@registry.hook("check_test_coverage_gaps")
def check_test_coverage_gaps(data):
    output = get_command_output(data)
    if not output: return allow()
    uncovered = re.findall(r"(\S+\.(?:py|js|ts))\s+\d+\s+\d+\s+(\d+)%", output)
    low_coverage = [(f, pct) for f, pct in uncovered if int(pct) < 50]
    if low_coverage:
        files = ", ".join(f"{f}({p}%)" for f, p in low_coverage[:5])
        return post_tool_context(f"Test coverage: Low coverage files: {files}")
    return allow()

@registry.hook("detect_brittle_selectors")
def detect_brittle_selectors(data):
    output = get_command_output(data)
    if not output: return allow()
    brittle = re.findall(r"\.querySelector\(['\"](?:div|span|p)\s*>|nth-child|\.class\d+|#id\d+", output)
    if len(brittle) > 3:
        return post_tool_context("Test quality: Brittle CSS selectors in tests. Use data-testid attributes instead.")
    return allow()

@registry.hook("check_e2e_test_practices")
def check_e2e_test_practices(data):
    output = get_command_output(data)
    if not output: return allow()
    issues = []
    if re.search(r"cy\.wait\(\d{4,}\)|page\.waitForTimeout\(\d{4,}\)", output): issues.append("long hard waits")
    if re.search(r"cy\.get\(['\"]body|page\.\$\(['\"]body", output): issues.append("broad selectors")
    if not re.search(r"\.intercept|\.route|mockServiceWorker", output) and re.search(r"\.visit|goto\(", output):
        issues.append("no API mocking")
    if issues:
        return post_tool_context(f"E2E test quality: Issues: {', '.join(issues)}")
    return allow()

@registry.hook("detect_snapshot_overuse")
def detect_snapshot_overuse(data):
    output = get_command_output(data)
    if not output: return allow()
    snapshots = len(re.findall(r"toMatchSnapshot|toMatchInlineSnapshot|matchSnapshot", output))
    if snapshots > 5:
        return post_tool_context(f"Test quality: {snapshots} snapshot tests. Overuse makes tests fragile. Prefer specific assertions.")
    return allow()

@registry.hook("check_test_setup_teardown")
def check_test_setup_teardown(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"def test_|it\(|test\(", output):
        if not re.search(r"setUp|tearDown|beforeEach|afterEach|beforeAll|afterAll|@Before|@After", output):
            if re.search(r"open\(|connect\(|create.*client|new.*Client", output):
                return post_tool_context("Test quality: Resource creation without setup/teardown. May leak resources.")
    return allow()

@registry.hook("detect_test_order_dependency")
def detect_test_order_dependency(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"@Order|order.*=.*\d+|test.*depends.*on|runOrder", output):
        return post_tool_context("Test quality: Test order dependency detected. Tests should be independent and runnable in any order.")
    return allow()

@registry.hook("check_async_test_handling")
def check_async_test_handling(data):
    output = get_command_output(data)
    if not output: return allow()
    async_tests = re.findall(r"async\s+(?:def test_|function test|it\()", output)
    awaits = re.findall(r"\bawait\b", output)
    if len(async_tests) > len(awaits) and async_tests:
        return post_tool_context("Test quality: Async tests without proper await. Tests may pass prematurely.")
    return allow()

@registry.hook("detect_test_data_hardcoding")
def detect_test_data_hardcoding(data):
    output = get_command_output(data)
    if not output: return allow()
    hardcoded = re.findall(r"[\"'](?:test@test\.com|password123|John Doe|123 Main St|555-\d{4})[\"']", output, re.IGNORECASE)
    if len(hardcoded) > 5:
        return post_tool_context("Test quality: Excessive hardcoded test data. Use fixtures or factories.")
    return allow()

@registry.hook("check_test_timeout_settings")
def check_test_timeout_settings(data):
    output = get_command_output(data)
    if not output: return allow()
    long_timeouts = re.findall(r"timeout[:\s=]+(\d+)", output)
    extreme = [t for t in long_timeouts if int(t) > 30000]
    if extreme:
        return post_tool_context(f"Test quality: Very long timeouts ({', '.join(extreme[:3])}ms). May mask performance issues.")
    return allow()

@registry.hook("detect_test_file_io")
def detect_test_file_io(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"def test_.*:\s*\n.*(?:open\(|os\.path|shutil|pathlib)", output):
        if not re.search(r"tmp_path|tempfile|tmpdir|TemporaryDirectory", output):
            return post_tool_context("Test quality: File I/O in tests without temp directory. Use pytest tmp_path or tempfile.")
    return allow()

@registry.hook("check_test_assertions_specificity")
def check_test_assertions_specificity(data):
    output = get_command_output(data)
    if not output: return allow()
    vague = len(re.findall(r"assertIsNotNone|toBeTruthy|toBeDefined|\.to\.exist|assertNotNull", output))
    if vague > 5:
        return post_tool_context(f"Test quality: {vague} vague assertions (not null/truthy). Use specific value checks.")
    return allow()

@registry.hook("detect_test_pollution")
def detect_test_pollution(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"os\.environ\[|process\.env\.|System\.setProperty", output):
        if not re.search(r"monkeypatch|mock\.patch|jest\.replaceProperty|@RestoreSystemProperties", output):
            return post_tool_context("Test quality: Modifying environment variables without cleanup. Use monkeypatch or mock.")
    return allow()

@registry.hook("check_parameterized_tests")
def check_parameterized_tests(data):
    output = get_command_output(data)
    if not output: return allow()
    similar = re.findall(r"def (test_\w+)_(\w+)\(", output)
    if len(similar) > 5:
        prefixes = {}
        for name, variant in similar:
            prefixes[name] = prefixes.get(name, 0) + 1
        many = [(k, v) for k, v in prefixes.items() if v > 3]
        if many:
            return post_tool_context(f"Test quality: Similar test variants detected. Consider @pytest.mark.parametrize.")
    return allow()

if __name__ == "__main__":
    registry.main()
