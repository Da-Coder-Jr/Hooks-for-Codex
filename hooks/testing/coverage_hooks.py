#!/usr/bin/env python3
"""Testing: Coverage analysis hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("parse_pytest_coverage")
def parse_pytest_coverage(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"pytest.*--cov|coverage\s+run", cmd) or not output: return allow()
    match = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", output)
    if match:
        pct = int(match.group(1))
        status = "PASS" if pct >= 80 else "WARN" if pct >= 60 else "FAIL"
        return post_tool_context(f"Coverage: {pct}% ({status})")
    return allow()

@registry.hook("parse_jest_coverage")
def parse_jest_coverage(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"jest.*--coverage|npx.*jest.*coverage", cmd) or not output: return allow()
    match = re.search(r"All files\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)", output)
    if match:
        stmts, branch, funcs, lines = match.groups()
        return post_tool_context(f"Jest coverage: Stmts {stmts}%, Branch {branch}%, Funcs {funcs}%, Lines {lines}%")
    return allow()

@registry.hook("parse_go_coverage")
def parse_go_coverage(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"go\s+test.*-cover", cmd) or not output: return allow()
    match = re.search(r"coverage:\s*([\d.]+)%\s*of statements", output)
    if match:
        pct = float(match.group(1))
        return post_tool_context(f"Go coverage: {pct}% of statements")
    return allow()

@registry.hook("parse_jacoco_coverage")
def parse_jacoco_coverage(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"Total.*?(\d+)%\s*(?:of|coverage)", output)
    if match and re.search(r"jacoco|JaCoCo", output, re.IGNORECASE):
        return post_tool_context(f"JaCoCo coverage: {match.group(1)}%")
    return allow()

@registry.hook("detect_coverage_regression")
def detect_coverage_regression(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"coverage.*decreased|coverage.*dropped|coverage.*below.*threshold", output, re.IGNORECASE):
        match = re.search(r"(\d+(?:\.\d+)?)%.*→.*(\d+(?:\.\d+)?)%", output)
        if match:
            return post_tool_context(f"Coverage regression: {match.group(1)}% → {match.group(2)}%")
        return post_tool_context("Coverage regression detected. New code may lack tests.")
    return allow()

@registry.hook("check_uncovered_branches")
def check_uncovered_branches(data):
    output = get_command_output(data)
    if not output: return allow()
    uncovered = re.findall(r"(\S+\.(?:py|js|ts|java|go))\s+.*?(\d+)\s+miss", output, re.IGNORECASE)
    if uncovered:
        high_miss = [(f, int(m)) for f, m in uncovered if int(m) > 20]
        if high_miss:
            files = ", ".join(f"{f}({m} missed)" for f, m in high_miss[:3])
            return post_tool_context(f"Coverage: High missed branches: {files}")
    return allow()

@registry.hook("detect_untested_files")
def detect_untested_files(data):
    output = get_command_output(data)
    if not output: return allow()
    zero_cov = re.findall(r"(\S+\.(?:py|js|ts))\s+\d+\s+\d+\s+0%", output)
    if zero_cov:
        return post_tool_context(f"Coverage: {len(zero_cov)} files with 0% coverage: {', '.join(zero_cov[:5])}")
    return allow()

@registry.hook("check_coverage_threshold")
def check_coverage_threshold(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"coverage.*threshold.*not met|below.*minimum.*coverage|Coverage failure", output, re.IGNORECASE):
        return post_tool_context("Coverage: Below configured threshold. Add tests for uncovered code paths.")
    return allow()

@registry.hook("parse_istanbul_coverage")
def parse_istanbul_coverage(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"istanbul|nyc|c8", output, re.IGNORECASE):
        match = re.search(r"Statements\s*:\s*([\d.]+)%|Lines\s*:\s*([\d.]+)%", output)
        if match:
            pct = match.group(1) or match.group(2)
            return post_tool_context(f"Istanbul/nyc coverage: {pct}%")
    return allow()

@registry.hook("detect_coverage_report_generated")
def detect_coverage_report_generated(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"coverage report.*generated|wrote.*coverage|HTML report.*written", output, re.IGNORECASE):
        match = re.search(r"(?:to|at|in)\s+(\S+(?:coverage|htmlcov)\S*)", output)
        if match:
            return post_tool_context(f"Coverage report generated: {match.group(1)}")
    return allow()

@registry.hook("check_mutation_testing")
def check_mutation_testing(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"mutant|mutation.*score|pitest|mutmut|stryker", output, re.IGNORECASE):
        match = re.search(r"mutation.*score.*?(\d+(?:\.\d+)?)%", output, re.IGNORECASE)
        if match:
            return post_tool_context(f"Mutation testing score: {match.group(1)}%")
    return allow()

@registry.hook("detect_new_code_without_tests")
def detect_new_code_without_tests(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+diff\s+--stat", cmd) or not output: return allow()
    source_files = re.findall(r"\s(\S+\.(?:py|js|ts|java|go|rs))\s", output)
    test_files = [f for f in source_files if re.search(r"test|spec|_test\.", f, re.IGNORECASE)]
    impl_files = [f for f in source_files if f not in test_files]
    if impl_files and not test_files:
        return post_tool_context(f"Coverage: {len(impl_files)} source files changed with no test files. Add tests.")
    return allow()

@registry.hook("parse_coverage_diff")
def parse_coverage_diff(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"diff.*coverage|coverage.*diff|new.*lines.*covered", output, re.IGNORECASE):
        match = re.search(r"new.*?(\d+(?:\.\d+)?)%.*covered", output, re.IGNORECASE)
        if match:
            return post_tool_context(f"Diff coverage: {match.group(1)}% of new lines covered")
    return allow()

@registry.hook("check_tarpaulin_coverage")
def check_tarpaulin_coverage(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"cargo\s+tarpaulin", cmd) or not output: return allow()
    match = re.search(r"(\d+(?:\.\d+)?)%\s+coverage", output)
    if match:
        return post_tool_context(f"Rust tarpaulin coverage: {match.group(1)}%")
    return allow()

@registry.hook("detect_coverage_exclusions")
def detect_coverage_exclusions(data):
    output = get_command_output(data)
    if not output: return allow()
    exclusions = re.findall(r"#\s*pragma:\s*no\s*cover|istanbul\s+ignore|LCOV_EXCL|@codeCoverageIgnore", output)
    if len(exclusions) > 5:
        return post_tool_context(f"Coverage: {len(exclusions)} coverage exclusion annotations. Review if justified.")
    return allow()

if __name__ == "__main__":
    registry.main()
