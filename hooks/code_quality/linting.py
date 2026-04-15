#!/usr/bin/env python3
"""
Code Quality: Linting hooks for Codex.
25 PostToolUse hooks that parse linter output and provide summaries.
"""

import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()


def _is_cmd(cmd, pattern):
    return bool(re.search(pattern, cmd))


@registry.hook("lint_python_flake8")
def lint_python_flake8(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bflake8\b") or not output: return allow()
    errors = re.findall(r"[A-Z]\d{3}", output)
    cats = {}
    for e in errors:
        prefix = e[0]
        cats[prefix] = cats.get(prefix, 0) + 1
    names = {"E": "style", "W": "warning", "F": "pyflakes", "C": "complexity", "N": "naming"}
    summary = ", ".join(f"{names.get(k,k)}:{v}" for k, v in sorted(cats.items()))
    return post_tool_context(f"Flake8: {len(errors)} issues ({summary})")

@registry.hook("lint_python_pylint")
def lint_python_pylint(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bpylint\b") or not output: return allow()
    score = re.search(r"Your code has been rated at ([0-9.]+)/10", output)
    errors = len(re.findall(r"^[A-Z]:\s*\d+", output, re.MULTILINE))
    msg = f"Pylint: {errors} issues"
    if score: msg += f", score: {score.group(1)}/10"
    return post_tool_context(msg)

@registry.hook("lint_python_mypy")
def lint_python_mypy(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bmypy\b") or not output: return allow()
    errors = len(re.findall(r": error:", output))
    warnings = len(re.findall(r": (warning|note):", output))
    return post_tool_context(f"Mypy: {errors} errors, {warnings} warnings/notes")

@registry.hook("lint_python_ruff")
def lint_python_ruff(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bruff\b") or not output: return allow()
    issues = len(re.findall(r"\b[A-Z]+\d{3,4}\b", output))
    fixable = len(re.findall(r"(?i)fixable", output))
    msg = f"Ruff: {issues} issues"
    if fixable: msg += f" ({fixable} auto-fixable)"
    return post_tool_context(msg)

@registry.hook("lint_python_bandit")
def lint_python_bandit(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bbandit\b") or not output: return allow()
    high = len(re.findall(r"Severity: High", output))
    medium = len(re.findall(r"Severity: Medium", output))
    low = len(re.findall(r"Severity: Low", output))
    return post_tool_context(f"Bandit security: {high} high, {medium} medium, {low} low severity")

@registry.hook("lint_js_eslint")
def lint_js_eslint(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\beslint\b") or not output: return allow()
    errors = len(re.findall(r"\berror\b", output))
    warnings = len(re.findall(r"\bwarning\b", output))
    summary_match = re.search(r"(\d+) problems? \((\d+) errors?, (\d+) warnings?\)", output)
    if summary_match:
        return post_tool_context(f"ESLint: {summary_match.group(2)} errors, {summary_match.group(3)} warnings")
    return post_tool_context(f"ESLint: {errors} errors, {warnings} warnings")

@registry.hook("lint_js_prettier_check")
def lint_js_prettier_check(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bprettier\b.*--check") or not output: return allow()
    unformatted = re.findall(r"^\S+\.\w+$", output, re.MULTILINE)
    if unformatted:
        return post_tool_context(f"Prettier: {len(unformatted)} unformatted files")
    return allow()

@registry.hook("lint_ts_tsc")
def lint_ts_tsc(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\btsc\b") or not output: return allow()
    errors = re.findall(r"TS(\d+):", output)
    cats = {}
    for e in errors:
        cats[e] = cats.get(e, 0) + 1
    top = sorted(cats.items(), key=lambda x: -x[1])[:5]
    summary = ", ".join(f"TS{k}:{v}" for k, v in top)
    return post_tool_context(f"TypeScript: {len(errors)} errors. Top: {summary}")

@registry.hook("lint_rust_clippy")
def lint_rust_clippy(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bcargo\s+clippy\b") or not output: return allow()
    warnings = len(re.findall(r"warning:", output))
    errors = len(re.findall(r"error\[", output))
    return post_tool_context(f"Clippy: {errors} errors, {warnings} warnings")

@registry.hook("lint_rust_fmt_check")
def lint_rust_fmt_check(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bcargo\s+fmt\b.*--check") or not output: return allow()
    diffs = len(re.findall(r"^Diff in", output, re.MULTILINE))
    return post_tool_context(f"Cargo fmt: {diffs} files need formatting")

@registry.hook("lint_go_vet")
def lint_go_vet(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bgo\s+vet\b") or not output: return allow()
    issues = len(re.findall(r"\.go:\d+:\d+:", output))
    return post_tool_context(f"Go vet: {issues} issues found")

@registry.hook("lint_go_staticcheck")
def lint_go_staticcheck(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bstaticcheck\b") or not output: return allow()
    issues = re.findall(r"(SA\d+|S\d+|ST\d+|QF\d+)", output)
    return post_tool_context(f"Staticcheck: {len(issues)} issues")

@registry.hook("lint_go_golangci")
def lint_go_golangci(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bgolangci-lint\b") or not output: return allow()
    issues = len(re.findall(r"\.go:\d+:\d+:", output))
    linters = set(re.findall(r"\((\w+)\)$", output, re.MULTILINE))
    return post_tool_context(f"golangci-lint: {issues} issues from {len(linters)} linters")

@registry.hook("lint_ruby_rubocop")
def lint_ruby_rubocop(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\brubocop\b") or not output: return allow()
    summary = re.search(r"(\d+) files? inspected, (\d+) offenses?", output)
    if summary:
        return post_tool_context(f"RuboCop: {summary.group(1)} files, {summary.group(2)} offenses")
    return allow()

@registry.hook("lint_php_phpcs")
def lint_php_phpcs(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bphpcs\b") or not output: return allow()
    errors = len(re.findall(r"\bERROR\b", output))
    warnings = len(re.findall(r"\bWARNING\b", output))
    return post_tool_context(f"PHPCS: {errors} errors, {warnings} warnings")

@registry.hook("lint_java_checkstyle")
def lint_java_checkstyle(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bcheckstyle\b") or not output: return allow()
    violations = len(re.findall(r"\[(?:ERROR|WARN)\]", output))
    return post_tool_context(f"Checkstyle: {violations} violations")

@registry.hook("lint_java_spotbugs")
def lint_java_spotbugs(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\b(spotbugs|findbugs)\b") or not output: return allow()
    bugs = len(re.findall(r"(?i)\bbug\b", output))
    return post_tool_context(f"SpotBugs: {bugs} potential bugs")

@registry.hook("lint_swift_swiftlint")
def lint_swift_swiftlint(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bswiftlint\b") or not output: return allow()
    violations = len(re.findall(r"(warning|error):", output))
    return post_tool_context(f"SwiftLint: {violations} violations")

@registry.hook("lint_kotlin_ktlint")
def lint_kotlin_ktlint(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bktlint\b") or not output: return allow()
    issues = len(re.findall(r"\.kt:\d+:\d+:", output))
    return post_tool_context(f"ktlint: {issues} issues")

@registry.hook("lint_shell_shellcheck")
def lint_shell_shellcheck(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bshellcheck\b") or not output: return allow()
    issues = re.findall(r"SC(\d+)", output)
    return post_tool_context(f"ShellCheck: {len(issues)} issues")

@registry.hook("lint_yaml_yamllint")
def lint_yaml_yamllint(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\byamllint\b") or not output: return allow()
    issues = len(re.findall(r"\b(error|warning)\b", output))
    return post_tool_context(f"yamllint: {issues} issues")

@registry.hook("lint_docker_hadolint")
def lint_docker_hadolint(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bhadolint\b") or not output: return allow()
    issues = re.findall(r"DL\d+", output)
    return post_tool_context(f"Hadolint: {len(issues)} Dockerfile issues")

@registry.hook("lint_terraform_tflint")
def lint_terraform_tflint(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\btflint\b") or not output: return allow()
    issues = len(re.findall(r"(Error|Warning):", output))
    return post_tool_context(f"tflint: {issues} issues")

@registry.hook("lint_css_stylelint")
def lint_css_stylelint(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bstylelint\b") or not output: return allow()
    issues = len(re.findall(r"✖|✕|error|warning", output))
    return post_tool_context(f"Stylelint: {issues} issues")

@registry.hook("lint_markdown_markdownlint")
def lint_markdown_markdownlint(data):
    cmd, output = get_command(data), get_command_output(data)
    if not _is_cmd(cmd, r"\bmarkdownlint\b") or not output: return allow()
    issues = re.findall(r"MD\d+", output)
    return post_tool_context(f"markdownlint: {len(issues)} issues")


if __name__ == "__main__":
    registry.main()
