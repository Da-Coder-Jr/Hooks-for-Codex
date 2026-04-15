#!/usr/bin/env python3
"""
Code Quality: Style Enforcement hooks for Codex.
25 PostToolUse hooks checking code style in command output.
"""

import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()


@registry.hook("check_trailing_whitespace")
def check_trailing_whitespace(data):
    output = get_command_output(data)
    if not output: return allow()
    lines_with_trailing = [i+1 for i, l in enumerate(output.split("\n")) if l != l.rstrip() and l.strip()]
    if len(lines_with_trailing) > 5:
        return post_tool_context(f"Style: {len(lines_with_trailing)} lines have trailing whitespace")
    return allow()

@registry.hook("check_mixed_indentation")
def check_mixed_indentation(data):
    output = get_command_output(data)
    if not output: return allow()
    has_tabs = bool(re.search(r"^\t", output, re.MULTILINE))
    has_spaces = bool(re.search(r"^    ", output, re.MULTILINE))
    if has_tabs and has_spaces:
        return post_tool_context("Style: Mixed tabs and spaces indentation detected")
    return allow()

@registry.hook("check_line_length")
def check_line_length(data):
    output = get_command_output(data)
    if not output: return allow()
    long_lines = [i+1 for i, l in enumerate(output.split("\n")) if len(l) > 120]
    if len(long_lines) > 3:
        return post_tool_context(f"Style: {len(long_lines)} lines exceed 120 characters")
    return allow()

@registry.hook("check_missing_newline_eof")
def check_missing_newline_eof(data):
    output = get_command_output(data)
    if output and not output.endswith("\n"):
        cmd = get_command(data)
        if re.search(r"\bcat\b", cmd):
            return post_tool_context("Style: File missing newline at end of file")
    return allow()

@registry.hook("check_consecutive_blank_lines")
def check_consecutive_blank_lines(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"\n\s*\n\s*\n\s*\n", output):
        return post_tool_context("Style: 3+ consecutive blank lines detected")
    return allow()

@registry.hook("check_import_sorting")
def check_import_sorting(data):
    output = get_command_output(data)
    if not output: return allow()
    imports = re.findall(r"^(?:from\s+\S+\s+)?import\s+\S+", output, re.MULTILINE)
    if len(imports) > 3 and imports != sorted(imports):
        return post_tool_context("Style: Python imports appear unsorted (consider isort)")
    return allow()

@registry.hook("check_unused_imports")
def check_unused_imports(data):
    output = get_command_output(data)
    if not output: return allow()
    unused = re.findall(r"(?i)imported but unused|unused import", output)
    if unused:
        return post_tool_context(f"Style: {len(unused)} unused imports detected")
    return allow()

@registry.hook("check_wildcard_imports")
def check_wildcard_imports(data):
    output = get_command_output(data)
    if not output: return allow()
    wildcards = re.findall(r"^(?:from\s+\S+\s+)?import\s+\*", output, re.MULTILINE)
    if wildcards:
        return post_tool_context(f"Style: {len(wildcards)} wildcard imports detected (import *)")
    return allow()

@registry.hook("check_naming_snake_case")
def check_naming_snake_case(data):
    output = get_command_output(data)
    if not output: return allow()
    py_funcs = re.findall(r"def\s+([a-zA-Z_]\w+)\s*\(", output)
    camel = [f for f in py_funcs if re.search(r"[a-z][A-Z]", f) and not f.startswith("_")]
    if camel:
        return post_tool_context(f"Style: Python functions should use snake_case: {', '.join(camel[:5])}")
    return allow()

@registry.hook("check_naming_camel_case")
def check_naming_camel_case(data):
    output = get_command_output(data)
    if not output: return allow()
    js_funcs = re.findall(r"(?:function|const|let|var)\s+([a-zA-Z_]\w+)", output)
    snake = [f for f in js_funcs if "_" in f and not f.startswith("_") and not f.isupper()]
    if len(snake) > 2:
        return post_tool_context(f"Style: JS/TS functions should use camelCase: {', '.join(snake[:5])}")
    return allow()

@registry.hook("check_naming_pascal_case")
def check_naming_pascal_case(data):
    output = get_command_output(data)
    if not output: return allow()
    classes = re.findall(r"class\s+([a-zA-Z_]\w+)", output)
    non_pascal = [c for c in classes if c[0].islower() or "_" in c]
    if non_pascal:
        return post_tool_context(f"Style: Class names should use PascalCase: {', '.join(non_pascal[:5])}")
    return allow()

@registry.hook("check_naming_constants")
def check_naming_constants(data):
    output = get_command_output(data)
    if not output: return allow()
    consts = re.findall(r"(?:const|final|static)\s+(?:int|str|float|string|number)?\s*([a-z]\w+)\s*=\s*['\"\d]", output)
    if consts:
        return post_tool_context(f"Style: Constants should use UPPER_SNAKE_CASE: {', '.join(consts[:5])}")
    return allow()

@registry.hook("check_todo_fixme")
def check_todo_fixme(data):
    output = get_command_output(data)
    if not output: return allow()
    todos = re.findall(r"(?i)\b(TODO|FIXME|HACK|XXX|BUG|OPTIMIZE)\b", output)
    if len(todos) > 3:
        from collections import Counter
        counts = Counter(t.upper() for t in todos)
        summary = ", ".join(f"{k}:{v}" for k, v in counts.most_common())
        return post_tool_context(f"Style: {len(todos)} markers found ({summary})")
    return allow()

@registry.hook("check_debug_statements")
def check_debug_statements(data):
    output = get_command_output(data)
    if not output: return allow()
    debugs = []
    debugs += re.findall(r"\bconsole\.(log|debug|info|warn)\s*\(", output)
    debugs += re.findall(r"^\s*print\s*\(", output, re.MULTILINE)
    debugs += re.findall(r"\bdebugger\s*;", output)
    debugs += re.findall(r"\bpdb\.set_trace\(\)", output)
    debugs += re.findall(r"\bbreakpoint\(\)", output)
    if len(debugs) > 2:
        return post_tool_context(f"Style: {len(debugs)} debug/print statements detected")
    return allow()

@registry.hook("check_commented_code")
def check_commented_code(data):
    output = get_command_output(data)
    if not output: return allow()
    commented_code = re.findall(r"^\s*(#|//)\s*(if|for|while|def|function|class|return|import|const|let|var)\b", output, re.MULTILINE)
    if len(commented_code) > 5:
        return post_tool_context(f"Style: {len(commented_code)} lines of commented-out code detected")
    return allow()

@registry.hook("check_magic_numbers")
def check_magic_numbers(data):
    output = get_command_output(data)
    if not output: return allow()
    magic = re.findall(r"(?<![\w.])\b(?!0\b|1\b|2\b|100\b|1000\b)\d{2,}\b(?![\w.])", output)
    if len(magic) > 5:
        return post_tool_context(f"Style: {len(magic)} magic numbers detected (consider named constants)")
    return allow()

@registry.hook("check_string_concatenation")
def check_string_concatenation(data):
    output = get_command_output(data)
    if not output: return allow()
    concats = re.findall(r'["\'].*["\']\s*\+\s*\w+\s*\+\s*["\']', output)
    if len(concats) > 2:
        return post_tool_context("Style: String concatenation detected (consider f-strings or template literals)")
    return allow()

@registry.hook("check_deep_nesting")
def check_deep_nesting(data):
    output = get_command_output(data)
    if not output: return allow()
    max_indent = 0
    for line in output.split("\n"):
        stripped = line.lstrip()
        if stripped:
            indent = len(line) - len(stripped)
            level = indent // 4 if "    " in line[:indent] else indent // 2
            max_indent = max(max_indent, level)
    if max_indent > 5:
        return post_tool_context(f"Style: Deep nesting detected ({max_indent} levels) - consider refactoring")
    return allow()

@registry.hook("check_long_functions")
def check_long_functions(data):
    output = get_command_output(data)
    if not output: return allow()
    func_starts = [(m.start(), m.group(1)) for m in re.finditer(r"(?:def|function)\s+(\w+)", output)]
    lines = output.split("\n")
    long_funcs = []
    for i, (pos, name) in enumerate(func_starts):
        start_line = output[:pos].count("\n")
        end_line = func_starts[i+1][0] if i+1 < len(func_starts) else len(output)
        end_line_num = output[:end_line].count("\n")
        length = end_line_num - start_line
        if length > 50:
            long_funcs.append(f"{name}({length}L)")
    if long_funcs:
        return post_tool_context(f"Style: Long functions: {', '.join(long_funcs[:5])}")
    return allow()

@registry.hook("check_long_files")
def check_long_files(data):
    output = get_command_output(data)
    if not output: return allow()
    cmd = get_command(data)
    if re.search(r"\bwc\s+-l\b", cmd):
        long_files = re.findall(r"\s*(\d+)\s+(\S+)", output)
        big = [(name, int(count)) for count, name in long_files if int(count) > 500 and name != "total"]
        if big:
            return post_tool_context(f"Style: Large files: {', '.join(f'{n}({c}L)' for n,c in big[:5])}")
    return allow()

@registry.hook("check_missing_docstrings")
def check_missing_docstrings(data):
    output = get_command_output(data)
    if not output: return allow()
    funcs = re.findall(r"def\s+([a-zA-Z_]\w+)\s*\(.*\):", output)
    next_lines = {}
    lines = output.split("\n")
    for i, line in enumerate(lines):
        m = re.match(r"\s*def\s+(\w+)\s*\(", line)
        if m and i + 1 < len(lines):
            next_line = lines[i+1].strip()
            if not next_line.startswith(('"""', "'''", '#')):
                next_lines[m.group(1)] = True
    missing = [f for f in next_lines if not f.startswith("_")]
    if len(missing) > 2:
        return post_tool_context(f"Style: {len(missing)} public functions missing docstrings")
    return allow()

@registry.hook("check_missing_jsdoc")
def check_missing_jsdoc(data):
    output = get_command_output(data)
    if not output: return allow()
    exports = re.findall(r"export\s+(?:function|const|class)\s+(\w+)", output)
    lines = output.split("\n")
    missing = []
    for i, line in enumerate(lines):
        m = re.match(r"\s*export\s+(?:function|const|class)\s+(\w+)", line)
        if m and i > 0:
            prev = lines[i-1].strip()
            if not prev.endswith("*/") and not prev.startswith("//"):
                missing.append(m.group(1))
    if len(missing) > 2:
        return post_tool_context(f"Style: {len(missing)} exported items missing JSDoc")
    return allow()

@registry.hook("check_consistent_quotes")
def check_consistent_quotes(data):
    output = get_command_output(data)
    if not output: return allow()
    singles = len(re.findall(r"'[^']*'", output))
    doubles = len(re.findall(r'"[^"]*"', output))
    if singles > 5 and doubles > 5:
        dominant = "single" if singles > doubles else "double"
        return post_tool_context(f"Style: Mixed quote styles ({singles} single, {doubles} double). Prefer {dominant}.")
    return allow()

@registry.hook("check_semicolons_consistency")
def check_semicolons_consistency(data):
    output = get_command_output(data)
    if not output: return allow()
    with_semi = len(re.findall(r";\s*$", output, re.MULTILINE))
    without = len(re.findall(r"[^;{}\s]\s*$", output, re.MULTILINE))
    if with_semi > 5 and without > 5:
        return post_tool_context(f"Style: Inconsistent semicolon usage ({with_semi} with, {without} without)")
    return allow()

@registry.hook("check_bracket_style")
def check_bracket_style(data):
    output = get_command_output(data)
    if not output: return allow()
    same_line = len(re.findall(r"[)]\s*\{", output))
    new_line = len(re.findall(r"^\s*\{", output, re.MULTILINE))
    if same_line > 3 and new_line > 3:
        return post_tool_context("Style: Inconsistent brace style (mixed K&R and Allman)")
    return allow()


if __name__ == "__main__":
    registry.main()
