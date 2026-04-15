#!/usr/bin/env python3
"""Language-Specific: Rust hooks for Codex. 18 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("rust_parse_compiler_errors")
def rust_parse_compiler_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bcargo\s+(build|check|run)\b", cmd) or not output: return allow()
    errors = re.findall(r"error\[E(\d+)\]", output)
    if errors:
        from collections import Counter
        top = Counter(errors).most_common(5)
        return post_tool_context(f"Rust: {len(errors)} errors. Top: {', '.join(f'E{k}({v})' for k,v in top)}")
    return allow()

@registry.hook("rust_detect_borrow_errors")
def rust_detect_borrow_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    borrows = re.findall(r"error\[E(0505|0502|0503|0597|0499)\]", output)
    if borrows:
        return post_tool_context(f"Rust: {len(borrows)} borrow checker errors. Review ownership and lifetimes.")
    return allow()

@registry.hook("rust_check_lifetime_issues")
def rust_check_lifetime_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"error\[E0106\]|missing lifetime specifier|lifetime.*elided", output):
        return post_tool_context("Rust: Missing lifetime annotations. Add explicit lifetimes.")
    return allow()

@registry.hook("rust_detect_unsafe_usage")
def rust_detect_unsafe_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    unsafes = len(re.findall(r"\bunsafe\s*\{", output))
    if unsafes > 2:
        return post_tool_context(f"Rust: {unsafes} unsafe blocks. Minimize and document safety invariants.")
    return allow()

@registry.hook("rust_check_unwrap_usage")
def rust_check_unwrap_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    unwraps = len(re.findall(r"\.(unwrap|expect)\s*\(", output))
    if unwraps > 5:
        return post_tool_context(f"Rust: {unwraps} unwrap()/expect() calls. Use ? operator for better error handling.")
    return allow()

@registry.hook("rust_detect_clippy_warnings")
def rust_detect_clippy_warnings(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bcargo\s+clippy\b", cmd) or not output: return allow()
    warnings = re.findall(r"warning:.*\n.*#\[warn\(clippy::(\w+)\)\]", output)
    if warnings:
        from collections import Counter
        top = Counter(warnings).most_common(5)
        return post_tool_context(f"Clippy: {', '.join(f'{k}({v})' for k,v in top)}")
    return allow()

@registry.hook("rust_check_dead_code")
def rust_check_dead_code(data):
    output = get_command_output(data)
    if not output: return allow()
    dead = re.findall(r"warning:.*never (used|read|constructed)", output)
    if len(dead) > 3:
        return post_tool_context(f"Rust: {len(dead)} dead code warnings. Remove unused items.")
    return allow()

@registry.hook("rust_detect_panic_paths")
def rust_detect_panic_paths(data):
    output = get_command_output(data)
    if not output: return allow()
    panics = len(re.findall(r"\b(panic!|todo!|unimplemented!)\b", output))
    if panics > 2:
        return post_tool_context(f"Rust: {panics} panic!/todo!/unimplemented! macros. Replace before production.")
    return allow()

@registry.hook("rust_check_error_handling")
def rust_check_error_handling(data):
    output = get_command_output(data)
    if not output: return allow()
    unwraps = len(re.findall(r"\.unwrap\(\)", output))
    questions = len(re.findall(r"\?;", output))
    if unwraps > questions and unwraps > 3:
        return post_tool_context(f"Rust: More unwrap() ({unwraps}) than ? operator ({questions}). Prefer ? for error propagation.")
    return allow()

@registry.hook("rust_detect_memory_issues")
def rust_detect_memory_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"thread.*panicked.*stack overflow|SIGABRT|memory allocation.*failed", output):
        return post_tool_context("Rust: Memory/stack issue. Check recursion depth and allocation sizes.")
    return allow()

@registry.hook("rust_check_dependency_conflicts")
def rust_check_dependency_conflicts(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"failed to select a version|conflicting.*requirements|versions.*incompatible", output, re.IGNORECASE):
        return post_tool_context("Rust: Dependency version conflict. Check Cargo.toml version constraints.")
    return allow()

@registry.hook("rust_detect_build_warnings")
def rust_detect_build_warnings(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bcargo\b", cmd) or not output: return allow()
    warnings = len(re.findall(r"^warning:", output, re.MULTILINE))
    errors = len(re.findall(r"^error", output, re.MULTILINE))
    if warnings > 5 or errors > 0:
        return post_tool_context(f"Rust build: {errors} errors, {warnings} warnings")
    return allow()

@registry.hook("rust_check_edition_compatibility")
def rust_check_edition_compatibility(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"edition.*2015|requires edition 20(18|21|24)", output):
        return post_tool_context("Rust: Edition compatibility issue. Update edition in Cargo.toml.")
    return allow()

@registry.hook("rust_detect_macro_errors")
def rust_detect_macro_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"error.*macro|no rules expected|unexpected token in macro", output):
        return post_tool_context("Rust: Macro expansion error. Check macro syntax and arguments.")
    return allow()

@registry.hook("rust_check_test_results")
def rust_check_test_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bcargo\s+test\b", cmd) or not output: return allow()
    match = re.search(r"test result:.*?(\d+) passed.*?(\d+) failed.*?(\d+) ignored", output)
    if match:
        return post_tool_context(f"Cargo test: {match.group(1)} passed, {match.group(2)} failed, {match.group(3)} ignored")
    return allow()

@registry.hook("rust_detect_doc_warnings")
def rust_detect_doc_warnings(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"warning.*missing documentation|warn.*missing_docs", output):
        count = len(re.findall(r"missing documentation", output))
        return post_tool_context(f"Rust: {count} missing documentation warnings")
    return allow()

@registry.hook("rust_check_feature_flags")
def rust_check_feature_flags(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"feature.*not found|requires.*feature.*flag", output):
        return post_tool_context("Rust: Feature flag required. Enable in Cargo.toml [features] or with --features.")
    return allow()

@registry.hook("rust_detect_async_issues")
def rust_detect_async_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Send.*not satisfied|Sync.*not satisfied|future.*not.*Send", output):
        return post_tool_context("Rust: Async Send/Sync bound issue. Check for non-Send types across await points.")
    return allow()

if __name__ == "__main__":
    registry.main()
