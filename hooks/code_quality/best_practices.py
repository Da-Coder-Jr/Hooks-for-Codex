#!/usr/bin/env python3
"""
Code Quality: Best Practices hooks for Codex.
25 PostToolUse hooks checking coding best practices.
"""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()

@registry.hook("check_error_handling")
def check_error_handling(data):
    output = get_command_output(data)
    if not output: return allow()
    empty_catch = re.findall(r"except\s*:\s*\n\s*pass\b|catch\s*\([^)]*\)\s*\{\s*\}", output)
    if empty_catch:
        return post_tool_context(f"Best Practice: {len(empty_catch)} empty catch/except blocks (swallowing errors)")
    return allow()

@registry.hook("check_resource_cleanup")
def check_resource_cleanup(data):
    output = get_command_output(data)
    if not output: return allow()
    opens = len(re.findall(r"\bopen\s*\(", output))
    with_stmt = len(re.findall(r"\bwith\s+open\s*\(", output))
    if opens > with_stmt + 2:
        return post_tool_context(f"Best Practice: {opens - with_stmt} file opens without context manager (use 'with')")
    return allow()

@registry.hook("check_null_checks")
def check_null_checks(data):
    output = get_command_output(data)
    if not output: return allow()
    unsafe = re.findall(r"\w+\.\w+\.\w+\b(?!\s*[!=]=)", output)
    if len(unsafe) > 10:
        return post_tool_context("Best Practice: Many chained property accesses without null checks (use optional chaining)")
    return allow()

@registry.hook("check_type_coercion")
def check_type_coercion(data):
    output = get_command_output(data)
    if not output: return allow()
    loose = re.findall(r"[^!=]==[^=]", output)
    if len(loose) > 3 and re.search(r"\b(const|let|var|function)\b", output):
        return post_tool_context(f"Best Practice: {len(loose)} loose equality (==) in JS - use strict equality (===)")
    return allow()

@registry.hook("check_var_usage")
def check_var_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    vars_found = re.findall(r"\bvar\s+\w+", output)
    if vars_found and re.search(r"\b(const|let)\b", output):
        return post_tool_context(f"Best Practice: {len(vars_found)} 'var' declarations found (use const/let)")
    return allow()

@registry.hook("check_eval_usage")
def check_eval_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    evals = re.findall(r"\beval\s*\(", output)
    if evals:
        return post_tool_context(f"Best Practice: {len(evals)} eval() calls detected (security risk)")
    return allow()

@registry.hook("check_exec_usage")
def check_exec_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    execs = re.findall(r"\bexec\s*\(", output)
    if execs:
        return post_tool_context(f"Best Practice: {len(execs)} exec() calls detected (security risk)")
    return allow()

@registry.hook("check_global_variables")
def check_global_variables(data):
    output = get_command_output(data)
    if not output: return allow()
    globals_found = re.findall(r"^\s*global\s+\w+", output, re.MULTILINE)
    globals_found += re.findall(r"^\s*window\.\w+\s*=", output, re.MULTILINE)
    if len(globals_found) > 2:
        return post_tool_context(f"Best Practice: {len(globals_found)} global variables (minimize global state)")
    return allow()

@registry.hook("check_mutable_defaults")
def check_mutable_defaults(data):
    output = get_command_output(data)
    if not output: return allow()
    mutable = re.findall(r"def\s+\w+\s*\([^)]*(?:\[\]|\{\}|dict\(\)|list\(\))\s*[,)]", output)
    if mutable:
        return post_tool_context(f"Best Practice: {len(mutable)} mutable default arguments in Python (use None)")
    return allow()

@registry.hook("check_bare_except")
def check_bare_except(data):
    output = get_command_output(data)
    if not output: return allow()
    bare = re.findall(r"^\s*except\s*:", output, re.MULTILINE)
    if bare:
        return post_tool_context(f"Best Practice: {len(bare)} bare except clauses (catch specific exceptions)")
    return allow()

@registry.hook("check_assertion_in_prod")
def check_assertion_in_prod(data):
    output = get_command_output(data)
    if not output: return allow()
    asserts = re.findall(r"^\s*assert\s+", output, re.MULTILINE)
    if len(asserts) > 5:
        return post_tool_context(f"Best Practice: {len(asserts)} assert statements (disabled with -O flag in production)")
    return allow()

@registry.hook("check_hardcoded_paths")
def check_hardcoded_paths(data):
    output = get_command_output(data)
    if not output: return allow()
    hardcoded = re.findall(r'["\']/(usr|home|Users|var|opt|etc)/[^"\']+["\']', output)
    if len(hardcoded) > 2:
        return post_tool_context(f"Best Practice: {len(hardcoded)} hardcoded absolute paths (use config/env vars)")
    return allow()

@registry.hook("check_hardcoded_credentials")
def check_hardcoded_credentials(data):
    output = get_command_output(data)
    if not output: return allow()
    creds = re.findall(r'(?i)(password|passwd|secret|api_key)\s*=\s*["\'][^"\']{4,}["\']', output)
    if creds:
        return post_tool_context(f"Best Practice: {len(creds)} hardcoded credentials detected (use env vars)")
    return allow()

@registry.hook("check_sql_string_format")
def check_sql_string_format(data):
    output = get_command_output(data)
    if not output: return allow()
    unsafe_sql = re.findall(r'(?i)(SELECT|INSERT|UPDATE|DELETE).*["\'].*%[sd]|\.format\(', output)
    unsafe_sql += re.findall(r"(?i)f['\"].*(?:SELECT|INSERT|UPDATE|DELETE).*\{", output)
    if unsafe_sql:
        return post_tool_context(f"Best Practice: {len(unsafe_sql)} SQL queries built with string formatting (use parameterized queries)")
    return allow()

@registry.hook("check_insecure_random")
def check_insecure_random(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"\bMath\.random\(\)", output) or re.search(r"\brandom\.random\(\)", output):
        if re.search(r"(?i)(token|secret|password|key|salt|nonce|csrf)", output):
            return post_tool_context("Best Practice: Insecure random for security purpose (use crypto.getRandomValues/secrets)")
    return allow()

@registry.hook("check_race_conditions")
def check_race_conditions(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"if\s+.*os\.path\.exists.*\n.*open\(", output, re.MULTILINE):
        return post_tool_context("Best Practice: TOCTOU race condition (check-then-use pattern)")
    return allow()

@registry.hook("check_memory_leaks")
def check_memory_leaks(data):
    output = get_command_output(data)
    if not output: return allow()
    add_listeners = len(re.findall(r"addEventListener\(", output))
    remove_listeners = len(re.findall(r"removeEventListener\(", output))
    if add_listeners > remove_listeners + 2:
        return post_tool_context(f"Best Practice: {add_listeners - remove_listeners} event listeners added without removal (memory leak risk)")
    return allow()

@registry.hook("check_infinite_loops")
def check_infinite_loops(data):
    output = get_command_output(data)
    if not output: return allow()
    whiles = re.findall(r"while\s+(?:True|true|1)\s*[:{]", output)
    for w in whiles:
        ctx = output[output.index(w):output.index(w)+500]
        if "break" not in ctx and "return" not in ctx:
            return post_tool_context("Best Practice: while True without break/return (potential infinite loop)")
    return allow()

@registry.hook("check_dead_code")
def check_dead_code(data):
    output = get_command_output(data)
    if not output: return allow()
    dead = re.findall(r"(return\s+[^;\n]+[;\n])\s*((?!except|catch|finally|else|elif)\s*\w)", output)
    if len(dead) > 1:
        return post_tool_context(f"Best Practice: Potential dead code after return statements")
    return allow()

@registry.hook("check_unused_variables")
def check_unused_variables(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)unused variable|assigned.*never used|declared but.*not used", output):
        unused = re.findall(r"'(\w+)'.*(?:unused|never used|not used)", output, re.IGNORECASE)
        return post_tool_context(f"Best Practice: Unused variables: {', '.join(set(unused[:10]))}")
    return allow()

@registry.hook("check_single_letter_vars")
def check_single_letter_vars(data):
    output = get_command_output(data)
    if not output: return allow()
    assignments = re.findall(r"\b([a-z])\s*=\s*(?!.*\bfor\b)", output)
    non_loop = [v for v in assignments if v not in ("i", "j", "k", "x", "y", "z", "e", "_")]
    if len(non_loop) > 3:
        return post_tool_context(f"Best Practice: Single-letter variables outside loops: {', '.join(set(non_loop))}")
    return allow()

@registry.hook("check_boolean_trap")
def check_boolean_trap(data):
    output = get_command_output(data)
    if not output: return allow()
    calls = re.findall(r"\w+\([^)]*(?:True|False|true|false)\s*,\s*(?:True|False|true|false)[^)]*\)", output)
    if calls:
        return post_tool_context(f"Best Practice: {len(calls)} function calls with multiple boolean args (use named params)")
    return allow()

@registry.hook("check_yoda_conditions")
def check_yoda_conditions(data):
    output = get_command_output(data)
    if not output: return allow()
    yoda = re.findall(r"if\s+['\"\d]\S*\s*===?\s*\w+", output)
    if len(yoda) > 2:
        return post_tool_context(f"Best Practice: {len(yoda)} Yoda conditions (constant on left side)")
    return allow()

@registry.hook("check_nested_ternary")
def check_nested_ternary(data):
    output = get_command_output(data)
    if not output: return allow()
    nested = re.findall(r"\?[^:]+\?[^:]+:", output)
    if nested:
        return post_tool_context(f"Best Practice: {len(nested)} nested ternary operators (use if/else for readability)")
    return allow()

@registry.hook("check_return_consistency")
def check_return_consistency(data):
    output = get_command_output(data)
    if not output: return allow()
    funcs = re.findall(r"def\s+(\w+)\s*\([^)]*\).*?(?=\ndef\s|\Z)", output, re.DOTALL)
    for func_body in funcs[:10]:
        returns = re.findall(r"\breturn\b\s*(.*?)$", func_body, re.MULTILINE)
        has_value = any(r.strip() for r in returns)
        has_bare = any(not r.strip() for r in returns)
        if has_value and has_bare:
            return post_tool_context("Best Practice: Function has inconsistent returns (some with value, some without)")
    return allow()


if __name__ == "__main__":
    registry.main()
