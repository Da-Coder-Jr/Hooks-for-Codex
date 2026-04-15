#!/usr/bin/env python3
"""Error Handling: Error pattern detection hooks for Codex. 20 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("detect_bare_except")
def detect_bare_except(data):
    output = get_command_output(data)
    if not output: return allow()
    bare = re.findall(r"except:\s*$|except\s+Exception\s*:", output, re.MULTILINE)
    if len(bare) > 2:
        return post_tool_context(f"Error handling: {len(bare)} bare/broad except clauses. Catch specific exceptions.")
    return allow()

@registry.hook("detect_empty_catch")
def detect_empty_catch(data):
    output = get_command_output(data)
    if not output: return allow()
    empty = re.findall(r"catch\s*\([^)]*\)\s*\{\s*\}|except.*:\s*\n\s*pass\s*$", output, re.MULTILINE)
    if empty:
        return post_tool_context(f"Error handling: {len(empty)} empty catch/except blocks. Log or handle errors properly.")
    return allow()

@registry.hook("detect_error_swallowing")
def detect_error_swallowing(data):
    output = get_command_output(data)
    if not output: return allow()
    patterns = re.findall(r"catch\s*\(.*?\)\s*\{\s*(?:return|continue)\s*;?\s*\}|except.*:\s*\n\s*(?:return|continue)", output, re.MULTILINE)
    if patterns:
        return post_tool_context(f"Error handling: {len(patterns)} silently swallowed errors. At minimum, log the error.")
    return allow()

@registry.hook("check_error_message_quality")
def check_error_message_quality(data):
    output = get_command_output(data)
    if not output: return allow()
    generic = re.findall(r"raise\s+Exception\(['\"](?:error|something went wrong|an error occurred|failed)['\"]", output, re.IGNORECASE)
    if len(generic) > 2:
        return post_tool_context(f"Error handling: {len(generic)} generic error messages. Provide specific, actionable error info.")
    return allow()

@registry.hook("detect_untyped_throws")
def detect_untyped_throws(data):
    output = get_command_output(data)
    if not output: return allow()
    throw_string = re.findall(r"throw\s+['\"]|throw\s+new\s+Error\(\s*\)", output)
    if len(throw_string) > 2:
        return post_tool_context(f"Error handling: {len(throw_string)} throws with string/empty errors. Use typed Error classes.")
    return allow()

@registry.hook("check_error_propagation")
def check_error_propagation(data):
    output = get_command_output(data)
    if not output: return allow()
    re_raises = re.findall(r"raise\s+\w+Error|throw\s+new\s+\w+Error", output)
    catches = re.findall(r"except\s+\w+|catch\s*\(", output)
    if catches and not re_raises and len(catches) > 3:
        return post_tool_context("Error handling: Many catch blocks but no re-raises. Errors may be lost in the chain.")
    return allow()

@registry.hook("detect_callback_error_handling")
def detect_callback_error_handling(data):
    output = get_command_output(data)
    if not output: return allow()
    callbacks = re.findall(r"function\s*\(\s*err\s*[,)]|(?:err|error)\s*=>\s*\{", output)
    ignored = re.findall(r"function\s*\(\s*err\s*[,)].*?\{(?!\s*if\s*\(\s*err)", output, re.DOTALL)
    if len(ignored) > 2:
        return post_tool_context("Error handling: Callback errors not checked. Always handle err parameter in Node.js callbacks.")
    return allow()

@registry.hook("check_promise_catch")
def check_promise_catch(data):
    output = get_command_output(data)
    if not output: return allow()
    thens = len(re.findall(r"\.then\(", output))
    catches = len(re.findall(r"\.catch\(", output))
    if thens > catches + 3:
        return post_tool_context(f"Error handling: {thens} .then() but only {catches} .catch(). Add error handling to promise chains.")
    return allow()

@registry.hook("detect_async_await_try_catch")
def detect_async_await_try_catch(data):
    output = get_command_output(data)
    if not output: return allow()
    async_funcs = re.findall(r"async\s+(?:def|function)\s+\w+", output)
    awaits = len(re.findall(r"\bawait\b", output))
    try_blocks = len(re.findall(r"\btry\s*[:{]", output))
    if awaits > try_blocks + 3 and awaits > 5:
        return post_tool_context(f"Error handling: {awaits} awaits with only {try_blocks} try blocks. Wrap await in try/catch.")
    return allow()

@registry.hook("check_error_boundary_usage")
def check_error_boundary_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"componentDidCatch|getDerivedStateFromError|ErrorBoundary", output):
        return allow()
    if re.search(r"React\.|from\s+['\"]react['\"]", output) and re.search(r"render\(|return\s*\(", output):
        components = len(re.findall(r"(?:function|class)\s+\w+.*(?:React|Component|return.*<)", output))
        if components > 3:
            return post_tool_context("Error handling: React components without ErrorBoundary. Add error boundaries for graceful degradation.")
    return allow()

@registry.hook("detect_exit_code_ignored")
def detect_exit_code_ignored(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"subprocess\.call|os\.system|child_process\.exec", output):
        if not re.search(r"returncode|exit_code|exitCode|stderr|check=True|check_call", output):
            return post_tool_context("Error handling: Subprocess exit code not checked. Use check=True or check returncode.")
    return allow()

@registry.hook("check_retry_logic")
def check_retry_logic(data):
    output = get_command_output(data)
    if not output: return allow()
    retries = re.findall(r"retry|retries|max_attempts|backoff", output, re.IGNORECASE)
    if retries:
        if not re.search(r"exponential|backoff|jitter|delay\s*\*", output, re.IGNORECASE):
            return post_tool_context("Error handling: Retry without backoff/jitter. Use exponential backoff to avoid thundering herd.")
    return allow()

@registry.hook("detect_error_logging_without_context")
def detect_error_logging_without_context(data):
    output = get_command_output(data)
    if not output: return allow()
    log_err = re.findall(r"(?:console\.error|logger\.error|logging\.error)\s*\(\s*['\"]", output)
    log_with_err = re.findall(r"(?:console\.error|logger\.error|logging\.error)\s*\(.*?(?:err|error|exc|exception|e\b)", output)
    if len(log_err) > len(log_with_err) + 2:
        return post_tool_context("Error handling: Error logs without error objects. Include the error for stack traces.")
    return allow()

@registry.hook("check_http_error_handling")
def check_http_error_handling(data):
    output = get_command_output(data)
    if not output: return allow()
    fetches = re.findall(r"fetch\(|axios\.|requests\.|http\.get|http\.post", output)
    error_checks = re.findall(r"response\.ok|status.*[<>=].*[245]\d\d|raise_for_status|status_code", output)
    if len(fetches) > len(error_checks) + 2 and len(fetches) > 3:
        return post_tool_context("Error handling: HTTP calls without status checks. Check response.ok or status codes.")
    return allow()

@registry.hook("detect_finally_block_issues")
def detect_finally_block_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"finally\s*[:{].*?return\b", output, re.DOTALL):
        return post_tool_context("Error handling: Return in finally block can mask exceptions. Move return outside finally.")
    return allow()

@registry.hook("check_error_serialization")
def check_error_serialization(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"JSON\.stringify\(\s*(?:err|error)\s*\)", output):
        return post_tool_context("Error handling: JSON.stringify(error) loses message/stack. Use error.message and error.stack.")
    return allow()

@registry.hook("detect_error_in_constructor")
def detect_error_in_constructor(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"constructor\s*\([^)]*\)\s*\{[\s\S]*?throw\s+new", output):
        return post_tool_context("Error handling: Throwing in constructor leaves partially initialized object. Use factory method instead.")
    return allow()

@registry.hook("check_custom_error_classes")
def check_custom_error_classes(data):
    output = get_command_output(data)
    if not output: return allow()
    custom_errors = re.findall(r"class\s+(\w+Error)\s+extends\s+Error", output)
    if custom_errors:
        for err_class in custom_errors:
            if not re.search(rf"class\s+{err_class}.*?this\.name\s*=", output, re.DOTALL):
                return post_tool_context(f"Error handling: Custom error {err_class} missing this.name. Set name for proper error identification.")
    return allow()

@registry.hook("detect_window_onerror")
def detect_window_onerror(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"window\.onerror|window\.addEventListener\(['\"]error", output):
        if not re.search(r"window\.addEventListener\(['\"]unhandledrejection", output):
            return post_tool_context("Error handling: Global error handler but no unhandledrejection handler. Add both.")
    return allow()

@registry.hook("check_error_recovery")
def check_error_recovery(data):
    output = get_command_output(data)
    if not output: return allow()
    process_exit = re.findall(r"process\.exit|os\._exit|sys\.exit|System\.exit", output)
    if len(process_exit) > 2:
        return post_tool_context(f"Error handling: {len(process_exit)} hard exits. Prefer graceful shutdown with cleanup.")
    return allow()

if __name__ == "__main__":
    registry.main()
