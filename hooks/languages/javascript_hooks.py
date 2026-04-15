#!/usr/bin/env python3
"""
Language-Specific: JavaScript hooks for Codex.
20 PostToolUse hooks for JavaScript/Node.js development.
"""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()

@registry.hook("js_detect_syntax_errors")
def js_detect_syntax_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"SyntaxError: (Unexpected token|Missing|Unterminated|Invalid)", output):
        match = re.search(r"SyntaxError:\s*(.*?)$", output, re.MULTILINE)
        return post_tool_context(f"JS SyntaxError: {match.group(1) if match else 'check output'}")
    return allow()

@registry.hook("js_check_node_version")
def js_check_node_version(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"The engine .node. is incompatible", output):
        return post_tool_context("JS: Node.js version incompatible with package requirements. Check .nvmrc/package.json engines.")
    return allow()

@registry.hook("js_detect_runtime_errors")
def js_detect_runtime_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    errors = {"TypeError": [], "ReferenceError": [], "RangeError": []}
    for err_type in errors:
        matches = re.findall(rf"{err_type}:\s*(.*?)$", output, re.MULTILINE)
        errors[err_type] = matches
    found = {k: v for k, v in errors.items() if v}
    if found:
        summary = "; ".join(f"{k}: {v[0]}" for k, v in found.items())
        return post_tool_context(f"JS Runtime: {summary}")
    return allow()

@registry.hook("js_check_package_vulnerabilities")
def js_check_package_vulnerabilities(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bnpm\s+audit\b", cmd) or not output: return allow()
    critical = len(re.findall(r"\bcritical\b", output, re.IGNORECASE))
    high = len(re.findall(r"\bhigh\b", output, re.IGNORECASE))
    moderate = len(re.findall(r"\bmoderate\b", output, re.IGNORECASE))
    if critical or high:
        return post_tool_context(f"npm audit: {critical} critical, {high} high, {moderate} moderate vulnerabilities")
    return allow()

@registry.hook("js_detect_memory_leaks")
def js_detect_memory_leaks(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"FATAL ERROR:.*heap|JavaScript heap out of memory", output):
        return post_tool_context("JS: Heap out of memory. Increase with --max-old-space-size or fix memory leak.")
    return allow()

@registry.hook("js_check_event_loop_blocking")
def js_check_event_loop_blocking(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"event loop.*block|blocked.*event loop|MaxListenersExceededWarning", output, re.IGNORECASE):
        return post_tool_context("JS: Event loop blocking or MaxListeners warning - check for sync operations")
    return allow()

@registry.hook("js_detect_unhandled_rejections")
def js_detect_unhandled_rejections(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"UnhandledPromiseRejection|unhandled promise rejection", output, re.IGNORECASE):
        return post_tool_context("JS: Unhandled Promise rejection. Add .catch() or try/catch with async/await.")
    return allow()

@registry.hook("js_check_deprecated_apis")
def js_check_deprecated_apis(data):
    output = get_command_output(data)
    if not output: return allow()
    deps = re.findall(r"\[DEP\d+\]\s*DeprecationWarning:\s*(.*?)$", output, re.MULTILINE)
    if deps:
        return post_tool_context(f"JS Deprecations: {'; '.join(set(deps[:3]))}")
    return allow()

@registry.hook("js_detect_circular_deps")
def js_detect_circular_deps(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Circular dependency|circular require", output, re.IGNORECASE):
        return post_tool_context("JS: Circular dependency detected. Restructure imports to break the cycle.")
    return allow()

@registry.hook("js_check_module_resolution")
def js_check_module_resolution(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"Cannot find module '([^']+)'", output)
    if match:
        return post_tool_context(f"JS: Cannot find module '{match.group(1)}'. Run npm install or check import path.")
    return allow()

@registry.hook("js_detect_prototype_pollution")
def js_detect_prototype_pollution(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"__proto__|Object\.prototype\.\w+\s*=|constructor\[.prototype.\]", output):
        return post_tool_context("JS Security: Prototype pollution pattern detected")
    return allow()

@registry.hook("js_check_regex_redos")
def js_check_regex_redos(data):
    output = get_command_output(data)
    if not output: return allow()
    complex_regex = re.findall(r"/([^/]+)\+[^/]*\1\+/", output)
    if complex_regex:
        return post_tool_context("JS Security: Potentially vulnerable regex (ReDoS) with repeated quantifiers")
    return allow()

@registry.hook("js_detect_callback_errors")
def js_detect_callback_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"callback is not a function|cb is not a function", output):
        return post_tool_context("JS: Callback not a function error. Check function argument passing.")
    return allow()

@registry.hook("js_check_package_lock_sync")
def js_check_package_lock_sync(data):
    cmd, output = get_command(data), get_command_output(data)
    if not output: return allow()
    if re.search(r"\bnpm\s+install\b", cmd):
        if re.search(r"added \d+ packages|removed \d+ packages|updated \d+ packages", output):
            return post_tool_context("JS: Packages changed. Ensure package-lock.json is committed.")
    return allow()

@registry.hook("js_detect_test_failures")
def js_detect_test_failures(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\b(jest|mocha|vitest)\b", cmd) or not output: return allow()
    match = re.search(r"Tests?:\s*(\d+)\s*failed.*?(\d+)\s*passed", output)
    if match:
        return post_tool_context(f"JS Tests: {match.group(1)} failed, {match.group(2)} passed")
    match = re.search(r"(\d+)\s*passing.*?(\d+)\s*failing", output)
    if match:
        return post_tool_context(f"JS Tests: {match.group(1)} passing, {match.group(2)} failing")
    return allow()

@registry.hook("js_check_bundle_size")
def js_check_bundle_size(data):
    cmd, output = get_command(data), get_command_output(data)
    if not output: return allow()
    sizes = re.findall(r"(\d+(?:\.\d+)?)\s*(kB|MB|KB)\s*(?:│|\|)", output)
    large = [(s, u) for s, u in sizes if (u in ("MB",) and float(s) > 1) or (u in ("kB", "KB") and float(s) > 500)]
    if large:
        return post_tool_context(f"JS Bundle: {len(large)} large chunks detected. Consider code splitting.")
    return allow()

@registry.hook("js_detect_deprecation_warnings")
def js_detect_deprecation_warnings(data):
    output = get_command_output(data)
    if not output: return allow()
    deps = re.findall(r"npm warn deprecated (\S+)", output)
    if deps:
        return post_tool_context(f"JS: {len(deps)} deprecated packages: {', '.join(set(deps[:5]))}")
    return allow()

@registry.hook("js_check_eslint_disable")
def js_check_eslint_disable(data):
    output = get_command_output(data)
    if not output: return allow()
    disables = re.findall(r"eslint-disable(?!-next-line)", output)
    if len(disables) > 3:
        return post_tool_context(f"JS: {len(disables)} eslint-disable comments (consider fixing the issues)")
    return allow()

@registry.hook("js_detect_security_vulnerabilities")
def js_detect_security_vulnerabilities(data):
    output = get_command_output(data)
    if not output: return allow()
    issues = []
    if re.search(r"\beval\s*\(", output): issues.append("eval()")
    if re.search(r"\.innerHTML\s*=", output): issues.append("innerHTML assignment")
    if re.search(r"document\.write\s*\(", output): issues.append("document.write()")
    if re.search(r"dangerouslySetInnerHTML", output): issues.append("dangerouslySetInnerHTML")
    if issues:
        return post_tool_context(f"JS Security: {'; '.join(issues)}")
    return allow()

@registry.hook("js_check_peer_dependencies")
def js_check_peer_dependencies(data):
    output = get_command_output(data)
    if not output: return allow()
    peers = re.findall(r"npm warn.*peer dep.*? (\S+@\S+)", output)
    if peers:
        return post_tool_context(f"JS: {len(peers)} peer dependency warnings: {', '.join(set(peers[:5]))}")
    return allow()


if __name__ == "__main__":
    registry.main()
