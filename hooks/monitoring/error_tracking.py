#!/usr/bin/env python3
"""Monitoring: Error tracking hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("detect_unhandled_promise_rejection")
def detect_unhandled_promise_rejection(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"UnhandledPromiseRejectionWarning|unhandledRejection|Unhandled promise rejection", output):
        match = re.search(r"(?:UnhandledPromiseRejectionWarning|rejection):\s*(.*?)$", output, re.MULTILINE)
        return post_tool_context(f"Error: Unhandled promise rejection: {match.group(1)[:80] if match else 'check async code'}")
    return allow()

@registry.hook("detect_uncaught_exception")
def detect_uncaught_exception(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"uncaughtException|Uncaught.*Error|unhandled exception", output, re.IGNORECASE):
        match = re.search(r"(?:Uncaught|uncaughtException).*?:\s*(.*?)$", output, re.MULTILINE)
        return post_tool_context(f"Error: Uncaught exception: {match.group(1)[:80] if match else 'add error handler'}")
    return allow()

@registry.hook("detect_python_exception")
def detect_python_exception(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"(\w+Error|\w+Exception):\s*(.*?)$", output, re.MULTILINE)
    if match and re.search(r"Traceback", output):
        return post_tool_context(f"Error: Python {match.group(1)}: {match.group(2)[:80]}")
    return allow()

@registry.hook("detect_java_exception")
def detect_java_exception(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"(?:java\.\w+\.)?(\w+Exception|\w+Error):\s*(.*?)$", output, re.MULTILINE)
    if match and re.search(r"\bat\s+\w+\.\w+\(", output):
        return post_tool_context(f"Error: Java {match.group(1)}: {match.group(2)[:80]}")
    return allow()

@registry.hook("detect_rust_panic")
def detect_rust_panic(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"thread.*panicked at", output):
        match = re.search(r"panicked at\s+['\"]?(.*?)['\"]?,\s*(\S+:\d+)", output)
        if match:
            return post_tool_context(f"Error: Rust panic: {match.group(1)[:60]} at {match.group(2)}")
    return allow()

@registry.hook("detect_go_panic")
def detect_go_panic(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"goroutine \d+.*:\npanic:", output) or re.search(r"panic:.*\ngoroutine", output):
        match = re.search(r"panic:\s*(.*?)$", output, re.MULTILINE)
        return post_tool_context(f"Error: Go panic: {match.group(1)[:80] if match else 'check goroutine stack'}")
    return allow()

@registry.hook("detect_segmentation_fault")
def detect_segmentation_fault(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Segmentation fault|SIGSEGV|signal 11|core dumped", output):
        return post_tool_context("Error: Segmentation fault. Check null pointer dereference, buffer overflow, or use-after-free.")
    return allow()

@registry.hook("detect_assertion_failure")
def detect_assertion_failure(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"AssertionError|assert.*failed|assertion.*failure|SIGABRT", output, re.IGNORECASE):
        match = re.search(r"(?:AssertionError|assert.*failed):\s*(.*?)$", output, re.MULTILINE | re.IGNORECASE)
        return post_tool_context(f"Error: Assertion failed: {match.group(1)[:80] if match else 'check invariant'}")
    return allow()

@registry.hook("detect_permission_error")
def detect_permission_error(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"PermissionError|EACCES|Permission denied|Access is denied|EPERM", output):
        match = re.search(r"(?:PermissionError|EACCES).*?['\"](\S+)['\"]", output)
        return post_tool_context(f"Error: Permission denied{f' for {match.group(1)}' if match else ''}. Check file/directory permissions.")
    return allow()

@registry.hook("detect_import_module_error")
def detect_import_module_error(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"ModuleNotFoundError|ImportError|Cannot find module|Module not found", output):
        match = re.search(r"(?:ModuleNotFoundError|Cannot find module).*?['\"](\S+)['\"]", output)
        module = match.group(1) if match else "unknown"
        return post_tool_context(f"Error: Module not found: {module}. Install the package or check import path.")
    return allow()

@registry.hook("detect_type_error")
def detect_type_error(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"TypeError:\s*(.*?)$", output, re.MULTILINE)
    if match:
        return post_tool_context(f"Error: TypeError: {match.group(1)[:80]}")
    return allow()

@registry.hook("detect_network_error")
def detect_network_error(data):
    output = get_command_output(data)
    if not output: return allow()
    net_errors = []
    if re.search(r"ECONNREFUSED|Connection refused", output): net_errors.append("connection refused")
    if re.search(r"ENOTFOUND|DNS.*not found|getaddrinfo.*ENOTFOUND", output): net_errors.append("DNS resolution failed")
    if re.search(r"ETIMEDOUT|connect ETIMEDOUT|request.*timed out", output): net_errors.append("connection timeout")
    if re.search(r"ECONNRESET|Connection reset", output): net_errors.append("connection reset")
    if net_errors:
        return post_tool_context(f"Error: Network: {', '.join(net_errors)}")
    return allow()

@registry.hook("detect_database_error")
def detect_database_error(data):
    output = get_command_output(data)
    if not output: return allow()
    db_errors = []
    if re.search(r"OperationalError|connection.*refused.*5432|connection.*refused.*3306", output): db_errors.append("connection failed")
    if re.search(r"IntegrityError|duplicate key|unique constraint", output, re.IGNORECASE): db_errors.append("integrity violation")
    if re.search(r"ProgrammingError|syntax error.*sql|syntax error at or near", output, re.IGNORECASE): db_errors.append("SQL syntax error")
    if re.search(r"deadlock detected|Lock wait timeout", output, re.IGNORECASE): db_errors.append("deadlock")
    if db_errors:
        return post_tool_context(f"Error: Database: {', '.join(db_errors)}")
    return allow()

@registry.hook("detect_file_system_error")
def detect_file_system_error(data):
    output = get_command_output(data)
    if not output: return allow()
    fs_errors = []
    if re.search(r"ENOENT|FileNotFoundError|No such file", output): fs_errors.append("file not found")
    if re.search(r"ENOSPC|No space left", output): fs_errors.append("no disk space")
    if re.search(r"EMFILE|Too many open files", output): fs_errors.append("too many open files")
    if re.search(r"EISDIR|Is a directory", output): fs_errors.append("is a directory")
    if fs_errors:
        return post_tool_context(f"Error: Filesystem: {', '.join(fs_errors)}")
    return allow()

@registry.hook("detect_out_of_memory")
def detect_out_of_memory(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"OutOfMemoryError|MemoryError|JavaScript heap out of memory|ENOMEM|Killed.*signal 9", output):
        return post_tool_context("Error: Out of memory. Increase limits or reduce memory usage.")
    return allow()

if __name__ == "__main__":
    registry.main()
