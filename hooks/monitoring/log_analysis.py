#!/usr/bin/env python3
"""Monitoring: Log analysis hooks for Codex. 20 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("detect_error_log_spike")
def detect_error_log_spike(data):
    output = get_command_output(data)
    if not output: return allow()
    errors = len(re.findall(r"\bERROR\b|\bFATAL\b|\bCRITICAL\b", output))
    if errors > 10:
        return post_tool_context(f"Logs: {errors} error/fatal entries detected. Investigate error spike.")
    return allow()

@registry.hook("detect_stack_trace_in_logs")
def detect_stack_trace_in_logs(data):
    output = get_command_output(data)
    if not output: return allow()
    traces = re.findall(r"Traceback \(most recent|at \w+\.\w+\(\w+\.java:\d+\)|Error:.*\n\s+at\s+", output)
    if traces:
        first = re.search(r"(?:Error|Exception):\s*(.+?)$", output, re.MULTILINE)
        return post_tool_context(f"Logs: Stack trace found: {first.group(1)[:80] if first else 'check logs'}")
    return allow()

@registry.hook("check_log_level_distribution")
def check_log_level_distribution(data):
    output = get_command_output(data)
    if not output: return allow()
    debug = len(re.findall(r"\bDEBUG\b", output))
    info = len(re.findall(r"\bINFO\b", output))
    warn = len(re.findall(r"\bWARN(?:ING)?\b", output))
    error = len(re.findall(r"\bERROR\b", output))
    total = debug + info + warn + error
    if total > 20:
        if debug > total * 0.5:
            return post_tool_context(f"Logs: {debug}/{total} lines are DEBUG. Reduce log verbosity in production.")
        if error > total * 0.3:
            return post_tool_context(f"Logs: {error}/{total} lines are ERROR. High error rate, investigate.")
    return allow()

@registry.hook("detect_sensitive_data_in_logs")
def detect_sensitive_data_in_logs(data):
    output = get_command_output(data)
    if not output: return allow()
    sensitive = []
    if re.search(r"password[=:]\s*\S+|passwd[=:]\s*\S+", output, re.IGNORECASE): sensitive.append("passwords")
    if re.search(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", output): sensitive.append("card numbers")
    if re.search(r"Bearer\s+[A-Za-z0-9._-]{20,}", output): sensitive.append("tokens")
    if re.search(r"AKIA[0-9A-Z]{16}", output): sensitive.append("AWS keys")
    if sensitive:
        return post_tool_context(f"Logs: Sensitive data in logs: {', '.join(sensitive)}. Mask before logging.")
    return allow()

@registry.hook("check_log_format_consistency")
def check_log_format_consistency(data):
    output = get_command_output(data)
    if not output: return allow()
    json_logs = len(re.findall(r"^\{.*\"level\".*\"message\"", output, re.MULTILINE))
    text_logs = len(re.findall(r"^\d{4}-\d{2}-\d{2}.*(?:INFO|ERROR|DEBUG)", output, re.MULTILINE))
    if json_logs > 0 and text_logs > 0:
        return post_tool_context(f"Logs: Mixed formats ({json_logs} JSON, {text_logs} text). Standardize log format.")
    return allow()

@registry.hook("detect_request_errors")
def detect_request_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    status_codes = re.findall(r"\b(4\d{2}|5\d{2})\b", output)
    errors_5xx = [c for c in status_codes if c.startswith("5")]
    errors_4xx = [c for c in status_codes if c.startswith("4")]
    if len(errors_5xx) > 3:
        return post_tool_context(f"Logs: {len(errors_5xx)} server errors (5xx). Check application health.")
    if len(errors_4xx) > 10:
        return post_tool_context(f"Logs: {len(errors_4xx)} client errors (4xx). Check API contract/validation.")
    return allow()

@registry.hook("check_slow_request_logs")
def check_slow_request_logs(data):
    output = get_command_output(data)
    if not output: return allow()
    slow = re.findall(r"(?:response_time|duration|latency|elapsed)[=:\s]+(\d+)\s*ms", output, re.IGNORECASE)
    slow_requests = [int(t) for t in slow if int(t) > 5000]
    if slow_requests:
        avg = sum(slow_requests) // len(slow_requests)
        return post_tool_context(f"Logs: {len(slow_requests)} slow requests (>{5000}ms, avg {avg}ms). Profile endpoints.")
    return allow()

@registry.hook("detect_connection_errors")
def detect_connection_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    conn_errors = re.findall(r"ECONNREFUSED|ECONNRESET|ETIMEDOUT|Connection refused|Connection reset", output)
    if len(conn_errors) > 3:
        return post_tool_context(f"Logs: {len(conn_errors)} connection errors. Check downstream service health.")
    return allow()

@registry.hook("check_disk_space_warnings")
def check_disk_space_warnings(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"No space left|disk.*full|ENOSPC|disk usage.*9[5-9]%|disk usage.*100%", output, re.IGNORECASE):
        return post_tool_context("Logs: Disk space critical. Free space or rotate logs.")
    return allow()

@registry.hook("detect_rate_limit_hits")
def detect_rate_limit_hits(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"429|rate.?limit|too many requests|throttled|quota exceeded", output, re.IGNORECASE):
        return post_tool_context("Logs: Rate limit/throttling detected. Implement backoff or increase limits.")
    return allow()

@registry.hook("check_auth_failures")
def check_auth_failures(data):
    output = get_command_output(data)
    if not output: return allow()
    auth_fails = len(re.findall(r"401|403|authentication failed|unauthorized|forbidden|invalid.*token", output, re.IGNORECASE))
    if auth_fails > 5:
        return post_tool_context(f"Logs: {auth_fails} authentication failures. Possible brute force or misconfigured credentials.")
    return allow()

@registry.hook("detect_deprecation_warnings_in_logs")
def detect_deprecation_warnings_in_logs(data):
    output = get_command_output(data)
    if not output: return allow()
    deps = re.findall(r"DeprecationWarning|deprecated|will be removed", output, re.IGNORECASE)
    if len(deps) > 3:
        return post_tool_context(f"Logs: {len(deps)} deprecation warnings. Update code before breaking changes.")
    return allow()

@registry.hook("check_log_rotation")
def check_log_rotation(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bls\b.*\.log|du\s+-.*log", cmd) or not output: return allow()
    large = re.findall(r"(\S+\.log)\s+.*?(\d+(?:\.\d+)?)\s*(G|M)", output)
    big = [(n, s, u) for n, s, u in large if u == "G" or (u == "M" and float(s) > 500)]
    if big:
        names = ", ".join(f"{n}({s}{u})" for n, s, u in big[:3])
        return post_tool_context(f"Logs: Large log files: {names}. Configure log rotation.")
    return allow()

@registry.hook("detect_crash_loop_in_logs")
def detect_crash_loop_in_logs(data):
    output = get_command_output(data)
    if not output: return allow()
    restarts = re.findall(r"restarting|restart.*service|service.*started|process.*exited.*restarting", output, re.IGNORECASE)
    if len(restarts) > 3:
        return post_tool_context(f"Logs: {len(restarts)} service restarts. Application may be in crash loop.")
    return allow()

@registry.hook("check_correlation_ids")
def check_correlation_ids(data):
    output = get_command_output(data)
    if not output: return allow()
    has_req = re.search(r"request_id|correlation_id|trace_id|x-request-id", output, re.IGNORECASE)
    log_lines = len(re.findall(r"^\d{4}-\d{2}-\d{2}|^\{", output, re.MULTILINE))
    if log_lines > 20 and not has_req:
        return post_tool_context("Logs: No correlation/request IDs. Add for distributed tracing.")
    return allow()

@registry.hook("detect_memory_warnings_in_logs")
def detect_memory_warnings_in_logs(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"heap.*warning|memory.*warning|GC.*overhead|OOM.*warning|low.*memory", output, re.IGNORECASE):
        return post_tool_context("Logs: Memory warnings in logs. Monitor and increase limits or optimize.")
    return allow()

@registry.hook("check_database_connection_pool_logs")
def check_database_connection_pool_logs(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"pool.*exhausted|no available connections|connection.*timeout|waiting for.*connection", output, re.IGNORECASE):
        return post_tool_context("Logs: Database connection pool exhausted. Increase pool size or fix connection leaks.")
    return allow()

@registry.hook("detect_security_events")
def detect_security_events(data):
    output = get_command_output(data)
    if not output: return allow()
    events = []
    if re.search(r"SQL.*injection|SQLi.*detected", output, re.IGNORECASE): events.append("SQLi attempt")
    if re.search(r"XSS.*detected|script.*injection", output, re.IGNORECASE): events.append("XSS attempt")
    if re.search(r"CSRF.*token.*invalid|CSRF.*mismatch", output, re.IGNORECASE): events.append("CSRF violation")
    if events:
        return post_tool_context(f"Logs: Security events: {', '.join(events)}")
    return allow()

@registry.hook("check_unhandled_exception_logs")
def check_unhandled_exception_logs(data):
    output = get_command_output(data)
    if not output: return allow()
    unhandled = re.findall(r"unhandled.*(?:exception|rejection|error)|uncaught.*(?:exception|error)", output, re.IGNORECASE)
    if unhandled:
        return post_tool_context(f"Logs: {len(unhandled)} unhandled exceptions. Add global error handlers.")
    return allow()

@registry.hook("detect_certificate_expiry")
def detect_certificate_expiry(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"certificate.*expir|SSL.*expir|cert.*invalid|CERT_HAS_EXPIRED|unable to verify.*certificate", output, re.IGNORECASE):
        return post_tool_context("Logs: Certificate expiry/validation issue. Renew certificates.")
    return allow()

if __name__ == "__main__":
    registry.main()
