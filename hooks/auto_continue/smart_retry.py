#!/usr/bin/env python3
"""Auto-Continue: Smart retry hooks for Codex. 15 Stop hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, force_continue, get_command, get_command_output
registry = HookRegistry()

@registry.hook("retry_on_network_timeout")
def retry_on_network_timeout(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"ETIMEDOUT|ECONNRESET|socket hang up|network timeout|request timed out", output, re.IGNORECASE):
        return force_continue("Network timeout. Retrying request...")
    return allow()

@registry.hook("retry_on_npm_registry_error")
def retry_on_npm_registry_error(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"npm ERR!.*registry|FETCH_ERROR|npm ERR!.*network|npm ERR!.*ENOTFOUND", output):
        return force_continue("npm registry error. Retrying install...")
    return allow()

@registry.hook("retry_on_pip_download_error")
def retry_on_pip_download_error(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"pip.*Could not fetch|pip.*ConnectionError|Read timed out|HTTPSConnectionPool", output, re.IGNORECASE):
        return force_continue("pip download failed. Retrying with different mirror...")
    return allow()

@registry.hook("retry_on_docker_pull_timeout")
def retry_on_docker_pull_timeout(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"docker\s+pull", cmd) or not output: return allow()
    if re.search(r"timeout|TLS handshake|EOF|connection reset", output, re.IGNORECASE):
        return force_continue("Docker pull timeout. Retrying...")
    return allow()

@registry.hook("retry_on_git_network_error")
def retry_on_git_network_error(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+(push|pull|fetch|clone)\b", cmd) or not output: return allow()
    if re.search(r"Could not resolve host|Connection timed out|early EOF|the remote end hung up", output):
        return force_continue("Git network error. Retrying...")
    return allow()

@registry.hook("retry_on_api_rate_limit")
def retry_on_api_rate_limit(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"429|rate limit|too many requests|Retry-After", output, re.IGNORECASE):
        match = re.search(r"Retry-After:\s*(\d+)", output, re.IGNORECASE)
        wait = match.group(1) if match else "a moment"
        return force_continue(f"Rate limited. Waiting {wait}s and retrying...")
    return allow()

@registry.hook("retry_on_service_unavailable")
def retry_on_service_unavailable(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"503|Service Unavailable|temporarily unavailable|server is busy", output, re.IGNORECASE):
        return force_continue("Service temporarily unavailable. Retrying...")
    return allow()

@registry.hook("retry_on_dns_resolution")
def retry_on_dns_resolution(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"ENOTFOUND|getaddrinfo.*failed|DNS.*resolution.*failed|Temporary failure in name resolution", output):
        return force_continue("DNS resolution failed. Retrying...")
    return allow()

@registry.hook("retry_on_ssl_handshake")
def retry_on_ssl_handshake(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"SSL.*handshake.*failed|UNABLE_TO_VERIFY|certificate.*error|CERT_HAS_EXPIRED", output, re.IGNORECASE):
        return force_continue("SSL handshake error. Retrying with fallback...")
    return allow()

@registry.hook("retry_on_cargo_fetch")
def retry_on_cargo_fetch(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bcargo\b", cmd) or not output: return allow()
    if re.search(r"failed to download|Unable to update registry|network failure|spurious network error", output):
        return force_continue("Cargo registry fetch failed. Retrying...")
    return allow()

@registry.hook("retry_on_go_proxy")
def retry_on_go_proxy(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgo\s+(get|mod)\b", cmd) or not output: return allow()
    if re.search(r"GOPROXY|no matching versions|connection refused.*proxy|i/o timeout", output):
        return force_continue("Go proxy error. Retrying with GOPROXY=direct...")
    return allow()

@registry.hook("retry_on_heap_oom_build")
def retry_on_heap_oom_build(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"JavaScript heap out of memory|ENOMEM|Allocation failed", output):
        return force_continue("Build ran out of memory. Retrying with increased heap size...")
    return allow()

@registry.hook("retry_on_file_lock")
def retry_on_file_lock(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"EBUSY|resource busy|lock.*held|Another process|Could not get lock|File is locked", output, re.IGNORECASE):
        return force_continue("File lock contention. Waiting and retrying...")
    return allow()

@registry.hook("retry_on_stale_index")
def retry_on_stale_index(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"index\.lock|\.git/index\.lock|Unable to create.*lock", output):
        return force_continue("Git index lock exists. Cleaning up and retrying...")
    return allow()

@registry.hook("retry_on_container_restart")
def retry_on_container_restart(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"container.*restarting|connection refused.*localhost|ECONNREFUSED.*127\.0\.0\.1", output, re.IGNORECASE):
        return force_continue("Service container restarting. Waiting and retrying...")
    return allow()

if __name__ == "__main__":
    registry.main()
