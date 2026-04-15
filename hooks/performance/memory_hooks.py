#!/usr/bin/env python3
"""Performance: Memory analysis hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("detect_memory_leak_indicators")
def detect_memory_leak_indicators(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"memory leak|heap.*growing|RSS.*increasing|leaked.*bytes", output, re.IGNORECASE):
        return post_tool_context("Memory: Potential memory leak detected. Profile with heap snapshots.")
    return allow()

@registry.hook("check_heap_usage")
def check_heap_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"heap.*?(\d+(?:\.\d+)?)\s*(MB|GB)|rss[:\s]+(\d+(?:\.\d+)?)\s*(MB|GB)", output, re.IGNORECASE)
    if match:
        size = float(match.group(1) or match.group(3))
        unit = match.group(2) or match.group(4)
        if (unit == "GB" and size > 1) or (unit == "MB" and size > 512):
            return post_tool_context(f"Memory: High heap usage ({size}{unit}). Profile and reduce allocations.")
    return allow()

@registry.hook("detect_event_listener_leak")
def detect_event_listener_leak(data):
    output = get_command_output(data)
    if not output: return allow()
    add_listeners = len(re.findall(r"addEventListener|\.on\(|addListener", output))
    remove_listeners = len(re.findall(r"removeEventListener|\.off\(|removeListener|removeAllListeners", output))
    if add_listeners > remove_listeners + 5:
        return post_tool_context(f"Memory: {add_listeners} event listeners added, {remove_listeners} removed. Potential listener leak.")
    return allow()

@registry.hook("check_closure_memory")
def check_closure_memory(data):
    output = get_command_output(data)
    if not output: return allow()
    closures_in_loops = re.findall(r"(?:for|while)\s.*\{[\s\S]*?(?:function|=>)[\s\S]*?(?:setTimeout|setInterval|addEventListener)", output)
    if closures_in_loops:
        return post_tool_context("Memory: Closures in loops may retain outer scope. Use local variables or WeakRef.")
    return allow()

@registry.hook("detect_large_array_operations")
def detect_large_array_operations(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Array\(\d{6,}\)|new\s+\w+Array\(\d{6,}\)|range\(\d{6,}\)", output):
        return post_tool_context("Memory: Very large array allocation. Use generators/iterators for memory efficiency.")
    return allow()

@registry.hook("check_buffer_management")
def check_buffer_management(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Buffer\.alloc\(\d{7,}\)|malloc\(\d{7,}\)|allocate.*\d{7,}", output):
        return post_tool_context("Memory: Large buffer allocation (>10MB). Consider streaming or chunked processing.")
    return allow()

@registry.hook("detect_global_variable_accumulation")
def detect_global_variable_accumulation(data):
    output = get_command_output(data)
    if not output: return allow()
    globals_used = re.findall(r"\bglobal\s+\w+|window\.\w+\s*=|globalThis\.\w+\s*=", output)
    if len(globals_used) > 5:
        return post_tool_context(f"Memory: {len(globals_used)} global variable assignments. Globals prevent garbage collection.")
    return allow()

@registry.hook("check_cache_eviction")
def check_cache_eviction(data):
    output = get_command_output(data)
    if not output: return allow()
    cache_adds = len(re.findall(r"cache\.set|cache\.put|\.cache\[", output))
    cache_evicts = len(re.findall(r"cache\.delete|cache\.evict|cache\.clear|\.expire", output))
    if cache_adds > 10 and cache_evicts == 0:
        return post_tool_context("Memory: Cache grows without eviction. Add TTL or LRU eviction policy.")
    return allow()

@registry.hook("detect_circular_references")
def detect_circular_references(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"circular.*reference|Maximum call stack|circular structure|Converting circular", output, re.IGNORECASE):
        return post_tool_context("Memory: Circular reference detected. Use WeakRef/WeakMap or break the cycle.")
    return allow()

@registry.hook("check_stream_backpressure")
def check_stream_backpressure(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"highWaterMark|backpressure|buffer.*full|stream.*paused", output, re.IGNORECASE):
        return post_tool_context("Memory: Stream backpressure issue. Handle 'drain' events and respect highWaterMark.")
    return allow()

@registry.hook("detect_string_concatenation_loop")
def detect_string_concatenation_loop(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?:for|while)\s.*\{[\s\S]*?(?:\+=\s*['\"]|\.concat\(|result\s*\+)", output):
        return post_tool_context("Memory: String concatenation in loop. Use StringBuilder/join() for better memory usage.")
    return allow()

@registry.hook("check_object_pool_usage")
def check_object_pool_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    creates = len(re.findall(r"new\s+\w+\(", output))
    if creates > 20:
        return post_tool_context(f"Memory: {creates} object creations. Consider object pooling for frequently created objects.")
    return allow()

@registry.hook("detect_unbounded_collection")
def detect_unbounded_collection(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"\.push\(|\.add\(|\.set\(|\.append\(", output):
        if re.search(r"while\s*\(true\)|for\s*\(;;\)|while\s+True", output):
            return post_tool_context("Memory: Unbounded collection growth in infinite loop. Add size limit.")
    return allow()

@registry.hook("check_worker_memory")
def check_worker_memory(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Worker|worker_threads|multiprocessing|ThreadPoolExecutor", output):
        if re.search(r"--max-old-space-size|resource\.setrlimit|maxmemory", output):
            return allow()
        workers = len(re.findall(r"new\s+Worker|spawn\(|Process\(", output))
        if workers > 4:
            return post_tool_context(f"Memory: {workers} worker processes. Set memory limits per worker.")
    return allow()

@registry.hook("detect_valgrind_issues")
def detect_valgrind_issues(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"valgrind|memcheck|addresssanitizer|asan", cmd, re.IGNORECASE) or not output: return allow()
    leaks = re.search(r"definitely lost:\s*([\d,]+)\s*bytes", output)
    errors = re.search(r"ERROR SUMMARY:\s*(\d+)\s*errors", output)
    if leaks or (errors and int(errors.group(1).replace(",", "")) > 0):
        parts = []
        if leaks: parts.append(f"{leaks.group(1)} bytes leaked")
        if errors: parts.append(f"{errors.group(1)} errors")
        return post_tool_context(f"Memory: Valgrind: {', '.join(parts)}")
    return allow()

if __name__ == "__main__":
    registry.main()
