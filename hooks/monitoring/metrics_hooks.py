#!/usr/bin/env python3
"""Monitoring: Metrics and observability hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("check_cpu_usage")
def check_cpu_usage(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\btop\b|\bhtop\b|ps\s+aux|mpstat", cmd) or not output: return allow()
    cpus = re.findall(r"(\d+(?:\.\d+))%?\s*(?:cpu|CPU|us|user)", output)
    high = [float(c) for c in cpus if float(c) > 90]
    if high:
        return post_tool_context(f"Metrics: CPU usage > 90% ({max(high):.1f}%). Investigate high CPU processes.")
    return allow()

@registry.hook("check_memory_usage")
def check_memory_usage(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bfree\b|\btop\b|vmstat|/proc/meminfo", cmd) or not output: return allow()
    match = re.search(r"Mem:.*?(\d+)\s+(\d+)\s+(\d+)", output)
    if match:
        total, used = int(match.group(1)), int(match.group(2))
        if total > 0:
            pct = (used / total) * 100
            if pct > 90:
                return post_tool_context(f"Metrics: Memory usage at {pct:.1f}%. Consider scaling or optimization.")
    return allow()

@registry.hook("check_disk_usage")
def check_disk_usage(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bdf\b", cmd) or not output: return allow()
    partitions = re.findall(r"(\S+)\s+\d+\s+\d+\s+\d+\s+(\d+)%\s+(\S+)", output)
    critical = [(mount, pct) for dev, pct, mount in partitions if int(pct) > 90]
    if critical:
        parts = ", ".join(f"{m}({p}%)" for m, p in critical)
        return post_tool_context(f"Metrics: Disk usage critical: {parts}")
    return allow()

@registry.hook("check_load_average")
def check_load_average(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\buptime\b|\btop\b|/proc/loadavg", cmd) or not output: return allow()
    match = re.search(r"load average[s]?:\s*([\d.]+),?\s*([\d.]+),?\s*([\d.]+)", output)
    if match:
        load_1m = float(match.group(1))
        if load_1m > 8:
            return post_tool_context(f"Metrics: Load average {load_1m} (1m). System under heavy load.")
    return allow()

@registry.hook("check_process_count")
def check_process_count(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"ps\s+aux|ps\s+ef|wc\s+-l", cmd) or not output: return allow()
    match = re.search(r"(\d+)\s*$", output.strip())
    if match and int(match.group(1)) > 500:
        return post_tool_context(f"Metrics: {match.group(1)} processes running. Check for process leaks.")
    return allow()

@registry.hook("check_network_io")
def check_network_io(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"ifstat|iftop|nethogs|ss\s+-s", cmd) or not output: return allow()
    if re.search(r"(\d+)\s+(?:established|ESTAB)", output):
        match = re.search(r"(\d+)\s+(?:established|ESTAB)", output)
        conns = int(match.group(1))
        if conns > 1000:
            return post_tool_context(f"Metrics: {conns} established connections. Check for connection leaks.")
    return allow()

@registry.hook("check_docker_stats")
def check_docker_stats(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"docker\s+stats", cmd) or not output: return allow()
    high_cpu = re.findall(r"(\S+)\s+(\d+(?:\.\d+)?)%", output)
    hot = [(name, float(cpu)) for name, cpu in high_cpu if float(cpu) > 80]
    if hot:
        names = ", ".join(f"{n}({c:.0f}%)" for n, c in hot[:3])
        return post_tool_context(f"Metrics: High CPU containers: {names}")
    return allow()

@registry.hook("check_kubernetes_metrics")
def check_kubernetes_metrics(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"kubectl\s+top\s+(?:nodes?|pods?)", cmd) or not output: return allow()
    high_usage = re.findall(r"(\S+)\s+\d+m\s+(\d+)%\s+\d+Mi\s+(\d+)%", output)
    overloaded = [(name, cpu, mem) for name, cpu, mem in high_usage if int(cpu) > 80 or int(mem) > 80]
    if overloaded:
        items = ", ".join(f"{n}(cpu:{c}%,mem:{m}%)" for n, c, m in overloaded[:3])
        return post_tool_context(f"K8s metrics: High usage: {items}")
    return allow()

@registry.hook("check_response_time_metrics")
def check_response_time_metrics(data):
    output = get_command_output(data)
    if not output: return allow()
    p99 = re.search(r"p99[:\s]+(\d+)\s*ms|99th.*?(\d+)\s*ms", output, re.IGNORECASE)
    p95 = re.search(r"p95[:\s]+(\d+)\s*ms|95th.*?(\d+)\s*ms", output, re.IGNORECASE)
    if p99:
        val = int(p99.group(1) or p99.group(2))
        if val > 2000:
            return post_tool_context(f"Metrics: p99 latency {val}ms. Tail latency too high.")
    elif p95:
        val = int(p95.group(1) or p95.group(2))
        if val > 1000:
            return post_tool_context(f"Metrics: p95 latency {val}ms. Consider performance optimization.")
    return allow()

@registry.hook("check_error_rate")
def check_error_rate(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"error[_ ]rate[:\s]+([\d.]+)\s*%", output, re.IGNORECASE)
    if match:
        rate = float(match.group(1))
        if rate > 5:
            return post_tool_context(f"Metrics: Error rate at {rate}%. Exceeds typical 1% threshold.")
    return allow()

@registry.hook("check_queue_depth")
def check_queue_depth(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"queue[_ ](?:depth|length|size)[:\s]+(\d+)", output, re.IGNORECASE)
    if match:
        depth = int(match.group(1))
        if depth > 10000:
            return post_tool_context(f"Metrics: Queue depth {depth}. Consumers may be falling behind.")
    return allow()

@registry.hook("check_cache_hit_rate")
def check_cache_hit_rate(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"cache[_ ]hit[_ ]rate[:\s]+([\d.]+)\s*%|hit[_ ]ratio[:\s]+([\d.]+)", output, re.IGNORECASE)
    if match:
        rate = float(match.group(1) or match.group(2))
        if rate < 50:
            return post_tool_context(f"Metrics: Cache hit rate {rate}%. Low rate, review cache strategy.")
    return allow()

@registry.hook("check_gc_metrics")
def check_gc_metrics(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"GC.*pause[:\s]+(\d+)\s*ms|gc.*time[:\s]+(\d+)\s*ms", output, re.IGNORECASE)
    if match:
        pause = int(match.group(1) or match.group(2))
        if pause > 500:
            return post_tool_context(f"Metrics: GC pause {pause}ms. Tune heap size and GC parameters.")
    return allow()

@registry.hook("check_thread_pool_usage")
def check_thread_pool_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"thread[_ ]pool.*?active[:\s]+(\d+).*?max[:\s]+(\d+)", output, re.IGNORECASE)
    if match:
        active, maximum = int(match.group(1)), int(match.group(2))
        if maximum > 0 and active / maximum > 0.9:
            return post_tool_context(f"Metrics: Thread pool {active}/{maximum} ({100*active//maximum}% used). Near exhaustion.")
    return allow()

if __name__ == "__main__":
    registry.main()
