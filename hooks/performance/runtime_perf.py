#!/usr/bin/env python3
"""Performance: Runtime performance hooks for Codex. 20 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("detect_slow_command")
def detect_slow_command(data):
    cmd, output = get_command(data), get_command_output(data)
    if not output: return allow()
    match = re.search(r"real\s+(\d+)m([\d.]+)s", output)
    if match:
        minutes, seconds = int(match.group(1)), float(match.group(2))
        total = minutes * 60 + seconds
        if total > 120:
            return post_tool_context(f"Performance: Command took {minutes}m{seconds:.0f}s. Consider optimization.")
    return allow()

@registry.hook("detect_n_plus_one_query")
def detect_n_plus_one_query(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"N\+1|n\+1 query|SELECT.*repeated|duplicate.*query", output, re.IGNORECASE):
        return post_tool_context("Performance: N+1 query pattern detected. Use eager loading/joins.")
    return allow()

@registry.hook("check_database_query_time")
def check_database_query_time(data):
    output = get_command_output(data)
    if not output: return allow()
    slow = re.findall(r"(?:query|execution)\s+time[:\s]+(\d+(?:\.\d+)?)\s*(ms|s)", output, re.IGNORECASE)
    slow_queries = [(float(t), u) for t, u in slow if (u == "s" and float(t) > 1) or (u == "ms" and float(t) > 1000)]
    if slow_queries:
        return post_tool_context(f"Performance: {len(slow_queries)} slow queries detected. Add indexes or optimize.")
    return allow()

@registry.hook("detect_missing_indexes")
def detect_missing_indexes(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Seq Scan|full table scan|TABLE SCAN|Missing Index", output, re.IGNORECASE):
        return post_tool_context("Performance: Full table scan detected. Add appropriate indexes.")
    return allow()

@registry.hook("check_regex_performance")
def check_regex_performance(data):
    output = get_command_output(data)
    if not output: return allow()
    dangerous_patterns = re.findall(r"(?:\([^)]*\+\)[^)]*\+|\(\.[*+]\)[*+]|(?:\w+\|){10,})", output)
    if dangerous_patterns:
        return post_tool_context("Performance: Potentially catastrophic regex (ReDoS). Simplify nested quantifiers.")
    return allow()

@registry.hook("detect_synchronous_io")
def detect_synchronous_io(data):
    output = get_command_output(data)
    if not output: return allow()
    sync_calls = re.findall(r"\b(readFileSync|writeFileSync|execSync|spawnSync|synchronous)\b", output)
    if len(sync_calls) > 3:
        return post_tool_context(f"Performance: {len(sync_calls)} synchronous I/O calls. Use async alternatives.")
    return allow()

@registry.hook("check_algorithm_complexity")
def check_algorithm_complexity(data):
    output = get_command_output(data)
    if not output: return allow()
    nested_loops = re.findall(r"for\s+.*:\s*\n\s+for\s+.*:\s*\n\s+for\s+", output)
    if nested_loops:
        return post_tool_context("Performance: Triple-nested loops detected (O(n^3)). Consider algorithmic optimization.")
    return allow()

@registry.hook("detect_memory_allocation_pattern")
def detect_memory_allocation_pattern(data):
    output = get_command_output(data)
    if not output: return allow()
    allocs = re.findall(r"(?:string\s*\+\s*=|\.append\(|\.push\(|concat\().*(?:for|while|loop)", output, re.IGNORECASE)
    if len(allocs) > 2:
        return post_tool_context("Performance: Repeated string/array growth in loop. Pre-allocate or use join/builder.")
    return allow()

@registry.hook("check_caching_opportunity")
def check_caching_opportunity(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Cache-Control: no-cache|no-store|cache.*miss.*100%|X-Cache: MISS", output):
        return post_tool_context("Performance: No caching configured. Add Cache-Control headers or application caching.")
    return allow()

@registry.hook("detect_excessive_dom_operations")
def detect_excessive_dom_operations(data):
    output = get_command_output(data)
    if not output: return allow()
    dom_ops = re.findall(r"document\.(getElementById|querySelector|createElement|appendChild|innerHTML)", output)
    if len(dom_ops) > 10:
        return post_tool_context(f"Performance: {len(dom_ops)} direct DOM operations. Batch updates or use virtual DOM.")
    return allow()

@registry.hook("check_lazy_loading")
def check_lazy_loading(data):
    output = get_command_output(data)
    if not output: return allow()
    eager_imports = re.findall(r"^import\s+\{[^}]+\}\s+from\s+['\"](?!react|vue|angular)", output, re.MULTILINE)
    if len(eager_imports) > 20:
        return post_tool_context(f"Performance: {len(eager_imports)} eager imports. Consider lazy loading/code splitting.")
    return allow()

@registry.hook("detect_unoptimized_images")
def detect_unoptimized_images(data):
    output = get_command_output(data)
    if not output: return allow()
    large_imgs = re.findall(r"(\S+\.(?:png|jpg|jpeg|gif))\s+.*?(\d+(?:\.\d+)?)\s*(MB|KB)", output)
    big = [(n, s, u) for n, s, u in large_imgs if (u == "MB" and float(s) > 1) or (u == "KB" and float(s) > 500)]
    if big:
        return post_tool_context(f"Performance: {len(big)} large images. Compress, resize, or use WebP/AVIF format.")
    return allow()

@registry.hook("check_connection_pooling")
def check_connection_pooling(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"too many connections|connection pool exhausted|EMFILE|max_connections", output, re.IGNORECASE):
        return post_tool_context("Performance: Connection pool exhausted. Configure pool size or fix connection leaks.")
    return allow()

@registry.hook("detect_blocking_operations")
def detect_blocking_operations(data):
    output = get_command_output(data)
    if not output: return allow()
    blocking = []
    if re.search(r"time\.sleep\(\d{2,}\)|Thread\.sleep\(\d{4,}\)|setTimeout.*\d{5,}", output): blocking.append("long sleeps")
    if re.search(r"\.get\(\)\.result\(\)|\.join\(\)|Deferred.*block", output): blocking.append("blocking futures")
    if blocking:
        return post_tool_context(f"Performance: Blocking operations: {', '.join(blocking)}")
    return allow()

@registry.hook("check_pagination")
def check_pagination(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"SELECT \*|SELECT .*FROM.*(?!LIMIT|OFFSET|FETCH)", output) and not re.search(r"LIMIT|OFFSET|FETCH FIRST|TOP\s+\d+", output):
        if re.search(r"SELECT", output):
            return post_tool_context("Performance: Query without LIMIT. Add pagination for large result sets.")
    return allow()

@registry.hook("detect_render_performance")
def detect_render_performance(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"useEffect.*\[\]|componentDidMount|componentDidUpdate", output):
        if re.search(r"setState|setCount|set\w+\(", output) and re.search(r"useEffect\(\s*\(\)\s*=>\s*\{", output):
            return post_tool_context("Performance: State update in useEffect may cause extra render. Use useMemo/useCallback.")
    return allow()

@registry.hook("check_webpack_bundle_analysis")
def check_webpack_bundle_analysis(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"webpack|bundle.*analyz", output, re.IGNORECASE):
        large = re.findall(r"(\S+\.js)\s+(\d+(?:\.\d+)?)\s*(MB|KB)", output)
        big = [(n, s, u) for n, s, u in large if (u == "MB") or (u == "KB" and float(s) > 500)]
        if big:
            names = ", ".join(f"{n}({s}{u})" for n, s, u in big[:3])
            return post_tool_context(f"Performance: Large bundles: {names}. Tree-shake and code-split.")
    return allow()

@registry.hook("detect_inefficient_serialization")
def detect_inefficient_serialization(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"JSON\.parse\(JSON\.stringify|deepClone|structuredClone", output):
        return post_tool_context("Performance: JSON.parse(JSON.stringify) for deep clone is slow. Use structuredClone or targeted copy.")
    return allow()

@registry.hook("check_database_connection_overhead")
def check_database_connection_overhead(data):
    output = get_command_output(data)
    if not output: return allow()
    new_conns = re.findall(r"new\s+(?:Client|Connection|Pool|MongoClient|createConnection)", output)
    if len(new_conns) > 3:
        return post_tool_context(f"Performance: {len(new_conns)} new DB connections. Reuse connections with pooling.")
    return allow()

@registry.hook("detect_hot_path_allocation")
def detect_hot_path_allocation(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?:for|while)\s.*\{[\s\S]*?new\s+(?:Array|Object|Map|Set|RegExp)\(", output):
        return post_tool_context("Performance: Object allocation inside hot loop. Hoist allocation outside the loop.")
    return allow()

if __name__ == "__main__":
    registry.main()
