#!/usr/bin/env python3
"""
Code Quality: Complexity Analysis hooks for Codex.
20 PostToolUse hooks analyzing code complexity in command output.
"""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()

@registry.hook("analyze_cyclomatic_complexity")
def analyze_cyclomatic_complexity(data):
    output = get_command_output(data)
    if not output: return allow()
    branches = len(re.findall(r"\b(if|elif|else if|case|catch|except|for|while|&&|\|\|)\b", output))
    funcs = len(re.findall(r"\b(def|function|fn)\s+\w+", output))
    if funcs > 0 and branches / max(funcs, 1) > 8:
        return post_tool_context(f"Complexity: High cyclomatic complexity ({branches} branches across {funcs} functions, avg {branches//max(funcs,1)} per fn)")
    return allow()

@registry.hook("analyze_cognitive_complexity")
def analyze_cognitive_complexity(data):
    output = get_command_output(data)
    if not output: return allow()
    nesting_score = 0
    current_nesting = 0
    for line in output.split("\n"):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        level = indent // 4
        if re.match(r"(if|for|while|else|elif|catch|except)\b", stripped):
            nesting_score += 1 + level
            current_nesting = max(current_nesting, level)
    if nesting_score > 30:
        return post_tool_context(f"Complexity: High cognitive complexity score ({nesting_score}), max nesting depth {current_nesting}")
    return allow()

@registry.hook("analyze_function_params")
def analyze_function_params(data):
    output = get_command_output(data)
    if not output: return allow()
    high_param_funcs = []
    for m in re.finditer(r"(?:def|function)\s+(\w+)\s*\(([^)]*)\)", output):
        name, params = m.group(1), m.group(2)
        param_count = len([p for p in params.split(",") if p.strip()]) if params.strip() else 0
        if param_count > 5:
            high_param_funcs.append(f"{name}({param_count} params)")
    if high_param_funcs:
        return post_tool_context(f"Complexity: Functions with many parameters: {', '.join(high_param_funcs[:5])}")
    return allow()

@registry.hook("analyze_class_size")
def analyze_class_size(data):
    output = get_command_output(data)
    if not output: return allow()
    classes = re.findall(r"class\s+(\w+)", output)
    methods_per_class = {}
    for cls in classes:
        pattern = rf"class\s+{cls}\b.*?(?=\nclass\s|\Z)"
        match = re.search(pattern, output, re.DOTALL)
        if match:
            methods = len(re.findall(r"\bdef\s+\w+", match.group()))
            if methods > 20:
                methods_per_class[cls] = methods
    if methods_per_class:
        summary = ", ".join(f"{k}({v} methods)" for k, v in methods_per_class.items())
        return post_tool_context(f"Complexity: Large classes: {summary}")
    return allow()

@registry.hook("analyze_method_chains")
def analyze_method_chains(data):
    output = get_command_output(data)
    if not output: return allow()
    chains = re.findall(r"\w+(?:\.\w+\([^)]*\)){5,}", output)
    if chains:
        return post_tool_context(f"Complexity: {len(chains)} long method chains detected (>5 chained calls)")
    return allow()

@registry.hook("analyze_inheritance_depth")
def analyze_inheritance_depth(data):
    output = get_command_output(data)
    if not output: return allow()
    extends = re.findall(r"class\s+(\w+)\s*\(\s*(\w+)\s*\)", output)
    parents = {child: parent for child, parent in extends}
    for cls in parents:
        depth = 0
        current = cls
        while current in parents:
            current = parents[current]
            depth += 1
            if depth > 3:
                return post_tool_context(f"Complexity: Deep inheritance chain detected ({cls}, depth > 3)")
                break
    return allow()

@registry.hook("analyze_import_count")
def analyze_import_count(data):
    output = get_command_output(data)
    if not output: return allow()
    imports = re.findall(r"^(?:import|from)\s+", output, re.MULTILINE)
    if len(imports) > 20:
        return post_tool_context(f"Complexity: {len(imports)} imports in file (consider splitting module)")
    return allow()

@registry.hook("analyze_dependency_count")
def analyze_dependency_count(data):
    cmd, output = get_command(data), get_command_output(data)
    if not output: return allow()
    if re.search(r"\bcat\b.*package\.json", cmd) or re.search(r'"dependencies"', output):
        deps = len(re.findall(r'"\w[\w@/.-]+"\s*:', output))
        if deps > 50:
            return post_tool_context(f"Complexity: {deps} dependencies in package.json (consider reducing)")
    return allow()

@registry.hook("analyze_file_complexity")
def analyze_file_complexity(data):
    output = get_command_output(data)
    if not output: return allow()
    lines = output.count("\n")
    branches = len(re.findall(r"\b(if|for|while|switch|match)\b", output))
    nesting = max((len(l) - len(l.lstrip())) // 4 for l in output.split("\n") if l.strip()) if output.strip() else 0
    score = (lines * 0.1) + (branches * 2) + (nesting * 5)
    if score > 100:
        return post_tool_context(f"Complexity: High file complexity score ({score:.0f}): {lines}L, {branches} branches, max nesting {nesting}")
    return allow()

@registry.hook("analyze_boolean_complexity")
def analyze_boolean_complexity(data):
    output = get_command_output(data)
    if not output: return allow()
    complex_bools = re.findall(r"if\s+.*(?:and|or|&&|\|\|).*(?:and|or|&&|\|\|).*(?:and|or|&&|\|\|)", output)
    if complex_bools:
        return post_tool_context(f"Complexity: {len(complex_bools)} complex boolean expressions (>3 conditions)")
    return allow()

@registry.hook("analyze_switch_case_count")
def analyze_switch_case_count(data):
    output = get_command_output(data)
    if not output: return allow()
    cases = len(re.findall(r"\bcase\s+", output))
    if cases > 10:
        return post_tool_context(f"Complexity: {cases} switch/match cases (consider polymorphism or lookup table)")
    return allow()

@registry.hook("analyze_try_catch_nesting")
def analyze_try_catch_nesting(data):
    output = get_command_output(data)
    if not output: return allow()
    nested = re.findall(r"try\s*[:{].*?try\s*[:{]", output, re.DOTALL)
    if nested:
        return post_tool_context(f"Complexity: Nested try-catch blocks detected")
    return allow()

@registry.hook("analyze_callback_depth")
def analyze_callback_depth(data):
    output = get_command_output(data)
    if not output: return allow()
    callbacks = re.findall(r"function\s*\([^)]*\)\s*\{.*function\s*\([^)]*\)\s*\{.*function\s*\(", output, re.DOTALL)
    if callbacks:
        return post_tool_context("Complexity: Callback hell detected (3+ nested callbacks). Consider async/await.")
    return allow()

@registry.hook("analyze_promise_chain_length")
def analyze_promise_chain_length(data):
    output = get_command_output(data)
    if not output: return allow()
    chains = re.findall(r"\.then\(", output)
    if len(chains) > 5:
        return post_tool_context(f"Complexity: Long promise chain ({len(chains)} .then()). Consider async/await.")
    return allow()

@registry.hook("analyze_regex_complexity")
def analyze_regex_complexity(data):
    output = get_command_output(data)
    if not output: return allow()
    regexes = re.findall(r'(?:/[^/\n]+/[gims]*|re\.compile\(["\'][^"\']+["\'])', output)
    complex_re = [r for r in regexes if len(r) > 60]
    if complex_re:
        return post_tool_context(f"Complexity: {len(complex_re)} complex regex patterns (>60 chars). Add comments.")
    return allow()

@registry.hook("analyze_duplicate_code_blocks")
def analyze_duplicate_code_blocks(data):
    output = get_command_output(data)
    if not output: return allow()
    lines = [l.strip() for l in output.split("\n") if l.strip() and len(l.strip()) > 20]
    from collections import Counter
    dupes = [line for line, count in Counter(lines).items() if count > 2 and not line.startswith(("#", "//", "import", "from"))]
    if len(dupes) > 3:
        return post_tool_context(f"Complexity: {len(dupes)} duplicated code lines detected")
    return allow()

@registry.hook("analyze_god_class")
def analyze_god_class(data):
    output = get_command_output(data)
    if not output: return allow()
    lines = len(output.split("\n"))
    methods = len(re.findall(r"\b(def|function|public|private|protected)\s+\w+\s*\(", output))
    attrs = len(re.findall(r"\bself\.\w+\s*=|this\.\w+\s*=", output))
    if methods > 15 and attrs > 10:
        return post_tool_context(f"Complexity: Potential God class ({methods} methods, {attrs} attributes)")
    return allow()

@registry.hook("analyze_feature_envy")
def analyze_feature_envy(data):
    output = get_command_output(data)
    if not output: return allow()
    external = len(re.findall(r"\b\w+\.\w+\.\w+", output))
    internal = len(re.findall(r"\bself\.\w+|this\.\w+", output))
    if external > internal * 2 and external > 10:
        return post_tool_context(f"Complexity: Feature envy detected ({external} external accesses vs {internal} internal)")
    return allow()

@registry.hook("analyze_data_clump")
def analyze_data_clump(data):
    output = get_command_output(data)
    if not output: return allow()
    params_lists = re.findall(r"def\s+\w+\s*\(([^)]+)\)", output)
    if len(params_lists) >= 3:
        from collections import Counter
        all_params = []
        for pl in params_lists:
            params = [p.strip().split(":")[0].split("=")[0].strip() for p in pl.split(",") if p.strip()]
            all_params.extend(params)
        common = [p for p, c in Counter(all_params).items() if c >= 3 and p not in ("self", "cls", "this")]
        if len(common) >= 3:
            return post_tool_context(f"Complexity: Data clump detected - params appearing together: {', '.join(common[:5])}")
    return allow()

@registry.hook("analyze_primitive_obsession")
def analyze_primitive_obsession(data):
    output = get_command_output(data)
    if not output: return allow()
    str_params = len(re.findall(r":\s*str\b|:\s*string\b|String\s+\w+", output))
    int_params = len(re.findall(r":\s*int\b|:\s*number\b|int\s+\w+", output))
    if str_params + int_params > 20:
        return post_tool_context(f"Complexity: Possible primitive obsession ({str_params} strings, {int_params} ints). Consider value objects.")
    return allow()


if __name__ == "__main__":
    registry.main()
