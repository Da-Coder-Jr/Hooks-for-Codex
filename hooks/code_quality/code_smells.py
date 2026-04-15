#!/usr/bin/env python3
"""
Code Quality: Code Smell Detection hooks for Codex.
20 PostToolUse hooks detecting common code smells.
"""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()

@registry.hook("smell_long_parameter_list")
def smell_long_parameter_list(data):
    output = get_command_output(data)
    if not output: return allow()
    for m in re.finditer(r"(?:def|function)\s+(\w+)\s*\(([^)]+)\)", output):
        params = [p.strip() for p in m.group(2).split(",") if p.strip()]
        if len(params) > 5:
            return post_tool_context(f"Code Smell: {m.group(1)} has {len(params)} parameters (consider parameter object)")
    return allow()

@registry.hook("smell_god_object")
def smell_god_object(data):
    output = get_command_output(data)
    if not output: return allow()
    methods = len(re.findall(r"\b(def|function|public|private)\s+\w+\s*\(", output))
    lines = output.count("\n")
    if methods > 20 and lines > 400:
        return post_tool_context(f"Code Smell: God object ({methods} methods, {lines} lines) - split into smaller classes")
    return allow()

@registry.hook("smell_shotgun_surgery")
def smell_shotgun_surgery(data):
    cmd, output = get_command(data), get_command_output(data)
    if not output: return allow()
    if re.search(r"\bgit\s+diff\b", cmd):
        files = set(re.findall(r"^diff --git a/(\S+)", output, re.MULTILINE))
        if len(files) > 10:
            return post_tool_context(f"Code Smell: Shotgun surgery - change touches {len(files)} files (high coupling)")
    return allow()

@registry.hook("smell_divergent_change")
def smell_divergent_change(data):
    cmd, output = get_command(data), get_command_output(data)
    if not output: return allow()
    if re.search(r"\bgit\s+log\b", cmd):
        file_mentions = re.findall(r"\b(\w+\.(?:py|js|ts|java|rb))\b", output)
        from collections import Counter
        freq = Counter(file_mentions)
        hot = [(f, c) for f, c in freq.most_common(5) if c > 5]
        if hot:
            return post_tool_context(f"Code Smell: Frequently changed files (divergent change): {', '.join(f'{f}({c}x)' for f,c in hot)}")
    return allow()

@registry.hook("smell_parallel_inheritance")
def smell_parallel_inheritance(data):
    output = get_command_output(data)
    if not output: return allow()
    classes = re.findall(r"class\s+(\w+)", output)
    prefixes = {}
    for cls in classes:
        prefix = re.match(r"^[A-Z][a-z]+", cls)
        if prefix:
            p = prefix.group()
            prefixes[p] = prefixes.get(p, 0) + 1
    parallel = {p: c for p, c in prefixes.items() if c >= 3}
    if parallel:
        return post_tool_context(f"Code Smell: Parallel class hierarchies: {', '.join(f'{p}*({c})' for p,c in parallel.items())}")
    return allow()

@registry.hook("smell_lazy_class")
def smell_lazy_class(data):
    output = get_command_output(data)
    if not output: return allow()
    class_blocks = re.findall(r"class\s+(\w+).*?(?=\nclass\s|\Z)", output, re.DOTALL)
    for block in class_blocks[:10]:
        name = re.match(r"(\w+)", block).group(1) if re.match(r"(\w+)", block) else "unknown"
        methods = len(re.findall(r"\bdef\s+\w+", block))
        lines = block.count("\n")
        if methods <= 1 and lines < 10:
            return post_tool_context(f"Code Smell: Lazy class '{name}' ({methods} methods, {lines} lines) - consider inlining")
    return allow()

@registry.hook("smell_speculative_generality")
def smell_speculative_generality(data):
    output = get_command_output(data)
    if not output: return allow()
    abstracts = re.findall(r"(?:abstract\s+class|ABC|@abstractmethod|interface\s+)\s*(\w+)", output)
    if len(abstracts) > 3:
        return post_tool_context(f"Code Smell: {len(abstracts)} abstract classes/interfaces - ensure they're all needed (speculative generality)")
    return allow()

@registry.hook("smell_temporary_field")
def smell_temporary_field(data):
    output = get_command_output(data)
    if not output: return allow()
    none_inits = re.findall(r"self\.(\w+)\s*=\s*None\b", output)
    if len(none_inits) > 5:
        return post_tool_context(f"Code Smell: {len(none_inits)} fields initialized to None (temporary fields pattern)")
    return allow()

@registry.hook("smell_message_chain")
def smell_message_chain(data):
    output = get_command_output(data)
    if not output: return allow()
    chains = re.findall(r"\w+\.\w+\.\w+\.\w+\.\w+", output)
    if len(chains) > 3:
        return post_tool_context(f"Code Smell: {len(chains)} long message chains (Law of Demeter violation)")
    return allow()

@registry.hook("smell_middle_man")
def smell_middle_man(data):
    output = get_command_output(data)
    if not output: return allow()
    delegates = re.findall(r"def\s+(\w+)\s*\(self[^)]*\):\s*\n\s*return\s+self\.\w+\.\1\(", output)
    if len(delegates) > 3:
        return post_tool_context(f"Code Smell: {len(delegates)} methods just delegating (middle man class)")
    return allow()

@registry.hook("smell_inappropriate_intimacy")
def smell_inappropriate_intimacy(data):
    output = get_command_output(data)
    if not output: return allow()
    private_access = re.findall(r"\w+\._\w+", output)
    if len(private_access) > 5:
        return post_tool_context(f"Code Smell: {len(private_access)} private member accesses (inappropriate intimacy)")
    return allow()

@registry.hook("smell_alternative_classes")
def smell_alternative_classes(data):
    output = get_command_output(data)
    if not output: return allow()
    class_methods = {}
    for m in re.finditer(r"class\s+(\w+).*?(?=\nclass\s|\Z)", output, re.DOTALL):
        cls = m.group(1)
        methods = set(re.findall(r"\bdef\s+(\w+)", m.group()))
        class_methods[cls] = methods
    classes = list(class_methods.items())
    for i in range(len(classes)):
        for j in range(i+1, len(classes)):
            overlap = classes[i][1] & classes[j][1] - {"__init__", "__str__", "__repr__"}
            if len(overlap) > 3:
                return post_tool_context(f"Code Smell: {classes[i][0]} and {classes[j][0]} share {len(overlap)} methods (alternative classes)")
    return allow()

@registry.hook("smell_refused_bequest")
def smell_refused_bequest(data):
    output = get_command_output(data)
    if not output: return allow()
    overrides = re.findall(r"def\s+\w+\s*\([^)]*\):\s*\n\s*raise\s+NotImplementedError", output)
    if len(overrides) > 2:
        return post_tool_context(f"Code Smell: {len(overrides)} methods raising NotImplementedError (refused bequest)")
    return allow()

@registry.hook("smell_data_class")
def smell_data_class(data):
    output = get_command_output(data)
    if not output: return allow()
    for m in re.finditer(r"class\s+(\w+).*?(?=\nclass\s|\Z)", output, re.DOTALL):
        cls, body = m.group(1), m.group()
        getters = len(re.findall(r"@property|def\s+get_\w+", body))
        setters = len(re.findall(r"@\w+\.setter|def\s+set_\w+", body))
        logic = len(re.findall(r"def\s+(?!__init__|__str__|__repr__|get_|set_)\w+", body))
        if getters + setters > 4 and logic == 0:
            return post_tool_context(f"Code Smell: '{cls}' is a data class ({getters} getters, {setters} setters, no behavior)")
    return allow()

@registry.hook("smell_switch_statements")
def smell_switch_statements(data):
    output = get_command_output(data)
    if not output: return allow()
    elifs = re.findall(r"\belif\b|\belse if\b", output)
    if len(elifs) > 5:
        return post_tool_context(f"Code Smell: {len(elifs)+1} if/elif branches (consider polymorphism or strategy pattern)")
    return allow()

@registry.hook("smell_comments_as_deodorant")
def smell_comments_as_deodorant(data):
    output = get_command_output(data)
    if not output: return allow()
    lines = output.split("\n")
    comment_lines = sum(1 for l in lines if l.strip().startswith(("#", "//", "/*", "*")))
    code_lines = sum(1 for l in lines if l.strip() and not l.strip().startswith(("#", "//", "/*", "*")))
    if code_lines > 20 and comment_lines > code_lines * 0.4:
        return post_tool_context(f"Code Smell: High comment ratio ({comment_lines}/{code_lines}) - comments compensating for unclear code")
    return allow()

@registry.hook("smell_magic_strings")
def smell_magic_strings(data):
    output = get_command_output(data)
    if not output: return allow()
    from collections import Counter
    strings = re.findall(r'["\']([a-z_]{4,})["\']', output)
    repeated = [(s, c) for s, c in Counter(strings).items() if c >= 3]
    if repeated:
        return post_tool_context(f"Code Smell: Repeated string literals: {', '.join(f'{s}({c}x)' for s,c in repeated[:5])}")
    return allow()

@registry.hook("smell_flag_arguments")
def smell_flag_arguments(data):
    output = get_command_output(data)
    if not output: return allow()
    flag_fns = re.findall(r"def\s+(\w+)\s*\([^)]*\w+\s*:\s*bool[^)]*\)", output)
    if len(flag_fns) > 2:
        return post_tool_context(f"Code Smell: Boolean flag arguments in: {', '.join(flag_fns[:5])} (split into separate functions)")
    return allow()

@registry.hook("smell_global_state")
def smell_global_state(data):
    output = get_command_output(data)
    if not output: return allow()
    global_mutations = re.findall(r"^\s*global\s+(\w+)", output, re.MULTILINE)
    if len(global_mutations) > 2:
        return post_tool_context(f"Code Smell: {len(global_mutations)} global state mutations ({', '.join(set(global_mutations)[:5])})")
    return allow()

@registry.hook("smell_copy_paste")
def smell_copy_paste(data):
    output = get_command_output(data)
    if not output: return allow()
    lines = [l.strip() for l in output.split("\n") if l.strip() and len(l.strip()) > 30]
    from collections import Counter
    dupes = [(l[:50], c) for l, c in Counter(lines).items() if c >= 3 and not l.startswith(("#", "//", "import"))]
    if len(dupes) > 2:
        return post_tool_context(f"Code Smell: {len(dupes)} duplicated code patterns (copy-paste detected)")
    return allow()


if __name__ == "__main__":
    registry.main()
