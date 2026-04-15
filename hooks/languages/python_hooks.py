#!/usr/bin/env python3
"""
Language-Specific: Python hooks for Codex.
20 PostToolUse hooks for Python development.
"""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()

@registry.hook("python_check_syntax_errors")
def python_check_syntax_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"SyntaxError:", output):
        match = re.search(r'File "([^"]+)", line (\d+)\n.*\n\s*SyntaxError:\s*(.*)', output)
        if match:
            return post_tool_context(f"Python SyntaxError in {match.group(1)}:{match.group(2)}: {match.group(3)}")
        return post_tool_context("Python SyntaxError detected - check output for details")
    return allow()

@registry.hook("python_detect_deprecated_apis")
def python_detect_deprecated_apis(data):
    output = get_command_output(data)
    if not output: return allow()
    deprecated = {
        r"\basyncio\.coroutine\b": "asyncio.coroutine (use async def)",
        r"\bcollections\.(Mapping|MutableMapping|Sequence|MutableSequence)\b": "collections.abc module",
        r"\boptparse\b": "optparse (use argparse)",
        r"\bimp\b\.": "imp module (use importlib)",
        r"\bdistutils\b": "distutils (use setuptools)",
        r"\bpkg_resources\b": "pkg_resources (use importlib.metadata)",
    }
    found = []
    for pattern, msg in deprecated.items():
        if re.search(pattern, output):
            found.append(msg)
    if found:
        return post_tool_context(f"Python deprecated APIs: {'; '.join(found[:5])}")
    return allow()

@registry.hook("python_check_f_string_security")
def python_check_f_string_security(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{', output, re.IGNORECASE):
        return post_tool_context("Python: f-string in SQL query detected - use parameterized queries")
    if re.search(r'logging\.\w+\(f["\']', output):
        return post_tool_context("Python: f-string in logging call - use %s formatting for lazy evaluation")
    return allow()

@registry.hook("python_virtualenv_check")
def python_virtualenv_check(data):
    cmd = get_command(data)
    if re.search(r"\bpip3?\s+install\b", cmd):
        if not os.environ.get("VIRTUAL_ENV") and not os.environ.get("CONDA_DEFAULT_ENV"):
            return post_tool_context("Python: pip install outside virtualenv - consider activating a virtual environment")
    return allow()

@registry.hook("python_check_requirements_sync")
def python_check_requirements_sync(data):
    cmd = get_command(data)
    if re.search(r"\bpip3?\s+install\b", cmd) and not re.search(r"-r\s+requirements", cmd):
        return post_tool_context("Python: Package installed directly. Remember to update requirements.txt or pyproject.toml")
    return allow()

@registry.hook("python_detect_import_errors")
def python_detect_import_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"ModuleNotFoundError: No module named '(\w+)'", output)
    if match:
        return post_tool_context(f"Python: Module '{match.group(1)}' not found. Install: pip install {match.group(1)}")
    return allow()

@registry.hook("python_check_python_version")
def python_check_python_version(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"\bprint\s+['\"]", output) and not re.search(r"\bprint\s*\(", output):
        return post_tool_context("Python: print statement syntax detected (Python 2). Use print() function.")
    return allow()

@registry.hook("python_check_type_hints")
def python_check_type_hints(data):
    output = get_command_output(data)
    if not output: return allow()
    funcs_total = len(re.findall(r"def\s+\w+\s*\(", output))
    funcs_typed = len(re.findall(r"def\s+\w+\s*\([^)]*:\s*\w+", output))
    if funcs_total > 5 and funcs_typed < funcs_total * 0.3:
        return post_tool_context(f"Python: Only {funcs_typed}/{funcs_total} functions have type hints")
    return allow()

@registry.hook("python_detect_circular_imports")
def python_detect_circular_imports(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"ImportError:.*circular import|cannot import name.*partially initialized", output):
        return post_tool_context("Python: Circular import detected. Move imports inside functions or restructure.")
    return allow()

@registry.hook("python_check_async_await")
def python_check_async_await(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"RuntimeWarning: coroutine .* was never awaited", output):
        return post_tool_context("Python: Coroutine was never awaited. Add 'await' keyword.")
    if re.search(r"SyntaxError.*'await' outside.*async function", output):
        return post_tool_context("Python: 'await' used outside async function. Mark function as 'async def'.")
    return allow()

@registry.hook("python_detect_memory_issues")
def python_detect_memory_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"MemoryError", output):
        return post_tool_context("Python: MemoryError - consider using generators, chunked processing, or increasing memory")
    if re.search(r"ResourceWarning: unclosed", output):
        return post_tool_context("Python: Unclosed resource - use context managers (with statement)")
    return allow()

@registry.hook("python_check_encoding")
def python_check_encoding(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"UnicodeDecodeError", output):
        return post_tool_context("Python: UnicodeDecodeError - specify encoding: open(file, encoding='utf-8')")
    if re.search(r"UnicodeEncodeError", output):
        return post_tool_context("Python: UnicodeEncodeError - check output encoding or use errors='replace'")
    return allow()

@registry.hook("python_detect_deprecation_warnings")
def python_detect_deprecation_warnings(data):
    output = get_command_output(data)
    if not output: return allow()
    warnings = re.findall(r"DeprecationWarning: (.*?)$", output, re.MULTILINE)
    if warnings:
        return post_tool_context(f"Python: {len(warnings)} DeprecationWarnings: {'; '.join(set(warnings[:3]))}")
    return allow()

@registry.hook("python_check_path_handling")
def python_check_path_handling(data):
    output = get_command_output(data)
    if not output: return allow()
    os_path = len(re.findall(r"\bos\.path\.\w+\(", output))
    pathlib = len(re.findall(r"\bPath\(|pathlib\.", output))
    if os_path > 5 and pathlib == 0:
        return post_tool_context(f"Python: {os_path} os.path calls - consider using pathlib for cleaner path handling")
    return allow()

@registry.hook("python_check_exception_handling")
def python_check_exception_handling(data):
    output = get_command_output(data)
    if not output: return allow()
    broad = len(re.findall(r"except\s+Exception\s*:", output))
    bare = len(re.findall(r"except\s*:", output))
    if broad + bare > 3:
        return post_tool_context(f"Python: {broad + bare} broad exception catches. Catch specific exceptions.")
    return allow()

@registry.hook("python_detect_segfaults")
def python_detect_segfaults(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Segmentation fault|SIGSEGV|core dumped", output):
        return post_tool_context("Python: Segmentation fault (likely C extension issue). Check native dependencies.")
    return allow()

@registry.hook("python_check_packaging")
def python_check_packaging(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"error:.*setup\.py|error:.*pyproject\.toml|InvalidVersion", output):
        return post_tool_context("Python: Packaging error detected. Check setup.py/pyproject.toml configuration.")
    return allow()

@registry.hook("python_detect_test_failures")
def python_detect_test_failures(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bpytest\b", cmd) or not output: return allow()
    match = re.search(r"(\d+) passed.*?(\d+) failed", output)
    if match:
        return post_tool_context(f"Pytest: {match.group(1)} passed, {match.group(2)} failed")
    match = re.search(r"(\d+) passed", output)
    if match:
        return post_tool_context(f"Pytest: {match.group(1)} passed")
    return allow()

@registry.hook("python_check_security_issues")
def python_check_security_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    issues = []
    if re.search(r"\bpickle\.load\b", output): issues.append("pickle.load (arbitrary code execution)")
    if re.search(r"\byaml\.load\b(?!.*Loader)", output): issues.append("yaml.load without SafeLoader")
    if re.search(r"\beval\s*\(", output): issues.append("eval()")
    if re.search(r"\bexec\s*\(", output): issues.append("exec()")
    if re.search(r"\bsubprocess\.call\b.*shell\s*=\s*True", output): issues.append("subprocess with shell=True")
    if issues:
        return post_tool_context(f"Python Security: {'; '.join(issues)}")
    return allow()

@registry.hook("python_detect_performance_issues")
def python_detect_performance_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    issues = []
    if re.search(r"\+\s*=\s*.*\bfor\b.*\bin\b", output) and re.search(r"str\s*\+", output):
        issues.append("string concatenation in loop (use str.join())")
    if re.search(r"\blist\(.*\bfor\b.*\bin\b.*\)\s*\[\d+\]", output):
        issues.append("creating full list just to index (use itertools.islice)")
    if issues:
        return post_tool_context(f"Python Performance: {'; '.join(issues)}")
    return allow()


if __name__ == "__main__":
    registry.main()
