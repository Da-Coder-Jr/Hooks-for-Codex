#!/usr/bin/env python3
"""Documentation: Documentation quality hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("detect_missing_readme")
def detect_missing_readme(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bls\b|\bfind\b", cmd) or not output: return allow()
    if re.search(r"package\.json|setup\.py|Cargo\.toml|go\.mod", output):
        if not re.search(r"README|readme", output):
            return post_tool_context("Docs: No README found in project root. Add README.md for project documentation.")
    return allow()

@registry.hook("check_readme_completeness")
def check_readme_completeness(data):
    output = get_command_output(data)
    if not output or not re.search(r"README|readme", get_command(data)): return allow()
    sections = []
    if not re.search(r"#.*install|getting started|setup", output, re.IGNORECASE): sections.append("Installation")
    if not re.search(r"#.*usage|how to use|example", output, re.IGNORECASE): sections.append("Usage")
    if not re.search(r"#.*licen[sc]e", output, re.IGNORECASE): sections.append("License")
    if sections:
        return post_tool_context(f"Docs: README missing sections: {', '.join(sections)}")
    return allow()

@registry.hook("detect_broken_links_in_docs")
def detect_broken_links_in_docs(data):
    output = get_command_output(data)
    if not output: return allow()
    broken = re.findall(r"\[([^\]]+)\]\(([^)]*(?:404|not found|broken)[^)]*)\)", output, re.IGNORECASE)
    dead_refs = re.findall(r"\[([^\]]+)\]\(\s*\)", output)
    if broken or dead_refs:
        count = len(broken) + len(dead_refs)
        return post_tool_context(f"Docs: {count} broken/empty links in documentation.")
    return allow()

@registry.hook("check_api_doc_coverage")
def check_api_doc_coverage(data):
    output = get_command_output(data)
    if not output: return allow()
    public_funcs = re.findall(r"(?:def|function|func|pub fn|public)\s+(\w+)", output)
    documented = re.findall(r'""".*?"""|///.*|/\*\*[\s\S]*?\*/|#\s*@\w+', output, re.DOTALL)
    if len(public_funcs) > 5 and len(documented) < len(public_funcs) // 2:
        return post_tool_context(f"Docs: {len(public_funcs)} public functions, ~{len(documented)} documented. Improve API docs.")
    return allow()

@registry.hook("detect_outdated_docs")
def detect_outdated_docs(data):
    output = get_command_output(data)
    if not output: return allow()
    old_refs = re.findall(r"(?:deprecated|removed in|no longer supported|v[12]\.\d+)", output, re.IGNORECASE)
    if len(old_refs) > 2:
        return post_tool_context(f"Docs: {len(old_refs)} potentially outdated references. Review documentation currency.")
    return allow()

@registry.hook("check_jsdoc_completeness")
def check_jsdoc_completeness(data):
    output = get_command_output(data)
    if not output: return allow()
    jsdoc_blocks = re.findall(r"/\*\*([\s\S]*?)\*/", output)
    issues = 0
    for block in jsdoc_blocks:
        if re.search(r"@param", block) and not re.search(r"@returns?", block):
            issues += 1
    if issues > 2:
        return post_tool_context(f"Docs: {issues} JSDoc blocks with @param but missing @returns.")
    return allow()

@registry.hook("detect_todo_in_docs")
def detect_todo_in_docs(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"\.md$|\.rst$|\.adoc$", get_command(data)):
        todos = re.findall(r"TODO|FIXME|TBD|PLACEHOLDER|coming soon", output, re.IGNORECASE)
        if len(todos) > 2:
            return post_tool_context(f"Docs: {len(todos)} TODO/placeholder items in documentation.")
    return allow()

@registry.hook("check_docstring_format")
def check_docstring_format(data):
    output = get_command_output(data)
    if not output: return allow()
    docstrings = re.findall(r'"""(.*?)"""', output, re.DOTALL)
    issues = []
    for ds in docstrings:
        if len(ds.strip()) < 10: issues.append("too short")
        if re.search(r"Args:|Parameters:", ds) and not re.search(r"Returns:|Raises:", ds):
            issues.append("missing Returns/Raises")
    if len(issues) > 3:
        return post_tool_context(f"Docs: Docstring issues: {len(issues)} problems. Follow Google/NumPy style.")
    return allow()

@registry.hook("detect_sphinx_errors")
def detect_sphinx_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"sphinx|make\s+html|make\s+docs", cmd) or not output: return allow()
    warnings = len(re.findall(r"WARNING:", output))
    errors = len(re.findall(r"ERROR:", output))
    if errors or warnings > 5:
        return post_tool_context(f"Sphinx: {errors} errors, {warnings} warnings in doc build.")
    return allow()

@registry.hook("check_markdown_formatting")
def check_markdown_formatting(data):
    output = get_command_output(data)
    if not output: return allow()
    issues = []
    if re.search(r"^#{1,6}[^\s#]", output, re.MULTILINE): issues.append("missing space after #")
    if re.search(r"\n\n\n\n", output): issues.append("excessive blank lines")
    if re.search(r"^\s*[-*]\s+.{200,}$", output, re.MULTILINE): issues.append("very long list items")
    if issues:
        return post_tool_context(f"Docs: Markdown formatting issues: {', '.join(issues)}")
    return allow()

@registry.hook("detect_typedoc_issues")
def detect_typedoc_issues(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"typedoc|doc:generate", cmd) or not output: return allow()
    if re.search(r"Warning:.*not documented|symbol.*not exported", output):
        count = len(re.findall(r"Warning:", output))
        return post_tool_context(f"TypeDoc: {count} undocumented/unexported symbol warnings.")
    return allow()

@registry.hook("check_openapi_spec")
def check_openapi_spec(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"openapi|swagger", output, re.IGNORECASE):
        issues = []
        if re.search(r"missing.*description|no description", output, re.IGNORECASE): issues.append("missing descriptions")
        if re.search(r"missing.*example|no example", output, re.IGNORECASE): issues.append("missing examples")
        if re.search(r"error.*schema|invalid.*schema", output, re.IGNORECASE): issues.append("schema errors")
        if issues:
            return post_tool_context(f"OpenAPI spec: {', '.join(issues)}")
    return allow()

@registry.hook("detect_license_issues")
def detect_license_issues(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bls\b|\bfind\b", cmd) or not output: return allow()
    if re.search(r"package\.json|setup\.py|Cargo\.toml", output) and not re.search(r"LICENSE|LICENCE|COPYING", output):
        return post_tool_context("Docs: No LICENSE file found. Add a license for open source projects.")
    return allow()

@registry.hook("check_code_examples_in_docs")
def check_code_examples_in_docs(data):
    output = get_command_output(data)
    if not output: return allow()
    code_blocks = re.findall(r"```(\w*)\n", output)
    unlabeled = [b for b in code_blocks if not b]
    if len(unlabeled) > 2:
        return post_tool_context(f"Docs: {len(unlabeled)} code blocks without language labels. Add language for syntax highlighting.")
    return allow()

@registry.hook("detect_stale_screenshots")
def detect_stale_screenshots(data):
    output = get_command_output(data)
    if not output: return allow()
    images = re.findall(r"!\[.*?\]\((\S+\.(?:png|jpg|gif|svg))\)", output)
    broken = [img for img in images if re.search(r"broken|404|not found", output, re.IGNORECASE)]
    if broken:
        return post_tool_context(f"Docs: {len(broken)} broken image references in documentation.")
    return allow()

if __name__ == "__main__":
    registry.main()
