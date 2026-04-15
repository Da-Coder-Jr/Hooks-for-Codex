#!/usr/bin/env python3
"""Language-Specific: Java hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("java_parse_compiler_errors")
def java_parse_compiler_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\b(javac|mvn|gradle)\b", cmd) or not output: return allow()
    errors = re.findall(r"\.java:\d+: error:", output)
    warnings = re.findall(r"\.java:\d+: warning:", output)
    if errors or warnings:
        return post_tool_context(f"Java: {len(errors)} errors, {len(warnings)} warnings")
    return allow()

@registry.hook("java_detect_null_pointer")
def java_detect_null_pointer(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"NullPointerException", output):
        match = re.search(r"at (\S+)\((\S+):(\d+)\)", output)
        loc = f" at {match.group(1)} ({match.group(2)}:{match.group(3)})" if match else ""
        return post_tool_context(f"Java: NullPointerException{loc}. Add null checks or use Optional.")
    return allow()

@registry.hook("java_check_deprecation")
def java_check_deprecation(data):
    output = get_command_output(data)
    if not output: return allow()
    deps = re.findall(r"has been deprecated|@Deprecated", output)
    if len(deps) > 2:
        return post_tool_context(f"Java: {len(deps)} deprecation warnings. Update to newer APIs.")
    return allow()

@registry.hook("java_detect_class_not_found")
def java_detect_class_not_found(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"(?:ClassNotFoundException|NoClassDefFoundError):\s*(\S+)", output)
    if match:
        return post_tool_context(f"Java: Class not found: {match.group(1)}. Check classpath and dependencies.")
    return allow()

@registry.hook("java_check_memory_issues")
def java_check_memory_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"OutOfMemoryError|GC overhead limit exceeded", output):
        return post_tool_context("Java: OutOfMemoryError. Increase heap with -Xmx or fix memory leaks.")
    return allow()

@registry.hook("java_detect_concurrency_issues")
def java_detect_concurrency_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"ConcurrentModificationException", output):
        return post_tool_context("Java: ConcurrentModificationException. Use ConcurrentHashMap or synchronized access.")
    if re.search(r"deadlock|DEADLOCK DETECTED", output, re.IGNORECASE):
        return post_tool_context("Java: Deadlock detected. Review synchronized block ordering.")
    return allow()

@registry.hook("java_check_maven_build")
def java_check_maven_build(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bmvn\b", cmd) or not output: return allow()
    if re.search(r"BUILD FAILURE", output):
        error = re.search(r"\[ERROR\]\s*(.*?)$", output, re.MULTILINE)
        return post_tool_context(f"Maven BUILD FAILURE: {error.group(1) if error else 'check output'}")
    if re.search(r"BUILD SUCCESS", output):
        return post_tool_context("Maven: BUILD SUCCESS")
    return allow()

@registry.hook("java_check_gradle_build")
def java_check_gradle_build(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgradle\b", cmd) or not output: return allow()
    if re.search(r"BUILD FAILED", output):
        return post_tool_context("Gradle: BUILD FAILED. Check error messages above.")
    if re.search(r"BUILD SUCCESSFUL", output):
        tasks = re.search(r"(\d+) actionable task", output)
        return post_tool_context(f"Gradle: BUILD SUCCESSFUL ({tasks.group(1)} tasks)" if tasks else "Gradle: BUILD SUCCESSFUL")
    return allow()

@registry.hook("java_detect_test_failures")
def java_detect_test_failures(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)", output)
    if match:
        return post_tool_context(f"Java Tests: {match.group(1)} run, {match.group(2)} failures, {match.group(3)} errors, {match.group(4)} skipped")
    return allow()

@registry.hook("java_check_dependency_conflicts")
def java_check_dependency_conflicts(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Conflict.*version|version conflict|Could not resolve.*dependencies", output, re.IGNORECASE):
        return post_tool_context("Java: Dependency version conflict. Use dependency management to resolve.")
    return allow()

@registry.hook("java_detect_security_issues")
def java_detect_security_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    issues = []
    if re.search(r"ObjectInputStream|readObject|Serializable", output): issues.append("deserialization")
    if re.search(r"Statement.*execute.*\+.*\"", output): issues.append("SQL concatenation")
    if re.search(r"Runtime\.getRuntime\(\)\.exec", output): issues.append("Runtime.exec()")
    if issues:
        return post_tool_context(f"Java Security: Potential issues: {', '.join(issues)}")
    return allow()

@registry.hook("java_check_spring_issues")
def java_check_spring_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"BeanCreationException|NoSuchBeanDefinitionException|ApplicationContextException", output):
        match = re.search(r"(?:BeanCreationException|NoSuchBeanDefinitionException).*?:\s*(.*?)$", output, re.MULTILINE)
        return post_tool_context(f"Spring: Bean error: {match.group(1)[:100] if match else 'check context configuration'}")
    return allow()

@registry.hook("java_detect_classpath_issues")
def java_detect_classpath_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"ClassPath.*error|class path.*not found|jar.*not found", output, re.IGNORECASE):
        return post_tool_context("Java: Classpath issue. Check build tool configuration and JAR dependencies.")
    return allow()

@registry.hook("java_check_module_system")
def java_check_module_system(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"module.*does not.*export|requires.*module|module-info.*error", output):
        return post_tool_context("Java: Module system (JPMS) error. Check module-info.java exports/requires.")
    return allow()

@registry.hook("java_detect_resource_leaks")
def java_detect_resource_leaks(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Resource leak|unclosed|potential.*leak", output, re.IGNORECASE):
        return post_tool_context("Java: Resource leak warning. Use try-with-resources for AutoCloseable resources.")
    return allow()

if __name__ == "__main__":
    registry.main()
