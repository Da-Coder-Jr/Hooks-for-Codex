#!/usr/bin/env python3
"""DevOps: CI/CD pipeline hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("detect_github_actions_errors")
def detect_github_actions_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Error:.*Process completed with exit code|##\[error\]|::error::", output):
        match = re.search(r"(?:##\[error\]|::error::)\s*(.*?)$", output, re.MULTILINE)
        return post_tool_context(f"GitHub Actions error: {match.group(1)[:100] if match else 'check workflow logs'}")
    return allow()

@registry.hook("check_workflow_syntax")
def check_workflow_syntax(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Invalid workflow file|yaml syntax error|workflow.*not valid", output, re.IGNORECASE):
        return post_tool_context("CI/CD: Workflow YAML syntax error. Validate with actionlint or yamllint.")
    return allow()

@registry.hook("detect_pipeline_timeout")
def detect_pipeline_timeout(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"timed out|timeout exceeded|Job was cancelled.*timeout|execution expired", output, re.IGNORECASE):
        return post_tool_context("CI/CD: Pipeline timed out. Optimize build steps or increase timeout limit.")
    return allow()

@registry.hook("check_cache_efficiency")
def check_cache_efficiency(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Cache not found|cache miss|no cache.*restore|Skipping cache", output, re.IGNORECASE):
        return post_tool_context("CI/CD: Cache miss. Check cache key patterns for proper hit rates.")
    if re.search(r"Cache restored|cache hit", output, re.IGNORECASE):
        return post_tool_context("CI/CD: Cache hit - build should be faster.")
    return allow()

@registry.hook("detect_artifact_upload_failure")
def detect_artifact_upload_failure(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"artifact.*upload.*fail|failed to upload|Unable to find.*artifact", output, re.IGNORECASE):
        return post_tool_context("CI/CD: Artifact upload failed. Check file paths and artifact size limits.")
    return allow()

@registry.hook("check_environment_secrets")
def check_environment_secrets(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"secret.*not found|variable.*not set|undefined.*secret|env.*undefined", output, re.IGNORECASE):
        if re.search(r"(?:GITHUB|CI|DEPLOY|AWS|NPM)_", output):
            return post_tool_context("CI/CD: Environment secret/variable not found. Check repository/environment settings.")
    return allow()

@registry.hook("detect_test_failure_in_ci")
def detect_test_failure_in_ci(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Tests?\s+failed|FAILED.*test|test.*suite.*fail|\d+\s+failing", output, re.IGNORECASE):
        match = re.search(r"(\d+)\s+(?:failing|failed)", output, re.IGNORECASE)
        count = match.group(1) if match else "some"
        return post_tool_context(f"CI/CD: {count} test(s) failed. Fix before merging.")
    return allow()

@registry.hook("check_build_matrix")
def check_build_matrix(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"matrix.*strategy|matrix.*include|matrix expansion", output):
        match = re.search(r"(\d+)\s+jobs?\s+(?:in|from)\s+matrix", output)
        if match:
            return post_tool_context(f"CI/CD: Build matrix expanding to {match.group(1)} jobs.")
    return allow()

@registry.hook("detect_deployment_failure")
def detect_deployment_failure(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"deploy.*fail|deployment.*error|rollback.*triggered|release.*failed", output, re.IGNORECASE):
        return post_tool_context("CI/CD: Deployment failed. Check deployment logs and consider rollback.")
    return allow()

@registry.hook("check_code_coverage_gate")
def check_code_coverage_gate(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r"coverage.*?(\d+(?:\.\d+)?)\s*%", output, re.IGNORECASE)
    if match:
        coverage = float(match.group(1))
        if coverage < 50:
            return post_tool_context(f"CI/CD: Code coverage at {coverage}%. Below typical threshold (80%).")
        elif coverage >= 80:
            return post_tool_context(f"CI/CD: Code coverage at {coverage}%. Meets threshold.")
    return allow()

@registry.hook("detect_dependency_install_failure")
def detect_dependency_install_failure(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"npm ERR!.*install|pip.*error|Could not resolve dependencies|ERESOLVE", output, re.IGNORECASE):
        return post_tool_context("CI/CD: Dependency installation failed. Check lockfile and version constraints.")
    return allow()

@registry.hook("check_docker_build_in_ci")
def check_docker_build_in_ci(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Successfully built|Successfully tagged|pushed.*digest", output):
        match = re.search(r"Successfully tagged\s+(\S+)", output)
        if match:
            return post_tool_context(f"CI/CD: Docker image built: {match.group(1)}")
    return allow()

@registry.hook("detect_linting_gate_failure")
def detect_linting_gate_failure(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"lint.*error|linting.*failed|style.*check.*fail", output, re.IGNORECASE):
        match = re.search(r"(\d+)\s+errors?", output)
        return post_tool_context(f"CI/CD: Lint gate failed{f' ({match.group(1)} errors)' if match else ''}. Fix style issues.")
    return allow()

@registry.hook("check_security_scan_results")
def check_security_scan_results(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"vulnerability.*found|security.*scan.*fail|CVE-\d{4}", output, re.IGNORECASE):
        cves = re.findall(r"CVE-\d{4}-\d+", output)
        if cves:
            return post_tool_context(f"CI/CD: Security scan found {len(cves)} CVEs: {', '.join(cves[:3])}")
        else:
            return post_tool_context("CI/CD: Security scan found vulnerabilities. Review before deploying.")
    return allow()

@registry.hook("detect_release_publish")
def detect_release_publish(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Published.*release|Release.*created|published.*to.*npm|uploaded.*to.*PyPI", output, re.IGNORECASE):
        match = re.search(r"(?:version|v)\s*(\d+\.\d+\.\d+\S*)", output, re.IGNORECASE)
        version = match.group(1) if match else "new version"
        return post_tool_context(f"CI/CD: Release published: {version}")
    return allow()

if __name__ == "__main__":
    registry.main()
