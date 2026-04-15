#!/usr/bin/env python3
"""Dependencies: Dependency audit hooks for Codex. 20 PreToolUse/PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("parse_npm_audit")
def parse_npm_audit(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"npm\s+audit", cmd) or not output: return allow()
    match = re.search(r"(\d+)\s+(?:vulnerabilit|vuln)", output)
    critical = len(re.findall(r"critical", output, re.IGNORECASE))
    high = len(re.findall(r"\bhigh\b", output, re.IGNORECASE))
    if match:
        total = match.group(1)
        parts = [f"{total} vulnerabilities"]
        if critical: parts.append(f"{critical} critical")
        if high: parts.append(f"{high} high")
        return post_tool_context(f"npm audit: {', '.join(parts)}")
    return allow()

@registry.hook("parse_pip_audit")
def parse_pip_audit(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"pip.?audit|safety\s+check|pip\s+check", cmd) or not output: return allow()
    vulns = re.findall(r"(\S+)\s+(\S+)\s+.*?(CVE-\d{4}-\d+|PYSEC-\d{4})", output)
    if vulns:
        names = ", ".join(f"{n}@{v}({c})" for n, v, c in vulns[:5])
        return post_tool_context(f"pip audit: {len(vulns)} vulnerabilities: {names}")
    return allow()

@registry.hook("parse_cargo_audit")
def parse_cargo_audit(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"cargo\s+audit", cmd) or not output: return allow()
    vulns = re.findall(r"(RUSTSEC-\d{4}-\d+)", output)
    if vulns:
        return post_tool_context(f"cargo audit: {len(vulns)} advisories: {', '.join(vulns[:5])}")
    return allow()

@registry.hook("parse_snyk_results")
def parse_snyk_results(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bsnyk\b", cmd) or not output: return allow()
    match = re.search(r"(\d+)\s+vulnerabilit", output)
    if match:
        return post_tool_context(f"Snyk: {match.group(1)} vulnerabilities found")
    return allow()

@registry.hook("detect_outdated_npm_packages")
def detect_outdated_npm_packages(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"npm\s+outdated", cmd) or not output: return allow()
    outdated = re.findall(r"(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", output)
    major_updates = [(n, c, w) for n, c, w, l in outdated if c and w and c.split(".")[0] != w.split(".")[0]]
    if major_updates:
        names = ", ".join(f"{n}({c}→{w})" for n, c, w in major_updates[:5])
        return post_tool_context(f"npm: {len(major_updates)} major version updates available: {names}")
    return allow()

@registry.hook("detect_outdated_pip_packages")
def detect_outdated_pip_packages(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"pip\s+list\s+--outdated|pip\s+list\s+-o", cmd) or not output: return allow()
    outdated = re.findall(r"(\S+)\s+(\S+)\s+(\S+)\s+\w+", output)
    if len(outdated) > 10:
        return post_tool_context(f"pip: {len(outdated)} outdated packages. Run pip-review or update selectively.")
    return allow()

@registry.hook("block_install_typosquat_package")
def block_install_typosquat_package(data):
    cmd = get_command(data)
    match = re.search(r"(?:npm\s+install|pip\s+install|gem\s+install)\s+(\S+)", cmd)
    if match:
        pkg = match.group(1).lower().strip()
        typosquats = {
            "coffe-script": "coffeescript", "cross-env.js": "cross-env",
            "event-stream": "events-stream", "lodash.": "lodash",
            "electorn": "electron", "reqeusts": "requests",
            "djnago": "django", "flaask": "flask",
            "numpay": "numpy", "pandsa": "pandas",
        }
        for typo, real in typosquats.items():
            if typo in pkg and real not in pkg:
                return deny(f"Deps: Possible typosquat package '{pkg}'. Did you mean '{real}'?")
    return allow()

@registry.hook("detect_license_compatibility")
def detect_license_compatibility(data):
    output = get_command_output(data)
    if not output: return allow()
    copyleft = re.findall(r"(GPL|AGPL|LGPL|SSPL|EUPL)\s", output)
    if copyleft:
        return post_tool_context(f"Deps: Copyleft licenses found: {', '.join(set(copyleft))}. Check compatibility with your project license.")
    return allow()

@registry.hook("check_dependency_size")
def check_dependency_size(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"du\s+-.*node_modules|npm\s+ls", cmd) or not output: return allow()
    match = re.search(r"(\d+(?:\.\d+)?)\s*(M|G).*node_modules", output)
    if match:
        size, unit = float(match.group(1)), match.group(2)
        if unit == "G" or (unit == "M" and size > 500):
            return post_tool_context(f"Deps: node_modules is {size}{unit}. Review and prune unnecessary dependencies.")
    return allow()

@registry.hook("detect_peer_dependency_issues")
def detect_peer_dependency_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"peer dep|ERESOLVE|peer dependency|Could not resolve dependency", output, re.IGNORECASE):
        match = re.search(r"(?:peer dep|ERESOLVE).*?(\S+@\S+)", output)
        return post_tool_context(f"Deps: Peer dependency conflict{f' ({match.group(1)})' if match else ''}. Use --legacy-peer-deps or resolve manually.")
    return allow()

@registry.hook("check_lockfile_integrity")
def check_lockfile_integrity(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Your lockfile needs to be updated|lockfile.*outdated|frozen lockfile|integrity check.*failed", output, re.IGNORECASE):
        return post_tool_context("Deps: Lockfile out of sync. Run install to update lockfile.")
    return allow()

@registry.hook("detect_deprecated_packages")
def detect_deprecated_packages(data):
    output = get_command_output(data)
    if not output: return allow()
    deprecated = re.findall(r"npm WARN deprecated (\S+@\S+)", output)
    if deprecated:
        return post_tool_context(f"Deps: {len(deprecated)} deprecated packages: {', '.join(deprecated[:5])}")
    return allow()

@registry.hook("check_python_requirements_format")
def check_python_requirements_format(data):
    output = get_command_output(data)
    if not output or not re.search(r"requirements.*\.txt", get_command(data)): return allow()
    unpinned = re.findall(r"^(\w[\w-]+)\s*$", output, re.MULTILINE)
    if len(unpinned) > 3:
        return post_tool_context(f"Deps: {len(unpinned)} unpinned packages in requirements.txt. Pin versions for reproducibility.")
    return allow()

@registry.hook("detect_unused_dependencies")
def detect_unused_dependencies(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"depcheck|unused|pipreqs", cmd) or not output: return allow()
    unused = re.findall(r"Unused.*?:\s*(\S+)|(\S+)\s+is unused", output, re.IGNORECASE)
    if unused:
        names = [u[0] or u[1] for u in unused[:10]]
        return post_tool_context(f"Deps: {len(unused)} unused dependencies: {', '.join(names)}")
    return allow()

@registry.hook("check_go_mod_issues")
def check_go_mod_issues(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"go\s+mod\s+(?:tidy|verify|graph)", cmd) or not output: return allow()
    if re.search(r"missing go.sum entry|verif.*fail|not satisfied", output):
        return post_tool_context("Deps: Go module issue. Run go mod tidy to fix dependencies.")
    return allow()

@registry.hook("detect_supply_chain_indicators")
def detect_supply_chain_indicators(data):
    output = get_command_output(data)
    if not output: return allow()
    indicators = []
    if re.search(r"postinstall.*curl|postinstall.*wget|preinstall.*http", output): indicators.append("network in lifecycle scripts")
    if re.search(r"install.*--ignore-scripts", output): indicators.append("scripts disabled (may break)")
    if indicators:
        return post_tool_context(f"Deps: Supply chain concern: {', '.join(indicators)}")
    return allow()

@registry.hook("check_cargo_toml_issues")
def check_cargo_toml_issues(data):
    output = get_command_output(data)
    if not output or not re.search(r"Cargo\.toml", get_command(data)): return allow()
    wildcards = re.findall(r'(\w+)\s*=\s*"\*"', output)
    if wildcards:
        return post_tool_context(f"Deps: Wildcard versions in Cargo.toml: {', '.join(wildcards)}. Pin to specific versions.")
    return allow()

@registry.hook("detect_duplicate_dependencies")
def detect_duplicate_dependencies(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"duplicate.*package|dedup|multiple versions of", output, re.IGNORECASE):
        return post_tool_context("Deps: Duplicate packages detected. Run deduplicate to reduce bundle size.")
    return allow()

@registry.hook("check_bundler_audit")
def check_bundler_audit(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"bundle.?audit|bundler-audit", cmd) or not output: return allow()
    vulns = re.findall(r"(CVE-\d{4}-\d+|GHSA-\w+-\w+-\w+)", output)
    if vulns:
        return post_tool_context(f"bundle-audit: {len(vulns)} advisories: {', '.join(vulns[:5])}")
    return allow()

@registry.hook("detect_phantom_dependencies")
def detect_phantom_dependencies(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"phantom.*depend|undeclared.*depend|not.*listed.*package\.json", output, re.IGNORECASE):
        return post_tool_context("Deps: Phantom dependency (used but not declared). Add to package.json explicitly.")
    return allow()

if __name__ == "__main__":
    registry.main()
