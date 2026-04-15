#!/usr/bin/env python3
"""Dependencies: Version management hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("check_node_version")
def check_node_version(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"node\s+(-v|--version)", cmd) or not output: return allow()
    match = re.search(r"v(\d+)\.", output)
    if match:
        major = int(match.group(1))
        if major < 18:
            return post_tool_context(f"Version: Node.js v{major} is EOL. Upgrade to v18+ (LTS).")
        if major % 2 != 0:
            return post_tool_context(f"Version: Node.js v{major} is odd-numbered (non-LTS). Use even versions for stability.")
    return allow()

@registry.hook("check_python_version")
def check_python_version(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"python3?\s+(-V|--version)", cmd) or not output: return allow()
    match = re.search(r"Python (\d+)\.(\d+)\.(\d+)", output)
    if match:
        major, minor = int(match.group(1)), int(match.group(2))
        if major == 2:
            return post_tool_context("Version: Python 2 is EOL. Migrate to Python 3.8+.")
        if minor < 8:
            return post_tool_context(f"Version: Python 3.{minor} is EOL. Upgrade to 3.8+.")
    return allow()

@registry.hook("check_java_version")
def check_java_version(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"java\s+(-version|--version)", cmd) or not output: return allow()
    match = re.search(r'"?(\d+)(?:\.(\d+))?', output)
    if match:
        major = int(match.group(1))
        lts = {8, 11, 17, 21}
        if major not in lts and major < 21:
            return post_tool_context(f"Version: Java {major} is not LTS. Consider Java {max(v for v in lts if v <= max(major, 21))} (LTS).")
    return allow()

@registry.hook("check_go_version")
def check_go_version(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"go\s+version", cmd) or not output: return allow()
    match = re.search(r"go(\d+)\.(\d+)", output)
    if match:
        major, minor = int(match.group(1)), int(match.group(2))
        if major == 1 and minor < 21:
            return post_tool_context(f"Version: Go 1.{minor} may be outdated. Consider Go 1.21+.")
    return allow()

@registry.hook("check_rust_version")
def check_rust_version(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"rustc\s+--version|cargo\s+--version", cmd) or not output: return allow()
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", output)
    if match:
        minor = int(match.group(2))
        if minor < 70:
            return post_tool_context(f"Version: Rust 1.{minor} is old. Run rustup update for latest features.")
    return allow()

@registry.hook("check_npm_version")
def check_npm_version(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"npm\s+(-v|--version)", cmd) or not output: return allow()
    match = re.search(r"(\d+)\.", output)
    if match and int(match.group(1)) < 8:
        return post_tool_context(f"Version: npm {match.group(0)} is outdated. Upgrade to npm 8+ with: npm install -g npm@latest")
    return allow()

@registry.hook("detect_nvmrc_mismatch")
def detect_nvmrc_mismatch(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"\.nvmrc|\.node-version", get_command(data)):
        required = re.search(r"v?(\d+(?:\.\d+)*)", output)
        if required:
            return post_tool_context(f"Version: Project requires Node {required.group(1)}. Run nvm use or nvm install.")
    return allow()

@registry.hook("check_docker_version")
def check_docker_version(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"docker\s+(-v|--version|version)", cmd) or not output: return allow()
    match = re.search(r"(\d+)\.(\d+)\.", output)
    if match and int(match.group(1)) < 20:
        return post_tool_context(f"Version: Docker {match.group(0)} is old. Upgrade for security fixes and new features.")
    return allow()

@registry.hook("check_terraform_version")
def check_terraform_version(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"terraform\s+(-v|--version|version)", cmd) or not output: return allow()
    match = re.search(r"v?(\d+)\.(\d+)\.(\d+)", output)
    if match:
        major, minor = int(match.group(1)), int(match.group(2))
        if major < 1:
            return post_tool_context(f"Version: Terraform 0.{minor} is pre-1.0. Upgrade to 1.x for stability.")
    return allow()

@registry.hook("check_kubectl_version_skew")
def check_kubectl_version_skew(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"kubectl\s+version", cmd) or not output: return allow()
    client = re.search(r"Client Version.*?v(\d+)\.(\d+)", output)
    server = re.search(r"Server Version.*?v(\d+)\.(\d+)", output)
    if client and server:
        client_minor = int(client.group(2))
        server_minor = int(server.group(2))
        skew = abs(client_minor - server_minor)
        if skew > 1:
            return post_tool_context(f"Version: kubectl/cluster version skew is {skew} (max 1). Update kubectl.")
    return allow()

@registry.hook("detect_ruby_version_mismatch")
def detect_ruby_version_mismatch(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Your Ruby version is.*but your Gemfile specified|ruby.*version.*mismatch", output, re.IGNORECASE):
        return post_tool_context("Version: Ruby version mismatch with Gemfile. Use rbenv/rvm to switch.")
    return allow()

@registry.hook("check_php_version")
def check_php_version(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"php\s+(-v|--version)", cmd) or not output: return allow()
    match = re.search(r"PHP (\d+)\.(\d+)", output)
    if match:
        major, minor = int(match.group(1)), int(match.group(2))
        if major < 8:
            return post_tool_context(f"Version: PHP {major}.{minor} may be EOL. Upgrade to PHP 8.1+.")
    return allow()

@registry.hook("check_dotnet_version")
def check_dotnet_version(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"dotnet\s+--version|dotnet\s+--info", cmd) or not output: return allow()
    match = re.search(r"(\d+)\.(\d+)\.", output)
    if match:
        major = int(match.group(1))
        if major < 6:
            return post_tool_context(f"Version: .NET {major} is old. Upgrade to .NET 6+ (LTS) or .NET 8 (latest LTS).")
    return allow()

@registry.hook("detect_engine_requirements")
def detect_engine_requirements(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r'"engines"', output) and re.search(r"package\.json", get_command(data)):
        match = re.search(r'"node"\s*:\s*"([^"]+)"', output)
        if match:
            return post_tool_context(f"Version: package.json requires Node {match.group(1)}. Ensure CI and local match.")
    return allow()

@registry.hook("check_minimum_version_support")
def check_minimum_version_support(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"requires.*version|minimum.*version.*\d|version.*not supported", output, re.IGNORECASE):
        match = re.search(r"(?:requires?|minimum).*?version\s*(\S+)", output, re.IGNORECASE)
        if match:
            return post_tool_context(f"Version: Minimum version requirement: {match.group(1)}")
    return allow()

if __name__ == "__main__":
    registry.main()
