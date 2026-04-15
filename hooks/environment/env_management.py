#!/usr/bin/env python3
"""Hooks for environment management - variable validation, tool checks, version matching."""
import json
import re
import sys
import os
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import (
    HookRegistry, deny, allow, post_tool_context, session_context,
    get_command, get_command_output, get_cwd, get_session_id
)
from _lib.utils import log_event, file_exists, read_file_safe

registry = HookRegistry()

PRODUCTION_ENV_PATTERNS = [
    r'DATABASE_URL\s*=\s*.*prod',
    r'NODE_ENV\s*=\s*production',
    r'RAILS_ENV\s*=\s*production',
    r'DJANGO_SETTINGS_MODULE\s*=\s*.*prod',
    r'APP_ENV\s*=\s*production',
    r'ENVIRONMENT\s*=\s*prod',
    r'AWS_.*=.*prod',
]

REQUIRED_TOOLS_BY_PROJECT = {
    "package.json": ["node", "npm"],
    "yarn.lock": ["yarn"],
    "pnpm-lock.yaml": ["pnpm"],
    "Cargo.toml": ["cargo", "rustc"],
    "go.mod": ["go"],
    "Gemfile": ["ruby", "bundle"],
    "requirements.txt": ["python3"],
    "pyproject.toml": ["python3"],
    "composer.json": ["php", "composer"],
    "Dockerfile": ["docker"],
    "docker-compose.yml": ["docker", "docker-compose"],
    "docker-compose.yaml": ["docker", "docker-compose"],
    "Makefile": ["make"],
}


def _parse_env_file(filepath):
    """Parse a .env file into a dict of key-value pairs."""
    result = {}
    try:
        content = read_file_safe(filepath)
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)', line)
            if m:
                key = m.group(1)
                value = m.group(2).strip().strip("'\"")
                result[key] = value
    except Exception:
        pass
    return result


def _check_tool_installed(tool):
    """Check if a CLI tool is installed and accessible."""
    try:
        result = subprocess.run(
            ["which", tool],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def _get_tool_version(tool):
    """Get version of installed tool."""
    version_flags = ["--version", "-v", "version", "-V"]
    for flag in version_flags:
        try:
            result = subprocess.run(
                [tool, flag],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout + result.stderr
            m = re.search(r'(\d+\.\d+(?:\.\d+)?)', output)
            if m:
                return m.group(1)
        except Exception:
            continue
    return None


@registry.hook("env_detect_missing_vars")
def env_detect_missing_vars(data):
    """Detect missing required environment variables."""
    cwd = get_cwd(data)
    session_id = get_session_id(data)
    # Check .env.example for required variables
    example_path = os.path.join(cwd, ".env.example")
    env_path = os.path.join(cwd, ".env")
    if not os.path.isfile(example_path):
        return allow()
    example_vars = _parse_env_file(example_path)
    env_vars = _parse_env_file(env_path) if os.path.isfile(env_path) else {}
    missing = []
    empty = []
    for key in example_vars:
        if key not in env_vars and key not in os.environ:
            missing.append(key)
        elif key in env_vars and not env_vars[key]:
            empty.append(key)
    if missing or empty:
        parts = []
        if missing:
            parts.append(f"Missing: {', '.join(missing[:10])}")
        if empty:
            parts.append(f"Empty: {', '.join(empty[:10])}")
        return session_context(
            "ENV VARIABLES: " + "; ".join(parts) +
            ". Check .env.example for required values."
        )
    return allow()


@registry.hook("env_validate_format")
def env_validate_format(data):
    """Validate .env file format."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    # Check if .env was just edited
    if not re.search(r'\.env\b', command):
        return allow()
    env_path = os.path.join(cwd, ".env")
    if not os.path.isfile(env_path):
        return allow()
    content = read_file_safe(env_path)
    issues = []
    for i, line in enumerate(content.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Check format
        if "=" not in line:
            issues.append(f"Line {i}: Missing '=' separator: {line[:50]}")
            continue
        key, _, value = line.partition("=")
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', key.strip()):
            issues.append(f"Line {i}: Invalid variable name: {key[:30]}")
        # Check for unquoted values with spaces
        if " " in value and not (value.startswith('"') or value.startswith("'")):
            issues.append(f"Line {i}: Value with spaces should be quoted: {key.strip()}")
        # Check for trailing whitespace in values
        if value != value.rstrip() and not value.startswith('"'):
            issues.append(f"Line {i}: Trailing whitespace in {key.strip()}")
    if issues:
        return post_tool_context(
            "ENV FILE FORMAT ISSUES:\n" + "\n".join(f"  - {i}" for i in issues[:10])
        )
    return allow()


@registry.hook("env_check_example_sync")
def env_check_example_sync(data):
    """Check .env matches .env.example."""
    cwd = get_cwd(data)
    example_path = os.path.join(cwd, ".env.example")
    env_path = os.path.join(cwd, ".env")
    if not os.path.isfile(example_path) or not os.path.isfile(env_path):
        return allow()
    example_vars = set(_parse_env_file(example_path).keys())
    env_vars = set(_parse_env_file(env_path).keys())
    missing_from_env = example_vars - env_vars
    extra_in_env = env_vars - example_vars
    issues = []
    if missing_from_env:
        issues.append(f"In .env.example but not in .env: {', '.join(sorted(missing_from_env)[:5])}")
    if extra_in_env:
        issues.append(f"In .env but not in .env.example: {', '.join(sorted(extra_in_env)[:5])}")
    if issues:
        return session_context(
            "ENV SYNC: .env and .env.example are out of sync:\n"
            + "\n".join(f"  - {i}" for i in issues)
            + "\nUpdate .env.example when adding new environment variables."
        )
    return allow()


@registry.hook("env_detect_overrides")
def env_detect_overrides(data):
    """Detect environment variable overrides in commands."""
    command = get_command(data)
    # Detect inline env var overrides: VAR=value command
    overrides = re.findall(r'^([A-Z_][A-Z0-9_]*)=(\S+)\s+\w', command)
    if not overrides:
        overrides = re.findall(r'\bexport\s+([A-Z_][A-Z0-9_]*)=(\S+)', command)
    if overrides:
        override_list = [f"{k}={v[:20]}{'...' if len(v) > 20 else ''}" for k, v in overrides[:5]]
        return post_tool_context(
            f"ENV OVERRIDE: {len(overrides)} variable(s) overridden: {', '.join(override_list)}. "
            "Ensure these overrides are intentional and won't affect other processes."
        )
    return allow()


@registry.hook("env_block_production_values")
def env_block_production_values(data):
    """Block setting production env vars locally."""
    command = get_command(data)
    for pattern in PRODUCTION_ENV_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return deny(
                "BLOCKED: Production environment variable detected in command. "
                "Setting production values locally risks accidentally connecting to production services. "
                "Use a .env.local file or environment-specific configuration."
            )
    return allow()


@registry.hook("env_validate_urls")
def env_validate_urls(data):
    """Validate URL environment variables."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    env_path = os.path.join(cwd, ".env")
    if not re.search(r'\.env\b', command) or not os.path.isfile(env_path):
        return allow()
    env_vars = _parse_env_file(env_path)
    url_keys = [k for k in env_vars if re.search(r'URL|URI|ENDPOINT|HOST|ORIGIN', k, re.IGNORECASE)]
    issues = []
    for key in url_keys:
        value = env_vars[key]
        if not value:
            continue
        if re.search(r'URL|URI|ENDPOINT|ORIGIN', key, re.IGNORECASE):
            if not re.match(r'^https?://', value) and not re.match(r'^(postgres|mysql|redis|mongodb|amqp)://', value):
                issues.append(f"{key}: Value '{value[:30]}' doesn't look like a valid URL")
        if re.search(r'HOST$', key):
            if re.search(r'^https?://', value):
                issues.append(f"{key}: Should be hostname only, not full URL")
    if issues:
        return post_tool_context(
            "ENV URL VALIDATION:\n" + "\n".join(f"  - {i}" for i in issues[:5])
        )
    return allow()


@registry.hook("env_validate_ports")
def env_validate_ports(data):
    """Validate port number environment variables."""
    cwd = get_cwd(data)
    command = get_command(data)
    if not re.search(r'\.env\b', command):
        return allow()
    env_path = os.path.join(cwd, ".env")
    if not os.path.isfile(env_path):
        return allow()
    env_vars = _parse_env_file(env_path)
    port_keys = [k for k in env_vars if re.search(r'PORT', k, re.IGNORECASE)]
    issues = []
    for key in port_keys:
        value = env_vars[key]
        if not value:
            continue
        try:
            port = int(value)
            if port < 1 or port > 65535:
                issues.append(f"{key}={value}: Port must be between 1 and 65535")
            elif port < 1024:
                issues.append(f"{key}={value}: Privileged port (< 1024) - may require root/sudo")
        except ValueError:
            issues.append(f"{key}={value}: Not a valid port number")
    if issues:
        return post_tool_context(
            "ENV PORT VALIDATION:\n" + "\n".join(f"  - {i}" for i in issues[:5])
        )
    return allow()


@registry.hook("env_validate_paths")
def env_validate_paths(data):
    """Validate file path environment variables."""
    cwd = get_cwd(data)
    command = get_command(data)
    if not re.search(r'\.env\b', command):
        return allow()
    env_path = os.path.join(cwd, ".env")
    if not os.path.isfile(env_path):
        return allow()
    env_vars = _parse_env_file(env_path)
    path_keys = [k for k in env_vars if re.search(r'PATH|DIR|DIRECTORY|FOLDER|FILE|LOG_FILE', k, re.IGNORECASE)]
    # Exclude standard PATH
    path_keys = [k for k in path_keys if k != "PATH"]
    issues = []
    for key in path_keys:
        value = env_vars[key]
        if not value:
            continue
        # Expand ~ in paths
        expanded = os.path.expanduser(value)
        if os.path.isabs(expanded) and not os.path.exists(expanded):
            issues.append(f"{key}: Path does not exist: {value}")
    if issues:
        return post_tool_context(
            "ENV PATH VALIDATION:\n" + "\n".join(f"  - {i}" for i in issues[:5])
        )
    return allow()


@registry.hook("env_check_required_tools")
def env_check_required_tools(data):
    """Check required CLI tools are installed."""
    cwd = get_cwd(data)
    missing_tools = []
    for project_file, tools in REQUIRED_TOOLS_BY_PROJECT.items():
        if os.path.isfile(os.path.join(cwd, project_file)):
            for tool in tools:
                if not _check_tool_installed(tool):
                    missing_tools.append(f"{tool} (needed for {project_file})")
    if missing_tools:
        return session_context(
            "MISSING TOOLS:\n"
            + "\n".join(f"  - {t}" for t in missing_tools[:10])
            + "\nInstall missing tools before running project commands."
        )
    return allow()


@registry.hook("env_validate_node_version")
def env_validate_node_version(data):
    """Check Node.js version matches .nvmrc/.node-version."""
    cwd = get_cwd(data)
    expected = None
    source_file = None
    for fname in [".nvmrc", ".node-version"]:
        fpath = os.path.join(cwd, fname)
        if os.path.isfile(fpath):
            content = read_file_safe(fpath).strip()
            # Handle formats: "16", "v16", "16.14.0", "lts/hydrogen"
            m = re.search(r'v?(\d+(?:\.\d+(?:\.\d+)?)?)', content)
            if m:
                expected = m.group(1)
                source_file = fname
            break
    if not expected:
        return allow()
    actual = _get_tool_version("node")
    if actual:
        # Compare major versions at minimum
        expected_parts = expected.split(".")
        actual_parts = actual.split(".")
        if expected_parts[0] != actual_parts[0]:
            return session_context(
                f"NODE VERSION MISMATCH: {source_file} requires Node {expected}, "
                f"but installed version is {actual}. "
                f"Run 'nvm use' or 'nvm install {expected}' to switch."
            )
    return allow()


@registry.hook("env_validate_python_version")
def env_validate_python_version(data):
    """Check Python version matches requirements."""
    cwd = get_cwd(data)
    expected = None
    source_file = None
    # Check .python-version (pyenv)
    pyver_path = os.path.join(cwd, ".python-version")
    if os.path.isfile(pyver_path):
        content = read_file_safe(pyver_path).strip()
        m = re.search(r'(\d+\.\d+(?:\.\d+)?)', content)
        if m:
            expected = m.group(1)
            source_file = ".python-version"
    # Check pyproject.toml for requires-python
    if not expected:
        pyproject = os.path.join(cwd, "pyproject.toml")
        if os.path.isfile(pyproject):
            content = read_file_safe(pyproject)
            m = re.search(r'requires-python\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                req = m.group(1)
                # Extract minimum version from >=3.8 etc
                m2 = re.search(r'>=?\s*(\d+\.\d+)', req)
                if m2:
                    expected = m2.group(1)
                    source_file = "pyproject.toml"
    if not expected:
        return allow()
    actual = _get_tool_version("python3")
    if actual:
        expected_parts = [int(x) for x in expected.split(".")]
        actual_parts = [int(x) for x in actual.split(".")]
        # Check if actual >= expected
        if actual_parts[:len(expected_parts)] < expected_parts:
            return session_context(
                f"PYTHON VERSION: {source_file} requires Python >= {expected}, "
                f"but installed version is {actual}. "
                "Use pyenv or update Python."
            )
    return allow()


@registry.hook("env_check_docker_running")
def env_check_docker_running(data):
    """Check Docker daemon is running."""
    cwd = get_cwd(data)
    # Only check if project uses Docker
    has_docker = any(
        os.path.isfile(os.path.join(cwd, f))
        for f in ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"]
    )
    if not has_docker:
        return allow()
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return session_context(
                "DOCKER NOT RUNNING: Docker daemon is not running. "
                "Start Docker with 'sudo systemctl start docker' (Linux) "
                "or open Docker Desktop (macOS/Windows)."
            )
    except FileNotFoundError:
        return session_context(
            "DOCKER NOT INSTALLED: This project uses Docker but it's not installed. "
            "Install Docker from https://docs.docker.com/get-docker/"
        )
    except Exception:
        pass
    return allow()


@registry.hook("env_detect_conflicting_tools")
def env_detect_conflicting_tools(data):
    """Detect conflicting tool versions (nvm vs nodenv, etc.)."""
    conflicts = [
        (["nvm", "nodenv", "fnm", "volta", "n"], "Node.js version manager"),
        (["pyenv", "conda", "virtualenv"], "Python version/env manager"),
        (["rbenv", "rvm", "chruby"], "Ruby version manager"),
    ]
    detected_conflicts = []
    for tools, category in conflicts:
        installed = []
        for tool in tools:
            if _check_tool_installed(tool):
                installed.append(tool)
        if len(installed) > 1:
            detected_conflicts.append(
                f"Multiple {category}s installed: {', '.join(installed)} - this may cause version confusion"
            )
    if detected_conflicts:
        return session_context(
            "TOOL CONFLICTS:\n" + "\n".join(f"  - {c}" for c in detected_conflicts)
            + "\nConsider using only one version manager per language to avoid confusion."
        )
    return allow()


@registry.hook("env_check_git_config")
def env_check_git_config(data):
    """Validate git configuration."""
    cwd = get_cwd(data)
    issues = []
    # Check user.name and user.email
    for config_key in ["user.name", "user.email"]:
        try:
            result = subprocess.run(
                ["git", "config", "--get", config_key],
                cwd=cwd, capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0 or not result.stdout.strip():
                issues.append(f"git {config_key} is not set")
        except Exception:
            pass
    # Check for .gitignore
    if not os.path.isfile(os.path.join(cwd, ".gitignore")):
        issues.append("No .gitignore file found in project root")
    if issues:
        return session_context(
            "GIT CONFIG:\n" + "\n".join(f"  - {i}" for i in issues)
            + "\nSet with: git config --global user.name 'Your Name'"
        )
    return allow()


@registry.hook("env_detect_proxy_settings")
def env_detect_proxy_settings(data):
    """Detect proxy environment settings."""
    proxy_vars = ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
                  "ALL_PROXY", "FTP_PROXY", "ftp_proxy"]
    active_proxies = {}
    for var in proxy_vars:
        val = os.environ.get(var, "")
        if val:
            active_proxies[var] = val
    if active_proxies:
        details = [f"{k}={v[:50]}" for k, v in active_proxies.items()]
        return session_context(
            "PROXY DETECTED: Active proxy settings:\n"
            + "\n".join(f"  - {d}" for d in details)
            + "\nSome tools (npm, pip, docker) may need proxy configuration. "
            "If you're having network issues, check proxy settings."
        )
    return allow()


if __name__ == "__main__":
    registry.main()
