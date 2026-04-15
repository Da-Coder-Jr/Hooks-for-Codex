"""
Utility functions shared across hooks.

Provides file detection, logging, project analysis, and other
commonly-needed helper functions.
"""

import os
import re
import json
import hashlib
import datetime
import subprocess

LOG_DIR = os.path.expanduser("~/.codex/hooks/logs")


def ensure_log_dir():
    """Create the log directory if it doesn't exist."""
    os.makedirs(LOG_DIR, exist_ok=True)


def log_event(log_name, message):
    """Append a timestamped message to a named log file."""
    ensure_log_dir()
    log_path = os.path.join(LOG_DIR, f"{log_name}.log")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_path, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def file_exists(cwd, filename):
    """Check if a file exists relative to cwd."""
    return os.path.isfile(os.path.join(cwd, filename))


def read_file_safe(filepath, max_size=1048576):
    """Read a file safely, returning empty string on failure. Max 1MB default."""
    try:
        if os.path.getsize(filepath) > max_size:
            return ""
        with open(filepath, "r", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def detect_project_type(cwd):
    """Detect project type(s) from files in cwd."""
    from . import patterns as pat
    detected = []
    for filename, ptype in pat.PROJECT_MARKERS.items():
        if "*" in filename:
            continue
        if os.path.isfile(os.path.join(cwd, filename)):
            if ptype not in detected:
                detected.append(ptype)
    return detected


def detect_language_from_command(command):
    """Detect programming language from a shell command."""
    lang_commands = {
        "python": ["python", "python3", "pip", "pip3", "pytest", "mypy", "flake8",
                    "black", "isort", "pylint", "poetry", "pipenv", "tox"],
        "javascript": ["node", "npm", "npx", "yarn", "pnpm", "jest", "mocha",
                       "eslint", "prettier", "webpack", "vite", "esbuild"],
        "typescript": ["tsc", "ts-node", "tsx"],
        "rust": ["cargo", "rustc", "rustup", "clippy"],
        "go": ["go ", "go build", "go test", "go run", "go mod", "golangci-lint"],
        "java": ["java ", "javac", "mvn", "gradle", "ant"],
        "ruby": ["ruby", "gem", "bundle", "rake", "rails", "rspec"],
        "php": ["php", "composer", "artisan", "phpunit", "phpcs"],
        "swift": ["swift ", "swiftc", "xcodebuild", "xcrun"],
        "kotlin": ["kotlinc", "kotlin"],
        "csharp": ["dotnet", "nuget", "msbuild"],
        "elixir": ["mix ", "elixir", "iex"],
        "haskell": ["ghc", "cabal", "stack "],
    }
    detected = []
    for lang, cmds in lang_commands.items():
        for cmd in cmds:
            if cmd in command:
                if lang not in detected:
                    detected.append(lang)
    return detected


def is_test_command(command):
    """Check if a command is a test execution command."""
    test_indicators = [
        r"\bpytest\b", r"\bunittest\b", r"\bnose2?\b",
        r"\bjest\b", r"\bmocha\b", r"\bvitest\b", r"\bplaywright\b",
        r"\bcypress\b", r"\bkarma\b", r"\bjasmine\b",
        r"\bcargo\s+test\b", r"\bgo\s+test\b",
        r"\brspec\b", r"\bminitest\b",
        r"\bphpunit\b", r"\bphpspec\b",
        r"\bnpm\s+test\b", r"\byarn\s+test\b", r"\bpnpm\s+test\b",
        r"\bmake\s+test\b", r"\bctest\b",
        r"\bgradle\s+test\b", r"\bmvn\s+test\b",
        r"\bxctest\b", r"\bswift\s+test\b",
        r"\bmix\s+test\b",
    ]
    for pattern in test_indicators:
        if re.search(pattern, command):
            return True
    return False


def is_build_command(command):
    """Check if a command is a build command."""
    build_indicators = [
        r"\bnpm\s+run\s+build\b", r"\byarn\s+build\b", r"\bpnpm\s+build\b",
        r"\bcargo\s+build\b", r"\bgo\s+build\b",
        r"\bmake\b(?!\s+test)", r"\bcmake\b",
        r"\bgradle\s+build\b", r"\bmvn\s+(compile|package|install)\b",
        r"\bdotnet\s+build\b",
        r"\bgcc\b", r"\bg\+\+\b", r"\bclang\b",
        r"\bswift\s+build\b",
        r"\bmix\s+compile\b",
        r"\bnpm\s+run\s+compile\b",
        r"\btsc\b",
        r"\bwebpack\b", r"\bvite\s+build\b", r"\besbuild\b", r"\brollup\b",
    ]
    for pattern in build_indicators:
        if re.search(pattern, command):
            return True
    return False


def is_lint_command(command):
    """Check if a command is a lint/format command."""
    lint_indicators = [
        r"\beslint\b", r"\bprettier\b", r"\bbiome\b",
        r"\bflake8\b", r"\bpylint\b", r"\bmypy\b", r"\bruff\b",
        r"\bblack\b", r"\bisort\b", r"\bautoflake\b",
        r"\bcargo\s+clippy\b", r"\bcargo\s+fmt\b",
        r"\bgolangci-lint\b", r"\bgofmt\b", r"\bgoimports\b",
        r"\brubocop\b", r"\bstandardrb\b",
        r"\bphpcs\b", r"\bphp-cs-fixer\b",
        r"\bswiftlint\b", r"\bswiftformat\b",
        r"\bktlint\b", r"\bdetekt\b",
        r"\bshellcheck\b",
        r"\bmarkdownlint\b", r"\balex\b",
        r"\bstylelint\b",
        r"\bhtmlhint\b",
        r"\byamllint\b", r"\bjsonlint\b",
        r"\bhadolint\b",
        r"\btflint\b",
    ]
    for pattern in lint_indicators:
        if re.search(pattern, command):
            return True
    return False


def is_git_command(command):
    """Check if a command is a git command."""
    return bool(re.search(r"\bgit\s+", command))


def is_docker_command(command):
    """Check if a command is a Docker command."""
    return bool(re.search(r"\b(docker|docker-compose|podman)\s+", command))


def extract_file_paths(command):
    """Extract file paths from a command string."""
    # Match common path patterns
    paths = re.findall(r'(?:^|\s)([/~][^\s;|&>]+)', command)
    paths += re.findall(r'(?:^|\s)(\./[^\s;|&>]+)', command)
    paths += re.findall(r'(?:^|\s)(\.\./[^\s;|&>]+)', command)
    return [p.strip() for p in paths]


def hash_content(content):
    """Generate SHA256 hash of content for integrity checking."""
    return hashlib.sha256(content.encode()).hexdigest()


def get_git_branch(cwd):
    """Get the current git branch name."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def get_git_staged_files(cwd):
    """Get list of staged files in git."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip().split("\n") if result.returncode == 0 else []
    except Exception:
        return []


def get_git_modified_files(cwd):
    """Get list of modified files in git."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip().split("\n") if result.returncode == 0 else []
    except Exception:
        return []


def count_lines(text):
    """Count lines in text."""
    return len(text.strip().split("\n")) if text.strip() else 0


def extract_urls(text):
    """Extract URLs from text."""
    return re.findall(r'https?://[^\s\'"<>]+', text)


def is_ip_address(text):
    """Check if text contains IP addresses."""
    return bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text))


def extract_ports(command):
    """Extract port numbers from a command."""
    ports = re.findall(r'-p\s+(\d+)', command)
    ports += re.findall(r':(\d+)', command)
    ports += re.findall(r'--port\s+(\d+)', command)
    return [int(p) for p in ports if p.isdigit() and 0 < int(p) < 65536]


def get_file_size(filepath):
    """Get file size in bytes, returns 0 on error."""
    try:
        return os.path.getsize(filepath)
    except Exception:
        return 0


def is_binary_file(filepath):
    """Check if a file appears to be binary."""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk
    except Exception:
        return False


def truncate_string(s, max_len=200):
    """Truncate a string to max_len characters."""
    if len(s) <= max_len:
        return s
    return s[:max_len - 3] + "..."
