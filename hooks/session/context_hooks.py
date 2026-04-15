#!/usr/bin/env python3
"""Session: Context enrichment hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output, get_cwd
registry = HookRegistry()

@registry.hook("context_detect_file_type")
def context_detect_file_type(data):
    cmd, output = get_command(data), get_command_output(data)
    if not output: return allow()
    ext_map = {
        r"\.tsx?$": "TypeScript", r"\.jsx?$": "JavaScript", r"\.py$": "Python",
        r"\.rs$": "Rust", r"\.go$": "Go", r"\.java$": "Java",
        r"\.rb$": "Ruby", r"\.php$": "PHP", r"\.swift$": "Swift",
        r"\.kt$": "Kotlin", r"\.cs$": "C#", r"\.cpp$": "C++",
    }
    files = re.findall(r"(\S+\.(?:tsx?|jsx?|py|rs|go|java|rb|php|swift|kt|cs|cpp))\b", cmd)
    if files:
        languages = set()
        for f in files:
            for pattern, lang in ext_map.items():
                if re.search(pattern, f):
                    languages.add(lang)
        if languages:
            return post_tool_context(f"Working with: {', '.join(sorted(languages))}")
    return allow()

@registry.hook("context_detect_package_manager")
def context_detect_package_manager(data):
    cmd = get_command(data)
    managers = {
        r"\bnpm\b": "npm", r"\byarn\b": "yarn", r"\bpnpm\b": "pnpm",
        r"\bpip\b": "pip", r"\bpoetry\b": "poetry", r"\bpdm\b": "pdm",
        r"\bcargo\b": "cargo", r"\bgo\s+(?:get|mod)\b": "go modules",
        r"\bgem\b": "gem", r"\bcomposer\b": "composer",
        r"\bgradle\b": "gradle", r"\bmvn\b": "maven",
    }
    for pattern, name in managers.items():
        if re.search(pattern, cmd):
            return post_tool_context(f"Package manager: {name}")
    return allow()

@registry.hook("context_detect_test_framework")
def context_detect_test_framework(data):
    cmd = get_command(data)
    frameworks = {
        r"\bpytest\b": "pytest", r"\bjest\b": "Jest", r"\bmocha\b": "Mocha",
        r"\bvitest\b": "Vitest", r"\brspec\b": "RSpec", r"\bcargo\s+test\b": "cargo test",
        r"\bgo\s+test\b": "go test", r"\bphpunit\b": "PHPUnit",
        r"\bcypress\b": "Cypress", r"\bplaywright\b": "Playwright",
    }
    for pattern, name in frameworks.items():
        if re.search(pattern, cmd):
            return post_tool_context(f"Test framework: {name}")
    return allow()

@registry.hook("context_track_directory_changes")
def context_track_directory_changes(data):
    cmd = get_command(data)
    match = re.search(r"\bcd\s+(\S+)", cmd)
    if match:
        target = match.group(1)
        return post_tool_context(f"Directory changed to: {target}")
    return allow()

@registry.hook("context_detect_database_operations")
def context_detect_database_operations(data):
    cmd = get_command(data)
    dbs = {
        r"\bpsql\b|pg_dump|pg_restore": "PostgreSQL",
        r"\bmysql\b|mysqldump": "MySQL",
        r"\bmongo\b|mongosh|mongodump": "MongoDB",
        r"\bredis-cli\b": "Redis",
        r"\bsqlite3\b": "SQLite",
    }
    for pattern, name in dbs.items():
        if re.search(pattern, cmd):
            return post_tool_context(f"Database: {name} operation")
    return allow()

@registry.hook("context_detect_cloud_provider")
def context_detect_cloud_provider(data):
    cmd = get_command(data)
    clouds = {
        r"\baws\b|awscli": "AWS",
        r"\bgcloud\b|gsutil": "Google Cloud",
        r"\baz\b|azure": "Azure",
        r"\bdoctl\b": "DigitalOcean",
        r"\bheroku\b": "Heroku",
        r"\bvercel\b": "Vercel",
        r"\bnetlify\b": "Netlify",
        r"\bfly\b": "Fly.io",
    }
    for pattern, name in clouds.items():
        if re.search(pattern, cmd):
            return post_tool_context(f"Cloud provider: {name}")
    return allow()

@registry.hook("context_detect_build_tool")
def context_detect_build_tool(data):
    cmd = get_command(data)
    tools = {
        r"\bwebpack\b": "webpack", r"\bvite\b": "Vite", r"\besbuild\b": "esbuild",
        r"\brollup\b": "Rollup", r"\bparcel\b": "Parcel", r"\bturbo\b": "Turborepo",
        r"\bmake\b": "Make", r"\bcmake\b": "CMake", r"\bninja\b": "Ninja",
        r"\bbazel\b": "Bazel",
    }
    for pattern, name in tools.items():
        if re.search(pattern, cmd):
            return post_tool_context(f"Build tool: {name}")
    return allow()

@registry.hook("context_detect_linting_tool")
def context_detect_linting_tool(data):
    cmd = get_command(data)
    linters = {
        r"\beslint\b": "ESLint", r"\bprettier\b": "Prettier",
        r"\bflake8\b": "flake8", r"\bruff\b": "ruff", r"\bmypy\b": "mypy",
        r"\bblack\b": "black", r"\brubocop\b": "RuboCop",
        r"\bgolangci-lint\b": "golangci-lint", r"\bclippy\b": "clippy",
    }
    for pattern, name in linters.items():
        if re.search(pattern, cmd):
            return post_tool_context(f"Linter: {name}")
    return allow()

@registry.hook("context_detect_deployment")
def context_detect_deployment(data):
    cmd = get_command(data)
    if re.search(r"\bdeploy\b|kubectl\s+apply|terraform\s+apply|serverless\s+deploy|cdk\s+deploy", cmd):
        return post_tool_context("Deployment operation detected. Ensure you're targeting the correct environment.")
    return allow()

@registry.hook("context_detect_migration")
def context_detect_migration(data):
    cmd = get_command(data)
    if re.search(r"migrate|migration|alembic|flyway|sequelize.*migrate|prisma.*migrate|knex.*migrate", cmd, re.IGNORECASE):
        return post_tool_context("Database migration detected. Backup data before applying to production.")
    return allow()

@registry.hook("context_detect_container_operations")
def context_detect_container_operations(data):
    cmd = get_command(data)
    if re.search(r"docker\s+(?:build|run|compose)|podman\s+(?:build|run)", cmd):
        return post_tool_context("Container operation in progress.")
    return allow()

@registry.hook("context_detect_git_operations")
def context_detect_git_operations(data):
    cmd = get_command(data)
    ops = {
        r"git\s+merge": "merge", r"git\s+rebase": "rebase",
        r"git\s+cherry-pick": "cherry-pick", r"git\s+bisect": "bisect",
        r"git\s+stash": "stash",
    }
    for pattern, name in ops.items():
        if re.search(pattern, cmd):
            return post_tool_context(f"Git operation: {name}")
    return allow()

@registry.hook("context_detect_server_start")
def context_detect_server_start(data):
    cmd = get_command(data)
    servers = {
        r"npm\s+(?:run\s+)?(?:dev|start)|yarn\s+(?:dev|start)": "dev server",
        r"python\s+manage\.py\s+runserver": "Django dev server",
        r"flask\s+run": "Flask dev server",
        r"uvicorn|gunicorn|hypercorn": "Python ASGI/WSGI server",
        r"node\s+\S+\.js|nodemon": "Node.js server",
    }
    for pattern, name in servers.items():
        if re.search(pattern, cmd):
            return post_tool_context(f"Starting {name}.")
    return allow()

@registry.hook("context_summarize_git_status")
def context_summarize_git_status(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+status\b", cmd) or not output: return allow()
    staged = len(re.findall(r"new file:|modified:|deleted:|renamed:", output))
    modified = len(re.findall(r"modified:\s+\S+", output))
    untracked = len(re.findall(r"Untracked files:", output))
    parts = []
    if staged: parts.append(f"{staged} staged")
    if modified: parts.append(f"{modified} modified")
    if untracked: parts.append("untracked files")
    if re.search(r"nothing to commit, working tree clean", output):
        return post_tool_context("Git: Working tree clean.")
    if parts:
        return post_tool_context(f"Git status: {', '.join(parts)}")
    return allow()

@registry.hook("context_summarize_git_log")
def context_summarize_git_log(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+log\b", cmd) or not output: return allow()
    commits = re.findall(r"^commit [a-f0-9]{40}", output, re.MULTILINE)
    if commits:
        first_msg = re.search(r"^\s{4}(.+)$", output, re.MULTILINE)
        return post_tool_context(f"Git log: {len(commits)} commits shown. Latest: {first_msg.group(1).strip()[:60] if first_msg else 'check log'}")
    return allow()

if __name__ == "__main__":
    registry.main()
