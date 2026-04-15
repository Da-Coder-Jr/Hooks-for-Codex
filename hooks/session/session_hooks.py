#!/usr/bin/env python3
"""Session: Session lifecycle hooks for Codex. 15 SessionStart/Stop hooks."""

import json, re, sys, os, hashlib, datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, session_context, get_cwd, get_session_id
from _lib.utils import detect_project_type, get_git_branch, file_exists, ensure_log_dir
registry = HookRegistry()

@registry.hook("session_project_detection")
def session_project_detection(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    proj_type = detect_project_type(cwd)
    if proj_type:
        return session_context(f"Project type detected: {proj_type}")
    return allow()

@registry.hook("session_git_branch_info")
def session_git_branch_info(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    branch = get_git_branch(cwd)
    if branch:
        ctx = f"Git branch: {branch}"
        if re.search(r"main|master|production|release", branch):
            ctx += " (PROTECTED - be cautious with changes)"
        return session_context(ctx)
    return allow()

@registry.hook("session_detect_monorepo")
def session_detect_monorepo(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    indicators = []
    if file_exists(os.path.join(cwd, "lerna.json")): indicators.append("Lerna")
    if file_exists(os.path.join(cwd, "nx.json")): indicators.append("Nx")
    if file_exists(os.path.join(cwd, "pnpm-workspace.yaml")): indicators.append("pnpm workspace")
    if file_exists(os.path.join(cwd, "turbo.json")): indicators.append("Turborepo")
    pkg_json = os.path.join(cwd, "package.json")
    if file_exists(pkg_json):
        try:
            import json as j
            with open(pkg_json, "r") as f:
                pkg = j.load(f)
            if "workspaces" in pkg: indicators.append("npm workspaces")
        except Exception:
            pass
    if indicators:
        return session_context(f"Monorepo: {', '.join(indicators)}")
    return allow()

@registry.hook("session_detect_ci_environment")
def session_detect_ci_environment(data):
    ci_vars = {
        "GITHUB_ACTIONS": "GitHub Actions",
        "GITLAB_CI": "GitLab CI",
        "CIRCLECI": "CircleCI",
        "JENKINS_URL": "Jenkins",
        "TRAVIS": "Travis CI",
        "BUILDKITE": "Buildkite",
        "CODEBUILD_BUILD_ID": "AWS CodeBuild",
    }
    for var, name in ci_vars.items():
        if os.environ.get(var):
            return session_context(f"CI environment: {name}")
    return allow()

@registry.hook("session_check_env_files")
def session_check_env_files(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    envs = []
    for name in [".env", ".env.local", ".env.development", ".env.production"]:
        if file_exists(os.path.join(cwd, name)):
            envs.append(name)
    if envs:
        return session_context(f"Environment files: {', '.join(envs)}. These are NOT committed (check .gitignore).")
    return allow()

@registry.hook("session_detect_containerized")
def session_detect_containerized(data):
    if file_exists("/.dockerenv"):
        return session_context("Running inside Docker container.")
    if file_exists("/run/secrets/kubernetes.io"):
        return session_context("Running inside Kubernetes pod.")
    cgroup = "/proc/1/cgroup"
    if file_exists(cgroup):
        try:
            with open(cgroup, "r") as f:
                content = f.read()
            if "docker" in content or "kubepods" in content:
                return session_context("Running inside container (detected via cgroup).")
        except Exception:
            pass
    return allow()

@registry.hook("session_check_node_modules")
def session_check_node_modules(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    pkg = os.path.join(cwd, "package.json")
    nm = os.path.join(cwd, "node_modules")
    if file_exists(pkg) and not os.path.isdir(nm):
        return session_context("package.json found but no node_modules. Run npm install / yarn install first.")
    return allow()

@registry.hook("session_check_virtualenv")
def session_check_virtualenv(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    if file_exists(os.path.join(cwd, "requirements.txt")) or file_exists(os.path.join(cwd, "pyproject.toml")):
        if not os.environ.get("VIRTUAL_ENV") and not os.environ.get("CONDA_DEFAULT_ENV"):
            venvs = ["venv", ".venv", "env", ".env"]
            for v in venvs:
                if os.path.isdir(os.path.join(cwd, v, "bin")):
                    return session_context(f"Virtual environment found at {v}/ but not activated. Run: source {v}/bin/activate")
            return session_context("Python project without active virtual environment. Consider creating one.")
    return allow()

@registry.hook("session_log_start")
def session_log_start(data):
    log_dir = ensure_log_dir()
    session_id = get_session_id(data) or "unknown"
    cwd = get_cwd(data) or os.getcwd()
    timestamp = datetime.datetime.now().isoformat()
    log_entry = json.dumps({"event": "session_start", "session_id": session_id, "cwd": cwd, "timestamp": timestamp})
    try:
        log_file = os.path.join(log_dir, "sessions.jsonl")
        with open(log_file, "a") as f:
            f.write(log_entry + "\n")
    except Exception:
        pass
    return allow()

@registry.hook("session_detect_editor_config")
def session_detect_editor_config(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    configs = []
    if file_exists(os.path.join(cwd, ".editorconfig")): configs.append("EditorConfig")
    if file_exists(os.path.join(cwd, ".prettierrc")) or file_exists(os.path.join(cwd, ".prettierrc.json")): configs.append("Prettier")
    if file_exists(os.path.join(cwd, ".eslintrc.json")) or file_exists(os.path.join(cwd, ".eslintrc.js")): configs.append("ESLint")
    if file_exists(os.path.join(cwd, "pyproject.toml")): configs.append("pyproject.toml")
    if configs:
        return session_context(f"Code style configs: {', '.join(configs)}")
    return allow()

@registry.hook("session_detect_framework")
def session_detect_framework(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    frameworks = []
    pkg = os.path.join(cwd, "package.json")
    if file_exists(pkg):
        try:
            with open(pkg, "r") as f:
                content = f.read()
            if '"react"' in content: frameworks.append("React")
            if '"next"' in content: frameworks.append("Next.js")
            if '"vue"' in content: frameworks.append("Vue.js")
            if '"angular"' in content: frameworks.append("Angular")
            if '"express"' in content: frameworks.append("Express")
            if '"svelte"' in content: frameworks.append("Svelte")
        except Exception:
            pass
    if file_exists(os.path.join(cwd, "manage.py")): frameworks.append("Django")
    if file_exists(os.path.join(cwd, "Gemfile")):
        try:
            with open(os.path.join(cwd, "Gemfile"), "r") as f:
                if "rails" in f.read().lower(): frameworks.append("Rails")
        except Exception:
            pass
    if frameworks:
        return session_context(f"Frameworks detected: {', '.join(frameworks)}")
    return allow()

@registry.hook("session_check_docker_compose")
def session_check_docker_compose(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    for name in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
        if file_exists(os.path.join(cwd, name)):
            return session_context(f"Docker Compose: {name} found. Use docker compose up to start services.")
    return allow()

@registry.hook("session_check_makefile")
def session_check_makefile(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    makefile = os.path.join(cwd, "Makefile")
    if file_exists(makefile):
        try:
            with open(makefile, "r") as f:
                content = f.read()
            targets = re.findall(r"^(\w[\w-]+):", content, re.MULTILINE)
            if targets:
                return session_context(f"Makefile targets: {', '.join(targets[:10])}")
        except Exception:
            pass
    return allow()

@registry.hook("session_check_test_config")
def session_check_test_config(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    configs = []
    if file_exists(os.path.join(cwd, "jest.config.js")) or file_exists(os.path.join(cwd, "jest.config.ts")): configs.append("Jest")
    if file_exists(os.path.join(cwd, "pytest.ini")) or file_exists(os.path.join(cwd, "pyproject.toml")): configs.append("pytest")
    if file_exists(os.path.join(cwd, "vitest.config.ts")): configs.append("Vitest")
    if file_exists(os.path.join(cwd, ".rspec")): configs.append("RSpec")
    if file_exists(os.path.join(cwd, "cypress.config.js")) or file_exists(os.path.join(cwd, "cypress.config.ts")): configs.append("Cypress")
    if configs:
        return session_context(f"Test frameworks: {', '.join(configs)}")
    return allow()

@registry.hook("session_detect_secrets_management")
def session_detect_secrets_management(data):
    cwd = get_cwd(data)
    if not cwd: return allow()
    if file_exists(os.path.join(cwd, ".sops.yaml")):
        return session_context("Secrets management: SOPS configured. Encrypted secrets in repo.")
    if file_exists(os.path.join(cwd, ".vault")):
        return session_context("Secrets management: HashiCorp Vault configured.")
    return allow()

if __name__ == "__main__":
    registry.main()
