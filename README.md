# Hooks for Codex

**1,100+ lifecycle hooks for the [OpenAI Codex desktop app](https://openai.com/codex/)** — security guards, code quality checks, git protection, DevOps monitoring, and more. One command to install.

> Hooks are disabled by default in Codex. This project enables them with real, functional logic across 20 categories.

---

## Install

```bash
git clone https://github.com/Da-Coder-Jr/Hooks-for-Codex
cd Hooks-for-Codex
bash install.sh
```

Restart the Codex desktop app. Hooks fire automatically.

---

## What's included

| Category | Hooks | What it does |
|---|---|---|
| **Security** | 225 | Block dangerous commands, detect secrets/API keys, prevent injection |
| **Code Quality** | 115 | Parse linters, enforce style, detect code smells, complexity |
| **Languages** | 106 | Python, JavaScript, TypeScript, Rust, Go, Java error detection |
| **Frameworks** | 75 | React, Django, Express, Flask, Next.js error detection |
| **DevOps** | 73 | Docker, Kubernetes, Terraform, CI/CD output analysis |
| **Monitoring** | 65 | Log analysis, error tracking, metrics, health checks |
| **Git** | 60 | Branch protection, commit validation, workflow guards |
| **Performance** | 50 | Runtime perf, memory leaks, bundle size |
| **Testing** | 50 | Test runners (pytest/Jest/cargo test/etc.), coverage, quality |
| **Dependencies** | 35 | npm audit, pip audit, cargo audit, version checks |
| **Database** | 35 | SQL safety, migration error detection |
| **Auto-Continue** | 30 | Smart retry on network errors, test failures, build errors |
| **Session** | 30 | Project detection, git branch info, framework detection |
| **API** | 30 | Request security, response validation |
| **Project** | 30 | Task tracking, workflow automation |
| **Notifications** | 30 | Desktop notifications, integrations |
| **Documentation** | 30 | README quality, changelog format, API docs |
| **Environment** | 27 | Env var validation, config file checks |
| **Error Handling** | 20 | Pattern detection across all languages |
| **Accessibility** | 15 | WCAG checks, aria attributes, semantic HTML |

**Total: 1,131 hooks** across 65 files, zero external dependencies (Python stdlib only).

---

## How it works

The installer copies all hook modules to `~/.codex/hooks/` and sets up a dispatcher that runs all relevant hooks for each Codex event:

```
~/.codex/
  config.toml          ← codex_hooks = true
  hooks.json           ← 5 dispatcher entries (one per event type)
  hooks/
    _lib/
      dispatcher.py    ← routes events to all matching hook modules
      base.py          ← shared registry and utilities
    security/          ← command_guards.py, secret_detection.py, ...
    code_quality/      ← linting.py, best_practices.py, ...
    git/               ← branch_protection.py, commit_validation.py, ...
    ... (20 categories total)
```

Each event type triggers the dispatcher which runs all hooks for that category:

| Event | Fires when | Effect |
|---|---|---|
| **SessionStart** | Codex starts/resumes | Injects project context (git branch, framework, env files) |
| **PreToolUse** | Before a Bash command | **Blocks** dangerous commands, secrets, privilege escalation |
| **PostToolUse** | After a Bash command | Adds feedback on errors, test results, performance, security |
| **UserPromptSubmit** | User sends a prompt | **Blocks** prompts containing secrets or injection patterns |
| **Stop** | Agent finishes a turn | **Auto-continues** on recoverable errors (failures, timeouts) |

---

## Customize

**Disable a category**: Edit `~/.codex/hooks.json` — or edit the module files in `~/.codex/hooks/<category>/`.

**Edit a hook**: Each module is a plain Python file. Find the `@registry.hook("name")` function and change the logic.

**Add your own hook**: Add a function to any module file using the registry pattern:

```python
@registry.hook("my_custom_check")
def my_custom_check(data):
    cmd = get_command(data)
    if "something risky" in cmd:
        return deny("Blocked: reason")
    return allow()
```

**Per-project hooks**: Create `.codex/hooks.json` in your project root. Global and project hooks are merged.

---

## Known limitations

- PreToolUse/PostToolUse only fire for Bash — not file edits, web search, or MCP tools
- Hooks are currently disabled on Windows
- The hooks system is experimental and under active development
