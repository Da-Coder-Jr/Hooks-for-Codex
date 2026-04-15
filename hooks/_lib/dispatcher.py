#!/usr/bin/env python3
"""
Dispatcher: Runs all registered hooks for a given event type across all modules.

Usage:
    echo '{"tool_name":"shell",...}' | python3 dispatcher.py <event_type>

Event types: PreToolUse, PostToolUse, SessionStart, UserPromptSubmit, Stop

The dispatcher imports all hook modules, identifies hooks that match the
requested event type, and runs them in sequence. On a deny/block result
from any hook, it stops and returns that result. Otherwise it collects
context strings from all hooks and returns them as combined feedback.
"""

import json
import sys
import os
import importlib.util
import traceback

# Ensure _lib is importable
HOOKS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HOOKS_DIR)

from _lib.base import read_hook_input

# ── Module Discovery ──

# Map event types to categories and module patterns
EVENT_MODULES = {
    "PreToolUse": {
        "security": ["command_guards", "privilege_escalation", "secret_detection",
                      "network_guards", "filesystem_guards", "injection_prevention"],
        "git": ["branch_protection"],
        "devops": ["docker_hooks", "kubernetes_hooks", "terraform_hooks"],
        "api": ["api_security"],
        "dependencies": ["dep_audit"],
    },
    "PostToolUse": {
        "security": ["compliance_checks"],
        "code_quality": ["linting", "style_enforcement", "complexity_analysis",
                         "best_practices", "code_smells"],
        "languages": ["python_hooks", "javascript_hooks", "typescript_hooks",
                       "rust_hooks", "go_hooks", "java_hooks"],
        "frameworks": ["react_hooks", "django_hooks", "express_hooks",
                        "flask_hooks", "nextjs_hooks"],
        "git": ["commit_validation", "workflow_guards"],
        "devops": ["docker_hooks", "kubernetes_hooks", "terraform_hooks", "ci_cd_hooks"],
        "testing": ["test_quality", "coverage_hooks", "test_runner"],
        "documentation": ["doc_quality", "changelog_hooks"],
        "performance": ["runtime_perf", "memory_hooks", "bundle_size"],
        "monitoring": ["log_analysis", "error_tracking", "metrics_hooks", "health_checks"],
        "database": ["sql_safety", "migration_hooks"],
        "api": ["api_validation"],
        "project": ["task_tracking", "workflow_automation"],
        "notifications": ["integration_notifications"],
        "environment": ["env_management", "config_validation"],
        "dependencies": ["dep_audit", "version_hooks"],
        "accessibility": ["a11y_hooks"],
        "error_handling": ["error_patterns"],
        "session": ["context_hooks"],
    },
    "SessionStart": {
        "session": ["session_hooks"],
    },
    "UserPromptSubmit": {
        "security": ["prompt_guards"],
    },
    "Stop": {
        "auto_continue": ["auto_continue_hooks", "smart_retry"],
        "notifications": ["desktop_notifications"],
    },
}


def load_module(category, module_name):
    """Dynamically load a hook module and return its registry."""
    module_path = os.path.join(HOOKS_DIR, category, f"{module_name}.py")
    if not os.path.exists(module_path):
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            f"hooks.{category}.{module_name}", module_path
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return getattr(mod, "registry", None)
    except Exception:
        return None


def run_hooks_for_event(event_type, data):
    """Run all hooks for the given event type. Returns first deny/block or combined context."""
    modules = EVENT_MODULES.get(event_type, {})
    contexts = []

    for category, module_names in modules.items():
        for module_name in module_names:
            registry = load_module(category, module_name)
            if registry is None:
                continue
            for hook_name in registry.list_hooks():
                try:
                    result = registry.run(hook_name, data)
                    if result is None:
                        continue
                    # Check for deny/block responses (stop immediately)
                    hso = result.get("hookSpecificOutput", {})
                    if hso.get("permissionDecision") == "deny":
                        return result
                    decision = result.get("decision")
                    if decision == "block":
                        return result
                    # Collect context strings
                    ctx = hso.get("additionalContext")
                    if ctx:
                        contexts.append(ctx)
                except Exception:
                    continue

    # Return combined context if any
    if contexts:
        combined = " | ".join(contexts[:10])  # Cap at 10 context items
        return {
            "hookSpecificOutput": {
                "hookEventName": event_type,
                "additionalContext": combined,
            }
        }
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 dispatcher.py <event_type>", file=sys.stderr)
        print("Event types: PreToolUse, PostToolUse, SessionStart, UserPromptSubmit, Stop", file=sys.stderr)
        sys.exit(1)

    event_type = sys.argv[1]
    if event_type not in EVENT_MODULES:
        sys.exit(0)

    data = read_hook_input()
    result = run_hooks_for_event(event_type, data)
    if result:
        print(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    main()
