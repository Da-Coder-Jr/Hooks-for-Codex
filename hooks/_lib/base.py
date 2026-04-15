"""
Base utilities for Codex hooks.

Provides common functions for reading hook input, producing output,
and registering hook functions within category modules.
"""

import json
import sys
import os


def read_hook_input():
    """Read and parse JSON input from stdin (sent by Codex)."""
    try:
        return json.load(sys.stdin)
    except Exception:
        return {}


def get_command(data):
    """Extract the bash command from hook input data."""
    return data.get("tool_input", {}).get("command", "")


def get_command_output(data):
    """Extract the command output from PostToolUse hook data."""
    return data.get("tool_output", {}).get("stdout", "") + \
           data.get("tool_output", {}).get("stderr", "")


def get_prompt(data):
    """Extract the user prompt from UserPromptSubmit hook data."""
    return data.get("prompt", data.get("user_prompt", ""))


def get_cwd(data):
    """Extract the current working directory."""
    return data.get("cwd", os.getcwd())


def get_session_id(data):
    """Extract the session ID."""
    return data.get("session_id", "unknown")


def get_source(data):
    """Extract the session source (startup/resume) for SessionStart hooks."""
    return data.get("source", "startup")


def get_tool_name(data):
    """Extract the tool name from PreToolUse/PostToolUse data."""
    return data.get("tool_name", "")


# ── Output Builders ──


def deny(reason):
    """Build a PreToolUse deny response."""
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def allow():
    """Allow the action (returns None, hook exits cleanly)."""
    return None


def block_prompt(reason):
    """Build a UserPromptSubmit block response."""
    return {
        "decision": "block",
        "reason": reason,
    }


def add_context(event_name, context_text):
    """Build an additionalContext response for SessionStart or PostToolUse."""
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "additionalContext": context_text,
        }
    }


def force_continue(reason):
    """Build a Stop hook response that forces the agent to continue."""
    return {
        "decision": "block",
        "reason": reason,
    }


def post_tool_context(context_text):
    """Build a PostToolUse context/feedback response."""
    return add_context("PostToolUse", context_text)


def session_context(context_text):
    """Build a SessionStart context response."""
    return add_context("SessionStart", context_text)


# ── Hook Registry ──


class HookRegistry:
    """Registry for hooks within a category module.

    Usage in a module:
        registry = HookRegistry()

        @registry.hook("my_hook_name")
        def my_hook_name(data):
            command = get_command(data)
            if dangerous(command):
                return deny("Blocked: reason")
            return allow()

    From command line:
        python3 module.py hook_name < input.json
    """

    def __init__(self):
        self._hooks = {}

    def hook(self, name):
        """Decorator to register a hook function."""
        def decorator(fn):
            self._hooks[name] = fn
            return fn
        return decorator

    def run(self, name, data):
        """Run a named hook with the given input data."""
        fn = self._hooks.get(name)
        if fn is None:
            return None
        return fn(data)

    def list_hooks(self):
        """Return list of registered hook names."""
        return list(self._hooks.keys())

    def main(self):
        """CLI entry point: reads hook name from argv, input from stdin."""
        if len(sys.argv) < 2:
            # No hook specified; list available hooks
            for name in sorted(self._hooks):
                print(name)
            sys.exit(0)

        hook_name = sys.argv[1]
        if hook_name == "--list":
            for name in sorted(self._hooks):
                print(name)
            sys.exit(0)

        if hook_name not in self._hooks:
            sys.exit(0)

        data = read_hook_input()
        result = self.run(hook_name, data)
        if result:
            print(json.dumps(result))
        sys.exit(0)
