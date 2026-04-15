#!/usr/bin/env python3
"""Git: Commit validation hooks for Codex. 20 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("check_commit_message_length")
def check_commit_message_length(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+commit\b", cmd) or not output: return allow()
    match = re.search(r'-m\s+["\'](.+?)["\']', cmd)
    if match:
        msg = match.group(1)
        if len(msg) < 10:
            return post_tool_context("Git: Commit message too short. Describe what and why.")
        if len(msg.split('\n')[0]) > 72:
            return post_tool_context("Git: Commit subject line > 72 chars. Keep subject concise, use body for details.")
    return allow()

@registry.hook("check_conventional_commits")
def check_conventional_commits(data):
    cmd = get_command(data)
    if not re.search(r"\bgit\s+commit\b", cmd): return allow()
    match = re.search(r'-m\s+["\'](.+?)["\']', cmd)
    if match:
        msg = match.group(1)
        if not re.match(r"^(feat|fix|docs|style|refactor|perf|test|chore|ci|build|revert)(\(.+?\))?(!)?:\s", msg):
            return post_tool_context("Git: Consider Conventional Commits format: type(scope): description")
    return allow()

@registry.hook("detect_commit_with_conflicts")
def detect_commit_with_conflicts(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"<<<<<<<|=======|>>>>>>>", output):
        return post_tool_context("Git: Merge conflict markers detected in staged files. Resolve before committing.")
    return allow()

@registry.hook("check_empty_commit")
def check_empty_commit(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"nothing to commit|nothing added to commit|no changes added", output):
        return post_tool_context("Git: No changes to commit. Stage files with git add first.")
    return allow()

@registry.hook("detect_large_commit")
def detect_large_commit(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+diff\s+--stat", cmd) or not output: return allow()
    files_changed = re.findall(r"(\d+)\s+files?\s+changed", output)
    if files_changed and int(files_changed[0]) > 20:
        return post_tool_context(f"Git: Large commit ({files_changed[0]} files). Consider splitting into smaller, focused commits.")
    return allow()

@registry.hook("check_commit_signing")
def check_commit_signing(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+log\b.*--show-signature|git\s+verify-commit", cmd) or not output: return allow()
    if re.search(r"No signature|BAD signature|Can't check signature", output):
        return post_tool_context("Git: Unsigned or invalid commit signature detected.")
    return allow()

@registry.hook("detect_sensitive_files_staged")
def detect_sensitive_files_staged(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+(status|diff\s+--cached|diff\s+--staged)\b", cmd) or not output: return allow()
    sensitive = re.findall(r"(?:new file|modified):\s*(\S*(?:\.env|\.pem|\.key|credentials|secret|password|\.p12|\.pfx)\S*)", output, re.IGNORECASE)
    if sensitive:
        return post_tool_context(f"Git: Sensitive files staged: {', '.join(sensitive[:5])}. Add to .gitignore.")
    return allow()

@registry.hook("check_binary_files_staged")
def check_binary_files_staged(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+diff\s+--cached", cmd) or not output: return allow()
    binaries = re.findall(r"Binary files.*?b/(\S+)", output)
    if binaries:
        return post_tool_context(f"Git: Binary files staged: {', '.join(binaries[:5])}. Consider Git LFS.")
    return allow()

@registry.hook("detect_merge_commit")
def detect_merge_commit(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Merge branch|Merge remote-tracking|Merge pull request", output):
        return post_tool_context("Git: Merge commit created. Consider rebasing for cleaner history if appropriate.")
    return allow()

@registry.hook("check_amend_published")
def check_amend_published(data):
    cmd = get_command(data)
    if re.search(r"git\s+commit\s+--amend", cmd):
        return post_tool_context("Git: Amending commit. If already pushed, this requires force push. Avoid on shared branches.")
    return allow()

@registry.hook("detect_fixup_commits")
def detect_fixup_commits(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+log\b", cmd) or not output: return allow()
    fixups = re.findall(r"(?:fixup!|squash!)\s+", output)
    if len(fixups) > 2:
        return post_tool_context(f"Git: {len(fixups)} fixup/squash commits. Run interactive rebase to clean up.")
    return allow()

@registry.hook("check_wip_commits")
def check_wip_commits(data):
    cmd = get_command(data)
    match = re.search(r'-m\s+["\'](.+?)["\']', cmd)
    if match and re.search(r"\bWIP\b|work in progress|TODO|FIXME", match.group(1), re.IGNORECASE):
        return post_tool_context("Git: WIP/TODO commit message. Clean up before pushing to shared branch.")
    return allow()

@registry.hook("detect_debug_in_commit")
def detect_debug_in_commit(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+diff\s+--cached", cmd) or not output: return allow()
    debug_lines = re.findall(r"\+.*(?:console\.log|print\(|debugger|binding\.pry|import pdb)", output)
    if len(debug_lines) > 2:
        return post_tool_context(f"Git: {len(debug_lines)} debug statements in staged changes. Remove before committing.")
    return allow()

@registry.hook("check_commit_author")
def check_commit_author(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+log\b", cmd) or not output: return allow()
    if re.search(r"Author:.*noreply@|Author:.*root@|Author:.*localhost", output):
        return post_tool_context("Git: Commit author uses placeholder email. Set proper git config user.email.")
    return allow()

@registry.hook("detect_revert_chain")
def detect_revert_chain(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+log\b", cmd) or not output: return allow()
    reverts = re.findall(r'Revert ".*Revert', output)
    if reverts:
        return post_tool_context("Git: Revert-of-revert chain detected. Consider a clean fix instead.")
    return allow()

@registry.hook("check_gitignore_coverage")
def check_gitignore_coverage(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+status\b", cmd) or not output: return allow()
    untracked = re.findall(r"(?:Untracked files:[\s\S]*?)(\S+\.(?:log|tmp|cache|pid|sock|swp|DS_Store))", output)
    if untracked:
        return post_tool_context(f"Git: Untracked temp files: {', '.join(untracked[:5])}. Add patterns to .gitignore.")
    return allow()

@registry.hook("detect_submodule_changes")
def detect_submodule_changes(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+(status|diff)\b", cmd) or not output: return allow()
    if re.search(r"modified:\s+\S+\s+\(new commits\)|Submodule.*contains modified content", output):
        return post_tool_context("Git: Submodule changes detected. Update with git submodule update if needed.")
    return allow()

@registry.hook("check_tag_format")
def check_tag_format(data):
    cmd = get_command(data)
    match = re.search(r"git\s+tag\s+(\S+)", cmd)
    if match:
        tag = match.group(1)
        if not tag.startswith('-') and not re.match(r"^v?\d+\.\d+\.\d+", tag):
            return post_tool_context(f"Git: Tag '{tag}' doesn't follow semver (vX.Y.Z). Consider semantic versioning.")
    return allow()

@registry.hook("detect_detached_head")
def detect_detached_head(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"HEAD detached at|You are in 'detached HEAD' state", output):
        return post_tool_context("Git: Detached HEAD state. Create a branch (git checkout -b name) to save work.")
    return allow()

@registry.hook("check_cherry_pick_conflicts")
def check_cherry_pick_conflicts(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"CONFLICT.*cherry-pick|could not apply.*cherry-pick", output, re.IGNORECASE):
        return post_tool_context("Git: Cherry-pick conflict. Resolve conflicts, then git cherry-pick --continue.")
    return allow()

if __name__ == "__main__":
    registry.main()
