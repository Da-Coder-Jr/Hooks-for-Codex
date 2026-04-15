#!/usr/bin/env python3
"""Git: Workflow guard hooks for Codex. 20 PreToolUse/PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("block_push_without_pull")
def block_push_without_pull(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"rejected.*non-fast-forward|tip of your current branch is behind", output):
        return post_tool_context("Git: Push rejected (behind remote). Pull/rebase first, then push.")
    return allow()

@registry.hook("detect_diverged_branches")
def detect_diverged_branches(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"have diverged|(\d+) and (\d+) different commits", output):
        return post_tool_context("Git: Branches have diverged. Merge or rebase to reconcile.")
    return allow()

@registry.hook("check_upstream_tracking")
def check_upstream_tracking(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"no tracking information|no upstream configured|does not track", output, re.IGNORECASE):
        return post_tool_context("Git: No upstream tracking branch. Set with: git push -u origin <branch>")
    return allow()

@registry.hook("detect_stale_branch")
def detect_stale_branch(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+branch\b.*-v", cmd) or not output: return allow()
    stale = re.findall(r"\[gone\]\s+(\S+)", output)
    if stale:
        return post_tool_context(f"Git: {len(stale)} branches with deleted upstream. Consider cleanup.")
    return allow()

@registry.hook("warn_rebase_in_progress")
def warn_rebase_in_progress(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"rebase in progress|interactive rebase in progress|currently rebasing", output):
        return post_tool_context("Git: Rebase in progress. Use --continue, --skip, or --abort to resolve.")
    return allow()

@registry.hook("warn_merge_in_progress")
def warn_merge_in_progress(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"You have unmerged paths|Unmerged paths|fix conflicts and run", output):
        return post_tool_context("Git: Merge in progress with conflicts. Resolve conflicts, then git merge --continue.")
    return allow()

@registry.hook("detect_uncommitted_before_checkout")
def detect_uncommitted_before_checkout(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"error:.*would be overwritten|Please commit.*changes or stash them", output):
        return post_tool_context("Git: Uncommitted changes would be overwritten. Commit or stash before switching branches.")
    return allow()

@registry.hook("check_fetch_errors")
def check_fetch_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+(fetch|pull)\b", cmd) or not output: return allow()
    if re.search(r"fatal:.*Could not read|fatal:.*Authentication failed|fatal:.*repository.*not found", output):
        return post_tool_context("Git: Fetch/pull failed. Check remote URL, credentials, and network connectivity.")
    return allow()

@registry.hook("detect_large_files_push")
def detect_large_files_push(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"large files detected|File.*is.*MB.*exceeds.*limit|this exceeds GitHub's file size", output):
        return post_tool_context("Git: Large file detected. Use Git LFS for files > 100MB.")
    return allow()

@registry.hook("check_shallow_clone_limitations")
def check_shallow_clone_limitations(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"shallow update not allowed|--unshallow|grafted.*shallow", output):
        return post_tool_context("Git: Shallow clone limitation. Use git fetch --unshallow for full history.")
    return allow()

@registry.hook("detect_hook_failures")
def detect_hook_failures(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"pre-commit hook.*failed|pre-push hook.*failed|commit-msg hook.*failed", output):
        match = re.search(r"(pre-commit|pre-push|commit-msg) hook.*failed", output)
        hook_name = match.group(1) if match else "git hook"
        return post_tool_context(f"Git: {hook_name} hook failed. Fix issues or use --no-verify (not recommended).")
    return allow()

@registry.hook("check_bisect_progress")
def check_bisect_progress(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+bisect\b", cmd) or not output: return allow()
    match = re.search(r"roughly (\d+) steps", output)
    if match:
        return post_tool_context(f"Git bisect: ~{match.group(1)} steps remaining to find the bad commit.")
    if re.search(r"is the first bad commit", output):
        return post_tool_context("Git bisect: Found the first bad commit! Run git bisect reset when done.")
    return allow()

@registry.hook("warn_interactive_rebase_published")
def warn_interactive_rebase_published(data):
    cmd = get_command(data)
    if re.search(r"git\s+rebase\s+-i", cmd):
        return post_tool_context("Git: Interactive rebase rewrites history. Only use on unpublished commits.")
    return allow()

@registry.hook("detect_orphan_branch")
def detect_orphan_branch(data):
    cmd = get_command(data)
    if re.search(r"git\s+checkout\s+--orphan|git\s+switch\s+--orphan", cmd):
        return post_tool_context("Git: Creating orphan branch (no parent commits). Used for gh-pages or clean starts.")
    return allow()

@registry.hook("check_remote_changes")
def check_remote_changes(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+fetch\b", cmd) or not output: return allow()
    new_branches = re.findall(r"\[new branch\]\s+(\S+)", output)
    new_tags = re.findall(r"\[new tag\]\s+(\S+)", output)
    updates = re.findall(r"([a-f0-9]+\.\.[a-f0-9]+)\s+(\S+)", output)
    parts = []
    if new_branches: parts.append(f"{len(new_branches)} new branches")
    if new_tags: parts.append(f"{len(new_tags)} new tags")
    if updates: parts.append(f"{len(updates)} updated refs")
    if parts:
        return post_tool_context(f"Git fetch: {', '.join(parts)}")
    return allow()

@registry.hook("detect_permission_denied")
def detect_permission_denied(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Permission denied \(publickey\)|Permission to .* denied|403.*Forbidden", output):
        return post_tool_context("Git: Permission denied. Check SSH keys, tokens, or repository access permissions.")
    return allow()

@registry.hook("check_lfs_tracking")
def check_lfs_tracking(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+lfs\b", cmd) or not output: return allow()
    if re.search(r"Uploading LFS objects|Downloading LFS objects", output):
        match = re.search(r"(\d+)/(\d+)", output)
        if match:
            return post_tool_context(f"Git LFS: {match.group(1)}/{match.group(2)} objects transferred.")
    return allow()

@registry.hook("detect_sparse_checkout_issues")
def detect_sparse_checkout_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"sparse-checkout|cone mode|sparse index", output):
        return post_tool_context("Git: Sparse checkout active. Some files may be excluded from working directory.")
    return allow()

@registry.hook("check_commit_graph_corruption")
def check_commit_graph_corruption(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"commit-graph.*corrupt|bad object|broken link|missing tree", output):
        return post_tool_context("Git: Repository integrity issue detected. Run git fsck for diagnostics.")
    return allow()

@registry.hook("detect_credential_helper_issues")
def detect_credential_helper_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"credential.*helper.*error|unable to access.*credentials|401.*Unauthorized", output):
        return post_tool_context("Git: Credential helper issue. Reconfigure with: git config credential.helper")
    return allow()

if __name__ == "__main__":
    registry.main()
