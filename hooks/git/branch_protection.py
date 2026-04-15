#!/usr/bin/env python3
"""Git: Branch protection hooks for Codex. 20 PreToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, get_command
registry = HookRegistry()

@registry.hook("block_force_push_main")
def block_force_push_main(data):
    cmd = get_command(data)
    if re.search(r"git\s+push\s+.*--force.*\b(main|master)\b|git\s+push\s+-f.*\b(main|master)\b", cmd):
        return deny("Force push to main/master is blocked. Use a feature branch.")
    return allow()

@registry.hook("block_delete_protected_branch")
def block_delete_protected_branch(data):
    cmd = get_command(data)
    protected = r"\b(main|master|develop|staging|production|release)\b"
    if re.search(r"git\s+branch\s+-(d|D)\s+", cmd) and re.search(protected, cmd):
        return deny("Cannot delete protected branch. Only delete feature/topic branches.")
    return allow()

@registry.hook("block_push_delete_remote_branch")
def block_push_delete_remote_branch(data):
    cmd = get_command(data)
    protected = r"\b(main|master|develop|staging|production)\b"
    if re.search(r"git\s+push\s+\S+\s+--delete\s+", cmd) and re.search(protected, cmd):
        return deny("Cannot delete protected remote branch.")
    return allow()

@registry.hook("block_reset_hard_main")
def block_reset_hard_main(data):
    cmd = get_command(data)
    if re.search(r"git\s+reset\s+--hard", cmd) and re.search(r"\b(main|master|origin/main|origin/master)\b", cmd):
        return deny("Hard reset to main/master is dangerous. Use git stash or create a backup branch first.")
    return allow()

@registry.hook("block_rebase_protected")
def block_rebase_protected(data):
    cmd = get_command(data)
    if re.search(r"git\s+rebase\s+", cmd) and re.search(r"\b(main|master|production|staging)\b", cmd):
        return deny("Rebasing onto protected branch. Prefer merge or create a feature branch.")
    return allow()

@registry.hook("warn_checkout_discard")
def warn_checkout_discard(data):
    cmd = get_command(data)
    if re.search(r"git\s+checkout\s+--\s+\.", cmd) or re.search(r"git\s+checkout\s+\.\s*$", cmd):
        return deny("git checkout -- . discards ALL uncommitted changes. Use git stash instead.")
    return allow()

@registry.hook("block_clean_force")
def block_clean_force(data):
    cmd = get_command(data)
    if re.search(r"git\s+clean\s+-[a-zA-Z]*f[a-zA-Z]*d", cmd):
        return deny("git clean -fd removes untracked files AND directories permanently. Use git clean -n first.")
    return allow()

@registry.hook("block_push_all_branches")
def block_push_all_branches(data):
    cmd = get_command(data)
    if re.search(r"git\s+push\s+.*--all", cmd) or re.search(r"git\s+push\s+.*--mirror", cmd):
        return deny("Pushing all/mirror branches to remote is risky. Push specific branches instead.")
    return allow()

@registry.hook("block_force_push_no_lease")
def block_force_push_no_lease(data):
    cmd = get_command(data)
    if re.search(r"git\s+push\s+.*--force(?!\s*-with-lease)", cmd) and not re.search(r"--force-with-lease", cmd):
        return deny("Use --force-with-lease instead of --force for safer force pushes.")
    return allow()

@registry.hook("block_submodule_deinit")
def block_submodule_deinit(data):
    cmd = get_command(data)
    if re.search(r"git\s+submodule\s+deinit\s+--force", cmd):
        return deny("Force deinit of submodules removes local data. Review submodule status first.")
    return allow()

@registry.hook("block_filter_branch")
def block_filter_branch(data):
    cmd = get_command(data)
    if re.search(r"git\s+filter-branch", cmd):
        return deny("git filter-branch rewrites history destructively. Use git filter-repo instead.")
    return allow()

@registry.hook("block_reflog_expire")
def block_reflog_expire(data):
    cmd = get_command(data)
    if re.search(r"git\s+reflog\s+expire\s+--expire=now", cmd):
        return deny("Expiring reflog removes recovery points. Keep reflog for safety.")
    return allow()

@registry.hook("block_gc_prune_now")
def block_gc_prune_now(data):
    cmd = get_command(data)
    if re.search(r"git\s+gc\s+.*--prune=now", cmd) or re.search(r"git\s+prune", cmd):
        return deny("Immediate pruning removes unreachable objects. Let git gc handle this naturally.")
    return allow()

@registry.hook("block_push_tags_force")
def block_push_tags_force(data):
    cmd = get_command(data)
    if re.search(r"git\s+push\s+.*--tags\s+.*--force|git\s+push\s+.*--force\s+.*--tags", cmd):
        return deny("Force pushing tags rewrites shared release history. Delete and recreate specific tags instead.")
    return allow()

@registry.hook("block_worktree_remove_force")
def block_worktree_remove_force(data):
    cmd = get_command(data)
    if re.search(r"git\s+worktree\s+remove\s+--force", cmd):
        return deny("Force removing worktree may discard uncommitted changes. Commit or stash first.")
    return allow()

@registry.hook("block_stash_drop_all")
def block_stash_drop_all(data):
    cmd = get_command(data)
    if re.search(r"git\s+stash\s+clear", cmd):
        return deny("git stash clear removes ALL stashes permanently. Drop specific stashes instead.")
    return allow()

@registry.hook("block_replace_refs")
def block_replace_refs(data):
    cmd = get_command(data)
    if re.search(r"git\s+replace", cmd):
        return deny("git replace grafts can cause confusion. Document and review replacement refs carefully.")
    return allow()

@registry.hook("block_update_ref_delete")
def block_update_ref_delete(data):
    cmd = get_command(data)
    if re.search(r"git\s+update-ref\s+-d\s+refs/heads/(main|master|develop)", cmd):
        return deny("Cannot delete protected branch ref directly. Use branch management commands.")
    return allow()

@registry.hook("block_symbolic_ref_change")
def block_symbolic_ref_change(data):
    cmd = get_command(data)
    if re.search(r"git\s+symbolic-ref\s+HEAD\s+refs/heads/((?!main|master)\S+)", cmd):
        return deny("Changing HEAD symbolic ref can confuse repository state. Use git checkout instead.")
    return allow()

@registry.hook("block_remote_set_url_unverified")
def block_remote_set_url_unverified(data):
    cmd = get_command(data)
    if re.search(r"git\s+remote\s+set-url\s+origin\s+", cmd):
        match = re.search(r"set-url\s+origin\s+(\S+)", cmd)
        if match and not re.search(r"github\.com|gitlab\.com|bitbucket\.org", match.group(1)):
            return deny(f"Changing origin to unrecognized host. Verify URL: {match.group(1)[:80]}")
    return allow()

if __name__ == "__main__":
    registry.main()
