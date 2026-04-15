#!/usr/bin/env python3
"""
Security: Filesystem Guard hooks for Codex.
30 PreToolUse + PostToolUse hooks for filesystem security.
"""

import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, post_tool_context, get_command, get_command_output, get_cwd

registry = HookRegistry()


def _cmd_accesses_file(cmd, file_pattern):
    """Check if a command reads/accesses a file matching the pattern."""
    return bool(re.search(r"\b(cat|less|more|head|tail|grep|awk|sed|cp|mv|scp|rsync|vim?|nano|code|bat)\s+.*" + file_pattern, cmd))


@registry.hook("protect_env_files")
def protect_env_files(data):
    """Block exposure of .env files."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.env\b"):
        if not re.search(r"\.env\.(example|template|sample)", cmd):
            return deny("Blocked: accessing .env file (may contain secrets)")
    return allow()


@registry.hook("protect_dotenv_variants")
def protect_dotenv_variants(data):
    """Block access to .env variant files."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.env\.(local|production|staging|development|prod|dev)\b"):
        return deny("Blocked: accessing environment-specific .env file")
    return allow()


@registry.hook("protect_key_files")
def protect_key_files(data):
    """Block exposure of key/certificate files."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\S+\.(pem|key|p12|pfx|jks|keystore)\b"):
        return deny("Blocked: accessing key/certificate file")
    return allow()


@registry.hook("protect_ssh_keys")
def protect_ssh_keys(data):
    """Block cat/copy of SSH private keys."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"id_(rsa|ed25519|ecdsa|dsa)\b"):
        if not re.search(r"\.pub\b", cmd):
            return deny("Blocked: accessing SSH private key file")
    return allow()


@registry.hook("protect_aws_credentials")
def protect_aws_credentials(data):
    """Block reading ~/.aws/credentials."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"(~/|/home/\w+/)\.aws/(credentials|config)\b"):
        return deny("Blocked: accessing AWS credentials file")
    return allow()


@registry.hook("protect_kube_config")
def protect_kube_config(data):
    """Block reading ~/.kube/config."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.kube/config\b"):
        return deny("Blocked: accessing kubeconfig file")
    return allow()


@registry.hook("protect_docker_config")
def protect_docker_config(data):
    """Block reading ~/.docker/config.json."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.docker/config\.json\b"):
        return deny("Blocked: accessing Docker config (may contain registry auth)")
    return allow()


@registry.hook("protect_npmrc")
def protect_npmrc(data):
    """Block reading .npmrc with auth tokens."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.npmrc\b"):
        return deny("Blocked: accessing .npmrc (may contain auth tokens)")
    return allow()


@registry.hook("protect_pypirc")
def protect_pypirc(data):
    """Block reading .pypirc."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.pypirc\b"):
        return deny("Blocked: accessing .pypirc (contains PyPI credentials)")
    return allow()


@registry.hook("protect_netrc")
def protect_netrc(data):
    """Block reading .netrc."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.netrc\b"):
        return deny("Blocked: accessing .netrc (contains credentials)")
    return allow()


@registry.hook("protect_pgpass")
def protect_pgpass(data):
    """Block reading .pgpass."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.pgpass\b"):
        return deny("Blocked: accessing .pgpass (PostgreSQL passwords)")
    return allow()


@registry.hook("protect_git_credentials")
def protect_git_credentials(data):
    """Block reading .git-credentials."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.git-credentials\b"):
        return deny("Blocked: accessing .git-credentials")
    return allow()


@registry.hook("protect_bash_history")
def protect_bash_history(data):
    """Block reading/modifying shell history."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.(bash_history|zsh_history|history|python_history)\b"):
        return deny("Blocked: accessing shell history file")
    return allow()


@registry.hook("protect_gnupg")
def protect_gnupg(data):
    """Block reading .gnupg directory."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.gnupg/(private-keys|secring|trustdb)"):
        return deny("Blocked: accessing GnuPG private data")
    return allow()


@registry.hook("protect_password_store")
def protect_password_store(data):
    """Block reading password store."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"\.password-store/"):
        return deny("Blocked: accessing password store")
    return allow()


@registry.hook("detect_hidden_file_creation")
def detect_hidden_file_creation(data):
    """Warn when creating dotfiles in system directories."""
    cmd = get_command(data)
    if re.search(r"\b(touch|cat\s*>|tee)\s+/(usr|etc|var|opt)/\S*/\.\w+", cmd):
        return deny("Warning: creating hidden file in system directory")
    return allow()


@registry.hook("detect_binary_in_text_dir")
def detect_binary_in_text_dir(data):
    """Warn when placing binaries in source directories."""
    cmd = get_command(data)
    if re.search(r"\b(cp|mv)\s+.*\.(exe|dll|so|dylib|bin)\s+.*/src/", cmd):
        return deny("Warning: placing binary file in source directory")
    return allow()


@registry.hook("block_symlink_to_sensitive")
def block_symlink_to_sensitive(data):
    """Block creating symlinks to sensitive system files."""
    cmd = get_command(data)
    if re.search(r"\bln\s+-s\s+/etc/(passwd|shadow|sudoers)\b", cmd):
        return deny("Blocked: symlink to sensitive system file")
    return allow()


@registry.hook("block_hardlink_to_sensitive")
def block_hardlink_to_sensitive(data):
    """Block hard links to sensitive files."""
    cmd = get_command(data)
    if re.search(r"\bln\s+(?!-s)/etc/(passwd|shadow)\b", cmd):
        return deny("Blocked: hard link to sensitive system file")
    return allow()


@registry.hook("validate_file_permissions")
def validate_file_permissions(data):
    """Warn about world-readable/writable permissions on sensitive files."""
    cmd = get_command(data)
    output = get_command_output(data)
    if output and re.search(r"-rw[x-]rw[x-]rw[x-].*\.(env|key|pem|credentials)", output):
        return post_tool_context("WARNING: Sensitive file has world-readable/writable permissions")
    return allow()


@registry.hook("protect_ssl_certificates")
def protect_ssl_certificates(data):
    """Block reading/copying SSL certificate private keys."""
    cmd = get_command(data)
    if _cmd_accesses_file(cmd, r"(server|ssl|tls|https?)[_-]?(key|private)\.(pem|key)\b"):
        return deny("Blocked: accessing SSL private key file")
    return allow()


@registry.hook("protect_database_files")
def protect_database_files(data):
    """Block direct access to database files."""
    cmd = get_command(data)
    if re.search(r"\b(cat|cp|mv|rm|scp)\s+.*\.(sqlite3?|db)\s", cmd):
        if re.search(r"/(prod|production|data)/", cmd):
            return deny("Blocked: direct access to production database file")
    return allow()


@registry.hook("block_recursive_chmod")
def block_recursive_chmod(data):
    """Block chmod -R on large directory trees."""
    cmd = get_command(data)
    if re.search(r"\bchmod\s+-R\s+\d+\s+/\s*$", cmd):
        return deny("Blocked: recursive chmod on root directory")
    if re.search(r"\bchmod\s+-R\s+\d+\s+/(usr|etc|var|home)\b", cmd):
        return deny("Blocked: recursive chmod on system directory")
    return allow()


@registry.hook("detect_large_file_write")
def detect_large_file_write(data):
    """Warn about commands that could write very large files."""
    cmd = get_command(data)
    if re.search(r"\bdd\b.*\bcount=\d{7,}", cmd):
        return deny("Warning: dd command writing very large file")
    if re.search(r"\bfallocate\s+-l\s+\d+[GT]\b", cmd):
        return deny("Warning: allocating very large file")
    return allow()


@registry.hook("protect_workspace_boundary")
def protect_workspace_boundary(data):
    """Block accessing files outside the project directory."""
    cmd = get_command(data)
    cwd = get_cwd(data)
    paths = re.findall(r'(?:^|\s)(\.\./\.\./\.\./[^\s;|&>]+)', cmd)
    if paths:
        return deny("Warning: accessing files far outside workspace (excessive ../ traversal)")
    return allow()


@registry.hook("detect_zip_bomb")
def detect_zip_bomb(data):
    """Warn about extracting suspiciously small archives."""
    cmd = get_command(data)
    output = get_command_output(data)
    if output and re.search(r"\b(unzip|tar|7z)\b", cmd):
        if re.search(r"bomb|ratio.*[0-9]{4,}|compression ratio.*[0-9]{4,}", output, re.IGNORECASE):
            return post_tool_context("WARNING: Possible zip bomb detected (extreme compression ratio)")
    return allow()


@registry.hook("protect_tmp_race")
def protect_tmp_race(data):
    """Warn about predictable temp file names (TOCTOU)."""
    cmd = get_command(data)
    if re.search(r">\s*/tmp/\w+\.\w+\s*$", cmd):
        return post_tool_context("Warning: using predictable temp file name. Consider mktemp for safety.")
    return allow()


@registry.hook("block_world_writable_creation")
def block_world_writable_creation(data):
    """Block creating files with mode 666 or 777."""
    cmd = get_command(data)
    if re.search(r"\b(install|touch)\s+.*-m\s*(666|777)\b", cmd):
        return deny("Blocked: creating world-writable file")
    return allow()


@registry.hook("detect_file_type_mismatch")
def detect_file_type_mismatch(data):
    """Warn when file extension doesn't match content."""
    cmd = get_command(data)
    output = get_command_output(data)
    if output and re.search(r"\bfile\s+\S+", cmd):
        if re.search(r"\.txt:.*executable|\.jpg:.*text|\.png:.*text|\.pdf:.*text", output):
            return post_tool_context("Warning: file type doesn't match extension (possible disguised file)")
    return allow()


@registry.hook("protect_git_directory")
def protect_git_directory(data):
    """Block direct modification of .git/ internals."""
    cmd = get_command(data)
    if re.search(r"\b(vim?|nano|cat\s*>|tee|echo\s+.*>)\s+.*\.git/(HEAD|config|objects|refs|hooks)/", cmd):
        return deny("Blocked: direct modification of .git internals (use git commands)")
    return allow()


if __name__ == "__main__":
    registry.main()
