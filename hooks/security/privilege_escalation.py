#!/usr/bin/env python3
"""
Security: Privilege Escalation Prevention hooks for Codex.
20 PreToolUse hooks preventing privilege escalation attempts.
"""

import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, get_command

registry = HookRegistry()


@registry.hook("block_sudo_shell")
def block_sudo_shell(data):
    """Block sudo su, sudo bash, sudo sh, sudo -i."""
    cmd = get_command(data)
    if re.search(r"\bsudo\s+(su|bash|sh|zsh|csh|fish|ksh)\b", cmd):
        return deny("Blocked: sudo to interactive shell")
    if re.search(r"\bsudo\s+-[a-zA-Z]*i", cmd):
        return deny("Blocked: sudo login shell (-i)")
    return allow()


@registry.hook("block_sudo_tee_etc")
def block_sudo_tee_etc(data):
    """Block sudo tee to write to /etc/ files."""
    cmd = get_command(data)
    if re.search(r"\bsudo\s+tee\s+/etc/", cmd):
        return deny("Blocked: sudo tee writing to /etc/")
    if re.search(r"\|\s*sudo\s+tee\s+/etc/", cmd):
        return deny("Blocked: piping to sudo tee /etc/")
    return allow()


@registry.hook("block_sudo_chmod")
def block_sudo_chmod(data):
    """Block sudo chmod on system binaries."""
    cmd = get_command(data)
    if re.search(r"\bsudo\s+chmod\s+.*/(usr|bin|sbin|lib)/", cmd):
        return deny("Blocked: sudo chmod on system binaries")
    return allow()


@registry.hook("block_sudo_chattr")
def block_sudo_chattr(data):
    """Block sudo chattr -i (removing immutable flag)."""
    cmd = get_command(data)
    if re.search(r"\bsudo\s+chattr\s+-i\b", cmd):
        return deny("Blocked: removing immutable flag (chattr -i)")
    return allow()


@registry.hook("block_pkexec")
def block_pkexec(data):
    """Block pkexec commands."""
    cmd = get_command(data)
    if re.search(r"\bpkexec\b", cmd):
        return deny("Blocked: pkexec privilege escalation")
    return allow()


@registry.hook("block_doas")
def block_doas(data):
    """Block doas commands without explicit allow."""
    cmd = get_command(data)
    if re.search(r"\bdoas\s+(sh|bash|su)\b", cmd):
        return deny("Blocked: doas to shell")
    return allow()


@registry.hook("block_su_login")
def block_su_login(data):
    """Block su - (login shell)."""
    cmd = get_command(data)
    if re.search(r"\bsu\s+-\s*$", cmd):
        return deny("Blocked: su to root login shell")
    if re.search(r"\bsu\s+-\s+root\b", cmd):
        return deny("Blocked: su to root")
    return allow()


@registry.hook("block_setcap")
def block_setcap(data):
    """Block setcap to add Linux capabilities."""
    cmd = get_command(data)
    if re.search(r"\bsetcap\b", cmd):
        return deny("Blocked: setting Linux capabilities (setcap)")
    return allow()


@registry.hook("block_capabilities_modify")
def block_capabilities_modify(data):
    """Block capability modification tools."""
    cmd = get_command(data)
    if re.search(r"\b(capsh|setpriv)\b", cmd):
        return deny("Blocked: capability modification tool")
    return allow()


@registry.hook("block_namespace_escape")
def block_namespace_escape(data):
    """Block namespace escape via nsenter/unshare."""
    cmd = get_command(data)
    if re.search(r"\bnsenter\s+-t\s+1\b", cmd):
        return deny("Blocked: nsenter to PID 1 (namespace escape)")
    if re.search(r"\bnsenter\s+.*--mount.*--pid", cmd):
        return deny("Blocked: nsenter with mount+pid namespaces")
    if re.search(r"\bunshare\s+.*-[a-zA-Z]*r", cmd):
        return deny("Blocked: unshare with user namespace (potential escape)")
    return allow()


@registry.hook("block_ptrace_attach")
def block_ptrace_attach(data):
    """Block ptrace/strace/ltrace on system processes."""
    cmd = get_command(data)
    if re.search(r"\b(strace|ltrace)\s+.*-p\s+(1|[0-9]{1,3})\b", cmd):
        return deny("Blocked: tracing system process")
    if re.search(r"\bgdb\s+.*-p\s+(1|[0-9]{1,3})\b", cmd):
        return deny("Blocked: attaching debugger to system process")
    return allow()


@registry.hook("block_ld_preload")
def block_ld_preload(data):
    """Block LD_PRELOAD and LD_LIBRARY_PATH injection."""
    cmd = get_command(data)
    if re.search(r"\bLD_PRELOAD\s*=\s*\S+", cmd):
        return deny("Blocked: LD_PRELOAD library injection")
    if re.search(r"\bLD_LIBRARY_PATH\s*=.*/(tmp|home|dev/shm)", cmd):
        return deny("Blocked: LD_LIBRARY_PATH pointing to untrusted location")
    return allow()


@registry.hook("block_proc_mem_write")
def block_proc_mem_write(data):
    """Block writing to /proc/*/mem."""
    cmd = get_command(data)
    if re.search(r">\s*/proc/\d+/mem\b", cmd):
        return deny("Blocked: writing to process memory")
    if re.search(r"\bdd\s+.*of=/proc/\d+/mem\b", cmd):
        return deny("Blocked: dd to process memory")
    return allow()


@registry.hook("block_debugfs")
def block_debugfs(data):
    """Block debugfs access to filesystems."""
    cmd = get_command(data)
    if re.search(r"\bdebugfs\b", cmd):
        return deny("Blocked: debugfs filesystem access")
    return allow()


@registry.hook("block_mount_proc")
def block_mount_proc(data):
    """Block mounting proc/sysfs in unusual locations."""
    cmd = get_command(data)
    if re.search(r"\bmount\s+-t\s+(proc|sysfs)\s+\S+\s+(?!/(proc|sys)\b)", cmd):
        return deny("Blocked: mounting proc/sysfs in non-standard location")
    return allow()


@registry.hook("block_chroot_escape")
def block_chroot_escape(data):
    """Block chroot with privilege escalation."""
    cmd = get_command(data)
    if re.search(r"\bchroot\s+.*\b(bash|sh|su)\b", cmd):
        return deny("Blocked: chroot with shell execution")
    return allow()


@registry.hook("block_docker_socket")
def block_docker_socket(data):
    """Block docker -v /:/host type mounts (container escape)."""
    cmd = get_command(data)
    if re.search(r"\bdocker\s+run\b.*-v\s+/:/", cmd):
        return deny("Blocked: mounting host root in container (escape vector)")
    if re.search(r"\bdocker\s+run\b.*-v\s+/var/run/docker\.sock", cmd):
        return deny("Blocked: mounting Docker socket in container")
    return allow()


@registry.hook("block_container_privileged")
def block_container_privileged(data):
    """Block docker run --privileged."""
    cmd = get_command(data)
    if re.search(r"\bdocker\s+run\b.*--privileged\b", cmd):
        return deny("Blocked: running Docker container in privileged mode")
    return allow()


@registry.hook("block_nmap_scripts")
def block_nmap_scripts(data):
    """Block nmap with dangerous NSE scripts."""
    cmd = get_command(data)
    dangerous_scripts = r"(exploit|brute|dos|vuln|fuzzer|backdoor)"
    if re.search(r"\bnmap\b.*--script\s*=?\s*" + dangerous_scripts, cmd):
        return deny("Blocked: nmap with dangerous NSE script category")
    return allow()


@registry.hook("block_exploit_tools")
def block_exploit_tools(data):
    """Block known exploitation frameworks."""
    cmd = get_command(data)
    tools = r"\b(msfconsole|msfvenom|sqlmap|nikto|hydra|john|hashcat|burpsuite|wpscan|beef-xss|responder|mimikatz|empire|covenant|cobaltstrike)\b"
    if re.search(tools, cmd, re.IGNORECASE):
        return deny("Blocked: exploitation tool detected")
    return allow()


if __name__ == "__main__":
    registry.main()
