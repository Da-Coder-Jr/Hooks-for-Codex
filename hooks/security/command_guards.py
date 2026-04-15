#!/usr/bin/env python3
"""
Security: Command Guard hooks for Codex.
50 PreToolUse hooks that block dangerous shell commands.
Each hook targets a specific category of dangerous operations.
"""

import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, get_command

registry = HookRegistry()


@registry.hook("block_rm_system_dirs")
def block_rm_system_dirs(data):
    """Block rm targeting system directories."""
    cmd = get_command(data)
    if re.search(r"\brm\s+.*\b/(usr|etc|var|boot|lib|lib64|sbin|bin|proc|sys|dev)\b", cmd):
        return deny("Blocked: rm targeting system directory")
    if re.search(r"\brm\s+.*\b/(System|Library|Applications)\b", cmd):
        return deny("Blocked: rm targeting macOS system directory")
    return allow()


@registry.hook("block_rm_home")
def block_rm_home(data):
    """Block rm -rf on home directory."""
    cmd = get_command(data)
    if re.search(r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(~|\$HOME|/home/\w+)\s*$", cmd):
        return deny("Blocked: rm targeting home directory")
    return allow()


@registry.hook("block_rm_recursive_root")
def block_rm_recursive_root(data):
    """Block rm -r / or rm -rf /."""
    cmd = get_command(data)
    if re.search(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/\s*$", cmd):
        return deny("Blocked: recursive rm on root filesystem")
    if re.search(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+--no-preserve-root", cmd):
        return deny("Blocked: rm with --no-preserve-root")
    return allow()


@registry.hook("block_mkfs")
def block_mkfs(data):
    """Block filesystem formatting commands."""
    cmd = get_command(data)
    if re.search(r"\bmkfs(\.\w+)?\s+", cmd):
        return deny("Blocked: filesystem format command (mkfs)")
    return allow()


@registry.hook("block_dd_devices")
def block_dd_devices(data):
    """Block dd writing to block devices."""
    cmd = get_command(data)
    if re.search(r"\bdd\s+.*\bof=/dev/(sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|loop\d)", cmd):
        return deny("Blocked: dd writing to block device")
    return allow()


@registry.hook("block_fork_bomb")
def block_fork_bomb(data):
    """Block fork bomb patterns."""
    cmd = get_command(data)
    if re.search(r":\(\)\s*\{", cmd):
        return deny("Blocked: fork bomb pattern detected")
    if re.search(r"\bfork\b.*\bwhile\b.*\btrue\b", cmd):
        return deny("Blocked: fork bomb pattern detected")
    if re.search(r"while\s+true\s*;\s*do\s+.*&\s*;\s*done", cmd):
        return deny("Blocked: infinite background process spawning")
    return allow()


@registry.hook("block_chmod_777")
def block_chmod_777(data):
    """Block chmod 777 on system or broad paths."""
    cmd = get_command(data)
    if re.search(r"\bchmod\s+(-R\s+)?777\s+/", cmd):
        return deny("Blocked: chmod 777 on system path")
    return allow()


@registry.hook("block_chmod_suid")
def block_chmod_suid(data):
    """Block setting setuid/setgid bits."""
    cmd = get_command(data)
    if re.search(r"\bchmod\s+.*[ug]\+s\b", cmd):
        return deny("Blocked: setting setuid/setgid bit")
    if re.search(r"\bchmod\s+[2-7][0-7]{3}\s+", cmd):
        mode = re.search(r"\bchmod\s+([0-7]{4})\s+", cmd)
        if mode and int(mode.group(1)[0]) & 6:
            return deny("Blocked: setting setuid/setgid via numeric mode")
    return allow()


@registry.hook("block_chown_root")
def block_chown_root(data):
    """Block chown to root on sensitive paths."""
    cmd = get_command(data)
    if re.search(r"\bchown\s+(-R\s+)?root\s+/(usr|bin|sbin|etc|lib)", cmd):
        return deny("Blocked: chown to root on system path")
    return allow()


@registry.hook("block_shutdown")
def block_shutdown(data):
    """Block shutdown/reboot/halt/poweroff."""
    cmd = get_command(data)
    if re.search(r"\b(shutdown|reboot|halt|poweroff)\b", cmd):
        return deny("Blocked: system shutdown/reboot command")
    return allow()


@registry.hook("block_init_runlevel")
def block_init_runlevel(data):
    """Block init runlevel changes."""
    cmd = get_command(data)
    if re.search(r"\binit\s+[0-6]\b", cmd):
        return deny("Blocked: init runlevel change")
    if re.search(r"\btelinit\s+[0-6]\b", cmd):
        return deny("Blocked: telinit runlevel change")
    return allow()


@registry.hook("block_systemctl_dangerous")
def block_systemctl_dangerous(data):
    """Block dangerous systemctl operations on critical services."""
    cmd = get_command(data)
    critical = r"(sshd|systemd|dbus|NetworkManager|firewalld|ufw|docker|kubelet)"
    if re.search(r"\bsystemctl\s+(halt|poweroff)\b", cmd):
        return deny("Blocked: systemctl halt/poweroff")
    if re.search(r"\bsystemctl\s+(disable|mask|stop)\s+" + critical, cmd):
        return deny("Blocked: disabling critical system service")
    return allow()


@registry.hook("block_disk_overwrite")
def block_disk_overwrite(data):
    """Block direct writes to disk devices."""
    cmd = get_command(data)
    if re.search(r">\s*/dev/(sd[a-z]|nvme\d|hd[a-z]|vd[a-z])", cmd):
        return deny("Blocked: direct write to disk device")
    return allow()


@registry.hook("block_shred_system")
def block_shred_system(data):
    """Block shred on system files."""
    cmd = get_command(data)
    if re.search(r"\bshred\b.*/(usr|etc|var|boot|lib|bin|sbin)", cmd):
        return deny("Blocked: shred on system files")
    return allow()


@registry.hook("block_wipefs")
def block_wipefs(data):
    """Block wipefs commands."""
    cmd = get_command(data)
    if re.search(r"\bwipefs\s+", cmd):
        return deny("Blocked: wipefs (filesystem signature removal)")
    return allow()


@registry.hook("block_fdisk")
def block_fdisk(data):
    """Block partition modification tools."""
    cmd = get_command(data)
    if re.search(r"\b(fdisk|parted|gdisk|sfdisk|cfdisk)\s+/dev/", cmd):
        return deny("Blocked: partition modification tool")
    return allow()


@registry.hook("block_mount_dangerous")
def block_mount_dangerous(data):
    """Block mount with dangerous options."""
    cmd = get_command(data)
    if re.search(r"\bmount\s+.*-o\s*.*\bnosuid\b.*\bexec\b", cmd):
        return deny("Blocked: mount with dangerous option combination")
    if re.search(r"\bmount\s+--bind\s+/dev", cmd):
        return deny("Blocked: bind-mounting /dev")
    return allow()


@registry.hook("block_umount_system")
def block_umount_system(data):
    """Block unmounting critical filesystems."""
    cmd = get_command(data)
    if re.search(r"\bumount\s+(-[a-zA-Z]\s+)?/(proc|sys|dev|run|boot)\b", cmd):
        return deny("Blocked: unmounting critical filesystem")
    return allow()


@registry.hook("block_sysctl_write")
def block_sysctl_write(data):
    """Block sysctl kernel modifications."""
    cmd = get_command(data)
    if re.search(r"\bsysctl\s+-w\b", cmd):
        return deny("Blocked: sysctl kernel parameter modification")
    return allow()


@registry.hook("block_modprobe")
def block_modprobe(data):
    """Block kernel module loading/unloading."""
    cmd = get_command(data)
    if re.search(r"\b(modprobe|insmod|rmmod|depmod)\b", cmd):
        return deny("Blocked: kernel module manipulation")
    return allow()


@registry.hook("block_grub_modify")
def block_grub_modify(data):
    """Block GRUB/bootloader modification."""
    cmd = get_command(data)
    if re.search(r"\b(grub-install|grub-mkconfig|update-grub|grub2-install)\b", cmd):
        return deny("Blocked: bootloader modification")
    if re.search(r"\b(vim?|nano|emacs|cat|tee)\s+.*/grub", cmd):
        return deny("Blocked: editing GRUB configuration")
    return allow()


@registry.hook("block_passwd_shadow")
def block_passwd_shadow(data):
    """Block direct editing of /etc/passwd and /etc/shadow."""
    cmd = get_command(data)
    if re.search(r"\b(vim?|nano|emacs|cat\s*>|tee|sed\s+-i|echo\s+.*>>?)\s+.*/etc/(passwd|shadow|group|gshadow)", cmd):
        return deny("Blocked: direct editing of authentication files")
    return allow()


@registry.hook("block_sudoers_edit")
def block_sudoers_edit(data):
    """Block editing /etc/sudoers directly (use visudo)."""
    cmd = get_command(data)
    if re.search(r"\b(vim?|nano|emacs|cat\s*>|tee|sed\s+-i|echo\s+.*>>?)\s+.*/etc/sudoers", cmd):
        return deny("Blocked: direct sudoers editing (use visudo)")
    return allow()


@registry.hook("block_crontab_system")
def block_crontab_system(data):
    """Block modifying system crontabs."""
    cmd = get_command(data)
    if re.search(r"\b(vim?|nano|emacs|cat\s*>|tee|sed\s+-i)\s+.*/etc/cron", cmd):
        return deny("Blocked: modifying system crontab files")
    return allow()


@registry.hook("block_hosts_modify")
def block_hosts_modify(data):
    """Block modifying /etc/hosts or /etc/resolv.conf."""
    cmd = get_command(data)
    if re.search(r"\b(vim?|nano|emacs|cat\s*>|tee|sed\s+-i|echo\s+.*>>?)\s+.*/etc/(hosts|resolv\.conf)\b", cmd):
        return deny("Blocked: modifying network configuration files")
    return allow()


@registry.hook("block_dns_reconfigure")
def block_dns_reconfigure(data):
    """Block DNS reconfiguration commands."""
    cmd = get_command(data)
    if re.search(r"\bsystemd-resolve\s+--set-dns\b", cmd):
        return deny("Blocked: DNS reconfiguration")
    if re.search(r"\bnmcli\s+.*dns\b", cmd):
        return deny("Blocked: NetworkManager DNS change")
    return allow()


@registry.hook("block_iptables_flush")
def block_iptables_flush(data):
    """Block flushing iptables rules."""
    cmd = get_command(data)
    if re.search(r"\biptables\s+(-F|--flush)\b", cmd):
        return deny("Blocked: flushing all iptables rules")
    if re.search(r"\biptables\s+.*-j\s+DROP\b.*-p\s+all", cmd):
        return deny("Blocked: dropping all network traffic")
    return allow()


@registry.hook("block_firewall_disable")
def block_firewall_disable(data):
    """Block disabling firewalls."""
    cmd = get_command(data)
    if re.search(r"\bufw\s+disable\b", cmd):
        return deny("Blocked: disabling UFW firewall")
    if re.search(r"\bsystemctl\s+stop\s+firewalld\b", cmd):
        return deny("Blocked: stopping firewalld")
    if re.search(r"\bfirewall-cmd\s+.*--panic-on\b", cmd):
        return deny("Blocked: firewalld panic mode")
    return allow()


@registry.hook("block_selinux_disable")
def block_selinux_disable(data):
    """Block disabling SELinux."""
    cmd = get_command(data)
    if re.search(r"\bsetenforce\s+0\b", cmd):
        return deny("Blocked: disabling SELinux enforcement")
    if re.search(r'\bsed\b.*SELINUX=disabled', cmd):
        return deny("Blocked: disabling SELinux via config")
    return allow()


@registry.hook("block_apparmor_disable")
def block_apparmor_disable(data):
    """Block disabling AppArmor."""
    cmd = get_command(data)
    if re.search(r"\b(aa-disable|apparmor_parser\s+-R)\b", cmd):
        return deny("Blocked: disabling AppArmor profile")
    if re.search(r"\bsystemctl\s+(stop|disable)\s+apparmor\b", cmd):
        return deny("Blocked: stopping AppArmor service")
    return allow()


@registry.hook("block_history_clear")
def block_history_clear(data):
    """Block clearing shell history."""
    cmd = get_command(data)
    if re.search(r"\bhistory\s+-c\b", cmd):
        return deny("Blocked: clearing shell history")
    if re.search(r"\brm\s+.*\.(bash_history|zsh_history|history)\b", cmd):
        return deny("Blocked: deleting shell history file")
    if re.search(r"\bHISTSIZE\s*=\s*0\b", cmd):
        return deny("Blocked: disabling history via HISTSIZE=0")
    if re.search(r"\bunset\s+HISTFILE\b", cmd):
        return deny("Blocked: unsetting HISTFILE")
    return allow()


@registry.hook("block_log_deletion")
def block_log_deletion(data):
    """Block deleting log files."""
    cmd = get_command(data)
    if re.search(r"\brm\s+.*(/var/log/|/var/log$)", cmd):
        return deny("Blocked: deleting system log files")
    if re.search(r">\s*/var/log/\w+", cmd):
        return deny("Blocked: truncating system log file")
    return allow()


@registry.hook("block_package_remove_critical")
def block_package_remove_critical(data):
    """Block removing critical system packages."""
    cmd = get_command(data)
    critical_pkgs = r"(libc6?|glibc|systemd|bash|coreutils|kernel|linux-image|grub|openssh|openssl)"
    if re.search(r"\b(apt|apt-get|dnf|yum|pacman|zypper)\s+(remove|purge|erase)\s+.*\b" + critical_pkgs, cmd):
        return deny("Blocked: removing critical system package")
    return allow()


@registry.hook("block_curl_pipe_shell")
def block_curl_pipe_shell(data):
    """Block piping curl/wget to shell."""
    cmd = get_command(data)
    if re.search(r"\bcurl\b.*\|\s*(ba)?sh\b", cmd):
        return deny("Blocked: piping curl output to shell")
    if re.search(r"\bwget\b.*\|\s*(ba)?sh\b", cmd):
        return deny("Blocked: piping wget output to shell")
    if re.search(r"\bwget\s+-O\s*-\b.*\|\s*(ba)?sh\b", cmd):
        return deny("Blocked: piping wget output to shell")
    return allow()


@registry.hook("block_eval_remote")
def block_eval_remote(data):
    """Block eval of remotely fetched code."""
    cmd = get_command(data)
    if re.search(r'\beval\s+"\$\(curl\b', cmd):
        return deny("Blocked: eval of remote curl output")
    if re.search(r'\beval\s+"\$\(wget\b', cmd):
        return deny("Blocked: eval of remote wget output")
    return allow()


@registry.hook("block_python_exec_remote")
def block_python_exec_remote(data):
    """Block Python downloading and executing code."""
    cmd = get_command(data)
    if re.search(r"\bpython3?\s+-c\s+.*\b(urllib|requests)\b.*\bexec\b", cmd):
        return deny("Blocked: Python fetching and executing remote code")
    if re.search(r"\bpython3?\s+-c\s+.*\bexec\b.*\b(urllib|requests)\b", cmd):
        return deny("Blocked: Python fetching and executing remote code")
    return allow()


@registry.hook("block_nc_reverse_shell")
def block_nc_reverse_shell(data):
    """Block netcat reverse shell patterns."""
    cmd = get_command(data)
    if re.search(r"\b(nc|ncat|netcat)\s+.*-[a-zA-Z]*e\s+(ba)?sh\b", cmd):
        return deny("Blocked: netcat reverse shell")
    if re.search(r"\b(nc|ncat|netcat)\s+.*-[a-zA-Z]*e\s+/bin/", cmd):
        return deny("Blocked: netcat executing binary")
    return allow()


@registry.hook("block_bash_reverse_shell")
def block_bash_reverse_shell(data):
    """Block bash reverse shell patterns."""
    cmd = get_command(data)
    if re.search(r"\bbash\s+-i\s+.*>&\s*/dev/tcp/", cmd):
        return deny("Blocked: bash reverse shell via /dev/tcp")
    if re.search(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", cmd):
        return deny("Blocked: /dev/tcp connection (potential reverse shell)")
    return allow()


@registry.hook("block_perl_reverse_shell")
def block_perl_reverse_shell(data):
    """Block Perl reverse shell patterns."""
    cmd = get_command(data)
    if re.search(r"\bperl\s+-e\s+.*\bsocket\b.*\bINET\b", cmd):
        return deny("Blocked: Perl reverse shell pattern")
    if re.search(r"\bperl\s+.*-MIO::Socket", cmd):
        return deny("Blocked: Perl socket connection")
    return allow()


@registry.hook("block_ruby_reverse_shell")
def block_ruby_reverse_shell(data):
    """Block Ruby reverse shell patterns."""
    cmd = get_command(data)
    if re.search(r"\bruby\s+-[re].*\bTCPSocket\b", cmd):
        return deny("Blocked: Ruby reverse shell pattern")
    if re.search(r"\bruby\s+.*\bsocket\b.*\bspawn\b", cmd, re.IGNORECASE):
        return deny("Blocked: Ruby socket with spawn")
    return allow()


@registry.hook("block_python_reverse_shell")
def block_python_reverse_shell(data):
    """Block Python reverse shell patterns."""
    cmd = get_command(data)
    if re.search(r"\bpython3?\s+-c\s+.*\bsocket\b.*\bconnect\b", cmd):
        return deny("Blocked: Python reverse shell pattern")
    if re.search(r"\bpython3?\s+-c\s+.*\bsubprocess\b.*\bPopen\b.*\bsocket\b", cmd):
        return deny("Blocked: Python socket with subprocess")
    return allow()


@registry.hook("block_crypto_mining")
def block_crypto_mining(data):
    """Block cryptocurrency mining commands."""
    cmd = get_command(data)
    miners = r"\b(xmrig|minerd|cgminer|bfgminer|cpuminer|ethminer|nbminer|gminer|t-rex|phoenixminer|lolminer|claymore)\b"
    if re.search(miners, cmd, re.IGNORECASE):
        return deny("Blocked: cryptocurrency mining tool detected")
    if re.search(r"stratum\+tcp://", cmd):
        return deny("Blocked: mining pool connection")
    return allow()


@registry.hook("block_keylogger")
def block_keylogger(data):
    """Block keylogger-like tools."""
    cmd = get_command(data)
    if re.search(r"\bxinput\s+.*test\b", cmd):
        return deny("Blocked: xinput keyboard monitoring")
    if re.search(r"\bxev\b.*-event\s+keyboard", cmd):
        return deny("Blocked: xev keyboard event capture")
    if re.search(r"\b(logkeys|lkl|keysniffer)\b", cmd):
        return deny("Blocked: keylogger tool detected")
    return allow()


@registry.hook("block_screen_capture")
def block_screen_capture(data):
    """Block unauthorized screen capture."""
    cmd = get_command(data)
    if re.search(r"\b(xwd|import\s+-window\s+root|scrot\s+-s|ffmpeg\s+.*x11grab)\b", cmd):
        return deny("Blocked: screen capture tool (verify intent)")
    return allow()


@registry.hook("block_process_kill_system")
def block_process_kill_system(data):
    """Block killing system processes."""
    cmd = get_command(data)
    if re.search(r"\bkill\s+(-9\s+)?1\b", cmd):
        return deny("Blocked: killing PID 1 (init/systemd)")
    if re.search(r"\bkillall\s+(init|systemd|sshd|dockerd|kubelet)\b", cmd):
        return deny("Blocked: killing critical system process")
    return allow()


@registry.hook("block_user_management")
def block_user_management(data):
    """Block user/group management commands."""
    cmd = get_command(data)
    if re.search(r"\b(useradd|userdel|usermod|groupadd|groupdel|groupmod)\b", cmd):
        return deny("Blocked: user/group management command")
    return allow()


@registry.hook("block_password_change")
def block_password_change(data):
    """Block password changes for other users."""
    cmd = get_command(data)
    if re.search(r"\bpasswd\s+\w+", cmd):
        return deny("Blocked: changing another user's password")
    if re.search(r"\bchpasswd\b", cmd):
        return deny("Blocked: bulk password change")
    return allow()


@registry.hook("block_ssh_keygen_overwrite")
def block_ssh_keygen_overwrite(data):
    """Block ssh-keygen overwriting existing keys."""
    cmd = get_command(data)
    if re.search(r"\bssh-keygen\b.*-f\s+.*id_(rsa|ed25519|ecdsa).*-y\s*$", cmd):
        return allow()  # Public key extraction is safe
    if re.search(r"\bssh-keygen\b.*-f\s+(~|/home/).*id_(rsa|ed25519|ecdsa)", cmd):
        if "-N" not in cmd and not re.search(r"\b-y\b", cmd):
            return deny("Blocked: ssh-keygen may overwrite existing SSH key")
    return allow()


@registry.hook("block_git_force_push_main")
def block_git_force_push_main(data):
    """Block force-pushing to main/master/production."""
    cmd = get_command(data)
    if re.search(r"\bgit\s+push\s+.*--force", cmd) or re.search(r"\bgit\s+push\s+-f\b", cmd):
        if re.search(r"\b(main|master|production|prod|release)\b", cmd):
            return deny("Blocked: force push to protected branch")
    return allow()


@registry.hook("block_env_unset_path")
def block_env_unset_path(data):
    """Block unsetting critical environment variables."""
    cmd = get_command(data)
    if re.search(r"\bunset\s+(PATH|HOME|USER|SHELL|LD_LIBRARY_PATH)\b", cmd):
        return deny("Blocked: unsetting critical environment variable")
    if re.search(r"\bexport\s+PATH\s*=\s*$", cmd):
        return deny("Blocked: setting PATH to empty string")
    return allow()


if __name__ == "__main__":
    registry.main()
