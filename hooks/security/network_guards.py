#!/usr/bin/env python3
"""
Security: Network Guard hooks for Codex.
25 PreToolUse hooks for network security.
"""

import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, get_command

registry = HookRegistry()


@registry.hook("block_data_exfiltration_curl")
def block_data_exfiltration_curl(data):
    """Block curl POST/PUT with file data to external URLs."""
    cmd = get_command(data)
    if re.search(r"\bcurl\b.*(-d\s*@|-F\s*.*=@|--data-binary\s*@).*\.(env|pem|key|p12|pfx|credentials)", cmd):
        return deny("Blocked: curl uploading sensitive file")
    if re.search(r"\bcurl\b.*--upload-file\s+.*\.(env|pem|key|ssh)", cmd):
        return deny("Blocked: curl uploading sensitive file")
    return allow()


@registry.hook("block_data_exfiltration_wget")
def block_data_exfiltration_wget(data):
    """Block wget POST with sensitive data."""
    cmd = get_command(data)
    if re.search(r"\bwget\b.*--post-file\s*=?\s*\S*\.(env|pem|key|credentials)", cmd):
        return deny("Blocked: wget posting sensitive file")
    return allow()


@registry.hook("block_dns_tunneling")
def block_dns_tunneling(data):
    """Block DNS tunneling tools."""
    cmd = get_command(data)
    if re.search(r"\b(dnscat2?|iodine[d]?|dns2tcp|dnscrypt-proxy)\b", cmd):
        return deny("Blocked: DNS tunneling tool")
    return allow()


@registry.hook("block_tor_access")
def block_tor_access(data):
    """Block Tor network access."""
    cmd = get_command(data)
    if re.search(r"\b(tor|torsocks|proxychains|proxychains4)\b", cmd):
        return deny("Blocked: Tor/proxy chain access")
    return allow()


@registry.hook("block_port_scanning")
def block_port_scanning(data):
    """Block port scanning tools."""
    cmd = get_command(data)
    if re.search(r"\b(nmap|masscan|zmap|unicornscan|rustscan)\b", cmd):
        return deny("Blocked: port scanning tool")
    return allow()


@registry.hook("block_raw_socket")
def block_raw_socket(data):
    """Block raw socket tools."""
    cmd = get_command(data)
    if re.search(r"\b(hping3?|scapy|nemesis|packetsender)\b", cmd):
        return deny("Blocked: raw socket/packet crafting tool")
    return allow()


@registry.hook("block_packet_capture")
def block_packet_capture(data):
    """Block packet capture tools."""
    cmd = get_command(data)
    if re.search(r"\b(tcpdump|tshark|wireshark|dumpcap|snoop)\b", cmd):
        return deny("Blocked: packet capture tool")
    return allow()


@registry.hook("block_arp_spoofing")
def block_arp_spoofing(data):
    """Block ARP spoofing tools."""
    cmd = get_command(data)
    if re.search(r"\b(arpspoof|ettercap|bettercap|arp-scan\s+.*--arping)\b", cmd):
        return deny("Blocked: ARP spoofing/MITM tool")
    return allow()


@registry.hook("block_mac_spoofing")
def block_mac_spoofing(data):
    """Block MAC address spoofing."""
    cmd = get_command(data)
    if re.search(r"\bmacchanger\b", cmd):
        return deny("Blocked: MAC address spoofing tool")
    if re.search(r"\bip\s+link\s+set\s+.*\baddress\b", cmd):
        return deny("Blocked: MAC address change via ip link")
    return allow()


@registry.hook("block_wifi_attacks")
def block_wifi_attacks(data):
    """Block WiFi attack tools."""
    cmd = get_command(data)
    if re.search(r"\b(aircrack-ng|airmon-ng|aireplay-ng|airodump-ng|reaver|pixiewps|wifite|fluxion)\b", cmd):
        return deny("Blocked: WiFi attack tool")
    return allow()


@registry.hook("block_vpn_modification")
def block_vpn_modification(data):
    """Block VPN configuration modification."""
    cmd = get_command(data)
    if re.search(r"\b(openvpn|wg\s+set|wg-quick)\b.*\b(up|down|set)\b", cmd):
        return deny("Blocked: VPN configuration change")
    return allow()


@registry.hook("block_proxy_setup")
def block_proxy_setup(data):
    """Block setting up tunneling proxies."""
    cmd = get_command(data)
    if re.search(r"\b(http_proxy|https_proxy|ALL_PROXY)\s*=\s*socks", cmd, re.IGNORECASE):
        return deny("Blocked: setting SOCKS proxy environment")
    if re.search(r"\bssh\s+.*-D\s+\d+\b", cmd):
        return deny("Blocked: SSH SOCKS proxy tunnel")
    return allow()


@registry.hook("block_ip_forwarding")
def block_ip_forwarding(data):
    """Block enabling IP forwarding."""
    cmd = get_command(data)
    if re.search(r"\bsysctl\b.*net\.ipv4\.ip_forward\s*=\s*1", cmd):
        return deny("Blocked: enabling IPv4 forwarding")
    if re.search(r">\s*/proc/sys/net/ipv4/ip_forward", cmd):
        return deny("Blocked: enabling IP forwarding via proc")
    return allow()


@registry.hook("block_promiscuous_mode")
def block_promiscuous_mode(data):
    """Block setting interfaces to promiscuous mode."""
    cmd = get_command(data)
    if re.search(r"\bifconfig\s+\w+\s+promisc\b", cmd):
        return deny("Blocked: setting interface to promiscuous mode")
    if re.search(r"\bip\s+link\s+set\s+\w+\s+promisc\s+on\b", cmd):
        return deny("Blocked: setting interface to promiscuous mode")
    return allow()


@registry.hook("block_network_bridge")
def block_network_bridge(data):
    """Block creating network bridges for MITM."""
    cmd = get_command(data)
    if re.search(r"\b(brctl\s+addbr|ip\s+link\s+add.*type\s+bridge)\b", cmd):
        return deny("Blocked: creating network bridge")
    return allow()


@registry.hook("rate_limit_curl")
def rate_limit_curl(data):
    """Warn on curl/wget to suspicious rapid patterns."""
    cmd = get_command(data)
    if re.search(r"\bfor\b.*\b(curl|wget)\b", cmd):
        return deny("Blocked: loop with network requests (potential abuse)")
    if re.search(r"\bwhile\b.*\b(curl|wget)\b", cmd):
        return deny("Blocked: loop with network requests (potential abuse)")
    return allow()


@registry.hook("block_ftp_plain")
def block_ftp_plain(data):
    """Block unencrypted FTP connections."""
    cmd = get_command(data)
    if re.search(r"\bftp\s+(?!-s)", cmd) and not re.search(r"\bsftp\b", cmd):
        return deny("Blocked: unencrypted FTP (use SFTP/SCP instead)")
    return allow()


@registry.hook("block_telnet")
def block_telnet(data):
    """Block telnet connections."""
    cmd = get_command(data)
    if re.search(r"\btelnet\s+\S+", cmd):
        return deny("Blocked: telnet (use SSH instead)")
    return allow()


@registry.hook("block_rsh_rlogin")
def block_rsh_rlogin(data):
    """Block insecure remote protocols."""
    cmd = get_command(data)
    if re.search(r"\b(rsh|rlogin|rexec|rcp)\s+", cmd):
        return deny("Blocked: insecure remote protocol (use SSH)")
    return allow()


@registry.hook("validate_https_only")
def validate_https_only(data):
    """Warn when HTTP (not HTTPS) URLs are used."""
    cmd = get_command(data)
    if re.search(r"\b(curl|wget|http)\s+.*http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])", cmd):
        return deny("Warning: unencrypted HTTP URL detected (use HTTPS)")
    return allow()


@registry.hook("block_ngrok_expose")
def block_ngrok_expose(data):
    """Block public tunnel exposure tools."""
    cmd = get_command(data)
    if re.search(r"\b(ngrok|localtunnel|lt\s+--port|serveo|bore|cloudflared\s+tunnel)\b", cmd):
        return deny("Blocked: public tunnel tool (exposes local services)")
    return allow()


@registry.hook("block_netcat_listen")
def block_netcat_listen(data):
    """Block netcat in listening mode."""
    cmd = get_command(data)
    if re.search(r"\b(nc|ncat|netcat)\s+.*-[a-zA-Z]*l", cmd):
        return deny("Blocked: netcat in listening mode")
    return allow()


@registry.hook("block_socat_tunnel")
def block_socat_tunnel(data):
    """Block socat tunneling."""
    cmd = get_command(data)
    if re.search(r"\bsocat\b.*TCP.*EXEC", cmd):
        return deny("Blocked: socat tunnel with command execution")
    return allow()


@registry.hook("block_ssh_tunnel_reverse")
def block_ssh_tunnel_reverse(data):
    """Block SSH reverse tunnels."""
    cmd = get_command(data)
    if re.search(r"\bssh\s+.*-R\s+\d+:", cmd):
        return deny("Blocked: SSH reverse tunnel")
    return allow()


@registry.hook("block_ip_spoofing")
def block_ip_spoofing(data):
    """Block IP spoofing techniques."""
    cmd = get_command(data)
    if re.search(r"\bhping3?\s+.*--spoof\b", cmd):
        return deny("Blocked: IP spoofing via hping")
    if re.search(r"\bnmap\s+.*-S\s+\d+\.\d+\.\d+\.\d+", cmd):
        return deny("Blocked: IP spoofing via nmap")
    return allow()


if __name__ == "__main__":
    registry.main()
