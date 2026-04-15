#!/usr/bin/env python3
"""DevOps: Docker hooks for Codex. 20 PreToolUse/PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("block_docker_privileged")
def block_docker_privileged(data):
    cmd = get_command(data)
    if re.search(r"docker\s+run\s+.*--privileged", cmd):
        return deny("Docker: --privileged gives full host access. Use specific --cap-add instead.")
    return allow()

@registry.hook("block_docker_host_network")
def block_docker_host_network(data):
    cmd = get_command(data)
    if re.search(r"docker\s+run\s+.*--network\s*=?\s*host", cmd):
        return deny("Docker: --network=host exposes all host ports. Use bridge networking with -p.")
    return allow()

@registry.hook("block_docker_host_pid")
def block_docker_host_pid(data):
    cmd = get_command(data)
    if re.search(r"docker\s+run\s+.*--pid\s*=?\s*host", cmd):
        return deny("Docker: --pid=host shares host PID namespace. Security risk.")
    return allow()

@registry.hook("warn_docker_latest_tag")
def warn_docker_latest_tag(data):
    cmd = get_command(data)
    if re.search(r"docker\s+(pull|run)\s+\S+(?::latest\b|[^:])\s", cmd) and not re.search(r":\w+[\d.]", cmd):
        return post_tool_context("Docker: Using :latest tag is non-deterministic. Pin to specific version.")
    return allow()

@registry.hook("block_docker_mount_sensitive")
def block_docker_mount_sensitive(data):
    cmd = get_command(data)
    sensitive = [r"/etc/shadow", r"/etc/passwd", r"/var/run/docker\.sock", r"/root/\.ssh"]
    for pattern in sensitive:
        if re.search(rf"-v\s+{pattern}|--mount.*source={pattern}", cmd):
            return deny(f"Docker: Mounting sensitive host path is a security risk.")
    return allow()

@registry.hook("detect_docker_build_errors")
def detect_docker_build_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bdocker\s+build\b", cmd) or not output: return allow()
    if re.search(r"ERROR|failed to|COPY failed|returned a non-zero code", output):
        match = re.search(r"(?:ERROR|error).*?:\s*(.*?)$", output, re.MULTILINE)
        return post_tool_context(f"Docker build error: {match.group(1)[:100] if match else 'check Dockerfile'}")
    return allow()

@registry.hook("check_dockerfile_best_practices")
def check_dockerfile_best_practices(data):
    output = get_command_output(data)
    if not output: return allow()
    issues = []
    if re.search(r"^FROM\s+\S+\s+AS\s+root|USER\s+root\s*$", output, re.MULTILINE):
        issues.append("running as root")
    if re.search(r"^RUN\s+apt-get\s+install(?!.*--no-install-recommends)", output, re.MULTILINE):
        issues.append("missing --no-install-recommends")
    if re.search(r"^ADD\s+https?://", output, re.MULTILINE):
        issues.append("ADD with URL (use COPY + curl)")
    if issues:
        return post_tool_context(f"Dockerfile: {', '.join(issues)}")
    return allow()

@registry.hook("detect_docker_compose_errors")
def detect_docker_compose_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"docker[\s-]compose", cmd) or not output: return allow()
    if re.search(r"ERROR|error.*validat|yaml.*error|service.*has.*error", output, re.IGNORECASE):
        return post_tool_context("Docker Compose: Configuration error. Check YAML syntax and service definitions.")
    return allow()

@registry.hook("check_docker_image_size")
def check_docker_image_size(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bdocker\s+images\b", cmd) or not output: return allow()
    large = re.findall(r"(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\d+(?:\.\d+)?)\s*GB", output)
    if large:
        names = [f"{n}:{t} ({s}GB)" for n, t, s in large[:3]]
        return post_tool_context(f"Docker: Large images: {', '.join(names)}. Consider multi-stage builds.")
    return allow()

@registry.hook("detect_docker_push_errors")
def detect_docker_push_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bdocker\s+push\b", cmd) or not output: return allow()
    if re.search(r"denied|unauthorized|authentication required", output, re.IGNORECASE):
        return post_tool_context("Docker push: Authentication failed. Run docker login first.")
    return allow()

@registry.hook("block_docker_system_prune_all")
def block_docker_system_prune_all(data):
    cmd = get_command(data)
    if re.search(r"docker\s+system\s+prune\s+(-a|--all)", cmd):
        return deny("Docker: system prune -a removes ALL unused images, not just dangling. Very destructive.")
    return allow()

@registry.hook("check_docker_healthcheck")
def check_docker_healthcheck(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"HEALTHCHECK\s+NONE|no healthcheck", output, re.IGNORECASE):
        return post_tool_context("Docker: No healthcheck defined. Add HEALTHCHECK for production containers.")
    return allow()

@registry.hook("detect_docker_network_issues")
def detect_docker_network_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"network.*not found|could not connect|Cannot link to|pool overlaps", output, re.IGNORECASE):
        return post_tool_context("Docker: Network configuration issue. Check docker network ls and service names.")
    return allow()

@registry.hook("check_docker_volume_mounts")
def check_docker_volume_mounts(data):
    cmd = get_command(data)
    rw_mounts = re.findall(r"-v\s+(/\S+):/\S+(?!:ro)", cmd)
    if len(rw_mounts) > 3:
        return post_tool_context(f"Docker: {len(rw_mounts)} read-write volume mounts. Use :ro for read-only where possible.")
    return allow()

@registry.hook("detect_docker_oom")
def detect_docker_oom(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"OOMKilled|out of memory|memory limit|Killed.*oom", output, re.IGNORECASE):
        return post_tool_context("Docker: Container killed by OOM. Increase memory limit or optimize application.")
    return allow()

@registry.hook("block_docker_cap_sys_admin")
def block_docker_cap_sys_admin(data):
    cmd = get_command(data)
    if re.search(r"--cap-add\s*=?\s*SYS_ADMIN|--cap-add\s*=?\s*ALL", cmd):
        return deny("Docker: SYS_ADMIN/ALL capabilities grant near-root host access. Use minimal caps.")
    return allow()

@registry.hook("check_docker_port_conflicts")
def check_docker_port_conflicts(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"port is already allocated|Bind for.*failed|address already in use", output):
        match = re.search(r"(?:port|Bind for)\s+[\d.:]+:(\d+)", output)
        port = match.group(1) if match else "unknown"
        return post_tool_context(f"Docker: Port {port} already in use. Stop conflicting container or use different port.")
    return allow()

@registry.hook("detect_docker_layer_caching")
def detect_docker_layer_caching(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bdocker\s+build\b", cmd) or not output: return allow()
    cached = len(re.findall(r"CACHED|Using cache", output))
    total = len(re.findall(r"Step \d+/\d+|#\d+ ", output))
    if total > 0 and cached == 0:
        return post_tool_context("Docker: No cache hits. Optimize Dockerfile layer ordering (deps before code).")
    return allow()

@registry.hook("block_docker_rm_force_running")
def block_docker_rm_force_running(data):
    cmd = get_command(data)
    if re.search(r"docker\s+rm\s+-f\s+\$\(docker\s+ps\s+-aq\)", cmd):
        return deny("Docker: Force-removing all containers. This kills ALL running containers.")
    return allow()

@registry.hook("check_docker_security_scan")
def check_docker_security_scan(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"docker\s+scout|trivy|grype|snyk.*container", cmd) or not output: return allow()
    critical = len(re.findall(r"CRITICAL|critical", output))
    high = len(re.findall(r"\bHIGH\b|\bhigh\b", output))
    if critical or high:
        return post_tool_context(f"Docker scan: {critical} critical, {high} high vulnerabilities found.")
    return allow()

if __name__ == "__main__":
    registry.main()
