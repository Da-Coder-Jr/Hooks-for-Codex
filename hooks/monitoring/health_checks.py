#!/usr/bin/env python3
"""Monitoring: Health check hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("check_http_health_endpoint")
def check_http_health_endpoint(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"curl.*health|curl.*readyz|curl.*livez|curl.*status", cmd) or not output: return allow()
    if re.search(r'"status"\s*:\s*"(?:unhealthy|down|error|degraded)"', output, re.IGNORECASE):
        return post_tool_context("Health: Service reports unhealthy status. Check dependencies and logs.")
    if re.search(r'"status"\s*:\s*"(?:healthy|up|ok)"', output, re.IGNORECASE):
        return post_tool_context("Health: Service is healthy.")
    return allow()

@registry.hook("check_database_connectivity")
def check_database_connectivity(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"pg_isready|mysqladmin\s+ping|mongo.*ping|redis-cli\s+ping", cmd) or not output: return allow()
    if re.search(r"accepting connections|is alive|pong|ok", output, re.IGNORECASE):
        return post_tool_context("Health: Database connection healthy.")
    if re.search(r"refusing|no response|could not connect|not ready", output, re.IGNORECASE):
        return post_tool_context("Health: Database connection failed. Check service status and credentials.")
    return allow()

@registry.hook("check_redis_health")
def check_redis_health(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"redis-cli\s+info|redis-cli\s+ping", cmd) or not output: return allow()
    if re.search(r"PONG", output):
        mem = re.search(r"used_memory_human:(\S+)", output)
        clients = re.search(r"connected_clients:(\d+)", output)
        parts = []
        if mem: parts.append(f"mem:{mem.group(1)}")
        if clients: parts.append(f"clients:{clients.group(1)}")
        return post_tool_context(f"Health: Redis OK. {', '.join(parts)}" if parts else "Health: Redis OK.")
    return allow()

@registry.hook("check_ssl_certificate")
def check_ssl_certificate(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"openssl.*s_client|curl.*-vI.*https", cmd) or not output: return allow()
    expiry = re.search(r"Not After\s*:\s*(.*?)$", output, re.MULTILINE)
    if expiry:
        return post_tool_context(f"Health: SSL certificate expires: {expiry.group(1).strip()}")
    if re.search(r"certificate.*expired|verify.*error|SSL.*error", output, re.IGNORECASE):
        return post_tool_context("Health: SSL certificate error. Renew or fix certificate chain.")
    return allow()

@registry.hook("check_dns_resolution")
def check_dns_resolution(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bnslookup\b|\bdig\b|\bhost\b", cmd) or not output: return allow()
    if re.search(r"NXDOMAIN|server can't find|not found|SERVFAIL", output):
        return post_tool_context("Health: DNS resolution failed. Check domain name and DNS configuration.")
    return allow()

@registry.hook("check_service_port_open")
def check_service_port_open(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bnc\b.*-z|\bnetstat\b|\bss\b.*-l|curl.*localhost", cmd) or not output: return allow()
    if re.search(r"Connection refused|connect.*failed|No route to host", output):
        match = re.search(r"(?:port|:)\s*(\d+)", cmd)
        port = match.group(1) if match else "target"
        return post_tool_context(f"Health: Port {port} not responding. Service may be down.")
    return allow()

@registry.hook("check_elasticsearch_health")
def check_elasticsearch_health(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"_cluster/health|_cat/health|elasticsearch.*health", cmd) or not output: return allow()
    if re.search(r'"status"\s*:\s*"red"', output):
        return post_tool_context("Health: Elasticsearch cluster status RED. Data loss risk, investigate immediately.")
    if re.search(r'"status"\s*:\s*"yellow"', output):
        return post_tool_context("Health: Elasticsearch cluster status YELLOW. Replica shards unassigned.")
    return allow()

@registry.hook("check_rabbitmq_health")
def check_rabbitmq_health(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"rabbitmqctl\s+status|rabbitmq.*health", cmd) or not output: return allow()
    if re.search(r"running_applications.*rabbit", output):
        match = re.search(r"messages.*?(\d+)", output)
        if match and int(match.group(1)) > 10000:
            return post_tool_context(f"Health: RabbitMQ OK but {match.group(1)} messages queued. Check consumers.")
        return post_tool_context("Health: RabbitMQ is running.")
    if re.search(r"nodedown|not_running|Error", output):
        return post_tool_context("Health: RabbitMQ is down. Check service status.")
    return allow()

@registry.hook("check_nginx_status")
def check_nginx_status(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"nginx.*-t|nginx.*status|curl.*nginx_status", cmd) or not output: return allow()
    if re.search(r"syntax is ok|test is successful", output):
        return post_tool_context("Health: Nginx configuration test passed.")
    if re.search(r"syntax.*error|test failed|emerg", output, re.IGNORECASE):
        return post_tool_context("Health: Nginx configuration error. Fix before reload/restart.")
    active = re.search(r"Active connections:\s*(\d+)", output)
    if active:
        return post_tool_context(f"Health: Nginx active connections: {active.group(1)}")
    return allow()

@registry.hook("check_systemd_service")
def check_systemd_service(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"systemctl\s+status", cmd) or not output: return allow()
    if re.search(r"Active:\s+failed", output):
        match = re.search(r"Main PID:.*code=(\w+)", output)
        return post_tool_context(f"Health: Service failed{f' (exit {match.group(1)})' if match else ''}. Check journalctl for details.")
    if re.search(r"Active:\s+active \(running\)", output):
        uptime = re.search(r"since\s+(.*?)$", output, re.MULTILINE)
        return post_tool_context(f"Health: Service running{f' since {uptime.group(1).strip()[:50]}' if uptime else ''}.")
    return allow()

@registry.hook("check_pm2_status")
def check_pm2_status(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"pm2\s+(?:status|list|ls|show)", cmd) or not output: return allow()
    errored = re.findall(r"(\S+)\s+\│\s+errored", output)
    stopped = re.findall(r"(\S+)\s+\│\s+stopped", output)
    if errored:
        return post_tool_context(f"Health: PM2 errored apps: {', '.join(errored)}. Check pm2 logs.")
    if stopped:
        return post_tool_context(f"Health: PM2 stopped apps: {', '.join(stopped)}. Restart with pm2 start.")
    restarts = re.findall(r"(\S+)\s+.*?\│\s+(\d+)\s+\│.*?errored|restart", output)
    high_restarts = [(name, int(count)) for name, count in restarts if int(count) > 10]
    if high_restarts:
        return post_tool_context(f"Health: PM2 high restart counts detected. Application may be unstable.")
    return allow()

@registry.hook("check_container_health")
def check_container_health(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"docker\s+(?:ps|inspect)", cmd) or not output: return allow()
    unhealthy = re.findall(r"(\S+)\s+.*\(unhealthy\)", output)
    if unhealthy:
        return post_tool_context(f"Health: Unhealthy containers: {', '.join(unhealthy[:5])}")
    return allow()

@registry.hook("check_api_latency")
def check_api_latency(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"curl\s+.*-w|curl\s+.*--write-out|httpie|hey\s+|ab\s+|wrk\s+", cmd) or not output: return allow()
    time_total = re.search(r"time_total[:\s]+([\d.]+)", output)
    if time_total:
        seconds = float(time_total.group(1))
        if seconds > 5:
            return post_tool_context(f"Health: API response time {seconds:.2f}s. Exceeds acceptable latency.")
    return allow()

@registry.hook("check_cron_job_status")
def check_cron_job_status(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"crontab|systemctl.*timer|journalctl.*cron", cmd) or not output: return allow()
    if re.search(r"FAILED|error|failed.*run|exit status [^0]", output, re.IGNORECASE):
        return post_tool_context("Health: Cron job failure detected. Check job output and permissions.")
    return allow()

@registry.hook("check_backup_status")
def check_backup_status(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"backup.*completed|dump.*success|snapshot.*created", output, re.IGNORECASE):
        return post_tool_context("Health: Backup completed successfully.")
    if re.search(r"backup.*failed|dump.*error|snapshot.*failed", output, re.IGNORECASE):
        return post_tool_context("Health: Backup failed. Check storage and permissions.")
    return allow()

if __name__ == "__main__":
    registry.main()
