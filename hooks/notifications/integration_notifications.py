#!/usr/bin/env python3
"""PostToolUse hooks for sending notifications to external services."""
import json
import re
import sys
import os
import platform
import subprocess
import datetime
import urllib.request
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import (
    HookRegistry, allow, post_tool_context, get_command, get_command_output,
    get_session_id
)
from _lib.utils import log_event

registry = HookRegistry()

LOG_DIR = os.path.expanduser("~/.codex/hooks/logs")
NOTIFY_CONFIG_FILE = os.path.expanduser("~/.codex/hooks/notify_config.json")


def _load_notify_config():
    """Load notification configuration with webhook URLs and settings."""
    try:
        if os.path.isfile(NOTIFY_CONFIG_FILE):
            with open(NOTIFY_CONFIG_FILE, "r") as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError):
        pass
    return {}


def _should_notify(output, config, event_type="any"):
    """Determine if a notification should be sent based on output and config."""
    if not config:
        return False, ""
    # Check severity thresholds
    min_severity = config.get("min_severity", "error")
    severity_map = {"info": 0, "warning": 1, "error": 2, "critical": 3}
    detected_severity = "info"
    if re.search(r'\b(CRITICAL|FATAL|PANIC)\b', output):
        detected_severity = "critical"
    elif re.search(r'\b(ERROR|Error|FAIL|FAILED)\b', output):
        detected_severity = "error"
    elif re.search(r'\b(WARN|WARNING|Warning)\b', output):
        detected_severity = "warning"
    threshold = severity_map.get(min_severity, 2)
    current = severity_map.get(detected_severity, 0)
    if current < threshold:
        return False, ""
    # Build message
    msg = output[:500].strip()
    return True, msg


def _http_post(url, payload, headers=None, timeout=10):
    """Send HTTP POST request using urllib (no external dependencies)."""
    if headers is None:
        headers = {"Content-Type": "application/json"}
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except Exception as e:
        log_event("notify_errors", f"HTTP POST to {url[:50]}... failed: {e}")
        return None


@registry.hook("notify_slack_webhook")
def notify_slack_webhook(data):
    """Send notification to Slack via webhook."""
    config = _load_notify_config()
    webhook_url = config.get("slack_webhook_url", os.environ.get("CODEX_SLACK_WEBHOOK", ""))
    if not webhook_url:
        return allow()
    output = get_command_output(data)
    should_send, msg = _should_notify(output, config)
    if not should_send:
        return allow()
    session_id = get_session_id(data)
    command = get_command(data)
    payload = {
        "text": f":robot_face: *Codex Hook Alert*",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Session:* `{session_id[:20]}`\n*Command:* `{command[:100]}`\n*Output:*\n```{msg[:400]}```"
                }
            }
        ]
    }
    status = _http_post(webhook_url, payload)
    if status and 200 <= status < 300:
        log_event("notifications", f"Slack notification sent for session {session_id}")
    return allow()


@registry.hook("notify_discord_webhook")
def notify_discord_webhook(data):
    """Send notification to Discord via webhook."""
    config = _load_notify_config()
    webhook_url = config.get("discord_webhook_url", os.environ.get("CODEX_DISCORD_WEBHOOK", ""))
    if not webhook_url:
        return allow()
    output = get_command_output(data)
    should_send, msg = _should_notify(output, config)
    if not should_send:
        return allow()
    session_id = get_session_id(data)
    command = get_command(data)
    payload = {
        "embeds": [{
            "title": "Codex Hook Alert",
            "color": 15158332,  # Red
            "fields": [
                {"name": "Session", "value": f"`{session_id[:20]}`", "inline": True},
                {"name": "Command", "value": f"`{command[:100]}`", "inline": False},
                {"name": "Output", "value": f"```{msg[:500]}```", "inline": False},
            ],
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }]
    }
    status = _http_post(webhook_url, payload)
    if status and 200 <= status < 300:
        log_event("notifications", f"Discord notification sent for session {session_id}")
    return allow()


@registry.hook("notify_teams_webhook")
def notify_teams_webhook(data):
    """Send notification to Microsoft Teams via webhook."""
    config = _load_notify_config()
    webhook_url = config.get("teams_webhook_url", os.environ.get("CODEX_TEAMS_WEBHOOK", ""))
    if not webhook_url:
        return allow()
    output = get_command_output(data)
    should_send, msg = _should_notify(output, config)
    if not should_send:
        return allow()
    session_id = get_session_id(data)
    command = get_command(data)
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000",
        "summary": "Codex Hook Alert",
        "sections": [{
            "activityTitle": "Codex Hook Alert",
            "facts": [
                {"name": "Session", "value": session_id[:20]},
                {"name": "Command", "value": command[:100]},
            ],
            "text": f"```\n{msg[:500]}\n```"
        }]
    }
    _http_post(webhook_url, payload)
    return allow()


@registry.hook("notify_email_smtp")
def notify_email_smtp(data):
    """Send email notification via SMTP."""
    config = _load_notify_config()
    email_config = config.get("email", {})
    smtp_host = email_config.get("smtp_host", os.environ.get("CODEX_SMTP_HOST", ""))
    if not smtp_host:
        return allow()
    output = get_command_output(data)
    should_send, msg = _should_notify(output, config)
    if not should_send:
        return allow()
    smtp_port = int(email_config.get("smtp_port", os.environ.get("CODEX_SMTP_PORT", "587")))
    smtp_user = email_config.get("smtp_user", os.environ.get("CODEX_SMTP_USER", ""))
    smtp_pass = email_config.get("smtp_pass", os.environ.get("CODEX_SMTP_PASS", ""))
    to_addr = email_config.get("to", os.environ.get("CODEX_EMAIL_TO", ""))
    from_addr = email_config.get("from", smtp_user)
    if not all([smtp_user, smtp_pass, to_addr]):
        return allow()
    session_id = get_session_id(data)
    command = get_command(data)
    try:
        import smtplib
        from email.mime.text import MIMEText
        body = f"Session: {session_id}\nCommand: {command[:200]}\n\nOutput:\n{msg}"
        email_msg = MIMEText(body)
        email_msg["Subject"] = f"Codex Alert: {command[:50]}"
        email_msg["From"] = from_addr
        email_msg["To"] = to_addr
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, [to_addr], email_msg.as_string())
        log_event("notifications", f"Email sent to {to_addr} for session {session_id}")
    except Exception as e:
        log_event("notify_errors", f"Email failed: {e}")
    return allow()


@registry.hook("notify_telegram_bot")
def notify_telegram_bot(data):
    """Send Telegram bot notification."""
    config = _load_notify_config()
    bot_token = config.get("telegram_bot_token", os.environ.get("CODEX_TELEGRAM_TOKEN", ""))
    chat_id = config.get("telegram_chat_id", os.environ.get("CODEX_TELEGRAM_CHAT_ID", ""))
    if not bot_token or not chat_id:
        return allow()
    output = get_command_output(data)
    should_send, msg = _should_notify(output, config)
    if not should_send:
        return allow()
    session_id = get_session_id(data)
    command = get_command(data)
    text = f"*Codex Alert*\n`Session:` {session_id[:20]}\n`Command:` {command[:100]}\n```\n{msg[:400]}\n```"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    _http_post(url, payload)
    return allow()


@registry.hook("notify_pushover")
def notify_pushover(data):
    """Send Pushover notification."""
    config = _load_notify_config()
    user_key = config.get("pushover_user", os.environ.get("CODEX_PUSHOVER_USER", ""))
    api_token = config.get("pushover_token", os.environ.get("CODEX_PUSHOVER_TOKEN", ""))
    if not user_key or not api_token:
        return allow()
    output = get_command_output(data)
    should_send, msg = _should_notify(output, config)
    if not should_send:
        return allow()
    command = get_command(data)
    try:
        form_data = urllib.parse.urlencode({
            "token": api_token,
            "user": user_key,
            "title": f"Codex: {command[:50]}",
            "message": msg[:500],
            "priority": 1 if re.search(r'CRITICAL|FATAL', msg) else 0,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.pushover.net/1/messages.json",
            data=form_data, method="POST"
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log_event("notify_errors", f"Pushover failed: {e}")
    return allow()


@registry.hook("notify_ntfy")
def notify_ntfy(data):
    """Send ntfy.sh notification."""
    config = _load_notify_config()
    ntfy_topic = config.get("ntfy_topic", os.environ.get("CODEX_NTFY_TOPIC", ""))
    ntfy_server = config.get("ntfy_server", os.environ.get("CODEX_NTFY_SERVER", "https://ntfy.sh"))
    if not ntfy_topic:
        return allow()
    output = get_command_output(data)
    should_send, msg = _should_notify(output, config)
    if not should_send:
        return allow()
    command = get_command(data)
    url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"
    try:
        req = urllib.request.Request(url, data=msg[:500].encode("utf-8"), method="POST")
        req.add_header("Title", f"Codex: {command[:50]}")
        req.add_header("Priority", "high" if re.search(r'CRITICAL|FATAL', msg) else "default")
        req.add_header("Tags", "robot")
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log_event("notify_errors", f"ntfy failed: {e}")
    return allow()


@registry.hook("notify_gotify")
def notify_gotify(data):
    """Send Gotify notification."""
    config = _load_notify_config()
    gotify_url = config.get("gotify_url", os.environ.get("CODEX_GOTIFY_URL", ""))
    gotify_token = config.get("gotify_token", os.environ.get("CODEX_GOTIFY_TOKEN", ""))
    if not gotify_url or not gotify_token:
        return allow()
    output = get_command_output(data)
    should_send, msg = _should_notify(output, config)
    if not should_send:
        return allow()
    command = get_command(data)
    url = f"{gotify_url.rstrip('/')}/message?token={gotify_token}"
    payload = {
        "title": f"Codex: {command[:50]}",
        "message": msg[:500],
        "priority": 8 if re.search(r'CRITICAL|FATAL', msg) else 4,
    }
    _http_post(url, payload)
    return allow()


@registry.hook("notify_matrix")
def notify_matrix(data):
    """Send Matrix notification."""
    config = _load_notify_config()
    homeserver = config.get("matrix_homeserver", os.environ.get("CODEX_MATRIX_HOMESERVER", ""))
    room_id = config.get("matrix_room_id", os.environ.get("CODEX_MATRIX_ROOM_ID", ""))
    access_token = config.get("matrix_token", os.environ.get("CODEX_MATRIX_TOKEN", ""))
    if not all([homeserver, room_id, access_token]):
        return allow()
    output = get_command_output(data)
    should_send, msg = _should_notify(output, config)
    if not should_send:
        return allow()
    command = get_command(data)
    session_id = get_session_id(data)
    txn_id = f"codex_{session_id}_{datetime.datetime.now().timestamp()}"
    encoded_room = urllib.parse.quote(room_id)
    url = f"{homeserver.rstrip('/')}/_matrix/client/r0/rooms/{encoded_room}/send/m.room.message/{txn_id}"
    payload = {
        "msgtype": "m.text",
        "body": f"Codex Alert\nCommand: {command[:100]}\n{msg[:400]}",
        "format": "org.matrix.custom.html",
        "formatted_body": f"<b>Codex Alert</b><br><code>{command[:100]}</code><br><pre>{msg[:400]}</pre>"
    }
    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, method="PUT")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {access_token}")
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log_event("notify_errors", f"Matrix failed: {e}")
    return allow()


@registry.hook("notify_custom_webhook")
def notify_custom_webhook(data):
    """Send to custom webhook URL."""
    config = _load_notify_config()
    webhook_url = config.get("custom_webhook_url", os.environ.get("CODEX_CUSTOM_WEBHOOK", ""))
    if not webhook_url:
        return allow()
    output = get_command_output(data)
    should_send, msg = _should_notify(output, config)
    if not should_send:
        return allow()
    session_id = get_session_id(data)
    command = get_command(data)
    payload = {
        "source": "codex-hooks",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "session_id": session_id,
        "command": command[:200],
        "output": msg[:1000],
        "severity": "critical" if re.search(r'CRITICAL|FATAL', msg) else "error",
    }
    # Support custom headers from config
    custom_headers = config.get("custom_webhook_headers", {"Content-Type": "application/json"})
    _http_post(webhook_url, payload, headers=custom_headers)
    return allow()


@registry.hook("notify_log_to_file")
def notify_log_to_file(data):
    """Log notification to file."""
    output = get_command_output(data)
    command = get_command(data)
    session_id = get_session_id(data)
    # Always log (no config needed)
    if not output.strip():
        return allow()
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, "notifications.log")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Detect severity
    severity = "INFO"
    if re.search(r'\b(CRITICAL|FATAL|PANIC)\b', output):
        severity = "CRITICAL"
    elif re.search(r'\b(ERROR|FAIL|FAILED)\b', output):
        severity = "ERROR"
    elif re.search(r'\b(WARN|WARNING)\b', output):
        severity = "WARNING"
    if severity in ("ERROR", "CRITICAL"):
        try:
            with open(log_path, "a") as f:
                f.write(f"[{timestamp}] [{severity}] session={session_id} cmd={command[:100]} output={output[:300]}\n")
        except IOError:
            pass
    return allow()


@registry.hook("notify_log_to_syslog")
def notify_log_to_syslog(data):
    """Log to syslog."""
    output = get_command_output(data)
    command = get_command(data)
    if not re.search(r'\b(ERROR|FAIL|CRITICAL|FATAL)\b', output):
        return allow()
    session_id = get_session_id(data)
    msg = f"codex-hooks[{session_id[:12]}]: {command[:80]} -> {output[:200]}"
    try:
        import syslog
        priority = syslog.LOG_ERR if re.search(r'CRITICAL|FATAL', output) else syslog.LOG_WARNING
        syslog.openlog("codex-hooks", syslog.LOG_PID, syslog.LOG_USER)
        syslog.syslog(priority, msg)
        syslog.closelog()
    except Exception:
        # Fallback: use logger command
        try:
            subprocess.run(
                ["logger", "-t", "codex-hooks", msg[:500]],
                capture_output=True, timeout=5
            )
        except Exception:
            pass
    return allow()


@registry.hook("notify_desktop_and_log")
def notify_desktop_and_log(data):
    """Combined desktop + file logging notification."""
    output = get_command_output(data)
    command = get_command(data)
    session_id = get_session_id(data)
    if not re.search(r'\b(ERROR|FAIL|CRITICAL|FATAL)\b', output):
        return allow()
    # Desktop notification
    system = platform.system()
    title = "Codex Alert"
    msg = output[:200].replace('"', "'")
    try:
        if system == "Darwin":
            script = f'display notification "{msg}" with title "{title}"'
            subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
        elif system == "Linux":
            subprocess.run(["notify-send", title, msg], capture_output=True, timeout=5)
    except Exception:
        pass
    # File log
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(os.path.join(LOG_DIR, "alerts.log"), "a") as f:
            f.write(f"[{timestamp}] session={session_id} cmd={command[:100]} output={output[:300]}\n")
    except IOError:
        pass
    return allow()


@registry.hook("notify_sound_alert")
def notify_sound_alert(data):
    """Play system sound on events."""
    output = get_command_output(data)
    if not re.search(r'\b(ERROR|FAIL|CRITICAL|FATAL|PANIC)\b', output):
        return allow()
    system = platform.system()
    try:
        if system == "Darwin":
            # macOS: use afplay with system sounds
            sound = "/System/Library/Sounds/Basso.aiff"
            if re.search(r'CRITICAL|FATAL|PANIC', output):
                sound = "/System/Library/Sounds/Sosumi.aiff"
            subprocess.run(["afplay", sound], capture_output=True, timeout=5)
        elif system == "Linux":
            # Linux: try paplay, aplay, or beep
            for player in ["paplay", "aplay"]:
                try:
                    # Try standard alert sounds
                    sounds = [
                        "/usr/share/sounds/freedesktop/stereo/dialog-error.oga",
                        "/usr/share/sounds/ubuntu/stereo/dialog-error.ogg",
                        "/usr/share/sounds/gnome/default/alerts/drip.ogg",
                    ]
                    for s in sounds:
                        if os.path.isfile(s):
                            subprocess.run([player, s], capture_output=True, timeout=5)
                            break
                    break
                except FileNotFoundError:
                    continue
    except Exception:
        pass
    return allow()


@registry.hook("notify_terminal_bell")
def notify_terminal_bell(data):
    """Send terminal bell character on errors."""
    output = get_command_output(data)
    if re.search(r'\b(ERROR|FAIL|CRITICAL|FATAL|PANIC)\b', output):
        # Write BEL character to stderr (doesn't interfere with JSON stdout)
        try:
            sys.stderr.write("\a")
            sys.stderr.flush()
        except Exception:
            pass
    return allow()


if __name__ == "__main__":
    registry.main()
