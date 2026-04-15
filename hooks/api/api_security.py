#!/usr/bin/env python3
"""PreToolUse hooks for API security - validates API calls before execution."""
import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, get_command

registry = HookRegistry()

# Common API key patterns
API_KEY_PATTERNS = [
    r'(?:sk|pk|api|key|token|secret|access)[_-](?:live|test|prod)?[_-]?[A-Za-z0-9]{20,}',
    r'\bAIza[0-9A-Za-z_-]{35}\b',                    # Google API key
    r'\bsk-[A-Za-z0-9]{20,}\b',                        # OpenAI/Stripe secret key
    r'\bghp_[A-Za-z0-9]{36}\b',                        # GitHub personal access token
    r'\bgho_[A-Za-z0-9]{36}\b',                        # GitHub OAuth token
    r'\bglpat-[A-Za-z0-9_-]{20,}\b',                   # GitLab PAT
    r'\bxoxb-[0-9]{10,}-[A-Za-z0-9]{20,}\b',           # Slack bot token
    r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b',  # SendGrid
    r'\brk_live_[A-Za-z0-9]{24,}\b',                   # Stripe restricted key
    r'\bAKIA[0-9A-Z]{16}\b',                           # AWS access key
]

ADMIN_PATH_PATTERNS = [
    r'/admin\b', r'/admin/', r'/_admin', r'/dashboard/admin',
    r'/api/admin', r'/manage/', r'/superadmin',
    r'/phpmyadmin', r'/adminer', r'/wp-admin',
    r'/console', r'/actuator', r'/graphiql',
]

DEBUG_PATH_PATTERNS = [
    r'/__debug__', r'/debug/', r'/_debug',
    r'/_profiler', r'/profiler', r'/__profiler',
    r'/phpinfo', r'/_routes', r'/__routes',
    r'/server-info', r'/server-status',
    r'/health/detailed', r'/metrics',
    r'/swagger\.json', r'/openapi\.json',
    r'/graphql.*introspection',
]

INTERNAL_PATH_PATTERNS = [
    r'/internal/', r'/_internal/', r'/private/',
    r'/api/internal', r'/api/private',
    r'localhost:\d+/api', r'127\.0\.0\.1:\d+/api',
    r'10\.\d+\.\d+\.\d+', r'172\.(1[6-9]|2\d|3[01])\.',
    r'192\.168\.\d+\.\d+',
]


def _extract_url(command):
    """Extract URL from curl/httpie/wget commands."""
    # curl URL, httpie URL, wget URL
    url_match = re.search(r'(?:curl|http|https|wget)\s+(?:[^"\']*\s+)?["\']?(https?://[^\s"\']+)', command)
    if url_match:
        return url_match.group(1)
    # Just find any URL
    url_match = re.search(r'https?://[^\s"\']+', command)
    return url_match.group(0) if url_match else ""


def _extract_headers(command):
    """Extract headers from curl/httpie commands."""
    headers = {}
    # curl -H "Header: Value"
    for m in re.finditer(r'-H\s+["\']([^"\']+)["\']', command):
        parts = m.group(1).split(":", 1)
        if len(parts) == 2:
            headers[parts[0].strip().lower()] = parts[1].strip()
    # httpie Header:Value
    for m in re.finditer(r'\s(\w[\w-]+):(\S+)', command):
        headers[m.group(1).lower()] = m.group(2)
    return headers


def _is_api_call(command):
    """Check if the command is an API call."""
    return bool(re.search(r'\b(curl|wget|http|https|httpie|fetch)\b', command, re.IGNORECASE))


@registry.hook("api_block_hardcoded_keys")
def api_block_hardcoded_keys(data):
    """Block hardcoded API keys in curl/httpie commands."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    for pattern in API_KEY_PATTERNS:
        if re.search(pattern, command):
            return deny(
                "BLOCKED: Hardcoded API key detected in command. "
                "Use environment variables instead: "
                "curl -H \"Authorization: Bearer $API_KEY\" or export the key first."
            )
    return allow()


@registry.hook("api_enforce_https")
def api_enforce_https(data):
    """Block HTTP (non-HTTPS) API calls."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    url = _extract_url(command)
    if not url:
        return allow()
    # Allow localhost/127.0.0.1 over HTTP
    if re.search(r'https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])', url):
        return allow()
    if url.startswith("http://") and not url.startswith("https://"):
        return deny(
            "BLOCKED: HTTP (non-HTTPS) API call detected. "
            "Data sent over HTTP is unencrypted and vulnerable to interception. "
            "Use HTTPS instead: change http:// to https://"
        )
    return allow()


@registry.hook("api_check_auth_header")
def api_check_auth_header(data):
    """Ensure Authorization header is present for protected endpoints."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    url = _extract_url(command)
    if not url:
        return allow()
    # Skip public endpoints
    public_paths = ['/public/', '/health', '/ping', '/status', '/version', '/favicon', '/robots.txt']
    for p in public_paths:
        if p in url.lower():
            return allow()
    headers = _extract_headers(command)
    # Check for auth mechanisms
    has_auth = (
        'authorization' in headers or
        'x-api-key' in headers or
        re.search(r'--user\b|--basic\b|-u\s+\w+:', command) or
        re.search(r'token[=:]\S+', command, re.IGNORECASE) or
        re.search(r'\$\w*(TOKEN|KEY|AUTH|SECRET)', command)
    )
    if not has_auth and re.search(r'/api/', url):
        return deny(
            "WARNING: API call to a non-public endpoint without an Authorization header. "
            "Add -H \"Authorization: Bearer $TOKEN\" or appropriate authentication."
        )
    return allow()


@registry.hook("api_block_admin_endpoints")
def api_block_admin_endpoints(data):
    """Warn about accessing admin API endpoints."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    url = _extract_url(command)
    for pattern in ADMIN_PATH_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return deny(
                "WARNING: Accessing an admin endpoint. "
                "Ensure you have proper authorization and are targeting the correct environment. "
                "Admin endpoints can make destructive changes."
            )
    return allow()


@registry.hook("api_validate_content_type")
def api_validate_content_type(data):
    """Ensure proper Content-Type headers for POST/PUT/PATCH requests."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    # Check if this is a request with a body
    has_body = re.search(r'-d\s+|--data\s+|-X\s+(POST|PUT|PATCH)|--json\b', command, re.IGNORECASE)
    if not has_body:
        return allow()
    headers = _extract_headers(command)
    # --json flag in curl auto-sets Content-Type
    if '--json' in command:
        return allow()
    if 'content-type' not in headers:
        return deny(
            "WARNING: POST/PUT/PATCH request without Content-Type header. "
            "Add -H \"Content-Type: application/json\" for JSON payloads, "
            "or use curl's --json flag which sets it automatically."
        )
    return allow()


@registry.hook("api_check_rate_limit_headers")
def api_check_rate_limit_headers(data):
    """Remind about rate limiting for batch API calls."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    # Detect looping patterns that suggest batch API calls
    batch_patterns = [
        r'\bfor\b.*\bcurl\b', r'\bwhile\b.*\bcurl\b',
        r'\bxargs\b.*\bcurl\b', r'\bparallel\b.*\bcurl\b',
        r'\bseq\b.*\bcurl\b',
    ]
    for p in batch_patterns:
        if re.search(p, command, re.IGNORECASE):
            return deny(
                "WARNING: Batch API calls detected. Ensure you respect rate limits. "
                "Add a delay between requests (sleep 1) and check X-RateLimit-Remaining headers. "
                "Consider using the API's batch endpoint if available."
            )
    return allow()


@registry.hook("api_block_debug_endpoints")
def api_block_debug_endpoints(data):
    """Block accessing debug/profiling endpoints."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    url = _extract_url(command)
    for pattern in DEBUG_PATH_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return deny(
                "WARNING: Accessing a debug/profiling endpoint. "
                "These endpoints may expose sensitive internal information. "
                "Ensure this is intentional and not a production URL."
            )
    return allow()


@registry.hook("api_validate_cors_preflight")
def api_validate_cors_preflight(data):
    """Check CORS preflight requests."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    if re.search(r'-X\s+OPTIONS\b', command, re.IGNORECASE):
        headers = _extract_headers(command)
        if 'origin' not in headers:
            return deny(
                "WARNING: CORS preflight (OPTIONS) request without Origin header. "
                "Add -H \"Origin: https://your-domain.com\" to properly test CORS behavior."
            )
        if 'access-control-request-method' not in headers:
            return deny(
                "WARNING: CORS preflight without Access-Control-Request-Method header. "
                "Add -H \"Access-Control-Request-Method: POST\" (or the actual method) for a valid preflight."
            )
    return allow()


@registry.hook("api_check_api_versioning")
def api_check_api_versioning(data):
    """Ensure API version is specified in requests."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    url = _extract_url(command)
    if not url:
        return allow()
    # Skip if version is already in URL or headers
    if re.search(r'/v\d+/', url) or re.search(r'/api/\d+/', url):
        return allow()
    headers = _extract_headers(command)
    if any(k in headers for k in ['api-version', 'x-api-version', 'accept-version']):
        return allow()
    # Only warn for known API patterns
    if re.search(r'/api/', url) and not re.search(r'localhost|127\.0\.0\.1', url):
        return deny(
            "SUGGESTION: API call without version specifier. "
            "Pin to a specific version (e.g., /api/v2/) to avoid breaking changes "
            "when the API is updated."
        )
    return allow()


@registry.hook("api_block_mass_assignment")
def api_block_mass_assignment(data):
    """Warn about sending unexpected fields in requests."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    # Look for JSON data with admin/role/permission fields
    data_match = re.search(r"(?:-d|--data|--json)\s+['\"]?(\{.+?\})", command, re.DOTALL)
    if data_match:
        payload = data_match.group(1).lower()
        dangerous_fields = [
            "is_admin", "isadmin", "role", "roles", "permission", "permissions",
            "is_superuser", "admin", "verified", "is_verified", "email_verified",
            "is_staff", "privilege", "access_level",
        ]
        found = [f for f in dangerous_fields if f in payload]
        if found:
            return deny(
                f"WARNING: Request payload contains potentially privileged fields: {', '.join(found)}. "
                "This may attempt mass assignment of protected attributes. "
                "Ensure the API properly validates and whitelists accepted fields."
            )
    return allow()


@registry.hook("api_check_pagination")
def api_check_pagination(data):
    """Suggest pagination for list endpoints."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    url = _extract_url(command)
    if not url:
        return allow()
    # Check for common list endpoints without pagination params
    list_indicators = ['/list', '/all', '/search', '/users', '/items', '/products', '/events', '/logs']
    is_list = any(ind in url.lower() for ind in list_indicators)
    if is_list:
        has_pagination = re.search(r'[?&](page|limit|offset|per_page|page_size|cursor|after|before)=', url)
        if not has_pagination:
            return deny(
                "SUGGESTION: List endpoint called without pagination parameters. "
                "Add ?page=1&limit=50 (or ?cursor=...) to avoid fetching all records, "
                "which can be slow and memory-intensive."
            )
    return allow()


@registry.hook("api_validate_webhook_signatures")
def api_validate_webhook_signatures(data):
    """Remind about webhook signature verification."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    url = _extract_url(command)
    if re.search(r'webhook', url + " " + command, re.IGNORECASE):
        headers = _extract_headers(command)
        sig_headers = ['x-hub-signature', 'x-hub-signature-256', 'stripe-signature',
                       'x-webhook-signature', 'x-signature', 'x-slack-signature']
        has_sig = any(h in headers for h in sig_headers)
        if not has_sig and re.search(r'-X\s+POST\b', command, re.IGNORECASE):
            return deny(
                "REMINDER: When testing webhooks, include a valid signature header. "
                "Webhook endpoints should verify signatures to prevent spoofed payloads. "
                "Example: -H \"X-Hub-Signature-256: sha256=<computed_hmac>\""
            )
    return allow()


@registry.hook("api_check_timeout_config")
def api_check_timeout_config(data):
    """Warn about missing timeout on API calls."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    if not re.search(r'\bcurl\b', command):
        return allow()
    has_timeout = re.search(r'--max-time\b|--connect-timeout\b|-m\s+\d', command)
    if not has_timeout:
        # Only warn for external calls, not localhost
        url = _extract_url(command)
        if url and not re.search(r'localhost|127\.0\.0\.1|0\.0\.0\.0', url):
            return deny(
                "SUGGESTION: curl call without timeout. Add --max-time 30 --connect-timeout 10 "
                "to prevent hanging indefinitely on slow or unresponsive servers."
            )
    return allow()


@registry.hook("api_block_internal_endpoints")
def api_block_internal_endpoints(data):
    """Block accessing internal/private API endpoints externally."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    url = _extract_url(command)
    for pattern in INTERNAL_PATH_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return deny(
                "WARNING: Accessing an internal/private endpoint. "
                "These endpoints are typically not meant for external access "
                "and may lack proper authentication/authorization. Verify this is intentional."
            )
    return allow()


@registry.hook("api_check_error_exposure")
def api_check_error_exposure(data):
    """Warn about verbose error flags that might expose details."""
    command = get_command(data)
    if not _is_api_call(command):
        return allow()
    # Check for verbose/debug flags that might leak info
    if re.search(r'-v\b|--verbose\b|-vvv|--trace\b', command):
        url = _extract_url(command)
        if url and not re.search(r'localhost|127\.0\.0\.1', url):
            return deny(
                "NOTICE: Verbose/trace mode enabled for external API call. "
                "This may display sensitive headers (Authorization, cookies, tokens) in the output. "
                "Ensure you're not logging or sharing this output."
            )
    return allow()


if __name__ == "__main__":
    registry.main()
