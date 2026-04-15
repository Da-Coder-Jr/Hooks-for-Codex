#!/usr/bin/env python3
"""PostToolUse hooks for API response validation and analysis."""
import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()

HTTP_STATUS_CATEGORIES = {
    range(200, 300): "Success",
    range(300, 400): "Redirection",
    range(400, 500): "Client Error",
    range(500, 600): "Server Error",
}

HTTP_STATUS_DETAILS = {
    400: "Bad Request - check request syntax/parameters",
    401: "Unauthorized - authentication required or credentials invalid",
    403: "Forbidden - authenticated but lacking permission",
    404: "Not Found - endpoint or resource doesn't exist",
    405: "Method Not Allowed - wrong HTTP method for this endpoint",
    408: "Request Timeout - server timed out waiting",
    409: "Conflict - request conflicts with current state",
    413: "Payload Too Large - reduce request body size",
    415: "Unsupported Media Type - check Content-Type header",
    422: "Unprocessable Entity - valid syntax but semantic errors",
    429: "Too Many Requests - rate limited, wait and retry",
    500: "Internal Server Error - server-side bug",
    502: "Bad Gateway - upstream server error",
    503: "Service Unavailable - server overloaded or in maintenance",
    504: "Gateway Timeout - upstream server didn't respond in time",
}

SECURITY_HEADERS = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]


def _is_api_response(command, output):
    """Check if the output looks like an API response."""
    return bool(
        re.search(r'\bcurl\b|\bwget\b|\bhttp\b|\bhttpie\b', command, re.IGNORECASE) or
        re.search(r'HTTP/[\d.]+\s+\d{3}', output) or
        (output.strip().startswith('{') and '"' in output)
    )


def _extract_status_code(output):
    """Extract HTTP status code from response output."""
    m = re.search(r'HTTP/[\d.]+\s+(\d{3})', output)
    if m:
        return int(m.group(1))
    # curl -w "%{http_code}" output
    m = re.search(r'\b([2-5]\d{2})\s*$', output.strip())
    if m:
        return int(m.group(1))
    return None


def _extract_headers(output):
    """Extract response headers from verbose curl output."""
    headers = {}
    for m in re.finditer(r'^<?\s*([\w-]+):\s*(.+?)\s*$', output, re.MULTILINE):
        headers[m.group(1).lower()] = m.group(2)
    return headers


def _extract_json_body(output):
    """Try to extract and parse JSON from the response body."""
    # Find the first JSON object or array
    for pattern in [r'(\{[\s\S]*\})', r'(\[[\s\S]*\])']:
        m = re.search(pattern, output)
        if m:
            try:
                return json.loads(m.group(1))
            except (json.JSONDecodeError, ValueError):
                continue
    return None


def _estimate_response_time(output):
    """Extract response time from curl output."""
    # curl -w with time_total
    m = re.search(r'time_total[:\s]+(\d+\.?\d*)', output)
    if m:
        return float(m.group(1))
    # curl verbose timing
    m = re.search(r'total.*?(\d+\.?\d*)\s*s', output, re.IGNORECASE)
    if m:
        return float(m.group(1))
    return None


@registry.hook("api_validate_json_response")
def api_validate_json_response(data):
    """Validate JSON response format."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    # Check if response claims to be JSON
    headers = _extract_headers(output)
    content_type = headers.get('content-type', '')
    if 'json' in content_type or output.strip().startswith(('{', '[')):
        body = _extract_json_body(output)
        if body is None and len(output.strip()) > 10:
            # Looks like it should be JSON but isn't valid
            # Try to find specific JSON errors
            truncated = output.strip()[:200]
            return post_tool_context(
                "INVALID JSON RESPONSE: The response appears to be JSON but failed to parse. "
                f"Response starts with: {truncated}... "
                "Check for: truncated responses, HTML error pages, or malformed JSON."
            )
    return allow()


@registry.hook("api_check_status_codes")
def api_check_status_codes(data):
    """Categorize and explain HTTP status codes."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    status = _extract_status_code(output)
    if status is None:
        return allow()
    if status >= 400:
        detail = HTTP_STATUS_DETAILS.get(status, "")
        category = "Client Error" if status < 500 else "Server Error"
        hint = f" - {detail}" if detail else ""
        return post_tool_context(
            f"HTTP {status} ({category}){hint}. "
            + ("Check the request parameters, headers, and authentication." if status < 500
               else "This is a server-side issue. Check server logs or retry later.")
        )
    return allow()


@registry.hook("api_detect_error_responses")
def api_detect_error_responses(data):
    """Parse API error responses with details."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    body = _extract_json_body(output)
    if not isinstance(body, dict):
        return allow()
    # Common error response fields
    error_fields = ['error', 'errors', 'message', 'error_message', 'error_description',
                    'detail', 'details', 'reason', 'fault', 'exception']
    found_errors = []
    for field in error_fields:
        if field in body:
            val = body[field]
            if isinstance(val, str):
                found_errors.append(f"{field}: {val[:200]}")
            elif isinstance(val, list):
                for item in val[:3]:
                    if isinstance(item, dict):
                        msg = item.get('message', item.get('msg', str(item)))
                    else:
                        msg = str(item)
                    found_errors.append(f"{field}: {msg[:200]}")
            elif isinstance(val, dict):
                msg = val.get('message', val.get('msg', val.get('code', str(val))))
                found_errors.append(f"{field}: {str(msg)[:200]}")
    if found_errors:
        return post_tool_context(
            "API ERROR RESPONSE:\n"
            + "\n".join(f"  - {e}" for e in found_errors[:5])
        )
    return allow()


@registry.hook("api_validate_schema")
def api_validate_schema(data):
    """Validate response against expected patterns."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    body = _extract_json_body(output)
    if not isinstance(body, dict):
        return allow()
    issues = []
    # Check for inconsistent data types
    for key, value in body.items():
        if key.endswith('_id') or key.endswith('Id'):
            if value is not None and not isinstance(value, (str, int)):
                issues.append(f"Field '{key}' has unexpected type {type(value).__name__} (expected string or int)")
        if key.endswith('_at') or key.endswith('At') or key in ('created', 'updated', 'timestamp'):
            if isinstance(value, str) and value and not re.match(r'\d{4}-\d{2}-\d{2}', value):
                issues.append(f"Field '{key}' has non-standard date format: {value[:50]}")
        if key == 'email' and isinstance(value, str):
            if not re.match(r'^[^@]+@[^@]+\.[^@]+$', value):
                issues.append(f"Field 'email' has invalid format: {value[:50]}")
    # Check for empty required-looking fields
    for key in ['id', 'type', 'status']:
        if key in body and (body[key] is None or body[key] == ''):
            issues.append(f"Field '{key}' is empty/null but appears required")
    if issues:
        return post_tool_context(
            "RESPONSE SCHEMA ISSUES:\n"
            + "\n".join(f"  - {i}" for i in issues[:5])
        )
    return allow()


@registry.hook("api_check_response_time")
def api_check_response_time(data):
    """Warn about slow API responses."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    elapsed = _estimate_response_time(output)
    if elapsed is not None and elapsed > 5.0:
        return post_tool_context(
            f"SLOW API RESPONSE: Request took {elapsed:.1f}s. "
            "Possible causes: large payload, missing indexes on server, no caching, "
            "or network latency. Consider adding pagination, caching, or optimizing the query."
        )
    elif elapsed is not None and elapsed > 2.0:
        return post_tool_context(
            f"API RESPONSE TIME: {elapsed:.1f}s - slower than typical. "
            "Consider investigating if this is consistently slow."
        )
    return allow()


@registry.hook("api_detect_deprecation_headers")
def api_detect_deprecation_headers(data):
    """Parse API deprecation warning headers."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    headers = _extract_headers(output)
    deprecation_indicators = []
    if 'deprecation' in headers:
        deprecation_indicators.append(f"Deprecation: {headers['deprecation']}")
    if 'sunset' in headers:
        deprecation_indicators.append(f"Sunset date: {headers['sunset']}")
    if 'x-deprecated' in headers:
        deprecation_indicators.append(f"X-Deprecated: {headers['x-deprecated']}")
    if 'warning' in headers and re.search(r'deprecat', headers['warning'], re.IGNORECASE):
        deprecation_indicators.append(f"Warning: {headers['warning']}")
    # Check response body for deprecation notices
    body = _extract_json_body(output)
    if isinstance(body, dict):
        for key in ['deprecated', 'deprecation_notice', 'deprecation_warning']:
            if key in body:
                deprecation_indicators.append(f"{key}: {str(body[key])[:100]}")
    if deprecation_indicators:
        return post_tool_context(
            "API DEPRECATION NOTICE:\n"
            + "\n".join(f"  - {d}" for d in deprecation_indicators)
            + "\nMigrate to the newer API version before the sunset date."
        )
    return allow()


@registry.hook("api_check_content_encoding")
def api_check_content_encoding(data):
    """Validate response encoding (gzip, br)."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    headers = _extract_headers(output)
    # Check if compressed response was requested but not returned
    if re.search(r'--compressed\b|-H.*Accept-Encoding', command):
        encoding = headers.get('content-encoding', '')
        if not encoding:
            content_length = headers.get('content-length', '')
            if content_length and int(content_length) > 10000:
                return post_tool_context(
                    "ENCODING NOTICE: Compression was requested but the server did not compress the response. "
                    f"Response size: {content_length} bytes. "
                    "The server may not support gzip/br compression, resulting in slower transfers."
                )
    return allow()


@registry.hook("api_validate_pagination")
def api_validate_pagination(data):
    """Validate pagination response format."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    body = _extract_json_body(output)
    if not isinstance(body, dict):
        return allow()
    # Detect pagination context
    pagination_keys = ['page', 'per_page', 'total', 'total_pages', 'next', 'previous',
                       'next_page', 'prev_page', 'has_more', 'cursor', 'next_cursor',
                       'offset', 'limit', 'count', 'total_count']
    found_keys = [k for k in pagination_keys if k in body]
    if not found_keys:
        # Check if it's a list response that should be paginated
        if isinstance(body.get('data'), list) or isinstance(body.get('results'), list) or isinstance(body.get('items'), list):
            list_key = next(k for k in ('data', 'results', 'items') if isinstance(body.get(k), list))
            items = body[list_key]
            if len(items) >= 100:
                return post_tool_context(
                    f"PAGINATION MISSING: Response contains {len(items)} items in '{list_key}' "
                    "without pagination metadata. This may not be the complete dataset. "
                    "Check if the API supports pagination parameters (page, limit, cursor)."
                )
        return allow()
    # Validate pagination consistency
    issues = []
    if 'total' in body and 'page' in body and 'per_page' in body:
        try:
            total = int(body['total'])
            per_page = int(body['per_page'])
            if per_page > 0:
                expected_pages = (total + per_page - 1) // per_page
                if 'total_pages' in body and int(body['total_pages']) != expected_pages:
                    issues.append(f"total_pages ({body['total_pages']}) doesn't match total/per_page ({expected_pages})")
        except (ValueError, TypeError):
            pass
    if issues:
        return post_tool_context("PAGINATION ISSUES: " + "; ".join(issues))
    return allow()


@registry.hook("api_check_cache_headers")
def api_check_cache_headers(data):
    """Analyze caching headers (ETag, Cache-Control)."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    headers = _extract_headers(output)
    cache_info = []
    if 'cache-control' in headers:
        cc = headers['cache-control']
        if 'no-store' in cc:
            cache_info.append("Cache-Control: no-store (never cached)")
        elif 'no-cache' in cc:
            cache_info.append("Cache-Control: no-cache (must revalidate)")
        elif 'max-age=' in cc:
            m = re.search(r'max-age=(\d+)', cc)
            if m:
                seconds = int(m.group(1))
                cache_info.append(f"Cache-Control: max-age={seconds}s ({seconds//60}m)")
    if 'etag' in headers:
        cache_info.append(f"ETag: {headers['etag'][:50]}")
    if 'last-modified' in headers:
        cache_info.append(f"Last-Modified: {headers['last-modified']}")
    if 'age' in headers:
        cache_info.append(f"Age: {headers['age']}s (served from cache)")
    if 'x-cache' in headers:
        cache_info.append(f"X-Cache: {headers['x-cache']}")
    if cache_info:
        return post_tool_context("CACHE INFO: " + " | ".join(cache_info))
    return allow()


@registry.hook("api_detect_breaking_changes")
def api_detect_breaking_changes(data):
    """Detect breaking API changes from response format."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    body = _extract_json_body(output)
    if not isinstance(body, dict):
        return allow()
    # Detect common breaking change indicators
    indicators = []
    status = _extract_status_code(output)
    if status == 410:
        indicators.append("HTTP 410 Gone - this endpoint has been permanently removed")
    if status == 301 or status == 308:
        headers = _extract_headers(output)
        location = headers.get('location', '')
        indicators.append(f"Permanent redirect to: {location}")
    # Check for version mismatch messages
    version_warnings = [
        r'(?:api|endpoint)\s+(?:version\s+)?\S+\s+(?:is\s+)?deprecated',
        r'(?:this|endpoint)\s+(?:has been|is)\s+(?:removed|discontinued|sunset)',
        r'please\s+(?:use|upgrade|migrate)\s+(?:to\s+)?(?:v\d|version)',
    ]
    for p in version_warnings:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            indicators.append(m.group(0).strip())
    if indicators:
        return post_tool_context(
            "BREAKING API CHANGE:\n"
            + "\n".join(f"  - {i}" for i in indicators)
            + "\nUpdate your API integration to use the current version."
        )
    return allow()


@registry.hook("api_validate_error_format")
def api_validate_error_format(data):
    """Check error responses follow standard format (RFC 7807)."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    status = _extract_status_code(output)
    if status is None or status < 400:
        return allow()
    body = _extract_json_body(output)
    if not isinstance(body, dict):
        return allow()
    # Check RFC 7807 Problem Details fields
    rfc7807_fields = ['type', 'title', 'status', 'detail', 'instance']
    has_rfc7807 = sum(1 for f in rfc7807_fields if f in body)
    # Check common alternative formats
    has_common = any(f in body for f in ['error', 'message', 'code', 'errors'])
    if has_rfc7807 >= 3:
        return post_tool_context(
            "ERROR FORMAT: Response follows RFC 7807 (Problem Details). "
            f"Type: {body.get('type', 'N/A')} | Title: {body.get('title', 'N/A')} | "
            f"Detail: {str(body.get('detail', 'N/A'))[:100]}"
        )
    elif not has_common and not has_rfc7807:
        return post_tool_context(
            f"ERROR FORMAT: HTTP {status} error response lacks standard error fields. "
            "Consider using RFC 7807 Problem Details format with: type, title, status, detail, instance."
        )
    return allow()


@registry.hook("api_check_security_headers")
def api_check_security_headers(data):
    """Validate security headers in API responses."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    headers = _extract_headers(output)
    if not headers:
        return allow()
    missing = []
    for sh in SECURITY_HEADERS:
        if sh not in headers:
            missing.append(sh)
    # Only report if we have some headers (verbose mode was used) but security ones are missing
    if missing and len(headers) >= 3:
        present = [sh for sh in SECURITY_HEADERS if sh in headers]
        if len(missing) >= 4:
            return post_tool_context(
                f"SECURITY HEADERS: {len(missing)} security headers missing: {', '.join(missing[:5])}. "
                + (f"Present: {', '.join(present)}. " if present else "")
                + "Consider adding these headers to protect against common web vulnerabilities."
            )
    return allow()


@registry.hook("api_detect_data_leaks")
def api_detect_data_leaks(data):
    """Detect unexpected sensitive data in responses."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    body = _extract_json_body(output)
    if not isinstance(body, dict):
        return allow()
    sensitive_fields = {
        'password': 'password hash/value',
        'password_hash': 'password hash',
        'secret': 'secret value',
        'secret_key': 'secret key',
        'private_key': 'private key',
        'ssn': 'social security number',
        'social_security': 'social security number',
        'credit_card': 'credit card number',
        'card_number': 'card number',
        'cvv': 'CVV code',
        'bank_account': 'bank account number',
        'routing_number': 'routing number',
        'access_token': 'access token',
        'refresh_token': 'refresh token',
        'api_key': 'API key',
        'api_secret': 'API secret',
    }

    def _check_dict(d, path=""):
        found = []
        for key, value in d.items():
            full_path = f"{path}.{key}" if path else key
            key_lower = key.lower()
            if key_lower in sensitive_fields and value is not None and value != "" and value != "***":
                found.append(f"'{full_path}' contains {sensitive_fields[key_lower]}")
            if isinstance(value, dict):
                found.extend(_check_dict(value, full_path))
            elif isinstance(value, list):
                for i, item in enumerate(value[:3]):
                    if isinstance(item, dict):
                        found.extend(_check_dict(item, f"{full_path}[{i}]"))
        return found

    leaks = _check_dict(body)
    if leaks:
        return post_tool_context(
            "DATA LEAK WARNING: Sensitive fields found in API response:\n"
            + "\n".join(f"  - {l}" for l in leaks[:5])
            + "\nAPI responses should never expose passwords, tokens, or financial data. "
            "Ensure server-side serialization excludes sensitive fields."
        )
    return allow()


@registry.hook("api_validate_graphql")
def api_validate_graphql(data):
    """Parse GraphQL response errors."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    # Detect GraphQL context
    if not re.search(r'graphql|/gql\b', command + " " + output, re.IGNORECASE):
        return allow()
    body = _extract_json_body(output)
    if not isinstance(body, dict):
        return allow()
    errors = body.get('errors', [])
    if not isinstance(errors, list) or not errors:
        return allow()
    details = []
    for err in errors[:5]:
        if isinstance(err, dict):
            msg = err.get('message', 'Unknown error')
            locations = err.get('locations', [])
            path = err.get('path', [])
            extensions = err.get('extensions', {})
            loc_str = ""
            if locations:
                loc_str = f" at line {locations[0].get('line', '?')}:{locations[0].get('column', '?')}"
            path_str = f" (path: {'.'.join(str(p) for p in path)})" if path else ""
            code = extensions.get('code', '')
            code_str = f" [{code}]" if code else ""
            details.append(f"  - {msg}{code_str}{loc_str}{path_str}")
    return post_tool_context(
        f"GRAPHQL ERRORS: {len(errors)} error(s):\n"
        + "\n".join(details)
        + "\nCheck query syntax, field names, and variable types."
    )


@registry.hook("api_check_response_size")
def api_check_response_size(data):
    """Warn about unusually large API responses."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_api_response(command, output):
        return allow()
    headers = _extract_headers(output)
    content_length = headers.get('content-length', '')
    size_bytes = 0
    if content_length:
        try:
            size_bytes = int(content_length)
        except ValueError:
            pass
    else:
        # Estimate from output length
        size_bytes = len(output.encode('utf-8', errors='ignore'))
    if size_bytes > 10_000_000:  # 10MB
        size_mb = size_bytes / 1_000_000
        return post_tool_context(
            f"LARGE RESPONSE: {size_mb:.1f}MB response detected. "
            "Consider: (1) adding pagination, (2) requesting specific fields, "
            "(3) using compression (--compressed), (4) filtering server-side."
        )
    elif size_bytes > 1_000_000:  # 1MB
        size_mb = size_bytes / 1_000_000
        return post_tool_context(
            f"RESPONSE SIZE: {size_mb:.1f}MB - larger than typical. "
            "Consider pagination or field selection to reduce payload."
        )
    return allow()


if __name__ == "__main__":
    registry.main()
