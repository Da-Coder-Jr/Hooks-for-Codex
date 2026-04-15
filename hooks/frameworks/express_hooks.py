#!/usr/bin/env python3
"""Express.js development hooks for parsing errors and detecting common issues."""
import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()


@registry.hook("express_detect_middleware_errors")
def express_detect_middleware_errors(data):
    """Parse Express middleware chain errors."""
    output = get_command_output(data)
    patterns = [
        (r"Error:.*(?:requires|is not a) middleware", "Invalid middleware"),
        (r"TypeError:.*(?:app\.use|router\.use).*requires a middleware function", "Non-function passed to app.use"),
        (r"Error:.*next\(\) called.*after.*response", "next() called after response sent"),
        (r"Error:.*Cannot set headers after they are sent", "Headers already sent"),
        (r"TypeError:.*is not a function.*middleware", "Middleware is not a function"),
        (r"Error:.*Route\.(?:get|post|put|delete|patch)\(\) requires a callback function", "Route missing callback"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "EXPRESS MIDDLEWARE ERROR: " + "; ".join(issues) + ". "
            "Check: (1) middleware functions have (req, res, next) signature, "
            "(2) middleware order in app.use() calls, "
            "(3) always call next() or send a response (not both), "
            "(4) error-handling middleware has (err, req, res, next) signature."
        )
    return allow()


@registry.hook("express_check_error_handling")
def express_check_error_handling(data):
    """Detect missing error handling middleware in Express output."""
    output = get_command_output(data)
    patterns = [
        r"UnhandledPromiseRejectionWarning",
        r"unhandledRejection",
        r"Error.*not caught.*middleware",
        r"TypeError:.*Cannot read propert.*of (?:undefined|null)",
        r"ReferenceError:.*is not defined",
    ]
    # Check if error appears without structured error response
    has_unhandled = False
    for p in patterns:
        if re.search(p, output, re.IGNORECASE):
            has_unhandled = True
            break
    # Check for Express default HTML error page (indicates no custom error handler)
    if re.search(r"<!DOCTYPE html>.*<pre>.*Error:.*at\s+\w+", output, re.DOTALL):
        has_unhandled = True
    if has_unhandled:
        return post_tool_context(
            "EXPRESS ERROR HANDLING: Unhandled error detected. "
            "Add error-handling middleware at the END of your middleware stack: "
            "app.use((err, req, res, next) => { console.error(err.stack); "
            "res.status(500).json({ error: 'Internal Server Error' }); }); "
            "For async routes, wrap handlers with: "
            "const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);"
        )
    return allow()


@registry.hook("express_detect_route_conflicts")
def express_detect_route_conflicts(data):
    """Parse route conflict warnings and issues."""
    output = get_command_output(data)
    patterns = [
        (r"(?:Error|Warning):.*route.*conflict", "Route conflict"),
        (r"Cannot (?:GET|POST|PUT|DELETE|PATCH) (/\S*)", "Route not found"),
        (r"404.*Not Found.*(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+)", "404 - route not matched"),
    ]
    issues = []
    missing_routes = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            path = m.group(1) if m.lastindex else ""
            if "not found" in desc.lower() or "not matched" in desc.lower():
                missing_routes.append(path)
            else:
                issues.append(desc)
    if missing_routes:
        issues.append(f"Routes not found: {', '.join(missing_routes[:5])}")
    if issues:
        return post_tool_context(
            "EXPRESS ROUTING: " + "; ".join(issues) + ". "
            "Check: (1) route order matters - specific routes before parameterized ones, "
            "(2) HTTP method matches (GET vs POST), "
            "(3) router is mounted with correct prefix in app.use(), "
            "(4) route paths match exactly (case-sensitive by default)."
        )
    return allow()


@registry.hook("express_check_cors_config")
def express_check_cors_config(data):
    """Validate CORS middleware configuration from output."""
    output = get_command_output(data)
    patterns = [
        (r"Access-Control-Allow-Origin.*\*", "CORS allows all origins (*)"),
        (r"blocked by CORS policy", "Request blocked by CORS"),
        (r"No 'Access-Control-Allow-Origin' header", "Missing CORS headers"),
        (r"CORS.*preflight.*(?:failed|error)", "CORS preflight failed"),
        (r"credentials.*mode.*include.*wildcard.*origin", "Credentials with wildcard origin"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        cors_all = any("all origins" in i for i in issues)
        return post_tool_context(
            "EXPRESS CORS: " + "; ".join(issues) + ". "
            + ("WARNING: origin: '*' is insecure for production. " if cors_all else "") +
            "Configure CORS properly: "
            "const cors = require('cors'); "
            "app.use(cors({ origin: ['https://your-domain.com'], credentials: true })); "
            "For preflight, ensure OPTIONS requests are handled."
        )
    return allow()


@registry.hook("express_detect_body_parser_issues")
def express_detect_body_parser_issues(data):
    """Parse body-parser/express.json errors."""
    output = get_command_output(data)
    patterns = [
        (r"SyntaxError:.*(?:Unexpected token|JSON).*body", "Invalid JSON in request body"),
        (r"PayloadTooLargeError", "Request payload too large"),
        (r"entity\.too\.large", "Request entity too large"),
        (r"req\.body is undefined", "Body parser not configured"),
        (r"UnsupportedMediaType", "Unsupported content type"),
        (r"encoding.*not supported", "Unsupported encoding"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "EXPRESS BODY PARSER: " + "; ".join(issues) + ". "
            "Ensure body parsers are configured BEFORE routes: "
            "app.use(express.json({ limit: '10mb' })); "
            "app.use(express.urlencoded({ extended: true })); "
            "For file uploads, use multer. Check Content-Type header matches parser."
        )
    return allow()


@registry.hook("express_check_security_headers")
def express_check_security_headers(data):
    """Warn about missing helmet/security middleware."""
    output = get_command_output(data)
    command = get_command(data)
    # Detect if security scan or headers check was run
    security_issues = []
    header_checks = [
        (r"X-Powered-By:\s*Express", "X-Powered-By header exposes Express"),
        (r"(?:missing|no)\s+(?:Content-Security-Policy|CSP)", "Missing Content-Security-Policy"),
        (r"(?:missing|no)\s+X-Content-Type-Options", "Missing X-Content-Type-Options"),
        (r"(?:missing|no)\s+X-Frame-Options", "Missing X-Frame-Options"),
        (r"(?:missing|no)\s+Strict-Transport-Security", "Missing HSTS header"),
        (r"(?:missing|no)\s+X-XSS-Protection", "Missing X-XSS-Protection"),
    ]
    for p, desc in header_checks:
        if re.search(p, output, re.IGNORECASE):
            security_issues.append(desc)
    # Check if Express is exposing powered-by
    if re.search(r"x-powered-by", output, re.IGNORECASE) and not security_issues:
        security_issues.append("X-Powered-By header is visible")
    if security_issues:
        return post_tool_context(
            f"EXPRESS SECURITY: {len(security_issues)} security header issue(s):\n"
            + "\n".join(f"  - {i}" for i in security_issues) +
            "\nInstall helmet: npm install helmet && app.use(helmet()); "
            "Also: app.disable('x-powered-by'); "
            "Helmet sets secure headers by default."
        )
    return allow()


@registry.hook("express_detect_port_conflicts")
def express_detect_port_conflicts(data):
    """Parse EADDRINUSE port conflict errors."""
    output = get_command_output(data)
    m = re.search(r"(?:EADDRINUSE|address already in use).*?(?:::)?(\d+)", output, re.IGNORECASE)
    if m:
        port = m.group(1)
        return post_tool_context(
            f"EXPRESS PORT CONFLICT: Port {port} is already in use. "
            f"Fix: (1) Find the process: lsof -i :{port} or netstat -tlnp | grep {port}, "
            f"(2) Kill it: kill -9 <PID>, "
            "(3) Or use a different port: PORT=3001 node app.js, "
            "(4) Or set port via environment: process.env.PORT || 3000."
        )
    return allow()


@registry.hook("express_check_rate_limiting")
def express_check_rate_limiting(data):
    """Warn about missing rate limiting from test/scan output."""
    output = get_command_output(data)
    patterns = [
        r"(?:rate.?limit|throttl).*(?:missing|not configured|absent)",
        r"Too Many Requests.*429",
        r"express-rate-limit.*error",
        r"DDoS.*(?:detected|warning)",
    ]
    for p in patterns:
        if re.search(p, output, re.IGNORECASE):
            return post_tool_context(
                "EXPRESS RATE LIMITING: Rate limiting issue detected. "
                "Add rate limiting middleware: "
                "const rateLimit = require('express-rate-limit'); "
                "app.use(rateLimit({ windowMs: 15*60*1000, max: 100, "
                "standardHeaders: true, legacyHeaders: false })); "
                "Apply stricter limits to auth endpoints. "
                "Consider using Redis store for distributed deployments."
            )
    return allow()


@registry.hook("express_detect_memory_issues")
def express_detect_memory_issues(data):
    """Parse Express memory leak warnings."""
    output = get_command_output(data)
    patterns = [
        (r"FATAL ERROR:.*(?:heap|memory|allocation)", "Fatal heap error"),
        (r"JavaScript heap out of memory", "Heap out of memory"),
        (r"MaxListenersExceededWarning.*?(\d+)\s+(\w+)\s+listeners", "Too many event listeners"),
        (r"Possible memory leak detected", "Memory leak detected"),
        (r"warning.*--max-old-space-size", "Memory limit warning"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            issues.append(desc)
    if issues:
        return post_tool_context(
            "EXPRESS MEMORY: " + "; ".join(issues) + ". "
            "Fix: (1) Check for event listener leaks (remove listeners on cleanup), "
            "(2) Avoid storing large data in closures or global scope, "
            "(3) Stream large responses instead of buffering, "
            "(4) Increase memory: node --max-old-space-size=4096, "
            "(5) Use 'clinic doctor' or 'node --inspect' to profile memory."
        )
    return allow()


@registry.hook("express_check_session_config")
def express_check_session_config(data):
    """Validate Express session configuration security."""
    output = get_command_output(data)
    patterns = [
        (r"(?:Warning|Error):.*session.*secret.*(?:default|weak|missing)", "Weak/default session secret"),
        (r"MemoryStore.*not.*production", "MemoryStore used (not for production)"),
        (r"express-session.*deprecated.*default.*MemoryStore", "Using deprecated default MemoryStore"),
        (r"cookie.*secure.*false.*(?:https|production)", "Session cookie not secure"),
        (r"Session.*(?:expired|timeout|invalid)", "Session expired or invalid"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "EXPRESS SESSION: " + "; ".join(issues) + ". "
            "Use a production session store: "
            "const session = require('express-session'); "
            "const RedisStore = require('connect-redis').default; "
            "app.use(session({ store: new RedisStore({ client: redisClient }), "
            "secret: process.env.SESSION_SECRET, resave: false, "
            "saveUninitialized: false, cookie: { secure: true, httpOnly: true, "
            "sameSite: 'strict', maxAge: 24*60*60*1000 } }));"
        )
    return allow()


@registry.hook("express_detect_template_errors")
def express_detect_template_errors(data):
    """Parse template engine (EJS, Pug, Handlebars) errors."""
    output = get_command_output(data)
    patterns = [
        (r"(?:EJS|ejs).*(?:Error|error):\s*(.+?)(?:\n|$)", "EJS error"),
        (r"(?:Pug|pug|Jade).*(?:Error|error):\s*(.+?)(?:\n|$)", "Pug error"),
        (r"(?:Handlebars|hbs).*(?:Error|error):\s*(.+?)(?:\n|$)", "Handlebars error"),
        (r"Error:.*Failed to lookup view\s+['\"](.+?)['\"]", "View not found"),
        (r"Error:.*No default engine was specified", "No template engine set"),
        (r"ENOENT.*views", "View file not found"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{desc}: {detail}" if detail else desc)
    if issues:
        return post_tool_context(
            "EXPRESS TEMPLATE: " + "; ".join(issues) + ". "
            "Check: (1) app.set('view engine', 'ejs/pug/hbs'), "
            "(2) app.set('views', path.join(__dirname, 'views')), "
            "(3) template file exists with correct extension, "
            "(4) template syntax is valid for the engine."
        )
    return allow()


@registry.hook("express_check_static_serving")
def express_check_static_serving(data):
    """Warn about serving static files from root or insecure paths."""
    output = get_command_output(data)
    command = get_command(data)
    issues = []
    # Check for common misconfigurations in output
    if re.search(r"express\.static\s*\(\s*['\"]\.?/?['\"]", output):
        issues.append("Serving static files from root directory exposes all files")
    if re.search(r"express\.static.*\.\./", output):
        issues.append("Path traversal risk with ../ in static path")
    if re.search(r"dotfiles.*allow", output, re.IGNORECASE):
        issues.append("dotfiles are accessible (should be 'deny' or 'ignore')")
    if re.search(r"ENOENT.*(?:public|static|assets|dist)", output):
        issues.append("Static directory not found")
    if issues:
        return post_tool_context(
            "EXPRESS STATIC FILES: " + "; ".join(issues) + ". "
            "Serve static files from a specific directory: "
            "app.use('/static', express.static(path.join(__dirname, 'public'), "
            "{ dotfiles: 'deny', maxAge: '1d', etag: true })); "
            "Never serve from root. Consider using a CDN or nginx for production."
        )
    return allow()


@registry.hook("express_detect_socket_issues")
def express_detect_socket_issues(data):
    """Parse WebSocket/Socket.io errors."""
    output = get_command_output(data)
    patterns = [
        (r"(?:WebSocket|ws|socket\.io).*(?:Error|error):\s*(.+?)(?:\n|$)", "WebSocket error"),
        (r"(?:ECONNREFUSED|ECONNRESET).*(?:ws|socket)", "WebSocket connection refused/reset"),
        (r"WebSocket is (?:not open|already in CLOSING|CLOSED)", "WebSocket not in OPEN state"),
        (r"Invalid WebSocket frame", "Invalid WebSocket frame"),
        (r"socket\.io.*(?:timeout|disconnect).*(?:transport|polling)", "Socket.io transport error"),
        (r"socket hang up", "Socket hang up"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{desc}: {detail}" if detail else desc)
    if issues:
        return post_tool_context(
            "EXPRESS WEBSOCKET: " + "; ".join(issues) + ". "
            "Check: (1) WebSocket server is initialized with HTTP server, "
            "(2) CORS is configured for WebSocket connections, "
            "(3) proxy settings support WebSocket upgrade (nginx: proxy_set_header Upgrade), "
            "(4) client reconnection logic is implemented, "
            "(5) heartbeat/ping-pong is configured for connection health."
        )
    return allow()


@registry.hook("express_check_ssl_config")
def express_check_ssl_config(data):
    """Validate HTTPS/TLS configuration."""
    output = get_command_output(data)
    patterns = [
        (r"ERR_SSL_PROTOCOL_ERROR", "SSL protocol error"),
        (r"UNABLE_TO_VERIFY_LEAF_SIGNATURE", "SSL certificate verification failed"),
        (r"CERT_HAS_EXPIRED", "SSL certificate expired"),
        (r"DEPTH_ZERO_SELF_SIGNED_CERT", "Self-signed certificate"),
        (r"ERR_TLS_CERT_ALTNAME_INVALID", "Certificate hostname mismatch"),
        (r"EPROTO.*SSL", "SSL/TLS protocol error"),
        (r"NODE_TLS_REJECT_UNAUTHORIZED.*0", "TLS verification disabled (insecure)"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "EXPRESS SSL/TLS: " + "; ".join(issues) + ". "
            "Check: (1) certificate files exist and are valid, "
            "(2) certificate chain is complete (include CA bundle), "
            "(3) certificate hostname matches domain, "
            "(4) NEVER set NODE_TLS_REJECT_UNAUTHORIZED=0 in production, "
            "(5) use Let's Encrypt for free certificates, "
            "(6) consider terminating SSL at reverse proxy (nginx)."
        )
    return allow()


@registry.hook("express_detect_graceful_shutdown")
def express_detect_graceful_shutdown(data):
    """Warn about missing graceful shutdown handling."""
    output = get_command_output(data)
    patterns = [
        r"(?:SIGTERM|SIGINT).*(?:unhandled|not handled)",
        r"server.*(?:force|abrupt).*(?:shutdown|close|kill)",
        r"connection.*(?:reset|dropped).*(?:shutdown|close)",
        r"Error:.*(?:ECONNRESET|EPIPE).*(?:shutdown|close)",
    ]
    for p in patterns:
        if re.search(p, output, re.IGNORECASE):
            return post_tool_context(
                "EXPRESS GRACEFUL SHUTDOWN: Missing or broken graceful shutdown handling. "
                "Implement: process.on('SIGTERM', () => { "
                "server.close(() => { /* close DB, Redis, etc. */ process.exit(0); }); "
                "setTimeout(() => process.exit(1), 10000); }); "
                "This ensures in-flight requests complete before shutdown, "
                "preventing connection resets in production deployments."
            )
    return allow()


if __name__ == "__main__":
    registry.main()
