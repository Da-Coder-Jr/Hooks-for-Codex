#!/usr/bin/env python3
"""Flask development hooks for parsing errors and detecting common issues."""
import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()


@registry.hook("flask_detect_debug_mode")
def flask_detect_debug_mode(data):
    """Warn about debug mode in production contexts."""
    output = get_command_output(data)
    command = get_command(data)
    issues = []
    # Check for debug mode indicators
    if re.search(r"Debugger is active!", output):
        issues.append("Flask debugger is active")
    if re.search(r"FLASK_DEBUG\s*=\s*1", output):
        issues.append("FLASK_DEBUG=1 is set")
    if re.search(r"Debug mode:\s*on", output):
        issues.append("Debug mode is on")
    if re.search(r"app\.run\(.*debug\s*=\s*True", output):
        issues.append("app.run(debug=True) detected in source")
    # Check if running in what looks like a production context
    prod_indicators = re.search(r"(?:production|prod|deploy|gunicorn|uwsgi)", output + command, re.IGNORECASE)
    if issues and prod_indicators:
        return post_tool_context(
            "FLASK SECURITY: " + "; ".join(issues) + " in production context. "
            "NEVER run debug mode in production - it exposes an interactive debugger "
            "that allows arbitrary code execution. "
            "Use: FLASK_DEBUG=0, remove debug=True from app.run(), "
            "and use a proper WSGI server (gunicorn, uwsgi) instead."
        )
    elif issues:
        return post_tool_context(
            "FLASK DEBUG: " + "; ".join(issues) + ". "
            "Debug mode is fine for development but ensure it is disabled in production. "
            "Set FLASK_DEBUG=0 and use a WSGI server for deployment."
        )
    return allow()


@registry.hook("flask_check_secret_key")
def flask_check_secret_key(data):
    """Detect hardcoded or weak secret keys."""
    output = get_command_output(data)
    patterns = [
        (r"SECRET_KEY\s*=\s*['\"](?:secret|password|changeme|dev|test|key|default|123|abc)['\"]",
         "Hardcoded weak SECRET_KEY"),
        (r"SECRET_KEY\s*=\s*['\"](.{1,15})['\"]", "SECRET_KEY too short (< 16 chars)"),
        (r"app\.secret_key\s*=\s*['\"](?:secret|password|changeme|dev|test|key|default)['\"]",
         "Hardcoded weak app.secret_key"),
        (r"RuntimeError:.*(?:secret.?key|SECRET_KEY).*(?:not set|missing)", "SECRET_KEY not set"),
        (r"The session is unavailable.*secret key", "Session unavailable - no secret key"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "FLASK SECRET KEY: " + "; ".join(issues) + ". "
            "Generate a strong secret key: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "Store it in an environment variable: "
            "app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32). "
            "Never commit secret keys to version control."
        )
    return allow()


@registry.hook("flask_detect_import_errors")
def flask_detect_import_errors(data):
    """Parse Flask import and circular import errors."""
    output = get_command_output(data)
    patterns = [
        (r"ImportError:.*cannot import name\s+['\"](\w+)['\"].*from\s+['\"](\S+)['\"]",
         "Circular import"),
        (r"ModuleNotFoundError:.*No module named\s+['\"](\S+)['\"]",
         "Module not found"),
        (r"ImportError:.*(?:flask|werkzeug).*?(\S+)", "Flask import error"),
        (r"AttributeError:.*partially initialized module.*circular import",
         "Circular import detected"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1) if m.lastindex else ""
            issues.append(f"{desc}: {detail}" if detail else desc)
    if issues:
        return post_tool_context(
            "FLASK IMPORT ERROR: " + "; ".join(issues) + ". "
            "For circular imports: (1) Use the Flask application factory pattern, "
            "(2) Move imports inside functions (lazy imports), "
            "(3) Use flask.current_app instead of importing app directly, "
            "(4) Structure: app/__init__.py creates app, models.py and routes.py import from __init__."
        )
    return allow()


@registry.hook("flask_check_blueprint_issues")
def flask_check_blueprint_issues(data):
    """Parse blueprint registration errors."""
    output = get_command_output(data)
    patterns = [
        (r"(?:AssertionError|ValueError):.*(?:blueprint|Blueprint).*(?:already registered|name conflict)",
         "Blueprint name conflict"),
        (r"AttributeError:.*Blueprint.*has no attribute\s+['\"](\w+)['\"]",
         "Blueprint missing attribute"),
        (r"(?:Error|error):.*register_blueprint.*?(\S+)", "Blueprint registration error"),
        (r"BuildError:.*Could not build url for endpoint\s+['\"](\S+)['\"]",
         "Invalid endpoint in blueprint"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1) if m.lastindex else ""
            issues.append(f"{desc}: {detail}" if detail else desc)
    if issues:
        return post_tool_context(
            "FLASK BLUEPRINT: " + "; ".join(issues) + ". "
            "Check: (1) Each blueprint has a unique name, "
            "(2) url_prefix is set when registering: app.register_blueprint(bp, url_prefix='/api'), "
            "(3) Endpoints use blueprint name: url_for('blueprint_name.view_func'), "
            "(4) Blueprint template/static folders are configured correctly."
        )
    return allow()


@registry.hook("flask_detect_template_errors")
def flask_detect_template_errors(data):
    """Parse Jinja2 template errors."""
    output = get_command_output(data)
    patterns = [
        (r"jinja2\.exceptions\.TemplateNotFound:\s*(\S+)", "Template not found"),
        (r"jinja2\.exceptions\.TemplateSyntaxError:\s*(.+?)(?:\n|$)", "Template syntax error"),
        (r"jinja2\.exceptions\.UndefinedError:\s*['\"](\w+)['\"].*is undefined", "Undefined variable"),
        (r"jinja2\.exceptions\.TemplateAssertionError:\s*(.+?)(?:\n|$)", "Template assertion error"),
        (r"TypeError:.*(?:render_template|render_string).*?(\S+)", "Render error"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip()
            issues.append(f"{desc}: {detail}")
    if issues:
        return post_tool_context(
            "FLASK TEMPLATE ERROR: " + "; ".join(issues) + ". "
            "Check: (1) Templates are in the 'templates/' directory, "
            "(2) Template name in render_template() matches the file, "
            "(3) Variables passed to template match those used in {{ }}, "
            "(4) Jinja2 syntax: {% for %}, {% if %}, {{ variable }}, {# comment #}."
        )
    return allow()


@registry.hook("flask_check_sqlalchemy_issues")
def flask_check_sqlalchemy_issues(data):
    """Parse SQLAlchemy connection and query errors."""
    output = get_command_output(data)
    patterns = [
        (r"sqlalchemy\.exc\.OperationalError:\s*(.+?)(?:\n|$)", "OperationalError"),
        (r"sqlalchemy\.exc\.IntegrityError:\s*(.+?)(?:\n|$)", "IntegrityError"),
        (r"sqlalchemy\.exc\.ProgrammingError:\s*(.+?)(?:\n|$)", "ProgrammingError"),
        (r"sqlalchemy\.exc\.DisconnectionError", "Database disconnected"),
        (r"sqlalchemy\.exc\.TimeoutError", "Connection pool timeout"),
        (r"(?:detached|expired).*instance", "Detached/expired SQLAlchemy instance"),
        (r"InvalidRequestError:.*(?:Session|session).*(?:closed|committed|rolled back)",
         "Invalid session state"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{desc}: {detail}" if detail else desc)
    if issues:
        return post_tool_context(
            "FLASK SQLALCHEMY: " + "; ".join(issues) + ". "
            "Check: (1) SQLALCHEMY_DATABASE_URI is correct, "
            "(2) db.create_all() was called or migrations applied, "
            "(3) Use db.session.commit() and handle db.session.rollback() on error, "
            "(4) For pool timeout: increase SQLALCHEMY_POOL_SIZE or SQLALCHEMY_POOL_TIMEOUT, "
            "(5) Use db.session.close() or @app.teardown_appcontext."
        )
    return allow()


@registry.hook("flask_detect_context_errors")
def flask_detect_context_errors(data):
    """Parse 'Working outside of application context' and request context errors."""
    output = get_command_output(data)
    patterns = [
        (r"RuntimeError:.*Working outside of application context", "Outside application context"),
        (r"RuntimeError:.*Working outside of request context", "Outside request context"),
        (r"RuntimeError:.*Attempted to generate a URL without.*request context",
         "URL generation without request context"),
        (r"RuntimeError:.*(?:push|pop).*(?:app|request).*context", "Context push/pop error"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "FLASK CONTEXT ERROR: " + "; ".join(issues) + ". "
            "Fix by wrapping code in the appropriate context: "
            "App context: with app.app_context(): ... "
            "Request context: with app.test_request_context(): ... "
            "In CLI commands, use @app.cli.command(). "
            "In Celery tasks, use: with app.app_context(): ... "
            "Use flask.current_app and flask.g within app context."
        )
    return allow()


@registry.hook("flask_check_csrf_protection")
def flask_check_csrf_protection(data):
    """Warn about missing CSRF protection."""
    output = get_command_output(data)
    patterns = [
        (r"The CSRF (?:token|session token) is missing", "CSRF token missing"),
        (r"The CSRF token has expired", "CSRF token expired"),
        (r"CSRF validation failed", "CSRF validation failed"),
        (r"CSRFError", "CSRF error"),
        (r"WTF_CSRF_ENABLED\s*=\s*False", "CSRF protection disabled"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "FLASK CSRF: " + "; ".join(issues) + ". "
            "Ensure CSRF protection: (1) Initialize CSRFProtect(app), "
            "(2) Include {{ form.hidden_tag() }} or {{ csrf_token() }} in forms, "
            "(3) For AJAX: include X-CSRFToken header from meta tag, "
            "(4) Set WTF_CSRF_TIME_LIMIT for token expiry (default 3600s), "
            "(5) Never disable CSRF in production."
        )
    return allow()


@registry.hook("flask_detect_migration_issues")
def flask_detect_migration_issues(data):
    """Parse Flask-Migrate/Alembic errors."""
    output = get_command_output(data)
    patterns = [
        (r"alembic\.util\.exc\.CommandError:\s*(.+?)(?:\n|$)", "Alembic command error"),
        (r"Target database is not up to date", "Database not up to date"),
        (r"Can't locate revision identified by\s+['\"](\w+)['\"]", "Missing migration revision"),
        (r"(?:Multiple|Duplicate)\s+head revisions", "Multiple head revisions"),
        (r"(?:ERROR|Error).*?(?:flask db|alembic).*?(\S+)", "Migration error"),
        (r"FAILED.*?(?:upgrade|downgrade|migrate|revision)", "Migration command failed"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{desc}: {detail}" if detail else desc)
    if issues:
        return post_tool_context(
            "FLASK MIGRATION: " + "; ".join(issues) + ". "
            "Try: (1) 'flask db current' to see current revision, "
            "(2) 'flask db heads' to see head revisions, "
            "(3) 'flask db merge heads' for multiple heads, "
            "(4) 'flask db stamp head' to mark current as up to date, "
            "(5) 'flask db history' to see migration chain."
        )
    return allow()


@registry.hook("flask_check_cors_config")
def flask_check_cors_config(data):
    """Validate Flask-CORS configuration."""
    output = get_command_output(data)
    patterns = [
        (r"Access-Control-Allow-Origin.*\*", "CORS allows all origins"),
        (r"blocked by CORS policy", "CORS blocking request"),
        (r"No 'Access-Control-Allow-Origin' header", "Missing CORS headers"),
        (r"flask.cors.*error", "Flask-CORS error"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "FLASK CORS: " + "; ".join(issues) + ". "
            "Configure Flask-CORS: "
            "from flask_cors import CORS; "
            "CORS(app, resources={r'/api/*': {'origins': ['https://your-domain.com']}}, "
            "supports_credentials=True); "
            "Avoid origins='*' in production. "
            "For specific blueprints: CORS(blueprint, origins=[...])."
        )
    return allow()


@registry.hook("flask_detect_celery_issues")
def flask_detect_celery_issues(data):
    """Parse Celery integration errors with Flask."""
    output = get_command_output(data)
    patterns = [
        (r"RuntimeError:.*Working outside of application context.*celery",
         "Celery task missing app context"),
        (r"kombu\.exceptions\.OperationalError:\s*(.+?)(?:\n|$)",
         "Broker connection error"),
        (r"Received unregistered task.*?['\"](.+?)['\"]", "Unregistered task"),
        (r"celery.*?(?:Error|error):.*?import.*?(\S+)", "Celery import error"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{desc}: {detail}" if detail else desc)
    if issues:
        return post_tool_context(
            "FLASK CELERY: " + "; ".join(issues) + ". "
            "Ensure Celery tasks have app context: "
            "celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL']); "
            "celery.conf.update(app.config); "
            "class ContextTask(celery.Task): "
            "  def __call__(self, *args, **kwargs): "
            "    with app.app_context(): return self.run(*args, **kwargs); "
            "celery.Task = ContextTask;"
        )
    return allow()


@registry.hook("flask_check_wsgi_config")
def flask_check_wsgi_config(data):
    """Parse Gunicorn/uWSGI configuration issues."""
    output = get_command_output(data)
    patterns = [
        (r"gunicorn.*\[ERROR\]\s*(.+?)(?:\n|$)", "Gunicorn error"),
        (r"uwsgi.*(?:Error|error):\s*(.+?)(?:\n|$)", "uWSGI error"),
        (r"Worker.*?boot.*?timeout", "Worker boot timeout"),
        (r"\[CRITICAL\].*WORKER.*(?:TIMEOUT|timeout)", "Worker timeout"),
        (r"Address already in use", "Port already in use"),
        (r"(?:gunicorn|uwsgi).*?(?:ModuleNotFoundError|ImportError).*?(\S+)", "Import error"),
        (r"Application.*?not.*?(?:found|callable|loaded)", "Application not found"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{desc}: {detail}" if detail else desc)
    if issues:
        return post_tool_context(
            "FLASK WSGI: " + "; ".join(issues) + ". "
            "Check: (1) gunicorn command: gunicorn 'app:create_app()' or gunicorn app:app, "
            "(2) worker timeout: gunicorn --timeout 120, "
            "(3) number of workers: gunicorn -w 4, "
            "(4) port: gunicorn -b 0.0.0.0:8000, "
            "(5) ensure the application factory or app object is importable."
        )
    return allow()


@registry.hook("flask_detect_api_errors")
def flask_detect_api_errors(data):
    """Parse Flask-RESTful and marshmallow validation errors."""
    output = get_command_output(data)
    patterns = [
        (r"marshmallow\.exceptions\.ValidationError:\s*(.+?)(?:\n|$)", "Marshmallow validation error"),
        (r"flask_restful.*(?:Error|error):\s*(.+?)(?:\n|$)", "Flask-RESTful error"),
        (r'"errors":\s*\{(.+?)\}', "API validation errors"),
        (r"(?:400|422).*(?:Bad Request|Unprocessable).*?(?:message|error).*?['\"](.+?)['\"]",
         "Request validation failed"),
        (r"MethodNotAllowed.*?(\w+)", "Method not allowed"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{desc}: {detail}" if detail else desc)
    if issues:
        return post_tool_context(
            "FLASK API ERROR: " + "; ".join(issues) + ". "
            "Check: (1) Marshmallow schema field types match input data, "
            "(2) Required fields are provided in request, "
            "(3) Request Content-Type is application/json for JSON APIs, "
            "(4) API resource methods match HTTP methods (get, post, put, delete)."
        )
    return allow()


@registry.hook("flask_check_logging_config")
def flask_check_logging_config(data):
    """Validate logging configuration issues."""
    output = get_command_output(data)
    patterns = [
        (r"No handlers could be found for logger", "No logging handlers configured"),
        (r"FileNotFoundError.*\.log", "Log file path not found"),
        (r"PermissionError.*\.log", "Log file permission denied"),
        (r"WARNING:flask\.app", "Using default Flask logger (consider configuring)"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "FLASK LOGGING: " + "; ".join(issues) + ". "
            "Configure logging: "
            "import logging; "
            "handler = logging.StreamHandler(); "
            "handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s %(name)s: %(message)s')); "
            "app.logger.addHandler(handler); "
            "app.logger.setLevel(logging.INFO); "
            "Or use dictConfig for more complex setups. "
            "In production, log to files with RotatingFileHandler."
        )
    return allow()


@registry.hook("flask_detect_deprecation")
def flask_detect_deprecation(data):
    """Parse Flask deprecation warnings."""
    output = get_command_output(data)
    patterns = [
        (r"DeprecationWarning:.*(?:flask|werkzeug|jinja2).*?(.+?)(?:\n|$)", "Flask/Werkzeug deprecation"),
        (r"(?:flask|werkzeug).*deprecated.*?['\"](\w+)['\"]", "Deprecated API"),
        (r"before_first_request.*deprecated", "before_first_request is deprecated"),
        (r"json\.dumps.*deprecated.*app\.json", "JSON handling changed"),
    ]
    issues = []
    for p, desc in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{desc}: {detail}" if detail else desc)
    if issues:
        return post_tool_context(
            f"FLASK DEPRECATION: {len(issues)} warning(s):\n"
            + "\n".join(f"  - {i}" for i in issues[:8]) +
            "\nUpdate to current Flask APIs. "
            "Key Flask 2.3+ changes: before_first_request removed, "
            "use app.json instead of json module, "
            "use app.json.dumps/loads instead of flask.json.dumps/loads."
        )
    return allow()


if __name__ == "__main__":
    registry.main()
