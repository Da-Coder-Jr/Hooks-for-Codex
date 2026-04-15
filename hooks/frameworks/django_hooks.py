#!/usr/bin/env python3
"""Django development hooks for parsing errors and detecting common issues."""
import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()


@registry.hook("django_detect_migration_issues")
def django_detect_migration_issues(data):
    """Parse Django migration errors and conflicts."""
    output = get_command_output(data)
    patterns = [
        (r"django\.db\.migrations\.exceptions\.InconsistentMigrationHistory", "Inconsistent migration history"),
        (r"Conflicting migrations detected.*\n.*(\w+/\d+_\w+)", "Conflicting migrations"),
        (r"django\.db\.utils\.OperationalError:.*no such (?:table|column)", "Missing table/column - need migration"),
        (r"(?:apply|fake|squash).*migration.*error", "Migration apply error"),
        (r"django\.db\.migrations\.exceptions\.NodeNotFoundError:.*Migration (\S+)", "Missing migration dependency"),
        (r"Running migrations:\s*No migrations to apply", None),
        (r"table.*already exists", "Table already exists - consider fake migration"),
        (r"CircularDependencyError", "Circular migration dependency"),
    ]
    issues = []
    for p, desc in patterns:
        if desc and re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "DJANGO MIGRATION ERROR: " + "; ".join(issues) + ". "
            "Try: (1) 'python manage.py showmigrations' to see status, "
            "(2) 'python manage.py makemigrations --merge' for conflicts, "
            "(3) 'python manage.py migrate --fake <app> <migration>' for inconsistent history, "
            "(4) Check migration dependencies in the migration files."
        )
    return allow()


@registry.hook("django_check_security_settings")
def django_check_security_settings(data):
    """Warn about insecure Django settings in output."""
    output = get_command_output(data)
    command = get_command(data)
    issues = []
    # Check manage.py check --deploy output
    security_checks = [
        (r"DEBUG\s*=\s*True", "DEBUG=True should not be used in production"),
        (r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]?\*['\"]?\s*\]", "ALLOWED_HOSTS=['*'] is insecure"),
        (r"SECRET_KEY.*(?:insecure|default|changeme|secret|xxx)", "Insecure SECRET_KEY detected"),
        (r"SECURE_SSL_REDIRECT.*False", "SECURE_SSL_REDIRECT is False"),
        (r"SESSION_COOKIE_SECURE.*False", "SESSION_COOKIE_SECURE is False"),
        (r"CSRF_COOKIE_SECURE.*False", "CSRF_COOKIE_SECURE is False"),
        (r"SECURE_HSTS_SECONDS.*(?:0|None)", "HSTS not configured"),
        (r"security\.W00[4-9]|security\.W01[0-9]|security\.W020|security\.W021", "Django security check warnings"),
    ]
    for p, desc in security_checks:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            f"DJANGO SECURITY: {len(issues)} security issue(s) detected:\n"
            + "\n".join(f"  - {i}" for i in issues) +
            "\nRun 'python manage.py check --deploy' for a full security audit. "
            "These settings are critical for production deployments."
        )
    return allow()


@registry.hook("django_detect_orm_issues")
def django_detect_orm_issues(data):
    """Parse Django ORM errors from output."""
    output = get_command_output(data)
    orm_errors = [
        (r"django\.db\.utils\.IntegrityError:\s*(.+?)(?:\n|$)", "IntegrityError"),
        (r"django\.db\.utils\.OperationalError:\s*(.+?)(?:\n|$)", "OperationalError"),
        (r"django\.db\.utils\.ProgrammingError:\s*(.+?)(?:\n|$)", "ProgrammingError"),
        (r"django\.db\.utils\.DataError:\s*(.+?)(?:\n|$)", "DataError"),
        (r"django\.core\.exceptions\.FieldError:\s*(.+?)(?:\n|$)", "FieldError"),
        (r"django\.core\.exceptions\.(?:ObjectDoesNotExist|MultipleObjectsReturned)", "Query error"),
        (r"RelatedObjectDoesNotExist:\s*(.+?)(?:\n|$)", "Related object missing"),
    ]
    issues = []
    for p, label in orm_errors:
        m = re.search(p, output)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{label}: {detail}" if detail else label)
    if issues:
        return post_tool_context(
            "DJANGO ORM ERROR: " + "; ".join(issues[:3]) + ". "
            "Check: (1) model field definitions and constraints, "
            "(2) migration status ('manage.py migrate'), "
            "(3) query filters and related model references, "
            "(4) database connection and table existence."
        )
    return allow()


@registry.hook("django_check_n_plus_one")
def django_check_n_plus_one(data):
    """Detect N+1 query patterns in Django debug output."""
    output = get_command_output(data)
    # Look for django-debug-toolbar or nplusone output
    patterns = [
        r"nplusone\.core\.exceptions\.NPlusOneError",
        r"Potentially (\d+) queries.*instead of \d+",
    ]
    for p in patterns:
        m = re.search(p, output)
        if m:
            return post_tool_context(
                "DJANGO N+1 QUERY: N+1 query pattern detected. "
                "Use select_related() for ForeignKey/OneToOne fields "
                "or prefetch_related() for ManyToMany/reverse ForeignKey fields. "
                "Example: MyModel.objects.select_related('related_field').all()"
            )
    # Heuristic: detect repeated similar queries
    query_pattern = r"(?:\(\d+\.\d+\))\s+(SELECT\s+.+?FROM\s+\"(\w+)\")"
    queries = re.findall(query_pattern, output)
    if queries:
        table_counts = {}
        for _, table in queries:
            table_counts[table] = table_counts.get(table, 0) + 1
        suspect_tables = [t for t, c in table_counts.items() if c > 5]
        if suspect_tables:
            return post_tool_context(
                f"DJANGO N+1 QUERY: Repeated queries detected on table(s): {', '.join(suspect_tables)}. "
                "This is likely an N+1 query problem. Use select_related() or prefetch_related() "
                "to batch these queries."
            )
    return allow()


@registry.hook("django_detect_template_errors")
def django_detect_template_errors(data):
    """Parse Django template rendering errors."""
    output = get_command_output(data)
    patterns = [
        (r"django\.template\.exceptions\.TemplateSyntaxError:\s*(.+?)(?:\n|$)", "Syntax error"),
        (r"django\.template\.exceptions\.TemplateDoesNotExist:\s*(.+?)(?:\n|$)", "Template not found"),
        (r"VariableDoesNotExist:\s*(.+?)(?:\n|$)", "Variable does not exist"),
        (r"Invalid block tag.*?:\s*['\"](\w+)['\"]", "Invalid block tag"),
        (r"Unclosed tag.*?:\s*['\"](\w+)['\"]", "Unclosed tag"),
        (r"Invalid filter:\s*['\"](\w+)['\"]", "Invalid filter"),
    ]
    issues = []
    for p, label in patterns:
        m = re.search(p, output)
        if m:
            detail = m.group(1).strip()
            issues.append(f"{label}: {detail}")
    if issues:
        template_file = re.search(r"Template(?:\s+error)?\s+in\s+(\S+)", output)
        loc = f" in {template_file.group(1)}" if template_file else ""
        return post_tool_context(
            f"DJANGO TEMPLATE ERROR{loc}: " + "; ".join(issues) + ". "
            "Check: (1) template directory configuration in TEMPLATES setting, "
            "(2) template tag syntax {% %} and variable syntax {{ }}, "
            "(3) that custom template tags/filters are loaded with {% load %}, "
            "(4) template inheritance with {% extends %} and {% block %}."
        )
    return allow()


@registry.hook("django_check_url_patterns")
def django_check_url_patterns(data):
    """Parse URL configuration errors."""
    output = get_command_output(data)
    patterns = [
        (r"django\.urls\.exceptions\.NoReverseMatch:\s*(.+?)(?:\n|$)", "NoReverseMatch"),
        (r"Page not found.*404.*The current path.*didn't match any", "URL pattern not matched"),
        (r"(?:Reverse|resolve).*?not found.*?['\"](\w+)['\"]", "URL name not found"),
        (r"ImproperlyConfigured:.*?(?:url|URL|urlpatterns)(.+?)(?:\n|$)", "URL configuration error"),
        (r"is not a valid view function or pattern name", "Invalid view reference"),
    ]
    issues = []
    for p, label in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{label}: {detail}" if detail else label)
    if issues:
        return post_tool_context(
            "DJANGO URL ERROR: " + "; ".join(issues) + ". "
            "Run 'python manage.py show_urls' (django-extensions) to list all URL patterns. "
            "Check: (1) urlpatterns in urls.py files, (2) namespace and app_name in include(), "
            "(3) URL name matches in {% url %} tags and reverse() calls, "
            "(4) path() converter types match expected values."
        )
    return allow()


@registry.hook("django_detect_middleware_issues")
def django_detect_middleware_issues(data):
    """Parse Django middleware errors."""
    output = get_command_output(data)
    patterns = [
        (r"ImproperlyConfigured:.*MIDDLEWARE.*?(\S+)", "Middleware configuration error"),
        (r"ModuleNotFoundError:.*middleware.*?(\S+)", "Middleware module not found"),
        (r"MiddlewareNotUsed:\s*(.+?)(?:\n|$)", "Middleware not used"),
        (r"AttributeError:.*middleware.*?has no attribute\s+['\"](\w+)['\"]", "Middleware missing attribute"),
    ]
    issues = []
    for p, label in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip()
            issues.append(f"{label}: {detail}")
    if issues:
        return post_tool_context(
            "DJANGO MIDDLEWARE ERROR: " + "; ".join(issues) + ". "
            "Check MIDDLEWARE setting in settings.py. Middleware order matters: "
            "SecurityMiddleware should be first, then SessionMiddleware, CommonMiddleware, "
            "CsrfViewMiddleware, AuthenticationMiddleware, MessageMiddleware."
        )
    return allow()


@registry.hook("django_check_static_files")
def django_check_static_files(data):
    """Parse collectstatic and static file issues."""
    output = get_command_output(data)
    patterns = [
        (r"(?:STATIC_ROOT|STATICFILES_DIRS).*ImproperlyConfigured", "Static files misconfigured"),
        (r"(?:static|media)\s+file.*not found", "Static file not found"),
        (r"FileNotFoundError.*(?:static|media)", "Missing static/media file"),
        (r"collectstatic.*error", "collectstatic error"),
        (r"ManifestStaticFilesStorage.*Missing", "Missing file in manifest"),
    ]
    issues = []
    for p, label in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(label)
    if issues:
        return post_tool_context(
            "DJANGO STATIC FILES: " + "; ".join(issues) + ". "
            "Check: (1) STATIC_URL, STATIC_ROOT, and STATICFILES_DIRS in settings.py, "
            "(2) run 'python manage.py collectstatic', "
            "(3) ensure {% load static %} is in templates, "
            "(4) verify STATICFILES_FINDERS configuration."
        )
    return allow()


@registry.hook("django_detect_auth_issues")
def django_detect_auth_issues(data):
    """Parse authentication and permission errors."""
    output = get_command_output(data)
    patterns = [
        (r"PermissionDenied", "Permission denied"),
        (r"NotAuthenticated", "User not authenticated"),
        (r"AuthenticationFailed:\s*(.+?)(?:\n|$)", "Authentication failed"),
        (r"CSRF verification failed", "CSRF verification failed"),
        (r"Forbidden.*403.*CSRF", "CSRF cookie missing or incorrect"),
        (r"Invalid password", "Invalid password"),
        (r"No backend authenticated the credentials", "Authentication backend failure"),
    ]
    issues = []
    for p, label in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{label}: {detail}" if detail else label)
    if issues:
        return post_tool_context(
            "DJANGO AUTH ERROR: " + "; ".join(issues) + ". "
            "Check: (1) @login_required or LoginRequiredMixin on views, "
            "(2) CSRF token in forms with {% csrf_token %}, "
            "(3) AUTHENTICATION_BACKENDS setting, "
            "(4) REST_FRAMEWORK authentication/permission classes."
        )
    return allow()


@registry.hook("django_check_database_config")
def django_check_database_config(data):
    """Parse database configuration errors."""
    output = get_command_output(data)
    patterns = [
        (r"OperationalError.*(?:could not connect|Connection refused|timeout expired)", "Database connection failed"),
        (r"OperationalError.*(?:no such table|relation.*does not exist)", "Table does not exist"),
        (r"ImproperlyConfigured.*(?:database|DATABASES)", "Database misconfigured"),
        (r"(?:psycopg2|mysqlclient|sqlite3).*(?:Error|error):\s*(.+?)(?:\n|$)", "Database driver error"),
        (r"django\.db\.utils\.ConnectionDoesNotExist", "Database alias not configured"),
    ]
    issues = []
    for p, label in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{label}: {detail}" if detail else label)
    if issues:
        return post_tool_context(
            "DJANGO DATABASE ERROR: " + "; ".join(issues) + ". "
            "Check: (1) DATABASES setting in settings.py, "
            "(2) database server is running, "
            "(3) credentials and host/port are correct, "
            "(4) database driver is installed (psycopg2, mysqlclient, etc.), "
            "(5) run 'python manage.py migrate' to create tables."
        )
    return allow()


@registry.hook("django_detect_deprecation")
def django_detect_deprecation(data):
    """Parse Django deprecation warnings."""
    output = get_command_output(data)
    pattern = r"(?:Deprecation|Pending[Dd]eprecation)Warning:\s*(.+?)(?:\n|$)"
    matches = re.findall(pattern, output)
    # Also catch RemovedInDjango* warnings
    removed_pattern = r"RemovedInDjango(\d+)Warning:\s*(.+?)(?:\n|$)"
    removed = re.findall(removed_pattern, output)
    issues = []
    for version, msg in removed:
        issues.append(f"Removed in Django {version}: {msg.strip()}")
    for msg in matches:
        if not any(msg.strip() in i for i in issues):
            issues.append(msg.strip())
    if issues:
        return post_tool_context(
            f"DJANGO DEPRECATION: {len(issues)} deprecation warning(s):\n"
            + "\n".join(f"  - {i}" for i in issues[:8]) +
            "\nAddress these before upgrading Django to avoid breakage."
        )
    return allow()


@registry.hook("django_check_form_validation")
def django_check_form_validation(data):
    """Parse form validation errors from Django output."""
    output = get_command_output(data)
    patterns = [
        (r"ValidationError.*?(\[.+?\])", "Validation error"),
        (r"This field is required", "Required field missing"),
        (r"Enter a valid (?:email|URL|date|number|value)", "Invalid field format"),
        (r"ManagementForm data is missing or has been tampered with", "Formset management form error"),
    ]
    issues = []
    for p, label in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{label}: {detail}" if detail else label)
    if issues:
        return post_tool_context(
            "DJANGO FORM ERROR: " + "; ".join(issues) + ". "
            "Check: (1) form field definitions and validators, "
            "(2) form.is_valid() is called before accessing cleaned_data, "
            "(3) form errors are displayed in template with {{ form.errors }}, "
            "(4) formset management data is included ({{ formset.management_form }})."
        )
    return allow()


@registry.hook("django_detect_serializer_issues")
def django_detect_serializer_issues(data):
    """Parse Django REST Framework serializer errors."""
    output = get_command_output(data)
    patterns = [
        (r"Serializer.*?Error:\s*(.+?)(?:\n|$)", "Serializer error"),
        (r"AssertionError.*serializer.*?(\S+)", "Serializer assertion error"),
        (r"Field name.*?is not valid for model", "Invalid field for model"),
        (r"Got a.*TypeError.*?serializer.*?:?\s*(.+?)(?:\n|$)", "Serializer TypeError"),
        (r"ImproperlyConfigured:.*queryset.*serializer", "Missing queryset or serializer_class"),
        (r'"non_field_errors":\s*\[(.+?)\]', "Non-field validation error"),
    ]
    issues = []
    for p, label in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{label}: {detail}" if detail else label)
    if issues:
        return post_tool_context(
            "DJANGO REST FRAMEWORK: " + "; ".join(issues) + ". "
            "Check: (1) serializer Meta class fields and model, "
            "(2) field types match model field types, "
            "(3) nested serializer configuration, "
            "(4) ViewSet queryset and serializer_class attributes."
        )
    return allow()


@registry.hook("django_check_celery_tasks")
def django_check_celery_tasks(data):
    """Parse Celery task execution errors in Django context."""
    output = get_command_output(data)
    patterns = [
        (r"celery\.exceptions\.Retry:\s*(.+?)(?:\n|$)", "Task retry"),
        (r"(?:kombu|celery)\.exceptions\.OperationalError:\s*(.+?)(?:\n|$)", "Broker connection error"),
        (r"Received unregistered task.*?['\"](.+?)['\"]", "Unregistered task"),
        (r"TimeLimitExceeded", "Task time limit exceeded"),
        (r"SoftTimeLimitExceeded", "Soft time limit exceeded"),
        (r"WorkerLostError", "Celery worker lost"),
        (r"MaxRetriesExceededError", "Max retries exceeded"),
    ]
    issues = []
    for p, label in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{label}: {detail}" if detail else label)
    if issues:
        return post_tool_context(
            "DJANGO CELERY ERROR: " + "; ".join(issues) + ". "
            "Check: (1) Celery broker (Redis/RabbitMQ) is running, "
            "(2) CELERY_BROKER_URL in settings.py, "
            "(3) tasks are registered (celery -A project inspect registered), "
            "(4) task time limits (task_time_limit, task_soft_time_limit), "
            "(5) worker is running: celery -A project worker -l info."
        )
    return allow()


@registry.hook("django_detect_wsgi_issues")
def django_detect_wsgi_issues(data):
    """Parse WSGI/ASGI server startup errors."""
    output = get_command_output(data)
    patterns = [
        (r"ModuleNotFoundError:.*(?:wsgi|asgi)", "WSGI/ASGI module not found"),
        (r"ImproperlyConfigured:.*WSGI_APPLICATION", "WSGI_APPLICATION misconfigured"),
        (r"(?:gunicorn|uwsgi|daphne|uvicorn).*?(?:Error|error):\s*(.+?)(?:\n|$)", "Server error"),
        (r"Address already in use", "Port already in use"),
        (r"Worker.*?boot.*?timeout", "Worker boot timeout"),
        (r"\[CRITICAL\].*(?:WORKER|APP).*(?:timeout|failed)", "Critical worker failure"),
        (r"Application.*?not.*?(?:found|callable)", "Application not found or not callable"),
    ]
    issues = []
    for p, label in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            detail = m.group(1).strip() if m.lastindex else ""
            issues.append(f"{label}: {detail}" if detail else label)
    if issues:
        return post_tool_context(
            "DJANGO SERVER ERROR: " + "; ".join(issues) + ". "
            "Check: (1) WSGI_APPLICATION or ASGI_APPLICATION in settings.py, "
            "(2) the wsgi.py/asgi.py file exists and is correct, "
            "(3) gunicorn/uvicorn command syntax and worker count, "
            "(4) port availability (lsof -i :PORT), "
            "(5) application is importable from the project module."
        )
    return allow()


if __name__ == "__main__":
    registry.main()
