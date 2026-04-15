#!/usr/bin/env python3
"""SQL safety hooks for preventing dangerous database operations via PreToolUse."""
import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, get_command

registry = HookRegistry()

# Tables considered critical in most applications
CRITICAL_TABLES = [
    "users", "accounts", "payments", "transactions", "orders",
    "customers", "billing", "subscriptions", "permissions", "roles",
    "audit_log", "sessions", "credentials", "migrations",
]

PRODUCTION_INDICATORS = [
    r"--host[= ]+[^\s]*prod",
    r"-h\s+[^\s]*prod",
    r"@[^\s]*prod[^\s]*:",
    r"production",
    r"\.prod\.",
    r"prod-db",
    r"master\.db",
]

LARGE_TABLES = [
    "events", "logs", "analytics", "metrics", "audit",
    "history", "activity", "sessions", "clicks", "impressions",
    "messages", "notifications", "emails",
]


def _extract_sql(command):
    """Extract SQL from common database CLI tools."""
    sql = ""
    # psql -c "SQL", mysql -e "SQL", sqlite3 db "SQL"
    m = re.search(r'(?:-c|-e|--command|--execute)\s+["\'](.+?)["\']', command, re.DOTALL)
    if m:
        sql = m.group(1)
    # Heredoc or pipe: echo "SQL" | psql
    m2 = re.search(r'echo\s+["\'](.+?)["\']\s*\|', command, re.DOTALL)
    if m2:
        sql = m2.group(1)
    # If the command itself looks like SQL
    if not sql and re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|EXEC)\s', command, re.IGNORECASE):
        sql = command
    return sql.upper(), sql


def _is_production_context(command):
    """Check if the command targets a production database."""
    for p in PRODUCTION_INDICATORS:
        if re.search(p, command, re.IGNORECASE):
            return True
    return False


def _table_is_critical(sql_upper):
    """Check if the SQL references a critical table."""
    for table in CRITICAL_TABLES:
        if table.upper() in sql_upper:
            return table
    return None


@registry.hook("sql_block_drop_database")
def sql_block_drop_database(data):
    """Block DROP DATABASE commands."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bDROP\s+DATABASE\b', sql_upper):
        return deny("BLOCKED: DROP DATABASE is extremely dangerous. Use a migration tool or admin console to drop databases safely.")
    return allow()


@registry.hook("sql_block_drop_table")
def sql_block_drop_table(data):
    """Block DROP TABLE on production tables."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bDROP\s+TABLE\b', sql_upper):
        table = _table_is_critical(sql_upper)
        if table or _is_production_context(command):
            reason = f"on critical table '{table}'" if table else "in production context"
            return deny(f"BLOCKED: DROP TABLE {reason}. Back up data first and use a migration tool.")
        return deny("WARNING: DROP TABLE detected. Verify this is intentional and not targeting production data.")
    return allow()


@registry.hook("sql_block_truncate")
def sql_block_truncate(data):
    """Block TRUNCATE TABLE commands."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bTRUNCATE\s+(TABLE\s+)?\w', sql_upper):
        return deny("BLOCKED: TRUNCATE TABLE removes all rows without logging individual deletes. Use DELETE with WHERE for safer data removal, or confirm this is intentional.")
    return allow()


@registry.hook("sql_block_delete_no_where")
def sql_block_delete_no_where(data):
    """Block DELETE without WHERE clause."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bDELETE\s+FROM\b', sql_upper):
        if not re.search(r'\bWHERE\b', sql_upper):
            return deny("BLOCKED: DELETE without WHERE clause will remove ALL rows from the table. Add a WHERE clause to target specific rows.")
    return allow()


@registry.hook("sql_block_update_no_where")
def sql_block_update_no_where(data):
    """Block UPDATE without WHERE clause."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bUPDATE\s+\w', sql_upper):
        if re.search(r'\bSET\b', sql_upper) and not re.search(r'\bWHERE\b', sql_upper):
            return deny("BLOCKED: UPDATE without WHERE clause will modify ALL rows in the table. Add a WHERE clause to target specific rows.")
    return allow()


@registry.hook("sql_block_alter_drop_column")
def sql_block_alter_drop_column(data):
    """Block ALTER TABLE DROP COLUMN on critical tables."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bALTER\s+TABLE\b.*\bDROP\s+COLUMN\b', sql_upper):
        table = _table_is_critical(sql_upper)
        if table:
            return deny(f"BLOCKED: Dropping columns on critical table '{table}' can cause data loss and application errors. Use a migration tool and ensure backward compatibility.")
    return allow()


@registry.hook("sql_block_grant_all")
def sql_block_grant_all(data):
    """Block GRANT ALL PRIVILEGES."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bGRANT\s+ALL\s+(PRIVILEGES\s+)?ON\b', sql_upper):
        return deny("BLOCKED: GRANT ALL PRIVILEGES is overly permissive. Grant only the specific privileges needed (SELECT, INSERT, UPDATE, etc.) following the principle of least privilege.")
    return allow()


@registry.hook("sql_block_revoke_all")
def sql_block_revoke_all(data):
    """Block REVOKE ALL from critical users."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bREVOKE\s+ALL\b', sql_upper):
        critical_users = ["ROOT", "ADMIN", "POSTGRES", "MYSQL", "DBA", "SUPERUSER"]
        for user in critical_users:
            if user in sql_upper:
                return deny(f"BLOCKED: Revoking all privileges from '{user}' can lock you out of the database entirely. Revoke specific privileges instead.")
    return allow()


@registry.hook("sql_check_backup_before_alter")
def sql_check_backup_before_alter(data):
    """Remind to backup before ALTER TABLE."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bALTER\s+TABLE\b', sql_upper):
        table = _table_is_critical(sql_upper)
        if table:
            return deny(f"CAUTION: ALTER TABLE on critical table '{table}'. Ensure you have a backup before proceeding. Consider running the ALTER in a transaction if your database supports transactional DDL.")
    return allow()


@registry.hook("sql_block_raw_credentials")
def sql_block_raw_credentials(data):
    """Block connection strings with plaintext passwords in commands."""
    command = get_command(data)
    # Match patterns like: mysql -u root -pPassword, postgres://user:pass@host, --password=secret
    cred_patterns = [
        r'-p[A-Za-z0-9!@#$%^&*]{4,}',  # mysql -pPassword (no space)
        r'://\w+:[^@\s]{4,}@',           # postgres://user:pass@host
        r'--password[= ]+[^\s]{4,}',     # --password=secret
        r'PGPASSWORD=[^\s]{4,}',         # PGPASSWORD=secret
        r'MYSQL_PWD=[^\s]{4,}',          # MYSQL_PWD=secret
        r"IDENTIFIED\s+BY\s+['\"][^'\"]+['\"]",  # IDENTIFIED BY 'password'
    ]
    for p in cred_patterns:
        if re.search(p, command, re.IGNORECASE):
            return deny("BLOCKED: Plaintext database credentials detected in command. Use environment variables, .pgpass, .my.cnf, or a secrets manager instead.")
    return allow()


@registry.hook("sql_validate_migration_order")
def sql_validate_migration_order(data):
    """Check migration files are applied in order."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    # Detect running migration files out of order
    migration_file_match = re.findall(r'(\d{3,14})[_-]', command)
    if len(migration_file_match) > 1:
        timestamps = [int(t) for t in migration_file_match]
        if timestamps != sorted(timestamps):
            return deny("WARNING: Migration files appear to be out of order. Migrations should be applied sequentially by their timestamp/version number to avoid conflicts.")
    # Check for migration tools being run with skip/force flags
    if re.search(r'\b(migrate|migration)\b', command, re.IGNORECASE):
        if re.search(r'--skip|--force|--no-check|--ignore-order', command, re.IGNORECASE):
            return deny("WARNING: Running migrations with skip/force flags can cause schema inconsistencies. Resolve migration conflicts properly instead.")
    return allow()


@registry.hook("sql_block_concurrent_ddl")
def sql_block_concurrent_ddl(data):
    """Warn about DDL without locking strategy."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    ddl_keywords = [r'\bCREATE\s+INDEX\b', r'\bALTER\s+TABLE\b.*\bADD\b', r'\bALTER\s+TABLE\b.*\bMODIFY\b']
    for kw in ddl_keywords:
        if re.search(kw, sql_upper):
            # Check if it's on a large/busy table
            for table in LARGE_TABLES:
                if table.upper() in sql_upper:
                    if 'CONCURRENTLY' not in sql_upper and 'LOCK_NONE' not in sql_upper and 'ALGORITHM=INPLACE' not in sql_upper:
                        return deny(f"WARNING: DDL operation on potentially large table '{table}' without a locking strategy. Consider using CREATE INDEX CONCURRENTLY (PostgreSQL) or ALGORITHM=INPLACE (MySQL) to avoid blocking reads/writes.")
    return allow()


@registry.hook("sql_check_index_before_query")
def sql_check_index_before_query(data):
    """Suggest indexes for large table queries."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bSELECT\b', sql_upper) and re.search(r'\bWHERE\b', sql_upper):
        for table in LARGE_TABLES:
            if table.upper() in sql_upper:
                # Check for EXPLAIN
                if 'EXPLAIN' not in sql_upper:
                    return deny(f"SUGGESTION: Query on potentially large table '{table}'. Consider running EXPLAIN first to verify index usage and avoid full table scans.")
    return allow()


@registry.hook("sql_block_wildcard_select")
def sql_block_wildcard_select(data):
    """Warn about SELECT * in production queries."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bSELECT\s+\*\s+FROM\b', sql_upper):
        if _is_production_context(command):
            return deny("WARNING: SELECT * in production context fetches all columns, which wastes bandwidth and may expose sensitive fields. Specify only the columns you need.")
        for table in LARGE_TABLES:
            if table.upper() in sql_upper:
                return deny(f"WARNING: SELECT * on large table '{table}' may return excessive data. Specify needed columns and consider adding LIMIT.")
    return allow()


@registry.hook("sql_check_transaction_usage")
def sql_check_transaction_usage(data):
    """Warn about multi-statement changes without transactions."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    # Count DML statements
    dml_count = len(re.findall(r'\b(INSERT|UPDATE|DELETE)\b', sql_upper))
    if dml_count >= 2:
        if not re.search(r'\b(BEGIN|START\s+TRANSACTION)\b', sql_upper):
            return deny("WARNING: Multiple DML statements without a transaction. Wrap related INSERT/UPDATE/DELETE statements in BEGIN...COMMIT to ensure atomicity.")
    return allow()


@registry.hook("sql_block_cursor_abuse")
def sql_block_cursor_abuse(data):
    """Warn about cursor-based iteration over large result sets."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bDECLARE\s+\w+\s+CURSOR\b', sql_upper):
        if not re.search(r'\bLIMIT\b', sql_upper) and not re.search(r'\bFETCH\s+NEXT\s+\d+\b', sql_upper):
            return deny("WARNING: Cursor declared without row limits. Cursors iterating over large result sets consume significant memory. Consider using LIMIT/OFFSET pagination or batch processing instead.")
    return allow()


@registry.hook("sql_check_encoding")
def sql_check_encoding(data):
    """Warn about character encoding mismatches."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    # Check for charset/encoding settings
    if re.search(r'\bCHARACTER\s+SET\b|\bCHARSET\b|\bENCODING\b|\bCOLLATE\b', sql_upper):
        # Warn about latin1 when utf8 is standard
        if re.search(r'\bLATIN1\b', sql_upper) or re.search(r'\bASCII\b', sql_upper):
            return deny("WARNING: Using LATIN1/ASCII encoding. Modern applications should use UTF8MB4 (MySQL) or UTF8 (PostgreSQL) to support full Unicode including emojis.")
        if re.search(r'\bUTF8\b', sql_upper) and not re.search(r'\bUTF8MB4\b', sql_upper):
            if re.search(r'\bMYSQL\b|--host.*mysql|-u\s+\w', command, re.IGNORECASE):
                return deny("WARNING: MySQL's 'utf8' is only 3 bytes and doesn't support all Unicode characters. Use 'utf8mb4' instead for full Unicode support.")
    return allow()


@registry.hook("sql_block_exec_dynamic")
def sql_block_exec_dynamic(data):
    """Block EXEC with dynamic SQL concatenation."""
    command = get_command(data)
    sql_upper, raw_sql = _extract_sql(command)
    if re.search(r'\bEXEC(?:UTE)?\s*\(', sql_upper):
        # Check for string concatenation suggesting dynamic SQL
        if re.search(r"(\+\s*@|\|\|\s*'|CONCAT\s*\()", sql_upper):
            return deny("BLOCKED: Dynamic SQL via EXEC with string concatenation is vulnerable to SQL injection. Use parameterized queries (sp_executesql) or prepared statements instead.")
    # Also catch Python/language-level string formatting in SQL
    if re.search(r'(?:f["\']|\.format\(|%s|%d|\$\{)', raw_sql):
        if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b', sql_upper):
            return deny("WARNING: SQL query appears to use string interpolation, which is vulnerable to SQL injection. Use parameterized queries or prepared statements.")
    return allow()


@registry.hook("sql_check_null_handling")
def sql_check_null_handling(data):
    """Warn about NULL comparison with = instead of IS."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    # Match WHERE col = NULL or WHERE col != NULL (should be IS NULL / IS NOT NULL)
    if re.search(r'\bWHERE\b', sql_upper):
        if re.search(r'[=!<>]+\s*NULL\b', sql_upper) and not re.search(r'\bIS\s+(NOT\s+)?NULL\b', sql_upper):
            return deny("WARNING: Comparing with NULL using = or != always returns UNKNOWN in SQL. Use 'IS NULL' or 'IS NOT NULL' instead. Example: WHERE column IS NULL")
    return allow()


@registry.hook("sql_block_force_index")
def sql_block_force_index(data):
    """Warn about FORCE INDEX usage."""
    command = get_command(data)
    sql_upper, _ = _extract_sql(command)
    if re.search(r'\bFORCE\s+INDEX\b|\bUSE\s+INDEX\b|\bIGNORE\s+INDEX\b', sql_upper):
        return deny("WARNING: FORCE INDEX/USE INDEX overrides the query optimizer's decisions. This can degrade performance when data distribution changes. Let the optimizer choose indexes, or investigate why it's not using the expected index (check EXPLAIN output and statistics).")
    return allow()


if __name__ == "__main__":
    registry.main()
