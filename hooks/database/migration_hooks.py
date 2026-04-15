#!/usr/bin/env python3
"""PostToolUse hooks for database migration error detection and guidance."""
import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()

MIGRATION_TOOLS = [
    "alembic", "flyway", "knex", "sequelize", "prisma", "typeorm",
    "django", "migrate", "goose", "dbmate", "liquibase", "rails",
    "rake db:", "artisan migrate", "ecto.migrate", "diesel migration",
]

LARGE_TABLE_THRESHOLD_HINTS = [
    r"(\d+)\s+rows?\s+affected",
    r"(\d+)\s+rows?\s+estimated",
    r"table.*has\s+(\d+)\s+rows",
    r"rows_estimate.*?(\d+)",
]


def _is_migration_context(command, output):
    """Check if this is a migration-related command."""
    combined = (command + " " + output).lower()
    for tool in MIGRATION_TOOLS:
        if tool in combined:
            return True
    if re.search(r'\b(migration|migrate|schema|alembic|flyway)\b', combined):
        return True
    return False


def _extract_error_details(output):
    """Extract structured error info from migration output."""
    errors = []
    # Common migration error patterns
    patterns = [
        (r"(?:ERROR|Error|error)[:\s]+(.+?)(?:\n|$)", "error"),
        (r"(?:FATAL|Fatal)[:\s]+(.+?)(?:\n|$)", "fatal"),
        (r"(?:Failed|FAILED)[:\s]+(.+?)(?:\n|$)", "failure"),
        (r"relation \"(\w+)\" already exists", "duplicate_relation"),
        (r"column \"(\w+)\" of relation \"(\w+)\" already exists", "duplicate_column"),
        (r"table \"(\w+)\" does not exist", "missing_table"),
        (r"column \"(\w+)\" does not exist", "missing_column"),
        (r"constraint \"(\w+)\" .* does not exist", "missing_constraint"),
        (r"duplicate key value violates unique constraint", "unique_violation"),
        (r"cannot drop .* because other objects depend on it", "dependency_error"),
    ]
    for pattern, err_type in patterns:
        matches = re.findall(pattern, output, re.IGNORECASE)
        for m in matches[:3]:
            detail = m if isinstance(m, str) else " / ".join(m)
            errors.append((err_type, detail.strip()))
    return errors


@registry.hook("migration_detect_errors")
def migration_detect_errors(data):
    """Parse migration tool errors (Alembic, Flyway, Knex, etc.)."""
    command = get_command(data)
    output = get_command_output(data)
    if not _is_migration_context(command, output):
        return allow()
    errors = _extract_error_details(output)
    if errors:
        details = []
        for err_type, detail in errors[:5]:
            details.append(f"  - [{err_type}] {detail}")
        return post_tool_context(
            f"MIGRATION ERROR: {len(errors)} error(s) detected:\n"
            + "\n".join(details)
            + "\nCheck migration file syntax, ensure the database schema is in the expected state, "
            "and verify the migration tool version is compatible."
        )
    return allow()


@registry.hook("migration_check_reversibility")
def migration_check_reversibility(data):
    """Warn about irreversible migrations."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    irreversible_patterns = [
        (r'\bDROP\s+TABLE\b', "DROP TABLE"),
        (r'\bDROP\s+COLUMN\b', "DROP COLUMN"),
        (r'\bDROP\s+DATABASE\b', "DROP DATABASE"),
        (r'\bTRUNCATE\b', "TRUNCATE"),
        (r'\bDROP\s+TYPE\b', "DROP TYPE"),
        (r'irreversible', "marked irreversible"),
        (r'NotImplementedError.*down', "missing down migration"),
        (r'raise.*IrreversibleMigration', "IrreversibleMigration"),
    ]
    found = []
    combined = output + " " + command
    for pattern, label in irreversible_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            found.append(label)
    if found:
        return post_tool_context(
            f"IRREVERSIBLE MIGRATION: Detected irreversible operations: {', '.join(found)}. "
            "This migration cannot be safely rolled back. Ensure you have a backup "
            "and consider writing a separate data-recovery migration."
        )
    return allow()


@registry.hook("migration_detect_data_loss")
def migration_detect_data_loss(data):
    """Warn about migrations that may lose data."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    data_loss_patterns = [
        (r'\bDROP\s+COLUMN\b', "Dropping columns destroys data in those columns"),
        (r'\bALTER\s+.*\bTYPE\b.*\bVARCHAR\s*\(\s*(\d+)\s*\)', "Column type change may truncate data"),
        (r'\bDELETE\s+FROM\b', "DELETE removes data"),
        (r'\bTRUNCATE\b', "TRUNCATE removes all table data"),
        (r'data_loss|dataloss', "Migration flagged as data loss risk"),
        (r'\bRENAME\s+COLUMN\b', "Column rename may break dependent queries"),
        (r'changing.*from.*to.*losing', "Type conversion data loss"),
    ]
    found = []
    combined = output + " " + command
    for pattern, explanation in data_loss_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            found.append(explanation)
    if found:
        return post_tool_context(
            "DATA LOSS RISK: This migration may cause data loss:\n"
            + "\n".join(f"  - {f}" for f in found)
            + "\nBack up affected tables before applying. Consider a multi-step migration "
            "(add new column, copy data, drop old column) to preserve data."
        )
    return allow()


@registry.hook("migration_check_downtime")
def migration_check_downtime(data):
    """Estimate migration downtime for large tables."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    # Look for row count estimates
    row_counts = []
    for pattern in LARGE_TABLE_THRESHOLD_HINTS:
        matches = re.findall(pattern, output, re.IGNORECASE)
        for m in matches:
            try:
                row_counts.append(int(m))
            except ValueError:
                pass
    # Check for DDL operations that lock tables
    locking_ops = re.findall(
        r'\b(ALTER\s+TABLE|CREATE\s+INDEX|ADD\s+(?:UNIQUE\s+)?CONSTRAINT)\b',
        output + " " + command, re.IGNORECASE
    )
    if locking_ops and row_counts:
        max_rows = max(row_counts)
        if max_rows > 1_000_000:
            est_minutes = max_rows // 500_000  # rough estimate
            return post_tool_context(
                f"DOWNTIME WARNING: DDL operation ({', '.join(set(locking_ops))}) on table with ~{max_rows:,} rows. "
                f"Estimated lock time: {est_minutes}+ minutes. "
                "Consider: (1) CREATE INDEX CONCURRENTLY for indexes, "
                "(2) pt-online-schema-change or gh-ost for MySQL ALTER TABLE, "
                "(3) Running during off-peak hours."
            )
    elif locking_ops:
        return post_tool_context(
            f"DOWNTIME NOTICE: DDL operation ({', '.join(set(locking_ops))}) detected. "
            "Large tables may experience downtime. Check table size with "
            "SELECT count(*) or pg_stat_user_tables/information_schema before proceeding."
        )
    return allow()


@registry.hook("migration_validate_naming")
def migration_validate_naming(data):
    """Check migration file naming convention."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    # Extract migration filenames from output
    migration_files = re.findall(r'[\w/\\]*migrations?[/\\]([\w\-_.]+\.(?:py|sql|js|ts|rb|php))', output + " " + command, re.IGNORECASE)
    issues = []
    for fname in migration_files:
        # Check for timestamp prefix (common convention)
        if not re.match(r'^\d{4,14}[_\-]', fname) and not re.match(r'^V\d+', fname) and not re.match(r'^\d{3,4}_', fname):
            issues.append(f"'{fname}' does not follow timestamp/version prefix convention")
        # Check for spaces or special characters
        if re.search(r'[^a-zA-Z0-9_\-.]', fname):
            issues.append(f"'{fname}' contains special characters that may cause portability issues")
        # Check for descriptive name
        if re.match(r'^\d+\.', fname):
            issues.append(f"'{fname}' lacks a descriptive suffix (e.g., 001_create_users_table)")
    if issues:
        return post_tool_context(
            "MIGRATION NAMING: Issues found:\n"
            + "\n".join(f"  - {i}" for i in issues[:5])
            + "\nConvention: <timestamp/version>_<descriptive_name>.<ext> "
            "(e.g., 20240115120000_add_users_email_index.sql)"
        )
    return allow()


@registry.hook("migration_detect_conflicts")
def migration_detect_conflicts(data):
    """Detect migration dependency conflicts."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    conflict_patterns = [
        (r"(?:multiple|conflicting)\s+(?:heads?|leaf|leaves)", "Multiple migration heads detected"),
        (r"(?:branch|fork)\s+(?:detected|conflict)", "Migration branch conflict"),
        (r"depends on.*which (?:does not exist|hasn't been applied)", "Missing dependency"),
        (r"revision.*not found", "Missing revision reference"),
        (r"(?:merge|resolve)\s+(?:required|needed)", "Merge required for migration branches"),
        (r"ambiguous.*revision", "Ambiguous revision reference"),
        (r"checksum mismatch|hash mismatch|modified after", "Migration file modified after application"),
    ]
    found = []
    for pattern, desc in conflict_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            found.append(desc)
    if found:
        return post_tool_context(
            "MIGRATION CONFLICT: " + "; ".join(found) + ". "
            "Resolve by: (1) merging migration branches (alembic merge), "
            "(2) ensuring all team members' migrations are pulled before creating new ones, "
            "(3) checking migration dependency chain integrity."
        )
    return allow()


@registry.hook("migration_check_foreign_keys")
def migration_check_foreign_keys(data):
    """Warn about adding foreign keys to large tables."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    combined = output + " " + command
    if re.search(r'\bADD\s+(?:CONSTRAINT\s+\w+\s+)?FOREIGN\s+KEY\b', combined, re.IGNORECASE):
        # Check for NOT VALID option (PostgreSQL)
        if 'NOT VALID' not in combined.upper():
            return post_tool_context(
                "FOREIGN KEY WARNING: Adding a foreign key constraint requires scanning all existing rows "
                "to validate the constraint, which locks the table. For large tables, consider: "
                "(1) PostgreSQL: ADD CONSTRAINT ... NOT VALID, then VALIDATE CONSTRAINT separately, "
                "(2) MySQL: SET FOREIGN_KEY_CHECKS=0 temporarily (risky), "
                "(3) Adding the FK during a maintenance window."
            )
    return allow()


@registry.hook("migration_check_null_to_not_null")
def migration_check_null_to_not_null(data):
    """Warn about NULL to NOT NULL changes without defaults."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    combined = output + " " + command
    # ALTER COLUMN ... SET NOT NULL or MODIFY ... NOT NULL
    if re.search(r'\b(SET\s+NOT\s+NULL|MODIFY.*NOT\s+NULL|ALTER.*NOT\s+NULL)\b', combined, re.IGNORECASE):
        if not re.search(r'\bDEFAULT\b', combined, re.IGNORECASE):
            return post_tool_context(
                "NULL TO NOT NULL WARNING: Changing a column from NULL to NOT NULL without a DEFAULT "
                "will fail if any existing rows have NULL values. Steps: "
                "(1) UPDATE the table to fill NULL values with a sensible default, "
                "(2) SET DEFAULT on the column, "
                "(3) Then SET NOT NULL."
            )
    return allow()


@registry.hook("migration_detect_schema_drift")
def migration_detect_schema_drift(data):
    """Detect schema drift between environments."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    drift_patterns = [
        (r"schema.*(?:out of sync|drift|mismatch|differs)", "Schema drift detected"),
        (r"pending migrations?.*(?:not applied|missing)", "Pending unapplied migrations"),
        (r"database.*(?:ahead|behind).*migration", "Database version mismatch"),
        (r"applied.*not.*found.*locally", "Applied migration missing from source"),
        (r"local.*not.*applied.*database", "Local migration not applied to database"),
        (r"schema.*version.*(?:mismatch|different)", "Schema version discrepancy"),
    ]
    found = []
    for pattern, desc in drift_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            found.append(desc)
    if found:
        return post_tool_context(
            "SCHEMA DRIFT: " + "; ".join(found) + ". "
            "Ensure all environments run the same migration set. "
            "Use 'migrate status' or equivalent to compare, "
            "and never manually alter production schemas without updating migration files."
        )
    return allow()


@registry.hook("migration_check_index_creation")
def migration_check_index_creation(data):
    """Warn about index creation on large tables (locking)."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    combined = output + " " + command
    if re.search(r'\bCREATE\s+(?:UNIQUE\s+)?INDEX\b', combined, re.IGNORECASE):
        if 'CONCURRENTLY' not in combined.upper():
            return post_tool_context(
                "INDEX CREATION WARNING: CREATE INDEX acquires a lock that blocks writes "
                "(and possibly reads) on the table for the duration of the build. "
                "For production databases, use CREATE INDEX CONCURRENTLY (PostgreSQL) "
                "which builds the index without locking out writes. "
                "Note: CONCURRENTLY cannot be used inside a transaction block."
            )
    return allow()


@registry.hook("migration_suggest_concurrent")
def migration_suggest_concurrent(data):
    """Suggest CREATE INDEX CONCURRENTLY for PostgreSQL."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    combined = output + " " + command
    # Detect PostgreSQL context
    is_pg = re.search(r'\bpsql\b|\bpostgres\b|\bpg_\b|\balembic\b', combined, re.IGNORECASE)
    if is_pg and re.search(r'\bCREATE\s+INDEX\b', combined, re.IGNORECASE):
        if 'CONCURRENTLY' not in combined.upper():
            return post_tool_context(
                "POSTGRESQL TIP: Use CREATE INDEX CONCURRENTLY to avoid locking the table. "
                "For Alembic: op.create_index(..., postgresql_concurrently=True) "
                "and set the migration to non-transactional. "
                "For raw SQL: CREATE INDEX CONCURRENTLY idx_name ON table(column);"
            )
    return allow()


@registry.hook("migration_check_enum_changes")
def migration_check_enum_changes(data):
    """Warn about enum type modifications."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    combined = output + " " + command
    enum_patterns = [
        (r'\bALTER\s+TYPE\s+\w+\s+ADD\s+VALUE\b', "Adding enum value"),
        (r'\bALTER\s+TYPE\s+\w+\s+RENAME\s+VALUE\b', "Renaming enum value"),
        (r'\bDROP\s+TYPE\b', "Dropping enum type"),
        (r'\bCREATE\s+TYPE\s+\w+\s+AS\s+ENUM\b', "Creating enum type"),
        (r"enum.*(?:change|modify|alter)", "Enum modification"),
    ]
    found = []
    for pattern, desc in enum_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            found.append(desc)
    if found:
        return post_tool_context(
            "ENUM CHANGE: " + "; ".join(found) + ". "
            "Enum modifications can be tricky: "
            "(1) PostgreSQL: ALTER TYPE ... ADD VALUE cannot run inside a transaction, "
            "(2) Removing enum values requires recreating the type, "
            "(3) Application code must be updated to handle new/changed values, "
            "(4) Consider using a lookup table instead of enums for frequently-changing values."
        )
    return allow()


@registry.hook("migration_detect_rollback_errors")
def migration_detect_rollback_errors(data):
    """Parse migration rollback errors."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    # Check if this was a rollback/downgrade
    is_rollback = re.search(r'\b(rollback|downgrade|revert|undo|down)\b', command, re.IGNORECASE)
    if not is_rollback:
        return allow()
    errors = _extract_error_details(output)
    rollback_issues = [
        (r"(?:down|rollback)\s+(?:method|function)\s+(?:not\s+)?(?:defined|implemented|found)", "No rollback method defined"),
        (r"cannot.*rollback.*(?:irreversible|one.way)", "Irreversible migration cannot be rolled back"),
        (r"(?:table|column|index)\s+\w+\s+(?:does not exist|not found)", "Referenced object doesn't exist"),
    ]
    for pattern, desc in rollback_issues:
        if re.search(pattern, output, re.IGNORECASE):
            errors.append(("rollback", desc))
    if errors:
        details = [f"  - [{t}] {d}" for t, d in errors[:5]]
        return post_tool_context(
            "ROLLBACK ERROR: Migration rollback failed:\n"
            + "\n".join(details)
            + "\nOptions: (1) Fix the down migration and retry, "
            "(2) Manually restore from backup, "
            "(3) Create a new forward migration to fix the issue."
        )
    return allow()


@registry.hook("migration_check_seed_data")
def migration_check_seed_data(data):
    """Validate seed data consistency."""
    output = get_command_output(data)
    command = get_command(data)
    if not re.search(r'\b(seed|fixture|populate|load.data)\b', command + " " + output, re.IGNORECASE):
        return allow()
    issues = []
    # Check for foreign key violations in seed output
    if re.search(r'foreign key.*(?:violat|fail|constraint)', output, re.IGNORECASE):
        issues.append("Foreign key constraint violations - seed data references missing parent records")
    # Check for unique constraint violations
    if re.search(r'(?:unique|duplicate).*(?:violat|constraint|key)', output, re.IGNORECASE):
        issues.append("Duplicate key violations - seed data conflicts with existing records")
    # Check for not-null violations
    if re.search(r'not.null.*(?:violat|constraint|fail)', output, re.IGNORECASE):
        issues.append("NOT NULL constraint violations - seed data missing required fields")
    # Check for truncation warnings
    if re.search(r'(?:truncat|too long|data too)', output, re.IGNORECASE):
        issues.append("Data truncation - values exceed column size limits")
    if issues:
        return post_tool_context(
            "SEED DATA ISSUES:\n"
            + "\n".join(f"  - {i}" for i in issues)
            + "\nFix seed data files to match the current schema, "
            "or run seeds in the correct order (parent tables first)."
        )
    return allow()


@registry.hook("migration_detect_connection_errors")
def migration_detect_connection_errors(data):
    """Parse database connection errors."""
    output = get_command_output(data)
    command = get_command(data)
    if not _is_migration_context(command, output):
        return allow()
    conn_patterns = [
        (r"(?:connection|connect)\s+refused", "Connection refused - is the database server running?"),
        (r"(?:timeout|timed?\s*out)\s+(?:expired|connecting|waiting)", "Connection timeout - check host/port and network"),
        (r"(?:authentication|auth|login)\s+failed", "Authentication failed - check username/password"),
        (r"(?:database|relation).*does not exist", "Database/schema does not exist - create it first"),
        (r"(?:permission|access)\s+denied", "Permission denied - check user privileges"),
        (r"(?:SSL|TLS).*(?:required|error|fail)", "SSL/TLS connection error - check certificate configuration"),
        (r"(?:host|server).*(?:not found|unknown|unresolved)", "Host not found - check DATABASE_URL or host configuration"),
        (r"too many connections", "Connection pool exhausted - check max_connections setting"),
    ]
    found = []
    for pattern, desc in conn_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            found.append(desc)
    if found:
        return post_tool_context(
            "DATABASE CONNECTION ERROR:\n"
            + "\n".join(f"  - {f}" for f in found)
            + "\nVerify: DATABASE_URL, host, port, credentials, and that the database server is accessible."
        )
    return allow()


if __name__ == "__main__":
    registry.main()
