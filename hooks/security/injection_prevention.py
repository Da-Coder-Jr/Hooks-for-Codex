#!/usr/bin/env python3
"""
Security: Injection Prevention hooks for Codex.
20 PreToolUse hooks preventing SQL, XSS, command, and other injection attacks.
"""

import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, get_command

registry = HookRegistry()


@registry.hook("block_sql_injection_drop")
def block_sql_injection_drop(data):
    cmd = get_command(data)
    if re.search(r"(?i)\bDROP\s+(TABLE|DATABASE|INDEX|VIEW|SCHEMA)\b", cmd):
        return deny("Blocked: SQL DROP statement detected")
    return allow()

@registry.hook("block_sql_injection_union")
def block_sql_injection_union(data):
    cmd = get_command(data)
    if re.search(r"(?i)\bUNION\s+(ALL\s+)?SELECT\b", cmd):
        return deny("Blocked: SQL UNION SELECT injection pattern")
    return allow()

@registry.hook("block_sql_injection_delete")
def block_sql_injection_delete(data):
    cmd = get_command(data)
    if re.search(r"(?i)\bDELETE\s+FROM\s+\w+\s*;", cmd) and not re.search(r"(?i)\bWHERE\b", cmd):
        return deny("Blocked: DELETE without WHERE clause")
    return allow()

@registry.hook("block_sql_injection_update")
def block_sql_injection_update(data):
    cmd = get_command(data)
    if re.search(r"(?i)\bUPDATE\s+\w+\s+SET\b", cmd) and not re.search(r"(?i)\bWHERE\b", cmd):
        return deny("Blocked: UPDATE without WHERE clause")
    return allow()

@registry.hook("block_sql_truncate")
def block_sql_truncate(data):
    cmd = get_command(data)
    if re.search(r"(?i)\bTRUNCATE\s+TABLE\b", cmd):
        return deny("Blocked: TRUNCATE TABLE command")
    return allow()

@registry.hook("block_sql_load_file")
def block_sql_load_file(data):
    cmd = get_command(data)
    if re.search(r"(?i)\bLOAD_FILE\s*\(", cmd):
        return deny("Blocked: SQL LOAD_FILE() detected")
    if re.search(r"(?i)\bINTO\s+(OUT|DUMP)FILE\b", cmd):
        return deny("Blocked: SQL INTO OUTFILE detected")
    return allow()

@registry.hook("block_sql_exec")
def block_sql_exec(data):
    cmd = get_command(data)
    if re.search(r"(?i)\b(EXEC|EXECUTE)\s*\(", cmd):
        return deny("Blocked: SQL EXEC/EXECUTE detected")
    if re.search(r"(?i)\bxp_cmdshell\b", cmd):
        return deny("Blocked: SQL xp_cmdshell detected")
    return allow()

@registry.hook("block_sql_stacked_queries")
def block_sql_stacked_queries(data):
    cmd = get_command(data)
    if re.search(r";\s*(?i)(DROP|DELETE|INSERT|UPDATE|ALTER|EXEC|CREATE)\b", cmd):
        return deny("Blocked: stacked SQL queries detected")
    return allow()

@registry.hook("block_xss_script_tag")
def block_xss_script_tag(data):
    cmd = get_command(data)
    if re.search(r"\becho\b.*<script[\s>]", cmd, re.IGNORECASE):
        return deny("Blocked: XSS <script> tag in echo command")
    if re.search(r"\bprintf\b.*<script[\s>]", cmd, re.IGNORECASE):
        return deny("Blocked: XSS <script> tag in printf command")
    return allow()

@registry.hook("block_xss_event_handler")
def block_xss_event_handler(data):
    cmd = get_command(data)
    if re.search(r"\becho\b.*\bon(load|error|click|mouseover|focus)\s*=", cmd, re.IGNORECASE):
        return deny("Blocked: XSS event handler injection in echo")
    return allow()

@registry.hook("block_xss_javascript_uri")
def block_xss_javascript_uri(data):
    cmd = get_command(data)
    if re.search(r"\becho\b.*javascript:", cmd, re.IGNORECASE):
        return deny("Blocked: XSS javascript: URI injection")
    return allow()

@registry.hook("block_command_injection_semicolon")
def block_command_injection_semicolon(data):
    cmd = get_command(data)
    if re.search(r";\s*(cat\s+/etc/passwd|id\b|whoami\b|uname\s+-a)", cmd):
        return deny("Blocked: command injection via semicolon")
    return allow()

@registry.hook("block_command_injection_backtick")
def block_command_injection_backtick(data):
    cmd = get_command(data)
    if re.search(r"`\s*(cat|id|whoami|uname|wget|curl)\b", cmd):
        return deny("Blocked: command injection via backtick substitution")
    return allow()

@registry.hook("block_command_injection_dollar")
def block_command_injection_dollar(data):
    cmd = get_command(data)
    if re.search(r"\$\(\s*(cat\s+/etc/|id\b|whoami|wget|curl\s+.*\|)", cmd):
        return deny("Blocked: command injection via $() substitution")
    return allow()

@registry.hook("block_path_traversal")
def block_path_traversal(data):
    cmd = get_command(data)
    if re.search(r"\.\./\.\./\.\./", cmd):
        return deny("Blocked: path traversal attack (multiple ../)")
    if re.search(r"%2e%2e%2f", cmd, re.IGNORECASE):
        return deny("Blocked: URL-encoded path traversal")
    return allow()

@registry.hook("block_null_byte_injection")
def block_null_byte_injection(data):
    cmd = get_command(data)
    if re.search(r"(%00|\\x00|\\0)", cmd):
        return deny("Blocked: null byte injection detected")
    return allow()

@registry.hook("block_crlf_injection")
def block_crlf_injection(data):
    cmd = get_command(data)
    if re.search(r"(%0[dD]%0[aA]|\\r\\n)", cmd):
        return deny("Blocked: CRLF injection detected")
    return allow()

@registry.hook("block_ldap_injection")
def block_ldap_injection(data):
    cmd = get_command(data)
    if re.search(r"\bldapsearch\b.*\(\|.*\(\w+=\*\)", cmd):
        return deny("Blocked: LDAP injection pattern detected")
    return allow()

@registry.hook("block_xml_injection")
def block_xml_injection(data):
    cmd = get_command(data)
    if re.search(r"<!ENTITY\s+\w+\s+SYSTEM", cmd):
        return deny("Blocked: XXE (XML External Entity) injection")
    if re.search(r'<!DOCTYPE\s+\w+\s+\[.*<!ENTITY', cmd, re.DOTALL):
        return deny("Blocked: XML DOCTYPE with entity declaration")
    return allow()

@registry.hook("block_template_injection")
def block_template_injection(data):
    cmd = get_command(data)
    if re.search(r"\becho\b.*\{\{.*\}\}", cmd):
        if re.search(r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}", cmd):
            return deny("Blocked: template injection pattern (mathematical expression)")
    if re.search(r"\becho\b.*<%.*%>", cmd):
        return deny("Blocked: ERB/JSP template injection in echo")
    return allow()


if __name__ == "__main__":
    registry.main()
