#!/usr/bin/env python3
"""
Security: Compliance Check hooks for Codex.
25 PostToolUse hooks for regulatory and security compliance.
"""

import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()


@registry.hook("check_gdpr_personal_data")
def check_gdpr_personal_data(data):
    output = get_command_output(data)
    if not output: return allow()
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", output)
    phones = re.findall(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", output)
    ssns = re.findall(r"\b\d{3}-\d{2}-\d{4}\b", output)
    if len(emails) > 5 or phones or ssns:
        parts = []
        if emails: parts.append(f"{len(emails)} email addresses")
        if phones: parts.append(f"{len(phones)} phone numbers")
        if ssns: parts.append(f"{len(ssns)} potential SSNs")
        return post_tool_context(f"GDPR WARNING: Personal data detected in output: {', '.join(parts)}")
    return allow()

@registry.hook("check_gdpr_data_export")
def check_gdpr_data_export(data):
    cmd = get_command(data)
    output = get_command_output(data)
    if re.search(r"\b(scp|rsync|curl\s+-X\s+POST|aws\s+s3\s+cp)\b", cmd):
        if output and re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", output):
            return post_tool_context("GDPR WARNING: Personal data may be exported outside project")
    return allow()

@registry.hook("check_hipaa_phi")
def check_hipaa_phi(data):
    output = get_command_output(data)
    if not output: return allow()
    phi_patterns = [
        r"(?i)\b(patient|medical|diagnosis|prescription|treatment)\s*(id|name|record|number)\b",
        r"(?i)\bMRN[\s:=#]+\d+",
        r"(?i)\b(ICD-?10|CPT|HCPCS)\s*[-:]?\s*[A-Z0-9]+",
    ]
    for p in phi_patterns:
        if re.search(p, output):
            return post_tool_context("HIPAA WARNING: Protected Health Information (PHI) patterns detected")
    return allow()

@registry.hook("check_hipaa_medical_records")
def check_hipaa_medical_records(data):
    cmd = get_command(data)
    if re.search(r"(?i)(patient|medical|health|clinical)[_-]?(record|data|file)", cmd):
        return post_tool_context("HIPAA WARNING: Command accesses potential medical records")
    return allow()

@registry.hook("check_pci_card_numbers")
def check_pci_card_numbers(data):
    """Detect credit card numbers using Luhn validation."""
    output = get_command_output(data)
    if not output: return allow()
    candidates = re.findall(r"\b(?:\d[ -]*?){13,19}\b", output)
    for candidate in candidates[:20]:
        digits = re.sub(r"[^0-9]", "", candidate)
        if 13 <= len(digits) <= 19:
            total = 0
            for i, d in enumerate(reversed(digits)):
                n = int(d)
                if i % 2 == 1:
                    n *= 2
                    if n > 9: n -= 9
                total += n
            if total % 10 == 0 and digits[:1] in "3456":
                return post_tool_context("PCI-DSS WARNING: Valid credit card number detected in output")
    return allow()

@registry.hook("check_pci_cvv_exposure")
def check_pci_cvv_exposure(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)\b(cvv|cvc|cvv2|cvc2|security.?code)\s*[=:]\s*\d{3,4}\b", output):
        return post_tool_context("PCI-DSS WARNING: CVV/security code detected in output")
    return allow()

@registry.hook("check_pci_track_data")
def check_pci_track_data(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"%B\d{13,19}\^", output):
        return post_tool_context("PCI-DSS CRITICAL: Magnetic stripe track data detected")
    return allow()

@registry.hook("check_sox_audit_trail")
def check_sox_audit_trail(data):
    cmd = get_command(data)
    if re.search(r"(?i)(financial|accounting|revenue|billing|invoice|payment)", cmd):
        return post_tool_context("SOX: Financial data change detected - ensure audit trail is maintained")
    return allow()

@registry.hook("check_ccpa_personal_info")
def check_ccpa_personal_info(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"\b\d{3}-\d{2}-\d{4}\b", output) or re.search(r"(?i)\bdriver'?s?\s*license\b", output):
        return post_tool_context("CCPA WARNING: California consumer personal information detected")
    return allow()

@registry.hook("check_coppa_child_data")
def check_coppa_child_data(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)\b(child|minor|under.?13|kid|juvenile)\s*(name|age|data|account|profile)\b", output):
        return post_tool_context("COPPA WARNING: Potential child data processing detected")
    return allow()

@registry.hook("check_ferpa_education_records")
def check_ferpa_education_records(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)\b(student|pupil|enrollment|transcript|grade|GPA)\s*(id|record|number|data)\b", output):
        return post_tool_context("FERPA WARNING: Education record patterns detected")
    return allow()

@registry.hook("check_license_gpl_compliance")
def check_license_gpl_compliance(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)\bGPL[-v ]*[23]\b", output) or re.search(r"(?i)GNU General Public License", output):
        return post_tool_context("LICENSE: GPL-licensed code detected - ensure license compliance (derivative work must be GPL)")
    return allow()

@registry.hook("check_license_apache_notice")
def check_license_apache_notice(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)Apache License.*Version 2\.0", output):
        return post_tool_context("LICENSE: Apache 2.0 code detected - ensure NOTICE file is maintained")
    return allow()

@registry.hook("check_license_mit_attribution")
def check_license_mit_attribution(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)MIT License", output) and re.search(r"Copyright \(c\)", output):
        return post_tool_context("LICENSE: MIT-licensed code - include copyright notice and license text")
    return allow()

@registry.hook("check_license_agpl_network")
def check_license_agpl_network(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)AGPL|Affero", output):
        return post_tool_context("LICENSE WARNING: AGPL code detected - network use triggers copyleft obligations")
    return allow()

@registry.hook("check_export_control_crypto")
def check_export_control_crypto(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)\b(AES-256|RSA-4096|elliptic.curve|Diffie.Hellman|ECDHE)\b", output):
        return post_tool_context("EXPORT CONTROL: Strong cryptographic code detected - verify export compliance")
    return allow()

@registry.hook("check_data_classification")
def check_data_classification(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)\b(CONFIDENTIAL|RESTRICTED|TOP.?SECRET|CLASSIFIED|INTERNAL.?ONLY)\b", output):
        return post_tool_context("DATA CLASSIFICATION: Classified/restricted data marking detected in output")
    return allow()

@registry.hook("check_encryption_at_rest")
def check_encryption_at_rest(data):
    cmd = get_command(data)
    sensitive = re.search(r"(?i)(password|secret|credential|token|key)", cmd)
    if sensitive and re.search(r">\s*\S+\.(txt|csv|json|log)\b", cmd):
        return post_tool_context("SECURITY: Writing sensitive data to unencrypted file - consider encryption at rest")
    return allow()

@registry.hook("check_data_retention")
def check_data_retention(data):
    cmd = get_command(data)
    if re.search(r"(?i)\b(personal|customer|user)\s*data\b", cmd):
        return post_tool_context("DATA RETENTION: Personal data operation - verify retention policy compliance")
    return allow()

@registry.hook("check_access_logging")
def check_access_logging(data):
    cmd = get_command(data)
    if re.search(r"\b(cat|less|more|head|tail)\s+.*\.(env|key|pem|credentials|secret)", cmd):
        from _lib.utils import log_event
        log_event("access_audit", f"Sensitive file accessed: {cmd[:200]}")
    return allow()

@registry.hook("check_security_headers")
def check_security_headers(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)Content-Security-Policy|X-Frame-Options|Strict-Transport", output):
        return allow()
    if re.search(r"(?i)HTTP/[12]\.?\d?\s+200", output):
        missing = []
        if not re.search(r"(?i)X-Frame-Options", output): missing.append("X-Frame-Options")
        if not re.search(r"(?i)X-Content-Type-Options", output): missing.append("X-Content-Type-Options")
        if not re.search(r"(?i)Strict-Transport-Security", output): missing.append("HSTS")
        if missing:
            return post_tool_context(f"SECURITY: Missing headers: {', '.join(missing)}")
    return allow()

@registry.hook("check_cors_policy")
def check_cors_policy(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)Access-Control-Allow-Origin:\s*\*", output):
        return post_tool_context("SECURITY: Overly permissive CORS policy (Access-Control-Allow-Origin: *)")
    return allow()

@registry.hook("check_cookie_security")
def check_cookie_security(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)Set-Cookie:", output):
        issues = []
        if not re.search(r"(?i)HttpOnly", output): issues.append("HttpOnly")
        if not re.search(r"(?i)Secure", output): issues.append("Secure")
        if not re.search(r"(?i)SameSite", output): issues.append("SameSite")
        if issues:
            return post_tool_context(f"SECURITY: Cookie missing attributes: {', '.join(issues)}")
    return allow()

@registry.hook("check_tls_version")
def check_tls_version(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)(TLSv1\.0|TLSv1\.1|SSLv[23])", output):
        return post_tool_context("SECURITY: Deprecated TLS/SSL version detected (use TLS 1.2+)")
    return allow()

@registry.hook("check_password_hashing")
def check_password_hashing(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"(?i)\b(md5|sha1)\s*\(\s*password", output):
        return post_tool_context("SECURITY: Weak password hashing (MD5/SHA1) - use bcrypt/scrypt/argon2")
    if re.search(r"(?i)hashlib\.(md5|sha1)\b", output):
        return post_tool_context("SECURITY: MD5/SHA1 usage detected - not suitable for password hashing")
    return allow()


if __name__ == "__main__":
    registry.main()
