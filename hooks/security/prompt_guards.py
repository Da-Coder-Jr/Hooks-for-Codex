#!/usr/bin/env python3
"""
Security: Prompt Guard hooks for Codex.
15 UserPromptSubmit hooks that guard user prompts.
"""

import json
import re
import sys
import os
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, block_prompt, get_prompt

registry = HookRegistry()


@registry.hook("block_prompt_secrets")
def block_prompt_secrets(data):
    prompt = get_prompt(data)
    patterns = [
        (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9/+=_-]{16,}", "API key"),
        (r"(?i)(password|passwd)\s*[=:]\s*['\"]?\S{8,}", "password"),
        (r"sk-[A-Za-z0-9]{20,}", "OpenAI key"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
        (r"AKIA[0-9A-Z]{16}", "AWS key"),
    ]
    for p, name in patterns:
        if re.search(p, prompt):
            return block_prompt(f"Blocked: prompt contains a {name}")
    return allow()

@registry.hook("block_prompt_ssn")
def block_prompt_ssn(data):
    prompt = get_prompt(data)
    ssns = re.findall(r"\b\d{3}-\d{2}-\d{4}\b", prompt)
    valid = [s for s in ssns if not s.startswith("000") and not s.startswith("666") and s[0:3] != "900"]
    if len(valid) >= 1:
        return block_prompt("Blocked: prompt contains what appears to be a Social Security Number")
    return allow()

@registry.hook("block_prompt_credit_card")
def block_prompt_credit_card(data):
    prompt = get_prompt(data)
    candidates = re.findall(r"\b(?:\d[ -]*?){13,19}\b", prompt)
    for candidate in candidates[:10]:
        digits = re.sub(r"[^0-9]", "", candidate)
        if 13 <= len(digits) <= 19 and digits[0] in "3456":
            total = 0
            for i, d in enumerate(reversed(digits)):
                n = int(d)
                if i % 2 == 1:
                    n *= 2
                    if n > 9: n -= 9
                total += n
            if total % 10 == 0:
                return block_prompt("Blocked: prompt contains a credit card number")
    return allow()

@registry.hook("block_prompt_private_key")
def block_prompt_private_key(data):
    prompt = get_prompt(data)
    if re.search(r"-----BEGIN (RSA |OPENSSH |EC |DSA |ED25519 |PGP )?PRIVATE KEY", prompt):
        return block_prompt("Blocked: prompt contains a private key")
    return allow()

@registry.hook("block_prompt_connection_string")
def block_prompt_connection_string(data):
    prompt = get_prompt(data)
    if re.search(r"(?i)(postgres|mysql|mongodb|redis|mssql)://\S+:\S+@\S+", prompt):
        return block_prompt("Blocked: prompt contains a database connection string with credentials")
    return allow()

@registry.hook("block_prompt_injection_ignore")
def block_prompt_injection_ignore(data):
    prompt = get_prompt(data)
    if re.search(r"(?i)ignore\s+(all\s+)?previous\s+(instructions|context|rules)", prompt):
        return block_prompt("Blocked: prompt injection detected (ignore previous instructions)")
    if re.search(r"(?i)disregard\s+(all\s+)?(above|previous|prior)\s+(instructions|text|context)", prompt):
        return block_prompt("Blocked: prompt injection detected (disregard previous)")
    return allow()

@registry.hook("block_prompt_injection_system")
def block_prompt_injection_system(data):
    prompt = get_prompt(data)
    if re.search(r"(?i)system\s*:\s*you\s+are\s+(now\s+)?(a|an|in|the)\s+", prompt):
        return block_prompt("Blocked: prompt injection (system role override)")
    if re.search(r"(?i)new\s+system\s+prompt\s*:", prompt):
        return block_prompt("Blocked: prompt injection (new system prompt)")
    return allow()

@registry.hook("block_prompt_injection_jailbreak")
def block_prompt_injection_jailbreak(data):
    prompt = get_prompt(data)
    if re.search(r"(?i)\bjailbreak\b", prompt):
        return block_prompt("Blocked: jailbreak attempt detected")
    if re.search(r"(?i)override\s+(safety|security|rules|guidelines|restrictions)", prompt):
        return block_prompt("Blocked: attempt to override safety guidelines")
    if re.search(r"(?i)developer\s+mode\s+(enabled|activated|on)", prompt):
        return block_prompt("Blocked: fake developer mode activation")
    return allow()

@registry.hook("block_prompt_injection_roleplay")
def block_prompt_injection_roleplay(data):
    prompt = get_prompt(data)
    if re.search(r"(?i)pretend\s+(you'?re|to\s+be)\s+(a|an)\s+", prompt):
        if re.search(r"(?i)(unrestricted|unfiltered|evil|malicious|hacker)", prompt):
            return block_prompt("Blocked: malicious roleplay injection")
    if re.search(r"(?i)act\s+as\s+(if|though)\s+you\s+have\s+no\s+(restrictions|rules|limits)", prompt):
        return block_prompt("Blocked: restriction bypass roleplay")
    return allow()

@registry.hook("block_prompt_injection_encoding")
def block_prompt_injection_encoding(data):
    prompt = get_prompt(data)
    b64_chunks = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", prompt)
    for chunk in b64_chunks[:5]:
        try:
            decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
            if re.search(r"(?i)(ignore|disregard|override|system\s*:)", decoded):
                return block_prompt("Blocked: base64-encoded prompt injection detected")
        except Exception:
            pass
    return allow()

@registry.hook("block_prompt_pii_email_bulk")
def block_prompt_pii_email_bulk(data):
    prompt = get_prompt(data)
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", prompt)
    if len(emails) > 10:
        return block_prompt(f"Blocked: prompt contains {len(emails)} email addresses (bulk PII)")
    return allow()

@registry.hook("block_prompt_pii_phone")
def block_prompt_pii_phone(data):
    prompt = get_prompt(data)
    phones = re.findall(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", prompt)
    if len(phones) > 5:
        return block_prompt(f"Blocked: prompt contains {len(phones)} phone numbers (bulk PII)")
    return allow()

@registry.hook("block_prompt_excessive_length")
def block_prompt_excessive_length(data):
    prompt = get_prompt(data)
    if len(prompt) > 50000:
        return block_prompt(f"Blocked: prompt is excessively long ({len(prompt)} chars, max 50000)")
    return allow()

@registry.hook("block_prompt_binary_content")
def block_prompt_binary_content(data):
    prompt = get_prompt(data)
    non_printable = sum(1 for c in prompt if ord(c) < 32 and c not in "\n\r\t")
    if non_printable > len(prompt) * 0.1 and non_printable > 50:
        return block_prompt("Blocked: prompt contains significant non-printable/binary content")
    return allow()

@registry.hook("block_prompt_url_shortener")
def block_prompt_url_shortener(data):
    prompt = get_prompt(data)
    shorteners = r"https?://(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|adf\.ly|cutt\.ly)/\S+"
    if re.search(shorteners, prompt):
        return block_prompt("Warning: shortened URL detected in prompt (could be malicious)")
    return allow()


if __name__ == "__main__":
    registry.main()
