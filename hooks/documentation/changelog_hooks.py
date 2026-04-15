#!/usr/bin/env python3
"""Documentation: Changelog and versioning hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("detect_missing_changelog")
def detect_missing_changelog(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bls\b", cmd) or not output: return allow()
    if re.search(r"package\.json|setup\.py|Cargo\.toml", output):
        if not re.search(r"CHANGELOG|CHANGES|HISTORY|NEWS", output, re.IGNORECASE):
            return post_tool_context("Docs: No CHANGELOG found. Track changes with CHANGELOG.md (Keep a Changelog format).")
    return allow()

@registry.hook("check_changelog_format")
def check_changelog_format(data):
    output = get_command_output(data)
    if not output or not re.search(r"CHANGELOG", get_command(data), re.IGNORECASE): return allow()
    issues = []
    if not re.search(r"## \[?\d+\.\d+\.\d+\]?|## \[?Unreleased\]?", output): issues.append("no semver headings")
    if not re.search(r"### (?:Added|Changed|Deprecated|Removed|Fixed|Security)", output): issues.append("no category sections")
    if issues:
        return post_tool_context(f"Changelog: Format issues: {', '.join(issues)}. Follow keepachangelog.com.")
    return allow()

@registry.hook("detect_version_mismatch")
def detect_version_mismatch(data):
    output = get_command_output(data)
    if not output: return allow()
    versions = re.findall(r'"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)"', output)
    if len(set(versions)) > 1:
        return post_tool_context(f"Version mismatch: Found multiple versions: {', '.join(set(versions))}. Sync version numbers.")
    return allow()

@registry.hook("check_semver_compliance")
def check_semver_compliance(data):
    output = get_command_output(data)
    if not output: return allow()
    match = re.search(r'"version"\s*:\s*"([^"]+)"', output)
    if match:
        ver = match.group(1)
        if not re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$", ver):
            return post_tool_context(f"Version: '{ver}' doesn't follow semver. Use MAJOR.MINOR.PATCH format.")
    return allow()

@registry.hook("detect_unreleased_changes")
def detect_unreleased_changes(data):
    output = get_command_output(data)
    if not output or not re.search(r"CHANGELOG", get_command(data), re.IGNORECASE): return allow()
    if re.search(r"## \[?Unreleased\]?", output):
        unreleased = re.findall(r"(?:## \[?Unreleased\]?)([\s\S]*?)(?=## \[?\d+|\Z)", output)
        if unreleased and len(unreleased[0].strip()) > 50:
            entries = len(re.findall(r"^- ", unreleased[0], re.MULTILINE))
            return post_tool_context(f"Changelog: {entries} unreleased entries. Consider releasing a new version.")
    return allow()

@registry.hook("check_npm_version_bump")
def check_npm_version_bump(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"npm\s+version", cmd) or not output: return allow()
    match = re.search(r"v?(\d+\.\d+\.\d+)", output)
    if match:
        return post_tool_context(f"npm version bumped to {match.group(1)}. Update CHANGELOG and create git tag.")
    return allow()

@registry.hook("detect_breaking_changes")
def detect_breaking_changes(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bgit\s+(log|diff)", cmd) or not output: return allow()
    breaking = re.findall(r"BREAKING CHANGE|breaking:|!:", output, re.IGNORECASE)
    if breaking:
        return post_tool_context(f"Docs: {len(breaking)} breaking changes detected. Requires major version bump.")
    return allow()

@registry.hook("check_migration_guide")
def check_migration_guide(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"BREAKING CHANGE|major.*version|v\d+\.0\.0", output, re.IGNORECASE):
        if not re.search(r"migration|upgrade|MIGRAT", output, re.IGNORECASE):
            return post_tool_context("Docs: Breaking change without migration guide. Document upgrade path.")
    return allow()

@registry.hook("detect_deprecated_api_docs")
def detect_deprecated_api_docs(data):
    output = get_command_output(data)
    if not output: return allow()
    deprecated = re.findall(r"@deprecated|DEPRECATED|:deprecated:", output, re.IGNORECASE)
    if deprecated and not re.search(r"alternative|replacement|use .* instead|migrate to", output, re.IGNORECASE):
        return post_tool_context("Docs: Deprecated items without alternatives. Document replacement APIs.")
    return allow()

@registry.hook("check_release_notes")
def check_release_notes(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"git\s+tag|npm\s+publish|cargo\s+publish", cmd) or not output: return allow()
    if re.search(r"v?\d+\.\d+\.\d+", output):
        return post_tool_context("Release: Ensure release notes are published with the tag/release.")
    return allow()

@registry.hook("detect_conventional_changelog")
def detect_conventional_changelog(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"conventional-changelog|standard-version|semantic-release", cmd) or not output: return allow()
    if re.search(r"CHANGELOG.*generated|wrote.*CHANGELOG", output, re.IGNORECASE):
        return post_tool_context("Docs: Changelog auto-generated. Review before committing.")
    return allow()

@registry.hook("check_contributing_guide")
def check_contributing_guide(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bls\b", cmd) or not output: return allow()
    if re.search(r"CONTRIBUTING|contributing", output):
        return allow()
    if re.search(r"\.github|package\.json|setup\.py", output):
        return post_tool_context("Docs: No CONTRIBUTING.md found. Add guidelines for contributors.")
    return allow()

@registry.hook("detect_doc_build_success")
def detect_doc_build_success(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"mkdocs|sphinx|docusaurus|vuepress|gitbook", cmd) or not output: return allow()
    if re.search(r"build.*success|documentation.*ready|site.*built|Generated.*pages", output, re.IGNORECASE):
        return post_tool_context("Docs: Documentation site built successfully.")
    return allow()

@registry.hook("check_api_versioning")
def check_api_versioning(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"/api/v\d+/|/v\d+/api/", output):
        versions = set(re.findall(r"/(?:api/)?v(\d+)/", output))
        if len(versions) > 1:
            return post_tool_context(f"Docs: Multiple API versions referenced ({', '.join(f'v{v}' for v in sorted(versions))}). Ensure docs cover all.")
    return allow()

@registry.hook("detect_doc_link_rot")
def detect_doc_link_rot(data):
    output = get_command_output(data)
    if not output: return allow()
    external_links = re.findall(r"https?://[^\s)]+", output)
    localhost = [l for l in external_links if re.search(r"localhost|127\.0\.0\.1|0\.0\.0\.0", l)]
    if localhost and re.search(r"\.md$|\.rst$", get_command(data)):
        return post_tool_context(f"Docs: {len(localhost)} localhost URLs in documentation. Replace with actual URLs.")
    return allow()

if __name__ == "__main__":
    registry.main()
