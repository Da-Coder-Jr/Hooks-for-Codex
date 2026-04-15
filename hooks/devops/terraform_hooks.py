#!/usr/bin/env python3
"""DevOps: Terraform/IaC hooks for Codex. 18 PreToolUse/PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("block_terraform_destroy_production")
def block_terraform_destroy_production(data):
    cmd = get_command(data)
    if re.search(r"terraform\s+destroy", cmd):
        if re.search(r"prod|production", cmd, re.IGNORECASE) or re.search(r"-var.*env.*prod", cmd):
            return deny("Terraform: destroy on production is blocked. Use targeted destroys with -target.")
    return allow()

@registry.hook("warn_terraform_apply_no_plan")
def warn_terraform_apply_no_plan(data):
    cmd = get_command(data)
    if re.search(r"terraform\s+apply\s+-auto-approve", cmd):
        return post_tool_context("Terraform: -auto-approve skips review. Run terraform plan first in production.")
    return allow()

@registry.hook("detect_terraform_plan_changes")
def detect_terraform_plan_changes(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"terraform\s+plan", cmd) or not output: return allow()
    match = re.search(r"(\d+) to add, (\d+) to change, (\d+) to destroy", output)
    if match:
        add, change, destroy = match.group(1), match.group(2), match.group(3)
        msg = f"Terraform plan: +{add} ~{change} -{destroy}"
        if int(destroy) > 5:
            msg += " WARNING: Many resources being destroyed!"
        return post_tool_context(msg)
    return allow()

@registry.hook("detect_terraform_errors")
def detect_terraform_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bterraform\b", cmd) or not output: return allow()
    errors = re.findall(r"Error:\s*(.*?)$", output, re.MULTILINE)
    if errors:
        return post_tool_context(f"Terraform: {len(errors)} errors. First: {errors[0][:100]}")
    return allow()

@registry.hook("check_terraform_state_issues")
def check_terraform_state_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"state.*lock|lock.*state|Error locking state|ConflictException", output):
        return post_tool_context("Terraform: State lock conflict. Another operation may be running. Use force-unlock if stuck.")
    return allow()

@registry.hook("detect_terraform_drift")
def detect_terraform_drift(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Objects have changed outside of Terraform|drift detected|has been changed outside of Terraform", output):
        return post_tool_context("Terraform: Infrastructure drift detected. Review changes and run terraform apply to reconcile.")
    return allow()

@registry.hook("check_terraform_provider_issues")
def check_terraform_provider_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"provider.*not found|failed to install provider|Incompatible provider", output):
        return post_tool_context("Terraform: Provider issue. Run terraform init to install/update providers.")
    return allow()

@registry.hook("detect_terraform_sensitive_output")
def detect_terraform_sensitive_output(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"output.*password|output.*secret|output.*token|output.*key", output, re.IGNORECASE):
        if not re.search(r"sensitive\s*=\s*true", output):
            return post_tool_context("Terraform: Sensitive value in output. Mark with sensitive = true.")
    return allow()

@registry.hook("check_terraform_module_source")
def check_terraform_module_source(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r'source\s*=\s*"git::', output) and not re.search(r'\?ref=', output):
        return post_tool_context("Terraform: Module source without version pin. Add ?ref=<tag> for reproducibility.")
    return allow()

@registry.hook("detect_terraform_deprecation")
def detect_terraform_deprecation(data):
    output = get_command_output(data)
    if not output: return allow()
    deps = re.findall(r"Warning:.*deprecated|has been deprecated", output, re.IGNORECASE)
    if deps:
        return post_tool_context(f"Terraform: {len(deps)} deprecation warnings. Update to newer resource/attribute names.")
    return allow()

@registry.hook("block_terraform_state_rm")
def block_terraform_state_rm(data):
    cmd = get_command(data)
    if re.search(r"terraform\s+state\s+rm", cmd):
        return deny("Terraform: state rm removes resources from state without destroying. This can cause orphaned resources.")
    return allow()

@registry.hook("check_terraform_workspace")
def check_terraform_workspace(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"terraform\s+(plan|apply)", cmd) or not output: return allow()
    if re.search(r"workspace.*default|Using workspace.*default", output):
        return post_tool_context("Terraform: Using default workspace. Consider named workspaces for env separation.")
    return allow()

@registry.hook("detect_terraform_cycle")
def detect_terraform_cycle(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Cycle:|circular dependency|cycle.*detected", output, re.IGNORECASE):
        return post_tool_context("Terraform: Dependency cycle detected. Break circular references between resources.")
    return allow()

@registry.hook("check_terraform_backend_config")
def check_terraform_backend_config(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r'backend "local"|no backend configuration', output):
        return post_tool_context("Terraform: Using local backend. Configure remote backend (S3/GCS/Azure) for team collaboration.")
    return allow()

@registry.hook("detect_terraform_count_issues")
def detect_terraform_count_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"The \"count\" value depends on resource attributes|count.*cannot be determined", output):
        return post_tool_context("Terraform: Count depends on computed value. Use for_each with known keys instead.")
    return allow()

@registry.hook("check_terraform_version_constraint")
def check_terraform_version_constraint(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"required_version|version constraint|Unsupported Terraform Core version", output):
        if re.search(r"Unsupported|does not satisfy", output):
            return post_tool_context("Terraform: Version mismatch. Check required_version in terraform block.")
    return allow()

@registry.hook("detect_terraform_data_source_errors")
def detect_terraform_data_source_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"data\.\S+.*Error|No matching.*found|data source.*failed", output, re.IGNORECASE):
        return post_tool_context("Terraform: Data source query failed. Check filters and ensure resource exists.")
    return allow()

@registry.hook("check_terraform_variable_validation")
def check_terraform_variable_validation(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Invalid value for variable|variable validation failed|does not match", output):
        match = re.search(r'variable "(\w+)"', output)
        return post_tool_context(f"Terraform: Variable validation failed{f' for {match.group(1)}' if match else ''}. Check variable constraints.")
    return allow()

if __name__ == "__main__":
    registry.main()
