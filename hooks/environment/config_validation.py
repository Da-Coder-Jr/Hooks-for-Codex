#!/usr/bin/env python3
"""Hooks for configuration file validation - JSON, YAML, TOML, and tool-specific configs."""
import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import (
    HookRegistry, allow, post_tool_context, session_context,
    get_command, get_command_output, get_cwd
)
from _lib.utils import read_file_safe, file_exists

registry = HookRegistry()


def _try_parse_json(content):
    """Try to parse JSON and return (parsed, error_msg)."""
    try:
        return json.loads(content), None
    except json.JSONDecodeError as e:
        return None, f"Line {e.lineno}, column {e.colno}: {e.msg}"


def _try_parse_yaml(content):
    """Try to parse YAML and return (parsed, error_msg)."""
    try:
        import yaml
        return yaml.safe_load(content), None
    except ImportError:
        # Fallback: basic YAML syntax checking without the library
        issues = []
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if "\t" in line and not line.strip().startswith("#"):
                issues.append(f"Line {i}: YAML does not allow tabs for indentation")
            if line.rstrip() != line.rstrip("\n") and line.strip() and re.search(r':\s*$', line):
                pass  # Just a key with no value, that's fine
        if issues:
            return None, "; ".join(issues[:3])
        return {"_parsed": "basic"}, None
    except Exception as e:
        return None, str(e)[:200]


def _try_parse_toml(content):
    """Try to parse TOML and return (parsed, error_msg)."""
    try:
        import tomllib
        return tomllib.loads(content), None
    except ImportError:
        try:
            import tomli
            return tomli.loads(content), None
        except ImportError:
            # Basic TOML checking without library
            issues = []
            lines = content.split("\n")
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Check for basic section headers
                if line.startswith("[") and not line.endswith("]"):
                    if "]" not in line:
                        issues.append(f"Line {i}: Unclosed section header")
                # Check for key-value pairs
                if "=" in line and not line.startswith("["):
                    key, _, value = line.partition("=")
                    value = value.strip()
                    if value.startswith('"') and not value.endswith('"'):
                        issues.append(f"Line {i}: Unclosed string value")
            if issues:
                return None, "; ".join(issues[:3])
            return {"_parsed": "basic"}, None
    except Exception as e:
        return None, str(e)[:200]


def _get_edited_file(command, cwd):
    """Extract the file being edited from a command."""
    # Common edit patterns
    paths = re.findall(r'(?:^|\s)((?:[./]|~)?\S+\.(?:json|yaml|yml|toml|env|config|rc))\b', command)
    if paths:
        for p in paths:
            full = os.path.join(cwd, p) if not os.path.isabs(p) else p
            if os.path.isfile(full):
                return full
    return None


@registry.hook("config_validate_json")
def config_validate_json(data):
    """Validate JSON config file syntax."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    # Check if we edited a JSON file
    edited_file = _get_edited_file(command, cwd)
    if not edited_file or not edited_file.endswith('.json'):
        # Also check output for JSON parse errors
        if re.search(r'SyntaxError.*JSON|JSON\.parse|Unexpected token.*JSON|json\.decoder\.JSONDecodeError', output):
            m = re.search(r'(?:in|at)\s+([\w./]+\.json)', output)
            if m:
                fpath = os.path.join(cwd, m.group(1))
                if os.path.isfile(fpath):
                    edited_file = fpath
        if not edited_file:
            return allow()
    content = read_file_safe(edited_file)
    if not content.strip():
        return allow()
    parsed, error = _try_parse_json(content)
    if error:
        return post_tool_context(
            f"JSON SYNTAX ERROR in {os.path.basename(edited_file)}: {error}. "
            "Check for: trailing commas, missing quotes, or unescaped characters."
        )
    return allow()


@registry.hook("config_validate_yaml")
def config_validate_yaml(data):
    """Validate YAML config file syntax."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    edited_file = _get_edited_file(command, cwd)
    if not edited_file or not re.search(r'\.(ya?ml)$', edited_file):
        if re.search(r'yaml.*(?:error|invalid)|YAML.*(?:parse|scan)', output, re.IGNORECASE):
            m = re.search(r'(?:in|at|file)\s+"?([\w./]+\.ya?ml)"?', output)
            if m:
                fpath = os.path.join(cwd, m.group(1))
                if os.path.isfile(fpath):
                    edited_file = fpath
        if not edited_file:
            return allow()
    content = read_file_safe(edited_file)
    if not content.strip():
        return allow()
    parsed, error = _try_parse_yaml(content)
    if error:
        return post_tool_context(
            f"YAML SYNTAX ERROR in {os.path.basename(edited_file)}: {error}. "
            "Common issues: tabs instead of spaces, incorrect indentation, unquoted special characters."
        )
    return allow()


@registry.hook("config_validate_toml")
def config_validate_toml(data):
    """Validate TOML config file syntax."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    edited_file = _get_edited_file(command, cwd)
    if not edited_file or not edited_file.endswith('.toml'):
        if re.search(r'toml.*(?:error|invalid)|TOML.*parse', output, re.IGNORECASE):
            m = re.search(r'(?:in|at|file)\s+"?([\w./]+\.toml)"?', output)
            if m:
                fpath = os.path.join(cwd, m.group(1))
                if os.path.isfile(fpath):
                    edited_file = fpath
        if not edited_file:
            return allow()
    content = read_file_safe(edited_file)
    if not content.strip():
        return allow()
    parsed, error = _try_parse_toml(content)
    if error:
        return post_tool_context(
            f"TOML SYNTAX ERROR in {os.path.basename(edited_file)}: {error}. "
            "Check for: unclosed quotes, invalid section headers, or duplicate keys."
        )
    return allow()


@registry.hook("config_validate_env_file")
def config_validate_env_file(data):
    """Validate .env file format."""
    command = get_command(data)
    cwd = get_cwd(data)
    edited_file = _get_edited_file(command, cwd)
    if not edited_file:
        # Check common .env paths
        for name in [".env", ".env.local", ".env.development", ".env.test"]:
            if name in command:
                path = os.path.join(cwd, name)
                if os.path.isfile(path):
                    edited_file = path
                    break
    if not edited_file or not os.path.basename(edited_file).startswith('.env'):
        return allow()
    content = read_file_safe(edited_file)
    if not content.strip():
        return allow()
    issues = []
    seen_keys = {}
    for i, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            issues.append(f"Line {i}: Not a valid key=value pair")
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        # Duplicate check
        if key in seen_keys:
            issues.append(f"Line {i}: Duplicate key '{key}' (first at line {seen_keys[key]})")
        seen_keys[key] = i
        # Check for common mistakes
        if key.startswith("export "):
            issues.append(f"Line {i}: Remove 'export' prefix (not needed in .env files)")
        if value.strip().startswith("$") and not value.strip().startswith("${"):
            issues.append(f"Line {i}: Variable reference '{value.strip()[:20]}' - use ${{VAR}} syntax for interpolation")
    if issues:
        return post_tool_context(
            f"ENV FILE ISSUES in {os.path.basename(edited_file)}:\n"
            + "\n".join(f"  - {i}" for i in issues[:8])
        )
    return allow()


@registry.hook("config_validate_package_json")
def config_validate_package_json(data):
    """Validate package.json required fields."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    pkg_path = os.path.join(cwd, "package.json")
    if not os.path.isfile(pkg_path):
        return allow()
    # Only check if package.json was edited or npm/yarn had issues
    if not re.search(r'package\.json|npm|yarn|pnpm', command + " " + output):
        return allow()
    content = read_file_safe(pkg_path)
    parsed, error = _try_parse_json(content)
    if error:
        return post_tool_context(f"PACKAGE.JSON SYNTAX ERROR: {error}")
    if not isinstance(parsed, dict):
        return post_tool_context("PACKAGE.JSON ERROR: Root must be a JSON object")
    issues = []
    # Check required fields
    if "name" not in parsed:
        issues.append("Missing 'name' field")
    elif not re.match(r'^(@[\w-]+/)?[\w.-]+$', parsed["name"]):
        issues.append(f"Invalid package name: '{parsed['name']}'")
    if "version" not in parsed:
        issues.append("Missing 'version' field")
    elif not re.match(r'^\d+\.\d+\.\d+', str(parsed.get("version", ""))):
        issues.append(f"Invalid semver version: '{parsed.get('version')}'")
    # Check for common issues
    if "main" in parsed and not os.path.isfile(os.path.join(cwd, parsed["main"])):
        issues.append(f"'main' entry point '{parsed['main']}' does not exist")
    if "scripts" in parsed and not isinstance(parsed["scripts"], dict):
        issues.append("'scripts' must be an object")
    # Check for duplicate dependencies
    deps = set(parsed.get("dependencies", {}).keys())
    dev_deps = set(parsed.get("devDependencies", {}).keys())
    overlap = deps & dev_deps
    if overlap:
        issues.append(f"Packages in both dependencies and devDependencies: {', '.join(list(overlap)[:3])}")
    if issues:
        return post_tool_context(
            "PACKAGE.JSON ISSUES:\n" + "\n".join(f"  - {i}" for i in issues[:8])
        )
    return allow()


@registry.hook("config_validate_tsconfig")
def config_validate_tsconfig(data):
    """Validate tsconfig.json settings."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    tsconfig_path = os.path.join(cwd, "tsconfig.json")
    if not os.path.isfile(tsconfig_path):
        return allow()
    if not re.search(r'tsconfig|tsc|typescript', command + " " + output, re.IGNORECASE):
        return allow()
    content = read_file_safe(tsconfig_path)
    # tsconfig may have comments, strip them for parsing
    stripped = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
    stripped = re.sub(r'/\*.*?\*/', '', stripped, flags=re.DOTALL)
    # Also strip trailing commas (common in tsconfig)
    stripped = re.sub(r',(\s*[}\]])', r'\1', stripped)
    parsed, error = _try_parse_json(stripped)
    if error:
        return post_tool_context(f"TSCONFIG.JSON SYNTAX ERROR: {error}")
    if not isinstance(parsed, dict):
        return allow()
    issues = []
    compiler_opts = parsed.get("compilerOptions", {})
    # Check for recommended settings
    if compiler_opts.get("strict") is not True:
        issues.append("'strict' mode is not enabled - recommended for type safety")
    if "outDir" not in compiler_opts and "noEmit" not in compiler_opts:
        issues.append("Neither 'outDir' nor 'noEmit' specified - compiled files may clutter source")
    if compiler_opts.get("skipLibCheck") is True:
        issues.append("'skipLibCheck' is true - type errors in dependencies won't be caught")
    # Check target
    target = compiler_opts.get("target", "").lower()
    if target in ("es3", "es5"):
        issues.append(f"Target '{target}' is outdated - consider 'es2020' or newer unless supporting legacy browsers")
    if issues:
        return post_tool_context(
            "TSCONFIG SUGGESTIONS:\n" + "\n".join(f"  - {i}" for i in issues[:5])
        )
    return allow()


@registry.hook("config_validate_eslint")
def config_validate_eslint(data):
    """Validate ESLint configuration."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    # Find eslint config
    eslint_files = [".eslintrc.json", ".eslintrc.js", ".eslintrc.yml", ".eslintrc.yaml", ".eslintrc", "eslint.config.js", "eslint.config.mjs"]
    config_path = None
    for fname in eslint_files:
        fpath = os.path.join(cwd, fname)
        if os.path.isfile(fpath):
            config_path = fpath
            break
    if not config_path:
        return allow()
    if not re.search(r'eslint', command + " " + output, re.IGNORECASE):
        return allow()
    # Check for ESLint errors in output
    if re.search(r'ESLint couldn.t find.*config|Configuration.*invalid|Failed to load config', output):
        return post_tool_context(
            "ESLINT CONFIG ERROR: ESLint configuration is invalid or cannot be found. "
            "Check the config file syntax and ensure all referenced plugins/configs are installed."
        )
    # If it's JSON, validate
    if config_path.endswith('.json'):
        content = read_file_safe(config_path)
        parsed, error = _try_parse_json(content)
        if error:
            return post_tool_context(f"ESLINT CONFIG JSON ERROR: {error}")
        if isinstance(parsed, dict):
            issues = []
            if not parsed.get("extends") and not parsed.get("rules"):
                issues.append("No 'extends' or 'rules' defined - config has no effect")
            if issues:
                return post_tool_context(
                    "ESLINT CONFIG ISSUES:\n" + "\n".join(f"  - {i}" for i in issues)
                )
    return allow()


@registry.hook("config_validate_prettier")
def config_validate_prettier(data):
    """Validate Prettier configuration."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    prettier_files = [".prettierrc", ".prettierrc.json", ".prettierrc.yml", ".prettierrc.yaml",
                      ".prettierrc.js", ".prettierrc.toml", "prettier.config.js"]
    config_path = None
    for fname in prettier_files:
        fpath = os.path.join(cwd, fname)
        if os.path.isfile(fpath):
            config_path = fpath
            break
    if not config_path or not re.search(r'prettier', command + " " + output, re.IGNORECASE):
        return allow()
    if config_path.endswith('.json') or config_path.endswith('.prettierrc'):
        content = read_file_safe(config_path)
        if content.strip():
            parsed, error = _try_parse_json(content)
            if error:
                return post_tool_context(f"PRETTIER CONFIG ERROR: {error}")
            if isinstance(parsed, dict):
                valid_options = {
                    "printWidth", "tabWidth", "useTabs", "semi", "singleQuote",
                    "quoteProps", "jsxSingleQuote", "trailingComma", "bracketSpacing",
                    "bracketSameLine", "arrowParens", "proseWrap", "htmlWhitespaceSensitivity",
                    "endOfLine", "singleAttributePerLine", "overrides", "plugins",
                }
                unknown = set(parsed.keys()) - valid_options
                if unknown:
                    return post_tool_context(
                        f"PRETTIER CONFIG: Unknown options: {', '.join(unknown)}. "
                        "These will be ignored by Prettier."
                    )
    return allow()


@registry.hook("config_validate_docker_compose")
def config_validate_docker_compose(data):
    """Validate docker-compose.yml."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    compose_path = None
    for fname in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
        fpath = os.path.join(cwd, fname)
        if os.path.isfile(fpath):
            compose_path = fpath
            break
    if not compose_path:
        return allow()
    if not re.search(r'docker|compose', command + " " + output, re.IGNORECASE):
        return allow()
    content = read_file_safe(compose_path)
    parsed, error = _try_parse_yaml(content)
    if error:
        return post_tool_context(f"DOCKER-COMPOSE YAML ERROR: {error}")
    if not isinstance(parsed, dict):
        return allow()
    issues = []
    # Check version (deprecated in v2)
    if "version" in parsed:
        issues.append("'version' key is obsolete in Docker Compose V2 and can be removed")
    # Check services
    services = parsed.get("services", {})
    if not services:
        issues.append("No services defined")
    elif isinstance(services, dict):
        for name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            if "image" not in svc and "build" not in svc:
                issues.append(f"Service '{name}': needs either 'image' or 'build'")
            # Check for hardcoded ports on privileged range
            ports = svc.get("ports", [])
            for p in ports:
                p_str = str(p)
                m = re.match(r'^(\d+):', p_str)
                if m and int(m.group(1)) < 1024:
                    issues.append(f"Service '{name}': host port {m.group(1)} is privileged (< 1024)")
    if issues:
        return post_tool_context(
            "DOCKER-COMPOSE ISSUES:\n" + "\n".join(f"  - {i}" for i in issues[:5])
        )
    return allow()


@registry.hook("config_validate_github_actions")
def config_validate_github_actions(data):
    """Validate GitHub Actions workflow files."""
    command = get_command(data)
    output = get_command_output(data)
    cwd = get_cwd(data)
    workflows_dir = os.path.join(cwd, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return allow()
    if not re.search(r'github|workflow|action|\.yml|\.yaml', command + " " + output, re.IGNORECASE):
        return allow()
    issues = []
    try:
        for fname in os.listdir(workflows_dir):
            if not fname.endswith(('.yml', '.yaml')):
                continue
            fpath = os.path.join(workflows_dir, fname)
            content = read_file_safe(fpath)
            if not content:
                continue
            parsed, error = _try_parse_yaml(content)
            if error:
                issues.append(f"{fname}: YAML error - {error}")
                continue
            if not isinstance(parsed, dict):
                continue
            # Check required fields
            if "on" not in parsed and True not in parsed:
                issues.append(f"{fname}: Missing 'on' trigger")
            if "jobs" not in parsed:
                issues.append(f"{fname}: Missing 'jobs' section")
            elif isinstance(parsed.get("jobs"), dict):
                for job_name, job in parsed["jobs"].items():
                    if not isinstance(job, dict):
                        continue
                    if "runs-on" not in job:
                        issues.append(f"{fname}: Job '{job_name}' missing 'runs-on'")
                    if "steps" not in job:
                        issues.append(f"{fname}: Job '{job_name}' has no steps")
                    # Check for pinned actions
                    steps = job.get("steps", [])
                    if isinstance(steps, list):
                        for step in steps:
                            if isinstance(step, dict) and "uses" in step:
                                action = step["uses"]
                                if "@" not in str(action):
                                    issues.append(f"{fname}: Action '{action}' not version-pinned")
    except OSError:
        pass
    if issues:
        return post_tool_context(
            "GITHUB ACTIONS ISSUES:\n" + "\n".join(f"  - {i}" for i in issues[:8])
        )
    return allow()


@registry.hook("config_validate_gitignore")
def config_validate_gitignore(data):
    """Check .gitignore covers common patterns."""
    cwd = get_cwd(data)
    command = get_command(data)
    gitignore_path = os.path.join(cwd, ".gitignore")
    if not os.path.isfile(gitignore_path):
        return allow()
    if not re.search(r'\.gitignore|git\s+add|git\s+status', command):
        return allow()
    content = read_file_safe(gitignore_path)
    patterns = set(content.split("\n"))
    missing = []
    # Check for common patterns based on project files
    critical_patterns = {
        ".env": [".env", ".env.local", ".env*.local"],
        "node_modules": ["node_modules", "node_modules/"],
        ".DS_Store": [".DS_Store"],
    }
    # Always check these
    for name, alts in critical_patterns.items():
        if not any(alt in patterns for alt in alts):
            if name == "node_modules" and os.path.isfile(os.path.join(cwd, "package.json")):
                missing.append(name)
            elif name == ".env" and any(
                os.path.isfile(os.path.join(cwd, f))
                for f in [".env", ".env.local", ".env.example"]
            ):
                missing.append(name)
            elif name == ".DS_Store":
                missing.append(name)
    # Project-specific checks
    if os.path.isfile(os.path.join(cwd, "Cargo.toml")):
        if "target" not in content and "target/" not in content:
            missing.append("target/")
    if os.path.isfile(os.path.join(cwd, "go.mod")):
        # Go binaries - less standard but useful
        pass
    if os.path.isfile(os.path.join(cwd, "requirements.txt")) or os.path.isfile(os.path.join(cwd, "pyproject.toml")):
        venv_patterns = ["venv", ".venv", "__pycache__", "*.pyc"]
        for vp in venv_patterns:
            if vp not in content:
                missing.append(vp)
    if missing:
        return post_tool_context(
            "GITIGNORE: Missing common patterns:\n"
            + "\n".join(f"  - {m}" for m in missing[:8])
            + "\nAdd these to .gitignore to avoid committing generated/sensitive files."
        )
    return allow()


@registry.hook("config_validate_editorconfig")
def config_validate_editorconfig(data):
    """Validate .editorconfig settings."""
    cwd = get_cwd(data)
    command = get_command(data)
    ec_path = os.path.join(cwd, ".editorconfig")
    if not os.path.isfile(ec_path):
        return allow()
    if ".editorconfig" not in command:
        return allow()
    content = read_file_safe(ec_path)
    issues = []
    valid_properties = {
        "root", "indent_style", "indent_size", "tab_width",
        "end_of_line", "charset", "trim_trailing_whitespace",
        "insert_final_newline", "max_line_length",
    }
    valid_indent_styles = {"tab", "space"}
    valid_end_of_line = {"lf", "cr", "crlf"}
    valid_charsets = {"utf-8", "utf-8-bom", "utf-16be", "utf-16le", "latin1"}
    has_root = False
    current_section = None
    for i, line in enumerate(content.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # Section header
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
            continue
        # Key-value pair
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip().lower()
            value = value.strip().lower()
            if key == "root":
                has_root = True
                if value not in ("true", "false"):
                    issues.append(f"Line {i}: 'root' must be 'true' or 'false'")
            elif key == "indent_style" and value not in valid_indent_styles:
                issues.append(f"Line {i}: invalid indent_style '{value}' (use 'tab' or 'space')")
            elif key == "end_of_line" and value not in valid_end_of_line:
                issues.append(f"Line {i}: invalid end_of_line '{value}'")
            elif key == "charset" and value not in valid_charsets:
                issues.append(f"Line {i}: invalid charset '{value}'")
            elif key == "indent_size":
                if value != "tab" and not value.isdigit():
                    issues.append(f"Line {i}: indent_size must be a number or 'tab'")
    if not has_root:
        issues.append("Missing 'root = true' at the top of the file")
    if issues:
        return post_tool_context(
            "EDITORCONFIG ISSUES:\n" + "\n".join(f"  - {i}" for i in issues[:5])
        )
    return allow()


if __name__ == "__main__":
    registry.main()
