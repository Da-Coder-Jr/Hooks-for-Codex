#!/usr/bin/env python3
"""Language-Specific: TypeScript hooks for Codex. 18 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("ts_parse_compiler_errors")
def ts_parse_compiler_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\btsc\b", cmd) or not output: return allow()
    errors = re.findall(r"TS(\d+):", output)
    if errors:
        from collections import Counter
        top = Counter(errors).most_common(5)
        return post_tool_context(f"TypeScript: {len(errors)} errors. Top: {', '.join(f'TS{k}({v})' for k,v in top)}")
    return allow()

@registry.hook("ts_detect_any_usage")
def ts_detect_any_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    anys = re.findall(r":\s*any\b|<any>|as\s+any\b", output)
    if len(anys) > 3:
        return post_tool_context(f"TypeScript: {len(anys)} 'any' type usages (weakens type safety)")
    return allow()

@registry.hook("ts_check_strict_mode")
def ts_check_strict_mode(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r'"strict"\s*:\s*false', output) or (re.search(r'"compilerOptions"', output) and not re.search(r'"strict"\s*:\s*true', output)):
        return post_tool_context("TypeScript: strict mode not enabled in tsconfig.json")
    return allow()

@registry.hook("ts_detect_type_assertions")
def ts_detect_type_assertions(data):
    output = get_command_output(data)
    if not output: return allow()
    unsafe = len(re.findall(r"\bas\s+any\b|\bas\s+unknown\b", output))
    if unsafe > 2:
        return post_tool_context(f"TypeScript: {unsafe} unsafe type assertions (as any/unknown)")
    return allow()

@registry.hook("ts_check_null_safety")
def ts_check_null_safety(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"TS2531|TS2532|TS2533", output):
        count = len(re.findall(r"TS253[123]", output))
        return post_tool_context(f"TypeScript: {count} null safety violations. Use optional chaining (?.) or nullish coalescing (??).")
    return allow()

@registry.hook("ts_detect_implicit_any")
def ts_detect_implicit_any(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"TS7006|TS7031", output):
        count = len(re.findall(r"TS700[16]|TS7031", output))
        return post_tool_context(f"TypeScript: {count} implicit 'any' type warnings. Add explicit types.")
    return allow()

@registry.hook("ts_check_enum_usage")
def ts_check_enum_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    enums = len(re.findall(r"\benum\s+\w+", output))
    const_enums = len(re.findall(r"\bconst\s+enum\s+\w+", output))
    if enums > 3 and const_enums == 0:
        return post_tool_context(f"TypeScript: {enums} enums without const. Consider 'const enum' or union types.")
    return allow()

@registry.hook("ts_detect_declaration_errors")
def ts_detect_declaration_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"\.d\.ts.*error|Cannot find type definition", output):
        return post_tool_context("TypeScript: Declaration file (.d.ts) errors. Install @types/* packages.")
    return allow()

@registry.hook("ts_check_module_augmentation")
def ts_check_module_augmentation(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"TS2339.*does not exist on type", output):
        return post_tool_context("TypeScript: Property doesn't exist on type. Use module augmentation or type assertion.")
    return allow()

@registry.hook("ts_detect_generic_issues")
def ts_detect_generic_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"TS2344|TS2322.*generic|Type.*not assignable.*constraint", output):
        return post_tool_context("TypeScript: Generic type constraint violation. Check type parameters.")
    return allow()

@registry.hook("ts_check_decorator_usage")
def ts_check_decorator_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"TS1219|experimentalDecorators", output):
        return post_tool_context("TypeScript: Enable experimentalDecorators in tsconfig.json for decorator support.")
    return allow()

@registry.hook("ts_detect_import_type")
def ts_detect_import_type(data):
    output = get_command_output(data)
    if not output: return allow()
    type_imports = re.findall(r"import\s+\{[^}]*\}\s+from.*(?:type|interface|enum)", output)
    if len(type_imports) > 3:
        return post_tool_context("TypeScript: Consider 'import type' for type-only imports (reduces bundle size)")
    return allow()

@registry.hook("ts_check_readonly_usage")
def ts_check_readonly_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    arrays = len(re.findall(r":\s*\w+\[\]", output))
    readonlys = len(re.findall(r"readonly\s+\w+|ReadonlyArray", output))
    if arrays > 5 and readonlys == 0:
        return post_tool_context("TypeScript: Consider using readonly for immutable arrays/properties")
    return allow()

@registry.hook("ts_detect_union_exhaustiveness")
def ts_detect_union_exhaustiveness(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"TS2345.*not assignable.*never|Exhaustive check", output):
        return post_tool_context("TypeScript: Non-exhaustive union type handling. Add missing case.")
    return allow()

@registry.hook("ts_check_tsconfig_issues")
def ts_check_tsconfig_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"error TS5.*tsconfig|Cannot read.*tsconfig", output):
        return post_tool_context("TypeScript: tsconfig.json validation error. Check configuration syntax.")
    return allow()

@registry.hook("ts_detect_circular_types")
def ts_detect_circular_types(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"TS2456|circular.*referenced|Type.*circularly", output):
        return post_tool_context("TypeScript: Circular type reference detected. Break the cycle with interfaces.")
    return allow()

@registry.hook("ts_check_path_aliases")
def ts_check_path_aliases(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Cannot find module '@/|Cannot find module '~/", output):
        return post_tool_context("TypeScript: Path alias resolution error. Check tsconfig paths and bundler config.")
    return allow()

@registry.hook("ts_detect_migration_issues")
def ts_detect_migration_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    js_to_ts = re.findall(r"\.js.*→.*\.ts|rename.*\.js.*\.ts", output, re.IGNORECASE)
    if js_to_ts:
        return post_tool_context("TypeScript: JS→TS migration detected. Add types incrementally, use allowJs option.")
    return allow()

if __name__ == "__main__":
    registry.main()
