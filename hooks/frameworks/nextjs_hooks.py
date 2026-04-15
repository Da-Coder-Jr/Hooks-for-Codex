#!/usr/bin/env python3
"""Framework-Specific: Next.js hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("nextjs_detect_build_errors")
def nextjs_detect_build_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bnext\s+build\b|npm\s+run\s+build", cmd) or not output: return allow()
    if re.search(r"Build error|Failed to compile", output):
        match = re.search(r"(?:Build error|Error):\s*(.*?)$", output, re.MULTILINE)
        return post_tool_context(f"Next.js build error: {match.group(1)[:100] if match else 'check output'}")
    return allow()

@registry.hook("nextjs_check_page_errors")
def nextjs_check_page_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"is not a valid Page export|page.*must.*default export", output, re.IGNORECASE):
        return post_tool_context("Next.js: Invalid page export. Pages must have a default export.")
    return allow()

@registry.hook("nextjs_detect_api_route_issues")
def nextjs_detect_api_route_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"API resolved without sending a response|api.*handler.*error", output, re.IGNORECASE):
        return post_tool_context("Next.js: API route issue. Ensure handler sends a response (res.json/res.send).")
    return allow()

@registry.hook("nextjs_check_getServerSideProps")
def nextjs_check_getServerSideProps(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"getServerSideProps.*error|getStaticProps.*error|getStaticPaths.*error", output):
        return post_tool_context("Next.js: Data fetching error in getServerSideProps/getStaticProps. Check server-side code.")
    return allow()

@registry.hook("nextjs_detect_hydration_errors")
def nextjs_detect_hydration_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Hydration failed|Text content does not match|hydration mismatch", output, re.IGNORECASE):
        return post_tool_context("Next.js: Hydration mismatch. Server/client HTML differs. Check dynamic content and useEffect.")
    return allow()

@registry.hook("nextjs_check_image_optimization")
def nextjs_check_image_optimization(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"next/image.*error|Image Optimization", output):
        return post_tool_context("Next.js: Image optimization issue. Use next/image with width/height props.")
    return allow()

@registry.hook("nextjs_detect_routing_issues")
def nextjs_detect_routing_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"404|page not found|could not find.*route", output, re.IGNORECASE):
        return post_tool_context("Next.js: Route not found. Check file-based routing in pages/ or app/ directory.")
    return allow()

@registry.hook("nextjs_check_middleware_errors")
def nextjs_check_middleware_errors(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"middleware.*error|Edge.*Runtime.*error", output, re.IGNORECASE):
        return post_tool_context("Next.js: Middleware error. Middleware runs in Edge Runtime (limited Node.js APIs).")
    return allow()

@registry.hook("nextjs_detect_module_issues")
def nextjs_detect_module_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"Module not found|Can't resolve", output):
        match = re.search(r"(?:Module not found|Can't resolve)\s*[':]\s*(\S+)", output)
        return post_tool_context(f"Next.js: Module not found: {match.group(1) if match else 'check imports'}")
    return allow()

@registry.hook("nextjs_check_env_variables")
def nextjs_check_env_variables(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"NEXT_PUBLIC_\w+.*undefined|process\.env\.\w+.*undefined", output):
        return post_tool_context("Next.js: Env variable undefined. Client-side vars need NEXT_PUBLIC_ prefix. Restart dev server after .env changes.")
    return allow()

@registry.hook("nextjs_detect_typescript_errors")
def nextjs_detect_typescript_errors(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"\bnext\s+build\b", cmd) or not output: return allow()
    ts_errors = re.findall(r"Type error:", output)
    if ts_errors:
        return post_tool_context(f"Next.js: {len(ts_errors)} TypeScript errors in build")
    return allow()

@registry.hook("nextjs_check_bundle_analysis")
def nextjs_check_bundle_analysis(data):
    output = get_command_output(data)
    if not output: return allow()
    sizes = re.findall(r"(\S+)\s+(\d+(?:\.\d+)?)\s*(kB|MB)\s", output)
    large = [(name, size, unit) for name, size, unit in sizes if (unit == "MB" and float(size) > 0.5) or (unit == "kB" and float(size) > 200)]
    if large:
        return post_tool_context(f"Next.js: {len(large)} large bundle chunks. Consider code splitting/dynamic imports.")
    return allow()

@registry.hook("nextjs_detect_deployment_issues")
def nextjs_detect_deployment_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"DEPLOYMENT_FAILED|deploy.*error|vercel.*error", output, re.IGNORECASE):
        return post_tool_context("Next.js: Deployment error. Check build output and environment configuration.")
    return allow()

@registry.hook("nextjs_check_seo")
def nextjs_check_seo(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"<head>|<Head>", output):
        issues = []
        if not re.search(r"<title>", output, re.IGNORECASE): issues.append("title")
        if not re.search(r'meta.*description', output, re.IGNORECASE): issues.append("meta description")
        if not re.search(r'meta.*viewport', output, re.IGNORECASE): issues.append("viewport")
        if issues:
            return post_tool_context(f"Next.js SEO: Missing {', '.join(issues)} in <Head>")
    return allow()

@registry.hook("nextjs_detect_performance_issues")
def nextjs_detect_performance_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"First Load JS.*(?:red|(\d{3,}) kB)", output):
        return post_tool_context("Next.js: Large First Load JS. Optimize with dynamic imports and tree shaking.")
    return allow()

if __name__ == "__main__":
    registry.main()
