#!/usr/bin/env python3
"""Performance: Bundle size and asset optimization hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("check_npm_package_size")
def check_npm_package_size(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"npm\s+pack|npm\s+publish\s+--dry-run|bundlephobia|size-limit", cmd) or not output: return allow()
    match = re.search(r"package size:\s*([\d.]+)\s*(kB|MB|B)", output, re.IGNORECASE)
    if match:
        size, unit = float(match.group(1)), match.group(2)
        if unit == "MB" or (unit == "kB" and size > 500):
            return post_tool_context(f"Bundle: Package size {size}{unit} is large. Check for unnecessary files in package.")
    return allow()

@registry.hook("detect_large_dependencies")
def detect_large_dependencies(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"npm\s+ls|yarn\s+list|pnpm\s+list", get_command(data)):
        large = re.findall(r"(\S+)@\S+\s+.*?(\d+(?:\.\d+)?)\s*MB", output)
        if large:
            names = ", ".join(f"{n}({s}MB)" for n, s in large[:5])
            return post_tool_context(f"Bundle: Large dependencies: {names}")
    return allow()

@registry.hook("check_tree_shaking")
def check_tree_shaking(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"sideEffects.*false|\"sideEffects\"", output):
        return allow()
    if re.search(r"import\s+\*\s+as|require\(", output):
        namespace_imports = len(re.findall(r"import\s+\*\s+as", output))
        if namespace_imports > 3:
            return post_tool_context(f"Bundle: {namespace_imports} namespace imports (import *). Use named imports for tree-shaking.")
    return allow()

@registry.hook("detect_duplicate_packages")
def detect_duplicate_packages(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"npm\s+dedupe|yarn.*deduplicate|duplicate.*package", get_command(data), re.IGNORECASE):
        dupes = re.findall(r"(\S+)@\S+.*duplicate", output, re.IGNORECASE)
        if dupes:
            return post_tool_context(f"Bundle: {len(dupes)} duplicate packages. Run npm dedupe.")
    return allow()

@registry.hook("check_source_map_size")
def check_source_map_size(data):
    output = get_command_output(data)
    if not output: return allow()
    maps = re.findall(r"(\S+\.map)\s+(\d+(?:\.\d+)?)\s*(MB|KB)", output)
    large_maps = [(n, s, u) for n, s, u in maps if u == "MB" or (u == "KB" and float(s) > 1000)]
    if large_maps:
        return post_tool_context(f"Bundle: {len(large_maps)} large source maps. Use 'hidden-source-map' in production.")
    return allow()

@registry.hook("detect_polyfill_bloat")
def detect_polyfill_bloat(data):
    output = get_command_output(data)
    if not output: return allow()
    polyfills = re.findall(r"core-js|@babel/polyfill|regenerator-runtime|polyfill\.io", output)
    if len(polyfills) > 2:
        return post_tool_context("Bundle: Multiple polyfill sources. Use browserslist + useBuiltIns: 'usage' for targeted polyfills.")
    return allow()

@registry.hook("check_css_bundle_size")
def check_css_bundle_size(data):
    output = get_command_output(data)
    if not output: return allow()
    css_sizes = re.findall(r"(\S+\.css)\s+(\d+(?:\.\d+)?)\s*(kB|MB)", output)
    large = [(n, s, u) for n, s, u in css_sizes if (u == "MB") or (u == "kB" and float(s) > 200)]
    if large:
        return post_tool_context(f"Bundle: Large CSS files: {', '.join(f'{n}({s}{u})' for n,s,u in large[:3])}. Purge unused CSS.")
    return allow()

@registry.hook("detect_font_optimization")
def detect_font_optimization(data):
    output = get_command_output(data)
    if not output: return allow()
    fonts = re.findall(r"(\S+\.(?:woff2?|ttf|otf|eot))\s+(\d+(?:\.\d+)?)\s*(kB|MB)", output)
    if fonts:
        non_woff2 = [f for f, s, u in fonts if not f.endswith(".woff2")]
        if non_woff2:
            return post_tool_context(f"Bundle: {len(non_woff2)} non-WOFF2 fonts. Convert to WOFF2 for smaller size.")
    return allow()

@registry.hook("check_dynamic_import_usage")
def check_dynamic_import_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    static_large = re.findall(r"import\s+(?:\{[^}]+\}|\w+)\s+from\s+['\"](?:lodash|moment|antd|material-ui|rxjs)['\"]", output)
    if len(static_large) > 2:
        libs = set(re.findall(r"from\s+['\"](\w+)['\"]", " ".join(static_large)))
        return post_tool_context(f"Bundle: Static imports of large libs: {', '.join(libs)}. Use dynamic import() for code splitting.")
    return allow()

@registry.hook("detect_moment_usage")
def detect_moment_usage(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"from\s+['\"]moment['\"]|require\(['\"]moment['\"]\)", output):
        return post_tool_context("Bundle: moment.js (~300kB). Consider date-fns (~30kB) or dayjs (~2kB) instead.")
    return allow()

@registry.hook("check_image_format_optimization")
def check_image_format_optimization(data):
    output = get_command_output(data)
    if not output: return allow()
    images = re.findall(r"(\S+)\.(png|jpg|jpeg|gif|bmp)", output, re.IGNORECASE)
    if len(images) > 5:
        formats = set(ext.lower() for _, ext in images)
        if "webp" not in formats and "avif" not in formats:
            return post_tool_context(f"Bundle: {len(images)} images in legacy formats. Convert to WebP/AVIF for 30-50% savings.")
    return allow()

@registry.hook("detect_unused_exports")
def detect_unused_exports(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"unused.*export|export.*unused|dead.*code.*export", output, re.IGNORECASE):
        count = len(re.findall(r"unused.*export|export.*unused", output, re.IGNORECASE))
        return post_tool_context(f"Bundle: {count} unused exports. Remove to enable better tree-shaking.")
    return allow()

@registry.hook("check_gzip_compression")
def check_gzip_compression(data):
    output = get_command_output(data)
    if not output: return allow()
    gzipped = re.findall(r"(\S+)\s+(\d+(?:\.\d+)?)\s*(kB|MB)\s+.*?(\d+(?:\.\d+)?)\s*(kB|MB)\s*(?:gzip|gz)", output)
    if gzipped:
        for name, orig, ou, comp, cu in gzipped[:3]:
            orig_kb = float(orig) * (1024 if ou == "MB" else 1)
            comp_kb = float(comp) * (1024 if cu == "MB" else 1)
            if orig_kb > 0:
                ratio = (1 - comp_kb / orig_kb) * 100
                return post_tool_context(f"Bundle: {name} gzips from {orig}{ou} to {comp}{cu} ({ratio:.0f}% reduction)")
    return allow()

@registry.hook("detect_lodash_full_import")
def detect_lodash_full_import(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"import\s+_\s+from\s+['\"]lodash['\"]|require\(['\"]lodash['\"]\)", output):
        if not re.search(r"lodash-es|lodash/", output):
            return post_tool_context("Bundle: Full lodash import (~70kB). Use lodash-es or lodash/specific for tree-shaking.")
    return allow()

@registry.hook("check_vendor_chunk_size")
def check_vendor_chunk_size(data):
    output = get_command_output(data)
    if not output: return allow()
    vendor = re.search(r"vendor[^.]*\.(?:js|css)\s+(\d+(?:\.\d+)?)\s*(kB|MB)", output)
    if vendor:
        size, unit = float(vendor.group(1)), vendor.group(2)
        if unit == "MB" or (unit == "kB" and size > 500):
            return post_tool_context(f"Bundle: Vendor chunk is {size}{unit}. Split vendors by usage frequency.")
    return allow()

if __name__ == "__main__":
    registry.main()
