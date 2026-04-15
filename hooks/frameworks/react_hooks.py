#!/usr/bin/env python3
"""React development hooks for parsing build/runtime output and detecting common issues."""
import json
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, deny, allow, post_tool_context, get_command, get_command_output

registry = HookRegistry()


@registry.hook("react_detect_key_warnings")
def react_detect_key_warnings(data):
    """Parse 'Each child should have a unique key' warnings from React output."""
    output = get_command_output(data)
    pattern = r'Warning:.*Each child in a (?:list|array) should have a unique "key" prop'
    matches = re.findall(pattern, output)
    if matches:
        # Try to extract component names from the warning stack
        component_pattern = r'Check the (?:top-level )?render (?:call|method) (?:using|of) <(\w+)>'
        components = re.findall(component_pattern, output)
        comp_hint = ""
        if components:
            comp_hint = f" Affected component(s): {', '.join(set(components))}."
        return post_tool_context(
            f"REACT KEY WARNING: Found {len(matches)} missing key prop warning(s).{comp_hint} "
            "Add a unique 'key' prop to each element in the list/array. "
            "Use a stable identifier (e.g., item.id) rather than array index when items can be reordered."
        )
    return allow()


@registry.hook("react_detect_hook_violations")
def react_detect_hook_violations(data):
    """Parse 'Hooks can only be called inside a function component' errors."""
    output = get_command_output(data)
    patterns = [
        r"Invalid hook call.*Hooks can only be called inside.*the body of a function component",
        r"React Hook .+ is called (?:conditionally|in a loop|in a nested function)",
        r"React Hook .+ cannot be called (?:at the top level|inside a callback)",
        r"Error:.*Rules of Hooks",
    ]
    violations = []
    for p in patterns:
        found = re.findall(p, output, re.IGNORECASE)
        violations.extend(found)
    if violations:
        hook_names = re.findall(r"React Hook \"(use\w+)\"", output)
        hook_hint = ""
        if hook_names:
            hook_hint = f" Hooks involved: {', '.join(set(hook_names))}."
        return post_tool_context(
            f"REACT HOOK VIOLATION: {len(violations)} Rules of Hooks violation(s) detected.{hook_hint} "
            "Hooks must be called at the top level of a function component or custom hook, "
            "not inside conditions, loops, or nested functions. "
            "Common cause: multiple React copies in node_modules or calling hooks in class components."
        )
    return allow()


@registry.hook("react_check_prop_types")
def react_check_prop_types(data):
    """Parse PropTypes validation warnings from React output."""
    output = get_command_output(data)
    pattern = r'Warning: Failed (?:prop type|propType):?\s*(.+?)(?:\n|$)'
    matches = re.findall(pattern, output)
    if matches:
        details = []
        for m in matches[:5]:
            details.append(f"  - {m.strip()}")
        extra = f" (and {len(matches) - 5} more)" if len(matches) > 5 else ""
        return post_tool_context(
            f"REACT PROP TYPES: {len(matches)} PropTypes warning(s) found{extra}:\n"
            + "\n".join(details) +
            "\nFix by passing the correct prop types or updating the PropTypes/TypeScript definitions."
        )
    return allow()


@registry.hook("react_detect_state_updates_unmounted")
def react_detect_state_updates_unmounted(data):
    """Parse 'Can't perform a React state update on an unmounted component' warnings."""
    output = get_command_output(data)
    patterns = [
        r"Can't perform a React state update on an unmounted component",
        r"Warning:.*Can't perform a React state update on a component that hasn't mounted yet",
        r"Warning:.*setState.*unmounted",
    ]
    found = False
    for p in patterns:
        if re.search(p, output, re.IGNORECASE):
            found = True
            break
    if found:
        return post_tool_context(
            "REACT MEMORY LEAK: State update attempted on an unmounted component. "
            "This typically means an async operation (fetch, setTimeout, subscription) "
            "completed after the component was unmounted. Fix by: "
            "(1) Using an AbortController for fetch calls, "
            "(2) Clearing timeouts/intervals in useEffect cleanup, "
            "(3) Using a mounted ref flag, or "
            "(4) Using the useEffect cleanup function to cancel subscriptions."
        )
    return allow()


@registry.hook("react_check_dependency_array")
def react_check_dependency_array(data):
    """Detect missing useEffect/useMemo/useCallback dependency warnings."""
    output = get_command_output(data)
    dep_pattern = r"React Hook (use(?:Effect|Memo|Callback|LayoutEffect|ImperativeHandle))\s+has\s+(?:a\s+)?missing\s+dependenc(?:y|ies):\s*['\"]?([^'\".\n]+)"
    matches = re.findall(dep_pattern, output)
    unnecessary = re.findall(
        r"React Hook (use\w+)\s+has\s+(?:an?\s+)?unnecessary\s+dependenc(?:y|ies):\s*['\"]?([^'\".\n]+)",
        output
    )
    issues = []
    if matches:
        for hook, deps in matches[:5]:
            issues.append(f"  - {hook} missing: {deps.strip()}")
    if unnecessary:
        for hook, deps in unnecessary[:3]:
            issues.append(f"  - {hook} unnecessary: {deps.strip()}")
    if issues:
        return post_tool_context(
            f"REACT DEPENDENCY ARRAY: {len(matches) + len(unnecessary)} dependency issue(s):\n"
            + "\n".join(issues) +
            "\nAdd missing dependencies or wrap them with useCallback/useMemo. "
            "If intentionally omitting, add an eslint-disable comment with justification."
        )
    return allow()


@registry.hook("react_detect_render_loops")
def react_detect_render_loops(data):
    """Parse maximum update depth exceeded errors (infinite render loops)."""
    output = get_command_output(data)
    patterns = [
        r"Maximum update depth exceeded",
        r"Too many re-renders\.\s*React limits the number of renders",
        r"Uncaught Error:.*Maximum call stack size exceeded",
    ]
    for p in patterns:
        if re.search(p, output, re.IGNORECASE):
            # Try to extract component name
            comp_match = re.search(r"in (\w+)\s*\(", output)
            comp_hint = f" in component <{comp_match.group(1)}>" if comp_match else ""
            return post_tool_context(
                f"REACT INFINITE LOOP: Render loop detected{comp_hint}. "
                "Common causes: "
                "(1) setState called directly in render body (not in useEffect), "
                "(2) useEffect missing dependency array (runs every render), "
                "(3) Object/array dependency recreated each render (use useMemo), "
                "(4) Event handler calling setState without condition. "
                "Check for unconditional setState calls and unstable references in dependency arrays."
            )
    return allow()


@registry.hook("react_check_jsx_syntax")
def react_check_jsx_syntax(data):
    """Parse JSX syntax errors from build/compile output."""
    output = get_command_output(data)
    patterns = [
        (r"SyntaxError:.*(?:Unexpected token|Expected.*?>).*\.(?:jsx|tsx)", "Unexpected token in JSX"),
        (r"Adjacent JSX elements must be wrapped in an enclosing tag", "Multiple root JSX elements"),
        (r"JSX element '(\w+)' has no corresponding closing tag", "Unclosed JSX tag"),
        (r"Unterminated JSX contents", "Unterminated JSX"),
        (r"JSX expressions must have one parent element", "Multiple root elements"),
        (r"Expected corresponding JSX closing tag for ['\"]?<(\w+)", "Missing closing tag"),
    ]
    issues = []
    for p, label in patterns:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            issues.append(label)
    if issues:
        # Extract file and line info
        loc_match = re.search(r"([\w/.]+\.(?:jsx|tsx|js|ts)):(\d+):(\d+)", output)
        loc_hint = ""
        if loc_match:
            loc_hint = f" at {loc_match.group(1)}:{loc_match.group(2)}:{loc_match.group(3)}"
        return post_tool_context(
            f"REACT JSX ERROR{loc_hint}: {'; '.join(issues)}. "
            "Ensure all JSX elements are properly closed, use fragments (<>...</>) for multiple roots, "
            "and check for mismatched or unclosed tags."
        )
    return allow()


@registry.hook("react_detect_hydration_mismatch")
def react_detect_hydration_mismatch(data):
    """Parse SSR hydration mismatch errors."""
    output = get_command_output(data)
    patterns = [
        r"Warning:.*(?:Text content|Prop `\w+`) did not match\.\s*Server:\s*\"([^\"]*)\"\s*Client:\s*\"([^\"]*)",
        r"Hydration failed because the initial UI does not match what was rendered on the server",
        r"There was an error while hydrating",
        r"Error:.*Hydration.*Mismatch",
        r"Warning:.*Expected server HTML to contain a matching",
    ]
    mismatches = []
    for p in patterns:
        found = re.findall(p, output, re.IGNORECASE)
        if found:
            mismatches.extend(found if isinstance(found[0], tuple) else [(f,) for f in found])
    if mismatches:
        return post_tool_context(
            f"REACT HYDRATION MISMATCH: {len(mismatches)} SSR hydration error(s) detected. "
            "The server-rendered HTML does not match the client-side render. Common causes: "
            "(1) Using browser-only APIs (window, localStorage) during SSR, "
            "(2) Date/time-dependent rendering, "
            "(3) Conditional rendering based on state initialized differently on server vs client. "
            "Fix by deferring browser-only logic to useEffect or using dynamic imports with ssr: false."
        )
    return allow()


@registry.hook("react_check_deprecated_apis")
def react_check_deprecated_apis(data):
    """Detect deprecated React APIs in build output or source."""
    output = get_command_output(data)
    deprecated_apis = {
        r"\bcomponentWillMount\b": ("componentWillMount", "Use componentDidMount or useEffect instead"),
        r"\bcomponentWillReceiveProps\b": ("componentWillReceiveProps", "Use static getDerivedStateFromProps or useEffect"),
        r"\bcomponentWillUpdate\b": ("componentWillUpdate", "Use getSnapshotBeforeUpdate or useEffect"),
        r"\bUNSAFE_componentWillMount\b": ("UNSAFE_componentWillMount", "Migrate to useEffect"),
        r"\bUNSAFE_componentWillReceiveProps\b": ("UNSAFE_componentWillReceiveProps", "Migrate to getDerivedStateFromProps"),
        r"\bUNSAFE_componentWillUpdate\b": ("UNSAFE_componentWillUpdate", "Migrate to getSnapshotBeforeUpdate"),
        r"\bReactDOM\.render\b": ("ReactDOM.render", "Use createRoot().render() in React 18+"),
        r"\bReactDOM\.hydrate\b": ("ReactDOM.hydrate", "Use hydrateRoot() in React 18+"),
        r"\bReactDOM\.unmountComponentAtNode\b": ("ReactDOM.unmountComponentAtNode", "Use root.unmount() in React 18+"),
        r"\bfindDOMNode\b": ("findDOMNode", "Use refs instead"),
        r"\bReact\.createFactory\b": ("React.createFactory", "Use JSX or React.createElement"),
        r"\bdefaultProps\b.*function\s+\w+": ("defaultProps on function components", "Use default parameter values instead"),
    }
    found_deprecated = []
    for pattern, (api_name, suggestion) in deprecated_apis.items():
        if re.search(pattern, output):
            found_deprecated.append(f"  - {api_name}: {suggestion}")
    if found_deprecated:
        return post_tool_context(
            f"REACT DEPRECATED API: {len(found_deprecated)} deprecated API(s) detected:\n"
            + "\n".join(found_deprecated[:8]) +
            "\nMigrate to modern React APIs for future compatibility."
        )
    return allow()


@registry.hook("react_detect_context_issues")
def react_detect_context_issues(data):
    """Parse React context provider/consumer errors."""
    output = get_command_output(data)
    patterns = [
        (r"Cannot read propert(?:y|ies) of (?:undefined|null).*useContext", "useContext returned undefined - missing Provider"),
        (r"Error:.*Context.*Provider.*not found", "Context Provider not found in component tree"),
        (r"Warning:.*(?:Consumer|useContext).*without.*Provider", "Context consumed without Provider wrapper"),
        (r"undefined is not a valid.*context", "Invalid context value"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "REACT CONTEXT ERROR: " + "; ".join(issues) + ". "
            "Ensure the component consuming context is wrapped in the corresponding Provider. "
            "Check that: (1) the Provider is above the consumer in the component tree, "
            "(2) createContext() is imported from the same module instance, "
            "(3) the context has a sensible default value for cases without a Provider."
        )
    return allow()


@registry.hook("react_check_ref_forwarding")
def react_check_ref_forwarding(data):
    """Parse ref forwarding issues from React output."""
    output = get_command_output(data)
    patterns = [
        (r"Warning:.*Function components cannot be given refs", "Function component needs forwardRef"),
        (r"Warning:.*Ref.*not.*forwarded", "Ref not forwarded to child"),
        (r"Warning:.*createRef.*function component", "createRef used in function component (use useRef)"),
        (r"Warning:.*String refs are not allowed", "String refs deprecated - use callback or useRef"),
        (r"Warning:.*ref.*will be removed.*future", "Legacy ref API deprecated"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "REACT REF ISSUE: " + "; ".join(issues) + ". "
            "Wrap function components with React.forwardRef() to accept refs. "
            "Use useRef() (not createRef) in function components. "
            "Replace string refs with callback refs or useRef."
        )
    return allow()


@registry.hook("react_detect_suspense_issues")
def react_detect_suspense_issues(data):
    """Parse Suspense/lazy loading errors."""
    output = get_command_output(data)
    patterns = [
        (r"A component suspended while responding to synchronous input", "Sync suspend without startTransition"),
        (r"React\.lazy.*load.*chunk.*failed", "Lazy-loaded chunk failed to load"),
        (r"Error:.*Suspense.*boundary.*not found", "Missing Suspense boundary"),
        (r"Loading chunk \d+ failed", "Chunk loading failure (network or build issue)"),
        (r"ChunkLoadError", "Webpack chunk load error"),
        (r"A lazy component must be wrapped in.*Suspense", "Lazy component missing Suspense wrapper"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "REACT SUSPENSE ERROR: " + "; ".join(issues) + ". "
            "Wrap lazy-loaded components with <Suspense fallback={...}>. "
            "For chunk load failures: check build output, verify asset URLs, "
            "or implement an error boundary with retry logic. "
            "Use startTransition for suspending during user input."
        )
    return allow()


@registry.hook("react_check_strict_mode")
def react_check_strict_mode(data):
    """Parse React.StrictMode double-render warnings and effects."""
    output = get_command_output(data)
    # StrictMode causes double invocation of certain functions in dev
    strict_indicators = [
        r"Warning:.*StrictMode.*side.?effect",
        r"Warning:.*findDOMNode.*StrictMode",
        r"Warning:.*Legacy context API.*StrictMode",
        r"Warning:.*Using UNSAFE_.*StrictMode",
    ]
    found = []
    for p in strict_indicators:
        m = re.search(p, output, re.IGNORECASE)
        if m:
            found.append(m.group(0).strip())
    if found:
        return post_tool_context(
            f"REACT STRICT MODE: {len(found)} StrictMode warning(s) detected. "
            "React.StrictMode intentionally double-invokes render, effects, and certain lifecycle methods "
            "in development to help find bugs. These warnings indicate issues that should be fixed: "
            "side effects in render, legacy APIs, or UNSAFE_ lifecycle methods. "
            "The double-invocation does NOT happen in production builds."
        )
    return allow()


@registry.hook("react_detect_memory_leaks")
def react_detect_memory_leaks(data):
    """Detect event listener/subscription cleanup issues in React output."""
    output = get_command_output(data)
    patterns = [
        (r"Warning:.*Can't perform a React state update on an unmounted component.*"
         r"indicates a memory leak", "State update on unmounted component"),
        (r"Warning:.*subscription.*clean.?up", "Subscription not cleaned up"),
        (r"Warning:.*addEventListener.*removeEventListener", "Event listener not removed"),
        (r"Warning:.*memory leak.*(?:interval|timeout|subscription|listener)",
         "Potential memory leak from uncleared resources"),
    ]
    issues = []
    for p, desc in patterns:
        if re.search(p, output, re.IGNORECASE):
            issues.append(desc)
    # Also check for common patterns in source code being output
    cleanup_patterns = [
        (r"useEffect\(\s*\(\)\s*=>\s*\{[^}]*(?:addEventListener|setInterval|setTimeout|subscribe)[^}]*\}\s*\)",
         "useEffect with async operation but no cleanup return"),
    ]
    for p, desc in cleanup_patterns:
        if re.search(p, output):
            issues.append(desc)
    if issues:
        return post_tool_context(
            "REACT MEMORY LEAK: " + "; ".join(issues) + ". "
            "Always return a cleanup function from useEffect when adding: "
            "(1) event listeners (removeEventListener), "
            "(2) timers (clearInterval/clearTimeout), "
            "(3) subscriptions (unsubscribe), "
            "(4) WebSocket connections (close). "
            "Example: useEffect(() => { const id = setInterval(...); return () => clearInterval(id); }, []);"
        )
    return allow()


@registry.hook("react_check_accessibility")
def react_check_accessibility(data):
    """Parse jsx-a11y accessibility warnings from build/lint output."""
    output = get_command_output(data)
    a11y_pattern = r"(?:warning|error)\s+.*?(jsx-a11y/[\w-]+)"
    matches = re.findall(a11y_pattern, output, re.IGNORECASE)
    # Also catch common a11y patterns in warnings
    generic_a11y = [
        (r"img elements must have an alt prop", "jsx-a11y/alt-text"),
        (r"Anchors must have content", "jsx-a11y/anchor-has-content"),
        (r"href.*javascript:void", "jsx-a11y/anchor-is-valid"),
        (r"Missing.*role.*attribute", "jsx-a11y/role-has-required-aria-props"),
        (r"onClick.*without.*onKey", "jsx-a11y/click-events-have-key-events"),
        (r"non-interactive.*event handler", "jsx-a11y/no-noninteractive-element-interactions"),
        (r"tabIndex.*positive", "jsx-a11y/tabindex-no-positive"),
        (r"form.*label", "jsx-a11y/label-has-associated-control"),
        (r"autoFocus.*accessibility", "jsx-a11y/no-autofocus"),
    ]
    for p, rule in generic_a11y:
        if re.search(p, output, re.IGNORECASE) and rule not in matches:
            matches.append(rule)
    if matches:
        unique_rules = list(dict.fromkeys(matches))
        return post_tool_context(
            f"REACT ACCESSIBILITY: {len(matches)} a11y warning(s) found. Rules violated:\n"
            + "\n".join(f"  - {rule}" for rule in unique_rules[:10]) +
            "\nAccessibility is essential. Fix these issues to ensure the app is usable by everyone. "
            "See https://github.com/jsx-eslint/eslint-plugin-jsx-a11y for rule details."
        )
    return allow()


if __name__ == "__main__":
    registry.main()
