#!/usr/bin/env python3
"""Accessibility: Web accessibility hooks for Codex. 15 PostToolUse hooks."""

import json, re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _lib.base import HookRegistry, allow, post_tool_context, get_command, get_command_output
registry = HookRegistry()

@registry.hook("detect_missing_alt_text")
def detect_missing_alt_text(data):
    output = get_command_output(data)
    if not output: return allow()
    imgs_no_alt = re.findall(r"<img(?![^>]*alt=)[^>]*>", output, re.IGNORECASE)
    if imgs_no_alt:
        return post_tool_context(f"A11y: {len(imgs_no_alt)} <img> tags without alt attribute. Add alt text for screen readers.")
    return allow()

@registry.hook("check_form_labels")
def check_form_labels(data):
    output = get_command_output(data)
    if not output: return allow()
    inputs = re.findall(r"<input(?![^>]*(?:aria-label|aria-labelledby))[^>]*>", output, re.IGNORECASE)
    unlabeled = [i for i in inputs if "type=\"hidden\"" not in i.lower() and "type=\"submit\"" not in i.lower()]
    if len(unlabeled) > 2:
        return post_tool_context(f"A11y: {len(unlabeled)} inputs without labels. Use <label>, aria-label, or aria-labelledby.")
    return allow()

@registry.hook("detect_missing_aria_roles")
def detect_missing_aria_roles(data):
    output = get_command_output(data)
    if not output: return allow()
    interactive = re.findall(r"<div\s+onClick|<span\s+onClick|<div\s+on-click", output, re.IGNORECASE)
    if interactive:
        no_role = [el for el in interactive if "role=" not in el.lower()]
        if no_role:
            return post_tool_context(f"A11y: {len(no_role)} interactive divs/spans without role. Add role='button' and tabIndex.")
    return allow()

@registry.hook("check_heading_hierarchy")
def check_heading_hierarchy(data):
    output = get_command_output(data)
    if not output: return allow()
    headings = re.findall(r"<h(\d)", output, re.IGNORECASE)
    levels = [int(h) for h in headings]
    skips = []
    for i in range(1, len(levels)):
        if levels[i] > levels[i-1] + 1:
            skips.append(f"h{levels[i-1]}→h{levels[i]}")
    if skips:
        return post_tool_context(f"A11y: Heading hierarchy skips: {', '.join(skips[:3])}. Don't skip heading levels.")
    return allow()

@registry.hook("detect_color_contrast_issues")
def detect_color_contrast_issues(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"contrast.*ratio|color.*contrast|WCAG.*contrast", output, re.IGNORECASE):
        if re.search(r"fail|insufficient|below.*threshold|does not meet", output, re.IGNORECASE):
            return post_tool_context("A11y: Color contrast insufficient. WCAG requires 4.5:1 for normal text, 3:1 for large text.")
    return allow()

@registry.hook("check_keyboard_navigation")
def check_keyboard_navigation(data):
    output = get_command_output(data)
    if not output: return allow()
    issues = []
    if re.search(r"tabIndex\s*=\s*[\"']-1[\"']|tabindex\s*=\s*[\"']-1[\"']", output):
        items = len(re.findall(r"tabindex\s*=\s*[\"']-1[\"']", output, re.IGNORECASE))
        if items > 5: issues.append(f"{items} items removed from tab order")
    if re.search(r"tabIndex\s*=\s*[\"']([2-9]|\d{2,})[\"']|tabindex\s*=\s*[\"']([2-9]|\d{2,})[\"']", output, re.IGNORECASE):
        issues.append("positive tabindex (disrupts natural order)")
    if re.search(r"outline:\s*none|outline:\s*0[^.]|:focus\s*\{[^}]*outline:\s*none", output):
        issues.append("focus outline removed")
    if issues:
        return post_tool_context(f"A11y: Keyboard nav issues: {', '.join(issues)}")
    return allow()

@registry.hook("detect_missing_lang_attribute")
def detect_missing_lang_attribute(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"<html(?![^>]*lang=)", output, re.IGNORECASE):
        return post_tool_context("A11y: <html> missing lang attribute. Add lang='en' for screen readers.")
    return allow()

@registry.hook("check_aria_attributes")
def check_aria_attributes(data):
    output = get_command_output(data)
    if not output: return allow()
    invalid_aria = re.findall(r'aria-(?!label|labelledby|describedby|hidden|live|role|expanded|selected|pressed|checked|disabled|required|invalid|controls|owns|haspopup|current|modal|atomic|busy|relevant|roledescription|keyshortcuts|placeholder|valuemax|valuemin|valuenow|valuetext|activedescendant|colcount|colindex|colspan|level|multiline|multiselectable|orientation|posinset|readonly|rowcount|rowindex|rowspan|setsize|sort|autocomplete|errormessage|details|flowto|dropeffect|grabbed)\w+', output, re.IGNORECASE)
    if invalid_aria:
        return post_tool_context(f"A11y: Potentially invalid ARIA attributes: {', '.join(set(invalid_aria[:5]))}")
    return allow()

@registry.hook("detect_axe_violations")
def detect_axe_violations(data):
    cmd, output = get_command(data), get_command_output(data)
    if not re.search(r"axe|a11y.*audit|lighthouse.*accessibility|pa11y", cmd, re.IGNORECASE) or not output: return allow()
    violations = re.findall(r"(\d+)\s+violations?|Violations:\s*(\d+)", output, re.IGNORECASE)
    if violations:
        count = violations[0][0] or violations[0][1]
        return post_tool_context(f"A11y audit: {count} violations found. Fix critical issues first.")
    score = re.search(r"accessibility.*?(\d+)/100|accessibility.*?score.*?(\d+)", output, re.IGNORECASE)
    if score:
        val = int(score.group(1) or score.group(2))
        return post_tool_context(f"A11y score: {val}/100{'.' if val >= 90 else '. Aim for 90+.'}")
    return allow()

@registry.hook("check_video_captions")
def check_video_captions(data):
    output = get_command_output(data)
    if not output: return allow()
    videos = re.findall(r"<video|<iframe.*(?:youtube|vimeo)", output, re.IGNORECASE)
    tracks = re.findall(r"<track\s+kind=[\"'](?:captions|subtitles)", output, re.IGNORECASE)
    if videos and not tracks:
        return post_tool_context(f"A11y: {len(videos)} videos without captions/subtitles. Add <track> elements.")
    return allow()

@registry.hook("detect_auto_playing_media")
def detect_auto_playing_media(data):
    output = get_command_output(data)
    if not output: return allow()
    autoplay = re.findall(r"autoplay|autoPlay", output)
    if autoplay:
        return post_tool_context(f"A11y: {len(autoplay)} auto-playing media elements. Provide pause controls and respect prefers-reduced-motion.")
    return allow()

@registry.hook("check_link_text")
def check_link_text(data):
    output = get_command_output(data)
    if not output: return allow()
    bad_links = re.findall(r"<a[^>]*>\s*(?:click here|here|read more|more|link)\s*</a>", output, re.IGNORECASE)
    if bad_links:
        return post_tool_context(f"A11y: {len(bad_links)} links with non-descriptive text ('click here', 'more'). Use meaningful link text.")
    return allow()

@registry.hook("detect_motion_sensitivity")
def detect_motion_sensitivity(data):
    output = get_command_output(data)
    if not output: return allow()
    animations = re.findall(r"@keyframes|animation:|transition:", output)
    if animations and not re.search(r"prefers-reduced-motion", output):
        return post_tool_context("A11y: CSS animations without prefers-reduced-motion media query. Respect user motion preferences.")
    return allow()

@registry.hook("check_semantic_html")
def check_semantic_html(data):
    output = get_command_output(data)
    if not output: return allow()
    divs = len(re.findall(r"<div", output, re.IGNORECASE))
    semantic = len(re.findall(r"<(?:main|nav|header|footer|article|section|aside|figure)", output, re.IGNORECASE))
    if divs > 20 and semantic == 0:
        return post_tool_context(f"A11y: {divs} divs, 0 semantic elements. Use <main>, <nav>, <header>, <article>, etc.")
    return allow()

@registry.hook("detect_skip_navigation")
def detect_skip_navigation(data):
    output = get_command_output(data)
    if not output: return allow()
    if re.search(r"<nav|<header", output, re.IGNORECASE):
        if not re.search(r"skip.*nav|skip.*content|skip.*main|#main-content", output, re.IGNORECASE):
            return post_tool_context("A11y: No skip navigation link. Add 'Skip to main content' link for keyboard users.")
    return allow()

if __name__ == "__main__":
    registry.main()
