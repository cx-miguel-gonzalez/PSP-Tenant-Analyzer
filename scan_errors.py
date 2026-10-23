"""Error categories across Failed/Partial scans, extracted from their cached
scan workflows (GET /api/scans/{id}/workflow).

A workflow is a list of {source, info, timestamp} steps. Error steps are
recognized by wording and put into a broad category (Git / Source Errors,
Engine Failures, ...) from the component that logged them and the message,
so the same kind of problem is counted together across projects and scans.
Within a category, messages are also grouped by a "signature" (scan-specific
details like repo URLs, branch and image names, compile positions masked)
to show which specific errors make up the category. Each category and each
error counts a scan once, even when several components log the same thing
(e.g. sast-worker and sast-rm both report one engine failure)."""
from __future__ import annotations

import re

_ERROR_WORDS = (
    "fail", "error", "exception", "timeout", "timed out", "unable", "notcompleted",
    "deadlock", "denied", "not found", "could not",
)
# Final-status lines and wrappers that only restate a more specific error step.
_GENERIC = re.compile(r"^(scan (failed|partial|canceled)|resource manager - failed)$", re.I)

_MASKS = [
    (re.compile(r"git@[\w.\-]+:[\w./\-]+?\.git"), "<repo>"),
    (re.compile(r"https?://[^\s'\"]+"), "<url>"),
    (re.compile(r"provided value:\S+"), "provided value:<branch>"),
    (re.compile(r"Remote branch \S+ not found"), "Remote branch <branch> not found"),
    (re.compile(r"Image: \S+"), "Image: <image>"),
    # Compile positions like (99484,15) -- sometimes logged without the "(" --
    # while single codes like (65) are kept.
    (re.compile(r"\(?-?\d+(?:,-?\d+)+\)"), "(…)"),
]

# (category, description, test). First match wins, so message-based rules
# that cut across components (timeouts, platform faults) come before the
# component-based ones.
_CATEGORIES = [
    ("Timeouts", "A step ran past its time limit.",
     lambda c, m: "timeout" in m or "timed out" in m),
    ("Internal Errors", "Platform-side faults (internal errors, database deadlocks) -- usually transient or a support case.",
     lambda c, m: "internal error" in m or "deadlock" in m or "contact support" in m),
    ("Git / Source Errors", "The repository couldn't be fetched -- credentials or SSH keys, branch names, or SCM access settings.",
     lambda c, m: c.startswith("fetch-sources") or "clone" in m or "git" in m.split()),
    ("Container Image Errors", "A container image referenced by the project couldn't be found or extracted.",
     lambda c, m: c.startswith("containers-scan") or "image" in m and ("not found" in m or "extraction" in m)),
    ("Results Processing Errors", "Scan results were produced but couldn't be processed or stored.",
     lambda c, m: "results" in c or "result" in m and "process" in m),
    ("Engine Failures", "A scan engine (SAST, SCA, KICS, ...) failed while scanning -- e.g. custom query compilation errors.",
     lambda c, m: "engine" in m or any(k in c for k in ("worker", "runner", "-rm", "engine"))),
]
OTHER = ("Other Errors", "Errors that don't match a known category.")
CATEGORY_DESCRIPTIONS = {name: description for name, description, _ in _CATEGORIES} | {OTHER[0]: OTHER[1]}


def _component(source) -> str:
    source = str(source or "unknown")
    return source[:-3] if source.endswith("-nv") else source


def _message(step: dict) -> str:
    info = " ".join(str(step.get("info") or "").split())
    source = str(step.get("source") or "")
    if source and info.startswith(source):  # steps repeat their source as a prefix
        info = info[len(source):].strip()
    return re.sub(r"^failed:\s*", "", info, flags=re.I)


def signature(message: str) -> str:
    for pattern, replacement in _MASKS:
        message = pattern.sub(replacement, message)
    return message.strip(" .:")


def categorize(component: str, message: str) -> str:
    lowered = message.lower()
    for name, _, test in _CATEGORIES:
        if test(component, lowered):
            return name
    return OTHER[0]


def extract_errors(steps: list[dict]) -> dict[tuple[str, str], set[str]]:
    """{(category, error signature): components that logged it} for one scan's workflow."""
    errors: dict[tuple[str, str], set[str]] = {}
    for step in steps:
        message = _message(step)
        if not message or _GENERIC.match(message) or not any(w in message.lower() for w in _ERROR_WORDS):
            continue
        component = _component(step.get("source"))
        key = (categorize(component, message), signature(message))
        errors.setdefault(key, set()).add(component)
    return errors


def top_errors(scans: list[dict], workflows: dict[str, list[dict]], limit: int = 10) -> dict:
    """Error categories ranked by Failed/Partial scans affected. scans: the
    Failed/Partial scans ({id, status, project_id}); workflows: {scan_id:
    steps} for those that have one cached."""
    categories: dict[str, dict] = {}
    analyzed = without_detail = 0
    for scan in scans:
        steps = workflows.get(str(scan["id"]))
        if steps is None:
            continue
        analyzed += 1
        errors = extract_errors(steps)
        if not errors:
            without_detail += 1
        seen_categories = set()
        for (category, sig), components in errors.items():
            group = categories.setdefault(category, {
                "scan_ids": set(), "statuses": {}, "projects": set(), "components": set(), "errors": {},
            })
            group["components"] |= components
            group["errors"].setdefault(sig, set()).add(str(scan["id"]))
            if category not in seen_categories:
                seen_categories.add(category)
                group["scan_ids"].add(str(scan["id"]))
                group["statuses"][scan["status"]] = group["statuses"].get(scan["status"], 0) + 1
                group["projects"].add(str(scan["project_id"]))

    ranked = sorted(categories.items(), key=lambda item: (-len(item[1]["scan_ids"]), -len(item[1]["projects"]), item[0]))
    return {
        "categories": [
            {
                "category": name,
                "description": CATEGORY_DESCRIPTIONS[name],
                "scan_count": len(group["scan_ids"]),
                "scan_ids": sorted(group["scan_ids"]),
                "statuses": group["statuses"],
                "project_count": len(group["projects"]),
                "components": sorted(group["components"]),
                "errors": [
                    {"error": sig, "scan_count": len(ids)}
                    for sig, ids in sorted(group["errors"].items(), key=lambda item: (-len(item[1]), item[0]))
                ],
            }
            for name, group in ranked[:limit]
        ],
        "failed_partial_total": len(scans),
        "analyzed": analyzed,
        "without_detail": without_detail,
    }
