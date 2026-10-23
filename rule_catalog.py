"""Catalog of analyzer rules (analyzer_rules.json) plus the
user-editable enabled/warning-level overrides persisted in SQLite
(db.py's analyzer_rule_overrides table). analyzer.py evaluates the
effective rule set against the synced tenant data."""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path

import db
import health

_CATALOG_PATH = Path(__file__).parent / "analyzer_rules.json"
logger = logging.getLogger(__name__)

# Friendly sidebar/page labels for the JSON's section keys, matching the
# naming already used elsewhere in this console (e.g. SECTIONS in
# sections.py) where it differs from the raw rule-set key.
SECTION_LABELS = {
    "Global Configuration": "Global Configuration",
    "Preset Management": "Preset Management",
    "Scan Health": "Scan Health",
    "Integrations": "Integrations",
    "Feedback Apps": "Feedback Apps",
    "Policies": "Policies",
    "ProjectsApplications": "Projects / Applications",
    "Stale Projects": "Stale Projects",
}

# URL-safe ?tab= values for the Analyzer Config page's per-section tabs.
SECTION_SLUGS = {
    "Global Configuration": "global_configuration",
    "Preset Management": "preset_management",
    "Scan Health": "scan_health",
    "Integrations": "integrations",
    "Feedback Apps": "feedback_apps",
    "Policies": "policies",
    "ProjectsApplications": "projects_applications",
    "Stale Projects": "stale_projects",
}


def _rule_key(section: str, rule_check: str) -> str:
    # Content-derived (not positional) so a rule keeps its override even if
    # analyzer_rules.json gets reordered or gains/loses entries around it.
    digest = hashlib.sha256(f"{section}|{rule_check}".encode()).hexdigest()
    return f"r_{digest[:16]}"


def _load() -> dict[str, list[dict]]:
    with _CATALOG_PATH.open() as f:
        raw = json.load(f)
    catalog = {}
    for section, rules in raw.items():
        catalog[section] = [
            {
                "rule_key": _rule_key(section, rule["ruleCheck"]),
                "rule_check": rule["ruleCheck"],
                "reasoning": rule["reasoning"],
                "recommendation": rule.get("recommendation", ""),
                "default_warning_level": rule["warningLevel"],
            }
            for rule in rules
        ]
    return catalog


_cache = {"mtime": None, "catalog": {}}
_cache_lock = threading.Lock()


def catalog() -> dict[str, list[dict]]:
    """The rule set, re-read whenever analyzer_rules.json changes on disk so
    edits apply without restarting the app. If an edit leaves the file
    invalid (e.g. saved mid-edit), the last good version keeps being used."""
    mtime = _CATALOG_PATH.stat().st_mtime
    if _cache["mtime"] != mtime:
        with _cache_lock:
            if _cache["mtime"] != mtime:
                try:
                    _cache["catalog"] = _load()
                except (ValueError, KeyError, TypeError):
                    logger.exception("analyzer_rules.json is invalid; keeping the last good rule set")
                    if _cache["mtime"] is None:
                        raise
                _cache["mtime"] = mtime
    return _cache["catalog"]


def all_rule_keys() -> list[str]:
    return [rule["rule_key"] for rules in catalog().values() for rule in rules]


def display_text(text: str, look_back_days: int) -> str:
    """Fill a rule's {look_back} placeholder with the Overview's Look Back setting."""
    return text.replace("{look_back}", health.look_back_phrase(look_back_days))


def effective_rules() -> dict[str, list[dict]]:
    """catalog() with each rule's stored enabled/warning-level override applied."""
    overrides = db.get_rule_overrides()
    result = {}
    for section, rules in catalog().items():
        rows = []
        for rule in rules:
            override = overrides.get(rule["rule_key"])
            enabled = bool(override["enabled"]) if override is not None else True
            warning_level = (override["warning_level"] if override is not None else None) or rule["default_warning_level"]
            rows.append({**rule, "enabled": enabled, "warning_level": warning_level})
        result[section] = rows
    return result
