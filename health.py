"""Recommendation rules computed from the local SQLite cache -- never live
from the API. This is an extensible starting set derived from data we can
actually see (counts, statuses, join results), not a claim of exhaustive
Checkmarx One best-practice coverage. Each rule returns zero or more
{severity: "warning"|"info", message} findings for its section."""
from __future__ import annotations

import json

import db

# The single Look Back setting (chosen on the Overview page): the Scan Health
# sync window, and the "no scan within" window for Stale Projects, the
# Overview card, and the analyzer's stale rule. 0 means All Time.
LOOK_BACK_OPTIONS = [(7, "Past 7 Days"), (30, "Past 30 Days"), (90, "Past 90 Days"),
                     (180, "Past 180 Days"), (365, "Past 365 Days"), (0, "All Time")]
LOOK_BACK_DEFAULT = 90
_LOOK_BACK_SETTING = "look_back_days"
# Pre-consolidation setting from the Stale Projects page, honored until a Look Back is saved.
_LEGACY_STALE_SETTING = "stale_threshold_days"
_VALID_LOOK_BACK = {days for days, _ in LOOK_BACK_OPTIONS}


def look_back_days() -> int:
    for key in (_LOOK_BACK_SETTING, _LEGACY_STALE_SETTING):
        try:
            days = int(db.get_setting(key))
        except (TypeError, ValueError):
            continue
        if days in _VALID_LOOK_BACK:
            return days
    return LOOK_BACK_DEFAULT


def set_look_back_days(days: int) -> None:
    if days not in _VALID_LOOK_BACK:
        raise ValueError(f"Unsupported look back: {days}")
    db.set_setting(_LOOK_BACK_SETTING, str(days))


def look_back_label(days: int) -> str:
    return dict(LOOK_BACK_OPTIONS).get(days, f"Past {days} Days")


def look_back_phrase(days: int) -> str:
    """Fits "...not been scanned in <phrase>"."""
    return f"the last {days} days" if days else "the synced scan history (All Time)"


def _preset_management_findings() -> list[dict]:
    presets = db.list_presets()
    findings = []
    if not presets:
        return findings
    custom_count = sum(1 for p in presets if p["is_custom"])
    if custom_count > 15:
        findings.append(
            {
                "severity": "info",
                "message": f"{custom_count} custom presets defined -- worth reviewing for overlap/consolidation.",
            }
        )
    return findings


def _scan_health_findings() -> list[dict]:
    findings = []
    breakdown = db.scan_status_breakdown()
    total = sum(row["count"] for row in breakdown)
    if total == 0:
        return findings

    failed = sum(row["count"] for row in breakdown if row["status"] in ("Failed", "Partial", "Canceled"))
    failure_rate = failed / total
    if failure_rate > 0.15:
        findings.append(
            {
                "severity": "warning",
                "message": f"{failed} of {total} recently synced scans ({failure_rate:.0%}) ended Failed/Partial/Canceled.",
            }
        )

    recent = db.list_scans(limit=1)
    if recent:
        findings_recent_msg = None
    else:
        findings_recent_msg = "No scans found for this tenant."
    if findings_recent_msg:
        findings.append({"severity": "warning", "message": findings_recent_msg})

    return findings


def _integrations_findings() -> list[dict]:
    findings = []
    origin_breakdown = db.scan_origin_breakdown()
    if not origin_breakdown:
        return findings

    ci_cd_origins = {
        "Jenkins", "Bamboo", "Azure DevOps", "GitHub Actions", "GitLab CI",
        "CircleCI", "TeamCity",
    }
    ide_origins = {"VS Code Plugin", "JetBrains Plugin", "Eclipse Plugin", "Visual Studio Plugin"}

    origins_seen = {row["origin"] for row in origin_breakdown}
    if not origins_seen & ci_cd_origins:
        findings.append(
            {
                "severity": "info",
                "message": "No CI/CD tool origin (Jenkins/Azure DevOps/GitHub Actions/etc.) detected in recent scans.",
            }
        )
    if not origins_seen & ide_origins:
        findings.append(
            {
                "severity": "info",
                "message": "No IDE plugin origin detected in recent scans -- developers may not have IDE feedback configured.",
            }
        )

    scm_connections = db.list_scm_connections()
    if not scm_connections:
        findings.append(
            {
                "severity": "info",
                "message": "No SCM connections synced (or not available on this tenant).",
            }
        )
    return findings


def _feedback_profiles_findings() -> list[dict]:
    profiles = db.list_feedback_profiles()
    if not profiles:
        return [
            {
                "severity": "warning",
                "message": "No ticketing integration profiles configured -- findings are not being pushed to Jira/Azure DevOps.",
            }
        ]
    return []


def _policies_findings() -> list[dict]:
    policies = db.list_policies()
    if not policies:
        return [{"severity": "warning", "message": "No policies configured for this tenant."}]
    if not any(p["enabled"] for p in policies):
        return [{"severity": "warning", "message": f"{len(policies)} polic(y/ies) configured, but none are enabled/enforced."}]
    return []


def _project_management_findings() -> list[dict]:
    findings = []
    orphaned = db.orphaned_projects_count()
    if orphaned > 0:
        findings.append(
            {
                "severity": "info",
                "message": f"{orphaned} project(s) are not assigned to any application.",
            }
        )
    applications = db.list_applications()
    empty_apps = sum(1 for a in applications if not json.loads(a["project_ids"] or "[]"))
    if empty_apps > 0:
        findings.append(
            {
                "severity": "info",
                "message": f"{empty_apps} application(s) have no projects assigned.",
            }
        )
    return findings


def _stale_projects_findings(threshold_days: int) -> list[dict]:
    stale = db.stale_projects(threshold_days)
    if not stale:
        return []
    return [
        {
            "severity": "warning",
            "message": f"{len(stale)} project(s) have not been scanned in {look_back_phrase(threshold_days)}.",
        }
    ]


_SECTION_RULES = {
    "preset_management": lambda threshold_days: _preset_management_findings(),
    "scan_health": lambda threshold_days: _scan_health_findings(),
    "integrations": lambda threshold_days: _integrations_findings(),
    "feedback_profiles": lambda threshold_days: _feedback_profiles_findings(),
    "policies": lambda threshold_days: _policies_findings(),
    "project_management": lambda threshold_days: _project_management_findings(),
    "stale_projects": lambda threshold_days: _stale_projects_findings(threshold_days),
}


def section_findings(section_key: str) -> list[dict]:
    rule = _SECTION_RULES.get(section_key)
    if rule is None:
        return []
    return rule(look_back_days())
