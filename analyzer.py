"""Analyze Tenant: evaluates every enabled Analyzer Config rule against the
local SQLite cache of ITS OWN section only (Global Configuration rules read
tenant_config, Preset Management rules read presets, and so on) and
produces a report of every violating instance, grouped by section.

Each evaluator returns the violating instances as {"label", "target"}
dicts; an empty list means the rule passed. "target" ("project:<id>",
"config:<key>", ...) identifies the row/box on the section page to
highlight, or is None for a tenant-wide finding with no single culprit.
A rule whose source data has never been synced is reported as "not
evaluated" instead of guessing -- an empty table would otherwise read as a
false pass or a false violation."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import db
import health
import rule_catalog
import scan_errors

# Rule-set section -> console section(s) whose sync the rules read from.
_SECTION_SOURCES = {
    "Global Configuration": ("global_configurations",),
    "Preset Management": ("preset_management",),
    "Scan Health": ("scan_health",),
    "Integrations": ("integrations", "scan_health"),
    "Feedback Apps": ("feedback_profiles",),
    "Policies": ("policies",),
    "ProjectsApplications": ("project_management",),
    "Stale Projects": ("project_management", "scan_health"),
}

# Console section page -> the rule-set section whose violations it highlights.
PAGE_RULE_SECTION = {
    "global_configurations": "Global Configuration",
    "preset_management": "Preset Management",
    "scan_health": "Scan Health",
    "integrations": "Integrations",
    "feedback_profiles": "Feedback Apps",
    "policies": "Policies",
    "project_management": "ProjectsApplications",
    "stale_projects": "Stale Projects",
}

_SOURCE_LABELS = {
    "global_configurations": "Global Configurations",
    "preset_management": "Preset Management",
    "integrations": "Integrations",
    "scan_health": "Scan Health",
    "feedback_profiles": "Feedback Apps",
    "policies": "Policies",
    "project_management": "Project/Application Management",
}

_NOISY_PRESETS = ("ASA Premium", "Checkmarx Default", "All")
_LEVEL_RANK = {"High": 0, "Medium": 1, "Low": 2}


def _i(label: str, target: str | None = None, fields: dict | None = None) -> dict:
    # fields (column -> value) are the instance's row in the results tables; a
    # tenant-wide finding with no columns of its own gets a single Details cell.
    return {"label": label, "target": target, "fields": fields or {"Details": label}}


# ---------------------------------------------------------------------------
# Global Configuration -- tenant_config values are JSON-encoded strings.
# ---------------------------------------------------------------------------
def _tenant_config() -> dict[str, str]:
    values = {}
    for row in db.list_tenant_configuration():
        try:
            parsed = json.loads(row["value"]) if row["value"] is not None else ""
        except (TypeError, ValueError):
            parsed = row["value"]
        values[row["key"]] = "" if parsed is None else str(parsed).strip()
    return values


def _config_instance(ctx, key: str) -> list[dict]:
    value = ctx["config"].get(key, "")
    # Only target keys that actually exist, so the highlight has a row to land on.
    return [_i(
        f"{key} = {value}" if value else f"{key} is not set",
        f"config:{key}" if key in ctx["config"] else None,
        {"Setting": key, "Current Value": value or "Not set"},
    )]


def _config_is_false(key: str):
    def check(ctx):
        return _config_instance(ctx, key) if ctx["config"].get(key, "").lower() == "false" else []
    return check


def _config_is_empty(key: str):
    def check(ctx):
        return _config_instance(ctx, key) if ctx["config"].get(key, "") == "" else []
    return check


def _config_has_value(key: str):
    def check(ctx):
        return _config_instance(ctx, key) if ctx["config"].get(key, "") else []
    return check


def _source_code_management(ctx):
    # The rule fires when source code is NOT being retained ("keepAllSourceCode"
    # is the only value seen that keeps it); unset means the platform default.
    key = "scan.config.general.sourceCodeManagement"
    value = ctx["config"].get(key, "")
    return _config_instance(ctx, key) if value and value != "keepAllSourceCode" else []


def _language_mode_primary(ctx):
    key = "scan.config.sast.languageMode"
    return _config_instance(ctx, key) if ctx["config"].get(key, "").lower() == "primary" else []


def _tenant_preset_is_noisy(ctx):
    key = "scan.config.sast.presetName"
    return _config_instance(ctx, key) if ctx["config"].get(key, "") in _NOISY_PRESETS else []


# ---------------------------------------------------------------------------
# Preset Management
# ---------------------------------------------------------------------------
def _no_custom_preset(ctx):
    return [] if any(p["is_custom"] for p in ctx["presets"]) else [_i("No custom presets exist on this tenant")]


def _mainly_noisy_presets(ctx):
    in_use = [p for p in ctx["presets"] if (p["associated_projects"] or 0) > 0]
    total = sum(p["associated_projects"] for p in in_use)
    noisy = [p for p in in_use if p["name"] in _NOISY_PRESETS]
    noisy_total = sum(p["associated_projects"] for p in noisy)
    if not total or noisy_total / total <= 0.5:
        return []
    return [
        _i(
            f"{p['name']}: {p['associated_projects']} of {total} preset-associated projects",
            f"preset:{p['id']}",
            {"Preset": p["name"], "Associated Projects": p["associated_projects"],
             "Share": f"{p['associated_projects'] / total:.0%} of {total}"},
        )
        for p in sorted(noisy, key=lambda p: -p["associated_projects"])
    ]


def _only_one_preset(ctx):
    in_use = [p for p in ctx["presets"] if (p["associated_projects"] or 0) > 0]
    if len(in_use) == 1:
        p = in_use[0]
        return [_i(
            f"Only {p['name']} is associated to projects", f"preset:{p['id']}",
            {"Preset": p["name"], "Associated Projects": p["associated_projects"]},
        )]
    if not in_use:
        return [_i("No preset is associated to any project")]
    return []


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------
def _standard_github_connections(ctx):
    github_scms = {str(s["id"]): s for s in ctx["scm_connections"] if s["scm_type"] == "github"}
    results = []
    for org in ctx["scm_orgs"]:
        scm = github_scms.get(str(org["scm_id"]))
        if scm is None:
            continue
        results.append(_i(
            f"GitHub org {org['org_identity']}" + (" (personal)" if org["is_user_org"] else ""),
            f"org:{org['org_id']}",
            {"Organization": org["org_identity"],
             "Connection": scm["instance_name"] or scm["display_name"] or "GitHub",
             "Personal Org": "Yes" if org["is_user_org"] else "No"},
        ))
    return results


def _custom_scans(ctx):
    return [
        _i(f"{row['label']}: {row['count']} scan(s)", f"origin:{row['label']}",
           {"Scan Origin": row["label"], "Scans": row["count"]})
        for row in ctx["usage"]["custom"] if row["count"] > 0
    ]


def _no_cicd_or_scm(ctx):
    has_cicd = any(row["count"] > 0 for row in ctx["usage"]["cicd"])
    if has_cicd or ctx["scm_orgs"]:
        return []
    return [_i("No CI/CD scans and no connected source control organizations")]


# ---------------------------------------------------------------------------
# Feedback Apps
# ---------------------------------------------------------------------------
def _app_severities(app: dict) -> list[str]:
    filters = app.get("filters") or {}
    severities = filters.get("severity") or filters.get("severities") or []
    return [str(s) for s in severities] if isinstance(severities, list) else [str(severities)]


def _profile_app_ids(profile: dict) -> set[str]:
    ids = {str(a.get("id")) for a in profile.get("feedbackAppDtos") or [] if isinstance(a, dict)}
    ids.update(str(i) for i in profile.get("appsIds") or [])
    return ids


def _profile_project_ids(profile: dict) -> list:
    return profile.get("projectsIds") or profile.get("projectIds") or []


def _app_instance(app: dict, label: str, extra: dict | None = None) -> dict:
    name = str(app.get("name") or app.get("id"))
    return _i(label, f"feedback_app:{app.get('id')}", {"Feedback App": name, "Type": app.get("type") or "—", **(extra or {})})


def _profile_instance(profile: dict) -> dict:
    name = str(profile.get("name") or profile.get("id"))
    return _i(name, f"feedback_profile:{profile.get('id')}", {
        "Profile": name,
        "Associated Apps": len(_profile_app_ids(profile)),
        "Associated Projects": len(_profile_project_ids(profile)),
    })


def _feedback_noisy_severities(ctx):
    noisy = {"MEDIUM", "LOW", "INFO", "INFORMATIONAL"}
    results = []
    for app in ctx["feedback_apps"]:
        severities = _app_severities(app)
        hits = [s for s in severities if s.upper() in noisy]
        if hits:
            results.append(_app_instance(
                app, f"{app.get('name') or app.get('id')}: includes {', '.join(s.title() for s in hits)}",
                {"Noisy Severities": ", ".join(s.title() for s in hits),
                 "All Severities": ", ".join(s.title() for s in severities)},
            ))
    return results


def _feedback_app_without_profile(ctx):
    used = set()
    for profile in ctx["feedback_profiles"]:
        used |= _profile_app_ids(profile)
    return [
        _app_instance(app, str(app.get("name") or app.get("id")))
        for app in ctx["feedback_apps"] if str(app.get("id")) not in used
    ]


def _profile_without_apps(ctx):
    return [_profile_instance(p) for p in ctx["feedback_profiles"] if not _profile_app_ids(p)]


def _profile_without_projects(ctx):
    return [_profile_instance(p) for p in ctx["feedback_profiles"] if not _profile_project_ids(p)]


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
def _policy_is_default(policy: dict) -> bool:
    return any(policy.get(k) is True for k in ("defaultPolicy", "isDefault", "is_default"))


def _policy_instance(ctx, policy: dict) -> dict:
    name = str(policy.get("name") or policy.get("id"))
    rule_type, rules = ctx["policy_rule_summary"](policy)
    return _i(name, f"policy:{policy.get('id')}", {
        "Policy": name,
        "Rule Type": rule_type,
        "Rules": len(rules),
        "Associated Projects": (policy.get("violatingAssocProjects") or {}).get("assocProjects") or len(policy.get("projects") or []),
    })


def _policy_has_no_rules(ctx):
    summarize = ctx["policy_rule_summary"]
    return [_policy_instance(ctx, p) for p in ctx["policies"] if not summarize(p)[1]]


def _policy_unassociated(ctx):
    results = []
    for p in ctx["policies"]:
        if _policy_is_default(p):
            continue
        assoc = (p.get("violatingAssocProjects") or {}).get("assocProjects")
        if not (p.get("projects") or []) and not assoc:
            results.append(_policy_instance(ctx, p))
    return results


def _no_default_policy(ctx):
    return [] if any(_policy_is_default(p) for p in ctx["policies"]) else [_i("No policy is marked as the default policy")]


# ---------------------------------------------------------------------------
# Projects / Applications
# ---------------------------------------------------------------------------
def _assigned_project_ids(ctx) -> set[str]:
    assigned = set()
    for app in ctx["applications"]:
        assigned.update(str(i) for i in app.get("projectIds") or [])
    return assigned


def _project_instance(project: dict, column: str, value) -> dict:
    name = str(project.get("name") or project.get("id"))
    return _i(name, f"project:{project.get('id')}", {"Project": name, column: value})


def _application_instance(application: dict, column: str, value) -> dict:
    name = str(application.get("name") or application.get("id"))
    return _i(name, f"application:{application.get('id')}", {"Application": name, column: value})


def _project_missing_tags(ctx):
    return [_project_instance(p, "Origin", p.get("origin") or "—") for p in ctx["projects"] if not p.get("tags")]


def _project_no_primary_branch(ctx):
    return [_project_instance(p, "Repository", p.get("repoUrl") or "—") for p in ctx["projects"] if not p.get("mainBranch")]


def _project_no_application(ctx):
    assigned = _assigned_project_ids(ctx)
    return [
        _project_instance(p, "Origin", p.get("origin") or "—") for p in ctx["projects"]
        if not p.get("applicationIds") and str(p.get("id")) not in assigned
    ]


def _project_default_criticality(ctx):
    return [_project_instance(p, "Criticality", p.get("criticality")) for p in ctx["projects"] if str(p.get("criticality")) == "3"]


def _application_no_projects(ctx):
    return [_application_instance(a, "Projects", 0) for a in ctx["applications"] if not a.get("projectIds")]


def _application_no_authorizations(ctx):
    authorizations = ctx["authorizations"]
    return [
        _application_instance(a, "Projects", len(a.get("projectIds") or [])) for a in ctx["applications"]
        if str(a.get("id")) in authorizations and not authorizations[str(a.get("id"))]
    ]


# ---------------------------------------------------------------------------
# Scan Health -- failure rate = Failed + Partial scans / all synced scans in
# the Look Back window. The three rules are rate bands; only the one matching
# the current rate fires, and its result carries the Top Error Categories.
# ---------------------------------------------------------------------------
def _scan_failure_rate(in_band):
    def check(ctx):
        counts = ctx["scan_status_counts"]
        total = sum(counts.values())
        failed, partial = counts.get("Failed", 0), counts.get("Partial", 0)
        if not total:
            return []
        rate = (failed + partial) / total * 100
        if not in_band(rate):
            return []
        errors = ctx["top_errors"]
        instances = [
            _i(f"{c['category']}: {c['scan_count']} scan(s)", None, {
                "Error Category": c["category"],
                "Scans": c["scan_count"],
                "Failed / Partial": f"{c['statuses'].get('Failed', 0)} / {c['statuses'].get('Partial', 0)}",
                "Projects": c["project_count"],
            })
            for c in errors["categories"]
        ] or [_i("No error details cached for these scans yet -- sync Scan Health to fetch their workflows.")]
        summary = (
            f"Failure rate {rate:.1f}%: {failed + partial} of {total} scans ended Failed ({failed}) or "
            f"Partial ({partial}) in {health.look_back_phrase(ctx['look_back_days'])}."
        )
        if errors["categories"] and errors["analyzed"] < errors["failed_partial_total"]:
            summary += f" Error categories are based on {errors['analyzed']} of {errors['failed_partial_total']} of those scans' workflows."
        return {"instances": instances, "summary": summary}
    return check


# ---------------------------------------------------------------------------
# Stale Projects
# ---------------------------------------------------------------------------
def _stale_projects(ctx):
    # The Overview page's Look Back window.
    results = []
    for p in db.stale_projects(ctx["look_back_days"]):
        last_scan = p["last_scan_at"][:10] if p["last_scan_at"] else "Never Scanned"
        results.append(_i(
            f"{p['name']} — " + (f"Last scanned {last_scan}" if p["last_scan_at"] else "Never Scanned"),
            f"project:{p['id']}",
            {"Project": p["name"], "Last Scan Date": last_scan},
        ))
    return results


# (rule-set section, ruleCheck text) -> evaluator. Rules in
# analyzer_rules.json with no entry here are reported as "no evaluator".
_EVALUATORS = {
    ("Global Configuration", "Ai Allow usage is set to false"): _config_is_false("scan.config.ai.allowAiUsage"),
    ("Global Configuration", "Applications Direct Associations not set"): _config_is_empty("scan.config.applications.directAssociations"),
    ("Global Configuration", "General Source Code Management enabled"): _source_code_management,
    ("Global Configuration", "Plugins Ide Scans set to false"): _config_is_false("scan.config.plugins.ideScans"),
    ("Global Configuration", "AI Options set to false"): _config_is_false("scan.config.plugins.aiOptions"),
    ("Global Configuration", "AI MCP Server set to false"): _config_is_false("scan.config.plugins.aiMcpServer"),
    ("Global Configuration", "AI Guided Remediation set to false"): _config_is_false("scan.config.plugins.aiGuidedRemediation"),
    ("Global Configuration", "SAST Findings Analysis is set to false"): _config_is_false("scan.config.sast.findingsAnalysis"),
    ("Global Configuration", "SAST Extended Analysis is set to false"): _config_is_false("scan.config.sast.extendedAnalysis"),
    ("Global Configuration", "SAST Language Mode is set to Primary"): _language_mode_primary,
    ("Global Configuration", "SAST Incremental Scans is set to false"): _config_is_false("scan.config.sast.incremental"),
    ("Global Configuration", "Mandatory Comment When Changing State is set to false"): _config_is_false("scan.config.sast.mandatoryCommentWhenChangingState"),
    ("Global Configuration", "Preset Name is in: ASA Premium, Checkmarx Default, All"): _tenant_preset_is_noisy,
    ("Global Configuration", "Recommended Exclusions is set to false"): _config_is_false("scan.config.sast.recommendedExclusions"),
    ("Global Configuration", "KICS Preset ID contains a value"): _config_has_value("scan.config.kics.presetId"),
    ("Global Configuration", "SCA Exploitable Path is set to false"): _config_is_false("scan.config.sca.ExploitablePath"),
    ("Preset Management", "No Custom Preset"): _no_custom_preset,
    ("Preset Management", "Mainly using ASA Premium, Checkmarx Default, or All presets"): _mainly_noisy_presets,
    ("Preset Management", "Only using one preset"): _only_one_preset,
    ("Scan Health", "Scan failure rate is greater than 5%"): _scan_failure_rate(lambda r: r > 5),
    ("Scan Health", "Scan failure rate is between 2% and 5%"): _scan_failure_rate(lambda r: 2 <= r <= 5),
    ("Scan Health", "Scan failure rate is above 0% and below 2%"): _scan_failure_rate(lambda r: 0 < r < 2),
    ("Integrations", "Any connections using the standard GitHub Integration"): _standard_github_connections,
    ("Integrations", "Any custom scans are found"): _custom_scans,
    ("Integrations", "No CI/CD integrations or Source Control integrations"): _no_cicd_or_scm,
    ("Feedback Apps", "Feedback app includes Medium, Low, or Informational severities"): _feedback_noisy_severities,
    ("Feedback Apps", "Feedback app not associated to a profile"): _feedback_app_without_profile,
    ("Feedback Apps", "Profile has no associated apps"): _profile_without_apps,
    ("Feedback Apps", "Profile has no associated projects"): _profile_without_projects,
    ("Policies", "Policy has no rules"): _policy_has_no_rules,
    ("Policies", "Policy has no associated projects and is not default"): _policy_unassociated,
    ("Policies", "No default policy exists"): _no_default_policy,
    ("ProjectsApplications", "Project missing tags"): _project_missing_tags,
    ("ProjectsApplications", "Project has no primary branch"): _project_no_primary_branch,
    ("ProjectsApplications", "Project has no application association"): _project_no_application,
    ("ProjectsApplications", "Criticality set to 3"): _project_default_criticality,
    ("ProjectsApplications", "Application has no projects associated"): _application_no_projects,
    ("ProjectsApplications", "Application has no authorization assignments"): _application_no_authorizations,
    ("Stale Projects", "Project has not been scanned in {look_back}"): _stale_projects,
}


def _raw_rows(rows) -> list[dict]:
    return [json.loads(row["raw_json"]) for row in rows]


def _build_context(policy_rule_summary) -> dict:
    return {
        "config": _tenant_config(),
        "presets": [dict(p) for p in db.list_presets()],
        "scm_connections": [dict(s) for s in db.list_scm_connections()],
        "scm_orgs": [org for orgs in db.list_scm_orgs_by_scm().values() for org in orgs],
        "usage": db.integration_usage_breakdown(),
        "feedback_apps": _raw_rows(db.list_feedback_apps()),
        "feedback_profiles": _raw_rows(db.list_feedback_profiles()),
        "policies": _raw_rows(db.list_policies()),
        "policy_rule_summary": policy_rule_summary,
        "projects": _raw_rows(db.list_projects()),
        "applications": _raw_rows(db.list_applications()),
        "authorizations": db.list_application_authorizations(),
        "look_back_days": health.look_back_days(),
        "scan_status_counts": {row["status"]: row["count"] for row in db.scan_status_breakdown()},
        "top_errors": scan_errors.top_errors([dict(s) for s in db.failed_partial_scans()], db.scan_workflows_by_id()),
    }


def _evaluate_section(section_name: str, rules: list[dict], ctx: dict, sync_meta: dict, ran_at: str) -> dict:
    sources = _SECTION_SOURCES.get(section_name, ())
    unsynced = [
        _SOURCE_LABELS.get(key, key) for key in sources
        if not (sync_meta.get(key) and sync_meta[key]["last_synced_at"])
    ]
    violations, not_evaluated = [], []
    passed = disabled = skipped_unsynced = 0
    for rule in rules:
        if not rule["enabled"]:
            disabled += 1
            continue
        evaluator = _EVALUATORS.get((section_name, rule["rule_check"]))
        if evaluator is None:
            not_evaluated.append({"rule_check": rule["rule_check"], "reason": "No evaluator implemented for this rule"})
            continue
        if unsynced:
            skipped_unsynced += 1
            continue
        result = evaluator(ctx)
        # An evaluator returns its instances, or {"instances", "summary"} when
        # the result also has a one-line headline (e.g. the scan failure rate).
        summary = result.get("summary") if isinstance(result, dict) else None
        instances = result["instances"] if isinstance(result, dict) else result
        if instances:
            violations.append({
                "summary": summary,
                "rule_key": rule["rule_key"],
                "rule_check": rule_catalog.display_text(rule["rule_check"], ctx["look_back_days"]),
                "reasoning": rule_catalog.display_text(rule["reasoning"], ctx["look_back_days"]),
                "warning_level": rule["warning_level"],
                "instances": instances,
            })
        else:
            passed += 1
    violations.sort(key=lambda v: _LEVEL_RANK.get(v["warning_level"], 3))
    return {
        "name": section_name,
        "label": rule_catalog.SECTION_LABELS.get(section_name, section_name),
        "ran_at": ran_at,
        "violations": violations,
        "not_evaluated": not_evaluated,
        "unsynced": unsynced if skipped_unsynced else [],
        "skipped_unsynced": skipped_unsynced,
        "passed": passed,
        "disabled": disabled,
    }


def _not_run_section(section_name: str) -> dict:
    return {
        "name": section_name,
        "label": rule_catalog.SECTION_LABELS.get(section_name, section_name),
        "not_run": True, "ran_at": None, "violations": [], "not_evaluated": [],
        "unsynced": [], "skipped_unsynced": 0, "passed": 0, "disabled": 0,
    }


def _totals(sections: list[dict]) -> dict:
    return {
        "violations": sum(len(s["violations"]) for s in sections),
        "instances": sum(len(v["instances"]) for s in sections for v in s["violations"]),
        "passed": sum(s["passed"] for s in sections),
        "disabled": sum(s["disabled"] for s in sections),
        "not_evaluated": sum(len(s["not_evaluated"]) + s["skipped_unsynced"] for s in sections),
    }


def run_analysis(policy_rule_summary, rule_section: str | None = None) -> dict:
    """Evaluate every rule section, or only rule_section (a rule-set section
    name such as "Policies"), merging that one section into the stored report
    and leaving the other sections' last results untouched.

    policy_rule_summary is app.py's _policy_rule_summary, passed in so the
    "has no rules" check counts rules exactly the way the Policies page does."""
    sync_meta = db.all_sync_meta()
    ctx = _build_context(policy_rule_summary)
    ran_at = datetime.now(timezone.utc).isoformat()
    previous = {s["name"]: s for s in (db.get_analyzer_report() or {}).get("sections", [])}

    sections = []
    for section_name, rules in rule_catalog.effective_rules().items():
        if rule_section is None or section_name == rule_section:
            sections.append(_evaluate_section(section_name, rules, ctx, sync_meta, ran_at))
        else:
            sections.append(previous.get(section_name) or _not_run_section(section_name))

    report = {"ran_at": ran_at, "sections": sections, "totals": _totals(sections)}
    db.save_analyzer_report(report)
    return report


def page_highlights(page_key: str) -> dict:
    """From the last stored report, the highlights for one section page:
    {"targets": {target: {"level", "rules"}}, "section_wide": [violations
    with no single row to highlight], "ran_at"}. Each target takes the
    most severe level of all the rules it violates."""
    empty = {"targets": {}, "section_wide": [], "ran_at": None}
    report = db.get_analyzer_report()
    rule_section = PAGE_RULE_SECTION.get(page_key)
    if not report or not rule_section:
        return empty
    targets, section_wide, ran_at = {}, [], None
    for section in report["sections"]:
        if section["name"] != rule_section:
            continue
        ran_at = section.get("ran_at", report["ran_at"])
        for violation in section["violations"]:
            level = violation["warning_level"]
            untargeted = []
            for instance in violation["instances"]:
                # Reports saved before targets existed hold plain strings.
                target = instance.get("target") if isinstance(instance, dict) else None
                if not target:
                    untargeted.append(instance["label"] if isinstance(instance, dict) else str(instance))
                    continue
                entry = targets.setdefault(target, {"level": level, "rules": []})
                entry["rules"].append(f"{level}: {violation['rule_check']}")
                if _LEVEL_RANK.get(level, 3) < _LEVEL_RANK.get(entry["level"], 3):
                    entry["level"] = level
            if untargeted:
                section_wide.append({
                    "rule_check": violation["rule_check"], "warning_level": level,
                    "details": untargeted, "summary": violation.get("summary"),
                })
    return {"targets": targets, "section_wide": section_wide, "ran_at": ran_at}
