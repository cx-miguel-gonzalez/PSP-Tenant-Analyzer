"""Single source of truth for the console's 8 review sections: sidebar
entries, routes, and sync orchestration are all generated from this list
instead of being hand-duplicated per section in app.py."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import cx_client
import db
import health

logger = logging.getLogger(__name__)

# Minimal, hand-drawn inline SVG icons (24x24, stroke=currentColor) so the
# sidebar has no external icon-font/build-step dependency.
_ICON_GEAR = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="3"/><path d="M12 3v2.5M12 18.5V21M21 12h-2.5M5.5 12H3M18.36 5.64l-1.77 1.77M7.41 16.59l-1.77 1.77M18.36 18.36l-1.77-1.77M7.41 7.41 5.64 5.64" stroke-linecap="round"/></svg>"""
_ICON_LIST = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M8 6h12M8 12h12M8 18h12" stroke-linecap="round"/><path d="M4 6h.01M4 12h.01M4 18h.01" stroke-linecap="round" stroke-width="2.4"/></svg>"""
_ICON_PULSE = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M3 12h4l2-7 4 14 2-7h6" stroke-linecap="round" stroke-linejoin="round"/></svg>"""
_ICON_PLUG = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M9 3v5M15 3v5M7 8h10v3a5 5 0 0 1-5 5 5 5 0 0 1-5-5V8Z"/><path d="M12 16v5" stroke-linecap="round"/></svg>"""
_ICON_TICKET = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 8a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-2a2 2 0 0 0 0-4V8Z"/><path d="M14 6v12" stroke-dasharray="2 2"/></svg>"""
_ICON_SHIELD = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3Z"/><path d="M9 12l2 2 4-4" stroke-linecap="round" stroke-linejoin="round"/></svg>"""
_ICON_LAYERS = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="m12 3 9 5-9 5-9-5 9-5Z" stroke-linejoin="round"/><path d="m3 13 9 5 9-5" stroke-linejoin="round"/></svg>"""
_ICON_CLOCK = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2" stroke-linecap="round" stroke-linejoin="round"/></svg>"""
_ICON_HOME = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="m3 11 9-7 9 7" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 10v9a1 1 0 0 0 1 1h4v-6h4v6h4a1 1 0 0 0 1-1v-9" stroke-linecap="round" stroke-linejoin="round"/></svg>"""
_ICON_SLIDERS = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 6h6M14 6h6M4 12h10M18 12h2M4 18h4M12 18h8" stroke-linecap="round"/><circle cx="12" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/></svg>"""


def _sync_global_configurations(sess: dict) -> tuple[int, str]:
    entries = cx_client.list_tenant_configuration(sess["base_url"], sess["token"])
    count = db.replace_tenant_configuration(entries)
    return count, f"Synced {count} configuration entries."


def _sync_preset_management(sess: dict, refresh_catalog: bool = False, progress=None) -> tuple[int, str]:
    # The query catalog (families -> categories -> queries) is mostly
    # static, so it's only (re)fetched when the local cache is empty or a
    # refresh was explicitly requested -- not on every sync. Presets only
    # reference queries by id grouped under a family, with no name/
    # category/severity attached, so those must be resolved against this
    # catalog to display anything meaningful.
    def report(current, total, message):
        if progress is not None:
            progress(current, total, message)

    cached_catalog_count = db.query_catalog_count()
    need_catalog = refresh_catalog or cached_catalog_count == 0

    families = cx_client.list_query_families(sess["base_url"], sess["token"]) if need_catalog else []
    summaries = cx_client.list_presets(sess["base_url"], sess["token"])
    total_units = len(families) + len(summaries)
    done = 0
    report(0, total_units, "Starting...")

    catalog_note = ""
    if need_catalog:
        queries_synced = 0
        for family in families:
            queries = cx_client.list_queries_in_family(sess["base_url"], sess["token"], family)
            for query in queries:
                db.upsert_query_catalog_entry(family, query)
            queries_synced += len(queries)
            done += 1
            report(
                done, total_units,
                f"Syncing query catalog... {done} of {len(families)} families loaded "
                f"({queries_synced} queries so far)",
            )
        catalog_note = f" and {len(families)} query famil{'y' if len(families) == 1 else 'ies'} ({queries_synced} queries)"
    else:
        catalog_note = f" (query catalog cached: {cached_catalog_count} queries)"

    full_presets = []
    for i, summary in enumerate(summaries, start=1):
        preset_id = summary.get("id")
        if preset_id is not None:
            full_presets.append(cx_client.get_preset(sess["base_url"], sess["token"], preset_id))
        done += 1
        report(done, total_units, f"Syncing presets... {i} of {len(summaries)} loaded")

    count = db.replace_presets(full_presets)
    report(total_units, total_units, f"Synced {count} preset(s){catalog_note}.")
    return count, f"Synced {count} preset(s){catalog_note}."


def _sync_scan_health(sess: dict, progress=None) -> tuple[int, str]:
    def report(current, total, message):
        if progress is not None:
            progress(current, total, message)

    days_back = health.look_back_days()  # the Overview page's Look Back (0 = All Time)
    since = None
    window_note = "all time"
    if days_back and days_back > 0:
        since = datetime.now(timezone.utc) - timedelta(days=days_back)
        window_note = f"past {days_back} days"
    scans = cx_client.list_scans(sess["base_url"], sess["token"], limit=5000, since=since)

    # LOC is an enrichment from a separate batch call, not part of /api/scans
    # itself -- if it fails, still complete the sync (Scan Health doesn't
    # depend on it) rather than losing every scan over a missing LOC figure.
    loc_by_id = {}
    scan_ids = [str(s.get("id")) for s in scans if s.get("id") is not None]
    if scan_ids:
        try:
            loc_by_id = cx_client.get_sast_metadata(sess["base_url"], sess["token"], scan_ids)
        except Exception:
            # Deliberately broad: LOC is a nice-to-have enrichment, not core
            # to Scan Health, so anything going wrong here (an HTTP error,
            # or a response shape that doesn't match what's expected) should
            # degrade to "no LOC data" rather than losing the whole sync via
            # _run_section_sync's outer catch-all. Still logged, so a
            # persistent problem (e.g. a wrong endpoint on some tenant) is
            # visible in the server console instead of silently vanishing.
            logger.exception("Failed to fetch SAST metadata (LOC) for %d scan(s)", len(scan_ids))
            loc_by_id = {}

    count = db.replace_scans(scans, loc_by_id)

    # Workflows feed the Top 10 Errors KPI. Only Failed/Partial scans not yet
    # cached are fetched; a scan whose workflow can't be fetched is skipped
    # (and retried next sync) rather than failing the sync.
    db.prune_scan_workflows()
    cached = db.cached_workflow_scan_ids()
    to_fetch = [str(s["id"]) for s in db.failed_partial_scans() if str(s["id"]) not in cached]
    unavailable = 0
    for i, scan_id in enumerate(to_fetch, start=1):
        report(i - 1, len(to_fetch), f"Fetching workflows of failed/partial scans... {i} of {len(to_fetch)}")
        try:
            db.save_scan_workflow(scan_id, cx_client.get_scan_workflow(sess["base_url"], sess["token"], scan_id))
        except cx_client.CxApiError:
            logger.exception("Failed to fetch workflow for scan %s", scan_id)
            unavailable += 1
    message = f"Synced {count} scan(s) ({window_note})."
    if to_fetch:
        message += f" Fetched {len(to_fetch) - unavailable} failed/partial scan workflow(s)."
    if unavailable:
        message += f" {unavailable} workflow(s) unavailable."
    return count, message


def _sync_integrations(sess: dict) -> tuple[int, str]:
    scms = cx_client.list_scms(sess["base_url"], sess["token"])
    scm_count = db.replace_scm_connections(scms)

    orgs = cx_client.list_scm_orgs(sess["base_url"], sess["token"])
    org_count = db.replace_scm_orgs(orgs)

    return scm_count + org_count, f"Synced {scm_count} SCM connection(s) and {org_count} org(s)."


def _sync_feedback_profiles(sess: dict) -> tuple[int, str]:
    apps = []
    profiles = []
    errors = []
    for label, fetch, key in (
        ("Apps", cx_client.list_feedback_apps, "apps"),
        ("Profiles", cx_client.list_feedback_profiles, "profiles"),
    ):
        try:
            if key == "apps":
                apps = fetch(sess["base_url"], sess["token"])
            else:
                profiles = fetch(sess["base_url"], sess["token"])
        except cx_client.CxEndpointUnavailable as exc:
            errors.append(f"{label}: {exc}")
    app_count = db.replace_feedback_apps(apps)
    profile_count = db.replace_feedback_profiles(profiles)
    count = app_count + profile_count
    message = f"Synced {app_count} app(s) and {profile_count} profile(s)."
    if errors:
        message += " Not available: " + "; ".join(errors)
    return count, message


def _sync_policies(sess: dict, progress=None) -> tuple[int, str]:
    def report(current, total, message):
        if progress is not None:
            progress(current, total, message)

    report(0, 0, "Loading policies...")
    try:
        policies = cx_client.list_policies(sess["base_url"], sess["token"])
    except cx_client.CxEndpointUnavailable as exc:
        db.replace_policies([])
        db.replace_policy_violations([])
        db.replace_policy_evaluations([])
        return 0, f"Policy Management is not available on this tenant ({exc})."

    engine_rule_errors = []
    engine_rule_count = 0
    engines = ("ai_sc", "sca", "sast", "kics", "containers")
    engine_policies = [
        policy for policy in policies
        if isinstance(policy, dict)
        and str(policy.get("type") or policy.get("ruleType") or "").upper()
        in {"ENGINES_RULES", "ENGINE_RULES", "ENGINE RULES"}
    ]
    scans_to_sync = db.completed_project_scans()
    total_steps = 1 + len(engine_policies) * len(engines) + len(scans_to_sync) * 2
    completed_steps = 1
    report(completed_steps, total_steps, f"Loaded {len(policies)} policies. Preparing engine rules...")

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        policy_type = str(policy.get("type") or policy.get("ruleType") or "").upper()
        if policy_type not in {"ENGINES_RULES", "ENGINE_RULES", "ENGINE RULES"}:
            continue
        policy_id = policy.get("id") or policy.get("policyId")
        if policy_id is None:
            engine_rule_errors.append(f"{policy.get('name') or 'Unnamed policy'} has no policy ID")
            continue

        rule_details = {}
        for engine in engines:
            report(
                completed_steps, total_steps,
                f"Loading {engine.replace('_', ' ').upper()} rules for {policy.get('name') or 'policy'}...",
            )
            try:
                payload = cx_client.get_policy_engine_rules(
                    sess["base_url"], sess["token"], str(policy_id), engine
                )
                rule_details[engine] = payload
                engine_rule_count += 1
            except cx_client.CxEndpointUnavailable:
                continue
            except cx_client.CxApiError as exc:
                engine_rule_errors.append(f"{engine} rules for policy {policy_id}: {exc}")
            completed_steps += 1
            report(completed_steps, total_steps, f"Loaded {engine.replace('_', ' ').upper()} rules.")
        policy["engineRuleDetails"] = rule_details

    policy_count = db.replace_policies(policies)
    violations = []
    evaluations = []
    errors = []
    details_available = True
    evaluations_available = True

    for scan in scans_to_sync:
        project_id = scan["project_id"]
        scan_id = scan["id"]
        context = {
            "project_id": project_id,
            "project_name": scan["project_name"],
            "branch": scan["branch"],
            "scan_id": scan_id,
        }
        if details_available:
            report(completed_steps, total_steps, f"Loading violations for {scan['project_name'] or project_id}...")
            try:
                policy_results = cx_client.list_policy_violations(
                    sess["base_url"], sess["token"], project_id, scan_id
                )
                for policy_result in policy_results:
                    if not isinstance(policy_result, dict):
                        continue
                    violated_rules = policy_result.get("rulesViolated") or []
                    if violated_rules:
                        for rule in violated_rules:
                            if not isinstance(rule, dict):
                                rule = {"ruleName": str(rule)}
                            violation = {
                                "policyName": policy_result.get("policyName"),
                                "description": policy_result.get("description"),
                                "tags": policy_result.get("tags"),
                                "breakBuild": policy_result.get("breakBuild"),
                                **rule,
                            }
                            violations.append({**context, "raw": violation})
                    else:
                        violations.append({**context, "raw": policy_result})
            except cx_client.CxEndpointUnavailable as exc:
                details_available = False
                errors.append(f"Violations: {exc}")
            except cx_client.CxApiError as exc:
                errors.append(f"Violations for {scan_id}: {exc}")
            completed_steps += 1
            report(completed_steps, total_steps, f"Loaded violations for {scan['project_name'] or project_id}.")
        else:
            completed_steps += 1
            report(completed_steps, total_steps, "Skipping detailed violations; endpoint is unavailable.")

        if evaluations_available:
            report(completed_steps, total_steps, f"Loading evaluation summary for {scan['project_name'] or project_id}...")
            try:
                evaluation = cx_client.get_policy_evaluation(
                    sess["base_url"], sess["token"], project_id, scan_id
                )
                evaluations.append({**context, "raw": evaluation})
            except cx_client.CxEndpointUnavailable as exc:
                evaluations_available = False
                errors.append(f"Evaluation: {exc}")
            except cx_client.CxApiError as exc:
                errors.append(f"Evaluation for {scan_id}: {exc}")
        completed_steps += 1
        report(completed_steps, total_steps, f"Loaded evaluation summary for {scan['project_name'] or project_id}.")

    violation_count = db.replace_policy_violations(violations)
    evaluation_count = db.replace_policy_evaluations(evaluations)
    message = (
        f"Synced {policy_count} polic(y/ies) and fetched {engine_rule_count} engine-rule response(s), "
        f"{violation_count} violation(s), "
        f"{evaluation_count} evaluation(s) across all completed cached project scans."
    )
    if engine_rule_errors:
        errors.extend(engine_rule_errors)
    if errors:
        message += " Incomplete: " + "; ".join(errors)
    report(total_steps, total_steps, "Policies sync complete.")
    return policy_count + violation_count + evaluation_count, message


def _sync_project_management(sess: dict, progress=None) -> tuple[int, str]:
    def report(current, total, message):
        if progress is not None:
            progress(current, total, message)

    scans = db.latest_completed_project_scans()
    applications_cached = db.list_applications()
    total_steps = len(scans) + len(applications_cached) + 2
    report(0, total_steps, "Syncing projects and applications...")
    projects = cx_client.list_projects(sess["base_url"], sess["token"])
    applications = cx_client.list_applications(sess["base_url"], sess["token"])
    project_count = db.replace_projects(projects)
    app_count = db.replace_applications(applications)
    applications_cached = db.list_applications()
    report(1, total_steps, f"Synced project records. Loading summaries for {len(scans)} latest completed scans...")

    summaries = []
    errors = []
    summary_endpoint_available = True
    for index, scan in enumerate(scans, start=1):
        scan_name = scan["project_name"] or scan["project_id"]
        if summary_endpoint_available:
            report(index, total_steps, f"Loading vulnerability summary for {scan_name}...")
            try:
                summary = cx_client.get_scan_summary(
                    sess["base_url"], sess["token"], str(scan["id"])
                )
                summaries.append({
                    "scan_id": str(scan["id"]),
                    "project_id": scan["project_id"],
                    "project_name": scan["project_name"],
                    "raw": summary,
                })
            except cx_client.CxEndpointUnavailable as exc:
                summary_endpoint_available = False
                errors.append(f"Scan summary: {exc}")
            except cx_client.CxApiError as exc:
                errors.append(f"Scan summary for {scan['id']}: {exc}")
        report(index + 1, total_steps, f"Processed scan summary for {scan_name}.")

    summary_count = db.replace_scan_summaries(summaries)
    assignments_synced = 0
    authorization_errors = []
    try:
        report(len(scans) + 1, total_steps, "Discovering application resource IDs...")
        resource_payload = cx_client.list_accessible_resources(
            sess["base_url"], sess["token"], "view-results", ["application"]
        )
        resources = resource_payload.get("resources") or []
        resource_ids = {
            str(resource.get("resourceId")): resource
            for resource in resources if isinstance(resource, dict) and resource.get("resourceId") is not None
        }
        assignments = []
        for index, application in enumerate(applications_cached, start=1):
            application_id = str(application["id"])
            resource = resource_ids.get(application_id)
            entities = []
            if resource is not None:
                report(
                    len(scans) + 1 + index, total_steps,
                    f"Loading authorization assignments for {application['name']}...",
                )
                try:
                    entities = cx_client.list_resource_entities(
                        sess["base_url"], sess["token"], application_id, "application"
                    )
                except cx_client.CxEndpointUnavailable as exc:
                    authorization_errors.append(f"{application['name']}: {exc}")
                except cx_client.CxApiError as exc:
                    authorization_errors.append(f"{application['name']}: {exc}")
            assignments.append({"application_id": application_id, "entities": entities})
            report(
                len(scans) + 1 + index, total_steps,
                f"Processed authorizations for {application['name']}.",
            )
        assignments_synced = db.replace_application_authorizations(assignments)
    except cx_client.CxEndpointUnavailable as exc:
        authorization_errors.append(f"Application resources: {exc}")
    except cx_client.CxApiError as exc:
        authorization_errors.append(f"Application resources: {exc}")

    message = (
        f"Synced {project_count} project(s), {app_count} application(s), "
        f"{summary_count} scan summary(ies), and {assignments_synced} application authorization record(s)."
    )
    errors.extend(authorization_errors)
    if errors:
        message += " Incomplete: " + "; ".join(errors)
    return project_count + app_count + summary_count, message


# Stale Projects has no sync of its own -- it's derived from
# Project Management + Scan Health data already in SQLite.


SECTIONS = [
    {
        "key": "global_configurations",
        "label": "Global Configurations",
        "icon": _ICON_GEAR,
        "sync_fn": _sync_global_configurations,
    },
    {
        "key": "preset_management",
        "label": "Preset Management",
        "icon": _ICON_LIST,
        "sync_fn": _sync_preset_management,
    },
    {
        "key": "scan_health",
        "label": "Scan Health",
        "icon": _ICON_PULSE,
        "sync_fn": _sync_scan_health,
    },
    {
        "key": "integrations",
        "label": "Integrations",
        "icon": _ICON_PLUG,
        "sync_fn": _sync_integrations,
    },
    {
        "key": "feedback_profiles",
        "label": "Feedback Apps",
        "icon": _ICON_TICKET,
        "sync_fn": _sync_feedback_profiles,
    },
    {
        "key": "policies",
        "label": "Policies",
        "icon": _ICON_SHIELD,
        "sync_fn": _sync_policies,
    },
    {
        "key": "project_management",
        "label": "Project/Application Management",
        "icon": _ICON_LAYERS,
        "sync_fn": _sync_project_management,
    },
    {
        "key": "stale_projects",
        "label": "Stale Projects",
        "icon": _ICON_CLOCK,
        "sync_fn": None,  # derived from project_management + scan_health, no API call of its own
    },
]

SECTIONS_BY_KEY = {s["key"]: s for s in SECTIONS}

DASHBOARD_ICON = _ICON_HOME
ANALYZER_CONFIG_ICON = _ICON_SLIDERS
RECOMMENDATIONS_ICON = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M9 18h6M10 21h4" stroke-linecap="round"/><path d="M12 3a6 6 0 0 0-3.5 10.9c.6.4 1 1.1 1 1.8V16h5v-.3c0-.7.4-1.4 1-1.8A6 6 0 0 0 12 3Z" stroke-linejoin="round"/></svg>"""
