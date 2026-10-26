"""Checkmarx One Tenant Analyzer.

Local Flask console: authenticate to a CxOne tenant, sync 8 review areas
(Global Configurations, Preset Management, Scan Health, Integrations,
Feedback Apps and Profiles, Policies, Project/Application Management, Stale
Projects) into a local SQLite cache, and browse a health/recommendations
view. Every page renders from the local cache -- never live from the API.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime
from itertools import groupby
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, Response, flash, g, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect

import analyzer
import cx_client
import db
import diff
import export
import health
import pdf_report
import rule_catalog
import scan_errors
from sections import SECTIONS, SECTIONS_BY_KEY, DASHBOARD_ICON, ANALYZER_CONFIG_ICON, RECOMMENDATIONS_ICON

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["WTF_CSRF_TIME_LIMIT"] = None  # token lives as long as the session, so a page left open still submits

# Every POST (forms and app.js fetches) must carry this session's CSRF token,
# so another site can't submit forms here -- e.g. post to /login to sign the
# browser into a different tenant or point the app at other hosts.
csrf = CSRFProtect(app)

# Tenant data cached from the API reaches pages only through Jinja
# autoescaping or JSON read by app.js via textContent. This policy is the
# backstop if that ever slips: only same-origin scripts may run (no inline
# or injected <script>, no event-handler attributes), and responses can't be
# MIME-sniffed into HTML. Inline styles stay allowed for the computed chart
# widths/colors in the templates.
_CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


@app.after_request
def _set_security_headers(response):
    response.headers.setdefault("Content-Security-Policy", _CONTENT_SECURITY_POLICY)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    if request.is_secure:  # only meaningful over https; never sent on the local http server
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


@app.errorhandler(CSRFError)
def _csrf_failed(error):
    flash("That form expired or didn't come from this app. Please try again.", "error")
    return redirect(url_for("dashboard"))


@app.template_filter("from_json")
def _from_json_filter(value):
    if not value:
        return []
    return json.loads(value)


@app.template_filter("yesno")
def _yesno_filter(value):
    return "Yes" if value else "No"


# Words that should render as an acronym (all caps) rather than Title Case
# when humanizing a dotted tenant-config key into a display label.
_KEY_ACRONYMS = {
    "ai", "api", "url", "id", "sca", "sast", "kics", "iast", "ci", "cd",
    "sso", "saml", "jwt", "ui", "ip", "os", "db", "sql", "http", "https",
}


@app.template_filter("humanize_key")
def _humanize_key_filter(key: str) -> str:
    """'scan.config.ai.allowAiUsage' -> 'Allow AI Usage' -- last dotted
    segment, camelCase split, known acronyms upper-cased."""
    if not key:
        return key
    last_segment = key.rsplit(".", 1)[-1]
    words = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", last_segment)
    if not words:
        return last_segment
    return " ".join(w.upper() if w.lower() in _KEY_ACRONYMS else w.capitalize() for w in words)


@app.template_filter("display_value")
def _display_value_filter(value):
    """Unwrap a JSON-encoded tenant-config value for display -- a string
    value shows without its surrounding quotes, booleans show as Yes/No."""
    if value is None:
        return ""
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return value
    if isinstance(parsed, bool):
        return "Yes" if parsed else "No"
    if parsed is None:
        return ""
    return parsed


@app.template_filter("override_label")
def _override_label_filter(value):
    """tenant_config.allow_override is NULL when the tenant's config entry
    has no allow-override concept at all (N/A), 0/1 otherwise."""
    if value is None:
        return "N/A"
    return "Yes" if value else "No"


@app.template_filter("duration_label")
def _duration_label_filter(minutes):
    """Every scan-duration value on the Scan Health page (the Scans table,
    Long-Running, Inconsistent) goes through this one filter, so "45 min"
    vs "1 hr 5 min" formatting can't drift between widgets."""
    if minutes is None:
        return "—"
    # Round first, then branch on the rounded value -- julianday() arithmetic
    # can land a whole-minute duration at e.g. 59.99999977648258, which would
    # otherwise take the < 60 branch and print "60.0 min" instead of "1 hr 0 min".
    minutes = round(float(minutes), 1)
    if minutes < 60:
        return f"{minutes} min"
    hours, remainder = divmod(minutes, 60)
    hours, remainder = int(hours), round(remainder)
    if remainder == 60:  # rounding carry, e.g. 119.6 -> 2 hr 0 min not 1 hr 60 min
        hours += 1
        remainder = 0
    return f"{hours} hr{'s' if hours != 1 else ''} {remainder} min"


# In-memory, per-process session store. Deliberately never persisted to disk:
# credentials and tokens live only as long as this process runs.
_SESSIONS: dict[str, dict] = {}

# In-memory sync-job progress, keyed by (sid, section_key) or (sid, "all").
_SYNC_STATUS: dict[tuple[str, str], dict] = {}
_sync_lock = threading.Lock()

def _current_session() -> dict | None:
    sid = session.get("sid")
    if not sid:
        return None
    return _SESSIONS.get(sid)


def _ensure_token(sess: dict) -> None:
    """Refresh the access token in-place if it has expired."""
    if sess["expires_at"] > time.time() + 5:
        return
    token, expires_in = cx_client.get_access_token(
        sess["iam_url"],
        sess["tenant"],
        sess["auth_method"],
        client_id=sess.get("client_id"),
        client_secret=sess.get("client_secret"),
        api_key=sess.get("api_key"),
    )
    sess["token"] = token
    sess["expires_at"] = time.time() + expires_in


def _env_config() -> dict | None:
    """Credentials supplied via a local .env file (see .env.example), so the
    login form doesn't need to be retyped every run. Returns None if no
    usable set of credentials is present."""
    tenant = os.environ.get("CX_TENANT", "").strip()
    if not tenant:
        return None

    api_key = os.environ.get("CX_API_KEY", "").strip() or None
    client_id = os.environ.get("CX_CLIENT_ID", "").strip() or None
    client_secret = os.environ.get("CX_CLIENT_SECRET", "").strip() or None
    if not api_key and not (client_id and client_secret):
        return None

    auth_method = os.environ.get("CX_AUTH_METHOD", "").strip()
    if auth_method not in ("api_key", "client_credentials"):
        auth_method = "api_key" if api_key else "client_credentials"

    return {
        "tenant": tenant,
        "base_url": os.environ.get("CX_BASE_URL", "").strip() or cx_client.DEFAULT_BASE_URL,
        "iam_url": os.environ.get("CX_IAM_URL", "").strip() or cx_client.DEFAULT_IAM_URL,
        "auth_method": auth_method,
        "client_id": client_id,
        "client_secret": client_secret,
        "api_key": api_key,
    }


def _establish_session(base_url, iam_url, tenant, auth_method, client_id, client_secret, api_key):
    try:
        base_url = cx_client.safe_endpoint(base_url)  # reject non-Checkmarx hosts before any request
        token, expires_in = cx_client.get_access_token(
            iam_url, tenant, auth_method,
            client_id=client_id, client_secret=client_secret, api_key=api_key,
        )
    except cx_client.CxApiError as exc:
        return exc

    tenant_name, tenant_uuid = _tenant_identity(token, tenant, base_url)
    db_path = db.tenant_db_path(tenant_name, tenant_uuid)
    # The pre-split shared database is copied into this tenant's file only if
    # all of its projects belong to this tenant.
    db.claim_legacy_db(tenant_uuid, db_path)

    sid = secrets.token_hex(16)
    _SESSIONS[sid] = {
        "base_url": base_url,
        "iam_url": iam_url,
        "tenant": tenant,
        "auth_method": auth_method,
        "client_id": client_id,
        "client_secret": client_secret,
        "api_key": api_key,
        "token": token,
        "expires_at": time.time() + expires_in,
        "db_path": str(db_path),
    }
    session["sid"] = sid
    return None


def _tenant_identity(token: str, tenant: str, base_url: str) -> tuple[str, str]:
    """(tenant name, tenant UUID) from the access token's own claims -- the
    UUID keeps same-named tenants in different regions apart. The token just
    came from IAM, so it's only decoded here, not verified. Falls back to the
    typed tenant name and the API host if the claims aren't there."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        claims = {}
    tenant_uuid = str(claims.get("tenant_id") or "").rsplit("::", 1)[-1]
    return str(claims.get("tenant_name") or tenant), tenant_uuid or (urlparse(base_url).hostname or "unknown-host")


def _complete_login(base_url, iam_url, tenant, auth_method, client_id, client_secret, api_key):
    error = _establish_session(base_url, iam_url, tenant, auth_method, client_id, client_secret, api_key)
    if error is not None:
        flash(f"Authentication failed: {error}", "error")
        return redirect(url_for("login"))
    flash("Signed in.", "success")
    return redirect(url_for("dashboard"))


@app.before_request
def require_login():
    if request.endpoint in ("login", "login_env", "static"):
        return None
    if _current_session() is None:
        return redirect(url_for("login"))
    g.tenant_db_token = db.use_tenant_db(_current_session()["db_path"])  # this tenant's own database


@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        env_config = _env_config()
        if env_config is not None and not session.get("suppress_auto_login"):
            error = _establish_session(
                env_config["base_url"], env_config["iam_url"], env_config["tenant"],
                env_config["auth_method"], env_config["client_id"],
                env_config["client_secret"], env_config["api_key"],
            )
            if error is None:
                flash("Signed in automatically using .env credentials.", "success")
                return redirect(url_for("dashboard"))
            session["suppress_auto_login"] = True
            flash(f"Automatic .env sign-in failed: {error}", "error")

        return render_template(
            "login.html",
            default_base_url=cx_client.DEFAULT_BASE_URL,
            default_iam_url=cx_client.DEFAULT_IAM_URL,
            env_config=env_config,
        )

    base_url = request.form.get("base_url", "").strip() or cx_client.DEFAULT_BASE_URL
    iam_url = request.form.get("iam_url", "").strip() or cx_client.DEFAULT_IAM_URL
    tenant = request.form.get("tenant", "").strip()
    auth_method = request.form.get("auth_method")
    client_id = request.form.get("client_id", "").strip() or None
    client_secret = request.form.get("client_secret", "").strip() or None
    api_key = request.form.get("api_key", "").strip() or None

    if not tenant:
        flash("Tenant name is required.", "error")
        return redirect(url_for("login"))

    return _complete_login(base_url, iam_url, tenant, auth_method, client_id, client_secret, api_key)


@app.route("/login/env", methods=["POST"])
def login_env():
    cfg = _env_config()
    if cfg is None:
        flash("No usable credentials found in .env.", "error")
        return redirect(url_for("login"))
    return _complete_login(
        cfg["base_url"], cfg["iam_url"], cfg["tenant"],
        cfg["auth_method"], cfg["client_id"], cfg["client_secret"], cfg["api_key"],
    )


@app.route("/logout", methods=["POST"])
def logout():
    sid = session.pop("sid", None)
    if sid:
        _SESSIONS.pop(sid, None)
    session["suppress_auto_login"] = True
    flash("Signed out.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
def _derived_stale_projects_meta():
    """Stale Projects has no sync of its own (sync_fn=None in sections.py) --
    it's a live join over Project Management + Scan Health data, so its
    sync_meta row sits at 'idle' forever even once both real sources have
    synced. Build a synthetic entry for the Overview card instead: ready
    only once BOTH sources have synced at least once, timestamped to the
    OLDER of the two (the data is only as fresh as the staler input), and
    carrying the worse of the two statuses."""
    project_meta = db.get_sync_meta("project_management")
    scan_meta = db.get_sync_meta("scan_health")
    metas = [project_meta, scan_meta]
    if any(m is None or not m["last_synced_at"] for m in metas):
        return None
    statuses = {m["status"] for m in metas}
    status = "error" if "error" in statuses else ("running" if "running" in statuses else "done")
    oldest_synced_at = min(m["last_synced_at"] for m in metas)
    stale_count = len(db.stale_projects(health.look_back_days()))
    return {"status": status, "last_synced_at": oldest_synced_at, "record_count": stale_count}


@app.route("/dashboard")
def dashboard():
    sync_meta = db.all_sync_meta()
    derived_stale_meta = _derived_stale_projects_meta()
    if derived_stale_meta is not None:
        sync_meta["stale_projects"] = derived_stale_meta
    return render_template(
        "dashboard.html", sync_meta=sync_meta, analyzer_report=db.get_analyzer_report(),
        look_back_days=health.look_back_days(), look_back_options=health.LOOK_BACK_OPTIONS,
    )


@app.route("/settings/look-back", methods=["POST"])
def set_look_back():
    days = request.form.get("look_back_days", type=int)
    try:
        health.set_look_back_days(days)
    except ValueError:
        flash("Unsupported look back.", "error")
        return redirect(url_for("dashboard"))
    flash(
        f"Look back set to {health.look_back_label(days)}. Sync Scan Health to pull scans for this window, "
        "then re-run the analysis.",
        "success",
    )
    return redirect(url_for("dashboard"))


def _recommendation_data():
    """(report, groups, severity_counts) shared by the Tenant Recommendations
    page and its PDF export, so the two can't drift apart."""
    report = db.get_analyzer_report()
    page_for_rule_section = {rule: page for page, rule in analyzer.PAGE_RULE_SECTION.items()}
    # Looked up from the catalog at render time (not frozen in the report) so
    # wording edits to analyzer_rules.json show without re-running the analysis.
    recommendations = {}
    for section_name, rules in rule_catalog.catalog().items():
        for rule in rules:
            recommendations[rule["rule_key"]] = rule["recommendation"]
            # Reports saved before rule_key was stored only carry the rule text.
            recommendations[(section_name, rule["rule_check"])] = rule["recommendation"]
    groups = []
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    for section in (report or {}).get("sections", []):
        if not section["violations"]:
            continue
        findings = []
        for violation in section["violations"]:
            severity_counts[violation["warning_level"]] = severity_counts.get(violation["warning_level"], 0) + 1
            findings.append({
                **violation,
                "recommendation": recommendations.get(
                    violation.get("rule_key"), recommendations.get((section["name"], violation["rule_check"]), "")
                ),
            })
        groups.append({
            "label": section["label"],
            "page_key": page_for_rule_section.get(section["name"]),
            "findings": findings,
        })
    return report, groups, severity_counts


@app.route("/recommendations")
def tenant_recommendations():
    report, groups, severity_counts = _recommendation_data()
    return render_template(
        "tenant_recommendations.html",
        report=report, groups=groups, severity_counts=severity_counts,
    )


@app.route("/recommendations/export.pdf")
def tenant_recommendations_pdf():
    report, groups, severity_counts = _recommendation_data()
    if report is None:
        flash('Run "Analyze Tenant Configurations" before exporting recommendations.', "error")
        return redirect(url_for("tenant_recommendations"))
    tenant = _current_session()["tenant"]
    pdf = pdf_report.build_recommendations_pdf(tenant, report, groups, severity_counts)
    filename = f"tenant-recommendations-{re.sub(r'[^A-Za-z0-9_-]+', '-', tenant)}-{report['ran_at'][:10]}.pdf"
    return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.route("/analyze", methods=["POST"])
def analyze_tenant():
    report = analyzer.run_analysis(_policy_rule_summary)
    totals = report["totals"]
    flash(
        f"Analysis complete: {totals['violations']} rule violation(s) across "
        f"{totals['instances']} instance(s). Violating items are now highlighted on each section page.",
        "success",
    )
    return redirect(url_for("dashboard") + "#analyzer-results")


# ---------------------------------------------------------------------------
# Section pages
# ---------------------------------------------------------------------------
def _global_configurations_context():
    rows = db.list_tenant_configuration()  # already ordered by category, key
    groups = [
        {"category": category or "Uncategorized", "rows": list(group_rows)}
        for category, group_rows in groupby(rows, key=lambda r: r["category"])
    ]
    return "global_configurations.html", {"groups": groups, "has_rows": bool(rows)}


def _preset_management_context():
    return "presets.html", {"rows": db.list_presets()}


# Reuses this app's own already-established status colors (the same tokens
# the Scans table's badges use) rather than introducing a second, unrelated
# palette -- so a status means the same color everywhere on the page.
_STATUS_PIE_COLORS = {
    "Completed": "var(--badge-done-text)",
    "Failed": "var(--badge-error-text)",
    "Partial": "var(--badge-warning-text)",
    "Canceled": "var(--cx-text-muted)",
}
_STATUS_PIE_DEFAULT_COLOR = "var(--cx-accent)"
_INTEGRATION_PIE_COLORS = [
    "var(--badge-done-text)", "var(--badge-warning-text)",
    "var(--cx-accent)", "var(--badge-error-text)",
]


def _build_pie_slices(status_breakdown):
    total = sum(row["count"] for row in status_breakdown)
    slices = []
    cursor = 0.0
    for row in status_breakdown:
        pct = (row["count"] / total * 100) if total else 0
        slices.append({
            "status": row["status"] or "Unknown",
            "count": row["count"],
            "pct": pct,
            "start": cursor,
            "end": cursor + pct,
            "color": _STATUS_PIE_COLORS.get(row["status"], _STATUS_PIE_DEFAULT_COLOR),
        })
        cursor += pct
    return slices, total


def _build_integration_pie_slices(type_counts):
    total = sum(row["count"] for row in type_counts)
    slices = []
    cursor = 0.0
    for index, row in enumerate(type_counts):
        pct = (row["count"] / total * 100) if total else 0
        slices.append({
            "label": row["label"],
            "count": row["count"],
            "pct": pct,
            "start": cursor,
            "end": cursor + pct,
            "color": _INTEGRATION_PIE_COLORS[index],
        })
        cursor += pct
    if total and slices:
        slices[-1]["end"] = 100.0
    return slices, total


def _scan_health_context():
    # All synced scans go to the template; the "Scans" table filters, sorts,
    # and paginates client-side (status tiles, per-column filters, sortable
    # headers) rather than needing a separate query per view.
    status_breakdown = db.scan_status_breakdown()
    pie_slices, total_scans = _build_pie_slices(status_breakdown)
    top_failing = db.top_failing_projects(limit=10)
    max_failure_count = max((row["failure_count"] for row in top_failing), default=0) or 1

    return "scan_health.html", {
        "look_back_label": health.look_back_label(health.look_back_days()),
        "status_breakdown": status_breakdown,
        "scans": db.list_scans_with_duration(),
        "pie_slices": pie_slices,
        "total_scans": total_scans,
        "top_failing": top_failing,
        "max_failure_count": max_failure_count,
        "long_running": db.long_running_scans_by_project(min_minutes=30),
        "inconsistent": db.inconsistent_scan_projects(min_scans=3, limit=10),
        "top_errors": scan_errors.top_errors(
            [dict(s) for s in db.failed_partial_scans()], db.scan_workflows_by_id(), limit=10,
        ),
    }


def _integrations_context():
    usage = db.integration_usage_breakdown()
    integration_totals = db.integration_type_totals()
    integration_pie_slices, integration_pie_total = _build_integration_pie_slices(
        db.integration_scan_type_counts()
    )
    max_integration_count = max((row["count"] for row in integration_totals), default=0)
    return "integrations.html", {
        "scm_connections": db.list_scm_connections(),
        "orgs_by_scm": db.list_scm_orgs_by_scm(),
        "cicd_usage": usage["cicd"],
        "ide_usage": usage["ide"],
        "platform_usage": usage["platform"],
        "custom_usage": usage["custom"],
        "integration_totals": integration_totals,
        "max_integration_count": max_integration_count,
        "integration_pie_slices": integration_pie_slices,
        "integration_pie_total": integration_pie_total,
        "scan_health_meta": db.get_sync_meta("scan_health"),
    }


def _feedback_profiles_context():
    return "feedback_apps.html", {
        "apps": db.list_feedback_apps(),
        "profiles": db.list_feedback_profiles(),
        "feedback_apps_by_id": {str(row["id"]): row["name"] for row in db.list_feedback_apps()},
        "projects_by_id": {str(row["id"]): row["name"] for row in db.list_projects()},
        "active_tab": request.args.get("tab", "apps"),
    }


def _policies_context():
    policies = []
    for row in db.list_policies():
        raw = json.loads(row["raw_json"])
        rule_type, rules = _policy_rule_summary(raw)
        project_value = (
            raw.get("projects") or raw.get("projectIds") or raw.get("projectsIds")
            or raw.get("associatedProjects") or raw.get("project_ids") or []
        )
        projects = project_value if isinstance(project_value, list) else []
        is_default = any(
            _policy_bool(raw.get(key)) is True
            for key in ("isDefault", "defaultPolicy", "is_default")
        ) or str(raw.get("scope", raw.get("policyType", ""))).lower() == "default"
        policies.append({
            "id": row["id"],
            "name": row["name"] or raw.get("displayName") or "Unnamed policy",
            "rule_type": rule_type,
            "rules": rules,
            "exemptions": _policy_values(raw.get("exemptions") or raw.get("exceptions") or raw.get("exemptedProjects")),
            "break_build": _policy_break_build(raw),
            "project_association": "Default" if is_default else str(
                raw.get("projectCount") if raw.get("projectCount") is not None else len(projects)
            ),
        })
    evaluations = db.list_policy_evaluations()
    evaluations_by_scan = {
        str(row["scan_id"]): json.loads(row["raw_json"])
        for row in evaluations
    }
    scans_by_id = {str(row["id"]): row for row in db.list_scans()}
    violation_rows = []
    seen_violation_keys = set()
    for row in db.list_policy_violations():
        raw = json.loads(row["raw_json"])
        seen_violation_keys.add(_policy_violation_key(row["scan_id"], row["policy_name"], raw))
        violation_rows.append({
            "record": dict(row),
            "raw": raw,
            "summary": _policy_evaluation_summary(evaluations_by_scan.get(str(row["scan_id"]))),
            "details": _policy_violation_details(raw),
        })
    for evaluation in evaluations:
        scan_id = str(evaluation["scan_id"])
        evaluation_data = evaluations_by_scan.get(scan_id) or {}
        scan = scans_by_id.get(scan_id)
        for policy in evaluation_data.get("policies") or []:
            if not isinstance(policy, dict):
                continue
            rules_violated = policy.get("rulesViolated") or []
            if not isinstance(rules_violated, list):
                rules_violated = [rules_violated]
            for rule in rules_violated:
                raw = rule if isinstance(rule, dict) else {"violationName": str(rule)}
                violation_key = _policy_violation_key(scan_id, policy.get("policyName"), raw)
                if violation_key in seen_violation_keys:
                    continue
                seen_violation_keys.add(violation_key)
                record = {
                    "project_name": evaluation["project_name"],
                    "project_id": evaluation["project_id"],
                    "branch": scan["branch"] if scan else None,
                    "policy_name": policy.get("policyName"),
                    "scan_id": scan_id,
                    "raw_json": json.dumps(raw),
                }
                violation_rows.append({
                    "record": record,
                    "raw": raw,
                    "summary": _policy_evaluation_summary(evaluation_data),
                    "details": _policy_violation_details(raw),
                })
    project_incident_counts = {}
    rule_incident_counts = {}
    for violation in violation_rows:
        record = violation["record"]
        project_id = record.get("project_id") or record.get("project_name") or "Unknown project"
        project_name = record.get("project_name") or str(project_id)
        if project_id not in project_incident_counts:
            project_incident_counts[project_id] = {"project_name": project_name, "count": 0}
        project_incident_counts[project_id]["count"] += 1

        raw = violation["raw"]
        rule_name = raw.get("ruleName") or raw.get("violationName") or raw.get("name")
        if not rule_name:
            findings = raw.get("findings") or []
            query_names = sorted({
                str(finding.get("queryName"))
                for finding in findings if isinstance(finding, dict) and finding.get("queryName")
            })
            rule_name = ", ".join(query_names) if query_names else raw.get("message") or "Unspecified rule"
        rule_incident_counts[str(rule_name)] = rule_incident_counts.get(str(rule_name), 0) + 1

    project_incidents = sorted(
        project_incident_counts.values(), key=lambda item: (-item["count"], item["project_name"].casefold())
    )
    top_violated_rules = [
        {"rule_name": name, "count": count}
        for name, count in sorted(rule_incident_counts.items(), key=lambda item: (-item[1], item[0].casefold()))[:10]
    ]
    return "policies.html", {
        "policies": policies,
        "violations": violation_rows,
        "project_incidents": project_incidents,
        "top_violated_rules": top_violated_rules,
        "max_rule_incidents": max((item["count"] for item in top_violated_rules), default=0) or 1,
        "evaluations": evaluations,
        "active_tab": request.args.get("tab", "policies"),
    }


def _policy_violation_key(scan_id, policy_name, raw):
    identity = (
        raw.get("id") or raw.get("violationId") or raw.get("queryId")
        or raw.get("ruleId") or raw.get("violationName") or raw.get("ruleName")
        or raw.get("name") or raw.get("message") or json.dumps(raw, sort_keys=True)
    )
    return str(scan_id), str(policy_name or "").casefold(), str(identity).casefold()


def _policy_evaluation_summary(payload):
    if not isinstance(payload, (dict, list)):
        return "—"
    summary_keys = {
        "evaluationstatus": "Status", "status": "Status", "outcome": "Outcome",
        "verdict": "Verdict", "result": "Result", "summary": "Summary",
        "message": "Message", "breakbuild": "Break Build",
        "breakbuildenabled": "Break Build", "violationcount": "Violations",
        "totalviolations": "Violations", "policyviolationscount": "Violations",
        "findingscount": "Findings", "totalcount": "Total", "failedcount": "Failed",
        "passedcount": "Passed", "isviolated": "Violated", "hasviolations": "Has Violations",
        "policyresult": "Policy Result", "isbreakbuild": "Break Build",
    }
    values = []

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = "".join(char for char in str(key).lower() if char.isalnum())
                label = summary_keys.get(normalized_key)
                if label and isinstance(item, (str, int, float, bool)):
                    display = "Yes" if item is True else "No" if item is False else str(item)
                    pair = (label, display)
                    if pair not in values:
                        values.append(pair)
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(payload)
    return " · ".join(f"{label}: {value}" for label, value in values[:5]) or "Evaluation recorded"


def _policy_violation_details(raw):
    detail_keys = {
        "queryname": "Query Name", "querytitle": "Query Name", "queryid": "Query ID",
        "findingname": "Finding", "findingtitle": "Finding", "findingid": "Finding ID",
        "similarityid": "Similarity ID", "resultid": "Result ID",
        "rulename": "Rule", "ruleid": "Rule ID",
        "scanner": "Scanner", "engine": "Scanner", "severity": "Severity",
        "description": "Description", "message": "Finding Details",
        "sourcefile": "File", "filename": "File", "filepath": "File",
        "path": "File", "line": "Line", "linenumber": "Line",
        "cweid": "CWE", "cwe": "CWE",
    }
    details = []

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = "".join(char for char in str(key).lower() if char.isalnum())
                label = detail_keys.get(normalized_key)
                if label and isinstance(item, (str, int, float)) and str(item).strip():
                    pair = (label, str(item))
                    if pair not in details:
                        details.append(pair)
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(raw)
    return details


def _policy_rule_summary(raw):
    raw_type = str(raw.get("type") or raw.get("ruleType") or "").strip().upper()
    if raw_type in {"NET_NEW", "NET NEW"}:
        rule_type = "Net New"
    elif raw_type in {"ENGINES_RULES", "ENGINE_RULES", "ENGINE RULES"}:
        rule_type = "Engine Rules"
    else:
        rule_type = raw_type.replace("_", " ").title() if raw_type else "Unknown"

    rules = []
    all_scanner_severities = raw.get("allScannersSeverities") or raw.get("allScannerSeverities")
    if all_scanner_severities:
        for severity in _policy_severity_values(all_scanner_severities):
            rules.append({"label": f"All Scanners: {severity}", "severity": severity.lower()})

    scanner_severities = raw.get("scannerSeverities") or raw.get("scannersSeverities")
    for scanner, severity in _policy_scanner_severities(scanner_severities):
        rules.append({"label": f"{scanner}: {severity}", "severity": severity.lower()})

    engine_labels = {
        "ai_sc": "AI Security",
        "sca": "SCA",
        "sast": "SAST",
        "kics": "KICS",
        "containers": "Containers",
    }
    for engine, payload in (raw.get("engineRuleDetails") or {}).items():
        scanner = engine_labels.get(engine, str(engine).replace("_", " ").upper())
        entries = _policy_engine_rule_entries(payload)
        for entry in entries:
            rules.append({
                "label": f"{scanner}: {entry['label']}",
                "severity": entry.get("severity", "").lower(),
            })

    unique_rules = []
    seen_labels = set()
    for rule in rules:
        normalized_label = rule["label"].casefold()
        if normalized_label not in seen_labels:
            seen_labels.add(normalized_label)
            unique_rules.append(rule)

    return rule_type, unique_rules


def _policy_engine_rule_entries(payload):
    severity_names = {"critical", "high", "medium", "low", "info", "informational"}
    severities = []
    rule_names = []

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = str(key).replace("_", "").lower()
                if normalized_key in {"severity", "severities", "severitylevel", "severitylevels"}:
                    for severity in _policy_severity_values(item):
                        if severity.casefold() in severity_names:
                            severities.append(severity)
                if normalized_key in {"rulename", "displayname", "queryname", "title"}:
                    if isinstance(item, (str, int, float)) and str(item).strip():
                        rule_names.append(str(item).strip())
                visit(item)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (str, int, float)):
                    text = str(item).strip()
                    if text and text.casefold() not in severity_names:
                        rule_names.append(text)
                else:
                    visit(item)

    visit(payload)
    if severities:
        labels = []
        for severity in severities:
            normalized = severity.casefold()
            label = "Info" if normalized == "informational" else severity
            if label.casefold() not in {item.casefold() for item in labels}:
                labels.append(label)
        return [{"label": severity, "severity": severity} for severity in labels]

    return [
        {"label": name, "severity": ""}
        for name in dict.fromkeys(rule_names)
    ]


def _policy_severity_values(value):
    if isinstance(value, dict):
        value = value.get("severities") or value.get("severity") or value.get("values") or []
    if not isinstance(value, list):
        value = [value]
    return [str(item).replace("_", " ").title() for item in value if item is not None]


def _policy_scanner_severities(value):
    if not value:
        return []
    entries = value.items() if isinstance(value, dict) else []
    if isinstance(value, list):
        entries = (
            (
                item.get("scanner") or item.get("scannerType") or item.get("engine") or item.get("type") or "Scanner",
                item.get("severities") or item.get("severity") or item.get("values") or [],
            )
            for item in value if isinstance(item, dict)
        )

    normalized = []
    for scanner, severities in entries:
        scanner_name = str(scanner).replace("_", " ").upper()
        for severity in _policy_severity_values(severities):
            normalized.append((scanner_name, severity))
    return normalized


def _policy_values(value):
    if value is None or value == "":
        return []
    values = value if isinstance(value, list) else [value]
    display = []
    for item in values:
        if isinstance(item, dict):
            label = item.get("name") or item.get("displayName") or item.get("ruleName") or item.get("projectName")
            display.append(str(label) if label else json.dumps(item, sort_keys=True))
        else:
            display.append(str(item))
    return display


def _policy_break_build(raw):
    for key in ("breakBuild", "breakBuildEnabled", "isBreakBuildEnabled", "break_build"):
        if key in raw:
            return _policy_bool(raw[key])
    return None


def _policy_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "enabled", "1"}:
            return True
        if normalized in {"false", "no", "disabled", "0"}:
            return False
    if isinstance(value, (int, float)):
        return value != 0
    return None


def _project_management_context():
    cached_applications = db.list_applications()
    projects = db.list_projects()
    applications_by_project = {}
    for application in cached_applications:
        project_ids = json.loads(application["project_ids"] or "[]")
        for project_id in project_ids:
            applications_by_project.setdefault(str(project_id), []).append(application["name"])

    latest_scan_by_project = {
        str(scan["project_id"]): str(scan["id"])
        for scan in db.latest_completed_project_scans()
    }
    scan_summary_by_id = {
        str(summary["scan_id"]): json.loads(summary["raw_json"])
        for summary in db.list_scan_summaries()
    }
    findings_by_project = {}
    finding_ids_by_project = {}
    for violation in db.list_policy_violations():
        project_id = str(violation["project_id"] or "")
        if not project_id or str(violation["scan_id"]) != latest_scan_by_project.get(project_id):
            continue
        raw = json.loads(violation["raw_json"])
        for finding in _nested_policy_findings(raw):
            identity = str(
                finding.get("resultId")
                or "|".join(str(finding.get(key) or "") for key in (
                    "similarityId", "queryId", "queryName", "fileName", "line", "description"
                ))
            )
            if identity.strip("|") and identity not in finding_ids_by_project.setdefault(project_id, set()):
                finding_ids_by_project[project_id].add(identity)
                severity = str(finding.get("severity") or "Unknown").strip().title()
                project_findings = findings_by_project.setdefault(project_id, {})
                project_findings[severity] = project_findings.get(severity, 0) + 1

    project_rows = []
    for project in projects:
        project_id = str(project["id"])
        project_raw = json.loads(project["raw_json"])
        latest_scan_id = latest_scan_by_project.get(project_id)
        scan_summary = scan_summary_by_id.get(latest_scan_id)
        severity_counts = _scan_summary_severity_counts(scan_summary)
        if not severity_counts and _scan_summary_confirms_zero_vulnerabilities(scan_summary):
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        if not severity_counts:
            severity_counts = findings_by_project.get(project_id, {})
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5}
        project_rows.append({
            **dict(project),
            "primary_branch": project_raw.get("mainBranch") or "—",
            "tag_values": json.loads(project["tags"] or "{}"),
            "application_names": sorted(set(applications_by_project.get(project_id, []))),
            "vulnerability_severity_counts": [
                {"severity": severity, "count": count}
                for severity, count in sorted(
                    severity_counts.items(),
                    key=lambda item: (severity_order.get(item[0], 6), item[0].casefold()),
                )
            ],
        })
    project_rows_by_id = {str(project["id"]): project for project in project_rows}
    application_authorizations = db.list_application_authorizations()
    applications = []
    for application in cached_applications:
        project_ids = [str(project_id) for project_id in json.loads(application["project_ids"] or "[]")]
        # Sum the projects that have scan results; projects without any are
        # left out and reported as coverage ("2 of 5 projects") rather than
        # blanking the whole application.
        application_severity_counts = {}
        projects_counted = 0
        for project_id in project_ids:
            project = project_rows_by_id.get(project_id)
            if project is None or not project["vulnerability_severity_counts"]:
                continue
            projects_counted += 1
            for item in project["vulnerability_severity_counts"]:
                severity = item["severity"]
                application_severity_counts[severity] = application_severity_counts.get(severity, 0) + item["count"]
        raw_application = json.loads(application["raw_json"])
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5}
        applications.append({
            **dict(application),
            "authorization_values": _application_authorization_values(
                raw_application, application_authorizations.get(str(application["id"]), [])
            ),
            "vulnerability_severity_counts": [
                {"severity": severity, "count": count}
                for severity, count in sorted(
                    application_severity_counts.items(),
                    key=lambda item: (severity_order.get(item[0], 6), item[0].casefold()),
                )
            ] if projects_counted else None,
            "vulnerability_projects_counted": projects_counted,
            "vulnerability_projects_total": len(project_ids),
        })
    # Summaries are fetched by this section's sync for the latest completed
    # scans cached at that moment, so a later Scan Health sync can add latest
    # scans that have no summary until this section is synced again.
    missing_summary_count = sum(1 for scan_id in latest_scan_by_project.values() if scan_id not in scan_summary_by_id)
    return "project_management.html", {
        "projects": project_rows,
        "applications": applications,
        "missing_summary_count": missing_summary_count,
        "orphaned_count": db.orphaned_projects_count(),
        "active_tab": request.args.get("tab", "projects"),
    }


def _application_authorization_values(raw, assigned_entities=None):
    values = []
    for entity in assigned_entities or []:
        if not isinstance(entity, dict):
            continue
        entity_type = str(entity.get("entityType") or "Entity").title()
        entity_name = entity.get("entityName") or entity.get("origin_entityID") or entity.get("entityID")
        roles = entity.get("entityRoles") or []
        if not isinstance(roles, list):
            roles = [roles]
        role_text = ", ".join(str(role) for role in roles if role is not None)
        label = f"{entity_type}: {entity_name}" if entity_name else entity_type
        if role_text:
            label += f" ({role_text})"
        values.append(label)

    for key in ("authorizations", "authorization", "permissions", "roles"):
        value = raw.get(key)
        if value is None or value == "":
            continue
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            if isinstance(entry, dict):
                label = (
                    entry.get("name") or entry.get("displayName") or entry.get("roleName")
                    or entry.get("permissionName") or entry.get("authorizationName")
                    or entry.get("id")
                )
                if label is None:
                    label = json.dumps(entry, sort_keys=True)
                values.append(str(label))
            else:
                values.append(str(entry))
    return list(dict.fromkeys(values))


def _nested_policy_findings(value):
    findings = []

    def visit(item):
        if isinstance(item, dict):
            if item.get("resultId") or (
                item.get("queryName") and (item.get("fileName") or item.get("similarityId"))
            ):
                findings.append(item)
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)

    visit(value)
    return findings


def _scan_summary_severity_counts(payload):
    severity_names = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info", "informational": "Info"}
    count_suffixes = (
        "count", "counts", "vulnerabilities", "vulnerabilitycount", "vulnerabilitiescount",
        "findings", "findingcount", "findingscount", "severitycount", "total",
    )

    def numeric_count(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return None

    def parse(value):
        if isinstance(value, list):
            combined = {}
            for child in value:
                for severity, count in parse(child).items():
                    combined[severity] = combined.get(severity, 0) + count
            return combined
        if not isinstance(value, dict):
            return {}

        direct_counts = {}
        for key, item in value.items():
            normalized = "".join(char for char in str(key).lower() if char.isalnum())
            for source_name, display_name in severity_names.items():
                if normalized == source_name or (
                    normalized.startswith(source_name)
                    and normalized[len(source_name):] in count_suffixes
                ):
                    count = numeric_count(item)
                    if count is None and isinstance(item, dict):
                        count = next((numeric_count(item[count_key]) for count_key in (
                            "count", "total", "totalCount", "findingCount", "vulnerabilityCount"
                        ) if count_key in item), None)
                    if count is not None:
                        direct_counts[display_name] = direct_counts.get(display_name, 0) + count
                elif normalized.endswith(source_name) and normalized.startswith(("total", "numberof")):
                    count = numeric_count(item)
                    if count is not None:
                        direct_counts[display_name] = direct_counts.get(display_name, 0) + count
        if direct_counts:
            return direct_counts

        severity_value = value.get("severity") or value.get("severityName")
        count_value = next((value[key] for key in (
            "counter", "count", "total", "totalCount", "findingCount", "vulnerabilityCount"
        ) if key in value), None)
        count = numeric_count(count_value)
        severity = severity_names.get(str(severity_value).strip().lower()) if severity_value is not None else None
        if severity and count is not None:
            return {severity: count}

        combined = {}
        for key, child in value.items():
            normalized_key = "".join(char for char in str(key).lower() if char.isalnum())
            if normalized_key in {"severitystatuscounters", "severitystatusvulnerabilitiescounters"}:
                continue
            if isinstance(child, (dict, list)):
                for child_severity, child_count in parse(child).items():
                    combined[child_severity] = combined.get(child_severity, 0) + child_count
        return combined

    return parse(payload)


def _scan_summary_confirms_zero_vulnerabilities(payload):
    if not isinstance(payload, (dict, list)):
        return False
    severity_arrays = []
    total_counters = []

    def visit(value, parent_key=""):
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = "".join(char for char in str(key).lower() if char.isalnum())
                if normalized in {"severitycounters", "severityvulnerabilitiescounters"} and isinstance(item, list):
                    severity_arrays.append(item)
                is_package_inventory = parent_key == "scapackagescounters" and normalized == "totalcounter"
                if (
                    normalized in {"totalcounter", "totalvulnerabilitiescounter"}
                    and not is_package_inventory
                    and isinstance(item, (int, float))
                    and not isinstance(item, bool)
                ):
                    total_counters.append(item)
                visit(item, normalized)
        elif isinstance(value, list):
            for item in value:
                visit(item, parent_key)

    visit(payload)
    return bool(severity_arrays) and all(not entries for entries in severity_arrays) and bool(total_counters) and all(count == 0 for count in total_counters)


def _stale_projects_context():
    look_back = health.look_back_days()
    return "stale_projects.html", {
        "stale": db.stale_projects(look_back),
        "look_back_label": health.look_back_label(look_back),
        "look_back_phrase": health.look_back_phrase(look_back),
        "project_meta": db.get_sync_meta("project_management"),
        "scan_meta": db.get_sync_meta("scan_health"),
    }


def _analyzer_config_context() -> list[dict]:
    look_back = health.look_back_days()
    return [
        {
            "name": section_name,
            "label": rule_catalog.SECTION_LABELS.get(section_name, section_name),
            "slug": rule_catalog.SECTION_SLUGS.get(section_name, section_name),
            "rules": [
                {
                    **rule,
                    "rule_check": rule_catalog.display_text(rule["rule_check"], look_back),
                    "reasoning": rule_catalog.display_text(rule["reasoning"], look_back),
                }
                for rule in rules
            ],
        }
        for section_name, rules in rule_catalog.effective_rules().items()
    ]


@app.route("/analyzer-config")
def analyzer_config():
    rule_sections = _analyzer_config_context()
    default_tab = rule_sections[0]["slug"] if rule_sections else None
    active_tab = request.args.get("tab") or default_tab
    if active_tab not in {s["slug"] for s in rule_sections}:
        active_tab = default_tab
    return render_template("analyzer_config.html", rule_sections=rule_sections, active_tab=active_tab)


@app.route("/analyzer-config/save", methods=["POST"])
def analyzer_config_save():
    overrides = []
    for rule_key in rule_catalog.all_rule_keys():
        warning_level_field = f"warning_level__{rule_key}"
        if warning_level_field not in request.form:
            # Not part of the tab that was actually submitted -- leave its
            # stored override untouched rather than defaulting it to disabled.
            continue
        enabled = request.form.get(f"enabled__{rule_key}") == "on"
        warning_level = request.form.get(warning_level_field, "").strip() or None
        overrides.append({"rule_key": rule_key, "enabled": enabled, "warning_level": warning_level})
    db.save_rule_overrides(overrides)
    flash("Analyzer configuration saved.", "success")
    return redirect(url_for("analyzer_config", tab=request.form.get("active_tab")))


_SECTION_CONTEXT_BUILDERS = {
    "global_configurations": _global_configurations_context,
    "preset_management": _preset_management_context,
    "scan_health": _scan_health_context,
    "integrations": _integrations_context,
    "feedback_profiles": _feedback_profiles_context,
    "policies": _policies_context,
    "project_management": _project_management_context,
    "stale_projects": _stale_projects_context,
}


@app.route("/section/<key>")
def section(key):
    if key not in SECTIONS_BY_KEY:
        flash("Unknown section.", "error")
        return redirect(url_for("dashboard"))

    template, context = _SECTION_CONTEXT_BUILDERS[key]()
    return render_template(
        template,
        section_key=key,
        section=SECTIONS_BY_KEY[key],
        sync_meta=db.get_sync_meta(key),
        findings=health.section_findings(key),
        analyzer_highlights=analyzer.page_highlights(key),
        analyzable=key in analyzer.PAGE_RULE_SECTION,
        **context,
    )


@app.route("/section/<key>/analyze", methods=["POST"])
def analyze_section(key):
    rule_section = analyzer.PAGE_RULE_SECTION.get(key)
    if rule_section is None:
        flash("This section has no analyzer rules.", "error")
        return redirect(url_for("section", key=key) if key in SECTIONS_BY_KEY else url_for("dashboard"))

    report = analyzer.run_analysis(_policy_rule_summary, rule_section=rule_section)
    result = next(s for s in report["sections"] if s["name"] == rule_section)
    if result["unsynced"]:
        flash(f"Not analyzed -- sync {' and '.join(result['unsynced'])} first.", "error")
    elif result["violations"]:
        instances = sum(len(v["instances"]) for v in result["violations"])
        flash(f"Analysis complete: {len(result['violations'])} rule violation(s) across {instances} instance(s).", "success")
    else:
        flash("Analysis complete: No Configuration Warnings Detected.", "success")

    # Rebuilt from a known parameter (never a client-supplied URL) so the
    # user lands back on the same tab.
    params = {"tab": request.form["tab"]} if request.form.get("tab") else {}
    return redirect(url_for("section", key=key, **params))


# ---------------------------------------------------------------------------
# Scan Health -- live scan workflow detail panel. Fetched on demand per scan
# rather than synced/cached: it's scan-specific debug history, not tenant
# health data, and would be a lot of extra API calls to pull for every scan
# up front when only a handful ever get inspected.
# ---------------------------------------------------------------------------
@app.route("/scans/<scan_id>/workflow")
def scan_workflow(scan_id):
    sess = _current_session()
    try:
        _ensure_token(sess)
        steps = cx_client.get_scan_workflow(sess["base_url"], sess["token"], scan_id)
    except cx_client.CxApiError as exc:
        return {"error": str(exc)}, exc.status_code or 502
    return {"scan_id": scan_id, "steps": steps}


# ---------------------------------------------------------------------------
# Integrations -- SCM org detail panel. Reads the local cache (unlike Scan
# Workflow's live fetch): org/repo settings are already pulled tenant-wide
# by the Integrations sync, so there's no need for a per-click API call.
# ---------------------------------------------------------------------------
@app.route("/scm-orgs/<org_id>/detail")
def scm_org_detail(org_id):
    org = db.get_scm_org(org_id)
    if org is None:
        return {"error": "Org not found in the local cache. Try syncing Integrations first."}, 404

    raw = json.loads(org["raw_json"])
    return {
        "org_id": org["org_id"],
        "org_identity": org["org_identity"],
        "scm_id": org["scm_id"],
        "is_user_org": bool(org["is_user_org"]),
        "webhook_enabled": bool(org["webhook_enabled"]),
        "webhook_editable": bool(raw.get("webhookEditable")),
        "settings": raw.get("defaultRepositorySettings") or {},
    }


def _render_preset_page(template, **context):
    """Every Preset Management sub-page (compare/combine/update/delete)
    still lives under the Preset Management sidebar entry, so it always
    passes the same section_key/section pair the sidebar highlight needs."""
    return render_template(
        template,
        section_key="preset_management",
        section=SECTIONS_BY_KEY["preset_management"],
        **context,
    )


# ---------------------------------------------------------------------------
# Preset Management -- delete
# ---------------------------------------------------------------------------
@app.route("/presets/delete")
def presets_delete():
    # Built-in presets can't be deleted, so they aren't worth showing here.
    rows = [p for p in db.list_presets() if p["is_custom"]]
    return _render_preset_page("presets_delete.html", presets=rows)


@app.route("/presets/delete/confirm", methods=["POST"])
def presets_delete_confirm():
    ids = request.form.getlist("selected_preset_ids")
    if not ids:
        flash("Select at least one preset to delete.", "error")
        return redirect(url_for("presets_delete"))

    to_delete = [
        meta for meta in (db.get_cached_preset_meta(pid) for pid in ids)
        if meta is not None and meta["is_custom"]
    ]
    if not to_delete:
        flash("No deletable presets were selected (Built-in presets cannot be deleted).", "error")
        return redirect(url_for("presets_delete"))

    return _render_preset_page("presets_delete_confirm.html", presets=to_delete)


@app.route("/presets/delete/apply", methods=["POST"])
def presets_delete_apply():
    sess = _current_session()
    ids = request.form.getlist("preset_ids")
    if not ids:
        flash("No presets selected to delete.", "error")
        return redirect(url_for("presets_delete"))

    try:
        _ensure_token(sess)
    except cx_client.CxApiError as exc:
        flash(f"Could not refresh authentication: {exc}", "error")
        return redirect(url_for("presets_delete"))

    deleted, failed = [], []
    for preset_id in ids:
        try:
            cx_client.delete_preset(sess["base_url"], sess["token"], preset_id)
            db.delete_cached_preset(preset_id)
            deleted.append(preset_id)
        except cx_client.CxApiError as exc:
            failed.append((preset_id, str(exc)))

    if deleted:
        flash(f"Deleted {len(deleted)} preset(s).", "success")
    if failed:
        detail = "; ".join(f"id {pid}: {err}" for pid, err in failed)
        flash(f"Failed to delete {len(failed)} preset(s): {detail}", "error")

    return redirect(url_for("section", key="preset_management"))


# ---------------------------------------------------------------------------
# Preset Management -- compare + combine
# ---------------------------------------------------------------------------
@app.route("/presets/compare")
def presets_compare():
    rows = db.list_presets()
    a_id = request.args.get("a")
    b_id = request.args.get("b")

    if not a_id or not b_id:
        return _render_preset_page("presets_compare.html", presets=rows, groups=None, a_id=a_id, b_id=b_id)

    preset_a = db.get_cached_preset(a_id)
    preset_b = db.get_cached_preset(b_id)
    if preset_a is None or preset_b is None:
        flash("Selected preset(s) not found in the local cache. Try syncing again.", "error")
        return redirect(url_for("section", key="preset_management"))

    groups = diff.compare_presets(db.normalize_preset_queries(preset_a), db.normalize_preset_queries(preset_b))
    return _render_preset_page(
        "presets_compare.html",
        presets=rows, groups=groups, preset_a=preset_a, preset_b=preset_b,
        a_id=a_id, b_id=b_id, any_differences=diff.has_differences(groups),
    )


@app.route("/presets/compare/export.csv")
def presets_compare_export_csv():
    a_id = request.args.get("a")
    b_id = request.args.get("b")
    preset_a = db.get_cached_preset(a_id)
    preset_b = db.get_cached_preset(b_id)
    if preset_a is None or preset_b is None:
        flash("Selected preset(s) not found in the local cache.", "error")
        return redirect(url_for("section", key="preset_management"))

    groups = diff.compare_presets(db.normalize_preset_queries(preset_a), db.normalize_preset_queries(preset_b))
    csv_text = export.diff_to_csv(groups, preset_a.get("name", str(a_id)), preset_b.get("name", str(b_id)))
    filename = f"preset_diff_{a_id}_vs_{b_id}.csv"
    return Response(
        csv_text, mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# The combine/update flows carry the chosen queries between steps in hidden
# form fields, so what comes back is only a request: every id is resolved
# against what the tenant actually has (the synced catalog plus the presets
# involved), unknown ids are dropped, and the names/families shown or sent to
# Checkmarx come from that lookup, never from the form. A submission naming
# more ids than exist isn't a real form and is rejected outright.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # well above any real preset form


def _query_lookup(*presets) -> dict[str, dict]:
    lookup = db.query_catalog_by_id()
    for preset in presets:
        for query in db.normalize_preset_queries(preset) if preset else []:
            if query.get("queryId") is not None:
                lookup.setdefault(str(query["queryId"]), {**query, "queryId": str(query["queryId"])})
    return lookup


def _known_queries(query_ids, lookup: dict[str, dict]) -> list[dict]:
    query_ids = [str(query_id) for query_id in query_ids]
    if len(query_ids) > len(lookup):
        raise ValueError("more queries submitted than the tenant has")
    return [lookup[query_id] for query_id in dict.fromkeys(query_ids) if query_id in lookup]


def _submitted_query_list(queries_json: str, *presets) -> list[dict]:
    """A combine flow's hidden queries_json, reduced to the tenant's real queries."""
    entries = json.loads(queries_json)
    if not isinstance(entries, list):
        raise ValueError("expected a list of queries")
    ids = [entry.get("queryId") for entry in entries if isinstance(entry, dict) and entry.get("queryId") is not None]
    return _known_queries(ids, _query_lookup(*presets))


def _combine_presets_from_form():
    return db.get_cached_preset(request.form.get("a_id")), db.get_cached_preset(request.form.get("b_id"))


@app.route("/presets/compare/combine", methods=["POST"])
def presets_compare_combine():
    a_id = request.form.get("a_id")
    b_id = request.form.get("b_id")
    selected_ids = set(request.form.getlist("selected_query_ids"))

    preset_a = db.get_cached_preset(a_id)
    preset_b = db.get_cached_preset(b_id)
    if preset_a is None or preset_b is None:
        flash("Selected preset(s) not found in the local cache.", "error")
        return redirect(url_for("section", key="preset_management"))

    groups = diff.compare_presets(db.normalize_preset_queries(preset_a), db.normalize_preset_queries(preset_b))

    # Queries common to both presets are always carried over unconditionally;
    # only-in-Base/only-in-Target queries are included only if checked.
    final_queries: dict[str, dict] = {}
    for bucket in groups.values():
        for q in bucket["common"]:
            final_queries[q["queryId"]] = q
        for q in bucket["only_a"] + bucket["only_b"]:
            if q["queryId"] in selected_ids:
                final_queries[q["queryId"]] = q

    final_list = sorted(final_queries.values(), key=lambda q: (q["language"], q["group"], q["name"]))

    return _render_preset_page(
        "presets_combine_preview.html",
        preset_a=preset_a, preset_b=preset_b, a_id=a_id, b_id=b_id,
        suggested_name=preset_a.get("name", ""),
        suggested_description=preset_a.get("description") or "",
        groups=diff.group_single_preset(final_list),
        total_queries=len(final_list),
        queries_json=json.dumps(final_list),
    )


@app.route("/presets/compare/combine/export.csv", methods=["POST"])
def presets_compare_combine_export_csv():
    preset_name = request.form.get("preset_name", "").strip() or "Combined Preset"
    queries_json = request.form.get("queries_json", "[]")
    try:
        final_list = _submitted_query_list(queries_json, *_combine_presets_from_form())
    except ValueError:
        flash("Could not read the combined query list; please try again.", "error")
        return redirect(url_for("section", key="preset_management"))

    csv_text = export.queries_to_csv(final_list)
    filename = export.combined_export_filename(preset_name)
    return Response(
        csv_text, mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/presets/compare/combine/confirm", methods=["POST"])
def presets_compare_combine_confirm():
    preset_name = request.form.get("preset_name", "").strip() or "Combined Preset"
    description = request.form.get("description", "").strip()
    queries_json = request.form.get("queries_json", "[]")
    a_id = request.form.get("a_id")
    b_id = request.form.get("b_id")
    try:
        final_list = _submitted_query_list(queries_json, *_combine_presets_from_form())
    except ValueError:
        flash("Could not read the combined query list; please try again.", "error")
        return redirect(url_for("section", key="preset_management"))

    existing = next(
        (p for p in db.list_presets() if p["name"].lower() == preset_name.lower()), None
    )
    # A name that collides with a Built-in preset can never be an "update"
    # target -- Built-ins can't be modified, so this blocks proceeding and
    # requires a different name instead of silently attempting a PATCH the
    # live API would reject anyway.
    existing_is_builtin = existing is not None and not existing["is_custom"]
    final_by_family = db.group_queries_by_family(final_list)

    payload = {
        "name": preset_name,
        "description": description,
        "queries": [{"familyName": family, "queryIds": ids} for family, ids in final_by_family.items()],
    }

    return _render_preset_page(
        "presets_combine_confirm.html",
        preset_name=preset_name, description=description,
        existing=None if existing_is_builtin else existing,
        existing_is_builtin=existing_is_builtin,
        a_id=a_id, b_id=b_id,
        total_queries=len(final_list), payload_json=json.dumps(payload, indent=2),
        queries_json=json.dumps(final_list),
    )


@app.route("/presets/compare/combine/apply", methods=["POST"])
def presets_compare_combine_apply():
    sess = _current_session()
    preset_name = request.form.get("preset_name", "").strip() or "Combined Preset"
    description = request.form.get("description", "").strip()
    queries_json = request.form.get("queries_json", "[]")
    target_preset_id = request.form.get("target_preset_id") or None

    try:
        final_list = _submitted_query_list(queries_json, *_combine_presets_from_form())
    except ValueError:
        flash("Could not read the combined query list; please try again.", "error")
        return redirect(url_for("section", key="preset_management"))

    final_by_family = db.group_queries_by_family(final_list)

    # Re-check server-side (not just in the confirm page's UI) that the
    # target isn't a Built-in preset -- Built-ins can't be modified, and a
    # form field is not something to trust blindly.
    if target_preset_id is not None:
        target_meta = db.get_cached_preset_meta(target_preset_id)
        if target_meta is not None and not target_meta["is_custom"]:
            flash(
                f"'{target_meta['name']}' is a Built-in preset and cannot be updated. "
                "Choose a different name to create a new preset instead.",
                "error",
            )
            return redirect(url_for("section", key="preset_management"))

    try:
        _ensure_token(sess)
        if target_preset_id is not None:
            cx_client.update_preset(
                sess["base_url"], sess["token"], target_preset_id, preset_name, description, final_by_family
            )
            saved_id = target_preset_id
            verb = "updated"
        else:
            created = cx_client.create_preset(
                sess["base_url"], sess["token"], preset_name, description, final_by_family
            )
            saved_id = created.get("id")
            verb = "created"

        if saved_id is not None:
            refreshed = cx_client.get_preset(sess["base_url"], sess["token"], saved_id)
            db.upsert_preset(refreshed)
        flash(f"Preset '{preset_name}' {verb} with {len(final_list)} queries.", "success")
    except cx_client.CxApiError as exc:
        error_message = f"Could not save the combined preset: {exc}"
        if exc.body:
            error_message += " Response body: " + exc.body
        flash(error_message, "error")
        return redirect(url_for("section", key="preset_management"))

    return redirect(url_for("section", key="preset_management"))


# ---------------------------------------------------------------------------
# Preset Management -- detail panel, export, update
# ---------------------------------------------------------------------------
@app.route("/presets/<preset_id>/detail")
def preset_detail(preset_id):
    preset = db.get_cached_preset(preset_id)
    meta = db.get_cached_preset_meta(preset_id)
    if preset is None or meta is None:
        return {"error": "Preset not found in the local cache. Try syncing first."}, 404

    queries = db.normalize_preset_queries(preset)
    return {
        "id": meta["id"], "name": meta["name"], "is_custom": bool(meta["is_custom"]),
        "description": meta["description"], "total_queries": len(queries),
        "groups": diff.group_single_preset(queries),
    }


@app.route("/presets/<preset_id>/export.json")
def preset_export_json(preset_id):
    preset = db.get_cached_preset(preset_id)
    if preset is None:
        flash("Preset not found in the local cache. Try syncing first.", "error")
        return redirect(url_for("section", key="preset_management"))
    filename = f"preset_{preset_id}.json"
    return Response(
        json.dumps(preset, indent=2), mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/presets/<preset_id>/update", methods=["GET", "POST"])
def preset_update(preset_id):
    preset = db.get_cached_preset(preset_id)
    meta = db.get_cached_preset_meta(preset_id)
    if preset is None or meta is None:
        flash("Preset not found in the local cache. Try syncing first.", "error")
        return redirect(url_for("section", key="preset_management"))

    current_queries = db.normalize_preset_queries(preset)
    current_ids = {q["queryId"] for q in current_queries if q.get("queryId") is not None}

    if request.method == "GET":
        return _render_preset_page(
            "presets_update.html", meta=meta, catalog=db.full_query_catalog(),
            current_ids=current_ids, total_queries=len(current_ids),
        )

    is_builtin = not meta["is_custom"]
    new_preset_name = request.form.get("new_preset_name", "").strip()

    if is_builtin and not new_preset_name:
        flash("Built-in presets cannot be modified directly -- enter a New Preset Name.", "error")
        return redirect(url_for("preset_update", preset_id=preset_id))

    lookup = _query_lookup(preset)
    try:
        selected = _known_queries(request.form.getlist("selected_query_ids"), lookup)
    except ValueError:
        flash("Could not read the selected queries; please try again.", "error")
        return redirect(url_for("preset_update", preset_id=preset_id))
    current_ids = {str(query_id) for query_id in current_ids}
    selected_ids = {query["queryId"] for query in selected}
    added_ids = selected_ids - current_ids
    removed_ids = current_ids - selected_ids

    def _sorted_resolved(ids):
        return sorted((lookup[q] for q in ids), key=lambda q: (q["language"], q["group"], q["name"]))

    final_by_family = db.group_queries_by_family(selected)
    target_name = new_preset_name if is_builtin else meta["name"]
    target_description = request.form.get("description", "").strip()

    payload = {
        "name": target_name,
        "description": target_description,
        "queries": [{"familyName": family, "queryIds": ids} for family, ids in final_by_family.items()],
    }

    return _render_preset_page(
        "presets_update_confirm.html",
        preset=preset, meta=meta, is_builtin=is_builtin, target_name=target_name,
        target_description=target_description, new_preset_name=new_preset_name,
        added=_sorted_resolved(added_ids), removed=_sorted_resolved(removed_ids),
        current_count=len(current_ids), final_count=len(selected_ids),
        payload_json=json.dumps(payload, indent=2), final_by_family_json=json.dumps(final_by_family),
    )


@app.route("/presets/<preset_id>/update/confirm", methods=["POST"])
def preset_update_confirm(preset_id):
    sess = _current_session()
    meta = db.get_cached_preset_meta(preset_id)
    if meta is None:
        flash("Preset not found in the local cache. Try syncing first.", "error")
        return redirect(url_for("section", key="preset_management"))

    final_by_family_json = request.form.get("final_by_family_json", "{}")
    try:
        submitted = json.loads(final_by_family_json)
        if not isinstance(submitted, dict) or not all(isinstance(ids, list) for ids in submitted.values()):
            raise ValueError("expected {family: [queryId, ...]}")
        # Families are re-derived from the lookup, not taken from the form.
        selected = _known_queries([qid for ids in submitted.values() for qid in ids], _query_lookup(db.get_cached_preset(preset_id)))
        final_by_family = db.group_queries_by_family(selected)
    except ValueError:
        flash("Could not read the confirmed query list; please try again.", "error")
        return redirect(url_for("preset_update", preset_id=preset_id))

    new_preset_name = request.form.get("new_preset_name", "").strip()
    description = request.form.get("description", "").strip()
    total_queries = sum(len(ids) for ids in final_by_family.values())

    try:
        _ensure_token(sess)
        if new_preset_name:
            created = cx_client.create_preset(
                sess["base_url"], sess["token"], new_preset_name, description, final_by_family
            )
            new_id = created.get("id")
            if new_id is not None:
                refreshed = cx_client.get_preset(sess["base_url"], sess["token"], new_id)
                db.upsert_preset(refreshed)
            flash(f"Created new preset '{new_preset_name}' with {total_queries} queries.", "success")
        else:
            cx_client.update_preset(
                sess["base_url"], sess["token"], preset_id, meta["name"], description, final_by_family
            )
            refreshed = cx_client.get_preset(sess["base_url"], sess["token"], preset_id)
            db.upsert_preset(refreshed)
            flash(f"Preset {preset_id} updated with {total_queries} queries.", "success")
    except cx_client.CxApiError as exc:
        error_message = f"Could not apply preset changes: {exc}"
        if exc.body:
            error_message += " Response body: " + exc.body
        flash(error_message, "error")
        return redirect(url_for("preset_update", preset_id=preset_id))

    return redirect(url_for("section", key="preset_management"))


# ---------------------------------------------------------------------------
# Sync (per-section + all)
# ---------------------------------------------------------------------------
def _run_section_sync(sid: str, section_key: str, **extra_kwargs) -> None:
    status_key = (sid, section_key)
    status = _SYNC_STATUS[status_key]
    sess = _SESSIONS.get(sid)
    if sess is None:
        # No session means no known tenant, so there's no database to record this in.
        status.update(state="error", message="Session expired. Please sign in again.")
        return
    db.use_tenant_db(sess["db_path"])  # sync threads start with no tenant selected

    section_cfg = SECTIONS_BY_KEY[section_key]
    sync_fn = section_cfg["sync_fn"]
    if sync_fn is None:
        status.update(state="done", message="This section has no sync of its own.")
        return

    # Long-running syncs publish phase messages and, when possible, numeric progress.
    if section_key in {"preset_management", "scan_health", "policies", "project_management"}:
        def _progress(current, total, message):
            status.update(current=current, total=total, message=message)
        extra_kwargs = {**extra_kwargs, "progress": _progress}

    try:
        db.set_sync_status(section_key, "running", "Syncing...")
        _ensure_token(sess)
        count, message = sync_fn(sess, **extra_kwargs)
        db.set_sync_done(section_key, count, message)
        status.update(state="done", message=message)
    except cx_client.CxApiError as exc:
        message = f"Sync failed: {exc}"
        db.set_sync_status(section_key, "error", message)
        status.update(state="error", message=message)
    except Exception as exc:  # safety net so the UI never polls forever
        message = f"Sync failed: {exc}"
        db.set_sync_status(section_key, "error", message)
        status.update(state="error", message=message)


@app.route("/sync/<key>/start", methods=["POST"])
def sync_start(key):
    if key not in SECTIONS_BY_KEY:
        return {"error": "unknown section"}, 404
    sid = session["sid"]
    status_key = (sid, key)
    extra_kwargs = {}
    if key == "preset_management" and request.args.get("refresh_catalog") == "1":
        extra_kwargs["refresh_catalog"] = True
    with _sync_lock:
        existing = _SYNC_STATUS.get(status_key)
        if existing and existing.get("state") == "running":
            return existing
        _SYNC_STATUS[status_key] = {"state": "running", "message": "Starting..."}
        threading.Thread(target=_run_section_sync, args=(sid, key), kwargs=extra_kwargs, daemon=True).start()
    return _SYNC_STATUS[status_key]


@app.route("/sync/<key>/status")
def sync_status(key):
    sid = session["sid"]
    return _SYNC_STATUS.get((sid, key), {"state": "idle", "message": ""})


def _run_all_sync(sid: str) -> None:
    status_key = (sid, "all")
    status = _SYNC_STATUS[status_key]
    sess = _SESSIONS.get(sid)
    if sess is None:
        status.update(state="error", message="Session expired. Please sign in again.")
        return
    db.use_tenant_db(sess["db_path"])  # sync threads start with no tenant selected

    syncable = [s for s in SECTIONS if s["sync_fn"] is not None]
    status.update(state="running", current=0, total=len(syncable), message="Starting...")

    try:
        _ensure_token(sess)
    except cx_client.CxApiError as exc:
        status.update(state="error", message=f"Could not refresh authentication: {exc}")
        return

    for i, section_cfg in enumerate(syncable, start=1):
        key = section_cfg["key"]
        status.update(message=f"Syncing {section_cfg['label']}... ({i} of {len(syncable)})")
        try:
            db.set_sync_status(key, "running", "Syncing...")
            count, message = section_cfg["sync_fn"](sess)
            db.set_sync_done(key, count, message)
        except cx_client.CxApiError as exc:
            db.set_sync_status(key, "error", f"Sync failed: {exc}")
        except Exception as exc:
            db.set_sync_status(key, "error", f"Sync failed: {exc}")
        status.update(current=i)

    status.update(state="done", message=f"Synced {len(syncable)} section(s).")


@app.route("/sync/all/start", methods=["POST"])
def sync_all_start():
    sid = session["sid"]
    status_key = (sid, "all")
    with _sync_lock:
        existing = _SYNC_STATUS.get(status_key)
        if existing and existing.get("state") == "running":
            return existing
        _SYNC_STATUS[status_key] = {"state": "running", "current": 0, "total": 0, "message": "Starting..."}
        threading.Thread(target=_run_all_sync, args=(sid,), daemon=True).start()
    return _SYNC_STATUS[status_key]


@app.route("/sync/all/status")
def sync_all_status():
    sid = session["sid"]
    return _SYNC_STATUS.get((sid, "all"), {"state": "idle", "current": 0, "total": 0, "message": ""})


@app.teardown_request
def _release_tenant_db(exc=None):
    # Request threads are reused, so clear the tenant selection rather than
    # let it carry into the next request.
    token = g.pop("tenant_db_token", None)
    if token is not None:
        db.reset_tenant_db(token)


@app.context_processor
def inject_globals():
    return {
        "now": datetime.utcnow(),
        "logged_in": _current_session() is not None,
        "current_session": _current_session(),
        "sections": SECTIONS,
        "dashboard_icon": DASHBOARD_ICON,
        "analyzer_config_icon": ANALYZER_CONFIG_ICON,
        "recommendations_icon": RECOMMENDATIONS_ICON,
        "request": request,
    }


if __name__ == "__main__":
    # Debug mode (Werkzeug's interactive debugger + reloader) is opt-in via
    # FLASK_DEBUG=1 in .env, which Flask reads on startup; off by default.
    app.run(host="127.0.0.1", port=8888, threaded=True)
