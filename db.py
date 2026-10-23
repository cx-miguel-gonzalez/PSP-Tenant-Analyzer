"""SQLite cache for all 8 review sections. Every section's page renders
from these tables -- never live from the API -- so a sync is a full
replace-all of that section's table(s): defensible because this console
only reads tenant data, it never edits or diffs it locally (unlike the
Preset Manager Console this app borrows its look from).

Each tenant has its own database file (data/tenants/<name>__<uuid>.db), so
no tenant's data is ever stored alongside another's. The active tenant's
file is a per-request / per-sync-thread context variable; using the
database without one selected is an error rather than a silent default.
Reviewer settings that aren't tenant data (Analyzer Config rule overrides,
the Look Back) live in a separate shared data/app_config.db."""
from __future__ import annotations

import contextvars
import json
import os
import re
import sqlite3
import statistics
import threading
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(os.environ.get("TENANT_ANALYZER_DATA_DIR") or (Path(__file__).parent / "data"))
TENANT_DB_DIR = DATA_DIR / "tenants"
CONFIG_DB_PATH = DATA_DIR / "app_config.db"
# Single shared database from before per-tenant files; only ever read
# (copied to its owning tenant's file), never written or deleted.
LEGACY_DB_PATH = DATA_DIR / "tenant_analyzer.db"
# Tests/tooling: one scratch file for everything, bypassing per-tenant files.
SINGLE_DB_OVERRIDE = os.environ.get("TENANT_ANALYZER_DB_PATH")

_active_tenant_db: contextvars.ContextVar[Path | None] = contextvars.ContextVar("active_tenant_db", default=None)
_initialized: set[tuple[str, str]] = set()
_init_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_meta (
    section_key TEXT PRIMARY KEY,
    last_synced_at TEXT,
    record_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'idle',
    message TEXT
);

CREATE TABLE IF NOT EXISTS tenant_config (
    key TEXT PRIMARY KEY,
    category TEXT,
    value TEXT,
    allow_override INTEGER,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS presets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    is_custom INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    raw_json TEXT NOT NULL,
    associated_projects INTEGER,
    is_tenant_default INTEGER
);

CREATE TABLE IF NOT EXISTS query_catalog (
    query_id TEXT PRIMARY KEY,
    family TEXT NOT NULL,
    name TEXT NOT NULL,
    group_name TEXT,
    severity TEXT,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    project_name TEXT,
    status TEXT,
    branch TEXT,
    engines TEXT,
    origin TEXT,
    initiator TEXT,
    created_at TEXT,
    updated_at TEXT,
    raw_json TEXT NOT NULL,
    loc INTEGER
);

CREATE TABLE IF NOT EXISTS scm_connections (
    id TEXT PRIMARY KEY,
    scm_type TEXT,
    display_name TEXT,
    instance_name TEXT,
    on_prem INTEGER,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scm_orgs (
    org_id TEXT PRIMARY KEY,
    scm_id TEXT,
    org_identity TEXT,
    is_user_org INTEGER,
    webhook_enabled INTEGER,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback_profiles (
    id TEXT PRIMARY KEY,
    name TEXT,
    profile_type TEXT,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback_apps (
    id TEXT PRIMARY KEY,
    name TEXT,
    app_type TEXT,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT,
    enabled INTEGER,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_violations (
    id TEXT PRIMARY KEY,
    policy_name TEXT,
    project_id TEXT,
    project_name TEXT,
    scan_id TEXT,
    raw_json TEXT NOT NULL,
    branch TEXT
);

CREATE TABLE IF NOT EXISTS policy_evaluations (
    scan_id TEXT PRIMARY KEY,
    project_id TEXT,
    project_name TEXT,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_summaries (
    scan_id TEXT PRIMARY KEY,
    project_id TEXT,
    project_name TEXT,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    groups TEXT,
    tags TEXT,
    criticality TEXT,
    created_at TEXT,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    project_ids TEXT,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS application_authorizations (
    application_id TEXT PRIMARY KEY,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_workflows (
    scan_id TEXT PRIMARY KEY,
    raw_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyzer_report (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    ran_at TEXT NOT NULL,
    raw_json TEXT NOT NULL
);
"""


CONFIG_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyzer_rule_overrides (
    rule_key TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    warning_level TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def tenant_db_path(tenant_name: str, tenant_uuid: str) -> Path:
    def clean(value):
        return re.sub(r"[^A-Za-z0-9_-]+", "_", str(value or "")).strip("_") or "unknown"
    path = (TENANT_DB_DIR / f"{clean(tenant_name).lower()}__{clean(tenant_uuid).lower()}.db").resolve()
    if path.parent != TENANT_DB_DIR.resolve():
        raise ValueError("Tenant database path escapes the tenants directory.")
    return path


def use_tenant_db(path) -> contextvars.Token:
    """Select the tenant database for the current request or sync thread."""
    return _active_tenant_db.set(Path(path) if path else None)


def reset_tenant_db(token: contextvars.Token) -> None:
    _active_tenant_db.reset(token)


def active_tenant_db() -> Path:
    if SINGLE_DB_OVERRIDE:
        return Path(SINGLE_DB_OVERRIDE)
    path = _active_tenant_db.get()
    if path is None:
        raise RuntimeError("No tenant database selected -- refusing to read or write tenant data.")
    return path


def _connect(path: Path) -> sqlite3.Connection:
    path = Path(os.path.normpath(os.path.abspath(path)))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_initialized(path: Path, initializer) -> None:
    # Keyed per schema too: in single-file mode the tenant and config schemas
    # share one file, and each still has to be applied.
    key = (os.path.normpath(os.path.abspath(path)), initializer.__name__)
    if key in _initialized:
        return
    with _init_lock:
        if key not in _initialized:
            conn = _connect(path)
            try:
                initializer(conn)
            finally:
                conn.close()
            _initialized.add(key)


def get_connection() -> sqlite3.Connection:
    """Connection to the active tenant's database."""
    path = active_tenant_db()
    _ensure_initialized(path, _init_tenant_schema)
    return _connect(path)


def get_config_connection() -> sqlite3.Connection:
    """Connection to the shared reviewer-settings database (not tenant data)."""
    path = Path(SINGLE_DB_OVERRIDE) if SINGLE_DB_OVERRIDE else CONFIG_DB_PATH
    _ensure_initialized(path, _init_config_schema)
    return _connect(path)


def _init_config_schema(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript(CONFIG_SCHEMA)
        # First run after the per-tenant split: carry the settings over from
        # the old shared database. These tables hold reviewer settings only.
        if SINGLE_DB_OVERRIDE or not LEGACY_DB_PATH.exists():
            return
        has_overrides = conn.execute("SELECT 1 FROM analyzer_rule_overrides LIMIT 1").fetchone()
        has_settings = conn.execute("SELECT 1 FROM app_settings LIMIT 1").fetchone()
        if has_overrides or has_settings:
            return
        legacy = sqlite3.connect(f"file:{LEGACY_DB_PATH}?mode=ro", uri=True)
        try:
            legacy_tables = {row[0] for row in legacy.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "analyzer_rule_overrides" in legacy_tables:
                conn.executemany(
                    "INSERT OR IGNORE INTO analyzer_rule_overrides (rule_key, enabled, warning_level, updated_at) VALUES (?, ?, ?, ?)",
                    legacy.execute("SELECT rule_key, enabled, warning_level, updated_at FROM analyzer_rule_overrides").fetchall(),
                )
            if "app_settings" in legacy_tables:
                conn.executemany(
                    "INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)",
                    legacy.execute("SELECT key, value FROM app_settings").fetchall(),
                )
        finally:
            legacy.close()


def claim_legacy_db(tenant_uuid: str, target: Path) -> bool:
    """Copy the old shared database to `target` (a tenant's new file) only
    if every project in it belongs to that tenant. The old file itself is
    never modified or removed."""
    if SINGLE_DB_OVERRIDE or target.exists() or not LEGACY_DB_PATH.exists() or not tenant_uuid:
        return False
    legacy = sqlite3.connect(f"file:{LEGACY_DB_PATH}?mode=ro", uri=True)
    try:
        try:
            owners = {json.loads(row[0]).get("tenantId") for row in legacy.execute("SELECT raw_json FROM projects")}
        except sqlite3.Error:
            return False
        if owners != {tenant_uuid}:
            return False
        copy = _connect(target)
        try:
            legacy.backup(copy)
        finally:
            copy.close()
        return True
    finally:
        legacy.close()


def init_db() -> None:
    """Make sure the active tenant's database has the current schema."""
    get_connection().close()


def _init_tenant_schema(conn: sqlite3.Connection) -> None:
    if SINGLE_DB_OVERRIDE:
        conn.executescript(CONFIG_SCHEMA)
    with conn:
        conn.executescript(SCHEMA)
        # One-off migration for local caches created before allow_override
        # existed -- CREATE TABLE IF NOT EXISTS above won't add it.
        existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(tenant_config)")}
        if "allow_override" not in existing_columns:
            conn.execute("ALTER TABLE tenant_config ADD COLUMN allow_override INTEGER")
        existing_scan_columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
        if "loc" not in existing_scan_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN loc INTEGER")
        existing_violation_columns = {row["name"] for row in conn.execute("PRAGMA table_info(policy_violations)")}
        if "branch" not in existing_violation_columns:
            conn.execute("ALTER TABLE policy_violations ADD COLUMN branch TEXT")
        existing_preset_columns = {row["name"] for row in conn.execute("PRAGMA table_info(presets)")}
        if "associated_projects" not in existing_preset_columns:
            conn.execute("ALTER TABLE presets ADD COLUMN associated_projects INTEGER")
        if "is_tenant_default" not in existing_preset_columns:
            conn.execute("ALTER TABLE presets ADD COLUMN is_tenant_default INTEGER")
        conn.execute(
            """
            UPDATE scans
            SET origin = CASE
                WHEN lower(trim(origin)) LIKE 'grpc-dotnet%' THEN 'Auto-scan'
                WHEN lower(trim(origin)) LIKE '%grpc-java-netty%' THEN 'Project Scan'
                WHEN lower(trim(origin)) = 'na' THEN 'Scheduler'
                ELSE origin
            END
            WHERE lower(trim(origin)) LIKE 'grpc-dotnet%'
               OR lower(trim(origin)) LIKE '%grpc-java-netty%'
               OR lower(trim(origin)) = 'na'
            """
        )
        # scm_connections' columns were replaced outright (name/repo_type ->
        # scm_type/display_name/instance_name/on_prem) rather than extended,
        # so a column-add migration doesn't fit -- drop and let the schema
        # above recreate it. Safe: it's a pure re-sync cache, never
        # independently edited.
        existing_scm_columns = {row["name"] for row in conn.execute("PRAGMA table_info(scm_connections)")}
        if existing_scm_columns and "scm_type" not in existing_scm_columns:
            conn.execute("DROP TABLE scm_connections")
            conn.executescript(SCHEMA)
        for key in SECTION_KEYS:
            conn.execute(
                "INSERT OR IGNORE INTO sync_meta (section_key, status) VALUES (?, 'idle')",
                (key,),
            )


SECTION_KEYS = (
    "global_configurations",
    "preset_management",
    "scan_health",
    "integrations",
    "feedback_profiles",
    "policies",
    "project_management",
    "stale_projects",
)


# ---------------------------------------------------------------------------
# sync_meta
# ---------------------------------------------------------------------------
def set_sync_status(section_key: str, status: str, message: str = "") -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE sync_meta SET status = ?, message = ? WHERE section_key = ?",
            (status, message, section_key),
        )


def set_sync_done(section_key: str, record_count: int, message: str = "") -> None:
    with get_connection() as conn:
        conn.execute(
            """UPDATE sync_meta
               SET status = 'done', record_count = ?, message = ?, last_synced_at = ?
               WHERE section_key = ?""",
            (record_count, message, datetime.now(timezone.utc).isoformat(), section_key),
        )


def get_sync_meta(section_key: str) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM sync_meta WHERE section_key = ?", (section_key,)
        ).fetchone()


def all_sync_meta() -> dict[str, sqlite3.Row]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM sync_meta").fetchall()
    return {row["section_key"]: row for row in rows}


# Fixed, closed set of tables a replace-all sync is ever allowed to target,
# mapped to their exact column count. _replace_all() validates both the
# table name and the row shape against this before building any SQL, so the
# identifier can never come from anything other than one of these vetted
# literals and a row can never be inserted with the wrong arity.
#
# checkmarx: table names below are validated against this fixed allow-list
# before use, never derived from request/user input -- see _replace_all().
_REPLACEABLE_TABLES = {
    "tenant_config": 5,
    "presets": 7,
    "scans": 12,
    "scm_connections": 6,
    "scm_orgs": 6,
    "feedback_apps": 4,
    "feedback_profiles": 4,
    "policies": 4,
    "policy_violations": 7,
    "policy_evaluations": 4,
    "scan_summaries": 4,
    "projects": 7,
    "applications": 4,
    "application_authorizations": 2,
}


def _replace_all(conn: sqlite3.Connection, table: str, rows: list[tuple]) -> None:
    if table not in _REPLACEABLE_TABLES:
        raise ValueError(f"Refusing to replace rows in unrecognized table: {table!r}")
    expected_columns = _REPLACEABLE_TABLES[table]
    if rows and len(rows[0]) != expected_columns:
        raise ValueError(
            f"Column count mismatch for table {table!r}: expected {expected_columns}, got {len(rows[0])}"
        )

    conn.execute("DELETE FROM " + table)
    if not rows:
        return
    placeholders = ", ".join("?" for _ in range(expected_columns))
    conn.executemany("INSERT INTO " + table + " VALUES (" + placeholders + ")", rows)


# ---------------------------------------------------------------------------
# Global Configurations
# ---------------------------------------------------------------------------
def _extract_allow_override(entry: dict) -> int | None:
    """None means the entry has no allow-override concept at all (rendered
    as N/A), which is distinct from it being explicitly set to false."""
    for key in ("allowOverride", "allow_override", "isOverridable", "overridable"):
        if key in entry:
            return 1 if entry[key] else 0
    return None


def replace_tenant_configuration(entries: list[dict]) -> int:
    rows = []
    for entry in entries:
        key = str(entry.get("key") or entry.get("name") or entry.get("id"))
        category = entry.get("category")
        value = entry.get("value")
        allow_override = _extract_allow_override(entry)
        rows.append((key, category, json.dumps(value), allow_override, json.dumps(entry)))
    with get_connection() as conn:
        _replace_all(conn, "tenant_config", rows)
    return len(rows)


def list_tenant_configuration() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM tenant_config ORDER BY category, key"
        ).fetchall()


# ---------------------------------------------------------------------------
# Preset Management
# ---------------------------------------------------------------------------
def _is_custom_preset(preset: dict) -> bool:
    for key in ("isCustom", "custom", "isUserDefined"):
        if key in preset:
            return bool(preset[key])
    for key in ("isDefault", "isBuiltIn", "builtIn"):
        if key in preset:
            return not bool(preset[key])
    return False


def replace_presets(presets: list[dict]) -> int:
    rows = []
    for preset in presets:
        preset_id = str(preset.get("id"))
        name = preset.get("name", f"Preset {preset_id}")
        is_custom = 1 if _is_custom_preset(preset) else 0
        description = preset.get("description")
        associated_projects = preset.get("associatedProjects", 0)
        is_tenant_default = 1 if preset.get("isTenantDefault") else 0
        rows.append((
            preset_id, name, is_custom, description, json.dumps(preset),
            associated_projects, is_tenant_default,
        ))
    with get_connection() as conn:
        _replace_all(conn, "presets", rows)
    return len(rows)


def list_presets() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM presets ORDER BY name").fetchall()


def upsert_preset(preset: dict) -> None:
    """Single-row upsert, used after create/update/delete against the live
    API so that one action doesn't require re-syncing every preset."""
    preset_id = str(preset.get("id"))
    name = preset.get("name", f"Preset {preset_id}")
    is_custom = 1 if _is_custom_preset(preset) else 0
    description = preset.get("description")
    associated_projects = preset.get("associatedProjects", 0)
    is_tenant_default = 1 if preset.get("isTenantDefault") else 0
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO presets (id, name, is_custom, description, raw_json, associated_projects, is_tenant_default)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   name=excluded.name,
                   is_custom=excluded.is_custom,
                   description=excluded.description,
                   raw_json=excluded.raw_json,
                   associated_projects=excluded.associated_projects,
                   is_tenant_default=excluded.is_tenant_default""",
            (preset_id, name, is_custom, description, json.dumps(preset), associated_projects, is_tenant_default),
        )


def delete_cached_preset(preset_id) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM presets WHERE id = ?", (str(preset_id),))


def get_cached_preset(preset_id) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT raw_json FROM presets WHERE id = ?", (str(preset_id),)).fetchone()
    return json.loads(row["raw_json"]) if row else None


def get_cached_preset_meta(preset_id) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM presets WHERE id = ?", (str(preset_id),)).fetchone()


def upsert_query_catalog_entry(family: str, query: dict) -> None:
    """Cache one flattened entry from cx_client.list_queries_in_family. The
    "key" field is the same identifier a preset's queryIds array
    references; "title" is the query's display name; "group" is the
    category it was nested under."""
    query_id = str(query.get("key") or query.get("queryId") or query.get("id"))
    name = query.get("title") or query.get("name") or query.get("queryName") or query_id
    group = query.get("group") or query.get("category") or family
    severity = query.get("severity")

    with get_connection() as conn:
        conn.execute(
            """INSERT INTO query_catalog (query_id, family, name, group_name, severity, raw_json)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(query_id) DO UPDATE SET
                   family=excluded.family,
                   name=excluded.name,
                   group_name=excluded.group_name,
                   severity=excluded.severity,
                   raw_json=excluded.raw_json""",
            (query_id, family, name, group, severity, json.dumps(query)),
        )


def query_catalog_count() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM query_catalog").fetchone()[0]


def get_query_metadata(query_id) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT query_id, family, name, group_name, severity FROM query_catalog WHERE query_id = ?",
            (str(query_id),),
        ).fetchone()
    if row is None:
        return None
    return {
        "queryId": row["query_id"],
        "language": row["family"],
        "group": row["group_name"],
        "name": row["name"],
        "severity": row["severity"],
    }


def normalize_preset_queries(preset: dict) -> list[dict]:
    """Returns a flat list of query dicts (queryId, language, group, name,
    severity), resolving a preset's grouped-by-family bare queryIds against
    the local query_catalog. An id with no catalog match still renders,
    labeled with its family and a placeholder name, rather than being
    silently dropped."""
    raw_queries = preset.get("queries") or []
    if not raw_queries:
        return []

    is_grouped = isinstance(raw_queries[0], dict) and "queryIds" in raw_queries[0]
    if not is_grouped:
        return raw_queries

    flat = []
    for group in raw_queries:
        family = group.get("familyName") or group.get("family") or "Unknown"
        for query_id in group.get("queryIds", []) or []:
            meta = get_query_metadata(query_id)
            if meta:
                flat.append(meta)
            else:
                flat.append(
                    {
                        "queryId": str(query_id),
                        "language": family,
                        "group": "Uncategorized",
                        "name": f"Query {query_id}",
                    }
                )
    return flat


def group_queries_by_family(queries) -> dict[str, list[str]]:
    """Inverse of normalize_preset_queries: takes an iterable of query dicts
    and regroups their ids by family (language), sorted, for building a
    create/update preset request body."""
    by_family: dict[str, list[str]] = {}
    for q in queries:
        query_id = q.get("queryId")
        if query_id is None:
            continue
        by_family.setdefault(q.get("language") or "Unknown", []).append(str(query_id))
    for family in by_family:
        by_family[family].sort()
    return dict(sorted(by_family.items()))


def full_query_catalog() -> dict:
    """The entire synced query catalog grouped by language -> category ->
    [{"queryId", "name"}, ...], for the update-preset query picker."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT query_id, family, name, group_name FROM query_catalog "
            "ORDER BY family, group_name, name"
        ).fetchall()

    groups: dict[str, dict[str, list]] = {}
    for row in rows:
        category = row["group_name"] or "Uncategorized"
        groups.setdefault(row["family"], {}).setdefault(category, []).append(
            {"queryId": row["query_id"], "name": row["name"]}
        )
    return groups


# ---------------------------------------------------------------------------
# Scan Health / Integrations (shared "scans" table)
# ---------------------------------------------------------------------------
def _classify_origin(origin: str | None) -> str:
    if not origin:
        return "Unknown"
    o = origin.strip().lower()
    if o.startswith("grpc-dotnet"):
        return "Auto-scan"
    if "grpc-java-netty" in o:
        return "Project Scan"
    if o == "na":
        return "Scheduler"
    if "jenkins" in o:
        return "Jenkins"
    if "bamboo" in o:
        return "Bamboo"
    if "azure" in o or "vsts" in o or "ado" in o:
        return "Azure DevOps"
    if "github" in o:
        return "GitHub Actions"
    if "gitlab" in o:
        return "GitLab CI"
    if "circleci" in o:
        return "CircleCI"
    if "teamcity" in o:
        return "TeamCity"
    if "bitbucket" in o:
        return "Bitbucket Pipeline"
    if "codebuild" in o:
        return "Codebuild"
    if "maven" in o:
        return "Maven"
    if "vscode" in o or "vs code" in o or "visual studio code" in o:
        return "VS Code Plugin"
    if "intellij" in o or "jetbrains" in o:
        return "JetBrains Plugin"
    if "eclipse" in o:
        return "Eclipse Plugin"
    if "visual studio" in o:
        return "Visual Studio Plugin"
    if "cursor" in o:
        return "Cursor Plugin"
    if "windsurf" in o:
        return "Windsurf Plugin"
    if "kiro" in o:
        return "Kiro Plugin"
    if "cli" in o:
        return "CLI"
    if "web" in o or "portal" in o:
        return "Web Portal"
    return origin


def replace_scans(scans: list[dict], loc_by_id: dict | None = None) -> int:
    """`loc_by_id` (scan id -> lines of code) comes from a separate
    /api/sast-metadata batch call (see cx_client.get_sast_metadata) -- it's
    an enrichment, not part of the base /api/scans payload, so a scan with
    no entry there (too old, no completed SAST engine, etc.) just gets
    loc=None rather than failing the sync."""
    loc_by_id = loc_by_id or {}
    rows = []
    for scan in scans:
        scan_id = str(scan.get("id"))
        project_id = scan.get("projectId")
        project_name = scan.get("projectName") or scan.get("project_name")
        status = scan.get("status")
        branch = scan.get("branch")
        engines = json.dumps(scan.get("engines") or [])
        origin = scan.get("userAgent") or scan.get("origin") or scan.get("initiator")
        origin = _classify_origin(origin)
        initiator = scan.get("initiator")
        created_at = scan.get("createdAt") or scan.get("created_at")
        updated_at = scan.get("updatedAt") or scan.get("updated_at")
        loc = loc_by_id.get(scan_id)
        rows.append(
            (
                scan_id, project_id, project_name, status, branch, engines,
                origin, initiator, created_at, updated_at, json.dumps(scan), loc,
            )
        )
    with get_connection() as conn:
        _replace_all(conn, "scans", rows)
    return len(rows)


def list_scans(limit: int | None = None) -> list[sqlite3.Row]:
    with get_connection() as conn:
        sql = "SELECT * FROM scans ORDER BY created_at DESC"
        if limit:
            return conn.execute(sql + " LIMIT ?", (int(limit),)).fetchall()
        return conn.execute(sql).fetchall()


def list_scans_with_duration() -> list[sqlite3.Row]:
    """Same as list_scans() but with a computed duration_minutes column, for
    the Scans explorer table -- lets the UI show/sort/highlight by duration
    without every caller re-deriving it."""
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT *,
                   CASE
                       WHEN created_at IS NOT NULL AND updated_at IS NOT NULL
                            AND julianday(updated_at) >= julianday(created_at)
                       THEN (julianday(updated_at) - julianday(created_at)) * 24 * 60
                       ELSE NULL
                   END AS duration_minutes
            FROM scans
            ORDER BY created_at DESC
            """
        ).fetchall()


def scan_status_breakdown() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT status, COUNT(*) AS count FROM scans GROUP BY status ORDER BY count DESC"
        ).fetchall()


def scan_origin_breakdown() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT origin, COUNT(*) AS count FROM scans GROUP BY origin ORDER BY count DESC"
        ).fetchall()


# Fixed lists the Integrations page always shows a box for (0 if unused),
# matching _classify_origin's own output strings exactly.
CICD_ORIGINS = [
    "Jenkins", "TeamCity", "GitHub Actions", "Azure DevOps", "Maven",
    "Bitbucket Pipeline", "CircleCI", "GitLab CI", "Bamboo", "Codebuild",
]
IDE_ORIGINS = [
    "VS Code Plugin", "JetBrains Plugin", "Cursor Plugin", "Windsurf Plugin",
    "Kiro Plugin", "Visual Studio Plugin", "Eclipse Plugin",
]
# "Project Scan" and "Scheduler" are CxOne's own built-in scan triggers (a
# manually-created project scan, and a recurring scheduled scan) -- not a
# third-party CI/CD tool or IDE plugin, but still worth its own category
# rather than being lost in the Custom catch-all.
PLATFORM_SCAN_ORIGINS = ["Project Scan", "Scheduler"]
# Baseline scan paths, not integrations -- excluded from "Custom" too, not
# just from the CI/CD and IDE lists.
_BASELINE_ORIGINS = {"Web Portal", "CLI", "Unknown"}


def integration_usage_breakdown() -> dict:
    """Splits scan_origin_breakdown() into the fixed CI/CD, IDE Plugin, and
    Platform Scans boxes (always shown, 0 when unused) plus a dynamic
    "Custom" bucket for any other classified origin -- excluding Web
    Portal/CLI/Unknown, which are the baseline ways to run a scan, not a
    third-party integration."""
    counts = {row["origin"]: row["count"] for row in scan_origin_breakdown()}
    cicd = [{"label": name, "count": counts.get(name, 0)} for name in CICD_ORIGINS]
    ide = [{"label": name, "count": counts.get(name, 0)} for name in IDE_ORIGINS]
    platform = [{"label": name, "count": counts.get(name, 0)} for name in PLATFORM_SCAN_ORIGINS]
    known = set(CICD_ORIGINS) | set(IDE_ORIGINS) | set(PLATFORM_SCAN_ORIGINS) | _BASELINE_ORIGINS
    custom = sorted(
        ({"label": name, "count": count} for name, count in counts.items() if name not in known),
        key=lambda row: -row["count"],
    )
    return {"cicd": cicd, "ide": ide, "platform": platform, "custom": custom}


def integration_scan_type_counts() -> list[dict]:
    """Group integration scans into mutually exclusive SCM, CI/CD, IDE, and
    Custom buckets. Baseline scan paths are not included in the mix."""
    counts = {row["origin"]: row["count"] for row in scan_origin_breakdown()}
    scm_origins = {"project-scan", "project scan", "push-webhook", "pull-request"}
    cicd_origins = set(CICD_ORIGINS)
    ide_origins = set(IDE_ORIGINS)
    known_origins = cicd_origins | ide_origins | _BASELINE_ORIGINS

    scm = sum(
        count for origin, count in counts.items()
        if origin and origin.strip().lower() in scm_origins
    )
    cicd = sum(count for origin, count in counts.items() if origin in cicd_origins)
    ide = sum(count for origin, count in counts.items() if origin in ide_origins)
    custom = sum(
        count for origin, count in counts.items()
        if origin not in known_origins
        and not (origin and origin.strip().lower() in scm_origins)
    )
    return [
        {"label": "SCM", "count": scm},
        {"label": "CI/CD", "count": cicd},
        {"label": "IDE", "count": ide},
        {"label": "Custom", "count": custom},
    ]


def integration_type_totals() -> list[dict]:
    """Flat, non-zero list across CI/CD + IDE Plugin + Platform Scans +
    Custom, sorted by count desc -- feeds the Integrations page's breakdown
    bar chart. Same exclusions as integration_usage_breakdown() (Web
    Portal/CLI/Unknown aren't integrations)."""
    usage = integration_usage_breakdown()
    rows = usage["cicd"] + usage["ide"] + usage["platform"] + usage["custom"]
    rows = [row for row in rows if row["count"] > 0]
    rows.sort(key=lambda row: -row["count"])
    return rows


# ---------------------------------------------------------------------------
# Scan Health KPIs -- duration is derived from created_at/updated_at (no
# separate duration field from the API). SQLite's julianday() accepts the
# ISO8601 "T"-separated timestamps the API returns directly.
# ---------------------------------------------------------------------------
def long_running_scans_by_project(min_minutes: int = 30) -> list[sqlite3.Row]:
    """Every project with at least one scan running longer than min_minutes,
    most-affected first. No LIMIT here -- the caller paginates."""
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT project_id, project_name,
                   COUNT(*) AS long_scan_count,
                   MAX((julianday(updated_at) - julianday(created_at)) * 24 * 60) AS max_minutes,
                   AVG((julianday(updated_at) - julianday(created_at)) * 24 * 60) AS avg_minutes
            FROM scans
            WHERE created_at IS NOT NULL AND updated_at IS NOT NULL
              AND julianday(updated_at) >= julianday(created_at)
              AND (julianday(updated_at) - julianday(created_at)) * 24 * 60 >= ?
            GROUP BY project_id, project_name
            ORDER BY long_scan_count DESC, max_minutes DESC
            """,
            (min_minutes,),
        ).fetchall()


def top_failing_projects(limit: int = 10) -> list[sqlite3.Row]:
    """Top projects by count of Failed/Partial scans, worst first."""
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT project_id, project_name, COUNT(*) AS failure_count
            FROM scans
            WHERE status IN ('Failed', 'Partial')
            GROUP BY project_id, project_name
            ORDER BY failure_count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def failed_partial_scans() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT id, status, project_id, project_name FROM scans WHERE status IN ('Failed', 'Partial')"
        ).fetchall()


# A finished scan's workflow never changes, so each is fetched once and kept
# for as long as the scan itself stays in the synced window.
def cached_workflow_scan_ids() -> set[str]:
    with get_connection() as conn:
        return {row["scan_id"] for row in conn.execute("SELECT scan_id FROM scan_workflows")}


def save_scan_workflow(scan_id: str, steps: list[dict]) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO scan_workflows (scan_id, raw_json, fetched_at) VALUES (?, ?, ?) "
            "ON CONFLICT(scan_id) DO UPDATE SET raw_json = excluded.raw_json, fetched_at = excluded.fetched_at",
            (str(scan_id), json.dumps(steps), datetime.now(timezone.utc).isoformat()),
        )


def prune_scan_workflows() -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM scan_workflows WHERE scan_id NOT IN (SELECT id FROM scans)")


def scan_workflows_by_id() -> dict[str, list[dict]]:
    with get_connection() as conn:
        rows = conn.execute("SELECT scan_id, raw_json FROM scan_workflows").fetchall()
    return {row["scan_id"]: json.loads(row["raw_json"]) for row in rows}


def inconsistent_scan_projects(min_scans: int = 3, limit: int = 10) -> list[dict]:
    """Projects whose scan durations vary the most (highest population
    standard deviation), highest-variance first. Requires at least
    `min_scans` scans per project -- variance from 1-2 data points doesn't
    mean "inconsistent," it means "not enough history yet."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT project_id, project_name,
                   (julianday(updated_at) - julianday(created_at)) * 24 * 60 AS minutes
            FROM scans
            WHERE created_at IS NOT NULL AND updated_at IS NOT NULL
              AND julianday(updated_at) >= julianday(created_at)
            """
        ).fetchall()

    durations_by_project: dict = {}
    names: dict = {}
    for row in rows:
        project_id = row["project_id"]
        if project_id is None:
            continue
        durations_by_project.setdefault(project_id, []).append(row["minutes"])
        names[project_id] = row["project_name"]

    results = []
    for project_id, durations in durations_by_project.items():
        if len(durations) < min_scans:
            continue
        results.append(
            {
                "project_id": project_id,
                "project_name": names[project_id],
                "scan_count": len(durations),
                "stdev_minutes": statistics.pstdev(durations),
                "min_minutes": min(durations),
                "max_minutes": max(durations),
                "avg_minutes": sum(durations) / len(durations),
            }
        )
    results.sort(key=lambda r: r["stdev_minutes"], reverse=True)
    return results[:limit]


# ---------------------------------------------------------------------------
# Integrations -- SCM connections
# ---------------------------------------------------------------------------
def replace_scm_connections(scms: list[dict]) -> int:
    rows = []
    for scm in scms:
        scm_id = str(scm.get("id"))
        scm_type = scm.get("type")
        display_name = scm.get("displayName")
        instance_name = scm.get("instanceName") or display_name
        on_prem = 1 if scm.get("onPrem") else 0
        rows.append((scm_id, scm_type, display_name, instance_name, on_prem, json.dumps(scm)))
    with get_connection() as conn:
        _replace_all(conn, "scm_connections", rows)
    return len(rows)


def replace_scm_orgs(orgs: list[dict]) -> int:
    rows = []
    for org in orgs:
        org_id = str(org.get("orgId"))
        scm_id = str(org.get("scmId"))
        org_identity = org.get("orgIdentity")
        is_user_org = 1 if org.get("isUserOrg") else 0
        webhook_enabled = 1 if org.get("webhookEnabled") else 0
        rows.append((org_id, scm_id, org_identity, is_user_org, webhook_enabled, json.dumps(org)))
    with get_connection() as conn:
        _replace_all(conn, "scm_orgs", rows)
    return len(rows)


def list_scm_connections() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM scm_connections ORDER BY instance_name").fetchall()


def list_scm_orgs_by_scm() -> dict:
    """{scm_id: [org rows]} so the template can nest each SCM's orgs under it
    without an N+1 query per SCM connection."""
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM scm_orgs ORDER BY org_identity").fetchall()
    by_scm = {}
    for row in rows:
        by_scm.setdefault(row["scm_id"], []).append(row)
    return by_scm


def get_scm_org(org_id: str) -> sqlite3.Row | None:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM scm_orgs WHERE org_id = ?", (org_id,)).fetchone()


# ---------------------------------------------------------------------------
# Feedback Apps and Profiles
# ---------------------------------------------------------------------------
def replace_feedback_apps(apps: list[dict]) -> int:
    rows = []
    for index, app in enumerate(apps):
        app_id = str(app.get("id") or app.get("appId") or app.get("name") or index)
        name = app.get("name") or app.get("displayName") or app.get("title")
        app_type = app.get("appType") or app.get("type") or app.get("provider")
        rows.append((app_id, name, app_type, json.dumps(app)))
    with get_connection() as conn:
        _replace_all(conn, "feedback_apps", rows)
    return len(rows)


def list_feedback_apps() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM feedback_apps ORDER BY name, id"
        ).fetchall()


def replace_feedback_profiles(profiles: list[dict]) -> int:
    rows = []
    for index, profile in enumerate(profiles):
        profile_id = str(profile.get("id") or profile.get("profileId") or profile.get("name") or index)
        name = profile.get("name") or profile.get("displayName") or profile.get("title")
        profile_type = profile.get("profileType") or profile.get("type") or profile.get("provider") or "Feedback Profile"
        rows.append((profile_id, name, profile_type, json.dumps(profile)))
    with get_connection() as conn:
        _replace_all(conn, "feedback_profiles", rows)
    return len(rows)


def list_feedback_profiles() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM feedback_profiles ORDER BY profile_type, name"
        ).fetchall()


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
def replace_policies(policies: list[dict]) -> int:
    rows = []
    for policy in policies:
        policy_id = str(policy.get("id") or policy.get("name"))
        name = policy.get("name")
        enabled = 1 if policy.get("enabled") or policy.get("isActive") else 0
        rows.append((policy_id, name, enabled, json.dumps(policy)))
    with get_connection() as conn:
        _replace_all(conn, "policies", rows)
    return len(rows)


def list_policies() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM policies ORDER BY name").fetchall()


def replace_policy_violations(violations: list[dict]) -> int:
    rows = []
    for violation in violations:
        raw = violation["raw"]
        violation_id = str(
            raw.get("id") or raw.get("violationId") or raw.get("policyViolationId")
            or f"{violation['scan_id']}:{len(rows)}"
        )
        rows.append((
            f"{violation['scan_id']}:{violation_id}",
            violation.get("policy_name") or raw.get("policyName") or raw.get("name"),
            violation.get("project_id"),
            violation.get("project_name"),
            violation.get("scan_id"),
            json.dumps(raw),
            violation.get("branch"),
        ))
    with get_connection() as conn:
        _replace_all(conn, "policy_violations", rows)
    return len(rows)


def list_policy_violations() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM policy_violations ORDER BY project_name, policy_name, scan_id"
        ).fetchall()


def replace_policy_evaluations(evaluations: list[dict]) -> int:
    rows = [
        (
            str(item["scan_id"]), item.get("project_id"), item.get("project_name"),
            json.dumps(item["raw"]),
        )
        for item in evaluations
    ]
    with get_connection() as conn:
        _replace_all(conn, "policy_evaluations", rows)
    return len(rows)


def list_policy_evaluations() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM policy_evaluations ORDER BY project_name, scan_id"
        ).fetchall()


def replace_scan_summaries(summaries: list[dict]) -> int:
    rows = [
        (
            str(item["scan_id"]), item.get("project_id"), item.get("project_name"),
            json.dumps(item["raw"]),
        )
        for item in summaries
    ]
    with get_connection() as conn:
        _replace_all(conn, "scan_summaries", rows)
    return len(rows)


def list_scan_summaries() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM scan_summaries ORDER BY project_name, scan_id"
        ).fetchall()


def latest_completed_project_scans() -> list[sqlite3.Row]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, project_id, project_name, branch, created_at
            FROM scans
            WHERE project_id IS NOT NULL AND lower(status) = 'completed'
            ORDER BY created_at DESC
            """
        ).fetchall()
    latest_by_project = {}
    for row in rows:
        latest_by_project.setdefault(row["project_id"], row)
    return list(latest_by_project.values())


def completed_project_scans() -> list[sqlite3.Row]:
    """All completed cached scans with a project, newest first."""
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT id, project_id, project_name, branch, created_at
            FROM scans
            WHERE project_id IS NOT NULL AND lower(status) = 'completed'
            ORDER BY created_at DESC
            """
        ).fetchall()


# ---------------------------------------------------------------------------
# Project / Application Management
# ---------------------------------------------------------------------------
def replace_projects(projects: list[dict]) -> int:
    rows = []
    for project in projects:
        project_id = str(project.get("id"))
        name = project.get("name", project_id)
        groups = json.dumps(project.get("groups") or [])
        tags = json.dumps(project.get("tags") or {})
        criticality = project.get("criticality")
        created_at = project.get("createdAt") or project.get("created_at")
        rows.append((project_id, name, groups, tags, criticality, created_at, json.dumps(project)))
    with get_connection() as conn:
        _replace_all(conn, "projects", rows)
    return len(rows)


def list_projects() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM projects ORDER BY name").fetchall()


def replace_applications(applications: list[dict]) -> int:
    rows = []
    for app in applications:
        app_id = str(app.get("id"))
        name = app.get("name", app_id)
        project_ids = json.dumps(app.get("projectIds") or app.get("project_ids") or [])
        rows.append((app_id, name, project_ids, json.dumps(app)))
    with get_connection() as conn:
        _replace_all(conn, "applications", rows)
    return len(rows)


def list_applications() -> list[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute("SELECT * FROM applications ORDER BY name").fetchall()


def replace_application_authorizations(assignments: list[dict]) -> int:
    rows = [
        (str(item["application_id"]), json.dumps(item.get("entities") or []))
        for item in assignments
    ]
    with get_connection() as conn:
        _replace_all(conn, "application_authorizations", rows)
    return len(rows)


def list_application_authorizations() -> dict[str, list]:
    with get_connection() as conn:
        rows = conn.execute("SELECT application_id, raw_json FROM application_authorizations").fetchall()
    return {str(row["application_id"]): json.loads(row["raw_json"] or "[]") for row in rows}


def orphaned_projects_count() -> int:
    """Projects that appear in no application's project_ids list."""
    with get_connection() as conn:
        projects = conn.execute("SELECT id FROM projects").fetchall()
        apps = conn.execute("SELECT project_ids FROM applications").fetchall()
    assigned = set()
    for app in apps:
        assigned.update(json.loads(app["project_ids"] or "[]"))
    return sum(1 for p in projects if p["id"] not in assigned)


# ---------------------------------------------------------------------------
# Stale Projects -- derived from projects + scans, no sync of its own.
# ---------------------------------------------------------------------------
def stale_projects(threshold_days: int = 90) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT p.id, p.name, p.criticality,
                   MAX(s.created_at) AS last_scan_at,
                   COUNT(s.id) AS scan_count
            FROM projects p
            LEFT JOIN scans s ON s.project_id = p.id
            GROUP BY p.id, p.name, p.criticality
            ORDER BY last_scan_at IS NOT NULL, last_scan_at ASC
            """
        ).fetchall()

    now = datetime.now(timezone.utc)
    results = []
    for row in rows:
        last_scan_at = row["last_scan_at"]
        days_since = None
        if last_scan_at:
            try:
                parsed = datetime.fromisoformat(last_scan_at.replace("Z", "+00:00"))
                days_since = (now - parsed).days
            except ValueError:
                days_since = None
        # threshold 0 (All Time): only projects with no scan in the synced history.
        is_stale = days_since is None or (threshold_days > 0 and days_since >= threshold_days)
        if not is_stale:
            continue
        results.append(
            {
                "id": row["id"],
                "name": row["name"],
                "criticality": row["criticality"],
                "last_scan_at": last_scan_at,
                "days_since_last_scan": days_since,
                "scan_count": row["scan_count"],
            }
        )
    return results


# ---------------------------------------------------------------------------
# Analyzer Config -- user overrides (enabled / warning level) layered on top
# of the rule_catalog.catalog() rule set. Not read by this console itself: it's
# configuration for a separate downstream process that analyzes synced
# tenant data against these rules.
# ---------------------------------------------------------------------------
def get_rule_overrides() -> dict[str, sqlite3.Row]:
    with get_config_connection() as conn:
        rows = conn.execute("SELECT * FROM analyzer_rule_overrides").fetchall()
    return {row["rule_key"]: row for row in rows}


def save_rule_overrides(overrides: list[dict]) -> int:
    now = datetime.now(timezone.utc).isoformat()
    with get_config_connection() as conn:
        for override in overrides:
            conn.execute(
                """
                INSERT INTO analyzer_rule_overrides (rule_key, enabled, warning_level, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(rule_key) DO UPDATE SET
                    enabled = excluded.enabled,
                    warning_level = excluded.warning_level,
                    updated_at = excluded.updated_at
                """,
                (
                    override["rule_key"],
                    1 if override["enabled"] else 0,
                    override["warning_level"],
                    now,
                ),
            )
    return len(overrides)


def get_setting(key: str) -> str | None:
    with get_config_connection() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(key: str, value: str) -> None:
    with get_config_connection() as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def save_analyzer_report(report: dict) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO analyzer_report (id, ran_at, raw_json) VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET ran_at = excluded.ran_at, raw_json = excluded.raw_json
            """,
            (report["ran_at"], json.dumps(report)),
        )


def get_analyzer_report() -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT raw_json FROM analyzer_report WHERE id = 1").fetchone()
    return json.loads(row["raw_json"]) if row else None
