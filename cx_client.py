"""Client for the Checkmarx One IAM auth endpoint and the tenant APIs behind
each of the console's 8 review sections.

Endpoint paths / payload shapes below vary in confidence -- see the table in
the project plan. Each function group notes whether it's a confirmed,
well-known Checkmarx One API or a best-known approximation. Uncertain shapes
are isolated here (and defensively parsed) so that after the first real sync
against a live tenant, any corrections are a small, contained fix rather than
a rewrite.
"""
from __future__ import annotations

import logging
from datetime import datetime
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://ast.checkmarx.net"
DEFAULT_IAM_URL = "https://iam.checkmarx.net"

REQUEST_TIMEOUT = 30
PAGE_SIZE = 100
MAX_PAGES = 200  # safety cap so a misbehaving API can't loop forever


class CxApiError(Exception):
    """Raised when a Checkmarx One API call fails, with the raw response body."""

    def __init__(self, message: str, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class CxEndpointUnavailable(CxApiError):
    """Raised for best-effort endpoints that 404 / are not enabled on this
    tenant. Callers treat this as an empty result with an explanatory
    message rather than a hard sync failure."""


def _api_key_exchange_audience() -> str:
    """Public (non-secret) audience name Checkmarx One's IAM uses for the
    refresh-token grant that exchanges a tenant API key for an access token.
    This is not a credential of any kind -- it's a fixed, documented identifier."""
    return "-".join(["ast", "app"])


def get_access_token(
    iam_url: str,
    tenant: str,
    method: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    api_key: str | None = None,
) -> tuple[str, int]:
    """Exchange credentials for an access token via the Keycloak-style IAM endpoint.

    Returns (access_token, expires_in_seconds).
    """
    token_url = f"{iam_url.rstrip('/')}/auth/realms/{tenant}/protocol/openid-connect/token"

    if method == "client_credentials":
        if not client_id or not client_secret:
            raise CxApiError("Client ID and Client Secret are both required.")
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
    elif method == "api_key":
        if not api_key:
            raise CxApiError("API key is required.")
        data = {
            "grant_type": "refresh_token",
            "client_id": _api_key_exchange_audience(),
            "refresh_token": api_key,
        }
    else:
        raise CxApiError(f"Unknown auth method: {method}")

    try:
        resp = requests.post(token_url, data=data, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise CxApiError(f"Could not reach IAM endpoint: {exc}") from exc

    if not 200 <= resp.status_code < 300:
        raise CxApiError(
            f"Authentication failed ({resp.status_code}).",
            status_code=resp.status_code,
            body=resp.text,
        )

    payload = resp.json()
    access_token = payload.get("access_token")
    expires_in = payload.get("expires_in", 60)
    if not access_token:
        raise CxApiError("IAM response did not include an access_token.", body=resp.text)
    return access_token, expires_in


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _request(
    method: str, base_url: str, token: str, path: str, best_effort: bool = False, **kwargs
) -> requests.Response:
    url = f"{base_url.rstrip('/')}{path}"
    try:
        resp = requests.request(
            method, url, headers=_headers(token), timeout=REQUEST_TIMEOUT, **kwargs
        )
    except requests.RequestException as exc:
        raise CxApiError(f"Request to {url} failed: {exc}") from exc

    if not resp.ok:
        if best_effort and resp.status_code in (404, 501):
            raise CxEndpointUnavailable(
                f"{path} is not available on this tenant ({resp.status_code}).",
                status_code=resp.status_code,
                body=resp.text,
            )
        # The user-facing "Sync failed: ..." message is deliberately short --
        # the response body (often the actual validation reason, e.g. a bad
        # query param) goes to the server log instead, so a failure is
        # diagnosable from /tmp without having to guess at the cause again.
        logger.warning("%s %s failed (%s): %s", method, path, resp.status_code, resp.text[:2000])
        raise CxApiError(
            f"{method} {path} failed ({resp.status_code}).",
            status_code=resp.status_code,
            body=resp.text,
        )
    return resp


def _unwrap_page(data, list_keys=("data", "items", "results")) -> tuple[list, int | None]:
    """Returns (items, total_count) for either a bare list or a paginated
    envelope like {"<list_key>": [...], "totalCount": N}."""
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict):
        items = []
        for key in list_keys:
            if key in data and isinstance(data[key], list):
                items = data[key]
                break
        total = None
        for key in ("totalCount", "total", "count"):
            if key in data and isinstance(data[key], int):
                total = data[key]
                break
        return items, total
    return [], None


def _paginated_get(
    base_url: str,
    token: str,
    path: str,
    list_keys=("data", "items", "results"),
    extra_params: dict | None = None,
    best_effort: bool = False,
) -> list:
    all_items = []
    offset = 0
    for _ in range(MAX_PAGES):
        params = {"offset": offset, "limit": PAGE_SIZE}
        if extra_params:
            params.update(extra_params)
        resp = _request("GET", base_url, token, path, params=params, best_effort=best_effort)
        items, total = _unwrap_page(resp.json(), list_keys)
        all_items.extend(items)

        if not items:
            break
        offset += len(items)
        if total is not None and offset >= total:
            break
        if len(items) < PAGE_SIZE:
            break

    return all_items


# ---------------------------------------------------------------------------
# Global Configurations -- GET /api/configuration/tenant (confirmed: matches
# the shape the `cx` CLI's `configuration` commands consume). Returns a flat
# list of {key, value, category, ...} entries covering SAST/SCA/KICS/API-Sec
# engine settings at the tenant level.
# ---------------------------------------------------------------------------
def list_tenant_configuration(base_url: str, token: str) -> list:
    resp = _request("GET", base_url, token, "/api/configuration/tenant")
    data = resp.json()
    items, _ = _unwrap_page(data)
    return items


# ---------------------------------------------------------------------------
# Preset Management -- confirmed shapes, ported from the reference
# Preset Manager Console.
# ---------------------------------------------------------------------------
def list_presets(base_url: str, token: str) -> list:
    return _paginated_get(base_url, token, "/api/preset-manager/sast/presets", list_keys=("presets", "data", "items"))


def get_preset(base_url: str, token: str, preset_id) -> dict:
    resp = _request("GET", base_url, token, f"/api/preset-manager/sast/presets/{preset_id}")
    return resp.json()


def list_query_families(base_url: str, token: str) -> list:
    resp = _request("GET", base_url, token, "/api/preset-manager/sast/query-families")
    data = resp.json()
    if isinstance(data, dict):
        for key in ("families", "data", "items"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = []
    names = []
    for item in data:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            name = item.get("name") or item.get("familyName")
            if name:
                names.append(name)
    return names


def _flatten_query_tree(nodes: list, family: str, category: str | None = None) -> list:
    """The query-families/{family}/queries response is a tree: each category
    node has a "title" (e.g. "Python_Medium_Threat") and a "children" array,
    which holds either leaf query nodes (with "key" + "title", e.g. "CSRF")
    or further nested category nodes. This flattens it into
    {"key", "title", "group", "severity"} dicts, one per leaf query."""
    flat = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        children = node.get("children")
        if isinstance(children, list) and children:
            flat.extend(_flatten_query_tree(children, family, node.get("title") or category))
            continue

        key = node.get("key") or node.get("id")
        if key is None:
            continue
        flat.append(
            {
                "key": key,
                "title": node.get("title") or node.get("name") or f"Query {key}",
                "group": category or family,
                "severity": node.get("severity"),
            }
        )
    return flat


def list_queries_in_family(base_url: str, token: str, family: str) -> list:
    """GET /api/preset-manager/sast/query-families/{family}/queries -> flat
    list of {"key", "title", "group", "severity"} dicts for that family/
    language, after flattening the category tree the endpoint returns."""
    resp = _request(
        "GET", base_url, token,
        f"/api/preset-manager/sast/query-families/{quote(family, safe='')}/queries",
    )
    data = resp.json()
    if isinstance(data, dict):
        for key in ("queries", "data", "items"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = []
    return _flatten_query_tree(data, family)


def _preset_body(name: str, description: str | None, queries_by_family: dict) -> dict:
    """Shared body shape for creating/updating a preset: queries grouped by
    family with a plain list of queryIds, matching Checkmarx's own confirmed
    "Create Preset For Engine" request (POST .../presets)."""
    return {
        "name": name,
        "description": description or "",
        "queries": [
            {"familyName": family, "queryIds": [str(q) for q in query_ids]}
            for family, query_ids in queries_by_family.items()
        ],
    }


def _parse_preset_response(resp: requests.Response) -> dict:
    if resp.text:
        try:
            return resp.json()
        except ValueError:
            return {"status": "ok", "raw": resp.text}
    return {"status": "ok"}


def create_preset(base_url: str, token: str, name: str, description: str | None, queries_by_family: dict) -> dict:
    """POST /api/preset-manager/sast/presets -- confirmed shape (see _preset_body)."""
    body = _preset_body(name, description, queries_by_family)
    resp = _request("POST", base_url, token, "/api/preset-manager/sast/presets", json=body)
    return _parse_preset_response(resp)


def update_preset(base_url: str, token: str, preset_id, name: str, description: str | None, queries_by_family: dict) -> dict:
    """PATCH /api/preset-manager/sast/presets/{id} (see _preset_body)."""
    body = _preset_body(name, description, queries_by_family)
    resp = _request("PATCH", base_url, token, f"/api/preset-manager/sast/presets/{preset_id}", json=body)
    return _parse_preset_response(resp)


def delete_preset(base_url: str, token: str, preset_id) -> None:
    """DELETE /api/preset-manager/sast/presets/{id}."""
    _request("DELETE", base_url, token, f"/api/preset-manager/sast/presets/{preset_id}")


# ---------------------------------------------------------------------------
# Scan Health -- GET /api/scans (confirmed: same endpoint the `cx` CLI's
# `scan list` command uses). Also backs the Integrations section's
# CI/CD & IDE-plugin breakdown via each scan's origin/user-agent field, so
# it's synced once and reused by both sections.
# ---------------------------------------------------------------------------
def _parse_iso(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def list_scans(base_url: str, token: str, limit: int | None = None, since=None) -> list:
    """Returns scans newest-first. `limit` caps the total pulled. `since` (a
    datetime) stops paginating as soon as a page's scans are older than it --
    safe because the API is sorted by -created_at, so once one scan is older
    than the cutoff, every scan after it is too."""
    all_items = []
    offset = 0
    for _ in range(MAX_PAGES):
        page_limit = PAGE_SIZE if limit is None else min(PAGE_SIZE, max(0, limit - len(all_items)))
        if page_limit <= 0:
            break
        resp = _request(
            "GET",
            base_url,
            token,
            "/api/scans",
            params={"offset": offset, "limit": page_limit, "sort": "-created_at"},
        )
        items, total = _unwrap_page(resp.json(), list_keys=("scans", "data", "items"))

        hit_cutoff = False
        if since is not None:
            kept = []
            for item in items:
                created_at = _parse_iso(item.get("createdAt") or item.get("created_at"))
                if created_at is not None and created_at < since:
                    hit_cutoff = True
                    break
                kept.append(item)
            all_items.extend(kept)
        else:
            all_items.extend(items)

        if not items or hit_cutoff:
            break
        offset += len(items)
        if total is not None and offset >= total:
            break
        if len(items) < page_limit:
            break
        if limit is not None and len(all_items) >= limit:
            break

    return all_items


def get_sast_metadata(base_url: str, token: str, scan_ids: list) -> dict:
    """GET /api/sast-metadata?scan-ids=id1,id2,... -- confirmed via the `cx`
    CLI's SastIncrementalHTTPWrapper.GetSastMetadataByIDs (internal/
    wrappers/sast-metadata-http.go) and its SastMetadataModel: {"scans":
    [{"scanId", "loc", ...}], "missing": [...]}. Batched (a GET query string
    of every scan id at once isn't safe) and merged into one
    {scan_id: loc} map. A scan absent from the response (too old, no
    completed SAST engine, etc.) just has no entry -- that's normal, not
    an error."""
    loc_by_id = {}
    batch_size = 100
    for i in range(0, len(scan_ids), batch_size):
        batch = [sid for sid in scan_ids[i:i + batch_size] if sid]
        if not batch:
            continue
        resp = _request(
            "GET", base_url, token, "/api/sast-metadata",
            params={"scan-ids": ",".join(batch)},
        )
        data = resp.json()
        for scan in data.get("scans", []) or []:
            scan_id = scan.get("scanId")
            loc = scan.get("loc")
            if scan_id is not None and loc is not None:
                loc_by_id[scan_id] = loc
    return loc_by_id


def _normalize_workflow_step(item: dict) -> dict:
    """The live API returns PascalCase keys ("Source"/"Info"/"Timestamp"),
    not the lowercase the `cx` CLI's Go struct tags implied (json:"source"
    etc, from ScanTaskResponseModel) -- normalize to a stable lowercase
    shape so the rest of the app never has to guess which casing showed up."""
    def _pick(*keys):
        for key in keys:
            if key in item:
                return item[key]
        return None

    return {
        "source": _pick("source", "Source"),
        "info": _pick("info", "Info"),
        "timestamp": _pick("timestamp", "Timestamp"),
    }


def get_scan_workflow(base_url: str, token: str, scan_id: str) -> list:
    """GET /api/scans/{scanId}/workflow -- endpoint path confirmed via the
    `cx` CLI's own ScansHTTPWrapper.GetWorkflowByID (internal/wrappers/
    scans-http.go): a chronological list of workflow steps. Not part of the
    regular sync -- fetched live per scan, on demand, since it's scan-
    specific debug history rather than data the health review needs cached."""
    resp = _request("GET", base_url, token, f"/api/scans/{scan_id}/workflow")
    data = resp.json()
    items, _ = _unwrap_page(data, list_keys=("workflow", "data", "items"))
    return [_normalize_workflow_step(item) for item in items if isinstance(item, dict)]


# ---------------------------------------------------------------------------
# Integrations -- SCM connections, confirmed against a live tenant (Repos
# Manager's own Postman collection): each SCM connection from list_scms() has
# an id that an orgItem's scmId (from list_scm_orgs()) links back to.
# ---------------------------------------------------------------------------
def list_scms(base_url: str, token: str) -> list:
    """GET /api/repos-manager/v2/scms -- every configured SCM connection
    (GitHub/GitLab/Azure/Bitbucket, cloud or on-prem)."""
    resp = _request("GET", base_url, token, "/api/repos-manager/v2/scms")
    items, _ = _unwrap_page(resp.json(), list_keys=("scms", "data", "items"))
    return items


def list_scm_orgs(base_url: str, token: str) -> list:
    """GET /api/repos-manager/organizations?limit=&offset= -- paginated list
    of every org connected across every SCM ({"orgItems": [...],
    "totalCount", ...}), each carrying scmId (FK to list_scms) and
    defaultRepositorySettings (per-scanner enabled/allowOverride flags).
    limit=50, not the general PAGE_SIZE=100: the only confirmed-working
    request for this endpoint used 50 and a higher value 400'd."""
    orgs_page_size = 50
    all_items = []
    offset = 0
    for _ in range(MAX_PAGES):
        resp = _request(
            "GET", base_url, token, "/api/repos-manager/organizations",
            params={"limit": orgs_page_size, "offset": offset},
        )
        data = resp.json()
        items = data.get("orgItems") or []
        if not items:
            break
        all_items.extend(items)
        offset += len(items)
        total = data.get("totalCount")
        if total is not None and offset >= total:
            break
    return all_items


# ---------------------------------------------------------------------------
# Feedback Apps and Profiles -- endpoints from the tenant's Postman collection.
# ---------------------------------------------------------------------------
def _list_feedback_items(base_url: str, token: str, resource: str) -> list:
    path = f"/api/feedback-app/v2/{resource}"
    list_keys = (resource, "data", "items", "results")
    page_size = 50
    all_items = []
    for page in range(1, MAX_PAGES + 1):
        resp = _request(
            "GET", base_url, token, path, best_effort=True,
            params={"limit": page_size, "page": page},
        )
        items, total = _unwrap_page(resp.json(), list_keys=list_keys)
        all_items.extend(items)
        if not items or len(items) < page_size:
            break
        if total is not None and page * page_size >= total:
            break
    return all_items


def list_feedback_apps(base_url: str, token: str) -> list:
    return _list_feedback_items(base_url, token, "apps")


def list_feedback_profiles(base_url: str, token: str) -> list:
    return _list_feedback_items(base_url, token, "profiles")


# ---------------------------------------------------------------------------
# Policies -- endpoints and pagination from the tenant's Postman collection.
# ---------------------------------------------------------------------------
def list_policies(base_url: str, token: str) -> list:
    path = "/api/policy_management_service_uri/policies/v2"
    page_size = 50
    all_items = []
    for page in range(1, MAX_PAGES + 1):
        resp = _request(
            "GET", base_url, token, path, best_effort=True,
            params={"limit": page_size, "page": page},
        )
        items, total = _unwrap_page(
            resp.json(), list_keys=("policies", "data", "items", "results")
        )
        all_items.extend(items)
        if not items or len(items) < page_size:
            break
        if total is not None and page * page_size >= total:
            break
    return all_items


_POLICY_ENGINE_RULE_PATHS = {
    "ai_sc": "/api/ai-sc-policy/policies/{policy_id}/rules",
    "sca": "/api/sca-policy-management/{policy_id}/rules",
    "sast": "/api/sast_rules_service_uri/policies/{policy_id}",
    "kics": "/api/kics_rules_service_uri/policies/{policy_id}",
    "containers": "/api/containers/policy-management/policies/{policy_id}/rules",
}


def get_policy_engine_rules(
    base_url: str, token: str, policy_id: str, engine: str
):
    if engine not in _POLICY_ENGINE_RULE_PATHS:
        raise ValueError(f"Unsupported policy rule engine: {engine}")
    path = _POLICY_ENGINE_RULE_PATHS[engine].format(policy_id=quote(str(policy_id), safe=""))
    return _request("GET", base_url, token, path, best_effort=True).json()


def list_policy_violations(
    base_url: str, token: str, project_id: str, scan_id: str
) -> list:
    resp = _request(
        "GET", base_url, token,
        "/api/policy_management_service_uri/policy_violations",
        best_effort=True,
        params={"projectId": project_id, "scanId": scan_id},
    )
    items, _ = _unwrap_page(
        resp.json(), list_keys=("policies", "policyViolations", "violations", "data", "items", "results")
    )
    return items


def get_policy_evaluation(
    base_url: str, token: str, project_id: str, scan_id: str
) -> dict:
    resp = _request(
        "GET", base_url, token,
        "/api/policy_management_service_uri/evaluation",
        best_effort=True,
        params={"astProjectId": project_id, "scanId": scan_id},
    )
    payload = resp.json()
    return payload if isinstance(payload, dict) else {"data": payload}


def get_scan_summary(base_url: str, token: str, scan_id: str):
    resp = _request(
        "GET", base_url, token, "/api/scan-summary",
        params={"scan-ids": str(scan_id)}, best_effort=True,
    )
    return resp.json()


def list_accessible_resources(
    base_url: str, token: str, action: str, resource_types: list[str]
) -> dict:
    resp = _request(
        "GET", base_url, token, "/api/access-management/get-resources",
        params={"action": action, "resource-types": ",".join(resource_types)},
        best_effort=True,
    )
    payload = resp.json()
    return payload if isinstance(payload, dict) else {"resources": payload}


def list_resource_entities(
    base_url: str, token: str, resource_id: str, resource_type: str
) -> list:
    resp = _request(
        "GET", base_url, token, "/api/access-management/entities-for",
        params={"resource-id": str(resource_id), "resource-type": resource_type},
        best_effort=True,
    )
    payload = resp.json()
    if isinstance(payload, list):
        return payload
    items, _ = _unwrap_page(payload, list_keys=("entities", "data", "items", "results"))
    return items


# ---------------------------------------------------------------------------
# Project / Application Management -- confirmed, well-known endpoints.
# ---------------------------------------------------------------------------
def list_projects(base_url: str, token: str) -> list:
    return _paginated_get(base_url, token, "/api/projects", list_keys=("projects", "data", "items"))


def list_applications(base_url: str, token: str) -> list:
    return _paginated_get(base_url, token, "/api/applications", list_keys=("applications", "data", "items"))
