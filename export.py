"""CSV export of a preset diff, JSON export of a single preset, and the
Tenant Recommendations zip of the report plus its table CSVs."""
from __future__ import annotations

import csv
import io
import re
import zipfile
from datetime import datetime


def _query_info(query: dict) -> str:
    """Defensive join of whatever metadata fields the query object has, since
    the exact schema returned by the live API is unconfirmed."""
    parts = []
    query_id = query.get("queryId") or query.get("id")
    if query_id is not None:
        parts.append(f"QueryId: {query_id}")
    for label, field in (
        ("Severity", "severity"),
        ("CWE", "cweId"),
        ("Group", "group"),
        ("Category", "category"),
    ):
        value = query.get(field)
        if value:
            parts.append(f"{label}: {value}")
    return " | ".join(parts)


def diff_to_csv(groups: dict, preset_a_name: str, preset_b_name: str) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Language", "Category", "Query Name", "Query Information"])

    for (language, category), bucket in groups.items():
        for query in bucket["only_a"]:
            info = f"Only in {preset_a_name}"
            details = _query_info(query)
            if details:
                info = f"{info} | {details}"
            writer.writerow([language, category, query.get("name") or query.get("queryName"), info])
        for query in bucket["only_b"]:
            info = f"Only in {preset_b_name}"
            details = _query_info(query)
            if details:
                info = f"{info} | {details}"
            writer.writerow([language, category, query.get("name") or query.get("queryName"), info])

    return buffer.getvalue()


def queries_to_csv(queries: list) -> str:
    """Plain listing (not a diff) of a query set: Language, Category, Query Name."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Language", "Category", "Query Name"])
    for query in queries:
        writer.writerow([query.get("language"), query.get("group"), query.get("name")])
    return buffer.getvalue()


def _sanitize_filename_component(text: str) -> str:
    text = re.sub(r"\s+", "", text)
    text = re.sub(r"[^A-Za-z0-9_-]", "", text)
    return text or "Preset"


def tenant_export_filename(tenant: str, name: str, ext: str = "csv") -> str:
    """Tenant first, today's date last, e.g. ("ps_na_miguel_gonzalez",
    "stale_projects") -> "ps_na_miguel_gonzalez_stale_projects_13_11_2026.csv".
    Kept in step with exportFilename() in static/js/app.js."""
    stamp = datetime.now().strftime("%d_%m_%Y")
    tenant_part = re.sub(r"[^A-Za-z0-9_-]", "", tenant or "") or "tenant"
    return f"{tenant_part}_{name}_{stamp}.{ext}"


def combined_export_filename(tenant: str, preset_name: str) -> str:
    """e.g. "Miguel Premium" -> "<tenant>_MiguelPremiumUpdated_13_11_2026.csv"."""
    return tenant_export_filename(tenant, f"{_sanitize_filename_component(preset_name)}Updated")


def table_to_csv(headers: list[str], rows: list[list]) -> str:
    """Same shape as the in-page Export CSV buttons (buildCsv in app.js)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    writer.writerows(["" if cell is None else cell for cell in row] for row in rows)
    return buffer.getvalue()


def zip_files(files: list[tuple[str, str | bytes]]) -> bytes:
    """(filename, content) pairs -> one zip archive."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files:
            archive.writestr(name, content)
    return buffer.getvalue()
