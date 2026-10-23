"""Grouping/diff logic for comparing two presets' query selections.

Queries are grouped by (language, category) to mirror how the Checkmarx One
preset editor organizes queries, then split into "only in A" / "only in B" /
"common" within each group.

Both functions here take already-normalized flat query lists (see
db.normalize_preset_queries), not raw preset dicts -- the raw API shape
groups queries by family with bare ids, and resolving those against the
query catalog is a data-layer concern, kept out of this pure logic module.
"""
from __future__ import annotations


def _query_key(query: dict):
    query_id = query.get("queryId") or query.get("id")
    if query_id is not None:
        return ("id", query_id)
    return (
        "path",
        query.get("language", "Unknown"),
        query.get("group") or query.get("category") or "Uncategorized",
        query.get("name") or query.get("queryName") or "Unnamed query",
    )


def _group_key(query: dict):
    return (
        query.get("language", "Unknown"),
        query.get("group") or query.get("category") or "Uncategorized",
    )


def _query_label(query: dict) -> str:
    return query.get("name") or query.get("queryName") or "Unnamed query"


def compare_presets(queries_a: list, queries_b: list) -> dict:
    """Returns:
    {
        (language, category): {
            "only_a": [query, ...],
            "only_b": [query, ...],
            "common": [query, ...],
        },
        ...
    } sorted by (language, category), with queries sorted by name within each bucket.
    """
    by_key_a = {_query_key(q): q for q in queries_a}
    by_key_b = {_query_key(q): q for q in queries_b}

    all_keys = set(by_key_a) | set(by_key_b)

    groups: dict = {}
    for key in all_keys:
        query = by_key_a.get(key) or by_key_b.get(key)
        group_key = _group_key(query)
        bucket = groups.setdefault(group_key, {"only_a": [], "only_b": [], "common": []})

        in_a = key in by_key_a
        in_b = key in by_key_b
        if in_a and in_b:
            bucket["common"].append(by_key_a[key])
        elif in_a:
            bucket["only_a"].append(by_key_a[key])
        else:
            bucket["only_b"].append(by_key_b[key])

    for bucket in groups.values():
        for name in ("only_a", "only_b", "common"):
            bucket[name].sort(key=_query_label)

    return dict(sorted(groups.items(), key=lambda item: item[0]))


def has_differences(groups: dict) -> bool:
    return any(bucket["only_a"] or bucket["only_b"] for bucket in groups.values())


def group_single_preset(queries: list) -> dict:
    """language -> category -> sorted list of query names, for the preset
    detail side panel."""
    groups: dict[str, dict[str, list]] = {}
    for query in queries:
        language = query.get("language", "Unknown")
        category = query.get("group") or query.get("category") or "Uncategorized"
        name = _query_label(query)
        groups.setdefault(language, {}).setdefault(category, []).append(name)

    ordered: dict[str, dict[str, list]] = {}
    for language in sorted(groups):
        ordered[language] = {
            category: sorted(names) for category, names in sorted(groups[language].items())
        }
    return ordered
