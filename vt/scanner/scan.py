from dataclasses import replace
from typing import Callable

from vt.db import get_conn
from vt.ingest.epss import epss_for
from vt.ingest.osv import fixed_versions_for_package, parse_osv_record, upsert_advisories
from vt.models import Advisory, Finding
from vt.retrieval.aliases import build_alias_groups
from vt.scanner.osv_client import fetch_vulns, query_batch
from vt.scanner.priority import compute_priority
from vt.scanner.requirements import parse_requirements
from vt.scanner.versions import min_safe_version

_PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
_ADVISORY_COLUMNS = "id, package, aliases, cve_ids, group_id, affected, fixed_versions, cvss_score"


def _row_to_advisory(row) -> Advisory:
    return Advisory(
        id=row[0], package=row[1], aliases=row[2] or [], cve_ids=row[3] or [], group_id=row[4],
        affected=row[5] or [], fixed_versions=row[6] or [], cvss_score=row[7],
    )


def _member_fixes(adv: Advisory, package: str) -> list[str]:
    """This member's own fix versions for `package`, never from other packages in its record."""
    return fixed_versions_for_package(adv.affected, package) if adv.affected else adv.fixed_versions


def merge_alias_group(members: list[Advisory], package: str, installed: str) -> Advisory:
    """Collapse records for one vulnerability (e.g. a GHSA and its PYSEC mirror) into one,
    keeping the most informative record's id and merging CVEs, aliases and CVSS.

    Mirrors can disagree about which version fixes the same vulnerability: a GHSA record may say
    8.1.2 while its PYSEC mirror says 8.1.1, and OSV's own querybatch still lists that GHSA id as
    affecting 8.1.1 -- a version only one mirror calls fixed is still affected according to the
    other. So the merged fix version must be one every mirror that HAS fix information agrees is
    fixed, not the union of everyone's fixes (which lets the smallest, least-informed one win).
    `min_safe_version` already computes exactly that ("smallest version above installed that fixes
    every advisory given"), so we hand it one pseudo-advisory per member that has fix data.
    Members with no fix information for this package give no evidence either way and are ignored,
    not treated as vetoing the fix."""
    rep = min(members, key=lambda a: (a.cvss_score is None, not a.id.startswith("GHSA-"), a.id))
    all_ids = {x for a in members for x in (a.id, *a.aliases)}
    with_fixes = [replace(a, fixed_versions=fixes) for a in members if (fixes := _member_fixes(a, package))]
    safe = min_safe_version(installed, with_fixes) if with_fixes else None
    scores = [a.cvss_score for a in members if a.cvss_score is not None]
    return replace(
        rep,
        aliases=sorted(all_ids - {rep.id}),
        cve_ids=sorted({c for a in members for c in a.cve_ids}),
        fixed_versions=[safe] if safe else [],
        cvss_score=max(scores) if scores else None,
        group_id=min(all_ids),
    )


def attribute_advisories(
    pinned: list[tuple[str, str]],
    vuln_id_lists: list[list[str]],
    advisories_by_id: dict[str, Advisory],
) -> dict[tuple[str, str], list[Advisory]]:
    """Advisories per pinned (package, version), taken from OSV's own querybatch answer for that
    exact pin, with alias mirrors merged into one advisory per vulnerability."""
    result: dict[tuple[str, str], list[Advisory]] = {}
    for (package, version), vuln_ids in zip(pinned, vuln_id_lists):
        advs = [advisories_by_id[v] for v in vuln_ids if v in advisories_by_id]
        groups = build_alias_groups(advs)
        by_group: dict[str, list[Advisory]] = {}
        for adv in advs:
            by_group.setdefault(groups[adv.id], []).append(adv)
        result[(package, version)] = [merge_alias_group(m, package, version) for m in by_group.values()]
    return result


def advisory_fixed_at(adv: Advisory, vulns_at_version: list[str]) -> bool:
    """True when OSV no longer lists this advisory, under any of its ids, at that version."""
    return not ({adv.id, *adv.aliases} & set(vulns_at_version))


def fetch_missing_advisories(vuln_ids: list[str], fetch=fetch_vulns) -> tuple[list[Advisory], dict[str, str]]:
    """Fetch advisories OSV reported but the local corpus lacks.
    Returns (parsed advisories, {vuln_id: reason} for ids that couldn't be used)."""
    records = fetch(vuln_ids)
    advisories: list[Advisory] = []
    unresolved: dict[str, str] = {}
    for vid in vuln_ids:
        record = records.get(vid)
        if record is None:
            unresolved[vid] = "could not be fetched from OSV"
            continue
        adv = parse_osv_record(record)
        if adv is None:
            unresolved[vid] = "withdrawn or not a PyPI advisory"
            continue
        advisories.append(adv)
    return advisories, unresolved


def _best_epss(cve_ids: list[str], epss_lookup: dict[str, tuple[float, float]]):
    """(cve, epss, percentile) of the advisory's highest-EPSS CVE, or (None, None, None)."""
    scored = [(epss_lookup[c][0], epss_lookup[c][1], c) for c in cve_ids if c in epss_lookup]
    if not scored:
        return None, None, None
    epss, pct, cve = max(scored)
    return cve, epss, pct


def build_findings(
    pinned: list[tuple[str, str]],
    advisories_by_pin: dict[tuple[str, str], list[Advisory]],
    kev_cves: set[str],
    epss_lookup: dict[str, tuple[float, float]],  # cve_id -> (epss, percentile)
    verify_fn: Callable[[str, str, Advisory], bool],
) -> list[Finding]:
    findings: list[Finding] = []
    for package, installed in pinned:
        for adv in advisories_by_pin.get((package, installed), []):
            safe_version = min_safe_version(installed, [adv])
            verified = verify_fn(package, safe_version, adv) if safe_version else False
            in_kev = any(cve in kev_cves for cve in adv.cve_ids)
            epss_cve, epss, epss_pct = _best_epss(adv.cve_ids, epss_lookup)
            priority = compute_priority(
                cvss_score=adv.cvss_score, epss=epss, epss_percentile=epss_pct, in_kev=in_kev
            )
            findings.append(
                Finding(
                    package=package, installed=installed, advisory_id=adv.id, cve_ids=adv.cve_ids,
                    priority=priority, min_safe_version=safe_version, verified=verified,
                    kev=in_kev, epss=epss, epss_cve=epss_cve, epss_percentile=epss_pct,
                    aliases=adv.aliases, generated_by="template",
                )
            )

    findings.sort(key=lambda f: (_PRIORITY_ORDER[f.priority], -(f.epss or 0)))
    return findings


def scan_requirements_text(text: str) -> tuple[list[Finding], list[dict]]:
    """Full pipeline: parse -> OSV querybatch -> load/fetch advisories -> build_findings.
    Returns (findings, skipped) where skipped is [{"package": ..., "reason": ...}, ...].
    """
    parsed_lines = parse_requirements(text)
    skipped = [
        {"package": p.package, "reason": p.skipped_reason}
        for p in parsed_lines if p.skipped_reason is not None
    ]
    # Distinct pins in file order; the same package may legitimately appear at two versions.
    pinned = list(dict.fromkeys((p.package, p.version) for p in parsed_lines if p.skipped_reason is None))
    if not pinned:
        return [], skipped

    vuln_id_lists = query_batch(pinned)
    all_ids = sorted({vid for ids in vuln_id_lists for vid in ids if vid})

    with get_conn() as conn:
        advisories_by_id: dict[str, Advisory] = {}
        if all_ids:
            with conn.cursor() as cur:
                cur.execute(f"SELECT {_ADVISORY_COLUMNS} FROM advisories WHERE id = ANY(%s)", (all_ids,))
                advisories_by_id = {row[0]: _row_to_advisory(row) for row in cur.fetchall()}

        # The local corpus may be a subset of OSV (e.g. `vt ingest osv --limit`): fetch what's
        # missing instead of silently reporting those packages as clean, and cache it locally.
        missing = [vid for vid in all_ids if vid not in advisories_by_id]
        if missing:
            fetched, unresolved = fetch_missing_advisories(missing, fetch=fetch_vulns)
            if fetched:
                upsert_advisories(conn, fetched)
                advisories_by_id.update({a.id: a for a in fetched})
            for (package, _version), vuln_ids in zip(pinned, vuln_id_lists):
                for vid in vuln_ids:
                    if vid in unresolved:
                        skipped.append({"package": package, "reason": f"{vid}: {unresolved[vid]}"})

        advisories_by_pin = attribute_advisories(pinned, vuln_id_lists, advisories_by_id)

        all_cves = sorted({c for advs in advisories_by_pin.values() for a in advs for c in a.cve_ids})
        kev_cves: set[str] = set()
        if all_cves:
            with conn.cursor() as cur:
                cur.execute("SELECT cve_id FROM kev WHERE cve_id = ANY(%s)", (all_cves,))
                kev_cves = {r[0] for r in cur.fetchall()}

        epss_lookup = {cve: (e.epss, e.percentile) for cve, e in epss_for(conn, all_cves).items()}

        # Verify every suggested upgrade in one querybatch call. A fix is verified when OSV no
        # longer lists *this* advisory (under any alias id) at that version; unrelated
        # advisories still open at the same version don't count against it.
        to_verify = sorted({
            (package, sv)
            for (package, installed), advs in advisories_by_pin.items()
            for adv in advs
            if (sv := min_safe_version(installed, [adv])) is not None
        })
        vulns_at = dict(zip(to_verify, query_batch(to_verify))) if to_verify else {}

        def verify_fn(package: str, version: str, adv: Advisory) -> bool:
            remaining = vulns_at.get((package, version))
            return remaining is not None and advisory_fixed_at(adv, remaining)

        findings = build_findings(pinned, advisories_by_pin, kev_cves, epss_lookup, verify_fn)

    return findings, skipped
