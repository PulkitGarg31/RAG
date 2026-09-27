from typing import Callable

from vt.db import get_conn
from vt.ingest.epss import epss_for
from vt.models import Advisory, Finding
from vt.scanner.osv_client import query_batch
from vt.scanner.priority import compute_priority
from vt.scanner.requirements import parse_requirements
from vt.scanner.versions import min_safe_version

_PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def build_findings(
    parsed: list[tuple[str, str]],
    advisories_by_pkg: dict[str, list[Advisory]],
    kev_cves: set[str],
    epss_lookup: dict[str, tuple[float, float]],  # cve_id -> (epss, percentile)
    verify_fn: Callable[[str, str], bool],
) -> list[Finding]:
    findings: list[Finding] = []
    for package, installed in parsed:
        advisories = advisories_by_pkg.get(package, [])
        if not advisories:
            continue

        for adv in advisories:
            safe_version = min_safe_version(installed, [adv])
            verified = verify_fn(package, safe_version) if safe_version else False

            in_kev = any(cve in kev_cves for cve in adv.cve_ids)
            epss_scores = [epss_lookup[c] for c in adv.cve_ids if c in epss_lookup]
            best_epss = max((e for e, _ in epss_scores), default=None)
            best_percentile = max((p for _, p in epss_scores), default=None)

            priority = compute_priority(
                cvss_score=adv.cvss_score, epss=best_epss, epss_percentile=best_percentile, in_kev=in_kev
            )

            findings.append(
                Finding(
                    package=package, installed=installed, advisory_id=adv.id, cve_ids=adv.cve_ids,
                    priority=priority, min_safe_version=safe_version, verified=verified,
                    kev=in_kev, epss=best_epss, generated_by="template",
                )
            )

    findings.sort(key=lambda f: (_PRIORITY_ORDER[f.priority], -(f.epss or 0)))
    return findings


def scan_requirements_text(text: str) -> tuple[list[Finding], list[dict]]:
    """Full pipeline: parse -> OSV querybatch -> load advisories -> build_findings.
    Returns (findings, skipped) where skipped is [{"package": ..., "reason": ...}, ...].
    """
    parsed_lines = parse_requirements(text)
    skipped = [
        {"package": p.package, "reason": p.skipped_reason}
        for p in parsed_lines if p.skipped_reason is not None
    ]
    pinned = [(p.package, p.version) for p in parsed_lines if p.skipped_reason is None]
    if not pinned:
        return [], skipped

    vuln_id_lists = query_batch(pinned)

    with get_conn() as conn:
        all_ids = sorted({vid for ids in vuln_id_lists for vid in ids if vid})
        advisories_by_id: dict[str, Advisory] = {}
        if all_ids:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, package, cve_ids, fixed_versions, cvss_score FROM advisories WHERE id = ANY(%s)",
                    (all_ids,),
                )
                for row in cur.fetchall():
                    advisories_by_id[row[0]] = Advisory(
                        id=row[0], package=row[1], cve_ids=row[2], fixed_versions=row[3], cvss_score=row[4]
                    )

        # Attribute advisories to packages using OSV's own per-package querybatch mapping,
        # not the DB row's stored `package` field -- an advisory affecting multiple PyPI
        # packages is stored under only one of them at ingest time, so re-deriving
        # attribution from the DB row can mis-assign or drop findings for the others.
        advisories_by_pkg: dict[str, list[Advisory]] = {}
        for (package, _version), vuln_ids in zip(pinned, vuln_id_lists):
            for vid in vuln_ids:
                adv = advisories_by_id.get(vid)
                if adv is not None:
                    advisories_by_pkg.setdefault(package, []).append(adv)

        all_cves = sorted({c for advs in advisories_by_pkg.values() for a in advs for c in a.cve_ids})
        with conn.cursor() as cur:
            cur.execute("SELECT cve_id FROM kev WHERE cve_id = ANY(%s)", (all_cves,))
            kev_cves = {r[0] for r in cur.fetchall()}

        epss_entries = epss_for(conn, all_cves)
        epss_lookup = {cve: (e.epss, e.percentile) for cve, e in epss_entries.items()}

        # Batch-verify every distinct (package, candidate min_safe_version) pair in ONE
        # querybatch call instead of one network round-trip per (package, advisory) pair.
        to_verify: set[tuple[str, str]] = set()
        for package, installed in pinned:
            for adv in advisories_by_pkg.get(package, []):
                sv = min_safe_version(installed, [adv])
                if sv is not None:
                    to_verify.add((package, sv))

        verified_lookup: dict[tuple[str, str], bool] = {}
        if to_verify:
            to_verify_list = sorted(to_verify)
            verify_results = query_batch(to_verify_list)
            for (package, sv), results in zip(to_verify_list, verify_results):
                verified_lookup[(package, sv)] = len(results) == 0

        def verify_fn(package: str, version: str) -> bool:
            return verified_lookup.get((package, version), False)

        findings = build_findings(pinned, advisories_by_pkg, kev_cves, epss_lookup, verify_fn)

    return findings, skipped
