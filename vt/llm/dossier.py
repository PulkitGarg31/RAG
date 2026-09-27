from vt.models import Advisory, Chunk, Finding, KevEntry


def epss_evidence_id(finding: Finding) -> str | None:
    if finding.epss is None or finding.epss_cve is None:
        return None
    return f"EPSS:{finding.epss_cve}"


def evidence_ids(finding: Finding, advisory: Advisory, kev_entry: KevEntry | None, chunks: list[Chunk]) -> set[str]:
    """Exactly the ids build_dossier() prints in square brackets."""
    ids = {"FACT:pkg", "FACT:prio", advisory.id}
    if kev_entry is not None:
        ids.add(f"KEV:{kev_entry.cve_id}")
    epss_id = epss_evidence_id(finding)
    if epss_id is not None:
        ids.add(epss_id)
    ids.update(c.id for c in chunks)
    return ids


def build_dossier(finding: Finding, advisory: Advisory, kev_entry: KevEntry | None, chunks: list[Chunk]) -> str:
    lines = ["EVIDENCE (cite ids exactly as written in square brackets)"]

    verified_str = "true" if finding.verified else "false"
    lines.append(
        f"[FACT:pkg] package={finding.package} installed={finding.installed} "
        f"min_safe_version={finding.min_safe_version} (verified={verified_str})"
    )
    lines.append(f"[FACT:prio] priority={finding.priority}")

    cve_str = ", ".join(advisory.cve_ids) or "no known CVE"
    lines.append(f"[{advisory.id}] advisory id; CVEs: {cve_str}")

    if kev_entry is not None:
        lines.append(
            f"[KEV:{kev_entry.cve_id}] dateAdded={kev_entry.date_added}, ransomware={kev_entry.ransomware}"
        )

    epss_id = epss_evidence_id(finding)
    if epss_id is not None:
        pct = finding.epss_percentile if finding.epss_percentile is not None else "unknown"
        lines.append(f"[{epss_id}] epss={finding.epss} percentile={pct}")

    for chunk in chunks:
        lines.append(f"[{chunk.id}] {chunk.content}")

    return "\n".join(lines)
