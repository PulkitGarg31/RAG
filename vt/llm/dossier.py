from vt.models import Advisory, Chunk, Finding, KevEntry


def build_dossier(
    finding: Finding,
    advisory: Advisory,
    kev_entry: KevEntry | None,
    epss_percentile: float | None,
    chunks: list[Chunk],
) -> str:
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

    if finding.epss is not None:
        pct = epss_percentile if epss_percentile is not None else "unknown"
        cve_for_epss = advisory.cve_ids[0] if advisory.cve_ids else advisory.id
        lines.append(f"[EPSS:{cve_for_epss}] epss={finding.epss} percentile={pct}")

    for chunk in chunks:
        lines.append(f"[{chunk.id}] {chunk.content}")

    return "\n".join(lines)
