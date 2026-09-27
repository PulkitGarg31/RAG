from dataclasses import dataclass, field
from datetime import date, datetime


@dataclass
class Advisory:
    id: str
    package: str
    aliases: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    group_id: str | None = None
    summary: str = ""
    details: str = ""
    cvss_vector: str | None = None
    cvss_score: float | None = None
    cwe_ids: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    affected: list[dict] = field(default_factory=list)
    refs: list[dict] = field(default_factory=list)
    published: datetime | None = None
    modified: datetime | None = None


@dataclass
class Chunk:
    id: str
    advisory_id: str
    kind: str  # summary | details | affected | refs
    header: str
    content: str
    embedding: list[float] | None = None


@dataclass
class KevEntry:
    cve_id: str
    vendor: str | None
    product: str | None
    date_added: date | None
    due_date: date | None
    ransomware: str | None
    notes: str | None = None


@dataclass
class EpssEntry:
    cve_id: str
    epss: float
    percentile: float
    score_date: date


@dataclass
class Finding:
    package: str
    installed: str
    advisory_id: str
    cve_ids: list[str]
    priority: str
    min_safe_version: str | None
    verified: bool
    kev: bool
    epss: float | None
    summary: str = ""
    rationale: str = ""
    citations: list[str] = field(default_factory=list)
    generated_by: str = "llm"  # llm | template
