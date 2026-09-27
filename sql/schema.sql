CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY,
    aliases TEXT[] NOT NULL DEFAULT '{}',
    cve_ids TEXT[] NOT NULL DEFAULT '{}',
    package TEXT NOT NULL,
    group_id TEXT,
    summary TEXT,
    details TEXT,
    cvss_vector TEXT,
    cvss_score REAL,
    cwe_ids TEXT[] NOT NULL DEFAULT '{}',
    fixed_versions TEXT[] NOT NULL DEFAULT '{}',
    affected JSONB,
    refs JSONB,
    published TIMESTAMPTZ,
    modified TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS advisories_package_idx ON advisories (package);
CREATE INDEX IF NOT EXISTS advisories_cve_ids_idx ON advisories USING GIN (cve_ids);
CREATE INDEX IF NOT EXISTS advisories_aliases_idx ON advisories USING GIN (aliases);

CREATE TABLE IF NOT EXISTS chunks (
    id TEXT PRIMARY KEY,
    advisory_id TEXT REFERENCES advisories(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    header TEXT NOT NULL,
    content TEXT NOT NULL,
    embedding vector(384)
);
CREATE INDEX IF NOT EXISTS chunks_embedding_idx ON chunks USING hnsw (embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS kev (
    cve_id TEXT PRIMARY KEY,
    vendor TEXT,
    product TEXT,
    date_added DATE,
    due_date DATE,
    ransomware TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS epss (
    cve_id TEXT PRIMARY KEY,
    epss REAL,
    percentile REAL,
    score_date DATE,
    fetched_at TIMESTAMPTZ DEFAULT now()
);
