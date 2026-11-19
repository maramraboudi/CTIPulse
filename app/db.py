import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.config import DB_PATH


SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    cvss REAL NOT NULL DEFAULT 0,
    cvss_vector TEXT NOT NULL DEFAULT '',
    epss REAL NOT NULL DEFAULT 0,
    epss_updated_at TEXT,
    in_kev INTEGER NOT NULL DEFAULT 0,
    kev_due_date TEXT,
    kev_date_added TEXT,
    poc_count INTEGER NOT NOT NULL DEFAULT 0,
    risk_score REAL NOT NULL DEFAULT 0,
    priority TEXT NOT NULL DEFAULT 'Low',
    published_at TEXT,
    nvd_updated_at TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS epss_history (
    cve_id TEXT NOT NULL,
    epss REAL NOT NULL,
    percentile REAL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (cve_id, observed_at)
);

CREATE TABLE IF NOT EXISTS poc_references (
    cve_id TEXT NOT NULL,
    repository TEXT NOT NOT NULL,
    html_url TEXT NOT NULL,
    stars INTEGER NOT NULL DEFAULT 0,
    discovered_at TEXT NOT NULL,
    PRIMARY KEY (cve_id, repository)
);

CREATE TABLE IF NOT EXISTS attack_mappings (
    cve_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    manually_reviewed INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (cve_id, technique_id)
);

CREATE TABLE IF NOT EXISTS collection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    records INTEGER NOT NULL DEFAULT 0,
    message TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    minimum_priority TEXT NOT NULL DEFAULT 'High',
    require_kev INTEGER NOT NULL DEFAULT 0,
    require_poc INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_cves_priority ON cves(priority);
CREATE INDEX IF NOT EXISTS idx_cves_risk ON cves(risk_score);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(in_kev);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA.replace("NOT NOT NULL", "NOT NULL"))
    conn.commit()
    conn.close()


@contextmanager
def db_cursor(db_path: Path = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
