from datetime import datetime, timezone
import time

from app.collectors import fetch_epss, fetch_kev, fetch_nvd, find_pocs, utc_now
from app.db import db_cursor, init_db
from app.mitre import mappings_for
from app.scoring import calculate_risk, priority_for


DEFAULT_CVES = [
    "CVE-2021-44228",
    "CVE-2021-34527",
    "CVE-2023-38831",
    "CVE-2023-34362",
]


def add_run(source: str, status: str, records: int = 0, message: str = "") -> None:
    now = utc_now()
    with db_cursor() as conn:
        conn.execute(
            "INSERT INTO collection_runs(source,started_at,finished_at,status,records,message) VALUES(?,?,?,?,?,?)",
            (source, now, now, status, records, message),
        )


def collect(cve_ids: list[str] | None = None, github: bool = True) -> dict:
    init_db()
    ids = cve_ids or DEFAULT_CVES
    now = utc_now()
    kev = fetch_kev()
    epss = fetch_epss(ids)
    collected = 0

    for cve_id in ids:
        nvd = fetch_nvd(cve_id)
        if not nvd:
            continue
        kev_record = kev.get(cve_id)
        epss_record = epss.get(cve_id, {"epss": 0, "percentile": 0})
        poc_refs = find_pocs(cve_id) if github else []
        risk = calculate_risk(
            nvd["cvss"],
            epss_record["epss"],
            kev_record is not None,
            len(poc_refs),
        )

        with db_cursor() as conn:
            conn.execute(
                """
                INSERT INTO cves(
                    cve_id,title,description,cvss,cvss_vector,epss,epss_updated_at,
                    in_kev,kev_due_date,kev_date_added,poc_count,risk_score,priority,
                    published_at,nvd_updated_at,first_seen_at,last_seen_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    description=excluded.description, cvss=excluded.cvss,
                    cvss_vector=excluded.cvss_vector, epss=excluded.epss,
                    epss_updated_at=excluded.epss_updated_at,
                    in_kev=excluded.in_kev, kev_due_date=excluded.kev_due_date,
                    kev_date_added=excluded.kev_date_added, poc_count=excluded.poc_count,
                    risk_score=excluded.risk_score, priority=excluded.priority,
                    published_at=excluded.published_at, nvd_updated_at=excluded.nvd_updated_at,
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    cve_id, cve_id, nvd["description"], nvd["cvss"], nvd["cvss_vector"],
                    epss_record["epss"], now, int(kev_record is not None),
                    kev_record["due_date"] if kev_record else "", kev_record["date_added"] if kev_record else "",
                    len(poc_refs), risk, priority_for(risk), nvd["published_at"],
                    nvd["nvd_updated_at"], now, now,
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO epss_history(cve_id,epss,percentile,observed_at) VALUES(?,?,?,?)",
                (cve_id, epss_record["epss"], epss_record["percentile"], now),
            )
            conn.execute("DELETE FROM poc_references WHERE cve_id=?", (cve_id,))
            for poc in poc_refs:
                conn.execute(
                    "INSERT OR REPLACE INTO poc_references(cve_id,repository,html_url,stars,discovered_at) VALUES(?,?,?,?,?)",
                    (cve_id, poc["repository"], poc["html_url"], poc["stars"], now),
                )
            conn.execute("DELETE FROM attack_mappings WHERE cve_id=?", (cve_id,))
            for mapping in mappings_for(cve_id):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO attack_mappings(
                        cve_id,technique_id,technique_name,tactic,evidence,source,confidence,manually_reviewed
                    ) VALUES(?,?,?,?,?,?,?,1)
                    """,
                    (
                        cve_id, mapping["technique_id"], mapping["technique_name"],
                        mapping["tactic"], mapping["evidence"], "CTI-Pulse curated mapping",
                        mapping["confidence"],
                    ),
                )
        collected += 1
        time.sleep(0.2)

    add_run("pipeline", "success", collected)
    return {"collected": collected, "requested": len(ids)}
