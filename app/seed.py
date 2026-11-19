from app.db import db_cursor, init_db
from app.mitre import mappings_for
from app.scoring import calculate_risk, priority_for


DEMO_CVES = [
    ("CVE-2021-44228", "Apache Log4j2 JNDI lookup remote code execution", 10.0, 0.97, 1, [
        ("NCSC UK / evidence", "https://github.com/NCSC-NL/log4shell", 12000),
    ]),
    ("CVE-2021-34527", "Microsoft Windows Print Spooler remote code execution", 8.8, 0.73, 1, [
        ("Cube0x0 / PrintNightmare", "https://github.com/Cube0x0/CVE-2021-34527", 3200),
    ]),
    ("CVE-2023-38831", "RARLAB WinRAR code execution through crafted archives", 7.8, 0.63, 1, [
        ("BoredHackerBlog / CVE-2023-38831", "https://github.com/b1tg/CVE-2023-38831-winrar-exploit", 1800),
    ]),
    ("CVE-2023-34362", "Progress MOVEit Transfer SQL injection", 9.8, 0.41, 1, [
        ("horizon3ai / MOVEit", "https://github.com/horizon3ai/CVE-2023-34362", 900),
    ]),
    ("CVE-2024-3094", "XZ Utils supply-chain backdoor in Linux distributions", 10.0, 0.22, 0, [
        ("example / xz-analysis", "https://github.com/amlweems/xzbot", 450),
    ]),
]


def seed_demo() -> int:
    init_db()
    for cve_id, description, cvss, epss, kev, pocs in DEMO_CVES:
        risk = calculate_risk(cvss, epss, bool(kev), len(pocs))
        with db_cursor() as conn:
            conn.execute(
                """
                INSERT INTO cves(
                    cve_id,title,description,cvss,epss,in_kev,poc_count,risk_score,priority,
                    first_seen_at,last_seen_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    description=excluded.description,cvss=excluded.cvss,epss=excluded.epss,
                    in_kev=excluded.in_kev,poc_count=excluded.poc_count,
                    risk_score=excluded.risk_score,priority=excluded.priority,
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    cve_id, cve_id, description, cvss, epss, kev, len(pocs), risk,
                    priority_for(risk), "2026-11-19T00:00:00+00:00", "2026-11-19T00:00:00+00:00",
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO epss_history(cve_id,epss,percentile,observed_at) VALUES(?,?,?,?)",
                (cve_id, epss, epss, "2026-11-19T00:00:00+00:00"),
            )
            conn.execute("DELETE FROM poc_references WHERE cve_id=?", (cve_id,))
            for repository, url, stars in pocs:
                conn.execute(
                    "INSERT OR REPLACE INTO poc_references(cve_id,repository,html_url,stars,discovered_at) VALUES(?,?,?,?,?)",
                    (cve_id, repository, url, stars, "2026-11-19T00:00:00+00:00"),
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
    return len(DEMO_CVES)


if __name__ == "__main__":
    print(f"Seeded {seed_demo()} demonstration CVEs.")
