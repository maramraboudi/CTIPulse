from app.db import init_db
from app.seed import seed_demo


import sqlite3

from app.db import init_db


def test_seed_schema(tmp_path) -> None:
    db_path = tmp_path / "test.db"
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    conn.close()
    assert {"cves", "epss_history", "poc_references", "attack_mappings"} <= tables
