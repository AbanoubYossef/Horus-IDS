import sqlite3
import pytest
from pathlib import Path
from infrastructure.persistence.database import init_db, get_db

@pytest.fixture
def temp_db(tmp_path):
    db_path = tmp_path / "test_migration.db"
    return db_path

def test_init_db_creates_tables(temp_db):
    init_db(temp_db)
    
    with sqlite3.connect(temp_db) as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        table_names = {t[0] for t in tables}
        
        assert "predictions" in table_names
        assert "users" in table_names
        assert "sessions" in table_names
        assert "alerts" in table_names

def test_migration_adds_new_columns(temp_db):
    # Old schema without the newer columns
    with sqlite3.connect(temp_db) as conn:
        conn.execute('''
            CREATE TABLE predictions (
                id           TEXT PRIMARY KEY,
                attack_type  TEXT NOT NULL,
                confidence   REAL NOT NULL,
                is_attack    INTEGER NOT NULL,
                severity     TEXT NOT NULL,
                src_ip       TEXT,
                dst_ip       TEXT,
                model        TEXT,
                inference_ms REAL,
                probabilities TEXT,
                top_features  TEXT,
                group_pred   TEXT,
                ground_truth TEXT,
                created_at   TEXT NOT NULL
            )
        ''')
    
    # Should migrate
    init_db(temp_db)
    
    # Check new columns exist
    with sqlite3.connect(temp_db) as conn:
        cursor = conn.execute("PRAGMA table_info(predictions)")
        columns = {row[1] for row in cursor.fetchall()}
        
        assert "vlan_id" in columns
        assert "src_port" in columns
        assert "protocol" in columns
        assert "src_vlan" in columns
        assert "dst_vlan" in columns

def test_init_db_idempotent(temp_db):
    # Idempotent
    init_db(temp_db)
    init_db(temp_db)
    init_db(temp_db)
    assert True
