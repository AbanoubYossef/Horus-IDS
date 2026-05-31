"""SQLite database init and connection helper."""

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger("horus-api")


# ---------------------------------------------------------------------------
# Schema creation / migration
# ---------------------------------------------------------------------------

def init_db(db_path: Path) -> None:
    """Create all tables, indices, and run column migrations."""
    with sqlite3.connect(db_path) as conn:
        # -- predictions table ------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS predictions (
                id           TEXT PRIMARY KEY,
                attack_type  TEXT NOT NULL,
                confidence   REAL NOT NULL,
                is_attack    INTEGER NOT NULL,
                severity     TEXT NOT NULL,
                src_ip       TEXT,
                dst_ip       TEXT,
                src_port     INTEGER,
                dst_port     INTEGER,
                protocol     INTEGER,
                vlan_id      INTEGER,
                src_vlan     INTEGER,
                dst_vlan     INTEGER,
                model        TEXT,
                inference_ms REAL,
                probabilities TEXT,
                top_features  TEXT,
                group_pred   TEXT,
                ground_truth TEXT,
                created_at   TEXT NOT NULL
            )
        """)

        # Migrations for older schemas
        for col in (
            "vlan_id INTEGER",
            "src_port INTEGER",
            "protocol INTEGER",
            "src_vlan INTEGER",
            "dst_vlan INTEGER",
        ):
            try:
                conn.execute(f"ALTER TABLE predictions ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass  # column already exists

        # Indices
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pred_ts "
            "ON predictions(created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pred_sev "
            "ON predictions(severity)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pred_attack "
            "ON predictions(is_attack, created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pred_sev_ts "
            "ON predictions(severity, created_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pred_type "
            "ON predictions(attack_type)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pred_src "
            "ON predictions(src_ip)"
        )

        # WAL mode
        conn.execute("PRAGMA journal_mode=WAL")

        # -- users table ------------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         TEXT PRIMARY KEY,
                username   TEXT UNIQUE NOT NULL,
                email      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt       TEXT NOT NULL,
                role       TEXT NOT NULL DEFAULT 'analyst',
                created_at TEXT NOT NULL
            )
        """)

        # -- sessions table ---------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                user_id    TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_user "
            "ON sessions(user_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires "
            "ON sessions(expires_at)"
        )

        # -- alerts table -----------------------------------------------------
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id            TEXT PRIMARY KEY,
                title         TEXT NOT NULL,
                description   TEXT,
                severity      TEXT NOT NULL DEFAULT 'medium',
                status        TEXT NOT NULL DEFAULT 'open',
                prediction_id TEXT,
                assigned_to   TEXT,
                created_by    TEXT NOT NULL,
                notes         TEXT,
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                FOREIGN KEY (prediction_id) REFERENCES predictions(id),
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_status "
            "ON alerts(status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_sev "
            "ON alerts(severity)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_ts "
            "ON alerts(created_at DESC)"
        )

    log.info("SQLite ready -- %s", db_path)


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

@contextmanager
def get_db(db_path: Path):
    """Yield a sqlite3 connection with Row factory, WAL mode, auto-commit."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
