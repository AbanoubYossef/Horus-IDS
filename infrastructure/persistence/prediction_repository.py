"""SQLite implementation of ``domain.ports.PredictionRepository``."""

import json
import logging
import math
import sqlite3
from pathlib import Path
from typing import Optional

from domain.ports.prediction_repository import PredictionRepository
from infrastructure.persistence.database import get_db

log = logging.getLogger("horus-api")

_WINDOW_OFFSETS = {
    "1h": "-1 hour",
    "24h": "-24 hours",
    "7d": "-7 days",
    "30d": "-30 days",
}

_INSERT_SQL = """\
INSERT INTO predictions
    (id, attack_type, confidence, is_attack, severity,
     src_ip, dst_ip, src_port, dst_port, protocol, vlan_id,
     src_vlan, dst_vlan, model, inference_ms,
     probabilities, top_features, group_pred, ground_truth, created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


def _sanitize_floats(obj):
    """Replace NaN/Inf with 0.0 so JSON serialization never fails."""
    if isinstance(obj, float) and not math.isfinite(obj):
        return 0.0
    if isinstance(obj, dict):
        return {k: _sanitize_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_floats(v) for v in obj]
    return obj


def _result_to_row(r: dict) -> tuple:
    """Convert a prediction result dict into a positional tuple for INSERT."""
    return (
        r["id"],
        r["attack_type"],
        r["confidence"],
        int(r["is_attack"]),
        r["severity"],
        r.get("src_ip"),
        r.get("dst_ip"),
        r.get("src_port"),
        r.get("dst_port"),
        r.get("protocol"),
        r.get("vlan_id"),
        r.get("src_vlan"),
        r.get("dst_vlan"),
        r["model"],
        r["inference_ms"],
        json.dumps(r.get("probabilities", {})),
        json.dumps(r.get("top_features", [])),
        r.get("group_pred"),
        r.get("ground_truth"),
        r["created_at"],
    )


class SqlitePredictionRepository(PredictionRepository):
    """Concrete prediction repository backed by SQLite."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save(self, result: dict) -> None:
        """Insert a single prediction."""
        with get_db(self._db_path) as conn:
            conn.execute(_INSERT_SQL, _result_to_row(result))

    def save_many(self, results: list[dict]) -> None:
        """Bulk-insert predictions."""
        with get_db(self._db_path) as conn:
            conn.executemany(
                _INSERT_SQL,
                [_result_to_row(r) for r in results],
            )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_paginated(
        self,
        limit: int,
        offset: int,
        severity: Optional[str] = None,
        attack_only: bool = False,
    ) -> tuple[list[dict], int]:
        """Return ``(results, total)`` with optional filtering."""
        where: list[str] = []
        params: list = []

        if severity:
            where.append("severity = ?")
            params.append(severity)
        if attack_only:
            where.append("is_attack = 1")

        wc = (" WHERE " + " AND ".join(where)) if where else ""

        with get_db(self._db_path) as conn:
            rows = conn.execute(
                f"SELECT * FROM predictions{wc} "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()

            total = conn.execute(
                f"SELECT COUNT(*) FROM predictions{wc}", params
            ).fetchone()[0]

        results = []
        for row in rows:
            r = dict(row)
            r["probabilities"] = _sanitize_floats(
                json.loads(r["probabilities"]) if r["probabilities"] else {}
            )
            r["top_features"] = _sanitize_floats(
                json.loads(r["top_features"]) if r["top_features"] else []
            )
            r["is_attack"] = bool(r["is_attack"])
            results.append(r)

        return results, total

    def get_stats(self, window: Optional[str] = None) -> dict:
        """Aggregate statistics, optionally constrained to a time window."""
        where, params = "", []
        if window and window in _WINDOW_OFFSETS:
            where = " WHERE created_at >= datetime('now', ?)"
            params = [_WINDOW_OFFSETS[window]]

        atk_where = where + (" AND " if where else " WHERE ") + "is_attack=1"
        atk_params = params[:]

        with get_db(self._db_path) as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM predictions{where}", params
            ).fetchone()[0]
            attacks = conn.execute(
                f"SELECT COUNT(*) FROM predictions{atk_where}", atk_params
            ).fetchone()[0]
            avg_conf = (
                conn.execute(
                    f"SELECT AVG(confidence) FROM predictions{where}", params
                ).fetchone()[0]
                or 0
            )
            avg_ms = (
                conn.execute(
                    f"SELECT AVG(inference_ms) FROM predictions{where}", params
                ).fetchone()[0]
                or 0
            )

            by_severity = {
                r[0]: r[1]
                for r in conn.execute(
                    f"SELECT severity, COUNT(*) FROM predictions{where} "
                    "GROUP BY severity",
                    params,
                ).fetchall()
            }
            by_attack_type = {
                r[0]: r[1]
                for r in conn.execute(
                    f"SELECT attack_type, COUNT(*) FROM predictions{where} "
                    "GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 15",
                    params,
                ).fetchall()
            }

            recent = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, attack_type, confidence, severity, src_ip, "
                    "dst_ip, created_at, is_attack, group_pred "
                    "FROM predictions ORDER BY created_at DESC LIMIT 10"
                ).fetchall()
            ]

        return {
            "window": window or "all",
            "total_predictions": total,
            "total_attacks": attacks,
            "total_benign": total - attacks,
            "avg_confidence": round(avg_conf, 4),
            "avg_inference_ms": round(avg_ms, 3),
            "by_severity": by_severity,
            "by_attack_type": by_attack_type,
            "recent": recent,
        }

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def clear_all(self) -> None:
        """Delete every prediction row."""
        with get_db(self._db_path) as conn:
            conn.execute("DELETE FROM predictions")

    def retain(self, days: int) -> int:
        """Delete predictions older than *days* days and VACUUM.

        Returns the number of deleted rows.
        """
        with get_db(self._db_path) as conn:
            deleted = conn.execute(
                "DELETE FROM predictions WHERE created_at < datetime('now', ?)",
                [f"-{days} days"],
            ).rowcount

        # VACUUM needs its own connection
        try:
            vconn = sqlite3.connect(self._db_path)
            vconn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            vconn.execute("VACUUM")
            vconn.close()
        except sqlite3.OperationalError as exc:
            log.warning("VACUUM failed (non-critical): %s", exc)

        return deleted

    def get_db_stats(self) -> dict:
        """Database health: row count, file size, page stats."""
        with get_db(self._db_path) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM predictions"
            ).fetchone()[0]
            oldest = conn.execute(
                "SELECT MIN(created_at) FROM predictions"
            ).fetchone()[0]
            newest = conn.execute(
                "SELECT MAX(created_at) FROM predictions"
            ).fetchone()[0]
            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            journal = conn.execute("PRAGMA journal_mode").fetchone()[0]

        db_size_bytes = (
            self._db_path.stat().st_size if self._db_path.exists() else 0
        )

        return {
            "total_rows": total,
            "oldest_record": oldest,
            "newest_record": newest,
            "db_size_bytes": db_size_bytes,
            "db_size_mb": round(db_size_bytes / 1_048_576, 2),
            "page_count": page_count,
            "page_size": page_size,
            "journal_mode": journal,
        }

    def get_unalerted_attacks(self) -> list[dict]:
        """Return attack predictions that are not yet linked to any alert."""
        with get_db(self._db_path) as conn:
            rows = conn.execute(
                """SELECT p.id, p.attack_type, p.severity, p.confidence,
                          p.src_ip, p.dst_ip, p.dst_port, p.created_at
                   FROM predictions p
                   WHERE p.is_attack = 1
                     AND p.id NOT IN (
                         SELECT prediction_id FROM alerts
                         WHERE prediction_id IS NOT NULL
                     )
                   ORDER BY p.created_at DESC"""
            ).fetchall()

        return [dict(r) for r in rows]
