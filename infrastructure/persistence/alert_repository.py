"""SQLite implementation of ``domain.ports.AlertRepository``."""

from pathlib import Path
from typing import Optional

from domain.ports.alert_repository import AlertRepository
from infrastructure.persistence.database import get_db


class SqliteAlertRepository(AlertRepository):
    """Concrete alert repository backed by SQLite."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    # ------------------------------------------------------------------
    # List / Read
    # ------------------------------------------------------------------

    def list_alerts(
        self,
        limit: int,
        offset: int,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> tuple[list[dict], int]:
        """Return (alerts, total) with optional filtering."""
        where: list[str] = []
        params: list = []

        if status:
            where.append("a.status = ?")
            params.append(status)
        if severity:
            where.append("a.severity = ?")
            params.append(severity)

        wc = (" WHERE " + " AND ".join(where)) if where else ""

        with get_db(self._db_path) as conn:
            rows = conn.execute(
                f"SELECT a.*, u.username AS creator_name "
                f"FROM alerts a LEFT JOIN users u ON a.created_by = u.id"
                f"{wc} ORDER BY a.created_at DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()

            total = conn.execute(
                f"SELECT COUNT(*) FROM alerts a{wc}", params
            ).fetchone()[0]

        return [dict(r) for r in rows], total

    def get_alert(self, alert_id: str) -> Optional[dict]:
        """Fetch a single alert by its id (includes ``creator_name``)."""
        with get_db(self._db_path) as conn:
            row = conn.execute(
                "SELECT a.*, u.username AS creator_name "
                "FROM alerts a LEFT JOIN users u ON a.created_by = u.id "
                "WHERE a.id = ?",
                (alert_id,),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def create_alert(self, alert_data: dict) -> None:
        """Insert a new alert."""
        with get_db(self._db_path) as conn:
            conn.execute(
                "INSERT INTO alerts "
                "(id, title, description, severity, status, prediction_id, "
                "created_by, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    alert_data["id"],
                    alert_data["title"],
                    alert_data.get("description"),
                    alert_data["severity"],
                    alert_data["status"],
                    alert_data.get("prediction_id"),
                    alert_data["created_by"],
                    alert_data["created_at"],
                    alert_data["updated_at"],
                ),
            )

    def update_alert(
        self, alert_id: str, updates: dict
    ) -> Optional[dict]:
        """Apply updates, return updated alert or None."""
        with get_db(self._db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if not existing:
                return None

            set_clauses: list[str] = []
            params: list = []
            for key, value in updates.items():
                set_clauses.append(f"{key} = ?")
                params.append(value)

            params.append(alert_id)
            conn.execute(
                f"UPDATE alerts SET {', '.join(set_clauses)} WHERE id = ?",
                params,
            )

            row = conn.execute(
                "SELECT a.*, u.username AS creator_name "
                "FROM alerts a LEFT JOIN users u ON a.created_by = u.id "
                "WHERE a.id = ?",
                (alert_id,),
            ).fetchone()

        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_alert(self, alert_id: str) -> bool:
        """Delete an alert by id.  Returns ``True`` if a row was removed."""
        with get_db(self._db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if not existing:
                return False
            conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
        return True

    # ------------------------------------------------------------------
    # Batch
    # ------------------------------------------------------------------

    def create_alerts_batch(self, alerts: list[dict]) -> int:
        """Bulk-insert alerts.  Returns the number of rows created."""
        if not alerts:
            return 0

        with get_db(self._db_path) as conn:
            conn.executemany(
                "INSERT INTO alerts "
                "(id, title, description, severity, status, prediction_id, "
                "created_by, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                [
                    (
                        a["id"],
                        a["title"],
                        a.get("description"),
                        a["severity"],
                        a["status"],
                        a.get("prediction_id"),
                        a["created_by"],
                        a["created_at"],
                        a["updated_at"],
                    )
                    for a in alerts
                ],
            )

        return len(alerts)
