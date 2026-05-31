"""Alert CRUD use cases."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from domain.exceptions import AlertNotFoundError
from domain.ports.alert_repository import AlertRepository
from domain.ports.prediction_repository import PredictionRepository


class AlertService:
    def __init__(self, alert_repo: AlertRepository, prediction_repo: PredictionRepository):
        self._alert_repo = alert_repo
        self._prediction_repo = prediction_repo

    def list_alerts(
        self, limit: int, offset: int,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> dict:
        alerts, total = self._alert_repo.list_alerts(limit, offset, status, severity)
        return {"total": total, "alerts": alerts}

    def create_alert(self, title: str, description: Optional[str],
                     severity: str, prediction_id: Optional[str],
                     user_id: str, username: str) -> dict:
        alert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        alert_data = {
            "id": alert_id, "title": title, "description": description,
            "severity": severity, "status": "open",
            "prediction_id": prediction_id,
            "created_by": user_id, "created_at": now, "updated_at": now,
        }
        self._alert_repo.create_alert(alert_data)
        return {
            **alert_data,
            "creator_name": username,
        }

    def get_alert(self, alert_id: str) -> dict:
        alert = self._alert_repo.get_alert(alert_id)
        if not alert:
            raise AlertNotFoundError("Alert not found")
        return alert

    def update_alert(self, alert_id: str, updates: dict) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        updates["updated_at"] = now
        result = self._alert_repo.update_alert(alert_id, updates)
        if not result:
            raise AlertNotFoundError("Alert not found")
        return result

    def delete_alert(self, alert_id: str) -> dict:
        if not self._alert_repo.delete_alert(alert_id):
            raise AlertNotFoundError("Alert not found")
        return {"status": "deleted", "id": alert_id}

    def auto_create_from_predictions(self, results: list[dict]) -> int:
        now = datetime.now(timezone.utc).isoformat()
        alerts = []
        for r in results:
            if not r.get("is_attack"):
                continue
            alerts.append({
                "id": str(uuid.uuid4()),
                "title": f"{r['attack_type']} detected",
                "description": (
                    f"Source: {r.get('src_ip') or 'unknown'} → "
                    f"{r.get('dst_ip') or 'unknown'}:{r.get('dst_port') or '?'} | "
                    f"Confidence: {r['confidence'] * 100:.1f}%"
                ),
                "severity": r["severity"],
                "status": "open",
                "prediction_id": r["id"],
                "created_by": "system",
                "created_at": now,
                "updated_at": now,
            })
        if alerts:
            return self._alert_repo.create_alerts_batch(alerts)
        return 0

    def generate_alerts(self, user_id: str) -> dict:
        attacks = self._prediction_repo.get_unalerted_attacks()
        now = datetime.now(timezone.utc).isoformat()
        alerts = []
        for a in attacks:
            alert_data = {
                "id": str(uuid.uuid4()),
                "title": f"{a['attack_type']} detected",
                "description": (
                    f"Source: {a.get('src_ip') or 'unknown'} → "
                    f"{a.get('dst_ip') or 'unknown'}:{a.get('dst_port') or '?'} | "
                    f"Confidence: {a['confidence'] * 100:.1f}%"
                ),
                "severity": a["severity"],
                "status": "open",
                "prediction_id": a["id"],
                "created_by": user_id,
                "created_at": now,
                "updated_at": now,
            }
            alerts.append(alert_data)
        created = self._alert_repo.create_alerts_batch(alerts)
        return {"status": "generated", "created": created}
