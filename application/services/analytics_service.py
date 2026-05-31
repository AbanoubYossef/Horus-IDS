"""Analytics queries (timeline, trends, severity stats)."""

from domain.ports.prediction_repository import PredictionRepository


class AnalyticsService:
    def __init__(self, repo: PredictionRepository):
        self._repo = repo

    def get_timeline(self, period: str, days: int) -> dict:
        from infrastructure.persistence.database import get_db
        fmt = "%Y-%m-%dT%H" if period == "hour" else "%Y-%m-%d"
        with get_db(self._repo._db_path) as conn:
            rows = conn.execute(
                f"""SELECT strftime('{fmt}', created_at) as period,
                           COUNT(*) as total,
                           SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END) as attacks,
                           SUM(CASE WHEN is_attack = 0 THEN 1 ELSE 0 END) as benign
                    FROM predictions
                    WHERE created_at >= datetime('now', ?)
                    GROUP BY strftime('{fmt}', created_at)
                    ORDER BY period""",
                (f"-{days} days",),
            ).fetchall()
        return {"period": period, "days": days, "data": [dict(r) for r in rows]}

    def get_attack_trends(self, days: int) -> dict:
        from infrastructure.persistence.database import get_db
        with get_db(self._repo._db_path) as conn:
            rows = conn.execute(
                """SELECT attack_type,
                          strftime('%Y-%m-%d', created_at) as day,
                          COUNT(*) as count
                   FROM predictions
                   WHERE is_attack = 1 AND created_at >= datetime('now', ?)
                   GROUP BY attack_type, day
                   ORDER BY day, count DESC""",
                (f"-{days} days",),
            ).fetchall()

            top_attacks = conn.execute(
                """SELECT attack_type, COUNT(*) as count,
                          AVG(confidence) as avg_confidence,
                          severity
                   FROM predictions
                   WHERE is_attack = 1 AND created_at >= datetime('now', ?)
                   GROUP BY attack_type
                   ORDER BY count DESC""",
                (f"-{days} days",),
            ).fetchall()

        trends = {}
        for r in rows:
            r = dict(r)
            trends.setdefault(r["attack_type"], []).append(
                {"day": r["day"], "count": r["count"]}
            )
        return {
            "days": days,
            "trends": trends,
            "top_attacks": [dict(r) for r in top_attacks],
        }

    def get_severity_distribution(self, days: int) -> dict:
        from infrastructure.persistence.database import get_db
        with get_db(self._repo._db_path) as conn:
            rows = conn.execute(
                """SELECT severity,
                          strftime('%Y-%m-%d', created_at) as day,
                          COUNT(*) as count
                   FROM predictions
                   WHERE created_at >= datetime('now', ?)
                   GROUP BY severity, day
                   ORDER BY day""",
                (f"-{days} days",),
            ).fetchall()

            totals = conn.execute(
                """SELECT severity, COUNT(*) as count
                   FROM predictions
                   WHERE created_at >= datetime('now', ?)
                   GROUP BY severity""",
                (f"-{days} days",),
            ).fetchall()

        return {
            "days": days,
            "daily": [dict(r) for r in rows],
            "totals": {r["severity"]: r["count"] for r in totals},
        }
