"""AI chatbot use case."""

from domain.ports.prediction_repository import PredictionRepository
from infrastructure.external.groq_client import GroqClient


class AiService:
    def __init__(self, groq_client: GroqClient, prediction_repo: PredictionRepository):
        self._groq = groq_client
        self._repo = prediction_repo

    def _build_platform_context(self) -> str:
        from infrastructure.persistence.database import get_db
        try:
            with get_db(self._repo._db_path) as conn:
                total = conn.execute("SELECT COUNT(*) FROM predictions").fetchone()[0]
                attacks = conn.execute(
                    "SELECT COUNT(*) FROM predictions WHERE is_attack=1"
                ).fetchone()[0]
                recent_attacks = conn.execute(
                    """SELECT attack_type, COUNT(*) as cnt FROM predictions
                       WHERE is_attack=1 AND created_at >= datetime('now', '-1 day')
                       GROUP BY attack_type ORDER BY cnt DESC LIMIT 5"""
                ).fetchall()
                severity_counts = conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM predictions GROUP BY severity"
                ).fetchall()
                open_alerts = conn.execute(
                    "SELECT COUNT(*) FROM alerts WHERE status IN ('open', 'investigating')"
                ).fetchone()[0]

            attack_rate = f"{(attacks / total * 100):.1f}%" if total > 0 else "N/A"
            sev_parts = ", ".join(
                f"{r['severity']}: {r['cnt']}" for r in severity_counts
            )
            atk_parts = (
                ", ".join(f"{r['attack_type']}: {r['cnt']}" for r in recent_attacks)
                if recent_attacks else "None"
            )
            return (
                f"- Total predictions analyzed: {total}\n"
                f"- Total attacks detected: {attacks} ({attack_rate} attack rate)\n"
                f"- Open/investigating alerts: {open_alerts}\n"
                f"- Severity breakdown: {sev_parts}\n"
                f"- Recent attacks (last 24h): {atk_parts}"
            )
        except Exception:
            return ""

    async def chat(self, message: str, history: list[dict]) -> str:
        context = self._build_platform_context()
        return await self._groq.chat(message, history, context)
