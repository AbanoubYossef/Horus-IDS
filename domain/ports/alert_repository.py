"""Port for alert persistence -- implemented by infrastructure."""

from abc import ABC, abstractmethod
from typing import Optional


class AlertRepository(ABC):
    @abstractmethod
    def list_alerts(
        self, limit: int, offset: int,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> tuple[list[dict], int]: ...

    @abstractmethod
    def create_alert(self, alert_data: dict) -> None: ...

    @abstractmethod
    def get_alert(self, alert_id: str) -> Optional[dict]: ...

    @abstractmethod
    def update_alert(self, alert_id: str, updates: dict) -> Optional[dict]: ...

    @abstractmethod
    def delete_alert(self, alert_id: str) -> bool: ...

    @abstractmethod
    def create_alerts_batch(self, alerts: list[dict]) -> int: ...
