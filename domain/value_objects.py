"""Value objects -- immutable domain concepts."""

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_label(cls, attack_label: str) -> "Severity":
        from domain.constants import SEVERITY_MAP
        level = SEVERITY_MAP.get(attack_label, "medium")
        return cls(level)


class AlertStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class UserRole(str, Enum):
    VISITOR = "visitor"
    ANALYST = "analyst"
