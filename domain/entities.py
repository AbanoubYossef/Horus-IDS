"""Domain entities -- core data structures with no framework dependencies."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Prediction:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    attack_type: str = ""
    confidence: float = 0.0
    is_attack: bool = False
    severity: str = "info"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    vlan_id: Optional[int] = None
    src_vlan: Optional[int] = None
    dst_vlan: Optional[int] = None
    model: str = ""
    inference_ms: float = 0.0
    probabilities: dict = field(default_factory=dict)
    top_features: list = field(default_factory=list)
    group_pred: str = ""
    ground_truth: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "is_attack": self.is_attack,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "vlan_id": self.vlan_id,
            "src_vlan": self.src_vlan,
            "dst_vlan": self.dst_vlan,
            "model": self.model,
            "inference_ms": self.inference_ms,
            "probabilities": self.probabilities,
            "top_features": self.top_features,
            "group_pred": self.group_pred,
            "ground_truth": self.ground_truth,
            "created_at": self.created_at,
        }


@dataclass
class User:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    username: str = ""
    email: str = ""
    password_hash: str = ""
    salt: str = ""
    role: str = "analyst"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class Session:
    token: str = ""
    user_id: str = ""
    expires_at: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class Alert:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: Optional[str] = None
    severity: str = "medium"
    status: str = "open"
    prediction_id: Optional[str] = None
    assigned_to: Optional[str] = None
    created_by: str = ""
    notes: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
