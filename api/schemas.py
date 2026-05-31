"""Request/response schemas."""

from typing import Dict, Optional

from pydantic import BaseModel, Field


class SingleFlowRequest(BaseModel):
    features_dict: Dict[str, float]
    src_ip:   Optional[str] = None
    dst_ip:   Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    vlan_id:  Optional[int] = None
    src_vlan: Optional[int] = None
    dst_vlan: Optional[int] = None


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=5, max_length=100)
    password: str = Field(min_length=6, max_length=128)
    role: str = Field(default="visitor", pattern="^(visitor|analyst)$")


class LoginRequest(BaseModel):
    username: str
    password: str


class AlertCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: Optional[str] = None
    severity: str = Field(default="medium", pattern="^(critical|high|medium|low|info)$")
    prediction_id: Optional[str] = None


class AlertUpdateRequest(BaseModel):
    title: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = None
    severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    status: Optional[str] = Field(default=None, pattern="^(open|investigating|resolved|closed)$")
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    history: list[dict] = Field(default_factory=list)
