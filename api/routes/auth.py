"""Auth endpoints: register, login, logout, me."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Response

from api.schemas import RegisterRequest, LoginRequest
from api.dependencies import get_auth_service, get_current_user
from application.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register")
def register(
    req: RegisterRequest,
    service: AuthService = Depends(get_auth_service),
):
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    return service.register(user_id, req.username, req.email, req.password, req.role, now)


@router.post("/login")
def login(
    req: LoginRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),
):
    user_info, token = service.login(req.username, req.password)
    response.set_cookie(
        key="session_token", value=token, httponly=True,
        max_age=7 * 24 * 3600, samesite="lax",
    )
    return {"user": user_info, "token": token}


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    service: AuthService = Depends(get_auth_service),
):
    token = request.cookies.get("session_token")
    service.logout(token)
    response.delete_cookie("session_token")
    return {"status": "logged_out"}


@router.get("/me")
def me(user: dict | None = Depends(get_current_user)):
    if not user:
        from domain.exceptions import AuthenticationRequiredError
        raise AuthenticationRequiredError("Not authenticated")
    return {"user": user}
