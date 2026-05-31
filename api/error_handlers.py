"""Turn domain exceptions into proper HTTP error codes."""

from fastapi import Request
from fastapi.responses import JSONResponse

from domain.exceptions import (
    DomainError, ModelNotLoadedError, InvalidFlowError,
    BatchTooLargeError, InvalidFileError, PredictionNotFoundError,
    UserAlreadyExistsError, InvalidCredentialsError,
    AuthenticationRequiredError, InsufficientPermissionsError,
    AlertNotFoundError, NoDataAvailableError,
)

_STATUS_MAP = {
    ModelNotLoadedError: 503,
    InvalidFlowError: 422,
    BatchTooLargeError: 400,
    InvalidFileError: 400,
    PredictionNotFoundError: 404,
    UserAlreadyExistsError: 409,
    InvalidCredentialsError: 401,
    AuthenticationRequiredError: 401,
    InsufficientPermissionsError: 403,
    AlertNotFoundError: 404,
    NoDataAvailableError: 404,
}


async def domain_error_handler(request: Request, exc: DomainError) -> JSONResponse:
    status = _STATUS_MAP.get(type(exc), 400)
    return JSONResponse(
        status_code=status,
        content={"detail": str(exc)},
    )
