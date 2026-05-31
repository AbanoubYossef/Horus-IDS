"""Domain exceptions."""


class DomainError(Exception):
    pass


class ModelNotLoadedError(DomainError):
    pass


class InvalidFlowError(DomainError):
    pass


class BatchTooLargeError(DomainError):
    pass

    def __init__(self, size: int, maximum: int):
        super().__init__(f"Batch size {size} exceeds maximum {maximum}")
        self.size = size
        self.maximum = maximum


class InvalidFileError(DomainError):
    pass


class PredictionNotFoundError(DomainError):
    pass


class UserAlreadyExistsError(DomainError):
    pass


class InvalidCredentialsError(DomainError):
    pass


class AuthenticationRequiredError(DomainError):
    pass


class InsufficientPermissionsError(DomainError):
    pass


class AlertNotFoundError(DomainError):
    pass


class NoDataAvailableError(DomainError):
    pass
