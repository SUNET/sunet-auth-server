from auth_server.models.gnap import ErrorCode

__author__ = "lundberg"


class GNAPErrorException(Exception):
    """Raise to return an RFC 9635 error object to the client."""

    def __init__(self, status_code: int, error_code: ErrorCode, description: str | None = None) -> None:
        self.status_code = status_code
        self.error_code = error_code
        self.description = description
        super().__init__(description or error_code.value)
