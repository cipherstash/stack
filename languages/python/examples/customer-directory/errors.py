"""The error handling that both apps share."""

import logging

import stackencrypt
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

log = logging.getLogger("customer_directory")


def log_error(error: Exception) -> None:
    """Log what identifies an error, and never the error's own text.

    An SDK error's message never contains a value, so `code` and `field` are
    safe. PostgreSQL's primary message has no value in it. Its detail can
    quote the value, so the detail is not logged. Any other exception's text
    could contain plaintext, so only its type is logged.
    """
    # SQLAlchemy wraps the driver's error and keeps it in `orig`.
    cause = getattr(error, "orig", error)
    diag = getattr(cause, "diag", None)
    log.error(
        "customer_error type=%s code=%s field=%s sqlstate=%s message=%s",
        type(error).__name__,
        getattr(error, "code", None) if cause is error else None,
        getattr(error, "field", None),
        getattr(cause, "sqlstate", None),
        getattr(diag, "message_primary", None),
    )


def problem(status: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": detail})


def install_error_handlers(app: FastAPI) -> None:
    """Give an app fixed error responses, with the details in the log."""

    @app.middleware("http")
    async def fixed_500(request: Request, call_next):
        # This catches the error here because an `Exception` handler would
        # still re-raise it, and Uvicorn would then log its text.
        try:
            return await call_next(request)
        except Exception as error:
            log_error(error)
            return problem(500, "The request failed.")

    @app.exception_handler(RequestValidationError)
    def invalid_request(request: Request, error: RequestValidationError) -> JSONResponse:
        # FastAPI's default response repeats the rejected input.
        log_error(error)
        return problem(422, "A field has an invalid value.")

    @app.exception_handler(stackencrypt.InvalidValueError)
    def invalid_value(request: Request, error: stackencrypt.InvalidValueError) -> JSONResponse:
        log_error(error)
        return problem(422, "A field has an invalid value.")
