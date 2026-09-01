from fastapi import Request, Response
from fastapi.responses import JSONResponse
from typing import Any


class NewsMonException(Exception):
    def __init__(self, status_code: int, detail: str, error_type: str = "error"):
        self.status_code = status_code
        self.detail = detail
        self.error_type = error_type


ClarityTIException = NewsMonException  # Backward compatibility alias


async def newsmon_exception_handler(request: Request, exc: NewsMonException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": f"https://newsmon.io/errors/{exc.error_type}",
            "title": exc.detail,
            "status": exc.status_code,
            "instance": str(request.url),
        }
    )


clarityti_exception_handler = newsmon_exception_handler

