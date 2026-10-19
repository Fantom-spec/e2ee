"""FastAPI application factory.

Run with:  uvicorn app.main:create_app --factory
The factory form means a missing/unsafe configuration raises ConfigError at
startup instead of at import time, and tests can build isolated apps.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator, Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__, repo
from .config import Settings, load_settings
from .db import connect, init_db
from .routes import router, ws_router
from .services import build_services

logger = logging.getLogger("securechat")
CLEANUP_INTERVAL_SECONDS = 600


def _purge(db_path: str) -> None:
    conn = connect(db_path)
    try:
        now = int(time.time())
        repo.purge_expired_sessions(conn, now)
        repo.purge_expired_messages(conn, now)
        conn.commit()
    finally:
        conn.close()


async def _janitor(db_path: str) -> None:
    """Periodically delete expired sessions and expired queued messages."""
    while True:
        try:
            await asyncio.to_thread(_purge, db_path)
        except sqlite3.Error:
            logger.exception("periodic cleanup failed")
        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        init_db(settings.db_path)
        task = asyncio.create_task(_janitor(str(settings.db_path)))
        try:
            yield
        finally:
            task.cancel()

    dev = settings.is_development
    app = FastAPI(
        title="SecureChat Relay",
        version=__version__,
        lifespan=lifespan,
        # Interactive docs are an information leak in a public deployment.
        docs_url="/api/docs" if dev else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if dev else None,
    )
    app.state.settings = settings
    app.state.services = build_services(settings)

    # Explicit origin allow-list from configuration; never "*". Credentials are
    # off because auth uses an Authorization header, not cookies.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default 422 body echoes the submitted value ("input"),
        # which would reflect passwords back. Return only location + message.
        detail = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": detail})

    @app.get("/api/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "version": __version__, "stage": 2}

    app.include_router(router)
    app.include_router(ws_router)
    return app
