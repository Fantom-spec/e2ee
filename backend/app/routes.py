"""HTTP and WebSocket endpoints (thin wrappers over the tested logic modules).

Database connections are opened per request and committed explicitly by the
endpoint that wrote something, so a token is never handed out before its
session row is durable.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from typing import Iterator, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, WebSocket
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import auth_service, keys_service, repo
from .auth_service import AuthContext, AuthError
from .db import connect
from .ratelimit import RateLimiter
from .relay import CLOSE_POLICY, CLOSE_UNAUTHENTICATED
from .schemas import (
    BundleOut,
    IdentityOut,
    KeyStatusResponse,
    KeyUploadRequest,
    LoginRequest,
    LoginResponse,
    PublishKeysResponse,
    RegisterRequest,
    TicketResponse,
    UserOut,
)
from .services import Services
from .tickets import TICKET_TTL_SECONDS
from .validation import ValidationError, validate_search_query, validate_uuid

logger = logging.getLogger("securechat.api")
router = APIRouter(prefix="/api")
ws_router = APIRouter()
_bearer = HTTPBearer(auto_error=False)

CLOSE_FORBIDDEN_ORIGIN = 4403


def _services(request: Request) -> Services:
    return request.app.state.services  # type: ignore[no-any-return]


def _now() -> int:
    return int(time.time())


def db_conn(request: Request) -> Iterator[sqlite3.Connection]:
    # check_same_thread=False: FastAPI may run setup/endpoint/teardown of a
    # dependency on different worker threads; the connection is never used
    # concurrently.
    conn = connect(_services(request).settings.db_path, check_same_thread=False)
    try:
        yield conn
    finally:
        conn.close()  # discards anything not explicitly committed


def client_ip(request: Request) -> str:
    svc = _services(request)
    if svc.settings.trust_cf_connecting_ip:
        forwarded = request.headers.get("cf-connecting-ip")
        if forwarded:
            return forwarded.strip()[:64]
    return request.client.host if request.client else "unknown"


def _limit(limiter: RateLimiter, key: str) -> None:
    if not limiter.allow(key):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts; try again later",
            headers={"Retry-After": str(limiter.retry_after(key))},
        )


def current_auth(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
    conn: sqlite3.Connection = Depends(db_conn),
) -> AuthContext:
    unauthorized = HTTPException(status_code=401, detail="Not authenticated",
                                 headers={"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise unauthorized
    ctx = auth_service.authenticate(conn, _services(request).settings.secret_key, creds.credentials, _now())
    if ctx is None:
        raise unauthorized
    return ctx


@router.post("/auth/register", status_code=201, response_model=UserOut)
def register(body: RegisterRequest, request: Request, conn: sqlite3.Connection = Depends(db_conn)) -> UserOut:
    svc = _services(request)
    _limit(svc.register_limiter, client_ip(request))
    try:
        user_id = auth_service.register(conn, svc.hasher, body.username, body.display_name,
                                        body.password, _now())
    except repo.UsernameTaken:
        raise HTTPException(status_code=409, detail="That username is not available") from None
    except ValidationError as exc:  # unreachable after schema validation; kept as a safety net
        raise HTTPException(status_code=422, detail=str(exc)) from None
    conn.commit()
    return UserOut(id=user_id, username=body.username, display_name=body.display_name)


@router.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, conn: sqlite3.Connection = Depends(db_conn)) -> LoginResponse:
    svc = _services(request)
    user_key = body.username.strip().lower()[:64]
    _limit(svc.login_ip_limiter, client_ip(request))
    _limit(svc.login_user_limiter, user_key)
    try:
        result = auth_service.login(conn, svc.hasher, svc.settings.secret_key, body.username,
                                    body.password, _now(), svc.settings.session_ttl_seconds)
    except AuthError:
        raise HTTPException(status_code=401, detail="Invalid username or password") from None
    conn.commit()
    svc.login_user_limiter.reset(user_key)
    ctx = result.context
    return LoginResponse(token=result.token, expires_at=result.expires_at,
                         user=UserOut(id=ctx.user_id, username=ctx.username, display_name=ctx.display_name))


@router.post("/auth/logout", status_code=204)
async def logout(request: Request, ctx: AuthContext = Depends(current_auth),
                 conn: sqlite3.Connection = Depends(db_conn)) -> Response:
    def revoke() -> None:
        auth_service.logout(conn, ctx.session_id, _now())
        conn.commit()

    await run_in_threadpool(revoke)
    await _services(request).hub.close_session(ctx.session_id)  # drop live sockets too
    return Response(status_code=204)


@router.get("/auth/me", response_model=UserOut)
def me(ctx: AuthContext = Depends(current_auth)) -> UserOut:
    return UserOut(id=ctx.user_id, username=ctx.username, display_name=ctx.display_name)


@router.get("/users/search", response_model=list[UserOut])
def search_users(q: str = Query(max_length=64), ctx: AuthContext = Depends(current_auth),
                 conn: sqlite3.Connection = Depends(db_conn)) -> list[UserOut]:
    try:
        prefix = validate_search_query(q)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    rows = repo.search_users(conn, prefix, ctx.user_id)
    return [UserOut(id=r["id"], username=r["username"], display_name=r["display_name"]) for r in rows]


@router.get("/users/{user_id}", response_model=UserOut)
def get_user_profile(user_id: str, ctx: AuthContext = Depends(current_auth),
                     conn: sqlite3.Connection = Depends(db_conn)) -> UserOut:
    """Public profile of one account (used when a message arrives from someone not yet in the contact list).
    Declared after /users/search so that path is not shadowed."""
    try:
        target = validate_uuid(user_id, "user id")
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    row = repo.get_user(conn, target)
    if row is None or row["disabled"]:
        raise HTTPException(status_code=404, detail="User not found")
    return UserOut(id=row["id"], username=row["username"], display_name=row["display_name"])


@router.post("/keys", response_model=PublishKeysResponse)
def publish_keys(body: KeyUploadRequest, ctx: AuthContext = Depends(current_auth),
                 conn: sqlite3.Connection = Depends(db_conn)) -> PublishKeysResponse:
    """Bind or refresh the caller's PUBLIC keys. Private keys never reach the server."""
    try:
        upload = keys_service.parse_upload(body.model_dump())
        result = keys_service.publish_keys(conn, ctx.user_id, upload, _now())
    except ValidationError as exc:
        conn.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except keys_service.KeyConflict as exc:
        conn.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from None
    conn.commit()
    return PublishKeysResponse(identity_changed=result.identity_changed, key_version=result.key_version,
                               one_time_prekeys_remaining=result.one_time_prekeys_remaining)


# Declared before "/keys/{user_id}" so "status" is not parsed as a user id.
@router.get("/keys/status", response_model=KeyStatusResponse)
def key_status(ctx: AuthContext = Depends(current_auth),
               conn: sqlite3.Connection = Depends(db_conn)) -> KeyStatusResponse:
    return KeyStatusResponse(**keys_service.key_status(conn, ctx.user_id))


def _target_id(user_id: str, ctx: AuthContext) -> str:
    try:
        target = validate_uuid(user_id, "user id")
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if target == ctx.user_id:
        raise HTTPException(status_code=400, detail="Cannot start a conversation with yourself")
    return target


@router.get("/keys/{user_id}", response_model=BundleOut)
def fetch_bundle(user_id: str, request: Request, ctx: AuthContext = Depends(current_auth),
                 conn: sqlite3.Connection = Depends(db_conn)) -> BundleOut:
    """Prekey bundle for starting a session. Consumes one one-time prekey."""
    target = _target_id(user_id, ctx)
    _limit(_services(request).keys_fetch_limiter, ctx.user_id)
    bundle = keys_service.fetch_bundle(conn, target)
    if bundle is None:
        conn.rollback()
        raise HTTPException(status_code=404, detail="No keys available for that user")
    conn.commit()
    return BundleOut(**bundle)


@router.get("/keys/{user_id}/identity", response_model=IdentityOut)
def fetch_identity(user_id: str, ctx: AuthContext = Depends(current_auth),
                   conn: sqlite3.Connection = Depends(db_conn)) -> IdentityOut:
    """Identity key + version without consuming a prekey (used to check for key changes)."""
    target = _target_id(user_id, ctx)
    identity = keys_service.get_identity(conn, target)
    if identity is None:
        raise HTTPException(status_code=404, detail="No keys available for that user")
    return IdentityOut(**identity)


@router.post("/ws/ticket", response_model=TicketResponse)
def ws_ticket(request: Request, ctx: AuthContext = Depends(current_auth)) -> TicketResponse:
    try:
        ticket = _services(request).tickets.issue(ctx.user_id, ctx.session_id)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Server busy") from None
    return TicketResponse(ticket=ticket, expires_in=TICKET_TTL_SECONDS)


class SocketConnection:
    """Adapts a Starlette WebSocket to the relay's Connection protocol."""

    def __init__(self, ws: WebSocket, session_id: str) -> None:
        self._ws = ws
        self.session_id = session_id
        self.closed = False

    async def send_json(self, obj: dict) -> None:  # type: ignore[type-arg]
        await self._ws.send_json(obj)

    async def close(self, code: int) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            await self._ws.close(code=code)
        except RuntimeError:
            logger.info("close(%s) on an already-closed socket", code)


def _origin_ok(svc: Services, origin: Optional[str]) -> bool:
    # Browsers always send Origin on WebSocket handshakes. A missing Origin
    # (non-browser tools) is tolerated only in development.
    if origin is None:
        return svc.settings.is_development
    return origin.rstrip("/") in svc.settings.allowed_origins


@ws_router.websocket("/ws")
async def relay_socket(websocket: WebSocket) -> None:
    svc: Services = websocket.app.state.services
    if not _origin_ok(svc, websocket.headers.get("origin")):
        await websocket.close(code=CLOSE_FORBIDDEN_ORIGIN)
        return
    ident = svc.tickets.consume(websocket.query_params.get("ticket", ""))
    if ident is None:
        await websocket.close(code=CLOSE_UNAUTHENTICATED)
        return
    user_id, session_id = ident

    # The ticket proves a session existed 30 s ago; confirm it is still valid.
    ctx = await _context_for(svc, user_id, session_id)
    if ctx is None:
        await websocket.close(code=CLOSE_UNAUTHENTICATED)
        return

    await websocket.accept()
    conn = SocketConnection(websocket, session_id)
    if not svc.hub.register(user_id, conn):
        await conn.close(CLOSE_POLICY)  # too many simultaneous connections for this user
        return
    try:
        await svc.relay.on_connect(ctx, conn)
        while not conn.closed:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            text = message.get("text")
            if text is None:
                await conn.close(1003)  # binary frames are not part of the protocol
                break
            await svc.relay.on_frame(ctx, conn, text)
    except Exception:
        logger.exception("relay socket error for user %s", user_id)  # no frame contents logged
        await conn.close(1011)
    finally:
        svc.hub.unregister(user_id, conn)


async def _context_for(svc: Services, user_id: str, session_id: str) -> Optional[AuthContext]:
    def load() -> Optional[AuthContext]:
        c = connect(svc.settings.db_path)
        try:
            if not repo.session_is_active(c, session_id, _now()):
                return None
            user = repo.get_user(c, user_id)
            if user is None or user["disabled"]:
                return None
            return AuthContext(user_id, session_id, user["username"], user["display_name"])
        finally:
            c.close()

    return await run_in_threadpool(load)
