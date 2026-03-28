"""HTTP + WebSocket SIRA server (match sira Rust server.rs)."""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import Any, Awaitable, Callable

import msgpack
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from sira import crypto
from sira.types import (
    CLsend,
    ChunkPayload,
    SVsend,
    Beat,
    HEARTBEAT_TIMEOUT_SECS,
    MAX_ASSEMBLED_PAYLOAD,
    MAX_CHUNK_COUNT,
    MAX_CHUNK_DATA,
    MESSAGE_SIZE,
    SessionToken,
    COOKIE_MAX_AGE_PERSISTENT_SECS,
    COOKIE_MAX_AGE_SECS,
    expected_clsend_hash,
    compute_hash,
    initial_hash,
    now_unix,
)

log = logging.getLogger(__name__)


class MinuteRateLimiter:
    def __init__(self, max_per_rolling_minute: int) -> None:
        self._data: dict[str, list[int]] = {}
        self._max = max_per_rolling_minute

    def allow(self, key: str) -> bool:
        now = now_unix()
        v = self._data.setdefault(key, [])
        v[:] = [t for t in v if now - t < 60]
        if len(v) >= self._max:
            return False
        v.append(now)
        return True

    def purge_stale(self) -> None:
        now = now_unix()
        dead = []
        for k, v in self._data.items():
            v[:] = [t for t in v if now - t < 60]
            if not v:
                dead.append(k)
        for k in dead:
            del self._data[k]


class ChunkSlot:
    __slots__ = ("n", "parts", "filled", "bytes", "started")

    def __init__(self, n: int) -> None:
        self.n = n
        self.parts: list[bytes | None] = [None] * n
        self.filled = 0
        self.bytes = 0
        self.started = time.monotonic()


class ChunkBuffers:
    def __init__(self) -> None:
        self._inner: dict[str, ChunkSlot] = {}

    def purge_stale(self, max_age_s: float) -> None:
        now = time.monotonic()
        dead = [k for k, s in self._inner.items() if now - s.started > max_age_s]
        for k in dead:
            del self._inner[k]

    def push(self, assembly_key: str, ch: ChunkPayload) -> bytes | None:
        if (
            ch.k != "ch"
            or ch.n == 0
            or ch.n > MAX_CHUNK_COUNT
            or ch.i >= ch.n
            or len(ch.d) > MAX_CHUNK_DATA
        ):
            raise ValueError("bad chunk")

        slot = self._inner.get(assembly_key)
        if slot is None or time.monotonic() - slot.started > 120:
            slot = ChunkSlot(ch.n)
            self._inner[assembly_key] = slot

        if slot.n != ch.n:
            raise ValueError("chunk n mismatch")

        if slot.parts[ch.i] is not None:
            raise ValueError("dup chunk")

        add = len(ch.d)
        if slot.bytes + add > MAX_ASSEMBLED_PAYLOAD:
            raise ValueError("too large")

        slot.parts[ch.i] = ch.d
        slot.filled += 1
        slot.bytes += add

        if slot.filled < ch.n:
            return None

        out = bytearray(slot.bytes)
        o = 0
        for p in slot.parts:
            assert p is not None
            out[o : o + len(p)] = p
            o += len(p)
        del self._inner[assembly_key]
        return bytes(out)


class RefreshAuthenticator(ABC):
    @abstractmethod
    async def authenticate_app_token(self, app_token: str) -> str:
        ...


class Pipeline(ABC):
    @abstractmethod
    async def process(
        self,
        action: Any,
        session_id: str,
        window_id: str,
        user_id: str | None,
    ) -> Any:
        ...


def _cookie_header(value: str, persistent: bool) -> str:
    max_age = COOKIE_MAX_AGE_PERSISTENT_SECS if persistent else COOKIE_MAX_AGE_SECS
    return f"__s={value}; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}; Path=/"


def _extract_session_cookie(header_val: str | None) -> str | None:
    if not header_val:
        return None
    for part in header_val.split(";"):
        part = part.strip()
        if part.startswith("__s="):
            return part[4:]
    return None


def _extract_auth_app_token(a: Any) -> str | None:
    if not isinstance(a, dict):
        return None
    auth = a.get("auth")
    if not isinstance(auth, dict):
        return None
    t = auth.get("token")
    return str(t) if t is not None else None


def _client_ip(request: Request) -> str:
    c = request.client
    return c.host if c else "unknown"


def _try_beat(payload: bytes) -> Beat | None:
    try:
        d = msgpack.unpackb(payload, raw=False, strict_map_key=False)
        if isinstance(d, dict) and set(d) == {"beat", "w"}:
            return Beat(beat=bool(d["beat"]), w=str(d["w"]))
    except Exception:
        pass
    return None


def _try_chunk(payload: bytes) -> ChunkPayload | None:
    try:
        d = msgpack.unpackb(payload, raw=False, strict_map_key=False)
        if not isinstance(d, dict) or d.get("k") != "ch":
            return None
        raw_d = d["d"]
        b = raw_d if isinstance(raw_d, bytes) else bytes(raw_d)
        return ChunkPayload(k="ch", i=int(d["i"]), n=int(d["n"]), d=b)
    except Exception:
        return None


def _unpack_clsend(payload: bytes) -> CLsend | None:
    try:
        d = msgpack.unpackb(payload, raw=False, strict_map_key=False)
        if not isinstance(d, dict):
            return None
        s = d.get("s")
        sb = s if isinstance(s, bytes) else (bytes(s) if s is not None else None)
        return CLsend(h=str(d["h"]), a=d["a"], w=str(d["w"]), s=sb)
    except Exception:
        return None


class _ServerState:
    def __init__(
        self,
        master_secret: bytes,
        pipeline: Pipeline,
        refresh_auth: RefreshAuthenticator | None,
        revocation: Any | None,
    ) -> None:
        if len(master_secret) != 32:
            raise ValueError("master_secret must be 32 bytes")
        self.master_secret = master_secret
        self.pipeline = pipeline
        self.refresh_auth = refresh_auth
        self.revocation = revocation
        self.chunks = ChunkBuffers()
        self.hs_limit = MinuteRateLimiter(120)
        self.ws_limit = MinuteRateLimiter(60)
        self.refresh_limit = MinuteRateLimiter(120)

    def token_revoked(self, token: SessionToken) -> bool:
        if self.revocation is None:
            return False
        return self.revocation.is_revoked(token.created_at)


ASGIApp = Callable[[dict[str, Any], Any, Any], Awaitable[None]]
SIRA_WS_SESSION_KEY = "sira_ws_session"


def _cookie_from_scope(scope: dict[str, Any]) -> str | None:
    parts: list[str] = []
    for k, v in scope.get("headers", []):
        if k.decode("latin-1").lower() == "cookie":
            parts.append(v.decode("latin-1"))
    if not parts:
        return None
    return _extract_session_cookie("; ".join(parts))


def _client_ip_scope(scope: dict[str, Any]) -> str:
    client = scope.get("client")
    if isinstance(client, tuple) and len(client) >= 1:
        return str(client[0])
    return "unknown"


async def _asgi_send_401_noise(send: Any) -> None:
    body = crypto.noise()
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/octet-stream"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _asgi_send_429(send: Any) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 429,
            "headers": [(b"connection", b"close")],
        }
    )
    await send({"type": "http.response.body", "body": b"", "more_body": False})


class SiraWebSocketAuthMiddleware:
    """HTTP 401 + 1024 B noise before WebSocket upgrade when __s is missing/invalid."""

    def __init__(self, app: ASGIApp, state: _ServerState) -> None:
        self.app = app
        self.state = state

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "websocket":
            path = scope.get("path") or ""
            if path == "/w":
                ip = _client_ip_scope(scope)
                if not self.state.ws_limit.allow(ip):
                    await _asgi_send_429(send)
                    return
                raw = _cookie_from_scope(scope)
                if raw is None:
                    await _asgi_send_401_noise(send)
                    return
                try:
                    token = crypto.decrypt_session_token(raw, self.state.master_secret)
                except Exception:
                    await _asgi_send_401_noise(send)
                    return
                if self.state.token_revoked(token):
                    await _asgi_send_401_noise(send)
                    return
                scope[SIRA_WS_SESSION_KEY] = token
        await self.app(scope, receive, send)


def _build_starlette(state: _ServerState) -> ASGIApp:
    @asynccontextmanager
    async def lifespan(app: Starlette):
        async def maintenance() -> None:
            while True:
                await asyncio.sleep(60)
                if state.revocation is not None:
                    state.revocation.reload()
                state.hs_limit.purge_stale()
                state.ws_limit.purge_stale()
                state.refresh_limit.purge_stale()
                state.chunks.purge_stale(120.0)

        task = asyncio.create_task(maintenance())
        yield
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def handshake_handler(request: Request) -> Response:
        ip = _client_ip(request)
        if not state.hs_limit.allow(ip):
            return Response(status_code=429)
        body = await request.body()
        if len(body) != 32:
            return Response("expected 32 bytes", status_code=400)
        persistent = request.query_params.get("persistent", "false").lower() in (
            "1",
            "true",
            "yes",
        )
        try:
            aes_key, server_pub = crypto.handshake(body)
        except Exception:
            return Response("handshake failed", status_code=400)
        token = SessionToken.new(aes_key, persistent)
        try:
            cookie_val = crypto.encrypt_session_token(token, state.master_secret)
        except Exception:
            return Response("token error", status_code=500)
        headers = {
            "Set-Cookie": _cookie_header(cookie_val, persistent),
            "Content-Type": "application/octet-stream",
        }
        return Response(content=server_pub, headers=headers)

    async def refresh_handler(request: Request) -> Response:
        ip = _client_ip(request)
        if not state.refresh_limit.allow(ip):
            return Response(status_code=429)
        if state.refresh_auth is None:
            return Response(
                "POST /r requires a RefreshAuthenticator — none configured",
                status_code=503,
            )
        raw = _extract_session_cookie(request.headers.get("cookie"))
        if raw is None:
            return Response(
                content=crypto.noise(), status_code=401, media_type="application/octet-stream"
            )
        try:
            token = crypto.decrypt_session_token(raw, state.master_secret)
        except Exception:
            return Response(
                content=crypto.noise(), status_code=401, media_type="application/octet-stream"
            )
        if state.token_revoked(token):
            return Response(
                content=crypto.noise(), status_code=401, media_type="application/octet-stream"
            )
        body = await request.body()
        if len(body) != MESSAGE_SIZE:
            return Response(
                content=crypto.noise(), status_code=401, media_type="application/octet-stream"
            )
        try:
            _rid, payload = crypto.decrypt(body, token.key)
        except Exception:
            return Response(
                content=crypto.noise(), status_code=401, media_type="application/octet-stream"
            )
        clsend = _unpack_clsend(payload)
        if clsend is None:
            return Response(
                content=crypto.noise(), status_code=401, media_type="application/octet-stream"
            )
        if clsend.h != expected_clsend_hash(clsend.w, clsend.s):
            return Response(
                content=crypto.noise(), status_code=401, media_type="application/octet-stream"
            )
        app_tok = _extract_auth_app_token(clsend.a)
        if app_tok is None:
            return Response(
                content=crypto.noise(), status_code=401, media_type="application/octet-stream"
            )
        try:
            user_id = await state.refresh_auth.authenticate_app_token(app_tok)
        except Exception:
            return Response(
                content=crypto.noise(), status_code=401, media_type="application/octet-stream"
            )
        new_token = token.with_user_id(user_id)
        try:
            cookie_val = crypto.encrypt_session_token(new_token, state.master_secret)
        except Exception:
            return Response(
                content=crypto.noise(), status_code=401, media_type="application/octet-stream"
            )
        return Response(
            status_code=200,
            headers={"Set-Cookie": _cookie_header(cookie_val, new_token.persistent)},
        )

    async def ws_handler(ws: WebSocket) -> None:
        token = ws.scope.get(SIRA_WS_SESSION_KEY)
        if not isinstance(token, SessionToken):
            await ws.close(code=1008)
            return
        await ws.accept()
        await _handle_ws_loop(ws, state, token)

    routes = [
        Route("/h", handshake_handler, methods=["POST"]),
        Route("/r", refresh_handler, methods=["POST"]),
        WebSocketRoute("/w", ws_handler),
    ]
    inner = Starlette(routes=routes, lifespan=lifespan)
    return SiraWebSocketAuthMiddleware(inner, state)


async def _handle_ws_loop(ws: WebSocket, state: _ServerState, token: SessionToken) -> None:
    key = token.key
    session_fp = token.fingerprint()
    user_id = token.user_id

    while True:
        try:
            raw = await asyncio.wait_for(
                ws.receive_bytes(), timeout=HEARTBEAT_TIMEOUT_SECS
            )
        except asyncio.TimeoutError:
            log.warning("Heartbeat timeout session %s", session_fp[:8])
            break
        except WebSocketDisconnect:
            break
        except RuntimeError:
            break

        if state.token_revoked(token):
            break

        if len(raw) != MESSAGE_SIZE:
            await ws.send_bytes(crypto.noise())
            continue
        try:
            request_id, payload = crypto.decrypt(raw, key)
        except Exception:
            await ws.send_bytes(crypto.noise())
            continue

        beat = _try_beat(payload)
        if beat is not None:
            br = Beat(beat=True, w=beat.w)
            try:
                enc = msgpack.packb(
                    {"beat": br.beat, "w": br.w}, use_bin_type=True
                )
                frame = crypto.encrypt(enc, key, request_id)
                await ws.send_bytes(frame)
            except Exception:
                pass
            continue

        assembly_key = f"{session_fp}:{request_id.hex()}"
        clsend_bytes: bytes
        ch = _try_chunk(payload)
        if ch is not None:
            try:
                full = state.chunks.push(assembly_key, ch)
            except ValueError:
                await ws.send_bytes(crypto.noise())
                continue
            if full is None:
                continue
            clsend_bytes = full
        else:
            clsend_bytes = payload

        clsend = _unpack_clsend(clsend_bytes)
        if clsend is None:
            await ws.send_bytes(crypto.noise())
            continue
        if clsend.h != expected_clsend_hash(clsend.w, clsend.s):
            await ws.send_bytes(crypto.noise())
            continue

        substate = clsend.s
        new_hash = compute_hash(substate) if substate is not None else initial_hash(clsend.w)

        render = await state.pipeline.process(
            clsend.a, session_fp, clsend.w, user_id
        )

        response = SVsend(h=new_hash, r=render, w=clsend.w, s=substate)
        pack: dict[str, Any] = {"h": response.h, "r": response.r, "w": response.w}
        if response.s is not None:
            pack["s"] = response.s
        try:
            encoded = msgpack.packb(pack, use_bin_type=True)
            frames = crypto.encrypt_svsend_chunked(encoded, key, request_id)
        except Exception as e:
            log.error("encrypt response failed: %s", e)
            continue
        for frame in frames:
            await ws.send_bytes(frame)


class SiraServer:
    def __init__(
        self,
        pipeline: Pipeline,
        master_secret: bytes,
        refresh_auth: RefreshAuthenticator | None = None,
        host: str = "0.0.0.0",
        port: int = 3000,
        revocation: Any | None = None,
    ) -> None:
        self._state = _ServerState(master_secret, pipeline, refresh_auth, revocation)
        self.host = host
        self.port = port
        self._app = _build_starlette(self._state)

    @property
    def app(self) -> ASGIApp:
        return self._app

    def run(self) -> None:
        import uvicorn

        uvicorn.run(
            self._app,
            host=self.host,
            port=self.port,
            log_level="info",
        )


def create_app(
    pipeline: Pipeline,
    master_secret: bytes,
    refresh_auth: RefreshAuthenticator | None = None,
    revocation: Any | None = None,
) -> ASGIApp:
    """ASGI app factory for uvicorn/gunicorn."""
    st = _ServerState(master_secret, pipeline, refresh_auth, revocation)
    return _build_starlette(st)
