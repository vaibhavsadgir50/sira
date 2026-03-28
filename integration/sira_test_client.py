"""Pure-Python SIRA client for integration tests (uses sira-python crypto)."""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path
from typing import Any

import msgpack
import websockets

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sira-python"))

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sira.crypto import decrypt, encrypt, new_request_id
from sira.types import (
    DATA_SIZE,
    HKDF_INFO,
    MAX_ASSEMBLED_PAYLOAD,
    MAX_CHUNK_COUNT,
    MAX_CHUNK_DATA,
    MESSAGE_SIZE,
    initial_hash,
)

CHUNK_SAFE = 900


def _derive_wire_key(client_priv: X25519PrivateKey, server_pub: bytes) -> bytes:
    shared = client_priv.exchange(X25519PublicKey.from_public_bytes(server_pub))
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=HKDF_INFO)
    return hkdf.derive(shared)


def _parse_set_cookie(set_cookie: str | None) -> str:
    if not set_cookie or "__s=" not in set_cookie:
        raise ValueError("missing __s in Set-Cookie")
    i = set_cookie.index("__s=")
    rest = set_cookie[i + 4 :]
    semi = rest.find(";")
    return rest[:semi].strip() if semi != -1 else rest.strip()


def _try_chunk(pl: bytes) -> dict[str, Any] | None:
    try:
        d = msgpack.unpackb(pl, raw=False, strict_map_key=False)
        if isinstance(d, dict) and d.get("k") == "ch":
            raw_d = d["d"]
            b = raw_d if isinstance(raw_d, bytes) else bytes(raw_d)
            return {"k": "ch", "i": int(d["i"]), "n": int(d["n"]), "d": b}
    except Exception:
        pass
    return None


class _ChunkRx:
    def __init__(self, n: int) -> None:
        self.n = n
        self.parts: list[bytes | None] = [None] * n
        self.filled = 0
        self.bytes = 0


class SiraTestClient:
    def __init__(self, base_url: str, master_secret: bytes | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.master_secret = master_secret
        self.key: bytes | None = None
        self._ws: Any = None
        self._cookie: str | None = None
        self.window_id: str | None = None
        self.state_hash: str | None = None
        self.substate: bytes | None = None
        self._http_base = self.base_url
        self._chunk_buffers: dict[str, _ChunkRx] = {}

    def _ws_url(self) -> str:
        if self._http_base.startswith("https://"):
            return "wss://" + self._http_base[len("https://") :] + "/w"
        if self._http_base.startswith("http://"):
            return "ws://" + self._http_base[len("http://") :] + "/w"
        raise ValueError("base_url must start with http:// or https://")

    async def connect(self, persistent: bool = False) -> None:
        self.window_id = str(uuid.uuid4())
        self.state_hash = initial_hash(self.window_id)
        self.substate = None
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        url = f"{self._http_base}/h"
        if persistent:
            url += "?persistent=true"
        async with httpx.AsyncClient() as client:
            r = await client.post(url, content=pub, timeout=30.0)
            r.raise_for_status()
            server_pub = bytes(r.content[:32])
            self._cookie = _parse_set_cookie(r.headers.get("set-cookie"))
        self.key = _derive_wire_key(priv, server_pub)
        ws_u = self._ws_url()
        self._ws = await websockets.connect(
            ws_u,
            additional_headers=[("Cookie", f"__s={self._cookie}")],
            max_size=MESSAGE_SIZE + 100,
        )

    async def _send_payload(self, payload: bytes, rid: bytes) -> None:
        assert self.key is not None and self._ws is not None
        if len(payload) <= DATA_SIZE:
            await self._ws.send(encrypt(payload, self.key, rid))
            return
        nchunks = (len(payload) + CHUNK_SAFE - 1) // CHUNK_SAFE
        if nchunks > MAX_CHUNK_COUNT:
            raise ValueError("payload too large")
        n = nchunks
        for i in range(n):
            sl = payload[i * CHUNK_SAFE : (i + 1) * CHUNK_SAFE]
            cp = {"k": "ch", "i": i, "n": n, "d": sl}
            buf = msgpack.packb(cp, use_bin_type=True)
            if len(buf) > DATA_SIZE:
                raise ValueError("chunk msgpack too large")
            await self._ws.send(encrypt(buf, self.key, rid))

    async def _recv_one_logical(self, expect_rid: bytes) -> dict[str, Any]:
        assert self.key is not None and self._ws is not None
        session_fp = self.key[:8].hex()
        key_assembly = f"{session_fp}:{expect_rid.hex()}"

        while True:
            raw = await asyncio.wait_for(self._ws.recv(), timeout=90.0)
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            if len(raw) != MESSAGE_SIZE:
                continue
            try:
                rid, pl = decrypt(raw, self.key)
            except Exception:
                continue
            if rid != expect_rid:
                continue

            ch = _try_chunk(pl)
            if ch is not None:
                if (
                    ch["n"] == 0
                    or ch["n"] > MAX_CHUNK_COUNT
                    or ch["i"] >= ch["n"]
                    or len(ch["d"]) > MAX_CHUNK_DATA
                ):
                    continue
                slot = self._chunk_buffers.get(key_assembly)
                if slot is None or slot.n != ch["n"]:
                    slot = _ChunkRx(ch["n"])
                    self._chunk_buffers[key_assembly] = slot
                if slot.parts[ch["i"]] is not None:
                    continue
                slot.parts[ch["i"]] = ch["d"]
                slot.filled += 1
                slot.bytes += len(ch["d"])
                if slot.bytes > MAX_ASSEMBLED_PAYLOAD:
                    del self._chunk_buffers[key_assembly]
                    continue
                if slot.filled < ch["n"]:
                    continue
                out = b"".join(p for p in slot.parts if p is not None)
                del self._chunk_buffers[key_assembly]
                pl = out

            try:
                d = msgpack.unpackb(pl, raw=False, strict_map_key=False)
            except Exception:
                continue
            if not isinstance(d, dict) or "r" not in d:
                continue
            self.state_hash = str(d["h"])
            s = d.get("s")
            if s is not None:
                self.substate = s if isinstance(s, bytes) else bytes(s)
            else:
                self.substate = None
            return d

    async def send(self, action: Any) -> Any:
        assert self.window_id and self.key and self._ws
        rid = new_request_id()
        pack: dict[str, Any] = {
            "h": self.state_hash,
            "a": action,
            "w": self.window_id,
        }
        if self.substate is not None:
            pack["s"] = self.substate
        payload = msgpack.packb(pack, use_bin_type=True)
        await self._send_payload(payload, rid)
        d = await self._recv_one_logical(rid)
        return d["r"]

    async def ping(self) -> bool:
        assert self.window_id and self.key and self._ws
        rid = new_request_id()
        beat = msgpack.packb({"beat": True, "w": self.window_id}, use_bin_type=True)
        await self._ws.send(encrypt(beat, self.key, rid))
        try:
            raw = await asyncio.wait_for(self._ws.recv(), timeout=5.0)
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            if len(raw) != MESSAGE_SIZE:
                return False
            _rid, pl = decrypt(raw, self.key)
            d = msgpack.unpackb(pl, raw=False, strict_map_key=False)
            return isinstance(d, dict) and d.get("beat") is True
        except Exception:
            return False

    async def close(self) -> None:
        if self._ws is not None:
            await self._ws.close()
            self._ws = None
