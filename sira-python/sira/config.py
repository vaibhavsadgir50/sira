"""Master secret and optional revocation (match sira Rust config.rs)."""

from __future__ import annotations

import os
from pathlib import Path


def load_master_secret_from_env() -> bytes:
    """Load SIRA_MASTER_SECRET: 64 hex chars → 32 bytes. Raises if invalid or unset."""
    raw = os.environ.get("SIRA_MASTER_SECRET")
    if not raw:
        raise RuntimeError(
            "SIRA_MASTER_SECRET must be set to 64 hex characters (32 bytes)"
        )
    h = raw.strip()
    if len(h) != 64:
        raise ValueError("SIRA_MASTER_SECRET must be exactly 64 hex characters")
    return bytes.fromhex(h)


class RevocationState:
    """SIRA_REVOCATION_STORE: file of unix timestamps; tokens with created_at <= max are rejected."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._cutoff = 0
        self.reload()

    @classmethod
    def from_env(cls) -> RevocationState | None:
        p = os.environ.get("SIRA_REVOCATION_STORE", "").strip()
        if not p:
            return None
        return cls(p)

    def reload(self) -> None:
        self._cutoff = read_revocation_cutoff(self.path)

    def is_revoked(self, created_at: int) -> bool:
        c = self._cutoff
        return c > 0 and created_at <= c


def read_revocation_cutoff(path: Path) -> int:
    if not path.is_file():
        return 0
    m = 0
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = max(m, int(line))
    return m
