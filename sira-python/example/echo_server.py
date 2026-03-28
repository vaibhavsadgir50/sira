from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Allow running without pip install -e
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sira import Pipeline, SiraServer


class EchoPipeline(Pipeline):
    async def process(self, action, session_id, window_id, user_id):
        n = min(16, len(session_id))
        return {
            "echo": action,
            "session": session_id[:n],
            "window": window_id,
            "user_id": user_id,
            "message": "SIRA is working",
        }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    secret = os.environ.get("SIRA_MASTER_SECRET", "").strip()
    if len(secret) != 64:
        print("Set SIRA_MASTER_SECRET to 64 hex chars", file=sys.stderr)
        sys.exit(1)
    server = SiraServer(
        pipeline=EchoPipeline(),
        master_secret=bytes.fromhex(secret),
        host=args.host,
        port=args.port,
    )
    print(f"SIRA Python server running on http://localhost:{args.port}")
    server.run()
