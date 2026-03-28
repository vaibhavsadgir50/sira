import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sira-python"))

from sira_test_client import SiraTestClient


async def main() -> None:
    port = int(os.environ.get("SIRA_DEBUG_PORT", "3000"))
    c = SiraTestClient(f"http://127.0.0.1:{port}")
    await c.connect()
    print("window", c.window_id)
    print("hash", c.state_hash[:20])
    r = await asyncio.wait_for(
        c.send({"type": "echo", "data": "x"}), timeout=15.0
    )
    print("render", r)
    await c.close()


if __name__ == "__main__":
    asyncio.run(main())
