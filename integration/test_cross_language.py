"""Same CLsend → compare `r` shape and `echo` payload across all three echo servers."""

import pytest

from sira_test_client import SiraTestClient


@pytest.mark.asyncio
async def test_echo_identical_across_servers():
    action = {"type": "interop", "n": 42}
    renders = []
    for port in (3000, 3001, 3002):
        c = SiraTestClient(f"http://127.0.0.1:{port}")
        await c.connect()
        r = await c.send(action)
        await c.close()
        renders.append(r)
    e0, e1, e2 = [x.get("echo") for x in renders]
    assert e0 == e1 == e2 == action
    for r in renders:
        assert r.get("message") == "SIRA is working"
        assert "session" in r and "window" in r
        assert r.get("user_id") is None
