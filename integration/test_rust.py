import asyncio

import pytest

from sira_test_client import MESSAGE_SIZE, SiraTestClient

SERVER_PORT = 3000


@pytest.mark.asyncio
async def test_handshake():
    c = SiraTestClient(f"http://127.0.0.1:{SERVER_PORT}")
    await c.connect()
    assert c.key is not None
    await c.close()


@pytest.mark.asyncio
async def test_echo_roundtrip():
    c = SiraTestClient(f"http://127.0.0.1:{SERVER_PORT}")
    await c.connect()
    render = await c.send({"type": "echo", "data": "hello sira"})
    assert render is not None
    assert render.get("echo") == {"type": "echo", "data": "hello sira"}
    await c.close()


@pytest.mark.asyncio
async def test_multi_send():
    c = SiraTestClient(f"http://127.0.0.1:{SERVER_PORT}")
    await c.connect()
    for i in range(5):
        render = await c.send({"type": "echo", "seq": i})
        assert render is not None
    await c.close()


@pytest.mark.asyncio
async def test_heartbeat():
    c = SiraTestClient(f"http://127.0.0.1:{SERVER_PORT}")
    await c.connect()
    assert await c.ping() is True
    await c.close()


@pytest.mark.asyncio
async def test_invalid_size_gets_noise():
    c = SiraTestClient(f"http://127.0.0.1:{SERVER_PORT}")
    await c.connect()
    await c._ws.send(bytes(512))
    raw = await asyncio.wait_for(c._ws.recv(), timeout=5.0)
    assert len(raw) == MESSAGE_SIZE
    render = await c.send({"type": "echo"})
    assert render is not None
    await c.close()


@pytest.mark.asyncio
async def test_persistent_mode():
    c = SiraTestClient(f"http://127.0.0.1:{SERVER_PORT}")
    await c.connect(persistent=True)
    render = await c.send({"type": "echo"})
    assert render is not None
    await c.close()


@pytest.mark.asyncio
async def test_large_payload_chunking():
    c = SiraTestClient(f"http://127.0.0.1:{SERVER_PORT}")
    await c.connect()
    large_data = "x" * 5000
    render = await c.send({"type": "echo", "data": large_data})
    assert render is not None
    assert render.get("echo", {}).get("data") == large_data
    await c.close()
