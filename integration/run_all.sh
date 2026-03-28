#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

export SIRA_MASTER_SECRET="${SIRA_MASTER_SECRET:-$(openssl rand -hex 32)}"
export SIRA_PORT=3000

cleanup() {
  kill "${RUST_PID:-}" "${PYTHON_PID:-}" "${NODE_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT

free_port() {
  local p="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -ti:"$p" 2>/dev/null | xargs kill -9 2>/dev/null || true
  fi
}
for p in 3000 3001 3002; do free_port "$p"; done
sleep 1

echo "Building Rust server..."
(cd "$ROOT" && cargo build --bin sira)

echo "Starting Rust server on 3000..."
"$ROOT/target/debug/sira" &
RUST_PID=$!
sleep 2

echo "Starting Python server on 3001..."
python "$ROOT/sira-python/example/echo_server.py" --port 3001 &
PYTHON_PID=$!
sleep 2

echo "Starting Node server on 3002..."
node "$ROOT/sira-node/example/echo.js" --port 3002 &
NODE_PID=$!
sleep 2

echo "Running integration tests..."
pip install -q -e "$ROOT/sira-python" httpx websockets pytest pytest-asyncio
cd "$SCRIPT_DIR"
PYTHONPATH="$ROOT/sira-python" pytest -c pytest.ini -v \
  test_rust.py test_python.py test_node.py test_cross_language.py

echo "Stopping servers..."
cleanup
trap - EXIT

echo "All integration tests passed."
