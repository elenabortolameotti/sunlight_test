#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Sunlight Staging Real-World Demo ==="
echo ""

# Start server in background
echo "Starting server..."
../sunlight -c sunlight.yaml &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null || true; wait $SERVER_PID 2>/dev/null || true" EXIT

sleep 2

echo "Running client..."
go run demo-client.go http://localhost:8080/ctlog demo
