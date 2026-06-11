#!/usr/bin/env bash
# scripts/start-dev.sh — Inicia daemon + Electron em modo desenvolvimento
set -euo pipefail

echo "[Dev] Iniciando daemon de rede..."
node src/network/node.js &
DAEMON_PID=$!

echo "[Dev] Daemon PID: $DAEMON_PID"
echo "[Dev] Iniciando Electron..."
electron .

echo "[Dev] Encerrando daemon..."
kill "$DAEMON_PID" 2>/dev/null || true
