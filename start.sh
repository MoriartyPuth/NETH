#!/bin/sh
# NETH entrypoint: run the Telegram bot (if a token is set) alongside the web app.
set -e

if [ -n "$NETH_TELEGRAM_TOKEN" ]; then
  echo "[neth] starting Telegram bot (background, auto-restart)…"
  ( while true; do
      python -m neth.bot || echo "[neth] bot exited ($?), restarting in 5s…"
      sleep 5
    done ) &
else
  echo "[neth] NETH_TELEGRAM_TOKEN not set — bot disabled, web only."
fi

echo "[neth] starting web app on :${PORT:-8080}…"
exec uvicorn neth.api:app --host 0.0.0.0 --port "${PORT:-8080}"
