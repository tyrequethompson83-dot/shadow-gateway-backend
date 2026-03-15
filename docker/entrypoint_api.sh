#!/usr/bin/env sh
set -eu

python /app/docker/prestart_api.py

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec python -m uvicorn main:app --host 0.0.0.0 --port 8080
