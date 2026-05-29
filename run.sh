#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -d .venv ]]; then
  python3.12 -m venv .venv
  .venv/bin/pip install -r requirements.txt
fi

# shellcheck disable=SC1091
source .venv/bin/activate

[[ -f .env ]] || cp .env.example .env

# Only watch app/ — avoids reload storms from .venv and SQLite lock issues
exec uvicorn app.main:app --reload --reload-dir app --port 8000
