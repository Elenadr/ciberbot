#!/usr/bin/env bash
# Lanzador para cron: actualiza el código desde GitHub y ejecuta el bot.
set -euo pipefail
cd "$(dirname "$0")"

# Trae los cambios que hayas hecho en GitHub (feeds, prompt...). Si falla, sigue con lo que hay.
git pull --quiet --ff-only || echo "$(date '+%F %T') aviso: git pull falló, uso la versión local"

./.venv/bin/python main.py
