#!/bin/bash
# Thin wrapper: source .env (if present) and exec the Python importer.
# Run `./scanimport.sh --help` for usage.
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$SCRIPT_DIR/.env" ] && set -a && . "$SCRIPT_DIR/.env" && set +a
exec "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/tools/import_scan.py" "$@"
