#!/usr/bin/env bash
# One-time setup: virtualenv + dependencies (a few seconds).   ./setup.sh   then use .venv/bin/python
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
[ -d .venv ] || "${PYTHON:-python3}" -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt
echo "venv ok: $(.venv/bin/python -V)"
