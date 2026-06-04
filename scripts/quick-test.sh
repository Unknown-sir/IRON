#!/usr/bin/env bash
set -euo pipefail
python3 -m py_compile iron.py
python3 iron.py token >/dev/null
printf 'OK: syntax and token generation passed\n'
