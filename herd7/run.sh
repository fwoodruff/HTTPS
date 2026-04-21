#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v opam &>/dev/null; then
    eval "$(opam env 2>/dev/null)" || true; 
fi

out=$(herd7 -model rc11.cat "$SCRIPT_DIR"/*.litmus)
printf '%s\n' "$out"

if printf '%s\n' "$out" | grep -qx 'Ok'; then 
    exit 1;
fi
