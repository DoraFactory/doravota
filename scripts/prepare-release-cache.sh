#!/usr/bin/env bash
# All 1.0.0 dependencies are public. No private security-fork cache is required.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/verify-wasmd-snapshot.py
go mod download
go mod verify
