#!/usr/bin/env bash
# All 1.0.0 dependencies are public. No private security-fork cache is required.
set -euo pipefail
cd "$(dirname "$0")/.."
go mod download
go mod verify
