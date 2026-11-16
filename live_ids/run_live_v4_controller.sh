#!/bin/bash
set -euo pipefail

# Run the GitHub publication layout without hardcoded usernames or lab IPs.
REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export AI_IDS_PROJECT_ROOT="${AI_IDS_PROJECT_ROOT:-$REPO_ROOT}"
: "${AI_IDS_V4_SERVICE_IP:?Set AI_IDS_V4_SERVICE_IP to the inference service address}"
export AI_IDS_V4_SERVICE_PORT="${AI_IDS_V4_SERVICE_PORT:-9105}"
export PYTHONUNBUFFERED=1

mkdir -p "$AI_IDS_PROJECT_ROOT/simple_ids/reports"
# exec preserves the PID for a process supervisor.
echo $$ > "$AI_IDS_PROJECT_ROOT/simple_ids/reports/live_v4_controller.pid"

echo "Starting V4 controller; inference port: $AI_IDS_V4_SERVICE_PORT"
cd "$REPO_ROOT"
exec "${AI_IDS_PYTHON:-python3}" -m live_ids.live_v4_controller
