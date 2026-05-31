#!/usr/bin/env bash
# capture/start.sh — Start the Nexus capture service
#
# Must run as root (nfstream requires raw packet capture privileges).
# All traffic goes out eth0; eth1 is read-only capture only.
#
# Usage:
#   sudo SYSLOG_SERVER=10.40.0.x ./start.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Activate the project virtualenv
source "$PROJECT_DIR/.venv/bin/activate"

# Defaults (override by exporting these before calling the script)
export NEXUS_API_URL="${NEXUS_API_URL:-http://127.0.0.1:8000}"
export NEXUS_API_KEY="${NEXUS_API_KEY:-}"
export CAPTURE_IFACE="${CAPTURE_IFACE:-eth1}"
export MGMT_IFACE="${MGMT_IFACE:-eth0}"
export SYSLOG_SERVER="${SYSLOG_SERVER:-127.0.0.1}"
export SYSLOG_PORT="${SYSLOG_PORT:-514}"
export BATCH_SIZE="${BATCH_SIZE:-100}"
export BATCH_TIMEOUT_S="${BATCH_TIMEOUT_S:-2.0}"
export ALERT_MIN_SEVERITY="${ALERT_MIN_SEVERITY:-medium}"
export LOG_LEVEL="${LOG_LEVEL:-INFO}"

echo "=== Nexus Capture Service ==="
echo "  Capture interface : $CAPTURE_IFACE  (read-only RSPAN mirror)"
echo "  Mgmt interface    : $MGMT_IFACE     (all outbound traffic)"
echo "  Nexus API         : $NEXUS_API_URL"
echo "  Syslog server     : $SYSLOG_SERVER:$SYSLOG_PORT"
echo "  Batch size        : $BATCH_SIZE flows / ${BATCH_TIMEOUT_S}s"
echo "  Min alert sev     : $ALERT_MIN_SEVERITY"
echo ""

# Verify Nexus API is reachable before starting capture
if ! curl -sf "$NEXUS_API_URL/health" > /dev/null 2>&1; then
    echo "ERROR: Nexus API not reachable at $NEXUS_API_URL"
    echo "       Start the API first: cd $PROJECT_DIR && uvicorn api:app"
    exit 1
fi
echo "  Nexus API health  : OK"
echo ""

cd "$SCRIPT_DIR"
exec python flow_capture.py
