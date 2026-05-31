#!/usr/bin/env bash
# systemd/install.sh — Switch from disk collectors to nexus capture service.
# Run with sudo on the IDS host.

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (use sudo)." >&2
  exit 1
fi

REPO="/home/bogdan/Downloads/nexus-deploy-master"
SYSDIR="/etc/systemd/system"

echo "==> Stopping foreground API (if any) so nexus-api.service can take 8000"
pkill -f "uvicorn api:app" 2>/dev/null || true
sleep 1

echo "==> Stopping conflicting collectors"
for svc in nfcapd rspan-capture rsyslog snmptrapd; do
  if systemctl is-active --quiet "$svc"; then
    systemctl stop "$svc"
    echo "    stopped $svc"
  fi
done

echo "==> Installing unit files"
install -m 0644 "$REPO/systemd/nexus-api.service"     "$SYSDIR/nexus-api.service"
install -m 0644 "$REPO/systemd/nexus-capture.service" "$SYSDIR/nexus-capture.service"

systemctl daemon-reload

echo "==> Enabling + starting nexus-api"
systemctl enable --now nexus-api.service

echo "==> Waiting for /health"
for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf http://127.0.0.1:8000/health >/dev/null; then
    echo "    /health OK"
    break
  fi
  sleep 1
done

echo "==> Enabling + starting nexus-capture"
systemctl enable --now nexus-capture.service

sleep 3

echo ""
echo "=== STATUS ==="
systemctl --no-pager --lines=0 status nexus-api.service     | head -3
systemctl --no-pager --lines=0 status nexus-capture.service | head -3

echo ""
echo "=== UDP LISTENERS (162/514/2055) — should now be the venv python ==="
ss -lunp 2>/dev/null | grep -E ":(162|514|2055) " | sort -u

echo ""
echo "==> Done. Tail logs with: journalctl -fu nexus-capture.service"
