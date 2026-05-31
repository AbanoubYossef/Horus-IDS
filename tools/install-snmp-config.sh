#!/usr/bin/env bash
# Replace the broken /etc/prometheus/snmp.yml with a complete one and reload.
set -euo pipefail
if [ "$EUID" -ne 0 ]; then echo "run with sudo" >&2; exit 1; fi

REPO=/home/bogdan/Downloads/nexus-deploy-master

cp /etc/prometheus/snmp.yml /etc/prometheus/snmp.yml.bak.$(date +%s) 2>/dev/null || true
install -m 0644 "$REPO/tools/snmp.yml" /etc/prometheus/snmp.yml

systemctl restart prometheus-snmp-exporter
sleep 3

echo "=== probe SrvSW1 (7.7.7.7) — first 12 metric lines ==="
curl -s "http://127.0.0.1:9116/snmp?module=if_mib&target=7.7.7.7&auth=utcn_v3" | grep -E "^if[A-Z]" | head -12

echo ""
echo "=== reload Prometheus to pick up next scrape immediately ==="
curl -sX POST http://127.0.0.1:9090/-/reload && echo "    Prometheus config reloaded"

echo ""
echo "==> Wait ~60s for the next scrape, then refresh the Grafana dashboard."
