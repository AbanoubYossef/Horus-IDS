#!/usr/bin/env bash
# Enable and start the OpenSSH server so the NEXUS SOC host is reachable
# via SSH (e.g. from your laptop into the EVE-NG VM running NEXUS).
#
# Usage:
#   sudo ./tools/enable-ssh.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Re-running with sudo..."
    exec sudo -E "$0" "$@"
fi

SSH_PORT="${SSH_PORT:-22}"

log() { printf '\033[1;34m[ssh-setup]\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m[  ok  ]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[ warn ]\033[0m %s\n' "$*"; }

# 1. Install openssh-server if not present
if ! dpkg -s openssh-server >/dev/null 2>&1; then
    log "openssh-server not installed — installing..."
    apt-get update -y
    apt-get install -y openssh-server
    ok "openssh-server installed"
else
    ok "openssh-server already installed"
fi

# 2. Enable + start the service (Ubuntu 24.04 uses ssh.socket for activation)
log "Enabling ssh.socket and ssh.service at boot"
systemctl enable ssh.socket >/dev/null 2>&1 || true
systemctl enable ssh.service >/dev/null 2>&1 || true

log "Starting SSH"
systemctl start ssh.socket >/dev/null 2>&1 || true
systemctl start ssh.service

# 3. Open the firewall if ufw is active
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        log "ufw is active — allowing port ${SSH_PORT}/tcp"
        ufw allow "${SSH_PORT}/tcp" >/dev/null
        ok "ufw rule added"
    else
        warn "ufw installed but inactive — skipping firewall rule"
    fi
fi

# 4. Verify it's listening
if ss -tln | awk '{print $4}' | grep -qE "(:|\.)${SSH_PORT}\$"; then
    ok "SSH is listening on port ${SSH_PORT}"
else
    warn "SSH does not appear to be listening on port ${SSH_PORT}"
    systemctl --no-pager status ssh.service || true
    exit 1
fi

# 5. Print connection info
USER_NAME="${SUDO_USER:-$(id -un)}"
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
mapfile -t IPS < <(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)

echo
ok "SSH is active. Connect with one of:"
echo "    ssh ${USER_NAME}@${HOSTNAME_FQDN}"
for ip in "${IPS[@]}"; do
    echo "    ssh ${USER_NAME}@${ip}"
done
echo
log "First-time login uses your Linux password. To use a key instead, run on your client:"
echo "    ssh-copy-id ${USER_NAME}@${IPS[0]:-<host>}"
