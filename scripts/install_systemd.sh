#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_NAME="${SUDO_USER:-$(whoami)}"

echo "[*] Installing ThreatLocker Zero Trust Production Services from ${INSTALL_DIR}..."

sudo tee /etc/systemd/system/threatlocker-zt.service >/dev/null <<EOF
[Unit]
Description=ThreatLocker Zero Trust Control Plane & Production WSGI Server
After=network-online.target ollama.service
Wants=network-online.target

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${INSTALL_DIR}/server
Environment="TL_PORT=9443"
Environment="OLLAMA_URL=http://127.0.0.1:11434"
Environment="OLLAMA_MODEL=qwen3-hermes:latest"
ExecStart=/usr/bin/gunicorn --workers 4 --threads 4 --bind 0.0.0.0:9443 --timeout 90 app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/threatlocker-agent.service >/dev/null <<EOF
[Unit]
Description=ThreatLocker Zero Trust Linux Endpoint Agent
After=threatlocker-zt.service
Requires=threatlocker-zt.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/agents/linux
Environment="TL_SERVER_URL=http://127.0.0.1:9443"
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/agents/linux/tl_agent_linux.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now threatlocker-zt.service
sudo systemctl enable --now threatlocker-agent.service

if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow 9443/tcp comment 'ThreatLocker Zero Trust Portal' || true
fi

echo "[+] ThreatLocker Zero Trust Production Platform is active on port 9443!"
