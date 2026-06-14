#!/usr/bin/env bash
# setup_vps.sh — run this once on a fresh Oracle Cloud (or any Ubuntu 22+) VPS
# Usage:  bash setup_vps.sh
# IMPORTANT: run as the default ubuntu user (NOT root) so paths are correct.
set -euo pipefail

echo "============================================"
echo "  THREATSCOPE — VPS setup script"
echo "============================================"

# ── 1. Move SSH to port 49222 ─────────────────────────────────────────────────
# We do this first so the honeypot can own port 22.
# Your current session stays alive; sshd restart does NOT drop open connections.
echo "[1/6] Moving SSH to port 49222 ..."
sudo sed -i 's/^#\?Port .*/Port 49222/' /etc/ssh/sshd_config
sudo systemctl restart ssh
echo "      SSH is now on 49222. BEFORE closing this session open a second"
echo "      terminal and confirm:  ssh -p 49222 ubuntu@<your-ip>"
echo ""
read -rp "      Press ENTER once you have confirmed the new SSH port works: "

# ── 2. Open firewall ports (host layer) ──────────────────────────────────────
# OCI Ubuntu ships with iptables rules that block everything above port 22.
# We insert ACCEPT rules above the REJECT rule (position 6 on a stock image).
echo "[2/6] Opening honeypot + dashboard ports in iptables ..."
for p in 49222 23 80 443 2222 3389 5900 8080 8000; do
    sudo iptables -I INPUT 6 -p tcp --dport "$p" -j ACCEPT
done
sudo apt-get install -y -q netfilter-persistent
sudo netfilter-persistent save
echo "      Host firewall rules saved."

# ── 3. Install Python 3 + pip ─────────────────────────────────────────────────
echo "[3/6] Installing Python 3 and pip ..."
sudo apt-get update -q
sudo apt-get install -y -q python3 python3-pip python3-venv git

# ── 4. Clone repo & install Python deps ──────────────────────────────────────
REPO_DIR="$HOME/attack-map"
if [ -d "$REPO_DIR" ]; then
    echo "[4/6] $REPO_DIR already exists — pulling latest ..."
    git -C "$REPO_DIR" pull
else
    echo "[4/6] Cloning repo ..."
    # Replace the URL below with your actual repo URL if you've pushed it:
    git clone https://github.com/YOUR_USERNAME/attack-map.git "$REPO_DIR"
fi
cd "$REPO_DIR"
python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt
echo "      Python environment ready."

# ── 5. (Optional) Set threat-intel keys ──────────────────────────────────────
echo "[5/6] Threat-intel keys (press ENTER to skip either one) ..."
read -rp "      ABUSEIPDB_KEY (leave blank to skip): " ABUSEIPDB_KEY
read -rp "      GREYNOISE_KEY  (leave blank to skip): " GREYNOISE_KEY

ENV_FILE="$REPO_DIR/.env"
{
  echo "EVENTS_FILE=$REPO_DIR/events.jsonl"
  [ -n "$ABUSEIPDB_KEY" ] && echo "ABUSEIPDB_KEY=$ABUSEIPDB_KEY"
  [ -n "$GREYNOISE_KEY"  ] && echo "GREYNOISE_KEY=$GREYNOISE_KEY"
} > "$ENV_FILE"
echo "      Keys written to $ENV_FILE"

# ── 6. Create systemd services ────────────────────────────────────────────────
echo "[6/6] Installing systemd services ..."

# honeypot service (needs root to bind ports <1024)
sudo tee /etc/systemd/system/threatscope-sensor.service > /dev/null <<EOF
[Unit]
Description=ThreatScope Honeypot Sensor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$REPO_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$REPO_DIR/.venv/bin/python3 $REPO_DIR/honeypot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# dashboard / pipeline service
sudo tee /etc/systemd/system/threatscope-dashboard.service > /dev/null <<EOF
[Unit]
Description=ThreatScope Dashboard & Pipeline
After=network.target threatscope-sensor.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=$REPO_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$REPO_DIR/.venv/bin/uvicorn server:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now threatscope-sensor
sudo systemctl enable --now threatscope-dashboard

echo ""
echo "============================================"
echo "  Setup complete!"
echo ""
echo "  Dashboard:  http://$(curl -s https://api.ipify.org):8000"
echo ""
echo "  Status:"
echo "    sudo systemctl status threatscope-sensor"
echo "    sudo systemctl status threatscope-dashboard"
echo ""
echo "  Logs:"
echo "    sudo journalctl -fu threatscope-sensor"
echo "    sudo journalctl -fu threatscope-dashboard"
echo "============================================"
