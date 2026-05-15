#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${HOME}/network-thesis-GIT/src"
CONFIG_DIR="${HOME}/network-thesis-GIT/config"
RAW_DIR="${HOME}/network-thesis-GIT/windows_security_log"
STATE_DIR="${HOME}/network-thesis-GIT/state"
SYSTEMD_DIR="/etc/systemd/system"
ENV_FILE="${CONFIG_DIR}/windows_event_receiver.env"
TOKEN="${1:-${WINDOWS_LOG_TOKEN:-}}"
CURRENT_USER="$(id -un)"
PYTHON_BIN="$(command -v python3)"

mkdir -p "$SRC_DIR" "$CONFIG_DIR" "$RAW_DIR" "$STATE_DIR"

OLD_DIR="${HOME}/network-thesis-GIT/widows_security_log"
if [ -d "$OLD_DIR" ]; then
  echo "Rastas senas katalogas: $OLD_DIR"
  echo "Kopijuojami seni failai į: $RAW_DIR"
  rsync -a "$OLD_DIR/" "$RAW_DIR/" 2>/dev/null || cp -a "$OLD_DIR/." "$RAW_DIR/"
fi

if [ -z "$TOKEN" ]; then
  if command -v openssl >/dev/null 2>&1; then
    TOKEN="$(openssl rand -hex 24)"
  else
    TOKEN="$($PYTHON_BIN -c 'import secrets; print(secrets.token_hex(24))')"
  fi
fi

cat > "$ENV_FILE" <<EOF
WINDOWS_LOG_TOKEN=$TOKEN
WINDOWS_LOG_RECEIVER_HOST=0.0.0.0
WINDOWS_LOG_RECEIVER_PORT=8765
WINDOWS_SECURITY_LOG_DIR=$RAW_DIR
WINDOWS_EVENT_LOOKBACK_DAYS=1
WINDOWS_EVENT_STATE_RETENTION_DAYS=14
WINDOWS_EVENT_AI_MAX_EVENTS=500
WINDOWS_EVENT_NORMALIZER_MODE=context
EOF
chmod 600 "$ENV_FILE"

sudo tee "$SYSTEMD_DIR/network-thesis-windows-event-receiver.service" >/dev/null <<EOF
[Unit]
Description=Network Thesis Windows Security Event Receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$SRC_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$PYTHON_BIN $SRC_DIR/windows_event_receiver.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Svarbu: normalizavimas nebeleistas kaip periodinis servisas.
# Raw logus priima receiver, o normalizavimą paleidžia full_assessment.py,
# kad Windows kontekstas patektų į bendrą AI rekomendacijų paketą.
sudo systemctl disable --now network-thesis-windows-event-normalizer.timer >/dev/null 2>&1 || true
sudo systemctl disable --now network-thesis-windows-event-normalizer.service >/dev/null 2>&1 || true

sudo systemctl daemon-reload
sudo systemctl enable --now network-thesis-windows-event-receiver.service

COLLECTOR_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

cat <<EOF

Automatizavimas Kali pusėje įjungtas.

Receiver service:
  sudo systemctl status network-thesis-windows-event-receiver.service

Normalizer:
  periodinis normalizavimo timeris išjungtas; normalizuoja full_assessment.py

Raw log katalogas:
  $RAW_DIR/YYYY-MM-DD/<ip_adresas>_YYYY-MM-DD_security_log.jsonl

Collector URL Windows skriptui:
  http://${COLLECTOR_IP:-KALI_IP}:8765/ingest/windows-security

Token išsaugotas faile:
  $ENV_FILE

Token reikšmė:
  $TOKEN

EOF
