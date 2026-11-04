#!/usr/bin/env bash
# Install cert-uploader on the server (root not required).
#
#   ./deploy/install.sh [--app-dir DIR] [--config-dir DIR] [--no-systemd]
#
# Defaults: app -> /opt/cert-uploader, config -> /etc/cert-uploader.
# Without root (or with --no-systemd) it prints a crontab line instead.
set -euo pipefail

APP_DIR="/opt/cert-uploader"
CONFIG_DIR="/etc/cert-uploader"
NO_SYSTEMD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --app-dir) APP_DIR="$2"; shift 2 ;;
    --config-dir) CONFIG_DIR="$2"; shift 2 ;;
    --no-systemd) NO_SYSTEMD=1; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

SRC_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

echo "[1/5] copying sources to $APP_DIR"
mkdir -p "$APP_DIR"
tar -C "$SRC_DIR" \
  --exclude=./vendor --exclude=./.venv --exclude=./.git \
  --exclude='./state.json*' --exclude='__pycache__' --exclude='./config.toml' \
  -cf - . | tar -C "$APP_DIR" -xf -
chmod +x "$APP_DIR/bin/cert-uploader"

echo "[2/5] installing Python dependencies"
if python3 -m venv "$APP_DIR/.venv" 2>/dev/null; then
  "$APP_DIR/.venv/bin/pip" install --quiet 'oss2>=2.18,<3' 'cryptography>=41'
  echo "  using virtualenv $APP_DIR/.venv"
else
  # Debian 12 marks system pip EXTERNALLY-MANAGED and python3-venv may be absent;
  # --target installs are still allowed.
  pip3 install --quiet --target "$APP_DIR/vendor" \
    -i https://mirrors.aliyun.com/pypi/simple/ 'oss2>=2.18,<3' 'cryptography>=41'
  echo "  using vendor directory $APP_DIR/vendor"
fi

echo "[3/5] preparing config"
if ! mkdir -p "$CONFIG_DIR" 2>/dev/null; then
  CONFIG_DIR="$APP_DIR/config"
  mkdir -p "$CONFIG_DIR"
fi
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
  cp "$APP_DIR/config.example.toml" "$CONFIG_DIR/config.toml"
  chmod 600 "$CONFIG_DIR/config.toml"
  echo "  created $CONFIG_DIR/config.toml - EDIT IT NOW (region, targets, credentials)"
else
  echo "  keeping existing $CONFIG_DIR/config.toml"
fi

echo "[4/5] self check"
"$APP_DIR/bin/cert-uploader" --config "$CONFIG_DIR/config.toml" doctor || true

echo "[5/5] scheduling"
if [ "$(id -u)" = "0" ] && [ "$NO_SYSTEMD" = "0" ] && command -v systemctl >/dev/null 2>&1; then
  install -m 644 "$APP_DIR/deploy/cert-uploader.service" /etc/systemd/system/
  install -m 644 "$APP_DIR/deploy/cert-uploader.timer" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now cert-uploader.timer
  echo "  systemd timer installed: systemctl status cert-uploader.timer"
else
  echo "  add this line to crontab (crontab -e):"
  echo "  7,22,37,52 * * * * $APP_DIR/bin/cert-uploader sync --config $CONFIG_DIR/config.toml >> $APP_DIR/sync.log 2>&1"
fi

echo "done. next steps:"
echo "  1. edit $CONFIG_DIR/config.toml"
echo "  2. export OSS_ACCESS_KEY_ID / OSS_ACCESS_KEY_SECRET (or an env file for systemd)"
echo "  3. $APP_DIR/bin/cert-uploader --config $CONFIG_DIR/config.toml sync --dry-run"
