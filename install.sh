#!/usr/bin/env bash
# RunAlexDB install script
# Usage: curl -fsSL https://raw.githubusercontent.com/redlemonbe/RunAlexDB/main/install.sh | bash
# Or:    bash install.sh [--prefix /usr/local] [--config /etc/runalexdb]

set -euo pipefail

BLUE='\033[0;34m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${BLUE}[RunAlexDB]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/runalexdb}"
DATA_DIR="${DATA_DIR:-/var/lib/runalexdb}"
SERVICE_USER="${SERVICE_USER:-runalexdb}"
VERSION="${VERSION:-latest}"

REPO="https://github.com/redlemonbe/RunAlexDB"
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

[[ "$OS" != "linux" ]] && err "Only Linux is supported."
[[ $(id -u) -ne 0 ]] && err "Must be run as root."

case "$ARCH" in
    x86_64)  ARCH_ID="x86_64"  ;;
    aarch64) ARCH_ID="aarch64" ;;
    arm64)   ARCH_ID="aarch64" ;;
    *)       err "Unsupported architecture: $ARCH" ;;
esac

if ldd --version 2>&1 | grep -qi musl 2>/dev/null; then
    LIBC="musl"
else
    LIBC="gnu"
fi

info "Installing RunAlexDB $VERSION ($ARCH_ID-$LIBC)"

if [[ "$VERSION" == "latest" ]]; then
    BINARY_URL="$REPO/releases/latest/download/runalexdb-${ARCH_ID}-linux-${LIBC}"
else
    BINARY_URL="$REPO/releases/download/$VERSION/runalexdb-${ARCH_ID}-linux-${LIBC}"
fi

info "Downloading from $BINARY_URL"
TMP=$(mktemp)
if command -v curl >/dev/null; then
    curl -fsSL --progress-bar -o "$TMP" "$BINARY_URL"
elif command -v wget >/dev/null; then
    wget -q --show-progress -O "$TMP" "$BINARY_URL"
else
    err "curl or wget required"
fi
chmod +x "$TMP"
mv "$TMP" "$PREFIX/bin/runalexdb"
ok "Binary installed to $PREFIX/bin/runalexdb"

# Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "Created service user: $SERVICE_USER"
fi

# Create directories
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$DATA_DIR/backups"
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$DATA_DIR/backups"
ok "Directories created"

# Write default config if none exists
if [[ ! -f "$CONFIG_DIR/runalexdb.toml" ]]; then
    ROOT_PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c 24)
    WEBUI_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c 40)
    MYSQL_PORT=3306
    WEBUI_PORT=8306
    cat > "$CONFIG_DIR/runalexdb.toml" << CONF
mysql_port = $MYSQL_PORT
webui_port = $WEBUI_PORT
bind       = "0.0.0.0"
data_dir   = "$DATA_DIR"

[auth]
root_password = "$ROOT_PASSWORD"
webui_api_key = "$WEBUI_KEY"

[xdp]
enabled = false
CONF
    chown root:root "$CONFIG_DIR/runalexdb.toml"
    chmod 640 "$CONFIG_DIR/runalexdb.toml"
    ok "Default config written to $CONFIG_DIR/runalexdb.toml"
    info "Root password : $ROOT_PASSWORD"
    info "Web UI API key: $WEBUI_KEY"
    info "Keep them safe — they are in $CONFIG_DIR/runalexdb.toml"
else
    info "Config already exists at $CONFIG_DIR/runalexdb.toml — skipping."
fi

# Write systemd unit
cat > /etc/systemd/system/runalexdb.service << UNIT
[Unit]
Description=RunAlexDB — In-memory SQL database, MariaDB-compatible
Documentation=https://github.com/redlemonbe/RunAlexDB
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$PREFIX/bin/runalexdb $CONFIG_DIR/runalexdb.toml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable runalexdb
ok "systemd unit installed and enabled"

if systemctl start runalexdb; then
    ok "RunAlexDB started"
    echo
    echo -e "${GREEN}Installation complete!${NC}"
    echo -e "  Status:   systemctl status runalexdb"
    echo -e "  Logs:     journalctl -u runalexdb -f"
    echo -e "  MySQL:    mysql -h 127.0.0.1 -P 3306 -u root -p"
    echo -e "  Web UI:   http://YOUR_SERVER:8306"
    echo -e "  Config:   $CONFIG_DIR/runalexdb.toml"
else
    warn "Service failed to start. Check: journalctl -u runalexdb"
fi
