#!/usr/bin/env bash
# RunAlexDB install script — installs binary, config, systemd unit.
# Usage: curl -fsSL https://raw.githubusercontent.com/redlemonbe/RunAlexDB/main/install.sh | sudo bash
# Or:    bash install.sh [--prefix /usr/local] [--config /etc/runalexdb]

set -euo pipefail

BLUE='\033[0;34m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${BLUE}[RunAlexDB]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/runalexdb}"
LOG_DIR="${LOG_DIR:-/var/log/runalexdb}"
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

if ldd --version 2>&1 | grep -qi musl; then
    LIBC="musl"
elif command -v ldd >/dev/null && ldd --version 2>&1 | grep -qi GLIBC; then
    LIBC="gnu"
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
install -Dm755 "$TMP" "$PREFIX/bin/runalexdb"
rm -f "$TMP"
ok "Binary installed to $PREFIX/bin/runalexdb"

# Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "Created system user $SERVICE_USER"
fi

mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR" "$DATA_DIR" 2>/dev/null || true

if [[ ! -f "$CONFIG_DIR/runalexdb.toml" ]]; then
    ROOT_PASS=$(head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)
    API_KEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    cat > "$CONFIG_DIR/runalexdb.toml" << CONF
# RunAlexDB configuration
# Documentation: https://github.com/redlemonbe/RunAlexDB

mysql_port = 3306
webui_port = 8306
bind       = "127.0.0.1"
data_dir   = "$DATA_DIR"

firewall_manage  = true
firewall_backend = "auto"
firewall_tag     = "runalexdb"

[auth]
root_password = "$ROOT_PASS"
webui_api_key = "$API_KEY"
CONF
    ok "Default config written to $CONFIG_DIR/runalexdb.toml"
    info "Root password: $ROOT_PASS"
    info "Web UI API key: $API_KEY"
    info "Keep these safe — also stored in $CONFIG_DIR/runalexdb.toml"
else
    info "Config already exists at $CONFIG_DIR/runalexdb.toml — skipping."
fi

cat > /etc/systemd/system/runalexdb.service << UNIT
[Unit]
Description=RunAlexDB — In-memory SQL database (MySQL wire protocol)
Documentation=https://github.com/redlemonbe/RunAlexDB
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$PREFIX/bin/runalexdb --config $CONFIG_DIR/runalexdb.toml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$LOG_DIR $DATA_DIR $CONFIG_DIR

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable runalexdb
ok "systemd unit installed and enabled"

if systemctl start runalexdb; then
    ok "RunAlexDB started successfully"
    VERSION_OUT=$("$PREFIX/bin/runalexdb" --version 2>/dev/null || echo "runalexdb v0.1.1")
    echo
    printf '%s\n' "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf " Version:  %s\n" "$VERSION_OUT"
    printf " MySQL:    mysql -h 127.0.0.1 -u root -p (port 3306)\n"
    printf " Web UI:   http://YOUR_SERVER:8306\n"
    printf " Config:   %s\n" "$CONFIG_DIR/runalexdb.toml"
    printf " Logs:     journalctl -u runalexdb -f\n"
    printf '%s\n' "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    warn "Service failed to start. Check: journalctl -u runalexdb"
fi
