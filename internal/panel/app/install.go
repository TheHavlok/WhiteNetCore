package app

import (
	"net/http"
	"strings"
	"text/template"
)

// installTemplate is the script a node runs. It is a template rather than a
// static file so the panel can bake its own URL into it: the agent binary and
// the Xray release are fetched from the panel, not from the internet at large,
// which means a node only has to be able to reach the panel.
var installTemplate = template.Must(template.New("install.sh").Parse(installScript))

type installData struct {
	PanelURL string
}

// handleInstallScript serves the installer.
//
// It is public and carries no secret: the token is in the command an admin
// pastes, and the CA fingerprint is pinned there too, so a node that fetched
// this script from the wrong place still cannot be enrolled against the wrong
// panel.
func (a *App) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	panelURL := ""
	if domains, err := a.Store.Domains(r.Context()); err == nil {
		panelURL = domains.PanelURL
	}
	if panelURL == "" {
		scheme := "http"
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			scheme = "https"
		}
		host := r.Host
		if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
			host = forwarded
		}
		panelURL = scheme + "://" + host
	}

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := installTemplate.Execute(w, installData{PanelURL: strings.TrimRight(panelURL, "/")}); err != nil {
		a.log.Error("could not render the install script", "error", err)
	}
}

// installScript is the node installer.
//
// It is deliberately plain POSIX shell with `set -euo pipefail`: it runs on
// whatever a VPS provider gives you, often a minimal Debian or Ubuntu with no
// extras, and anything it needs it either checks for or installs.
const installScript = `#!/usr/bin/env bash
# WhiteNet node installer.
#
# Usage:
#   curl -fsSL {{.PanelURL}}/install.sh | bash -s -- \
#       --token TOKEN --main HOST:PORT --ca-fingerprint HEX
#
# What it does:
#   * installs the agent and xray-core under /usr/local/lib/whitenet-agent
#   * writes /etc/whitenet-agent/agent.toml
#   * registers and starts the whitenet-agent systemd service
#   * enrols with the panel using the one-time token
#
# It is safe to run again: an already-enrolled node keeps its identity, and
# only the binaries and the unit file are refreshed.

set -euo pipefail

PANEL_URL="{{.PanelURL}}"
TOKEN=""
MAIN=""
CA_FINGERPRINT=""
XRAY_VERSION="latest"
INSTALL_DIR="/usr/local/lib/whitenet-agent"
BIN_DIR="$INSTALL_DIR/bin"
CONFIG_DIR="/etc/whitenet-agent"
DATA_DIR="/var/lib/whitenet-agent"
LOG_DIR="$DATA_DIR/logs"

log()  { printf '\033[0;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m!!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[0;31mxxx\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --token)          TOKEN="${2:-}"; shift 2 ;;
    --main)           MAIN="${2:-}"; shift 2 ;;
    --ca-fingerprint) CA_FINGERPRINT="${2:-}"; shift 2 ;;
    --xray-version)   XRAY_VERSION="${2:-}"; shift 2 ;;
    --panel)          PANEL_URL="${2:-}"; shift 2 ;;
    --help|-h)
      sed -n '2,20p' "$0" 2>/dev/null || true
      exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" = "0" ] || die "run this as root (it installs a systemd service)"
[ -n "$TOKEN" ] || die "--token is required; copy the whole command from the panel"
[ -n "$MAIN" ] || die "--main is required (the panel's agent endpoint, host:port)"
[ -n "$CA_FINGERPRINT" ] || die "--ca-fingerprint is required; it is what lets this node verify the panel"

command -v systemctl >/dev/null 2>&1 || die "this installer needs systemd"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)  GOARCH=amd64; XRAY_ARCH=64 ;;
  aarch64|arm64) GOARCH=arm64; XRAY_ARCH=arm64-v8a ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

log "Installing prerequisites"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates unzip >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q curl ca-certificates unzip >/dev/null
elif command -v yum >/dev/null 2>&1; then
  yum install -y -q curl ca-certificates unzip >/dev/null
else
  warn "unknown package manager; make sure curl and unzip are installed"
fi

# The DNS tunnel binds port 53. On a stock Ubuntu or Debian, systemd-resolved
# already holds 127.0.0.53:53, and the two cannot both bind. Turning off only
# the stub listener leaves name resolution working.
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  if ! grep -qs '^DNSStubListener=no' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/*.conf 2>/dev/null; then
    log "Freeing port 53 (turning off the systemd-resolved stub listener)"
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/whitenet.conf <<'RESOLVED'
# WhiteNet: the DNS tunnel needs port 53. Only the stub listener is turned
# off; systemd-resolved still resolves names for this host.
[Resolve]
DNSStubListener=no
RESOLVED
    # /etc/resolv.conf may point at the stub, which is about to stop
    # answering, so point it at the real resolver instead.
    if [ -L /etc/resolv.conf ] && readlink /etc/resolv.conf | grep -q stub-resolv.conf; then
      ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    fi
    systemctl restart systemd-resolved || warn "could not restart systemd-resolved"
  fi
fi

log "Creating directories"
# Everything is owned by root, because the agent runs as root: it binds
# privileged ports and the l3 flux exit needs raw sockets. The unit below
# trims root's capabilities down to just those, and a trimmed root has no
# CAP_DAC_OVERRIDE - so files owned by anyone else would be unreadable to it.
mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$DATA_DIR/cores" "$LOG_DIR"
chown -R root:root "$DATA_DIR" "$CONFIG_DIR"
chmod 700 "$DATA_DIR" "$CONFIG_DIR"

log "Downloading the agent"
curl -fsSL "$PANEL_URL/dist/wn-agent-linux-$GOARCH" -o "$BIN_DIR/wn-agent.new" \
  || die "could not download the agent from $PANEL_URL/dist/wn-agent-linux-$GOARCH"
chmod 0755 "$BIN_DIR/wn-agent.new"
mv "$BIN_DIR/wn-agent.new" "$BIN_DIR/wn-agent"

log "Downloading the WhiteNet core (the DNS tunnel)"
if curl -fsSL "$PANEL_URL/dist/whitenet-linux-$GOARCH" -o "$BIN_DIR/whitenet.new" 2>/dev/null; then
  chmod 0755 "$BIN_DIR/whitenet.new"
  mv "$BIN_DIR/whitenet.new" "$BIN_DIR/whitenet"
else
  warn "the WhiteNet core is not published on this panel; the DNS tunnel will not run on this node"
fi

log "Downloading xray-core"
XRAY_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$XRAY_ARCH.zip"
if [ "$XRAY_VERSION" != "latest" ]; then
  XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-$XRAY_ARCH.zip"
fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if curl -fsSL "$XRAY_URL" -o "$TMP/xray.zip"; then
  unzip -oq "$TMP/xray.zip" -d "$TMP/xray"
  install -m 0755 "$TMP/xray/xray" "$BIN_DIR/xray"
  # The geo files are what domain and IP routing rules match against.
  for asset in geoip.dat geosite.dat; do
    [ -f "$TMP/xray/$asset" ] && install -m 0644 "$TMP/xray/$asset" "$DATA_DIR/cores/$asset"
  done
else
  warn "could not download xray-core from GitHub; install it into $BIN_DIR/xray by hand"
fi

log "Writing the configuration"
# The token is written here and the agent blanks it as soon as it is spent, so
# a spent credential does not sit on disk.
cat > "$CONFIG_DIR/agent.toml" <<CONF
# WhiteNet node agent. Written by the installer.
#
# Inbounds, users, keys and which cores run are desired state pushed by the
# panel, so none of that belongs in this file.

main = "$MAIN"
token = "$TOKEN"
ca_fingerprint = "$CA_FINGERPRINT"

data_dir = "$DATA_DIR"
bin_dir = "$BIN_DIR"

[reconnect]
initial_delay = "1s"
max_delay = "5m"
multiplier = 2.0
jitter = 0.2
timeout = "20s"

[cores]
xray_binary = "xray"
wndns_binary = "whitenet"
xray_api_address = "127.0.0.1:10085"
restart_backoff = "2s"
restart_backoff_max = "2m"
start_timeout = "15s"
stop_timeout = "10s"

[log]
level = "info"
format = "text"
CONF
chown root:root "$CONFIG_DIR/agent.toml"
chmod 600 "$CONFIG_DIR/agent.toml"

log "Registering the service"
# The agent runs as root: binding ports 53 and 443 needs
# CAP_NET_BIND_SERVICE, and the l3 flux exit needs CAP_NET_RAW and
# CAP_NET_ADMIN. The bounding set is trimmed to those, which means this root
# cannot override file permissions either - hence everything it reads is owned
# by root above.
cat > /etc/systemd/system/whitenet-agent.service <<UNIT
[Unit]
Description=WhiteNet node agent
Documentation=$PANEL_URL
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/wn-agent -config $CONFIG_DIR/agent.toml run
Restart=always
RestartSec=5
# The agent supervises the cores, so a restart of the agent must not orphan
# them; they are in its control group and go with it.
KillMode=control-group
TimeoutStopSec=30

AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$DATA_DIR $CONFIG_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes

# A VPN node under load opens a lot of sockets; the default is far too low.
LimitNOFILE=1048576

StandardOutput=append:$LOG_DIR/agent.log
StandardError=append:$LOG_DIR/agent.log

[Install]
WantedBy=multi-user.target
UNIT

# Keep the logs from filling the disk on a small VPS.
cat > /etc/logrotate.d/whitenet-agent <<'ROTATE'
/var/lib/whitenet-agent/logs/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    copytruncate
}
ROTATE

systemctl daemon-reload
systemctl enable whitenet-agent >/dev/null 2>&1 || true

log "Enrolling with the panel"
# Enrolment is decided by whether the node already has its certificate, not by
# parsing any output: the certificate and the CA next to it are exactly what
# "enrolled" means, and a node that has them must keep its identity.
if [ -s "$DATA_DIR/agent.crt" ] && [ -s "$DATA_DIR/main-ca.crt" ]; then
  log "This node is already enrolled; keeping its identity"
  # The token in the file is unusable now, and leaving it there is a
  # credential nobody needs.
  sed -i 's/^token = .*/token = ""/' "$CONFIG_DIR/agent.toml"
else
  "$BIN_DIR/wn-agent" -config "$CONFIG_DIR/agent.toml" enroll \
    || die "enrolment failed; check that $MAIN is reachable from this node"
fi

log "Starting the agent"
systemctl restart whitenet-agent

sleep 2
if systemctl is-active --quiet whitenet-agent; then
  log "Done. This node should appear in the panel within a few seconds."
  "$BIN_DIR/wn-agent" -config "$CONFIG_DIR/agent.toml" status || true
else
  warn "the agent did not stay up; the last lines of its log:"
  tail -n 30 "$LOG_DIR/agent.log" 2>/dev/null || journalctl -u whitenet-agent -n 30 --no-pager || true
  exit 1
fi
`
