#!/usr/bin/env bash
# SentinelAI agent installer for BOSS 10 (spec §48).
#
#   sudo SENTINEL_SERVER_URL=https://sentinel.example.org SENTINEL_AGENT_TOKEN=sat_xxx ./install.sh
#
# Options:
#   --mode restricted|root   restricted (default): dedicated 'sentinelai' user with read-only
#                            capabilities; root: run as root (enables rkhunter/chkrootkit runs)
#   --wheelhouse DIR         install Python packages offline from DIR (pip download -d DIR -r requirements.txt)
#   --no-service             install files only; do not create/start a systemd service
#   -y, --yes                do not prompt (non-BOSS-10 hosts continue with a warning)
set -euo pipefail

PREFIX=/opt/sentinelai/agent
CONF_DIR=/etc/sentinelai
STATE_DIR=/var/lib/sentinelai
SERVICE=sentinel-agent
SERVICE_USER=sentinelai
RESTRICTED_CAPS="CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN"
MODE=restricted
WHEELHOUSE=""
WITH_SERVICE=1
ASSUME_YES=0
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mWARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --wheelhouse) WHEELHOUSE="$2"; shift 2 ;;
    --no-service) WITH_SERVICE=0; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ "$MODE" == restricted || "$MODE" == root ]] || die "--mode must be 'restricted' or 'root'"
[[ $EUID -eq 0 ]] || die "run as root (sudo ./install.sh)"

# ---------- 1. detect the OS (never assume) ----------
OS_NAME=unknown; OS_ID=unknown; OS_VERSION=unknown; OS_CODENAME=""
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_NAME="${NAME:-unknown}"; OS_ID="${ID:-unknown}"; OS_VERSION="${VERSION_ID:-unknown}"; OS_CODENAME="${VERSION_CODENAME:-}"
fi
echo
echo "Detected OS:      ${PRETTY_NAME:-$OS_NAME}"
echo "Detected Version: ${OS_VERSION}${OS_CODENAME:+ ($OS_CODENAME)}"
echo "Detected Kernel:  $(uname -r)"
echo "Architecture:     $(uname -m)"
INIT=$(cat /proc/1/comm 2>/dev/null || echo unknown)
[[ -d /run/systemd/system ]] && INIT=systemd
echo "Init system:      ${INIT}"
echo

IS_BOSS=0
if echo "${OS_ID} ${ID_LIKE:-} ${OS_NAME}" | grep -qi boss; then IS_BOSS=1; fi
if [[ $IS_BOSS -eq 1 && "${OS_VERSION%%.*}" == "10" ]]; then
  say "BOSS 10 detected."
else
  warn "This project targets BOSS 10. This host is '${PRETTY_NAME:-$OS_NAME}'."
  if [[ $ASSUME_YES -eq 0 ]]; then
    read -r -p "Continue anyway? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || die "aborted"
  else
    warn "continuing because --yes was given; some checks may report NOT_SUPPORTED."
  fi
fi

# ---------- 2. verify Python ----------
command -v python3 >/dev/null || die "python3 not found. On BOSS/Debian: sudo apt install python3 python3-venv"
python3 - <<'PY' || die "Python 3.9+ is required"
import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)
PY
python3 -c 'import venv, ensurepip' 2>/dev/null || die "Python venv support missing. On BOSS/Debian: sudo apt install python3-venv"
say "Python $(python3 -c 'import platform; print(platform.python_version())') OK"

# ---------- 3. files, user, directories ----------
say "Installing agent to ${PREFIX}"
mkdir -p "$PREFIX" "$CONF_DIR" "$STATE_DIR"
# Copy only the agent sources (not tests, not a dev venv).
tar -C "$SRC_DIR" --exclude='./venv' --exclude='./.venv' --exclude='./tests' --exclude='__pycache__' \
    --exclude='./.pytest_cache' -cf - . | tar -C "$PREFIX" -xf -

if [[ "$MODE" == restricted ]]; then
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    say "Creating system user ${SERVICE_USER}"
    useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  # Read auth logs / journal without root.
  for g in adm systemd-journal; do getent group "$g" >/dev/null && usermod -aG "$g" "$SERVICE_USER"; done
  RUN_AS="$SERVICE_USER"
else
  RUN_AS=root
fi
chown -R "$RUN_AS":"$RUN_AS" "$STATE_DIR"
chmod 700 "$STATE_DIR"

# ---------- 4. virtualenv + dependencies ----------
say "Creating virtual environment"
python3 -m venv "$PREFIX/venv"
if [[ -n "$WHEELHOUSE" ]]; then
  "$PREFIX/venv/bin/pip" install --no-index --find-links "$WHEELHOUSE" -r "$PREFIX/requirements.txt" -q
else
  "$PREFIX/venv/bin/pip" install -r "$PREFIX/requirements.txt" -q \
    || die "pip install failed. For offline hosts use --wheelhouse (see README)."
fi

# ---------- 5. configuration ----------
if [[ ! -f "$CONF_DIR/agent.yaml" ]]; then
  install -m 0644 "$SRC_DIR/deploy/agent.yaml" "$CONF_DIR/agent.yaml"
  say "Wrote $CONF_DIR/agent.yaml"
else
  say "Keeping existing $CONF_DIR/agent.yaml"
fi
SERVER_URL="${SENTINEL_SERVER_URL:-}"
if [[ -z "$SERVER_URL" ]]; then
  SERVER_URL=$(awk '/^server:/{s=1} s&&/url:/{gsub(/["\x27]/,"",$2); print $2; exit}' "$CONF_DIR/agent.yaml")
fi
if [[ -z "$SERVER_URL" && $ASSUME_YES -eq 0 ]]; then
  read -r -p "SentinelAI server URL (e.g. https://sentinel.example.org): " SERVER_URL
fi
[[ -n "$SERVER_URL" ]] || die "server URL required (SENTINEL_SERVER_URL)"
[[ "$SERVER_URL" == https://* ]] || warn "server URL is not HTTPS; credentials will travel in clear text"
TOKEN="${SENTINEL_AGENT_TOKEN:-}"
if [[ -z "$TOKEN" && ! -f "$STATE_DIR/credentials.json" && $ASSUME_YES -eq 0 ]]; then
  read -r -s -p "Enrollment token (from dashboard Settings): " TOKEN; echo
fi
umask 077
cat > "$CONF_DIR/agent.env" <<EOF
SENTINEL_SERVER_URL=${SERVER_URL}
SENTINEL_VERIFY_TLS=${SENTINEL_VERIFY_TLS:-true}
EOF
chown root:"$RUN_AS" "$CONF_DIR/agent.env"; chmod 0640 "$CONF_DIR/agent.env"
umask 022

AGENT=( "$PREFIX/venv/bin/python" "$PREFIX/main.py" --config "$CONF_DIR/agent.yaml" )
as_agent() { if [[ "$RUN_AS" == root ]]; then "$@"; else runuser -u "$RUN_AS" -- "$@"; fi; }

# ---------- 6. capability report + enrollment ----------
say "Capability discovery"
as_agent env SENTINEL_SERVER_URL="$SERVER_URL" "${AGENT[@]}" detect | sed -n '1,30p'

if [[ -f "$STATE_DIR/credentials.json" ]]; then
  say "Agent already enrolled (credentials in $STATE_DIR); skipping enrollment"
else
  [[ -n "$TOKEN" ]] || die "enrollment token required (SENTINEL_AGENT_TOKEN)"
  say "Enrolling with ${SERVER_URL}"
  # Token goes via environment, not argv, so it does not show up in `ps`.
  as_agent env SENTINEL_SERVER_URL="$SERVER_URL" SENTINEL_AGENT_TOKEN="$TOKEN" "${AGENT[@]}" enroll \
    || die "enrollment failed (check the token, server URL and TLS settings)"
fi

# ---------- 7. service ----------
if [[ $WITH_SERVICE -eq 1 ]]; then
  if [[ "$INIT" == systemd ]] && command -v systemctl >/dev/null; then
    say "Installing systemd unit ${SERVICE}.service (${MODE} mode)"
    UNIT=/etc/systemd/system/${SERVICE}.service
    sed -e "s|@SERVICE_USER@|${RUN_AS}|g" -e "s|@CAPS@|${RESTRICTED_CAPS}|g" "$SRC_DIR/deploy/sentinel-agent.service" > "$UNIT"
    if [[ "$MODE" == root ]]; then
      sed -i -e '/^AmbientCapabilities=/d' -e '/^CapabilityBoundingSet=/d' "$UNIT"
    fi
    systemctl daemon-reload
    systemctl enable --now "$SERVICE"
  else
    warn "systemd not detected (init: ${INIT}). Start the agent manually or with your init system:"
    echo "  ${AGENT[*]} run"
    WITH_SERVICE=0
  fi
fi

# ---------- 8. verify heartbeat ----------
say "Verifying heartbeat"
if as_agent env SENTINEL_SERVER_URL="$SERVER_URL" "${AGENT[@]}" ping; then
  [[ $WITH_SERVICE -eq 1 ]] && sleep 3 && systemctl is-active --quiet "$SERVICE" && say "Service is running."
  echo
  say "SentinelAI agent installed. The host appears in the dashboard within a few seconds."
else
  warn "heartbeat failed. Troubleshooting:"
  echo "  - Is the server reachable?   curl -I ${SERVER_URL}/health"
  echo "  - Agent logs:                journalctl -u ${SERVICE} -n 50"
  echo "  - TLS with a private CA:     set server.ca_bundle in $CONF_DIR/agent.yaml"
  echo "  - Re-enroll:                 rm $STATE_DIR/credentials.json and run install.sh with a new token"
  exit 1
fi
echo
echo "Useful commands:"
echo "  systemctl status ${SERVICE}            journalctl -u ${SERVICE} -f"
echo "  ${PREFIX}/venv/bin/python ${PREFIX}/main.py --config ${CONF_DIR}/agent.yaml scan --type QUICK --summary"
