#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
# LySec Installer
# Installs the Linux Forensics Monitoring Daemon
# Must be run as root.
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/lysec"
VENV_DIR="/opt/lysec/.venv"
CONFIG_DIR="/etc/lysec"
LOG_DIR="/var/log/lysec"
EVIDENCE_DIR="/var/lib/lysec/evidence"
PID_DIR="/var/run/lysec"
SYSTEMD_DIR="/etc/systemd/system"

banner() {
    echo -e "${CYAN}"
    echo ""
    echo "   ██╗  ██╗   ██╗███████╗███████╗ ██████╗"
    echo "   ██║  ╚██╗ ██╔╝██╔════╝██╔════╝██╔════╝"
    echo "   ██║   ╚████╔╝ ███████╗█████╗  ██║     "
    echo "   ██║    ╚██╔╝  ╚════██║██╔══╝  ██║     "
    echo "   ███████╗██║   ███████║███████╗╚██████╗"
    echo "   ╚══════╝╚═╝   ╚══════╝╚══════╝ ╚═════╝"
    echo ""
    echo "   Linux Forensics Monitoring Platform"
    echo "   Detect · Log · Alert · Correlate"
    echo ""
    echo -e "${NC}"
}

info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[  OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This installer must be run as root (sudo ./install.sh)"
    fi
}

check_python() {
    if command -v python3 &>/dev/null; then
        PY=$(command -v python3)
        PY_VER=$($PY --version 2>&1 | awk '{print $2}')
        info "Found Python: $PY ($PY_VER)"
    else
        error "Python 3.8+ is required but not found. Install it first."
    fi

    # Check version >= 3.8
    PY_MAJOR=$($PY -c "import sys; print(sys.version_info.major)")
    PY_MINOR=$($PY -c "import sys; print(sys.version_info.minor)")
    if [[ $PY_MAJOR -lt 3 ]] || [[ $PY_MINOR -lt 8 ]]; then
        error "Python 3.8+ required, found $PY_VER"
    fi

    # Ensure venv module is available
    if ! $PY -m venv --help >/dev/null 2>&1; then
        error "Python venv module is missing. Install python3-venv first."
    fi
}

create_venv() {
    info "Creating isolated Python environment at $VENV_DIR …"
    if [[ ! -d "$VENV_DIR" ]]; then
        $PY -m venv "$VENV_DIR" || error "Failed to create virtual environment"
    fi

    VENV_PY="$VENV_DIR/bin/python"
    VENV_PIP="$VENV_DIR/bin/pip"

    "$VENV_PIP" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
    success "Virtual environment ready"
}

install_dependencies() {
    info "Installing Python dependencies …"
    "$VENV_PIP" install -r requirements.txt || error "Failed to install dependencies"

    # Optional native fuzzy-hash libraries. Do not fail full install if unavailable.
    if "$VENV_PIP" install ssdeep py-tlsh >/dev/null 2>&1; then
        success "Optional fuzzy-hash dependencies installed (ssdeep, py-tlsh)"
    else
        warn "Optional fuzzy-hash dependencies could not be built (ssdeep/py-tlsh)."
        warn "LySec will continue without fuzzy hash fields on this host."
    fi

    success "Dependencies installed"
}

create_directories() {
    info "Creating directories …"
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$EVIDENCE_DIR"
    mkdir -p "$PID_DIR"

    # Restrict permissions on evidence & logs
    chmod 750 "$LOG_DIR"
    chmod 750 "$EVIDENCE_DIR"
    chmod 700 "$CONFIG_DIR"

    success "Directories created"
}

install_files() {
    info "Installing LySec …"

    # Copy source
    cp -r src/lysec "$INSTALL_DIR/"

    # Install as Python package
    "$VENV_PIP" install . || error "pip install failed"

    # Ensure commands are globally invokable for systemd and operators
    ln -sf "$VENV_DIR/bin/lysec" /usr/local/bin/lysec
    ln -sf "$VENV_DIR/bin/lysecd" /usr/local/bin/lysecd
    ln -sf "$VENV_DIR/bin/lysec-eval" /usr/local/bin/lysec-eval
    ln -sf "$VENV_DIR/bin/lysec-eval-plot" /usr/local/bin/lysec-eval-plot
    ln -sf "$VENV_DIR/bin/lysec-gui" /usr/local/bin/lysec-gui
    ln -sf "$VENV_DIR/bin/lysec-watchdog" /usr/local/bin/lysec-watchdog

    # Legacy command aliases for compatibility
    ln -sf "$VENV_DIR/bin/dftool" /usr/local/bin/dftool
    ln -sf "$VENV_DIR/bin/dftoold" /usr/local/bin/dftoold
    ln -sf "$VENV_DIR/bin/dftool-eval" /usr/local/bin/dftool-eval
    ln -sf "$VENV_DIR/bin/dftool-eval-plot" /usr/local/bin/dftool-eval-plot

    success "LySec package installed"
}

install_config() {
    if [[ -f "$CONFIG_DIR/lysec.yaml" ]]; then
        warn "Config already exists at $CONFIG_DIR/lysec.yaml — keeping existing"
    else
        cp config/lysec.yaml "$CONFIG_DIR/lysec.yaml"
        chmod 600 "$CONFIG_DIR/lysec.yaml"
        success "Config installed to $CONFIG_DIR/lysec.yaml"
    fi
}

install_systemd() {
    info "Installing systemd service …"
    cp systemd/lysec.service "$SYSTEMD_DIR/lysec.service"
    cp systemd/lysec-prelogin.service "$SYSTEMD_DIR/lysec-prelogin.service"
    cp systemd/lysec-watchdog.service "$SYSTEMD_DIR/lysec-watchdog.service"
    systemctl daemon-reload

    BOOT_PROFILE="${LYSEC_BOOT_PROFILE:-prelogin}"
    WATCHDOG_TARGET_SERVICE="lysec.service"
    if [[ "$BOOT_PROFILE" == "prelogin" ]]; then
        systemctl stop lysec.service >/dev/null 2>&1 || true
        systemctl disable lysec.service >/dev/null 2>&1 || true
        systemctl enable lysec-prelogin.service
        WATCHDOG_TARGET_SERVICE="lysec-prelogin.service"
        info "Boot profile: prelogin (enabled lysec-prelogin.service)"
    else
        systemctl stop lysec-prelogin.service >/dev/null 2>&1 || true
        systemctl disable lysec-prelogin.service >/dev/null 2>&1 || true
        systemctl enable lysec.service
        WATCHDOG_TARGET_SERVICE="lysec.service"
        info "Boot profile: standard (enabled lysec.service)"
    fi

    if [[ -f "$CONFIG_DIR/lysec.yaml" ]]; then
        # Keep watchdog aligned to the selected primary service profile.
        sed -i -E "s|^([[:space:]]*service_name:[[:space:]]*).*$|\\1${WATCHDOG_TARGET_SERVICE}|" "$CONFIG_DIR/lysec.yaml" || true
        if ! grep -qE '^[[:space:]]*service_fallbacks:' "$CONFIG_DIR/lysec.yaml"; then
            sed -i -E '/^[[:space:]]*service_name:/a\    service_fallbacks: []' "$CONFIG_DIR/lysec.yaml" || true
        fi
    fi

    systemctl enable lysec-watchdog.service
    success "Systemd service installed and enabled"
}

print_summary() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN} Installation Complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Config:   ${CYAN}$CONFIG_DIR/lysec.yaml${NC}"
    echo -e "  Logs:     ${CYAN}$LOG_DIR/${NC}"
    echo -e "  Evidence: ${CYAN}$EVIDENCE_DIR/${NC}"
    echo -e "  Service:  ${CYAN}lysec.service${NC}"
    echo -e "  Watchdog: ${CYAN}lysec-watchdog.service${NC}"
    echo ""
    echo -e "  ${YELLOW}Quick Start:${NC}"
    echo -e "    sudo systemctl start lysec      # Start the daemon"
    echo -e "    sudo systemctl start lysec-watchdog # Start watchdog"
    echo -e "    sudo systemctl status lysec     # Check status"
    echo -e "    sudo lysec status               # CLI status"
    echo -e "    sudo lysec alerts --last 1h     # View recent alerts"
    echo -e "    sudo lysec timeline             # View event timeline"
    echo -e "    lysec-gui                       # Launch desktop GUI"
    echo ""
    echo -e "  ${YELLOW}Run in foreground (debug):${NC}"
    echo -e "    sudo lysecd start --foreground"
    echo ""
    echo -e "  ${RED}Remember: LySec DETECTS and LOGS only.${NC}"
    echo -e "  ${RED}It does NOT prevent or block any activity.${NC}"
    echo ""
}

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
banner
check_root
check_python
create_directories
create_venv
install_dependencies
install_files
install_config
install_systemd
print_summary
