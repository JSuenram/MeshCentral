#!/usr/bin/env bash
# ==============================================================================
#   ISoné LiPa Proxy - AllInOne Installer v1.3.2
# ==============================================================================
#
# Usage:
#   install.sh [options]
#
# Options:
#   --migrate-tls    Migrate from Nginx reverse proxy to native TLS termination
#   --help           Show this help message
#
# Changes in v1.3.2:
#   - Fix: Set correct file permissions on SSL certificate and key files
#     during --migrate-tls migration so the proxy service user can read them.
#     Previously the key file remained root-only readable, causing
#     "permission denied" errors when the proxy tried to load TLS certificates.

set -euo pipefail

INSTALLER_VERSION="1.3.2"

# Default paths
PROXY_CONFIG="/etc/isone-proxy/config.yaml"
PROXY_SERVICE="isone-proxy"
PROXY_SSL_DIR="/etc/isone-proxy/ssl"
NGINX_SITE_AVAILABLE="/etc/nginx/sites-available/isone-proxy"
NGINX_SITE_ENABLED="/etc/nginx/sites-enabled/isone-proxy"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo "=============================================================================="
    echo "  $1"
    echo "=============================================================================="
    echo ""
}

log_info() {
    echo -e "[${BLUE}INFO${NC}] $1"
}

log_ok() {
    echo -e "[${GREEN}OK${NC}] $1"
}

log_warn() {
    echo -e "[${YELLOW}WARN${NC}] $1"
}

log_error() {
    echo -e "[${RED}ERROR${NC}] $1"
}

show_help() {
    echo "ISoné LiPa Proxy - AllInOne Installer v${INSTALLER_VERSION}"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --migrate-tls    Migrate from Nginx reverse proxy to native TLS termination"
    echo "  --help           Show this help message"
}

# ==============================================================================
#   System detection
# ==============================================================================
detect_system() {
    print_header "System-Erkennung"

    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
    fi

    # Detect package manager
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
    elif command -v apk >/dev/null 2>&1; then
        PKG_MANAGER="apk"
    else
        PKG_MANAGER="unknown"
    fi

    # Detect architecture
    ARCH_RAW=$(uname -m)
    case "$ARCH_RAW" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l|armv7) ARCH="armv7" ;;
        armv6l) ARCH="armv6" ;;
        *) ARCH="$ARCH_RAW" ;;
    esac

    log_info "Erkanntes System: ${OS_ID} ${OS_VERSION} ($(uname -s))"
    log_info "Package Manager: ${PKG_MANAGER}"
    log_info "Architektur: ${ARCH_RAW} (${ARCH})"
    log_ok "System-Erkennung abgeschlossen"
}

# ==============================================================================
#   Determine the service user from the systemd unit file
# ==============================================================================
get_proxy_service_user() {
    local service_file
    service_file=$(systemctl show -p FragmentPath "${PROXY_SERVICE}.service" 2>/dev/null | cut -d= -f2-)

    if [ -z "$service_file" ] || [ ! -f "$service_file" ]; then
        # Fallback: check common locations
        for f in "/etc/systemd/system/${PROXY_SERVICE}.service" "/lib/systemd/system/${PROXY_SERVICE}.service"; do
            if [ -f "$f" ]; then
                service_file="$f"
                break
            fi
        done
    fi

    if [ -n "$service_file" ] && [ -f "$service_file" ]; then
        local user
        user=$(grep -E '^\s*User\s*=' "$service_file" | tail -1 | sed 's/.*=\s*//' | tr -d '[:space:]')
        if [ -n "$user" ]; then
            echo "$user"
            return 0
        fi
    fi

    # Default: service runs as root
    echo "root"
    return 0
}

# ==============================================================================
#   Determine the service group from the systemd unit file
# ==============================================================================
get_proxy_service_group() {
    local service_file
    service_file=$(systemctl show -p FragmentPath "${PROXY_SERVICE}.service" 2>/dev/null | cut -d= -f2-)

    if [ -z "$service_file" ] || [ ! -f "$service_file" ]; then
        for f in "/etc/systemd/system/${PROXY_SERVICE}.service" "/lib/systemd/system/${PROXY_SERVICE}.service"; do
            if [ -f "$f" ]; then
                service_file="$f"
                break
            fi
        done
    fi

    if [ -n "$service_file" ] && [ -f "$service_file" ]; then
        local group
        group=$(grep -E '^\s*Group\s*=' "$service_file" | tail -1 | sed 's/.*=\s*//' | tr -d '[:space:]')
        if [ -n "$group" ]; then
            echo "$group"
            return 0
        fi
    fi

    # Fallback to service user's primary group, or root
    local svc_user
    svc_user=$(get_proxy_service_user)
    if [ "$svc_user" != "root" ] && id -gn "$svc_user" >/dev/null 2>&1; then
        id -gn "$svc_user"
    else
        echo "root"
    fi
    return 0
}

# ==============================================================================
#   Fix SSL certificate and key file permissions
# ==============================================================================
fix_ssl_permissions() {
    local cert_file="$1"
    local key_file="$2"
    local svc_user svc_group

    svc_user=$(get_proxy_service_user)
    svc_group=$(get_proxy_service_group)

    log_info "Proxy-Service User:  ${svc_user}"
    log_info "Proxy-Service Group: ${svc_group}"

    # Fix ownership and permissions on the SSL directory
    if [ -d "$(dirname "$cert_file")" ]; then
        chown root:"${svc_group}" "$(dirname "$cert_file")"
        chmod 750 "$(dirname "$cert_file")"
    fi

    # Certificate file: readable by everyone (public key, not sensitive)
    if [ -f "$cert_file" ]; then
        chown root:"${svc_group}" "$cert_file"
        chmod 644 "$cert_file"
        log_ok "Zertifikat-Berechtigungen gesetzt: ${cert_file} (644, root:${svc_group})"
    else
        log_warn "Zertifikat nicht gefunden: ${cert_file}"
    fi

    # Key file: readable only by owner and group (sensitive!)
    if [ -f "$key_file" ]; then
        chown root:"${svc_group}" "$key_file"
        chmod 640 "$key_file"
        log_ok "Schlüssel-Berechtigungen gesetzt: ${key_file} (640, root:${svc_group})"
    else
        log_warn "Schlüssel nicht gefunden: ${key_file}"
    fi
}

# ==============================================================================
#   Parse Nginx config to extract SSL settings
# ==============================================================================
parse_nginx_config() {
    local nginx_conf="$1"

    if [ ! -f "$nginx_conf" ]; then
        log_error "Nginx-Konfiguration nicht gefunden: ${nginx_conf}"
        return 1
    fi

    log_info "Lese bestehende Nginx-Konfiguration: ${nginx_conf}"

    # Extract SSL certificate path
    NGINX_SSL_CERT=$(grep -E '^\s*ssl_certificate\s' "$nginx_conf" | head -1 | sed 's/.*ssl_certificate\s\+//' | sed 's/\s*;\s*$//' | tr -d '[:space:]')
    # Extract SSL key path
    NGINX_SSL_KEY=$(grep -E '^\s*ssl_certificate_key\s' "$nginx_conf" | head -1 | sed 's/.*ssl_certificate_key\s\+//' | sed 's/\s*;\s*$//' | tr -d '[:space:]')
    # Extract HTTPS port
    NGINX_HTTPS_PORT=$(grep -E '^\s*listen\s' "$nginx_conf" | grep -i ssl | head -1 | sed 's/.*listen\s\+//' | grep -oE '[0-9]+' | head -1)
    # Extract server_name (domain)
    NGINX_DOMAIN=$(grep -E '^\s*server_name\s' "$nginx_conf" | head -1 | sed 's/.*server_name\s\+//' | sed 's/\s*;\s*$//' | tr -d '[:space:]')

    # Defaults
    NGINX_SSL_CERT="${NGINX_SSL_CERT:-${PROXY_SSL_DIR}/selfsigned.crt}"
    NGINX_SSL_KEY="${NGINX_SSL_KEY:-${PROXY_SSL_DIR}/selfsigned.key}"
    NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT:-443}"
    NGINX_DOMAIN="${NGINX_DOMAIN:-$(hostname -f 2>/dev/null || hostname)}"

    log_info "SSL-Zertifikat: ${NGINX_SSL_CERT}"
    log_info "SSL-Schlüssel:  ${NGINX_SSL_KEY}"
    log_info "HTTPS-Port:     ${NGINX_HTTPS_PORT}"
    log_info "Domain:         ${NGINX_DOMAIN}"
}

# ==============================================================================
#   Add CAP_NET_BIND_SERVICE to systemd service
# ==============================================================================
add_cap_net_bind() {
    local service_file
    service_file=$(systemctl show -p FragmentPath "${PROXY_SERVICE}.service" 2>/dev/null | cut -d= -f2-)

    if [ -z "$service_file" ] || [ ! -f "$service_file" ]; then
        for f in "/etc/systemd/system/${PROXY_SERVICE}.service" "/lib/systemd/system/${PROXY_SERVICE}.service"; do
            if [ -f "$f" ]; then
                service_file="$f"
                break
            fi
        done
    fi

    if [ -z "$service_file" ] || [ ! -f "$service_file" ]; then
        log_warn "Systemd-Service-Datei nicht gefunden, überspringe CAP_NET_BIND_SERVICE"
        return 0
    fi

    log_info "Füge CAP_NET_BIND_SERVICE zu Systemd-Service hinzu"

    if ! grep -q 'AmbientCapabilities=.*CAP_NET_BIND_SERVICE' "$service_file"; then
        # Add AmbientCapabilities under [Service] section
        sed -i '/^\[Service\]/a AmbientCapabilities=CAP_NET_BIND_SERVICE' "$service_file"
    fi

    if ! grep -q 'CapabilityBoundingSet=.*CAP_NET_BIND_SERVICE' "$service_file"; then
        sed -i '/^\[Service\]/a CapabilityBoundingSet=CAP_NET_BIND_SERVICE' "$service_file"
    fi

    systemctl daemon-reload
    log_ok "CAP_NET_BIND_SERVICE zu Systemd-Service hinzugefügt"
}

# ==============================================================================
#   Create backup of proxy configuration
# ==============================================================================
backup_config() {
    print_header "Erstelle Backup der Proxy-Konfiguration"

    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)

    if [ -f "$PROXY_CONFIG" ]; then
        cp "$PROXY_CONFIG" "${PROXY_CONFIG}.bak-pre-tls-${timestamp}"
        log_ok "Backup erstellt: ${PROXY_CONFIG}.bak-pre-tls-${timestamp}"
    fi
}

# ==============================================================================
#   Enable native TLS in config.yaml
# ==============================================================================
enable_native_tls() {
    local cert_file="$1"
    local key_file="$2"
    local port="$3"

    print_header "Aktiviere native TLS in config.yaml"

    if [ ! -f "$PROXY_CONFIG" ]; then
        log_error "Proxy-Konfiguration nicht gefunden: ${PROXY_CONFIG}"
        return 1
    fi

    # Update listen_address from 127.0.0.1 to 0.0.0.0
    if grep -q 'listen_address:.*127\.0\.0\.1' "$PROXY_CONFIG"; then
        sed -i 's/listen_address:.*127\.0\.0\.1/listen_address: 0.0.0.0/' "$PROXY_CONFIG"
        log_info "listen_address: 127.0.0.1 → 0.0.0.0"
    fi

    # Update listen_port
    if grep -q 'listen_port:' "$PROXY_CONFIG"; then
        local old_port
        old_port=$(grep 'listen_port:' "$PROXY_CONFIG" | head -1 | grep -oE '[0-9]+')
        sed -i "s/listen_port:.*/listen_port: ${port}/" "$PROXY_CONFIG"
        log_info "listen_port: ${old_port:-8080} → ${port}"
    fi

    # Add or update TLS section
    if grep -q '^\s*tls:' "$PROXY_CONFIG"; then
        # Update existing TLS section
        sed -i "s|^\(\s*\)cert_file:.*|\\1cert_file: ${cert_file}|" "$PROXY_CONFIG"
        sed -i "s|^\(\s*\)key_file:.*|\\1key_file: ${key_file}|" "$PROXY_CONFIG"
        if grep -q '^\s*enabled:' "$PROXY_CONFIG"; then
            sed -i 's/^\(\s*\)enabled:.*/\1enabled: true/' "$PROXY_CONFIG"
        fi
    else
        # Append TLS section
        cat >> "$PROXY_CONFIG" <<EOF

tls:
  enabled: true
  cert_file: ${cert_file}
  key_file: ${key_file}
EOF
    fi

    log_ok "TLS-Konfiguration in config.yaml aktiviert"
    log_info "  cert_file: ${cert_file}"
    log_info "  key_file:  ${key_file}"
    log_info "  Port:      ${port}"

    # Check for backend_proxy_ws_path
    if grep -q 'backend_proxy_ws_path' "$PROXY_CONFIG"; then
        log_info "Config-Migration: backend_proxy_ws_path bereits vorhanden, keine Änderung"
    fi

    # Check for websocket.allowed_subprotocols
    if grep -q 'allowed_subprotocols' "$PROXY_CONFIG"; then
        log_info "config.yaml: websocket.allowed_subprotocols bereits konfiguriert"
    fi
}

# ==============================================================================
#   Disable Nginx for ISoné Proxy
# ==============================================================================
disable_nginx() {
    print_header "Deaktiviere Nginx für ISoné Proxy"

    # Remove symlink from sites-enabled
    if [ -L "$NGINX_SITE_ENABLED" ]; then
        rm -f "$NGINX_SITE_ENABLED"
        log_info "Nginx-Site deaktiviert: ${NGINX_SITE_ENABLED} entfernt"
    fi

    # Backup the Nginx config
    if [ -f "$NGINX_SITE_AVAILABLE" ]; then
        local timestamp
        timestamp=$(date +%Y%m%d-%H%M%S)
        cp "$NGINX_SITE_AVAILABLE" "${NGINX_SITE_AVAILABLE}.bak-pre-tls-${timestamp}"
        log_info "Nginx-Konfiguration gesichert: ${NGINX_SITE_AVAILABLE}.bak-pre-tls-${timestamp}"
    fi

    # Check if there are other active Nginx sites
    local active_sites
    active_sites=$(find /etc/nginx/sites-enabled/ -type l 2>/dev/null | wc -l)

    if [ "$active_sites" -eq 0 ]; then
        log_info "Keine anderen Nginx-Sites aktiv — stoppe und deaktiviere Nginx"
        systemctl stop nginx 2>/dev/null || true
        systemctl disable nginx 2>/dev/null || true
        log_ok "Nginx gestoppt und deaktiviert"
    else
        log_info "${active_sites} andere Nginx-Sites noch aktiv — Nginx bleibt laufen"
        systemctl reload nginx 2>/dev/null || true
    fi
}

# ==============================================================================
#   Validate migration
# ==============================================================================
validate_migration() {
    print_header "Validiere Migration"

    local retries=5
    local wait_seconds=3
    local health_url="https://127.0.0.1/api/health"

    for _attempt in $(seq 1 $retries); do
        if curl -fsSk --connect-timeout 3 "$health_url" >/dev/null 2>&1; then
            log_ok "Proxy antwortet auf ${health_url}"
            return 0
        fi
        sleep "$wait_seconds"
    done

    log_warn "Proxy antwortet noch nicht auf ${health_url}"
    log_info "Bitte manuell prüfen: curl -k ${health_url}"
    log_info "Proxy-Logs: journalctl -u ${PROXY_SERVICE} -f"
    return 0
}

# ==============================================================================
#   Migrate from Nginx to native TLS
# ==============================================================================
migrate_tls() {
    print_header "Migration: Nginx → Native TLS-Terminierung"

    echo ""
    log_info "Der Proxy übernimmt die TLS-Terminierung direkt (ohne Nginx)."
    log_info "Agent- und API-Verbindungen funktionieren nach dem Neustart sofort weiter."
    echo ""

    # Step 1: Add CAP_NET_BIND_SERVICE
    add_cap_net_bind

    # Step 2: Parse existing Nginx config
    if [ -f "$NGINX_SITE_AVAILABLE" ]; then
        parse_nginx_config "$NGINX_SITE_AVAILABLE"
    else
        # Use defaults if no Nginx config found
        NGINX_SSL_CERT="${PROXY_SSL_DIR}/selfsigned.crt"
        NGINX_SSL_KEY="${PROXY_SSL_DIR}/selfsigned.key"
        NGINX_HTTPS_PORT="443"
        log_info "Keine Nginx-Konfiguration gefunden, verwende Standardwerte"
        log_info "SSL-Zertifikat: ${NGINX_SSL_CERT}"
        log_info "SSL-Schlüssel:  ${NGINX_SSL_KEY}"
        log_info "HTTPS-Port:     ${NGINX_HTTPS_PORT}"
    fi

    # Step 3: Backup config
    backup_config

    # Step 4: Enable native TLS
    enable_native_tls "$NGINX_SSL_CERT" "$NGINX_SSL_KEY" "$NGINX_HTTPS_PORT"

    # Step 5: Fix SSL file permissions (THE FIX for the permission denied issue)
    print_header "Setze SSL-Datei-Berechtigungen"
    fix_ssl_permissions "$NGINX_SSL_CERT" "$NGINX_SSL_KEY"

    # Step 6: Disable Nginx
    disable_nginx

    # Step 7: Restart proxy
    print_header "Starte Proxy-Service neu"
    systemctl restart "$PROXY_SERVICE" 2>/dev/null || true
    log_info "Proxy-Service gestartet"

    # Step 8: Validate
    validate_migration

    # Summary
    echo ""
    log_ok "=========================================================="
    log_ok "  Migration abgeschlossen: Nginx → Native TLS"
    log_ok "=========================================================="
    echo ""
    log_info "Der Proxy terminiert TLS jetzt direkt auf Port ${NGINX_HTTPS_PORT}."
    log_info "Nginx wurde deaktiviert und wird nicht mehr benötigt."
    log_info ""
    log_info "Zertifikat-Reload ohne Neustart:"
    log_info "  kill -HUP \$(pidof isone-proxy)"
    log_info ""
    log_info "Zurück zu Nginx (falls nötig):"
    log_info "  Backup zurückspielen: cp ${PROXY_CONFIG}.bak-pre-tls-* ${PROXY_CONFIG}"
    log_info "  systemctl enable --now nginx && systemctl restart ${PROXY_SERVICE}"
}

# ==============================================================================
#   Main
# ==============================================================================
main() {
    print_header "ISoné LiPa Proxy - AllInOne Installer v${INSTALLER_VERSION}"

    # Check root
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Dieses Skript muss als root ausgeführt werden."
        exit 1
    fi

    # Parse arguments
    local action=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --migrate-tls)
                action="migrate-tls"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unbekannte Option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Detect system
    detect_system

    # Execute action
    case "$action" in
        migrate-tls)
            migrate_tls
            ;;
        "")
            log_error "Keine Aktion angegeben. Verwende --help für Hilfe."
            exit 1
            ;;
    esac
}

main "$@"
