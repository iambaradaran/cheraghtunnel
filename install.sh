#!/bin/bash
# CheraghTunnel One-Click Panel Installer
set -e

echo "=========================================================="
echo "      CheraghTunnel Web Panel Setup & Installer"
echo "=========================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Ask for custom configuration interactively (using /dev/tty to support curl | bash piping)
echo "----------------------------------------------------------"
echo "Please configure your CheraghTunnel Web Panel:"
echo "----------------------------------------------------------"

# 1. Custom Web Panel Port
read -p "Enter Web Panel Port [Default: 8000]: " PANEL_PORT < /dev/tty
PANEL_PORT=${PANEL_PORT:-8000}
PANEL_PORT=$(echo "$PANEL_PORT" | tr -d '\r')

# Validate port is a number
if ! [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || [ "$PANEL_PORT" -lt 1 ] || [ "$PANEL_PORT" -gt 65535 ]; then
  echo "Invalid port. Using default: 8000"
  PANEL_PORT=8000
fi

# 2. Custom Admin Username
read -p "Enter Admin Username [Default: admin]: " ADMIN_USER < /dev/tty
ADMIN_USER=${ADMIN_USER:-admin}
ADMIN_USER=$(echo "$ADMIN_USER" | tr -d '\r')

# 3. Custom Admin Password
read -s -p "Enter Admin Password [Press Enter to generate a random one]: " ADMIN_PASS < /dev/tty
echo "" # New line after hidden password input
if [ -z "$ADMIN_PASS" ]; then
  ADMIN_PASS="cheragh_$(openssl rand -hex 3 2>/dev/null || echo $((RANDOM % 90000 + 10000)))"
  echo "Generated random password: $ADMIN_PASS"
fi
ADMIN_PASS=$(echo "$ADMIN_PASS" | tr -d '\r')

# 4. Optional SSL Domain Setup
read -p "Enable HTTPS / SSL Certificate for Panel? (y/N): " ENABLE_SSL < /dev/tty
ENABLE_SSL=$(echo "$ENABLE_SSL" | tr -d '\r' | tr '[:upper:]' '[:lower:]')

SSL_FLAGS=""
DOMAIN_NAME=""

if [ "$ENABLE_SSL" = "y" ] || [ "$ENABLE_SSL" = "yes" ]; then
  read -p "Enter Domain Name (e.g. panel.netbros.ir): " DOMAIN_NAME < /dev/tty
  DOMAIN_NAME=$(echo "$DOMAIN_NAME" | tr -d '\r')
  
  if [ -n "$DOMAIN_NAME" ]; then
    echo "Installing certbot for SSL certificate acquisition..."
    apt-get update && apt-get install -y certbot || true
    
    echo "Obtaining SSL certificate for $DOMAIN_NAME via certbot..."
    systemctl stop nginx 2>/dev/null || true
    certbot certonly --standalone -d "$DOMAIN_NAME" --non-interactive --agree-tos --register-unsafely-without-email || true
    
    CERT_PATH="/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem"
    KEY_PATH="/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem"
    
    if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
      echo "SSL Certificate acquired successfully!"
      SSL_FLAGS="--cert $CERT_PATH --key $KEY_PATH"
    else
      echo "[Warning] Certbot could not issue certificate for $DOMAIN_NAME. Falling back to HTTP."
    fi
  fi
fi

# Setup config and DB folders
mkdir -p /etc/cheraghtunnel
mkdir -p /var/lib/cheraghtunnel

# Stop any running instance before updating the binary (fixes 'write error' on locked files)
echo "Stopping any running CheraghTunnel services..."
systemctl stop cheraghtunnel 2>/dev/null || true

# Attempt to download pre-compiled release binary to save time (5 seconds vs 15 minutes)
echo "Attempting to download pre-compiled CheraghTunnel release binary..."
DOWNLOAD_SUCCESS=false

ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
  BINARY_SUFFIX="amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
  BINARY_SUFFIX="arm64"
else
  BINARY_SUFFIX="amd64"
fi

URL_DIRECT="https://github.com/iam4lucard/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-$BINARY_SUFFIX"
URL_MIRROR="https://ghfast.top/https://github.com/iam4lucard/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-$BINARY_SUFFIX"

if curl -sSfL --connect-timeout 10 --max-time 60 -o /tmp/cheraghtunnel-new "$URL_DIRECT"; then
    mv /tmp/cheraghtunnel-new /usr/local/bin/cheraghtunnel
    chmod +x /usr/local/bin/cheraghtunnel
    echo "Successfully downloaded pre-compiled binary! Skipping Rust compilation."
    DOWNLOAD_SUCCESS=true
else
    echo "Direct download failed or timed out. Trying mirror..."
    if curl -sSfL --connect-timeout 10 --max-time 60 -o /tmp/cheraghtunnel-new "$URL_MIRROR"; then
        mv /tmp/cheraghtunnel-new /usr/local/bin/cheraghtunnel
        chmod +x /usr/local/bin/cheraghtunnel
        echo "Successfully downloaded pre-compiled binary via mirror! Skipping Rust compilation."
        DOWNLOAD_SUCCESS=true
    else
        rm -f /tmp/cheraghtunnel-new
        echo "Pre-compiled release binary download failed. Falling back to compilation from source..."
    fi
fi

if [ "$DOWNLOAD_SUCCESS" = false ]; then
    # Install system dependencies
    echo "Installing system package dependencies..."
    apt-get update && apt-get install -y build-essential sqlite3 curl git sshpass || true

    # Install Rust toolchain if cargo is missing
    if ! command -v cargo &> /dev/null; then
        echo "Installing Rust compiler..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env 2>/dev/null || . $HOME/.cargo/env 2>/dev/null || true
    fi

    # Prepare source code if Cargo.toml is not in the current working directory
    echo "Preparing CheraghTunnel source code..."
    IS_CLONED=false
    if [ -f "Cargo.toml" ]; then
        echo "Found Cargo.toml in the current directory. Building directly..."
        cargo build --release
    else
        echo "Cargo.toml not found in current directory. Cloning repository from GitHub..."
        rm -rf /tmp/cheraghtunnel-source
        if ! git clone --depth 1 https://github.com/iam4lucard/cheraghtunnel.git /tmp/cheraghtunnel-source; then
            echo "Direct clone failed. Trying mirror..."
            git clone --depth 1 https://ghfast.top/https://github.com/iam4lucard/cheraghtunnel.git /tmp/cheraghtunnel-source
        fi
        cd /tmp/cheraghtunnel-source
        # Source cargo again just in case path needs refresh
        source $HOME/.cargo/env 2>/dev/null || . $HOME/.cargo/env 2>/dev/null || true
        cargo build --release
        IS_CLONED=true
    fi

    # Install binary to system path
    cp target/release/cheraghtunnel /usr/local/bin/cheraghtunnel
    chmod +x /usr/local/bin/cheraghtunnel

    # Cleanup cloned source folder if cloned
    if [ "$IS_CLONED" = true ]; then
        cd - > /dev/null
        rm -rf /tmp/cheraghtunnel-source
    fi
else
    # Install lightweight runtime dependencies only
    echo "Installing runtime dependencies..."
    apt-get update && apt-get install -y sqlite3 curl sshpass || true
fi

# Initialize DB to generate default database schemas
echo "Initializing SQLite Database schema..."
/usr/local/bin/cheraghtunnel panel --port $PANEL_PORT --db-path /var/lib/cheraghtunnel/cheraghtunnel.db > /dev/null 2>&1 &
PID=$!
sleep 2
kill $PID

# Apply custom credentials
echo "Applying custom credentials to Database..."

# Hash the admin password using SHA-256 for database insertion
if command -v openssl &> /dev/null; then
  HASHED_PASS=$(echo -n "$ADMIN_PASS" | openssl dgst -sha256 | sed 's/^.* //')
elif command -v sha256sum &> /dev/null; then
  HASHED_PASS=$(echo -n "$ADMIN_PASS" | sha256sum | cut -d' ' -f1)
else
  HASHED_PASS="$ADMIN_PASS"
fi

sqlite3 /var/lib/cheraghtunnel/cheraghtunnel.db "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_username', '$ADMIN_USER');"
sqlite3 /var/lib/cheraghtunnel/cheraghtunnel.db "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', '$HASHED_PASS');"

# Setup systemd service
echo "Configuring systemd service daemon..."
cat <<EOF > /etc/systemd/system/cheraghtunnel.service
[Unit]
Description=CheraghTunnel Web Management Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/lib/cheraghtunnel
ExecStart=/usr/local/bin/cheraghtunnel panel --port $PANEL_PORT --db-path /var/lib/cheraghtunnel/cheraghtunnel.db $SSL_FLAGS
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cheraghtunnel
systemctl start cheraghtunnel

# Get public and local IPs for display
PUBLIC_IP=$(curl -s --max-time 3 --noproxy "*" ifconfig.me || curl -s --max-time 3 --noproxy "*" api.ipify.org || curl -s --max-time 3 ifconfig.me || echo "")
PRIMARY_LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p')

echo "=========================================================="
echo "  CheraghTunnel Web Panel successfully installed!"
echo "  Access URLs:"
if [ -n "$PUBLIC_IP" ]; then
  echo "    - Public: http://$PUBLIC_IP:$PANEL_PORT"
fi
if [ -n "$PRIMARY_LOCAL_IP" ] && [ "$PRIMARY_LOCAL_IP" != "$PUBLIC_IP" ]; then
  echo "    - Local IP: http://$PRIMARY_LOCAL_IP:$PANEL_PORT"
fi
echo ""
echo "  [Note] If your server is behind a NAT/Firewall, Proxy, or active VPN,"
echo "         please use your server's actual public IP address instead."
echo "  "
echo "  Credentials:"
echo "  Username: $ADMIN_USER"
echo "  Password: $ADMIN_PASS"
echo "=========================================================="
