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

# Validate port is a number
if ! [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] || [ "$PANEL_PORT" -lt 1 ] || [ "$PANEL_PORT" -gt 65535 ]; then
  echo "Invalid port. Using default: 8000"
  PANEL_PORT=8000
fi

# 2. Custom Admin Username
read -p "Enter Admin Username [Default: admin]: " ADMIN_USER < /dev/tty
ADMIN_USER=${ADMIN_USER:-admin}

# 3. Custom Admin Password
read -s -p "Enter Admin Password [Press Enter to generate a random one]: " ADMIN_PASS < /dev/tty
echo "" # New line after hidden password input
if [ -z "$ADMIN_PASS" ]; then
  ADMIN_PASS="cheragh_$(openssl rand -hex 3 2>/dev/null || echo $((RANDOM % 90000 + 10000)))"
  echo "Generated random password: $ADMIN_PASS"
fi

# Setup config and DB folders
mkdir -p /etc/cheraghtunnel
mkdir -p /var/lib/cheraghtunnel

# Attempt to download pre-compiled release binary to save time (5 seconds vs 15 minutes)
echo "Attempting to download pre-compiled CheraghTunnel release binary..."
DOWNLOAD_SUCCESS=false
if curl -sSfL -o /usr/local/bin/cheraghtunnel "https://github.com/iambaradaran/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-amd64"; then
    chmod +x /usr/local/bin/cheraghtunnel
    echo "Successfully downloaded pre-compiled binary! Skipping Rust compilation."
    DOWNLOAD_SUCCESS=true
else
    echo "Pre-compiled release binary not found or download failed. Falling back to compilation from source..."
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
        git clone https://github.com/iambaradaran/cheraghtunnel.git /tmp/cheraghtunnel-source
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
sqlite3 /var/lib/cheraghtunnel/cheraghtunnel.db "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_username', '$ADMIN_USER');"
sqlite3 /var/lib/cheraghtunnel/cheraghtunnel.db "INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', '$ADMIN_PASS');"

# Setup systemd service
echo "Configuring systemd service daemon..."
cat <<EOF > /etc/systemd/system/cheraghtunnel.service
[Unit]
Description=CheraghTunnel Web Management Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/lib/cheraghtunnel
ExecStart=/usr/local/bin/cheraghtunnel panel --port $PANEL_PORT --db-path /var/lib/cheraghtunnel/cheraghtunnel.db
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cheraghtunnel
systemctl start cheraghtunnel

echo "=========================================================="
echo "  CheraghTunnel Web Panel successfully installed!"
echo "  Access URL: http://$(curl -s ifconfig.me || echo "YOUR_SERVER_IP"):$PANEL_PORT"
echo "  "
echo "  Credentials:"
echo "  Username: $ADMIN_USER"
echo "  Password: $ADMIN_PASS"
echo "=========================================================="
