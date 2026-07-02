use axum::{
    routing::{get, post},
    Router, Json, Extension,
    response::{IntoResponse, Response},
    http::{StatusCode, HeaderMap, header},
    middleware::{self, Next},
    extract::Request,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use rust_embed::RustEmbed;
use sysinfo::System;

use crate::db::{self, Tunnel};
use crate::tunnel;

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

// Global state to track active tunnel tasks
pub struct AppState {
    pub db_path: PathBuf,
    pub active_servers: Mutex<HashMap<i64, tokio::task::JoinHandle<()>>>,
    pub session_token: Mutex<Option<String>>,
    pub system_monitor: Mutex<System>,
}

pub async fn run_panel(port: u16, db_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Pre-create system monitor so CPU stats work correctly
    let mut sys = System::new_all();
    sys.refresh_cpu();
    sys.refresh_memory();

    let state = Arc::new(AppState {
        db_path: db_path.clone(),
        active_servers: Mutex::new(HashMap::new()),
        session_token: Mutex::new(None),
        system_monitor: Mutex::new(sys),
    });

    // Spawn background speed stats flusher
    let db_path_clone = db_path.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            
            // Get registry values and flush them to sqlite
            let registry = crate::tunnel::multiplex::TRAFFIC_REGISTRY.get();
            if let Some(reg) = registry {
                let map = reg.lock().unwrap();
                for (id, tracker) in map.iter() {
                    let rx_bytes = tracker.rx_bytes.swap(0, std::sync::atomic::Ordering::SeqCst);
                    let tx_bytes = tracker.tx_bytes.swap(0, std::sync::atomic::Ordering::SeqCst);
                    
                    // Update live speed snapshot and add to cumulative total
                    if let Err(e) = db::update_tunnel_speeds(&db_path_clone, *id, rx_bytes, tx_bytes) {
                        eprintln!("Failed to update speeds for tunnel {}: {}", id, e);
                    }
                }
            }
        }
    });

    // Spawn background system monitor refresh (every 2s so CPU readings are accurate)
    let state_mon = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            let mut sys = state_mon.system_monitor.lock().await;
            sys.refresh_cpu();
            sys.refresh_memory();
        }
    });

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/", get(static_handler))
        .route("/index.html", get(static_handler))
        .route("/style.css", get(static_handler))
        .route("/app.js", get(static_handler))
        .route("/api/auth/login", post(login_handler))
        // Node script is fetched by curl from remote servers, so it stays public
        .route("/api/tunnels/:id/node-script", get(node_script_handler));

    // Protected routes (require auth token)
    let protected_routes = Router::new()
        .route("/api/tunnels", get(get_tunnels_handler).post(create_tunnel_handler))
        .route("/api/tunnels/:id", get(get_tunnel_handler).put(update_tunnel_handler).delete(delete_tunnel_handler))
        .route("/api/tunnels/:id/toggle", post(toggle_tunnel_handler))
        .route("/api/tunnels/:id/deploy", post(deploy_tunnel_handler))
        .route("/api/stats", get(stats_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let app = public_routes
        .merge(protected_routes)
        .layer(Extension(state));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("Web Panel UI available at: http://127.0.0.1:{}", port);
    axum::serve(listener, app).await?;
    Ok(())
}

// Auth middleware
async fn auth_middleware(
    Extension(state): Extension<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token_lock = state.session_token.lock().await;
    
    if let Some(ref valid_token) = *token_lock {
        // Check Authorization header
        let auth_header = req.headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        
        let expected = format!("Bearer {}", valid_token);
        if auth_header == expected {
            drop(token_lock);
            return Ok(next.run(req).await);
        }
    }
    
    drop(token_lock);
    Err(StatusCode::UNAUTHORIZED)
}

// Embedded Static Asset Server
async fn static_handler(uri: axum::http::Uri) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/').to_string();
    if path.is_empty() || path == "index.html" {
        path = "index.html".to_string();
    }

    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(axum::body::Body::from(content.data))
                .unwrap()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// Authentication Handlers
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    success: bool,
    token: Option<String>,
    message: String,
}

async fn login_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let db_username = db::get_setting(&state.db_path, "admin_username")
        .unwrap_or(Some("admin".to_string()))
        .unwrap_or("admin".to_string());
    let db_password = db::get_setting(&state.db_path, "admin_password")
        .unwrap_or(None)
        .unwrap_or_default();

    if payload.username == db_username && payload.password == db_password {
        // Generate a cryptographically random session token
        let token = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        
        // Store it in shared state
        let mut session = state.session_token.lock().await;
        *session = Some(token.clone());
        
        Json(LoginResponse {
            success: true,
            token: Some(token),
            message: "Login successful".to_string(),
        })
    } else {
        Json(LoginResponse {
            success: false,
            token: None,
            message: "Invalid credentials".to_string(),
        })
    }
}

// Tunnel Management Handlers
async fn get_tunnels_handler(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    match db::get_tunnels(&state.db_path) {
        Ok(list) => (StatusCode::OK, Json(list)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn create_tunnel_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<Tunnel>,
) -> impl IntoResponse {
    match db::create_tunnel(&state.db_path, &payload) {
        Ok(id) => (StatusCode::CREATED, Json(id)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_tunnel_handler(
    Extension(state): Extension<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> impl IntoResponse {
    // First, stop the server if running
    let mut servers = state.active_servers.lock().await;
    if let Some(handle) = servers.remove(&id) {
        handle.abort();
    }
    
    match db::delete_tunnel(&state.db_path, id) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_tunnel_handler(
    Extension(state): Extension<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> impl IntoResponse {
    match db::get_tunnel_by_id(&state.db_path, id) {
        Ok(Some(t)) => (StatusCode::OK, Json(t)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn update_tunnel_handler(
    Extension(state): Extension<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Json(payload): Json<Tunnel>,
) -> impl IntoResponse {
    let mut servers = state.active_servers.lock().await;
    let was_active = servers.contains_key(&id);
    if was_active {
        if let Some(handle) = servers.remove(&id) {
            handle.abort();
        }
    }
    drop(servers);

    match db::update_tunnel(&state.db_path, id, &payload) {
        Ok(_) => {
            if was_active {
                if let Some(t) = db::get_tunnel_by_id(&state.db_path, id).unwrap_or(None) {
                    let _ = start_tunnel_server(state, &t, id).await;
                }
            }
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn start_tunnel_server(state: Arc<AppState>, tunnel: &db::Tunnel, id: i64) -> Result<(), String> {
    let mut servers = state.active_servers.lock().await;
    if servers.contains_key(&id) {
        return Ok(());
    }

    let token = tunnel.token.clone();
    let protocol = tunnel.protocol.clone();
    let control_port = tunnel.control_port;
    let public_port = tunnel.iran_port;
    let decoy = tunnel.decoy_url.clone();

    // Spawn background server task passing correct tunnel ID for speed stats tracking
    let proto_spawn = protocol.clone();
    let state_clone = state.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = tunnel::run_server(control_port, public_port, &token, &proto_spawn, decoy, id).await {
            eprintln!("Background tunnel server daemon error: {}", e);
        }
        let _ = db::update_tunnel_status(&state_clone.db_path, id, "inactive");
        let mut servers = state_clone.active_servers.lock().await;
        servers.remove(&id);
    });

    servers.insert(id, handle);
    let _ = db::update_tunnel_status(&state.db_path, id, "active");
    println!("Spawned background tunnel server daemon for id = {}, protocol = {}", id, protocol);
    Ok(())
}

async fn toggle_tunnel_handler(
    Extension(state): Extension<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> impl IntoResponse {
    let tunnel_opt = db::get_tunnel_by_id(&state.db_path, id).unwrap_or(None);
    
    let tunnel = match tunnel_opt {
        Some(t) => t,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let mut servers = state.active_servers.lock().await;

    if servers.contains_key(&id) {
        // If active, stop it
        if let Some(handle) = servers.remove(&id) {
            handle.abort();
        }
        let _ = db::update_tunnel_status(&state.db_path, id, "inactive");
        println!("Aborted tunnel server daemon for id = {}", id);
        (StatusCode::OK, Json("Tunnel stopped")).into_response()
    } else {
        drop(servers);
        match start_tunnel_server(state, &tunnel, id).await {
            Ok(_) => (StatusCode::OK, Json("Tunnel started")).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        }
    }
}

// SSH Node Deployer Handler
#[derive(Deserialize)]
struct DeployRequest {
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
    panel_host: String,
}

async fn deploy_tunnel_handler(
    Extension(state): Extension<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Json(payload): Json<DeployRequest>,
) -> impl IntoResponse {
    let tunnel_opt = db::get_tunnel_by_id(&state.db_path, id).unwrap_or(None);
    let tunnel = match tunnel_opt {
        Some(t) => t,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Auto-start server on Iran side so the control port is listening when Kharej connects!
    let _ = start_tunnel_server(state.clone(), &tunnel, id).await;

    let db_path_spawn = state.db_path.clone();
    
    // Set tunnel status to deploying
    let _ = db::update_tunnel_status(&state.db_path, id, "deploying");

    // Spawn deployment task using tokio::process::Command (non-blocking!)
    tokio::spawn(async move {
        println!("[DEPLOY] Initiating SSH deployment on {}@{}...", payload.username, payload.host);
        
        let node_url = format!("http://{}/api/tunnels/{}/node-script", payload.panel_host, id);
        let remote_cmd = format!("curl -sSfL -o /tmp/node.sh {} && bash /tmp/node.sh && rm -f /tmp/node.sh", node_url);
        
        let password_str = payload.password.unwrap_or_default();
        let result = tokio::process::Command::new("sshpass")
            .args(&[
                "-p", &password_str,
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-p", &payload.port.to_string(),
                &format!("{}@{}", payload.username, payload.host),
                &remote_cmd
            ])
            .output()
            .await;

        match result {
            Ok(output) => {
                if output.status.success() {
                    println!("[DEPLOY] SSH deployment for tunnel {} finished successfully", id);
                    let _ = db::update_tunnel_status(&db_path_spawn, id, "active");
                } else {
                    let err_msg = String::from_utf8_lossy(&output.stderr);
                    eprintln!("[DEPLOY] SSH deployment for tunnel {} failed: {}", id, err_msg);
                    let _ = db::update_tunnel_status(&db_path_spawn, id, "error");
                }
            }
            Err(e) => {
                eprintln!("[DEPLOY] Failed to run sshpass process: {}", e);
                let _ = db::update_tunnel_status(&db_path_spawn, id, "error");
            }
        }
    });

    (StatusCode::OK, Json("Deployment started in background")).into_response()
}

// Generate Kharej Server Node Installer Script
async fn node_script_handler(
    Extension(state): Extension<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tunnel_opt = db::get_tunnel_by_id(&state.db_path, id).unwrap_or(None);
    let tunnel = match tunnel_opt {
        Some(t) => t,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Get host from request headers to auto-fill Iran server IP
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("127.0.0.1")
        .split(':')
        .next()
        .unwrap_or("127.0.0.1");

    // Add multi-IP list if backup IPs exist
    let mut ips = host.to_string();
    if let Some(ref backups) = tunnel.backup_ips {
        if !backups.trim().is_empty() {
            ips = format!("{},{}", host, backups);
        }
    }

    let script = format!(
        r#"#!/bin/bash
# CheraghTunnel Node Installer Script
set -e

IRAN_IP="{}"
CONTROL_PORT="{}"
PUBLIC_PORT="{}"
LOCAL_PORT="{}"
TOKEN="{}"
PROTOCOL="{}"
TUNNEL_ID="{}"

echo "=================================================="
echo "  Installing CheraghTunnel Client Node..."
echo "  Target Server: $IRAN_IP:$CONTROL_PORT"
echo "  Forwarding Public Port: $PUBLIC_PORT -> Local: $LOCAL_PORT"
echo "=================================================="

# Setup working directories
mkdir -p /etc/cheraghtunnel
mkdir -p /tmp/cheraghtunnel

# Attempt to download pre-compiled release binary to save time (5 seconds vs 15 minutes)
echo "Attempting to download pre-compiled CheraghTunnel release binary..."
DOWNLOAD_SUCCESS=false
systemctl stop cheragh-node-$TUNNEL_ID 2>/dev/null || true
if curl -sSfL -o /tmp/cheraghtunnel-new "https://github.com/iambaradaran/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-amd64"; then
    mv /tmp/cheraghtunnel-new /usr/local/bin/cheraghtunnel
    chmod +x /usr/local/bin/cheraghtunnel
    echo "Successfully downloaded pre-compiled binary! Skipping Rust compilation."
    DOWNLOAD_SUCCESS=true
else
    rm -f /tmp/cheraghtunnel-new
    echo "Pre-compiled release binary not found or download failed. Falling back to compilation from source..."
fi

if [ "$DOWNLOAD_SUCCESS" = false ]; then
    # Install dependencies for compilation
    echo "Installing system package dependencies for compilation..."
    apt-get update && apt-get install -y build-essential sqlite3 curl git sshpass || true

    # Install Rust toolchain if not present
    if ! command -v cargo &> /dev/null; then
        echo "Installing Rust compilation toolchain..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
    fi

    echo "Cloning and compiling CheraghTunnel from source..."
    rm -rf /tmp/cheraghtunnel-source
    git clone https://github.com/iambaradaran/cheraghtunnel.git /tmp/cheraghtunnel-source
    cd /tmp/cheraghtunnel-source
    source $HOME/.cargo/env 2>/dev/null || . $HOME/.cargo/env 2>/dev/null || true
    cargo build --release
    mv target/release/cheraghtunnel /usr/local/bin/cheraghtunnel
    chmod +x /usr/local/bin/cheraghtunnel
    cd - > /dev/null
    rm -rf /tmp/cheraghtunnel-source
else
    # Install lightweight runtime dependencies only
    echo "Installing runtime dependencies..."
    apt-get update && apt-get install -y sqlite3 curl sshpass || true
fi

# Setup systemd daemon
cat <<EOF > /etc/systemd/system/cheragh-node-$TUNNEL_ID.service
[Unit]
Description=CheraghTunnel Client Node - $PROTOCOL ($TUNNEL_ID)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cheraghtunnel client -s $IRAN_IP -c $CONTROL_PORT -p $PUBLIC_PORT -l 127.0.0.1:$LOCAL_PORT -t $TOKEN --protocol $PROTOCOL --tunnel-id $TUNNEL_ID
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cheragh-node-$TUNNEL_ID
systemctl start cheragh-node-$TUNNEL_ID
echo "Setup completed successfully!"
"#,
        ips, tunnel.control_port, tunnel.iran_port, tunnel.kharej_port, tunnel.token, tunnel.protocol, id
    );

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-sh"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"node.sh\""),
        ],
        script,
    ).into_response()
}

// System Resources & Traffic metrics Handler
#[derive(Serialize)]
struct SystemStats {
    cpu_usage: f32,
    mem_usage: f32,
    active_tunnels: usize,
    total_tunnels: usize,
}

async fn stats_handler(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    let sys = state.system_monitor.lock().await;

    let cpu_usage = sys.global_cpu_info().cpu_usage();
    let total_mem = sys.total_memory();
    let mem_usage = if total_mem > 0 {
        (sys.used_memory() as f32 / total_mem as f32) * 100.0
    } else {
        0.0
    };
    drop(sys);
    
    let tunnels = db::get_tunnels(&state.db_path).unwrap_or_default();
    let total_tunnels = tunnels.len();
    let active_tunnels = tunnels.iter().filter(|t| t.status == "active").count();

    Json(SystemStats {
        cpu_usage,
        mem_usage,
        active_tunnels,
        total_tunnels,
    })
}
