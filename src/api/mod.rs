use axum::{
    routing::{get, post},
    Router, Json, Extension,
    response::{IntoResponse, Response},
    http::{StatusCode, HeaderMap, header},
    middleware::{self, Next},
    extract::{Request, Multipart},
};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use rust_embed::RustEmbed;
use sysinfo::System;

use crate::db::{self, Tunnel};

/// Constant-time byte comparison to prevent timing side-channel attacks.
/// Always compares all bytes regardless of mismatch position.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

/// Simple in-memory login rate limiter.
/// Tracks failed login attempts and blocks after MAX_ATTEMPTS within WINDOW_SECS.
pub struct LoginRateLimiter {
    attempt_count: AtomicU32,
    window_start: AtomicU64,
}

impl LoginRateLimiter {
    const MAX_ATTEMPTS: u32 = 5;
    const WINDOW_SECS: u64 = 60;

    fn new() -> Self {
        Self {
            attempt_count: AtomicU32::new(0),
            window_start: AtomicU64::new(0),
        }
    }

    fn check_and_record(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window = self.window_start.load(Ordering::SeqCst);

        if now.saturating_sub(window) > Self::WINDOW_SECS {
            // Reset window
            self.window_start.store(now, Ordering::SeqCst);
            self.attempt_count.store(1, Ordering::SeqCst);
            return true; // allowed
        }

        let count = self.attempt_count.fetch_add(1, Ordering::SeqCst) + 1;
        count <= Self::MAX_ATTEMPTS
    }

    fn reset(&self) {
        self.attempt_count.store(0, Ordering::SeqCst);
    }
}


// Global state to track active tunnel tasks
pub struct AppState {
    pub db_path: PathBuf,
    
    pub session_token: Mutex<Option<String>>,
    pub system_monitor: Mutex<System>,
    pub login_limiter: LoginRateLimiter,
}

pub async fn run_panel(
    port: u16,
    db_path: PathBuf,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Pre-create system monitor so CPU stats work correctly
    let mut sys = System::new_all();
    sys.refresh_cpu();
    sys.refresh_memory();

    let state = Arc::new(AppState {
        db_path: db_path.clone(),
        
        session_token: Mutex::new(None),
        system_monitor: Mutex::new(sys),
        login_limiter: LoginRateLimiter::new(),
    });

    // Spawn background system monitor refresher to update CPU & Memory metrics
    let state_clone = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            let mut sys = state_clone.system_monitor.lock().await;
            sys.refresh_cpu();
            sys.refresh_memory();
        }
    });
    
    // Spawn background telemetry fetcher & quota/expiry monitor
    let db_path_clone = db_path.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            
            if let Ok(tunnels) = db::get_tunnels(&db_path_clone) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                for t in tunnels {
                    if t.status == "active" {
                        // Check expiry date
                        if let Some(exp) = t.expires_at {
                            if exp > 0 && now >= exp {
                                println!("[PANEL] Tunnel '{}' (ID {:?}) expired. Shutting down...", t.name, t.id);
                                let _ = db::update_tunnel_status(&db_path_clone, t.id.unwrap(), "expired");
                                continue;
                            }
                        }
                        // Check quota limit
                        let quota_limit = t.quota_limit_bytes.unwrap_or(0);
                        let quota_used = t.quota_used_bytes.unwrap_or(0);
                        if quota_limit > 0 && quota_used >= quota_limit {
                            println!("[PANEL] Tunnel '{}' (ID {:?}) quota limit reached. Shutting down...", t.name, t.id);
                            let _ = db::update_tunnel_status(&db_path_clone, t.id.unwrap(), "quota_exceeded");
                            continue;
                        }

                        if let Some(iran_id) = t.iran_node_id {
                            if let Ok(Some(iran_node)) = db::get_node_by_id(&db_path_clone, iran_id) {
                                let api_port = 18000 + t.id.unwrap_or(0) as u16;
                                let url = format!("http://{}:{}/api/stats", iran_node.host, api_port);
                                
                                if let Ok(resp) = reqwest::get(&url).await {
                                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                                        let rx_delta = json["rx_delta"].as_u64().unwrap_or(0);
                                        let tx_delta = json["tx_delta"].as_u64().unwrap_or(0);
                                        let speed_rx = json["speed_rx"].as_u64().unwrap_or(0);
                                        let speed_tx = json["speed_tx"].as_u64().unwrap_or(0);
                                        let rtt_ms = json["rtt_ms"].as_f64().unwrap_or(999.0);
                                        let loss = json["packet_loss"].as_f64().unwrap_or(100.0);
                                        
                                        let _ = db::update_tunnel_speeds(&db_path_clone, t.id.unwrap(), rx_delta, tx_delta, speed_rx, speed_tx);
                                        let _ = db::log_telemetry(&db_path_clone, t.id.unwrap(), rtt_ms, loss);

                                        let probe_status = if rtt_ms < 500.0 && loss < 90.0 { "active" } else { "unreachable" };
                                        let _ = db::update_tunnel_probe(&db_path_clone, t.id.unwrap(), probe_status, rtt_ms);
                                    } else {
                                        let _ = db::update_tunnel_probe(&db_path_clone, t.id.unwrap(), "unreachable", 999.0);
                                    }
                                } else {
                                    let _ = db::update_tunnel_probe(&db_path_clone, t.id.unwrap(), "unreachable", 999.0);
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // Spawn background Node Health Checker & Automatic Failover Worker
    let db_path_node_check = db_path.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            if let Ok(nodes) = db::get_nodes(&db_path_node_check) {
                for node in nodes {
                    if let Some(node_id) = node.id {
                        let addr = format!("{}:{}", node.host, node.port);
                        let start = std::time::Instant::now();
                        let (status, latency) = match tokio::time::timeout(
                            tokio::time::Duration::from_secs(3),
                            tokio::net::TcpStream::connect(&addr),
                        ).await {
                            Ok(Ok(_)) => ("active", start.elapsed().as_secs_f64() * 1000.0),
                            _ => ("unreachable", 999.0),
                        };
                        let _ = db::update_node_health(&db_path_node_check, node_id, status, latency);

                        // Failover check if node is unreachable
                        if status == "unreachable" && (node.role == "kharej" || node.role == "both") {
                            if let Ok(tunnels) = db::get_tunnels(&db_path_node_check) {
                                for mut t in tunnels {
                                    if t.kharej_node_id == Some(node_id) && t.status == "active" {
                                        let backup_nodes: Vec<_> = db::get_nodes(&db_path_node_check)
                                            .unwrap_or_default()
                                            .into_iter()
                                            .filter(|n| n.id != Some(node_id) && n.status.as_deref() == Some("active") && (n.role == "kharej" || n.role == "both"))
                                            .collect();
                                        
                                        if let Some(backup) = backup_nodes.first() {
                                            println!("[FAILOVER] Kharej Node '{}' is unreachable. Failing over Tunnel '{}' to backup Node '{}'", node.name, t.name, backup.name);
                                            t.kharej_node_id = backup.id;
                                            let _ = db::update_tunnel(&db_path_node_check, t.id.unwrap(), &t);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/", get(static_handler))
        .route("/index.html", get(static_handler))
        .route("/style.css", get(static_handler))
        .route("/app.js", get(static_handler))
        .route("/api/auth/login", post(login_handler))
        .route("/api/ws/telemetry", get(ws_telemetry_handler))
        // Node script is fetched by curl from remote servers, so it stays public
        .route("/api/tunnels/:id/node-script", get(node_script_handler));

    // Protected routes (require auth token)
    let protected_routes = Router::new()
        .route("/api/tunnels", get(get_tunnels_handler).post(create_tunnel_handler))
        .route("/api/tunnels/:id", get(get_tunnel_handler).put(update_tunnel_handler).delete(delete_tunnel_handler))
        .route("/api/tunnels/:id/toggle", post(toggle_tunnel_handler))
        .route("/api/tunnels/:id/telemetry", get(telemetry_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/nodes", get(get_nodes_handler).post(create_node_handler))
        .route("/api/nodes/:id", axum::routing::delete(delete_node_handler))
        .route("/api/backup", get(backup_handler))
        .route("/api/restore", post(restore_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let app = public_routes
        .merge(protected_routes)
        .layer(Extension(state));

    if let (Some(cert), Some(key)) = (cert_path, key_path) {
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
        println!("Web Panel UI (HTTPS) available at: https://0.0.0.0:{}", port);
        axum_server::bind_rustls(format!("0.0.0.0:{}", port).parse()?, config)
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        println!("Web Panel UI (HTTP) available at: http://127.0.0.1:{}", port);
        axum::serve(listener, app).await?;
    }
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
        // 1. Check Authorization header
        let auth_header = req.headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let expected = format!("Bearer {}", valid_token);
        
        // 2. Check token in query parameter (useful for direct file downloads)
        let query_token = req.uri().query()
            .and_then(|q| {
                q.split('&')
                    .find(|p| p.starts_with("token="))
                    .map(|p| p.trim_start_matches("token="))
            })
            .unwrap_or("");

        if constant_time_eq(auth_header.as_bytes(), expected.as_bytes())
            || constant_time_eq(query_token.as_bytes(), valid_token.as_bytes())
        {
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
                .header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0")
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
    // Rate limit check: block after 5 failed attempts within 60 seconds
    if !state.login_limiter.check_and_record() {
        return Json(LoginResponse {
            success: false,
            token: None,
            message: "Too many login attempts. Please wait 60 seconds.".to_string(),
        });
    }

    let db_username = db::get_setting(&state.db_path, "admin_username")
        .unwrap_or(Some("admin".to_string()))
        .unwrap_or("admin".to_string());
    let db_password = db::get_setting(&state.db_path, "admin_password")
        .unwrap_or(None)
        .unwrap_or_default();

    if constant_time_eq(payload.username.as_bytes(), db_username.as_bytes()) && db::verify_password(&payload.password, &db_password) {
        // Reset rate limiter on successful login
        state.login_limiter.reset();

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

async fn telemetry_handler(
    Extension(state): Extension<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> impl IntoResponse {
    match db::get_recent_telemetry(&state.db_path, id, 100) {
        Ok(logs) => {
            let list: Vec<serde_json::Value> = logs.into_iter().map(|(rtt, loss, ts)| {
                serde_json::json!({
                    "rtt_ms": rtt,
                    "packet_loss": loss,
                    "timestamp": ts
                })
            }).collect();
            (StatusCode::OK, Json(list)).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_string())).into_response()
        }
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
    match db::get_tunnels(&state.db_path) {
        Ok(tunnels) => {
            for t in tunnels {
                if t.iran_node_id == payload.iran_node_id {
                    if t.iran_port == payload.iran_port {
                        return (StatusCode::BAD_REQUEST, "Public port is already in use on this server").into_response();
                    }
                    if t.control_port == payload.control_port {
                        return (StatusCode::BAD_REQUEST, "Control port is already in use on this server").into_response();
                    }
                }
            }
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    match db::create_tunnel(&state.db_path, &payload) {
        Ok(id) => (StatusCode::CREATED, Json(id)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_tunnel_handler(
    Extension(state): Extension<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> impl IntoResponse {
    if let Ok(Some(tunnel)) = db::get_tunnel_by_id(&state.db_path, id) {
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Some(i_id) = tunnel.iran_node_id {
                if let Ok(Some(n)) = db::get_node_by_id(&state_clone.db_path, i_id) {
                    let cmd = format!(
                        "systemctl stop cheragh-server-{} || true && systemctl disable cheragh-server-{} || true && rm -f /etc/systemd/system/cheragh-server-{}.service && rm -f /usr/local/bin/cheraghtunnel-{} && systemctl daemon-reload",
                        id, id, id, id
                    );
                    let _ = run_ssh_command(&n, &cmd, None).await;
                }
            }
            if let Some(k_id) = tunnel.kharej_node_id {
                if let Ok(Some(n)) = db::get_node_by_id(&state_clone.db_path, k_id) {
                    let cmd = format!(
                        "systemctl stop cheragh-node-{} || true && systemctl disable cheragh-node-{} || true && rm -f /etc/systemd/system/cheragh-node-{}.service && rm -f /usr/local/bin/cheraghtunnel-{} && systemctl daemon-reload",
                        id, id, id, id
                    );
                    let _ = run_ssh_command(&n, &cmd, None).await;
                }
            }
        });
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
    match db::get_tunnels(&state.db_path) {
        Ok(tunnels) => {
            for t in tunnels {
                if t.id != Some(id) {
                    if t.iran_node_id == payload.iran_node_id {
                        if t.iran_port == payload.iran_port {
                            return (StatusCode::BAD_REQUEST, "Public port is already in use on this server").into_response();
                        }
                        if t.control_port == payload.control_port {
                            return (StatusCode::BAD_REQUEST, "Control port is already in use on this server").into_response();
                        }
                    }
                }
            }
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    let tunnel_opt = db::get_tunnel_by_id(&state.db_path, id).unwrap_or(None);
    let was_active = if let Some(t) = &tunnel_opt { t.status == "active" } else { false };
    
    match db::update_tunnel(&state.db_path, id, &payload) {
        Ok(_) => {
            if was_active {
                let state_clone = state.clone();
                tokio::spawn(async move {
                    if let Ok(Some(tunnel)) = db::get_tunnel_by_id(&state_clone.db_path, id) {
                        if let Some(i_id) = tunnel.iran_node_id {
                            if let Ok(Some(n)) = db::get_node_by_id(&state_clone.db_path, i_id) {
                                let server_script = generate_server_script(&tunnel);
                                let cmd = "cat > /tmp/server.sh && bash /tmp/server.sh && rm -f /tmp/server.sh";
                                let _ = run_ssh_command(&n, cmd, Some(&server_script)).await;
                            }
                        }
                        if let Some(k_id) = tunnel.kharej_node_id {
                            if let Ok(Some(k_n)) = db::get_node_by_id(&state_clone.db_path, k_id) {
                                if let Some(i_id) = tunnel.iran_node_id {
                                    if let Ok(Some(i_n)) = db::get_node_by_id(&state_clone.db_path, i_id) {
                                        let client_script = generate_client_script(&tunnel, &i_n.host);
                                        let cmd = "cat > /tmp/client.sh && bash /tmp/client.sh && rm -f /tmp/client.sh";
                                        let _ = run_ssh_command(&k_n, cmd, Some(&client_script)).await;
                                    }
                                }
                            }
                        }
                    }
                });
            }
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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

    if tunnel.status == "active" {
        let _ = db::update_tunnel_status(&state.db_path, id, "inactive");
        
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Some(i_id) = tunnel.iran_node_id {
                if let Ok(Some(n)) = db::get_node_by_id(&state_clone.db_path, i_id) {
                    let _ = run_ssh_command(&n, &format!("systemctl disable cheragh-server-{} && systemctl stop cheragh-server-{}", tunnel.id.unwrap(), tunnel.id.unwrap()), None).await;
                }
            }
            if let Some(k_id) = tunnel.kharej_node_id {
                if let Ok(Some(n)) = db::get_node_by_id(&state_clone.db_path, k_id) {
                    let _ = run_ssh_command(&n, &format!("systemctl disable cheragh-node-{} && systemctl stop cheragh-node-{}", tunnel.id.unwrap(), tunnel.id.unwrap()), None).await;
                }
            }
        });
        StatusCode::OK.into_response()
    } else {
        // Find saved Iran and Kharej nodes
        let iran_node_id = match tunnel.iran_node_id {
            Some(id) => id,
            None => return (StatusCode::BAD_REQUEST, "Iran Node is not selected for this tunnel").into_response(),
        };
        let kharej_node_id = match tunnel.kharej_node_id {
            Some(id) => id,
            None => return (StatusCode::BAD_REQUEST, "Kharej Node is not selected for this tunnel").into_response(),
        };

        let iran_node = match db::get_node_by_id(&state.db_path, iran_node_id).unwrap_or(None) {
            Some(n) => n,
            None => return (StatusCode::BAD_REQUEST, "Selected Iran Node not found").into_response(),
        };
        let kharej_node = match db::get_node_by_id(&state.db_path, kharej_node_id).unwrap_or(None) {
            Some(n) => n,
            None => return (StatusCode::BAD_REQUEST, "Selected Kharej Node not found").into_response(),
        };

        let _ = db::update_tunnel_status(&state.db_path, id, "deploying");
        let db_path_spawn = state.db_path.clone();

        tokio::spawn(async move {
            // Deploy Iran Server
            let server_script = generate_server_script(&tunnel);
            let cmd = "cat > /tmp/server.sh && bash /tmp/server.sh && rm -f /tmp/server.sh";
            if let Err(e) = run_ssh_command(&iran_node, cmd, Some(&server_script)).await {
                eprintln!("[DEPLOY] Iran Node SSH failed: {}", e);
                let _ = db::update_tunnel_status(&db_path_spawn, id, "error");
                return;
            }

            // Deploy Kharej Client
            let client_script = generate_client_script(&tunnel, &iran_node.host);
            let cmd = "cat > /tmp/client.sh && bash /tmp/client.sh && rm -f /tmp/client.sh";
            if let Err(e) = run_ssh_command(&kharej_node, cmd, Some(&client_script)).await {
                eprintln!("[DEPLOY] Kharej Node SSH failed: {}", e);
                let _ = db::update_tunnel_status(&db_path_spawn, id, "error");
                return;
            }

            let _ = db::update_tunnel_status(&db_path_spawn, id, "active");
        });

        StatusCode::OK.into_response()
    }
}

async fn run_ssh_command(
    node: &db::Node,
    command: &str,
    stdin_data: Option<&str>,
) -> Result<String, String> {
    let key_path = if let Some(pk) = &node.private_key {
        if pk.trim().is_empty() { None } else {
            let path = format!("/tmp/cheragh_key_{}_{}", node.id.unwrap_or(0), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros());
            let _ = tokio::fs::write(&path, pk).await;
            let mut perms_cmd = tokio::process::Command::new("chmod");
            perms_cmd.args(["600", &path]);
            let _ = perms_cmd.output().await;
            Some(path)
        }
    } else { None };

    let mut ssh_cmd = tokio::process::Command::new(if key_path.is_none() { "sshpass" } else { "ssh" });
    
    if let Some(path) = &key_path {
        ssh_cmd.args([
            "-i", path,
            "-o", "StrictHostKeyChecking=no",
            "-p", &node.port.to_string(),
            &format!("{}@{}", node.username, node.host),
            command
        ]);
    } else {
        ssh_cmd.args([
            "-p", node.password.as_deref().unwrap_or_default(),
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-p", &node.port.to_string(),
            &format!("{}@{}", node.username, node.host),
            command
        ]);
    }

    if stdin_data.is_some() {
        ssh_cmd.stdin(std::process::Stdio::piped());
    }
    ssh_cmd.stdout(std::process::Stdio::piped());
    ssh_cmd.stderr(std::process::Stdio::piped());

    let mut child = ssh_cmd.spawn().map_err(|e| e.to_string())?;

    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(data.as_bytes()).await;
        }
    }

    let output = child.wait_with_output().await.map_err(|e| e.to_string())?;
    
    if let Some(path) = key_path {
        let _ = tokio::fs::remove_file(path).await;
    }

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn generate_server_script(tunnel: &db::Tunnel) -> String {
    let port_hop_flag = if tunnel.port_hopping.unwrap_or(0) == 1 { "--port-hopping" } else { "" };
    let decoy = tunnel.decoy_url.clone().unwrap_or_else(|| "google.com".to_string());
    let api_port = 18000 + tunnel.id.unwrap_or(0) as u16;
    let transport_opts_str = tunnel.transport_options.clone().unwrap_or_else(|| "{}".to_string());

    format!(
        r#"#!/bin/bash
set -e
mkdir -p /etc/cheraghtunnel

# Stop the existing service BEFORE replacing the binary to prevent ETXTBSY (Text file busy)
systemctl stop cheragh-server-{id} 2>/dev/null || true

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    BINARY_URL="https://github.com/iam4lucard/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-arm64"
else
    BINARY_URL="https://github.com/iam4lucard/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-amd64"
fi

# Download to a temp file on the SAME filesystem as the destination to ensure atomic rename
curl -sSfL -o /usr/local/bin/cheraghtunnel-{id}.tmp "$BINARY_URL" || true
if [ -f "/usr/local/bin/cheraghtunnel-{id}.tmp" ]; then
    chmod +x /usr/local/bin/cheraghtunnel-{id}.tmp
    # Atomic rename: replaces binary only after fully downloaded, avoids Text-file-busy
    mv /usr/local/bin/cheraghtunnel-{id}.tmp /usr/local/bin/cheraghtunnel-{id}
fi

cat << 'EOF' > /etc/systemd/system/cheragh-server-{id}.service
[Unit]
Description=CheraghTunnel Server {id}
After=network.target

[Service]
ExecStart=/usr/local/bin/cheraghtunnel-{id} server -c {control_port} -p {public_port} -t '{token}' --protocol {protocol} --decoy '{decoy}' {port_hop_flag} --api-port {api_port} --transport-options '{transport_options}'
Restart=always
RestartSec=2s
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cheragh-server-{id}
systemctl start cheragh-server-{id}
"#,
        id = tunnel.id.unwrap_or(0),
        control_port = tunnel.control_port,
        public_port = tunnel.iran_port,
        token = tunnel.token,
        protocol = tunnel.protocol,
        decoy = decoy,
        port_hop_flag = port_hop_flag,
        api_port = api_port,
        transport_options = transport_opts_str,
    )
}

fn generate_client_script(tunnel: &db::Tunnel, iran_ip: &str) -> String {
    let port_hop_flag = if tunnel.port_hopping.unwrap_or(0) == 1 { "--port-hopping" } else { "" };
    let decoy = tunnel.decoy_url.clone().unwrap_or_else(|| "google.com".to_string());
    let transport_opts_str = tunnel.transport_options.clone().unwrap_or_else(|| "{}".to_string());
    
    format!(
        r#"#!/bin/bash
set -e
mkdir -p /etc/cheraghtunnel

# Stop the existing service BEFORE replacing the binary to prevent ETXTBSY (Text file busy)
systemctl stop cheragh-node-{id} 2>/dev/null || true

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    BINARY_URL="https://github.com/iam4lucard/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-arm64"
else
    BINARY_URL="https://github.com/iam4lucard/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-amd64"
fi

# Download to a temp file on the SAME filesystem as the destination to ensure atomic rename
curl -sSfL -o /usr/local/bin/cheraghtunnel-{id}.tmp "$BINARY_URL" || true
if [ -f "/usr/local/bin/cheraghtunnel-{id}.tmp" ]; then
    chmod +x /usr/local/bin/cheraghtunnel-{id}.tmp
    # Atomic rename: replaces binary only after fully downloaded, avoids Text-file-busy
    mv /usr/local/bin/cheraghtunnel-{id}.tmp /usr/local/bin/cheraghtunnel-{id}
fi

cat << 'EOF' > /etc/systemd/system/cheragh-node-{id}.service
[Unit]
Description=CheraghTunnel Client Node {id}
After=network.target

[Service]
ExecStart=/usr/local/bin/cheraghtunnel-{id} client -s {iran_ip} -c {control_port} -p {public_port} -l 127.0.0.1:{kharej_port} -t '{token}' --protocol {protocol} --tunnel-id {id} --decoy '{decoy}' {port_hop_flag} --transport-options '{transport_options}'
Restart=always
RestartSec=2s
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cheragh-node-{id}
systemctl start cheragh-node-{id}
"#,
        id = tunnel.id.unwrap_or(0),
        iran_ip = iran_ip,
        control_port = tunnel.control_port,
        public_port = tunnel.iran_port,
        kharej_port = tunnel.kharej_port,
        token = tunnel.token,
        protocol = tunnel.protocol,
        decoy = decoy,
        port_hop_flag = port_hop_flag,
        transport_options = transport_opts_str,
    )
}



// ------------------------------------------------------------------
// Nodes CRUD Handlers
// ------------------------------------------------------------------

async fn get_nodes_handler(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    match db::get_nodes(&state.db_path) {
        Ok(nodes) => (StatusCode::OK, Json(nodes)).into_response(),
        Err(e) => {
            eprintln!("[API] Error fetching nodes: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn create_node_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<db::Node>,
) -> impl IntoResponse {
    match db::create_node(&state.db_path, &payload) {
        Ok(id) => (StatusCode::OK, Json(id)).into_response(),
        Err(e) => {
            eprintln!("[API] Error creating node: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn delete_node_handler(
    Extension(state): Extension<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> impl IntoResponse {
    match db::delete_node(&state.db_path, id) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            eprintln!("[API] Error deleting node: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

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

    let script = generate_client_script(&tunnel, host);

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

// ------------------------------------------------------------------
// Backup & Restore Handlers
// ------------------------------------------------------------------

async fn backup_handler(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    match tokio::fs::read(&state.db_path).await {
        Ok(data) => {
            let len = data.len();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_DISPOSITION, "attachment; filename=\"cheragh_backup.sqlite\"")
                .header(header::CONTENT_LENGTH, len)
                .body(axum::body::Body::from(data))
                .unwrap()
        }
        Err(e) => {
            eprintln!("[API] Failed to read database for backup: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("Failed to generate backup"))
                .unwrap()
        }
    }
}

async fn restore_handler(
    Extension(state): Extension<Arc<AppState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    if let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => return (StatusCode::BAD_REQUEST, format!("Failed to read upload: {}", e)).into_response(),
        };

        let tmp_path = std::env::temp_dir().join("cheragh_restore_tmp.sqlite");
        if let Err(e) = tokio::fs::write(&tmp_path, &data).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save temp file: {}", e)).into_response();
        }

        if let Err(e) = rusqlite::Connection::open(&tmp_path) {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return (StatusCode::BAD_REQUEST, format!("Invalid SQLite file: {}", e)).into_response();
        }

        if let Err(e) = tokio::fs::rename(&tmp_path, &state.db_path).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to restore database: {}", e)).into_response();
        }

        return StatusCode::OK.into_response();
    }
    
    (StatusCode::BAD_REQUEST, "No file uploaded".to_string()).into_response()
}

// ------------------------------------------------------------------
// Real-Time WebSocket Telemetry Stream
// ------------------------------------------------------------------

async fn ws_telemetry_handler(
    ws: axum::extract::ws::WebSocketUpgrade,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_ws_telemetry(socket, state))
}

async fn handle_ws_telemetry(mut socket: axum::extract::ws::WebSocket, state: Arc<AppState>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    loop {
        interval.tick().await;
        let tunnels = db::get_tunnels(&state.db_path).unwrap_or_default();
        let nodes = db::get_nodes(&state.db_path).unwrap_or_default();

        let sys = state.system_monitor.lock().await;
        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let total_mem = sys.total_memory();
        let mem_usage = if total_mem > 0 {
            (sys.used_memory() as f32 / total_mem as f32) * 100.0
        } else {
            0.0
        };
        drop(sys);
        
        let payload = serde_json::json!({
            "type": "telemetry_update",
            "cpu_usage": cpu_usage,
            "mem_usage": mem_usage,
            "tunnels": tunnels,
            "nodes": nodes,
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });

        if socket.send(axum::extract::ws::Message::Text(payload.to_string())).await.is_err() {
            break;
        }
    }
}
