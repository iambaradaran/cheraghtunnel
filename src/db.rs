use rusqlite::{params, Connection, Result};
use std::path::Path;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Tunnel {
    pub id: Option<i64>,
    pub name: String,
    pub iran_node_id: Option<i64>,
    pub kharej_node_id: Option<i64>,
    pub protocol: String,
    pub iran_port: u16,
    pub kharej_port: u16,
    pub control_port: u16,
    pub token: String,
    pub decoy_url: Option<String>,
    pub backup_ips: Option<String>,
    pub transport_options: Option<String>,
    pub status: String,
    pub stats_rx: u64,
    pub stats_tx: u64,
    pub stats_speed_rx: u64,
    pub stats_speed_tx: u64,
    pub port_hopping: Option<i32>,
    pub quota_limit_bytes: Option<i64>,
    pub quota_used_bytes: Option<i64>,
    pub speed_limit_kbps: Option<i32>,
    pub expires_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Node {
    pub id: Option<i64>,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub role: String,
    pub status: Option<String>,
    pub latency_ms: Option<f64>,
    pub is_backup: Option<i32>,
}

pub fn get_db_conn(db_path: &Path) -> Result<Connection> {
    Connection::open(db_path)
}

pub fn init_db(db_path: &Path) -> Result<()> {
    let conn = get_db_conn(db_path)?;

    // Create tunnels table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tunnels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            iran_node_id INTEGER,
            kharej_node_id INTEGER,
            protocol TEXT NOT NULL,
            iran_port INTEGER NOT NULL,
            kharej_port INTEGER NOT NULL,
            control_port INTEGER NOT NULL,
            token TEXT NOT NULL,
            decoy_url TEXT,
            backup_ips TEXT,
            transport_options TEXT,
            status TEXT NOT NULL,
            stats_rx INTEGER NOT NULL DEFAULT 0,
            stats_tx INTEGER NOT NULL DEFAULT 0,
            stats_speed_rx INTEGER NOT NULL DEFAULT 0,
            stats_speed_tx INTEGER NOT NULL DEFAULT 0,
            port_hopping INTEGER DEFAULT 0,
            quota_limit_bytes INTEGER DEFAULT 0,
            quota_used_bytes INTEGER DEFAULT 0,
            speed_limit_kbps INTEGER DEFAULT 0,
            expires_at INTEGER DEFAULT 0
        )",
        [],
    )?;

    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN transport_options TEXT", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN stats_speed_rx INTEGER DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN stats_speed_tx INTEGER DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN port_hopping INTEGER DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN quota_limit_bytes INTEGER DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN quota_used_bytes INTEGER DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN speed_limit_kbps INTEGER DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN expires_at INTEGER DEFAULT 0", []);

    // Create telemetry_logs table to store RTT/loss history
    conn.execute(
        "CREATE TABLE IF NOT EXISTS telemetry_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tunnel_id INTEGER NOT NULL,
            rtt_ms REAL NOT NULL,
            packet_loss REAL NOT NULL,
            timestamp INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY(tunnel_id) REFERENCES tunnels(id) ON DELETE CASCADE
        )",
        [],
    )?;

    // Create settings table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;

    // Create nodes table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL DEFAULT 'root',
            password TEXT,
            private_key TEXT,
            role TEXT NOT NULL DEFAULT 'both',
            status TEXT NOT NULL DEFAULT 'active',
            latency_ms REAL DEFAULT 0.0,
            is_backup INTEGER DEFAULT 0
        )",
        [],
    )?;

    // Migrations for existing DBs
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN iran_node_id INTEGER", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN kharej_node_id INTEGER", []);
    let _ = conn.execute("ALTER TABLE nodes ADD COLUMN private_key TEXT", []);
    let _ = conn.execute("ALTER TABLE nodes ADD COLUMN role TEXT NOT NULL DEFAULT 'both'", []);
    let _ = conn.execute("ALTER TABLE nodes ADD COLUMN status TEXT NOT NULL DEFAULT 'active'", []);
    let _ = conn.execute("ALTER TABLE nodes ADD COLUMN latency_ms REAL DEFAULT 0.0", []);
    let _ = conn.execute("ALTER TABLE nodes ADD COLUMN is_backup INTEGER DEFAULT 0", []);

    // Create default admin settings if not present
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM settings WHERE key = 'admin_username'",
        [],
        |row| row.get(0),
    )?;

    if count == 0 {
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('admin_username', 'admin')",
            [],
        )?;
        
        // Generate a random default password and store its SHA-256 hash
        let default_password = format!("cheragh_{}", rand::random::<u16>());
        let hashed = hash_password(&default_password);
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('admin_password', ?1)",
            params![hashed],
        )?;
        
        println!("\n=======================================================");
        println!("  CheraghTunnel Admin Credentials Created:");
        println!("  Username: admin");
        println!("  Password: {}", default_password);
        println!("  (Password is stored as SHA-256 hash in the database)");
        println!("=======================================================\n");
    }

    Ok(())
}

pub fn get_tunnels(db_path: &Path) -> Result<Vec<Tunnel>> {
    let conn = get_db_conn(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT id, name, protocol, iran_port, kharej_port, control_port, token, decoy_url, backup_ips, transport_options, status, stats_rx, stats_tx, stats_speed_rx, stats_speed_tx, port_hopping, quota_limit_bytes, quota_used_bytes, speed_limit_kbps, iran_node_id, kharej_node_id, expires_at FROM tunnels"
    )?;
    
    let tunnel_iter = stmt.query_map([], |row| {
        let rx: i64 = row.get(11)?;
        let tx: i64 = row.get(12)?;
        let rx_speed: i64 = row.get(13)?;
        let tx_speed: i64 = row.get(14)?;
        Ok(Tunnel {
            id: Some(row.get(0)?),
            name: row.get(1)?,
            protocol: row.get(2)?,
            iran_port: row.get(3)?,
            kharej_port: row.get(4)?,
            control_port: row.get(5)?,
            token: row.get(6)?,
            decoy_url: row.get(7)?,
            backup_ips: row.get(8)?,
            transport_options: row.get(9)?,
            status: row.get(10)?,
            stats_rx: rx as u64,
            stats_tx: tx as u64,
            stats_speed_rx: rx_speed as u64,
            stats_speed_tx: tx_speed as u64,
            port_hopping: row.get(15)?,
            quota_limit_bytes: row.get(16)?,
            quota_used_bytes: row.get(17)?,
            speed_limit_kbps: row.get(18)?,
            iran_node_id: row.get(19).unwrap_or(None),
            kharej_node_id: row.get(20).unwrap_or(None),
            expires_at: row.get(21).unwrap_or(Some(0)),
        })
    })?;

    let mut list = Vec::new();
    for t in tunnel_iter {
        list.push(t?);
    }
    Ok(list)
}

pub fn get_tunnel_by_id(db_path: &Path, id: i64) -> Result<Option<Tunnel>> {
    let conn = get_db_conn(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT id, name, protocol, iran_port, kharej_port, control_port, token, decoy_url, backup_ips, transport_options, status, stats_rx, stats_tx, stats_speed_rx, stats_speed_tx, port_hopping, quota_limit_bytes, quota_used_bytes, speed_limit_kbps, iran_node_id, kharej_node_id, expires_at FROM tunnels WHERE id = ?1"
    )?;
    
    let mut rows = stmt.query_map(params![id], |row| {
        let rx: i64 = row.get(11)?;
        let tx: i64 = row.get(12)?;
        let rx_speed: i64 = row.get(13)?;
        let tx_speed: i64 = row.get(14)?;
        Ok(Tunnel {
            id: Some(row.get(0)?),
            name: row.get(1)?,
            protocol: row.get(2)?,
            iran_port: row.get(3)?,
            kharej_port: row.get(4)?,
            control_port: row.get(5)?,
            token: row.get(6)?,
            decoy_url: row.get(7)?,
            backup_ips: row.get(8)?,
            transport_options: row.get(9)?,
            status: row.get(10)?,
            stats_rx: rx as u64,
            stats_tx: tx as u64,
            stats_speed_rx: rx_speed as u64,
            stats_speed_tx: tx_speed as u64,
            port_hopping: row.get(15)?,
            quota_limit_bytes: row.get(16)?,
            quota_used_bytes: row.get(17)?,
            speed_limit_kbps: row.get(18)?,
            iran_node_id: row.get(19).unwrap_or(None),
            kharej_node_id: row.get(20).unwrap_or(None),
            expires_at: row.get(21).unwrap_or(Some(0)),
        })
    })?;

    if let Some(row) = rows.next() {
        Ok(Some(row?))
    } else {
        Ok(None)
    }
}

pub fn create_tunnel(db_path: &Path, tunnel: &Tunnel) -> Result<i64> {
    let conn = get_db_conn(db_path)?;
    conn.execute(
        "INSERT INTO tunnels (name, protocol, iran_port, kharej_port, control_port, token, decoy_url, backup_ips, transport_options, status, stats_rx, stats_tx, stats_speed_rx, stats_speed_tx, port_hopping, quota_limit_bytes, quota_used_bytes, speed_limit_kbps, iran_node_id, kharej_node_id, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, 0, 0, 0, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            tunnel.name,
            tunnel.protocol,
            tunnel.iran_port,
            tunnel.kharej_port,
            tunnel.control_port,
            tunnel.token,
            tunnel.decoy_url,
            tunnel.backup_ips,
            tunnel.transport_options,
            "inactive",
            tunnel.port_hopping.unwrap_or(0),
            tunnel.quota_limit_bytes.unwrap_or(0),
            tunnel.quota_used_bytes.unwrap_or(0),
            tunnel.speed_limit_kbps.unwrap_or(0),
            tunnel.iran_node_id,
            tunnel.kharej_node_id,
            tunnel.expires_at.unwrap_or(0),
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_tunnel(db_path: &Path, id: i64) -> Result<()> {
    let conn = get_db_conn(db_path)?;
    conn.execute("DELETE FROM tunnels WHERE id = ?1", params![id])?;
    Ok(())
}

pub fn update_tunnel_status(db_path: &Path, id: i64, status: &str) -> Result<()> {
    let conn = get_db_conn(db_path)?;
    conn.execute(
        "UPDATE tunnels SET status = ?1 WHERE id = ?2",
        params![status, id],
    )?;
    Ok(())
}

pub fn update_tunnel_speeds(db_path: &Path, id: i64, rx_delta: u64, tx_delta: u64, speed_rx: u64, speed_tx: u64) -> Result<()> {
    let conn = get_db_conn(db_path)?;
    conn.execute(
        "UPDATE tunnels SET stats_speed_rx = ?1, stats_speed_tx = ?2, stats_rx = stats_rx + ?3, stats_tx = stats_tx + ?4, quota_used_bytes = quota_used_bytes + ?3 + ?4 WHERE id = ?5",
        params![speed_rx as i64, speed_tx as i64, rx_delta as i64, tx_delta as i64, id],
    )?;
    Ok(())
}

pub fn get_setting(db_path: &Path, key: &str) -> Result<Option<String>> {
    let conn = get_db_conn(db_path)?;
    let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
    let mut rows = stmt.query_map(params![key], |row| row.get::<_, String>(0))?;
    
    if let Some(row) = rows.next() {
        Ok(Some(row?))
    } else {
        Ok(None)
    }
}

#[allow(dead_code)]
pub fn set_setting(db_path: &Path, key: &str, value: &str) -> Result<()> {
    let conn = get_db_conn(db_path)?;
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

pub fn update_tunnel(db_path: &Path, id: i64, tunnel: &Tunnel) -> Result<()> {
    let conn = get_db_conn(db_path)?;
    conn.execute(
        "UPDATE tunnels 
         SET name = ?1, protocol = ?2, iran_port = ?3, kharej_port = ?4, control_port = ?5, 
             token = ?6, decoy_url = ?7, backup_ips = ?8, transport_options = ?9,
             port_hopping = ?10, quota_limit_bytes = ?11, quota_used_bytes = ?12, speed_limit_kbps = ?13, iran_node_id = ?14, kharej_node_id = ?15, expires_at = ?16
         WHERE id = ?17",
        params![
            tunnel.name,
            tunnel.protocol,
            tunnel.iran_port,
            tunnel.kharej_port,
            tunnel.control_port,
            tunnel.token,
            tunnel.decoy_url,
            tunnel.backup_ips,
            tunnel.transport_options,
            tunnel.port_hopping.unwrap_or(0),
            tunnel.quota_limit_bytes.unwrap_or(0),
            tunnel.quota_used_bytes.unwrap_or(0),
            tunnel.speed_limit_kbps.unwrap_or(0),
            tunnel.iran_node_id,
            tunnel.kharej_node_id,
            tunnel.expires_at.unwrap_or(0),
            id,
        ],
    )?;
    Ok(())
}

/// Hash a password using SHA-256 and return the hex-encoded digest.
pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
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

/// Verify a password against a stored hash. Supports both:
/// - New SHA-256 hashed passwords (64-char hex string)
/// - Legacy plaintext passwords (for backward compatibility during migration)
///
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub fn verify_password(input: &str, stored: &str) -> bool {
    if stored.len() == 64 && stored.chars().all(|c| c.is_ascii_hexdigit()) {
        // Stored value looks like a SHA-256 hex hash
        let hashed_input = hash_password(input);
        constant_time_eq(hashed_input.as_bytes(), stored.as_bytes())
    } else {
        // Legacy plaintext comparison (for DBs not yet migrated)
        constant_time_eq(input.as_bytes(), stored.as_bytes())
    }
}

// -------------------------------------------------------------
// Telemetry Database Functions
// -------------------------------------------------------------

pub fn log_telemetry(db_path: &Path, tunnel_id: i64, rtt_ms: f64, packet_loss: f64) -> Result<()> {
    let conn = get_db_conn(db_path)?;
    conn.execute(
        "INSERT INTO telemetry_logs (tunnel_id, rtt_ms, packet_loss) VALUES (?1, ?2, ?3)",
        params![tunnel_id, rtt_ms, packet_loss],
    )?;
    Ok(())
}

pub fn get_recent_telemetry(db_path: &Path, tunnel_id: i64, limit: usize) -> Result<Vec<(f64, f64, i64)>> {
    let conn = get_db_conn(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT rtt_ms, packet_loss, timestamp FROM telemetry_logs WHERE tunnel_id = ?1 ORDER BY id DESC LIMIT ?2"
    )?;
    let iter = stmt.query_map(params![tunnel_id, limit as i64], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })?;

    let mut list = Vec::new();
    for item in iter {
        list.push(item?);
    }
    list.reverse();
    Ok(list)
}

// -------------------------------------------------------------
// Nodes Database Functions
// -------------------------------------------------------------

pub fn get_nodes(db_path: &Path) -> Result<Vec<Node>> {
    let conn = get_db_conn(db_path)?;
    let mut stmt = conn.prepare("SELECT id, name, host, port, username, password, private_key, role, status, latency_ms, is_backup FROM nodes")?;
    
    let node_iter = stmt.query_map([], |row| {
        Ok(Node {
            id: Some(row.get(0)?),
            name: row.get(1)?,
            host: row.get(2)?,
            port: row.get(3)?,
            username: row.get(4)?,
            password: row.get(5)?,
            private_key: row.get(6)?,
            role: row.get(7)?,
            status: row.get(8).unwrap_or(Some("active".to_string())),
            latency_ms: row.get(9).unwrap_or(Some(0.0)),
            is_backup: row.get(10).unwrap_or(Some(0)),
        })
    })?;

    let mut list = Vec::new();
    for n in node_iter {
        list.push(n?);
    }
    Ok(list)
}

pub fn get_node_by_id(db_path: &Path, id: i64) -> Result<Option<Node>> {
    let conn = get_db_conn(db_path)?;
    let mut stmt = conn.prepare("SELECT id, name, host, port, username, password, private_key, role, status, latency_ms, is_backup FROM nodes WHERE id = ?1")?;
    
    let mut rows = stmt.query_map(params![id], |row| {
        Ok(Node {
            id: Some(row.get(0)?),
            name: row.get(1)?,
            host: row.get(2)?,
            port: row.get(3)?,
            username: row.get(4)?,
            password: row.get(5)?,
            private_key: row.get(6)?,
            role: row.get(7)?,
            status: row.get(8).unwrap_or(Some("active".to_string())),
            latency_ms: row.get(9).unwrap_or(Some(0.0)),
            is_backup: row.get(10).unwrap_or(Some(0)),
        })
    })?;

    if let Some(row) = rows.next() {
        Ok(Some(row?))
    } else {
        Ok(None)
    }
}

pub fn create_node(db_path: &Path, node: &Node) -> Result<i64> {
    let conn = get_db_conn(db_path)?;
    conn.execute(
        "INSERT INTO nodes (name, host, port, username, password, private_key, role, status, latency_ms, is_backup) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            node.name,
            node.host,
            node.port,
            node.username,
            node.password,
            node.private_key,
            node.role,
            node.status.as_deref().unwrap_or("active"),
            node.latency_ms.unwrap_or(0.0),
            node.is_backup.unwrap_or(0),
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn update_node_health(db_path: &Path, id: i64, status: &str, latency_ms: f64) -> Result<()> {
    let conn = get_db_conn(db_path)?;
    conn.execute(
        "UPDATE nodes SET status = ?1, latency_ms = ?2 WHERE id = ?3",
        params![status, latency_ms, id],
    )?;
    Ok(())
}

pub fn delete_node(db_path: &Path, id: i64) -> Result<()> {
    let conn = get_db_conn(db_path)?;
    conn.execute("DELETE FROM nodes WHERE id = ?1", params![id])?;
    Ok(())
}

