use rusqlite::{params, Connection, Result};
use std::path::Path;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Tunnel {
    pub id: Option<i64>,
    pub name: String,
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
            protocol TEXT NOT NULL,
            iran_port INTEGER NOT NULL,
            kharej_port INTEGER NOT NULL,
            control_port INTEGER NOT NULL,
            token TEXT NOT NULL,
            decoy_url TEXT,
            backup_ips TEXT,
            status TEXT NOT NULL,
            stats_rx INTEGER DEFAULT 0,
            stats_tx INTEGER DEFAULT 0,
            stats_speed_rx INTEGER DEFAULT 0,
            stats_speed_tx INTEGER DEFAULT 0
        )",
        [],
    )?;

    // Run schema migrations for existing DBs
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN backup_ips TEXT", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN transport_options TEXT", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN stats_speed_rx INTEGER DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE tunnels ADD COLUMN stats_speed_tx INTEGER DEFAULT 0", []);

    // Create settings table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;

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
        "SELECT id, name, protocol, iran_port, kharej_port, control_port, token, decoy_url, backup_ips, transport_options, status, stats_rx, stats_tx, stats_speed_rx, stats_speed_tx FROM tunnels"
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
        "SELECT id, name, protocol, iran_port, kharej_port, control_port, token, decoy_url, backup_ips, transport_options, status, stats_rx, stats_tx, stats_speed_rx, stats_speed_tx FROM tunnels WHERE id = ?1"
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
        "INSERT INTO tunnels (name, protocol, iran_port, kharej_port, control_port, token, decoy_url, backup_ips, transport_options, status, stats_rx, stats_tx, stats_speed_rx, stats_speed_tx)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, 0, 0, 0)",
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
            "inactive"
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

pub fn update_tunnel_speeds(db_path: &Path, id: i64, rx_bytes: u64, tx_bytes: u64) -> Result<()> {
    let conn = get_db_conn(db_path)?;
    // stats_speed_rx/tx = current speed snapshot (bytes transferred in last interval)
    // stats_rx/tx = cumulative total bytes transferred
    conn.execute(
        "UPDATE tunnels SET stats_speed_rx = ?1, stats_speed_tx = ?2, stats_rx = stats_rx + ?1, stats_tx = stats_tx + ?2 WHERE id = ?3",
        params![rx_bytes as i64, tx_bytes as i64, id],
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
        "UPDATE tunnels SET name=?1, protocol=?2, iran_port=?3, kharej_port=?4, control_port=?5, token=?6, decoy_url=?7, backup_ips=?8, transport_options=?9
         WHERE id=?10",
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
            id
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

