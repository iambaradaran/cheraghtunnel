use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod db;
mod api;
mod tunnel;
mod common;

#[derive(Parser)]
#[command(name = "cheraghtunnel")]
#[command(about = "CheraghTunnel: High-performance reverse tunneling manager in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Web Management Panel
    Panel {
        /// Port to bind the web panel to
        #[arg(short, long, default_value_t = 8000)]
        port: u16,

        /// Path to SQLite database file
        #[arg(short, long, default_value = "cheraghtunnel.db")]
        db_path: PathBuf,
    },
    /// Start the tunnel server listener (Iran server)
    Server {
        /// Control port to listen on for client nodes
        #[arg(short, long)]
        control_port: u16,

        /// Public port that users connect to
        #[arg(short, long)]
        public_port: u16,

        /// Authentication token
        #[arg(short, long)]
        token: String,

        /// Protocol (beam, aura, nova, glimmer, beacon, flash, ray, photon, lantern, mirage, halo, hysteria)
        #[arg(long, default_value = "beam")]
        protocol: String,

        /// Custom decoy website URL or local path for Mirage/Aura
        #[arg(long)]
        decoy: Option<String>,

        /// Enable Dynamic Port Hopping
        #[arg(long, default_value_t = false)]
        port_hopping: bool,
    },
    /// Start the tunnel client node (Kharej server)
    Client {
        /// Iran server IP or hostname
        #[arg(short, long)]
        server_ip: String,

        /// Iran server control port
        #[arg(short, long)]
        control_port: u16,

        /// Iran server public port to request forwarding
        #[arg(short, long)]
        public_port: u16,

        /// Local service address to forward to (e.g. 127.0.0.1:443)
        #[arg(short, long, default_value = "127.0.0.1:443")]
        local_service: String,

        /// Authentication token
        #[arg(short, long)]
        token: String,

        /// Protocol (beam, aura, nova, glimmer, beacon, flash, ray, photon, lantern, mirage, halo, hysteria)
        #[arg(long, default_value = "beam")]
        protocol: String,

        /// Tunnel ID for tracking traffic speeds
        #[arg(long, default_value_t = 0)]
        tunnel_id: i64,

        /// Custom decoy website URL (SNI) for TLS/WSS protocols
        #[arg(long)]
        decoy: Option<String>,

        /// Enable Dynamic Port Hopping
        #[arg(long, default_value_t = false)]
        port_hopping: bool,
    },
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Panel { port, db_path } => {
            println!("Initializing CheraghTunnel SQLite database at: {:?}", db_path);
            if let Err(e) = db::init_db(&db_path) {
                eprintln!("Failed to initialize database: {}", e);
                std::process::exit(1);
            }
            if let Err(e) = api::run_panel(port, db_path).await {
                eprintln!("Web Panel execution error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Server {
            control_port,
            public_port,
            token,
            protocol,
            decoy,
            port_hopping,
        } => {
            println!("Starting CheraghTunnel Server on control port {}, forwarding public port {} via protocol '{}'...",
                     control_port, public_port, protocol);
            let active_controls = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
            if let Err(e) = tunnel::run_server(control_port, public_port, &token, &protocol, decoy, 0, active_controls, port_hopping).await {
                eprintln!("Server tunnel error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Client {
            server_ip,
            control_port,
            public_port,
            local_service,
            token,
            protocol,
            tunnel_id,
            decoy,
            port_hopping,
        } => {
            println!("Starting CheraghTunnel Client connecting to {}:{}...", server_ip, control_port);
            if let Err(e) = tunnel::run_client(&server_ip, control_port, public_port, &local_service, &token, &protocol, tunnel_id, decoy, port_hopping).await {
                eprintln!("Client tunnel error: {}", e);
                std::process::exit(1);
            }
        }
    }
}
