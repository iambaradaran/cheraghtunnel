pub mod multiplex;
pub mod transport;

use std::error::Error;
use std::sync::Arc;
use std::task::Poll;
use tokio::net::TcpStream;
use yamux::{Config, Connection, Mode};
use tokio_util::compat::{TokioAsyncReadCompatExt, FuturesAsyncReadCompatExt};

use crate::tunnel::multiplex::{pipe_streams_monitored, connect_to_local};

enum ConnectionCommand {
    OpenStream(tokio::sync::oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>),
}

/// Thread-safe active Yamux connection session controller.
#[derive(Clone)]
pub struct YamuxSession {
    cmd_tx: tokio::sync::mpsc::Sender<ConnectionCommand>,
}

struct YamuxRunner<T, F> {
    conn: Connection<T>,
    cmd_rx: tokio::sync::mpsc::Receiver<ConnectionCommand>,
    command_pending: Option<tokio::sync::oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>>,
    inbound_handler: F,
}

impl<T, F> Unpin for YamuxRunner<T, F> {}

impl<T, F> futures::Future for YamuxRunner<T, F>
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
    F: Fn(yamux::Stream) + Send + 'static,
{
    type Output = ();

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        // 1. Process outbound stream commands
        if let Some(tx) = this.command_pending.take() {
            match this.conn.poll_new_outbound(cx) {
                Poll::Ready(res) => {
                    let _ = tx.send(res);
                }
                Poll::Pending => {
                    this.command_pending = Some(tx);
                }
            }
        } else {
            match this.cmd_rx.poll_recv(cx) {
                Poll::Ready(Some(ConnectionCommand::OpenStream(tx))) => {
                    match this.conn.poll_new_outbound(cx) {
                        Poll::Ready(res) => {
                            let _ = tx.send(res);
                        }
                        Poll::Pending => {
                            this.command_pending = Some(tx);
                        }
                    }
                }
                Poll::Ready(None) => {
                    return Poll::Ready(());
                }
                Poll::Pending => {}
            }
        }

        // 2. Drain ALL ready inbound streams (Fix: loop instead of single poll)
        loop {
            match this.conn.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    (this.inbound_handler)(stream);
                    // Continue looping to drain more ready streams
                }
                Poll::Ready(Some(Err(e))) => {
                    eprintln!("[TUNNEL] Connection closed with error: {}", e);
                    return Poll::Ready(());
                }
                Poll::Ready(None) => {
                    return Poll::Ready(());
                }
                Poll::Pending => break,
            }
        }

        Poll::Pending
    }
}

impl YamuxSession {
    pub fn new<T, F>(conn: Connection<T>, inbound_handler: F) -> Self
    where
        T: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
        F: Fn(yamux::Stream) + Send + 'static,
    {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<ConnectionCommand>(64);
        
        let runner = YamuxRunner {
            conn,
            cmd_rx,
            command_pending: None,
            inbound_handler,
        };
        
        tokio::spawn(runner);
        
        Self { cmd_tx }
    }
    
    pub async fn open_stream(&self) -> Result<yamux::Stream, Box<dyn Error>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx.send(ConnectionCommand::OpenStream(tx)).await?;
        let res = rx.await??;
        Ok(res)
    }
}

struct LoopGuard {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for LoopGuard {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

pub async fn run_server(
    control_port: u16,
    public_port: u16,
    token: &str,
    protocol: &str,
    decoy: Option<String>,
    tunnel_id: i64,
) -> Result<(), Box<dyn Error>> {
    println!(
        "[SERVER] Launching protocol: '{}' on control port: {}, public port: {}",
        protocol, control_port, public_port
    );

    let control_addr: std::net::SocketAddr = format!("0.0.0.0:{}", control_port).parse()?;
    let public_addr: std::net::SocketAddr = format!("0.0.0.0:{}", public_port).parse()?;

    // Bind BOTH listeners upfront with SO_REUSEADDR/SO_REUSEPORT configured before binding
    let control_listener = crate::common::network::bind_listener(control_addr)?;
    let public_listener = Arc::new(crate::common::network::bind_listener(public_addr)?);
    println!("[SERVER] Listening for public user traffic on port: {}", public_port);
    
    let mut loop_guard = LoopGuard { handle: None };

    // Accept the client control connection
    while let Ok((control_socket, addr)) = control_listener.accept().await {
        if let Some(h) = loop_guard.handle.take() {
            h.abort();
        }

        let _ = crate::common::network::optimize_socket(&control_socket);
        println!("[SERVER] Client node connected from: {}", addr);
        
        // Perform server handshake first
        let control_socket = match transport::server_handshake(control_socket, protocol, token, decoy.clone()).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[SERVER] Handshake failed: {}", e);
                continue;
            }
        };

        // Wrap control socket in Yamux connection using compatibility bridge
        let mut config = Config::default();
        config.set_receive_window(256 * 1024);
        
        let conn = Connection::new(control_socket.compat(), config, Mode::Server);
        
        let control_session = YamuxSession::new(conn, |unexpected_stream| {
            // Drop client-initiated stream, server only initiates streams in reverse proxy setup
            drop(unexpected_stream);
        });

        // Accept user connections and forward them via Yamux virtual streams
        let public_listener_clone = public_listener.clone();
        let handle = tokio::spawn(async move {
            while let Ok((user_socket, _)) = public_listener_clone.accept().await {
                let _ = crate::common::network::optimize_socket(&user_socket);
                println!("[SERVER] User connected to public port, establishing tunnel stream...");
                
                let control_session_clone = control_session.clone();
                // Open a virtual stream inside the Yamux control session
                match control_session_clone.open_stream().await {
                    Ok(tunnel_stream) => {
                        // Pipe user socket to virtual stream (bridging back to tokio)
                        tokio::spawn(async move {
                            pipe_streams_monitored(user_socket, tunnel_stream.compat(), tunnel_id).await;
                        });
                    }
                    Err(e) => {
                        eprintln!("[SERVER] Failed to open virtual stream over control session: {}", e);
                        break;
                    }
                }
            }
        });
        loop_guard.handle = Some(handle);
    }

    Ok(())
}

pub async fn run_client(
    server_ips: &str,
    control_port: u16,
    _public_port: u16,
    local_service: &str,
    token: &str,
    protocol: &str,
    tunnel_id: i64,
) -> Result<(), Box<dyn Error>> {
    let ips: Vec<&str> = server_ips
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if ips.is_empty() {
        return Err("No server IPs provided".into());
    }

    let mut ip_index = 0;

    loop {
        let current_ip = ips[ip_index % ips.len()];
        println!(
            "[CLIENT] Connecting to Iran Server {}:{} via '{}' (Failover index: {})...",
            current_ip, control_port, protocol, ip_index
        );

        // Connect to control port
        let control_socket = match TcpStream::connect(format!("{}:{}", current_ip, control_port)).await {
            Ok(s) => {
                let _ = crate::common::network::optimize_socket(&s);
                s
            }
            Err(e) => {
                eprintln!("[CLIENT] Connection to {} failed: {}. Trying next IP in 3s...", current_ip, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                ip_index += 1;
                continue;
            }
        };
        
        println!("[CLIENT] Connected to Iran control port successfully");

        // Perform client-side handshake
        let control_socket = match transport::client_handshake(control_socket, protocol, token).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[CLIENT] Handshake failed on {}: {}. Trying next IP in 3s...", current_ip, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                ip_index += 1;
                continue;
            }
        };
        
        println!("[CLIENT] Handshake succeeded");

        // Establish Yamux connection using compat
        let mut config = Config::default();
        config.set_receive_window(256 * 1024);
        
        let conn = Connection::new(control_socket.compat(), config, Mode::Client);
        let local_target = local_service.to_string();

        println!("[CLIENT] Entering event loop to accept incoming tunnel streams...");

        let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel::<yamux::Stream>(32);
        
        // Spawn session, routing incoming streams to inbound_tx channel
        let inbound_tx_clone = inbound_tx.clone();
        let _session = YamuxSession::new(conn, move |tunnel_stream| {
            let tx = inbound_tx_clone.clone();
            tokio::spawn(async move {
                let _ = tx.send(tunnel_stream).await;
            });
        });

        // Accept virtual streams opened by the server and pipe them
        while let Some(tunnel_stream) = inbound_rx.recv().await {
            println!("[CLIENT] Received incoming stream, connecting to local service: {}...", local_target);
            
            let local_target_task = local_target.clone();
            tokio::spawn(async move {
                let local_conn = match connect_to_local(&local_target_task).await {
                    Ok(s) => {
                        let _ = crate::common::network::optimize_socket(&s);
                        s
                    }
                    Err(e) => {
                        eprintln!("[CLIENT] Failed to connect to local service ({}): {}", local_target_task, e);
                        return;
                    }
                };

                // Pipe tunnel stream to local service
                pipe_streams_monitored(tunnel_stream.compat(), local_conn, tunnel_id).await;
            });
        }

        // If loop completes (e.g. connection lost), increment index and retry connection
        println!("[CLIENT] Connection lost. Commencing failover sequence...");
        ip_index += 1;
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }
}
