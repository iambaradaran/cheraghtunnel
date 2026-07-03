pub mod multiplex;
pub mod transport;

use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use crate::tunnel::multiplex::{connect_to_local, pipe_streams_monitored};
use crate::tunnel::transport::{TransportStream, server_handshake, client_handshake};
use crate::tunnel::transport::udp::{UdpVirtualStream, UdpMultiplexer, UdpMode};

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

async fn relay_control_channel(mut control: TransportStream, peer: TcpStream, tunnel_id: i64) {
    let _ = control.write_u8(1).await;
    let _ = control.flush().await;
    let _ = pipe_streams_monitored(peer, control, tunnel_id).await;
}

fn is_udp_protocol(protocol: &str) -> bool {
    matches!(protocol, "flash" | "ray" | "photon" | "lantern" | "halo" | "hysteria")
}

fn get_udp_mode(protocol: &str) -> UdpMode {
    match protocol {
        "ray" => UdpMode::Ray,
        "photon" => UdpMode::Photon,
        "lantern" => UdpMode::Lantern,
        "halo" => UdpMode::Halo,
        "hysteria" => UdpMode::Hysteria,
        _ => UdpMode::Flash,
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

    let public_addr: std::net::SocketAddr = format!("0.0.0.0:{}", public_port).parse()?;
    let public_listener = Arc::new(crate::common::network::bind_listener(public_addr)?);
    println!("[SERVER] Listening for public user traffic on port: {}", public_port);

    // Queue to hold authenticated control streams ready for public connections
    let (control_tx, mut control_rx) = mpsc::channel::<TransportStream>(64);

    let token_owned = token.to_string();
    let protocol_owned = protocol.to_string();
    let decoy_owned = decoy.clone();

    // Spawn task to accept and authenticate control connections from client nodes.
    // Wrap in LoopGuard so the task is auto-aborted when run_server returns.
    let _accept_guard = LoopGuard {
        handle: Some(tokio::spawn(async move {
            if is_udp_protocol(&protocol_owned) {
                // --- UDP Control Protocol Server ---
                let mode = get_udp_mode(&protocol_owned);
                let control_addr = format!("0.0.0.0:{}", control_port);
                let socket = match UdpSocket::bind(&control_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[SERVER] Failed to bind UDP control port {}: {}", control_port, e);
                        return;
                    }
                };
                
                println!("[SERVER] Listening for UDP control packets on port: {}", control_port);
                
                let (new_conn_tx, mut new_conn_rx) = mpsc::channel::<UdpVirtualStream>(100);
                let _multiplexer = UdpMultiplexer::new(socket, mode, new_conn_tx);
                
                let token_auth = format!("Cheragh-Auth {}", token_owned);
                
                while let Some(mut stream) = new_conn_rx.recv().await {
                    let control_tx_clone = control_tx.clone();
                    let token_auth_clone = token_auth.clone();
                    let mode_clone = mode;
                    
                    tokio::spawn(async move {
                        if mode_clone == UdpMode::Ray {
                            // Ray raw UDP needs no token handshake
                            let _ = control_tx_clone.send(TransportStream::Udp(stream)).await;
                            return;
                        }

                        // Wait for Client authentication header over reliable UDP
                        let mut buf = vec![0u8; token_auth_clone.len()];
                        if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await {
                            let auth_str = String::from_utf8_lossy(&buf);
                            if auth_str == token_auth_clone {
                                // Send ACK back to the client
                                if stream.write_all(b"ACK").await.is_ok() && stream.flush().await.is_ok() {
                                    let mut inner = stream.inner.lock().await;
                                    inner.handshake_done = true;
                                    drop(inner);
                                    let _ = control_tx_clone.send(TransportStream::Udp(stream)).await;
                                }
                            }
                        }
                    });
                }
            } else {
                // --- TCP Control Protocol Server ---
                let control_addr = format!("0.0.0.0:{}", control_port);
                let control_listener = match crate::common::network::bind_listener(control_addr.parse().unwrap()) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("[SERVER] Failed to bind TCP control port {}: {}", control_port, e);
                        return;
                    }
                };

                println!("[SERVER] Listening for TCP control connections on port: {}", control_port);

                loop {
                    match control_listener.accept().await {
                        Ok((control_socket, addr)) => {
                            let token_clone = token_owned.clone();
                            let proto_clone = protocol_owned.clone();
                            let decoy_clone = decoy_owned.clone();
                            let control_tx_clone = control_tx.clone();

                            tokio::spawn(async move {
                                if let Ok(s) = server_handshake(control_socket, &proto_clone, &token_clone, decoy_clone).await {
                                    println!("[SERVER] Authentic client connected from: {}", addr);
                                    if control_tx_clone.send(s).await.is_err() {
                                        eprintln!("[SERVER] Control channel closed, dropping node stream");
                                    }
                                }
                                // Ignore handshake errors (scanners/bots)
                            });
                        }
                        Err(e) => {
                            eprintln!("[SERVER] Control listener error: {}", e);
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        })),
    };

    // Main loop: accept public user connections and pair each with a queued control socket
    while let Ok((user_socket, user_addr)) = public_listener.accept().await {
        let _ = crate::common::network::optimize_socket(&user_socket);
        println!("[SERVER] User connected from {} to public port, waiting for control socket...", user_addr);

        // Wait for an authenticated control stream from the channel with a timeout
        let control_socket = match tokio::time::timeout(
            tokio::time::Duration::from_secs(10),
            control_rx.recv(),
        )
        .await
        {
            Ok(Some(cs)) => cs,
            Ok(None) => {
                eprintln!("[SERVER] Control channel closed, no more client nodes available");
                break;
            }
            Err(_) => {
                eprintln!("[SERVER] Timeout waiting for control socket, dropping user connection from {}", user_addr);
                continue;
            }
        };

        // Spawn relay in a separate task so we can immediately accept the next user
        let tid = tunnel_id;
        tokio::spawn(async move {
            relay_control_channel(control_socket, user_socket, tid).await;
        });
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

        let mut control_socket = if is_udp_protocol(protocol) {
            // --- UDP Client Transport ---
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[CLIENT] Failed to bind local UDP socket: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                    continue;
                }
            };
            if let Err(e) = socket.connect(format!("{}:{}", current_ip, control_port)).await {
                eprintln!("[CLIENT] Failed to connect UDP socket to {}:{}: {}", current_ip, control_port, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                ip_index += 1;
                continue;
            }
            let socket = Arc::new(socket);
            let (tx, rx) = mpsc::channel(1024);
            
            let mode = get_udp_mode(protocol);
            let peer_addr = match format!("{}:{}", current_ip, control_port).parse() {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("[CLIENT] Invalid target address: {}", e);
                    return Err(Box::new(e));
                }
            };
            let mut stream = UdpVirtualStream::new(socket.clone(), peer_addr, mode, rx, false);

            let socket_clone = socket.clone();
            let recv_handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok((n, _)) = socket_clone.recv_from(&mut buf).await {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            });
            stream.recv_handle = Some(recv_handle);
            
            if mode != UdpMode::Ray {
                // Send SYN handshake packet
                {
                    let mut inner = stream.inner.lock().await;
                    inner.send_syn().await;
                }
                
                // Wait for SYN_ACK from server
                let start = Instant::now();
                let mut success = false;
                while start.elapsed() < Duration::from_secs(5) {
                    let done = {
                        let inner = stream.inner.lock().await;
                        inner.handshake_done
                    };
                    if done {
                        success = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }

                if !success {
                    eprintln!("[CLIENT] UDP connection handshake timeout with {}", current_ip);
                    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                    ip_index += 1;
                    continue;
                }

                // Send authentication PSK header
                let auth = format!("Cheragh-Auth {}", token);
                if stream.write_all(auth.as_bytes()).await.is_err() || stream.flush().await.is_err() {
                    eprintln!("[CLIENT] Failed to write auth token to UDP stream");
                    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                    ip_index += 1;
                    continue;
                }

                // Read ACK response
                let mut ack = [0u8; 3];
                match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut ack)).await {
                    Ok(Ok(_)) if &ack == b"ACK" => {
                        // Handshake fully verified
                    }
                    _ => {
                        eprintln!("[CLIENT] UDP authentication failed on server {}", current_ip);
                        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                        ip_index += 1;
                        continue;
                    }
                }
            }

            TransportStream::Udp(stream)
        } else {
            // --- TCP Client Transport ---
            let tcp_socket = match TcpStream::connect(format!("{}:{}", current_ip, control_port)).await {
                Ok(s) => {
                    let _ = crate::common::network::optimize_socket(&s);
                    s
                }
                Err(e) => {
                    eprintln!(
                        "[CLIENT] Connection to {} failed: {}. Trying next IP in 3s...",
                        current_ip, e
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                    ip_index += 1;
                    continue;
                }
            };

            match client_handshake(tcp_socket, protocol, token).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "[CLIENT] Handshake failed on {}: {}. Trying next IP in 3s...",
                        current_ip, e
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                    ip_index += 1;
                    continue;
                }
            }
        };

        println!("[CLIENT] Handshake succeeded over '{}'", protocol);
        println!("[CLIENT] Waiting for tunnel relay signal...");

        let signal = match control_socket.read_u8().await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[CLIENT] Failed to read relay signal: {}", e);
                ip_index += 1;
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        if signal != 1 {
            eprintln!("[CLIENT] Unexpected relay signal byte: {}", signal);
            ip_index += 1;
            continue;
        }

        println!(
            "[CLIENT] Relay signal received, connecting to local service: {}...",
            local_service
        );

        let local_conn = match connect_to_local(local_service).await {
            Ok(s) => {
                let _ = crate::common::network::optimize_socket(&s);
                s
            }
            Err(e) => {
                eprintln!(
                    "[CLIENT] Failed to connect to local service ({}): {}",
                    local_service, e
                );
                ip_index += 1;
                continue;
            }
        };

        // Spawn relay in a separate task so we can immediately reconnect
        // to the server for the next user connection, enabling true concurrency.
        let tid = tunnel_id;
        tokio::spawn(async move {
            pipe_streams_monitored(control_socket, local_conn, tid).await;
            println!("[CLIENT] Relay task finished for tunnel_id={}", tid);
        });

        // Reset ip_index on success (we got a valid connection from this IP)
        ip_index = 0;

        // Immediately loop back to connect a new control socket for the next user
        println!("[CLIENT] Relay spawned, reconnecting for next user...");
    }
}
