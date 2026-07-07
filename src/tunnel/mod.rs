pub mod multiplex;
pub mod faketcp;
pub mod transport;

use std::error::Error;
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use crate::tunnel::multiplex::{connect_to_local, pipe_streams_monitored};
use crate::tunnel::transport::{TransportStream, server_handshake, client_handshake};
use crate::tunnel::transport::udp::{UdpVirtualStream, UdpMultiplexer, UdpMode};
use tokio_util::compat::{TokioAsyncReadCompatExt, FuturesAsyncReadCompatExt};
use futures::StreamExt;

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


fn is_udp_protocol(protocol: &str) -> bool {
    matches!(protocol, "flash" | "ray" | "lantern" | "halo" | "hysteria")
}

fn get_udp_mode(protocol: &str) -> UdpMode {
    match protocol {
        "ray" => UdpMode::Ray,
        "lantern" => UdpMode::Lantern,
        "halo" => UdpMode::Halo,
        "hysteria" => UdpMode::Hysteria,
        _ => UdpMode::Flash,
    }
}

fn is_faketcp_protocol(protocol: &str) -> bool {
    protocol == "photon"
}

pub fn get_hopped_port(base_port: u16, token: &str, epoch: u64) -> u16 {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.update(epoch.to_be_bytes());
    let hash = hasher.finalize();
    let offset = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 20; // Rotate over a range of 20 ports
    base_port + offset as u16
}

fn spawn_protocol_listener(
    control_port: u16,
    protocol: String,
    token: String,
    decoy: Option<String>,
    control_tx: mpsc::Sender<TransportStream>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let token_owned = token;
        let protocol_owned = protocol;
        let decoy_owned = decoy;

        if is_faketcp_protocol(&protocol_owned) {
            // --- FakeTCP (KCP) Protocol Server ---
            let mut config = kcp_tokio::KcpConfig::new().turbo_mode().stream_mode(true);
            config.snd_wnd = 2048;
            config.rcv_wnd = 2048;
            config.mtu = 1300;
            config.nodelay.resend = 2;
            config.socket_buffer_size = Some(1024 * 1024 * 8);
            let server = crate::tunnel::faketcp::FakeTcpServer::new(control_port);
            let mut kcp_listener = match server.bind(config).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[SERVER] Failed to bind FakeTCP port {}: {}", control_port, e);
                    return;
                }
            };

            println!("[SERVER] Listening for FakeTCP/KCP connections on port: {}", control_port);

            loop {
                match kcp_listener.accept().await {
                    Ok((mut kcp_stream, addr)) => {
                        let token_clone = token_owned.clone();
                        let control_tx_clone = control_tx.clone();
                        tokio::spawn(async move {
                            if let Ok(Ok(_)) = tokio::time::timeout(std::time::Duration::from_secs(5), crate::tunnel::transport::perform_server_handshake_check(&mut kcp_stream, &token_clone)).await {
                                println!("[SERVER] Authentic client connected from: {} (FakeTCP/KCP) on port {}", addr, control_port);
                                let _ = control_tx_clone.send(TransportStream::Kcp(kcp_stream)).await;
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[SERVER] FakeTCP Kcp listener error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        } else if is_udp_protocol(&protocol_owned) {
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
            
            let token_clone = token_owned.clone();
            let control_tx_clone_inner = control_tx.clone();
            tokio::spawn(async move {
                while let Some(mut stream) = new_conn_rx.recv().await {
                    let token_clone_inner = token_clone.clone();
                    let control_tx_clone_inner2 = control_tx_clone_inner.clone();
                    
                    tokio::spawn(async move {
                        if let Ok(Ok(_)) = tokio::time::timeout(std::time::Duration::from_secs(5), crate::tunnel::transport::perform_server_handshake_check(&mut stream, &token_clone_inner)).await {
                            println!("[SERVER] Authentic client connected (UDP) on port {}", control_port);
                            let _ = control_tx_clone_inner2.send(TransportStream::Udp(stream)).await;
                        }
                    });
                }
            });
        } else {
            // --- TCP/TLS/WS Control Protocol Server ---
            let control_addr = format!("0.0.0.0:{}", control_port);
            let control_listener = match tokio::net::TcpListener::bind(&control_addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[SERVER] Failed to bind control port {}: {}", control_port, e);
                    return;
                }
            };
            
            println!("[SERVER] Listening for TCP control connections on port: {}", control_port);
            
            loop {
                match control_listener.accept().await {
                    Ok((control_socket, addr)) => {
                        let _ = crate::common::network::optimize_socket(&control_socket);
                        let proto_clone = protocol_owned.clone();
                        let token_clone = token_owned.clone();
                        let decoy_clone = decoy_owned.clone();
                        let control_tx_clone = control_tx.clone();

                        tokio::spawn(async move {
                            match server_handshake(control_socket, &proto_clone, &token_clone, decoy_clone).await {
                                Ok(s) => {
                                    println!("[SERVER] Authentic client connected from: {} on port {}", addr, control_port);
                                    if control_tx_clone.send(s).await.is_err() {
                                        eprintln!("[SERVER] Control channel closed, dropping node stream");
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[SERVER] Handshake failed from {}: {}", addr, e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[SERVER] Control listener error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn run_server(
    control_port: u16,
    public_port: u16,
    token: &str,
    protocol: &str,
    decoy: Option<String>,
    tunnel_id: i64,
    active_controls: Arc<tokio::sync::Mutex<Vec<yamux::Control>>>,
    port_hopping: bool,
    api_port: Option<u16>,
) -> Result<(), Box<dyn Error>> {
    println!(
        "[SERVER] Launching protocol: '{}' on control port: {}, public port: {}, Port Hopping: {}",
        protocol, control_port, public_port, port_hopping
    );

    let public_addr: std::net::SocketAddr = format!("0.0.0.0:{}", public_port).parse()?;
    let public_listener = Arc::new(crate::common::network::bind_listener(public_addr)?);
    println!("[SERVER] Listening for public user traffic on port: {}", public_port);

    // Queue to hold authenticated control streams ready for public connections
    let (control_tx, mut control_rx) = mpsc::channel::<TransportStream>(64);
    let rr_index = Arc::new(AtomicUsize::new(0));

    let token_owned = token.to_string();
    let protocol_owned = protocol.to_string();
    let decoy_owned = decoy.clone();
    
    // Telemetry API & Ping Loop
    if let Some(port) = api_port {
        let controls_ping = active_controls.clone();
        tokio::spawn(async move {
            // Background ping loop
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                let pool = controls_ping.lock().await;
                if !pool.is_empty() {
                    let mut ctrl = pool[0].clone();
                    drop(pool);
                    let start = tokio::time::Instant::now();
                    if let Ok(Ok(stream)) = tokio::time::timeout(tokio::time::Duration::from_secs(3), ctrl.open_stream()).await {
                        let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
                        drop(stream);
                        let tracker = crate::tunnel::multiplex::get_traffic_tracker(tunnel_id);
                        tracker.rtt_ms.store(rtt_ms as u32, std::sync::atomic::Ordering::Relaxed);
                    } else {
                        let tracker = crate::tunnel::multiplex::get_traffic_tracker(tunnel_id);
                        tracker.rtt_ms.store(999, std::sync::atomic::Ordering::Relaxed);
                    }
                } else {
                    drop(pool);
                    let tracker = crate::tunnel::multiplex::get_traffic_tracker(tunnel_id);
                    tracker.rtt_ms.store(999, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });

        tokio::spawn(async move {
            use axum::{routing::get, Router, Json};
            let app = Router::new().route("/api/stats", get(move || async move {
                let tracker = crate::tunnel::multiplex::get_traffic_tracker(tunnel_id);
                // Get and reset rx/tx so it acts as a delta since last poll
                let rx_delta = tracker.rx_bytes.swap(0, std::sync::atomic::Ordering::Relaxed);
                let tx_delta = tracker.tx_bytes.swap(0, std::sync::atomic::Ordering::Relaxed);
                let rtt = tracker.rtt_ms.load(std::sync::atomic::Ordering::Relaxed);
                
                let current_time = std::time::Instant::now();
                let mut last_time = tracker.last_time.lock().unwrap();
                let elapsed = current_time.duration_since(*last_time).as_secs_f64();
                *last_time = current_time;
                
                let speed_rx = if elapsed > 0.0 { (rx_delta as f64 / elapsed) as u64 } else { 0 };
                let speed_tx = if elapsed > 0.0 { (tx_delta as f64 / elapsed) as u64 } else { 0 };

                let payload = serde_json::json!({
                    "rtt_ms": if rtt == 999 { 999.0 } else { rtt as f64 },
                    "packet_loss": if rtt == 999 { 100.0 } else { 0.0 },
                    "rx_delta": rx_delta,
                    "tx_delta": tx_delta,
                    "speed_rx": speed_rx,
                    "speed_tx": speed_tx
                });
                Json(payload)
            }));
            let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
            println!("[SERVER] Telemetry API listening on port {}", port);
            axum::serve(listener, app).await.unwrap();
        });
    }

    // Spawn task to accept and authenticate control connections from client nodes.
    // Wrap in LoopGuard so the task is auto-aborted when run_server returns.
    let _accept_guard = LoopGuard {
        handle: Some(tokio::spawn(async move {
            if port_hopping {
                let mut current_epoch = 0u64;
                let mut active_listeners: std::collections::HashMap<u16, tokio::task::JoinHandle<()>> = std::collections::HashMap::new();

                loop {
                    let epoch = std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() / 300;

                    if epoch != current_epoch {
                        current_epoch = epoch;
                        let p_curr = get_hopped_port(control_port, &token_owned, epoch);
                        let p_next = get_hopped_port(control_port, &token_owned, epoch + 1);

                        // Start p_curr if not active
                        active_listeners.entry(p_curr).or_insert_with(|| {
                            spawn_protocol_listener(p_curr, protocol_owned.clone(), token_owned.clone(), decoy_owned.clone(), control_tx.clone())
                        });

                        // Start p_next if not active
                        active_listeners.entry(p_next).or_insert_with(|| {
                            spawn_protocol_listener(p_next, protocol_owned.clone(), token_owned.clone(), decoy_owned.clone(), control_tx.clone())
                        });

                        // Evict old listeners
                        let active_ports: Vec<u16> = active_listeners.keys().cloned().collect();
                        for p in active_ports {
                            if p != p_curr && p != p_next {
                                if let Some(h) = active_listeners.remove(&p) {
                                    h.abort();
                                }
                            }
                        }
                    }

                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            } else {
                let handle = spawn_protocol_listener(control_port, protocol_owned, token_owned, decoy_owned, control_tx);
                let _ = handle.await;
            }
        })),
    };

    // Background task to accept authenticated client sockets and add them to the Yamux controls pool
    let active_controls_clone = active_controls.clone();
    let _pool_guard = LoopGuard {
        handle: Some(tokio::spawn(async move {
            while let Some(control_socket) = control_rx.recv().await {
                println!("[SERVER] Establishing Yamux session for new client node in pool...");
                let mut cfg = yamux::Config::default();
                cfg.set_window_update_mode(yamux::WindowUpdateMode::OnRead);
                cfg.set_max_buffer_size(1024 * 1024 * 4);
                cfg.set_receive_window(1024 * 1024);
                
                let conn = yamux::Connection::new(control_socket.compat(), cfg, yamux::Mode::Client);
                let ctrl = conn.control();
                
                // Spawn task to process the connection's packet routing
                tokio::spawn(async move {
                    let stream = Box::pin(yamux::into_stream(conn));
                    let _ = stream.for_each(|_| futures::future::ready(())).await;
                    println!("[SERVER] Client node Yamux session closed.");
                });
                
                let mut pool = active_controls_clone.lock().await;
                pool.push(ctrl);
                println!("[SERVER] Node added to pool. Total active nodes: {}", pool.len());
            }
        })),
    };

    // Background task to run public UDP relay listener
    let active_controls_udp = active_controls.clone();
    let rr_index_udp = rr_index.clone();
    let _udp_relay_guard = LoopGuard {
        handle: Some(tokio::spawn(async move {
            let public_udp_addr = format!("0.0.0.0:{}", public_port);
            let socket = match UdpSocket::bind(&public_udp_addr).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    eprintln!("[SERVER-UDP] Failed to bind public UDP port {}: {}", public_port, e);
                    return;
                }
            };
            
            println!("[SERVER-UDP] Listening for public UDP traffic on port: {}", public_port);
            
            let mut buf = vec![0u8; 65535];
            let sessions: Arc<tokio::sync::Mutex<HashMap<std::net::SocketAddr, mpsc::Sender<Vec<u8>>>>> = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
            
            while let Ok((n, user_addr)) = socket.recv_from(&mut buf).await {
                let data = buf[..n].to_vec();
                let mut map = sessions.lock().await;
                
                if let Some(tx) = map.get(&user_addr) {
                    let _ = tx.send(data).await;
                } else {
                    let pool = active_controls_udp.lock().await;
                    if pool.is_empty() {
                        continue;
                    }
                    
                    let idx = rr_index_udp.fetch_add(1, Ordering::SeqCst);
                    let mut ctrl = pool[idx % pool.len()].clone();
                    drop(pool);
                    
                    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1000);
                    map.insert(user_addr, tx.clone());
                    let sessions_clone = sessions.clone();
                    let socket_clone = socket.clone();
                    
                    tokio::spawn(async move {
                        if let Ok(stream) = ctrl.open_stream().await {
                            use tokio::io::AsyncWriteExt;
                            let mut compat_stream = stream.compat();
                            if compat_stream.write_all(b"UDP\n").await.is_ok() {
                                let (mut reader, mut writer) = tokio::io::split(compat_stream);
                                
                                let mut rx_task = tokio::spawn(async move {
                                    while let Some(pkt) = rx.recv().await {
                                        let len_bytes = (pkt.len() as u32).to_be_bytes();
                                        if writer.write_all(&len_bytes).await.is_err() || writer.write_all(&pkt).await.is_err() {
                                            break;
                                        }
                                    }
                                });
                                
                                let socket_clone2 = socket_clone.clone();
                                let mut tx_task = tokio::spawn(async move {
                                    use tokio::io::AsyncReadExt;
                                    let mut len_buf = [0u8; 4];
                                    loop {
                                        if tokio::time::timeout(tokio::time::Duration::from_secs(30), reader.read_exact(&mut len_buf)).await.is_err() {
                                            break;
                                        }
                                        let len = u32::from_be_bytes(len_buf) as usize;
                                        let mut pkt_buf = vec![0u8; len];
                                        if reader.read_exact(&mut pkt_buf).await.is_err() {
                                            break;
                                        }
                                        let _ = socket_clone2.send_to(&pkt_buf, user_addr).await;
                                    }
                                });
                                
                                tokio::select! {
                                    _ = &mut rx_task => { tx_task.abort(); }
                                    _ = &mut tx_task => { rx_task.abort(); }
                                }
                            }
                        }
                        let mut map = sessions_clone.lock().await;
                        map.remove(&user_addr);
                    });
                    
                    let _ = tx.send(data).await;
                }
            }
        })),
    };

    // Main loop: accept public user connections and pair each with a yamux logical stream from the active pool in a Round-Robin fashion
    while let Ok((user_socket, user_addr)) = public_listener.accept().await {
        let _ = crate::common::network::optimize_socket(&user_socket);
        
        let mut stream_result = None;
        let mut attempts = 0;
        
        loop {
            let pool = active_controls.lock().await;
            if pool.is_empty() {
                drop(pool);
                // Wait briefly for at least one client node to connect
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                attempts += 1;
                if attempts > 30 { // 3 seconds timeout
                    eprintln!("[SERVER] No client nodes available in pool to service user {}", user_addr);
                    break;
                }
                continue;
            }
            
            // Pick next control in round-robin fashion
            let idx = rr_index.fetch_add(1, Ordering::SeqCst) % pool.len();
            let mut ctrl = pool[idx].clone();
            drop(pool); // Release lock while we open the stream to avoid blocking other handshakes
            
            match ctrl.open_stream().await {
                Ok(s) => {
                    stream_result = Some(s);
                    break;
                }
                Err(_) => {
                    // Node disconnected/died. Evict it from the pool!
                    println!("[SERVER] Client node at index {} failed, removing from pool.", idx);
                    let mut pool = active_controls.lock().await;
                    if idx < pool.len() {
                        pool.remove(idx);
                    }
                    drop(pool);
                }
            }
        }

        if let Some(stream) = stream_result {
            let tid = tunnel_id;
            tokio::spawn(async move {
                pipe_streams_monitored(stream.compat(), user_socket, tid).await;
            });
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_client(
    server_ips: &str,
    control_port: u16,
    _public_port: u16,
    local_service: &str,
    token: &str,
    protocol: &str,
    tunnel_id: i64,
    decoy: Option<String>,
    port_hopping: bool,
) -> Result<(), Box<dyn Error>> {
    let ips: Vec<&str> = server_ips
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if ips.is_empty() {
        return Err("No server IPs provided".into());
    }

    let parallel_connections = 3;
    let mut handles = Vec::new();

    for worker_id in 0..parallel_connections {
        let ips_clone: Vec<String> = ips.iter().map(|s| s.to_string()).collect();
        let local_service_clone = local_service.to_string();
        let token_clone = token.to_string();
        let protocol_clone = protocol.to_string();
        let decoy_clone = decoy.clone();

        let handle = tokio::spawn(async move {
            let mut ip_index = 0;
            let mut dynamic_mtu = 1350;

            loop {
                let current_ip = &ips_clone[ip_index % ips_clone.len()];
                let active_control_port = if port_hopping {
                    let epoch = std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() / 300;
                    get_hopped_port(control_port, &token_clone, epoch)
                } else {
                    control_port
                };

                println!(
                    "[CLIENT-WORKER-{}] Connecting to Iran Server {}:{} via '{}' (Failover index: {})...",
                    worker_id, current_ip, active_control_port, protocol_clone, ip_index
                );
                let control_addr = format!("{}:{}", current_ip, active_control_port);

                let control_socket = if is_faketcp_protocol(&protocol_clone) {
                    println!("[CLIENT-WORKER-{}] Connecting via FakeTCP (KCP) to {} with MTU {}...", worker_id, control_addr, dynamic_mtu);
                    let mut config = kcp_tokio::KcpConfig::new().turbo_mode().stream_mode(true);
                    config.snd_wnd = 2048;
                    config.rcv_wnd = 2048;
                    config.mtu = dynamic_mtu;
                    config.nodelay.resend = 2;
                    config.socket_buffer_size = Some(1024 * 1024 * 8);
                    let mut client = crate::tunnel::faketcp::FakeTcpClient::new(control_addr.parse().unwrap());
                    
                    match client.connect(config).await {
                        Ok(mut s) => {
                            if let Ok(Ok(_)) = tokio::time::timeout(std::time::Duration::from_secs(5), crate::tunnel::transport::perform_client_upgrade_check(&mut s, &token_clone)).await {
                                dynamic_mtu = 1350;
                                TransportStream::Kcp(s)
                            } else {
                                eprintln!("[CLIENT-WORKER-{}] FakeTCP KCP authentication/upgrade failed on server {}", worker_id, current_ip);
                                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                                continue;
                            }
                        }
                        Err(e) => {
                            eprintln!("[CLIENT-WORKER-{}] Failed to establish FakeTCP KCP connection: {}. Calibrating PMTUD...", worker_id, e);
                            dynamic_mtu = if dynamic_mtu > 1200 { dynamic_mtu - 50 } else { 1350 };
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    }
                } else if is_udp_protocol(&protocol_clone) {
                    let socket = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[CLIENT-WORKER-{}] Failed to bind local UDP socket: {}", worker_id, e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                            continue;
                        }
                    };
                    if let Err(e) = socket.connect(format!("{}:{}", current_ip, active_control_port)).await {
                        eprintln!("[CLIENT-WORKER-{}] Failed to connect UDP socket to {}:{}: {}", worker_id, current_ip, active_control_port, e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                        ip_index += 1;
                        continue;
                    }
                    let socket = Arc::new(socket);
                    let (tx, rx) = mpsc::channel(1024);
                    
                    let mode = get_udp_mode(&protocol_clone);
                    let peer_addr = match format!("{}:{}", current_ip, active_control_port).parse() {
                        Ok(addr) => addr,
                        Err(e) => {
                            eprintln!("[CLIENT-WORKER-{}] Invalid target address: {}", worker_id, e);
                            return;
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
                        {
                            let mut inner = stream.inner.lock().await;
                            inner.send_syn().await;
                        }
                        
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
                            eprintln!("[CLIENT-WORKER-{}] UDP connection handshake timeout with {}", worker_id, current_ip);
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            ip_index += 1;
                            continue;
                        }

                        if let Err(e) = crate::tunnel::transport::perform_client_upgrade_check(&mut stream, &token_clone).await {
                            eprintln!("[CLIENT-WORKER-{}] UDP authentication/upgrade failed on server {}: {}", worker_id, current_ip, e);
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            ip_index += 1;
                            continue;
                        }
                    }

                    TransportStream::Udp(stream)
                } else {
                    let tcp_socket = match TcpStream::connect(format!("{}:{}", current_ip, active_control_port)).await {
                        Ok(s) => {
                            let _ = crate::common::network::optimize_socket(&s);
                            s
                        }
                        Err(e) => {
                            eprintln!(
                                "[CLIENT-WORKER-{}] Connection to {} failed: {}. Trying next IP in 3s...",
                                worker_id, current_ip, e
                            );
                            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                            ip_index += 1;
                            continue;
                        }
                    };

                    match client_handshake(tcp_socket, &protocol_clone, &token_clone, decoy_clone.clone()).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!(
                                "[CLIENT-WORKER-{}] Handshake failed on {}: {}. Trying next IP in 3s...",
                                worker_id, current_ip, e
                            );
                            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                            ip_index += 1;
                            continue;
                        }
                    }
                };

                println!("[CLIENT-WORKER-{}] Handshake succeeded over '{}'", worker_id, protocol_clone);
                println!("[CLIENT-WORKER-{}] Establishing Yamux Multiplexer Session...", worker_id);

                let mut cfg = yamux::Config::default();
                cfg.set_window_update_mode(yamux::WindowUpdateMode::OnRead);
                cfg.set_max_buffer_size(1024 * 1024 * 4);
                cfg.set_receive_window(1024 * 1024);
                let conn = yamux::Connection::new(control_socket.compat(), cfg, yamux::Mode::Server);
                let mut incoming = Box::pin(yamux::into_stream(conn));

                while let Some(stream_res) = incoming.next().await {
                    match stream_res {
                        Ok(stream) => {
                            let l_service = local_service_clone.clone();
                            let tid = tunnel_id;
                            tokio::spawn(async move {
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                let mut compat_stream = stream.compat();
                                let mut prefix = [0u8; 4];
                                let mut is_udp = false;
                                if let Ok(Ok(_)) = tokio::time::timeout(std::time::Duration::from_millis(100), compat_stream.read_exact(&mut prefix)).await {
                                    if &prefix == b"UDP\n" {
                                        is_udp = true;
                                    }
                                }
                                
                                if is_udp {
                                    let socket = match UdpSocket::bind("0.0.0.0:0").await {
                                        Ok(s) => s,
                                        Err(_) => return,
                                    };
                                    let target_addr = match l_service.parse::<std::net::SocketAddr>() {
                                        Ok(a) => a,
                                        Err(_) => return,
                                    };
                                    let _ = socket.connect(target_addr).await;
                                    let socket = Arc::new(socket);
                                    let (mut reader, mut writer) = tokio::io::split(compat_stream);
                                    
                                    let socket_clone = socket.clone();
                                    let mut tx_task = tokio::spawn(async move {
                                        let mut len_buf = [0u8; 4];
                                        loop {
                                            if reader.read_exact(&mut len_buf).await.is_err() {
                                                break;
                                            }
                                            let len = u32::from_be_bytes(len_buf) as usize;
                                            let mut pkt_buf = vec![0u8; len];
                                            if reader.read_exact(&mut pkt_buf).await.is_err() {
                                                break;
                                            }
                                            let _ = socket_clone.send(&pkt_buf).await;
                                        }
                                    });
                                    
                                    let mut rx_task = tokio::spawn(async move {
                                        let mut buf = vec![0u8; 65535];
                                        while let Ok(n) = socket.recv(&mut buf).await {
                                            let len_bytes = (n as u32).to_be_bytes();
                                            if writer.write_all(&len_bytes).await.is_err() || writer.write_all(&buf[..n]).await.is_err() {
                                                break;
                                            }
                                        }
                                    });
                                    
                                    tokio::select! {
                                        _ = &mut tx_task => { rx_task.abort(); }
                                        _ = &mut rx_task => { tx_task.abort(); }
                                    }
                                } else {
                                    match connect_to_local(&l_service).await {
                                        Ok(mut local_conn) => {
                                            let _ = crate::common::network::optimize_socket(&local_conn);
                                            let _ = local_conn.write_all(&prefix).await;
                                            pipe_streams_monitored(compat_stream, local_conn, tid).await;
                                        }
                                        Err(e) => {
                                            eprintln!("[CLIENT] Failed to connect to local service at {}: {}", l_service, e);
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("[CLIENT-WORKER-{}] Yamux connection error: {}", worker_id, e);
                            break;
                        }
                    }
                }

                ip_index = 0;
                println!("[CLIENT-WORKER-{}] Yamux session ended. Reconnecting in 3s...", worker_id);
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            }
        });

        handles.push(handle);
    }

    futures::future::join_all(handles).await;
    Ok(())
}
