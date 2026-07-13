use crate::tunnel::transport::{client_handshake, server_handshake, TransportStream, udp};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::{Duration, Instant};
use std::sync::Arc;

async fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

// Test helper to run a complete handshake, write/read data bidirectionally, and close the stream.
async fn run_handshake_test(protocol: &'static str, is_udp: bool) {
    let port = get_free_port().await;
    let token = "test_handshake_secret_token_123456";
    let message_client_to_server = b"hello from client!";
    let message_server_to_client = b"hello from server!";

    let token_owned = token.to_string();
    let protocol_owned = protocol.to_string();

    if is_udp {
        // --- UDP Transport Handshake Test ---
        let server_addr = format!("127.0.0.1:{}", port);
        let server_socket = UdpSocket::bind(&server_addr).await.unwrap();
        
        let (new_conn_tx, mut new_conn_rx) = tokio::sync::mpsc::channel(10);
        let mode = match protocol {
            "ray" => udp::UdpMode::Ray,
            "photon" => udp::UdpMode::Photon,
            "lantern" => udp::UdpMode::Lantern,
            "halo" => udp::UdpMode::Halo,
            "pulsar" => udp::UdpMode::Pulsar,
            "oracle" => udp::UdpMode::Oracle,
            "vortex" => udp::UdpMode::Vortex,
            _ => udp::UdpMode::Flash,
        };
        let _multiplexer = udp::UdpMultiplexer::new(server_socket, mode, new_conn_tx, token_owned.clone());

        // Spawn client task
        let client_token = token_owned.clone();
        let client_task = tokio::spawn(async move {
            let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client_socket.connect(&server_addr).await.unwrap();
            let socket = Arc::new(client_socket);
            let (tx, rx) = tokio::sync::mpsc::channel(100);

            let socket_clone = socket.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok((n, _)) = socket_clone.recv_from(&mut buf).await {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            });

            let peer_addr: std::net::SocketAddr = server_addr.parse().unwrap();

            // Ray: send the magic 4-byte prefix BEFORE creating the stream so
            // UdpMultiplexer opens the session before we start reading from it.
            if mode == udp::UdpMode::Ray {
                use sha2::{Sha256, Digest};
                let key = Sha256::digest(client_token.as_bytes());
                let _ = socket.send(&key[..4]).await;
                tokio::time::sleep(Duration::from_millis(80)).await;
            }

            let socket_arc = socket.clone(); // keep for Ray magic send
            let mut stream = udp::UdpVirtualStream::new(socket, peer_addr, mode, rx, false, false, &client_token);

            // For Ray: mark client handshake done immediately after magic send.
            // Server verifies the magic in process_packet; client only needs handshake_done=true
            // so that server reply packets (coming via recv_handle) flow into rx_buf.
            if mode == udp::UdpMode::Ray {
                stream.inner.lock().await.handshake_done = true;
            }

            if mode != udp::UdpMode::Ray {
                // SYN
                {
                    let mut inner = stream.inner.lock().await;
                    inner.send_syn().await;
                }
                // Wait for SYN_ACK
                let start = Instant::now();
                loop {
                    let done = stream.inner.lock().await.handshake_done;
                    if done || start.elapsed() > Duration::from_secs(3) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                // Auth PSK
                let auth = format!("Cheragh-Auth {}", client_token);
                stream.write_all(auth.as_bytes()).await.unwrap();
                stream.flush().await.unwrap();
                // Read ACK
                let mut ack = [0u8; 3];
                stream.read_exact(&mut ack).await.unwrap();
                assert_eq!(&ack, b"ACK");
            }
            let _ = socket_arc; // keep alive

            let mut client_stream = TransportStream::Udp(stream);
            // Write data to server
            client_stream.write_all(message_client_to_server).await.unwrap();
            client_stream.flush().await.unwrap();

            // Read response from server
            let mut buf = vec![0u8; message_server_to_client.len()];
            client_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, message_server_to_client);
        });

        // Server handler
        let server_token_auth = format!("Cheragh-Auth {}", token_owned);
        let mut server_stream = tokio::time::timeout(Duration::from_secs(3), new_conn_rx.recv())
            .await
            .unwrap()
            .unwrap();

        if mode != udp::UdpMode::Ray {
            // Read authentication token
            let mut auth_buf = vec![0u8; server_token_auth.len()];
            server_stream.read_exact(&mut auth_buf).await.unwrap();
            assert_eq!(String::from_utf8_lossy(&auth_buf), server_token_auth);

            // Send ACK back
            server_stream.write_all(b"ACK").await.unwrap();
            server_stream.flush().await.unwrap();
            server_stream.inner.lock().await.handshake_done = true;
        }

        let mut server_stream = TransportStream::Udp(server_stream);

        // Read client message
        let mut read_buf = vec![0u8; message_client_to_server.len()];
        server_stream.read_exact(&mut read_buf).await.unwrap();
        assert_eq!(&read_buf, message_client_to_server);

        // Write server message
        server_stream.write_all(message_server_to_client).await.unwrap();
        server_stream.flush().await.unwrap();

        client_task.await.unwrap();
    } else {
        // --- TCP Transport Handshake Test ---
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap();
        
        let client_proto = protocol_owned.clone();
        let client_token = token_owned.clone();
        let client_task = tokio::spawn(async move {
            let socket = TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap();
            let mut client_stream = client_handshake(socket, &client_proto, &client_token, None).await.unwrap();
            
            // Write data
            client_stream.write_all(message_client_to_server).await.unwrap();
            client_stream.flush().await.unwrap();

            // Read response
            let mut buf = vec![0u8; message_server_to_client.len()];
            client_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, message_server_to_client);
        });

        // Server accept
        let (socket, _) = listener.accept().await.unwrap();
        let mut server_stream = server_handshake(socket, &protocol_owned, &token_owned, None).await.unwrap();

        // Read client message
        let mut read_buf = vec![0u8; message_client_to_server.len()];
        server_stream.read_exact(&mut read_buf).await.unwrap();
        assert_eq!(&read_buf, message_client_to_server);

        // Write server message
        server_stream.write_all(message_server_to_client).await.unwrap();
        server_stream.flush().await.unwrap();

        client_task.await.unwrap();
    }
}

#[tokio::test]
async fn test_protocol_beam() {
    run_handshake_test("beam", false).await;
}

#[tokio::test]
async fn test_protocol_aura() {
    run_handshake_test("aura", false).await;
}

#[tokio::test]
async fn test_protocol_glimmer() {
    run_handshake_test("glimmer", false).await;
}

#[tokio::test]
async fn test_protocol_nova() {
    run_handshake_test("nova", false).await;
}

#[tokio::test]
async fn test_protocol_beacon() {
    run_handshake_test("beacon", false).await;
}

#[tokio::test]
async fn test_protocol_mirage() {
    run_handshake_test("mirage", false).await;
}

#[tokio::test]
async fn test_protocol_flash() {
    run_handshake_test("flash", true).await;
}

#[tokio::test]
async fn test_protocol_ray() {
    run_handshake_test("ray", true).await;
}

#[tokio::test]
async fn test_protocol_photon() {
    run_handshake_test("photon", false).await;
}

#[tokio::test]
async fn test_protocol_lantern() {
    run_handshake_test("lantern", true).await;
}

#[tokio::test]
async fn test_protocol_halo() {
    run_handshake_test("halo", true).await;
}

#[tokio::test]
async fn test_protocol_pulsar() {
    run_handshake_test("pulsar", true).await;
}

#[tokio::test]
async fn test_protocol_oracle() {
    run_handshake_test("oracle", true).await;
}

#[tokio::test]
async fn test_protocol_vortex() {
    run_handshake_test("vortex", true).await;
}

#[tokio::test]
async fn test_protocol_nirvana() {
    run_handshake_test("nirvana", false).await;
}
