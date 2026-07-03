pub mod udp;

use std::error::Error;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream, TlsAcceptor, TlsConnector};
use tokio_rustls::rustls;
use tokio_tungstenite::tungstenite::{self, protocol::Message};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use futures::{Stream, Sink};

// A adapter to wrap a WebSocketStream (which works on messages) into a byte-oriented AsyncRead/AsyncWrite stream.
pub struct WsByteStream<S> {
    ws: tokio_tungstenite::WebSocketStream<S>,
    read_buf: Vec<u8>,
}

impl<S> WsByteStream<S> {
    pub fn new(ws: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            ws,
            read_buf: Vec::new(),
        }
    }
}

impl<S> AsyncRead for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = std::cmp::min(buf.remaining(), self.read_buf.len());
                let drain = self.read_buf.drain(..n).collect::<Vec<_>>();
                buf.put_slice(&drain);
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.ws).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    match msg {
                        Message::Binary(bin) => {
                            self.read_buf = bin;
                        }
                        Message::Text(txt) => {
                            self.read_buf = txt.into_bytes();
                        }
                        Message::Close(_) => {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        _ => {} // Ignore Ping/Pong
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, e)));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.ws).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Message::Binary(buf.to_vec());
                match Pin::new(&mut self.ws).start_send(msg) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.ws).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.ws).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Unified transport stream type
pub enum TransportStream {
    Tcp(TcpStream),
    TlsClient(ClientTlsStream<TcpStream>),
    TlsServer(ServerTlsStream<TcpStream>),
    Ws(WsByteStream<TcpStream>),
    Wss(WsByteStream<ClientTlsStream<TcpStream>>),
    WssServer(WsByteStream<ServerTlsStream<TcpStream>>),
    Udp(udp::UdpVirtualStream),
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TransportStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::TlsClient(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::TlsServer(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::Ws(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::Wss(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::WssServer(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::Udp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            TransportStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::TlsClient(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::TlsServer(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::Ws(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::Wss(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::WssServer(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::Udp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TransportStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            TransportStream::TlsClient(s) => Pin::new(s).poll_flush(cx),
            TransportStream::TlsServer(s) => Pin::new(s).poll_flush(cx),
            TransportStream::Ws(s) => Pin::new(s).poll_flush(cx),
            TransportStream::Wss(s) => Pin::new(s).poll_flush(cx),
            TransportStream::WssServer(s) => Pin::new(s).poll_flush(cx),
            TransportStream::Udp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TransportStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::TlsClient(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::TlsServer(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::Ws(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::Wss(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::WssServer(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::Udp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// Generate an on-the-fly self-signed TLS certificate using rcgen for server endpoints
fn generate_self_signed_config() -> Result<rustls::ServerConfig, Box<dyn Error + Send + Sync>> {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    let certs = vec![CertificateDer::from(cert_der)];
    let private_key = PrivateKeyDer::Pkcs8(key_der.into());

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;

    Ok(server_config)
}

// Generates a simple TLS client config that trusts all certificates (necessary for self-signed keys)
#[derive(Debug)]
struct NoCertificateVerification;
impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn create_client_tls_config() -> rustls::ClientConfig {
    let verifier = Arc::new(NoCertificateVerification);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

// Handshake verification constants
const PSK_HEADER_PREFIX: &str = "Cheragh-Auth ";

/// Client handshake logic to wrap standard TcpStream into selected transport stream
pub async fn client_handshake(
    mut socket: TcpStream,
    protocol: &str,
    token: &str,
) -> Result<TransportStream, Box<dyn Error + Send + Sync>> {
    match protocol {
        "beam" | "tcpmux" | "photon" | "quantummux" => {
            let auth = format!("{}{}", PSK_HEADER_PREFIX, token);
            socket.write_all(auth.as_bytes()).await?;
            socket.flush().await?;
            let mut ack = [0u8; 3];
            socket.read_exact(&mut ack).await?;
            if &ack != b"ACK" {
                return Err("Server auth failed".into());
            }
            Ok(TransportStream::Tcp(socket))
        }
        "aura" | "httpmux" => {
            let req = format!(
                "GET /tunnel HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Authorization: {}{}\r\n\r\n",
                PSK_HEADER_PREFIX, token
            );
            socket.write_all(req.as_bytes()).await?;
            socket.flush().await?;
            let mut resp = [0u8; 256];
            let n = socket.read(&mut resp).await?;
            let resp_str = String::from_utf8_lossy(&resp[..n]);
            if !resp_str.contains("101 Switching Protocols") {
                return Err("HTTP upgrade failed".into());
            }
            Ok(TransportStream::Tcp(socket))
        }
        "glimmer" | "wsmux" => {
            let ws_url = format!("ws://localhost/ws?token={}", token);
            let (ws_stream, _) = tokio_tungstenite::client_async(ws_url, socket).await?;
            Ok(TransportStream::Ws(WsByteStream::new(ws_stream)))
        }
        "nova" | "httpsmux" => {
            let config = create_client_tls_config();
            let connector = TlsConnector::from(Arc::new(config));
            let domain = ServerName::try_from("localhost")?.to_owned();
            let tls_stream = connector.connect(domain, socket).await?;
            
            // Perform PSK handshake inside TLS
            let mut stream = TransportStream::TlsClient(tls_stream);
            let auth = format!("{}{}", PSK_HEADER_PREFIX, token);
            stream.write_all(auth.as_bytes()).await?;
            stream.flush().await?;
            let mut ack = [0u8; 3];
            stream.read_exact(&mut ack).await?;
            if &ack != b"ACK" {
                return Err("Nova server auth failed".into());
            }
            Ok(stream)
        }
        "beacon" | "wssmux" => {
            let config = create_client_tls_config();
            let connector = TlsConnector::from(Arc::new(config));
            let domain = ServerName::try_from("localhost")?.to_owned();
            let tls_stream = connector.connect(domain, socket).await?;
            
            let ws_url = format!("wss://localhost/wss?token={}", token);
            let (ws_stream, _) = tokio_tungstenite::client_async(ws_url, tls_stream).await?;
            Ok(TransportStream::Wss(WsByteStream::new(ws_stream)))
        }
        "mirage" | "realitymux" => {
            // Simulated Reality TLS client hello payload containing token
            let client_hello = format!(
                "CLIENT_HELLO_REALITY_SNI:microsoft.com;AUTH:{};END",
                token
            );
            socket.write_all(client_hello.as_bytes()).await?;
            socket.flush().await?;
            
            // Server responds with a pseudo ServerHello or upgrades directly
            let mut resp = [0u8; 32];
            socket.read_exact(&mut resp).await?;
            if &resp[..12] != b"REALITY_UPGR" {
                return Err("Reality handshake validation failed".into());
            }
            Ok(TransportStream::Tcp(socket))
        }
        _ => {
            // Fallback to Beam TCP PSK
            let auth = format!("{}{}", PSK_HEADER_PREFIX, token);
            socket.write_all(auth.as_bytes()).await?;
            socket.flush().await?;
            let mut ack = [0u8; 3];
            socket.read_exact(&mut ack).await?;
            Ok(TransportStream::Tcp(socket))
        }
    }
}

/// Server handshake logic to authenticate client and wrap standard TcpStream
pub async fn server_handshake(
    mut socket: TcpStream,
    protocol: &str,
    token: &str,
    decoy: Option<String>,
) -> Result<TransportStream, Box<dyn Error + Send + Sync>> {
    let expected = format!("{}{}", PSK_HEADER_PREFIX, token);

    match protocol {
        "beam" | "tcpmux" | "photon" | "quantummux" => {
            let mut buf = vec![0u8; expected.len()];
            socket.read_exact(&mut buf).await?;
            let auth = String::from_utf8_lossy(&buf);
            if auth != expected {
                return Err("Client authentication failed".into());
            }
            socket.write_all(b"ACK").await?;
            socket.flush().await?;
            Ok(TransportStream::Tcp(socket))
        }
        "aura" | "httpmux" => {
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await?;
            let req_str = String::from_utf8_lossy(&buf[..n]);
            if !req_str.contains(&expected) {
                // Return decoy page or redirect if validation fails
                send_decoy_response(&mut socket, decoy).await?;
                return Err("HTTP upgrade auth failed, decoy served".into());
            }
            let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\r\n";
            socket.write_all(resp.as_bytes()).await?;
            socket.flush().await?;
            Ok(TransportStream::Tcp(socket))
        }
        "glimmer" | "wsmux" => {
            let mut token_found = false;
            let callback = |req: &tungstenite::handshake::server::Request, resp: tungstenite::handshake::server::Response| {
                if let Some(query) = req.uri().query() {
                    if query.contains(&format!("token={}", token)) {
                        token_found = true;
                        return Ok(resp);
                    }
                }
                Err(tungstenite::http::Response::builder()
                    .status(401)
                    .body(Some("Unauthorized".to_string()))
                    .unwrap())
            };
            let ws_stream = tokio_tungstenite::accept_hdr_async(socket, callback).await?;
            if !token_found {
                return Err("WebSocket auth token validation failed".into());
            }
            Ok(TransportStream::Ws(WsByteStream::new(ws_stream)))
        }
        "nova" | "httpsmux" => {
            let config = generate_self_signed_config()?;
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let tls_stream = acceptor.accept(socket).await?;
            
            let mut stream = TransportStream::TlsServer(tls_stream);
            let mut buf = vec![0u8; expected.len()];
            stream.read_exact(&mut buf).await?;
            let auth = String::from_utf8_lossy(&buf);
            if auth != expected {
                return Err("Nova client TLS auth failed".into());
            }
            stream.write_all(b"ACK").await?;
            stream.flush().await?;
            Ok(stream)
        }
        "beacon" | "wssmux" => {
            let config = generate_self_signed_config()?;
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let tls_stream = acceptor.accept(socket).await?;

            let mut token_found = false;
            let callback = |req: &tungstenite::handshake::server::Request, resp: tungstenite::handshake::server::Response| {
                if let Some(query) = req.uri().query() {
                    if query.contains(&format!("token={}", token)) {
                        token_found = true;
                        return Ok(resp);
                    }
                }
                Err(tungstenite::http::Response::builder()
                    .status(401)
                    .body(Some("Unauthorized".to_string()))
                    .unwrap())
            };
            let ws_stream = tokio_tungstenite::accept_hdr_async(tls_stream, callback).await?;
            if !token_found {
                return Err("WSS auth token validation failed".into());
            }
            Ok(TransportStream::WssServer(WsByteStream::new(ws_stream)))
        }
        "mirage" | "realitymux" => {
            // Simulated Reality TLS logic
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await?;
            let req_str = String::from_utf8_lossy(&buf[..n]);
            
            // Check signature
            let sign_pattern = format!("AUTH:{};", token);
            if req_str.starts_with("CLIENT_HELLO_REALITY_SNI:") && req_str.contains(&sign_pattern) {
                // Valid Reality token client connection!
                // Respond with Reality Upgrade ACK sequence
                let mut ack = [0u8; 32];
                ack[..12].copy_from_slice(b"REALITY_UPGR");
                socket.write_all(&ack).await?;
                socket.flush().await?;
                Ok(TransportStream::Tcp(socket))
            } else {
                // Invalid token / active prober! Proxy connection directly to decoy website
                let decoy_target = decoy.unwrap_or_else(|| "microsoft.com".to_string());
                let decoy_host = if decoy_target.starts_with("http://") {
                    decoy_target.trim_start_matches("http://").to_string()
                } else if decoy_target.starts_with("https://") {
                    decoy_target.trim_start_matches("https://").to_string()
                } else {
                    decoy_target
                };
                
                let decoy_addr = format!("{}:80", decoy_host);
                println!("[SERVER] Reality active probe detected! Proxying to decoy: {}", decoy_addr);
                
                if let Ok(mut decoy_conn) = TcpStream::connect(&decoy_addr).await {
                    // Send client's initial hello payload
                    let _ = decoy_conn.write_all(&buf[..n]).await;
                    // Pipe connections together (best-effort proxying)
                    let _ = tokio::io::copy_bidirectional(&mut socket, &mut decoy_conn).await;
                }
                
                Err("Reality probe detected and proxy connection completed".into())
            }
        }
        _ => {
            // Fallback Beam PSK
            let mut buf = vec![0u8; expected.len()];
            socket.read_exact(&mut buf).await?;
            let auth = String::from_utf8_lossy(&buf);
            if auth != expected {
                return Err("Client authentication failed".into());
            }
            socket.write_all(b"ACK").await?;
            socket.flush().await?;
            Ok(TransportStream::Tcp(socket))
        }
    }
}

async fn send_decoy_response(socket: &mut TcpStream, decoy: Option<String>) -> io::Result<()> {
    let decoy_resp = if let Some(ref d) = decoy {
        if d.starts_with("http://") || d.starts_with("https://") {
            format!(
                "HTTP/1.1 302 Found\r\n\
                 Location: {}\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\r\n",
                d
            )
        } else {
            format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html; charset=UTF-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n\
                 {}",
                d.len(),
                d
            )
        }
    } else {
        let default_body = "<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Under Construction</h1></body></html>";
        format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=UTF-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {}",
            default_body.len(),
            default_body
        )
    };
    socket.write_all(decoy_resp.as_bytes()).await?;
    socket.flush().await
}

#[cfg(test)]
mod tests;
