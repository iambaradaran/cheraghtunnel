pub mod udp;

use std::collections::VecDeque;
use std::error::Error;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream, TlsAcceptor, TlsConnector};
use tokio_rustls::rustls;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{self, protocol::Message, protocol::Role};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use futures::{Stream, Sink};
use rand::Rng;
use kcp_tokio::KcpStream;

// A adapter to wrap a WebSocketStream (which works on messages) into a byte-oriented AsyncRead/AsyncWrite stream.
pub struct WsByteStream<S> {
    pub ws: tokio_tungstenite::WebSocketStream<S>,
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
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
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

// Stateful parser for Obfuscated Streams (adding random padding to evade DPI)
pub struct ObfuscatedStream<S> {
    inner: S,
    read_state: ReadState,
    read_buf: Vec<u8>,
    payload_buf: VecDeque<u8>,
    write_buf: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Header,
    Body { payload_len: u16, padding_len: u16 },
}

impl<S> ObfuscatedStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_state: ReadState::Header,
            read_buf: Vec::new(),
            payload_buf: VecDeque::new(),
            write_buf: Vec::new(),
        }
    }
}

impl<S> AsyncRead for ObfuscatedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 1. Yield any pending payload bytes
        if !this.payload_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), this.payload_buf.len());
            let (slice1, slice2) = this.payload_buf.as_slices();
            if slice1.len() >= n {
                buf.put_slice(&slice1[..n]);
            } else {
                buf.put_slice(slice1);
                buf.put_slice(&slice2[..(n - slice1.len())]);
            }
            this.payload_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        // 2. Read from stream to progress state machine
        let mut temp_raw = [0u8; 4096];
        let mut temp_buf = ReadBuf::new(&mut temp_raw);
        
        loop {
            match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = temp_buf.filled();
                    if bytes_read.is_empty() {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.read_buf.extend_from_slice(bytes_read);
                    temp_buf.clear();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if this.read_buf.is_empty() {
                        return Poll::Pending;
                    }
                    break;
                }
            }
        }

        // 3. Parse frames from read_buf
        loop {
            match this.read_state {
                ReadState::Header => {
                    if this.read_buf.len() < 4 {
                        break;
                    }
                    let payload_len = u16::from_be_bytes([this.read_buf[0], this.read_buf[1]]);
                    let padding_len = u16::from_be_bytes([this.read_buf[2], this.read_buf[3]]);
                    this.read_buf.drain(..4);
                    this.read_state = ReadState::Body { payload_len, padding_len };
                }
                ReadState::Body { payload_len, padding_len } => {
                    let total_needed = (payload_len as usize) + (padding_len as usize);
                    if this.read_buf.len() < total_needed {
                        break;
                    }
                    
                    let p_len = payload_len as usize;
                    let pad_len = padding_len as usize;
                    
                    // Directly extend payload_buf from the slice of read_buf without allocation
                    this.payload_buf.extend(&this.read_buf[..p_len]);
                    this.read_buf.drain(..p_len + pad_len);
                    this.read_state = ReadState::Header;
                }
            }
        }

        // 4. Yield bytes from payload_buf if populated
        if !this.payload_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), this.payload_buf.len());
            let (slice1, slice2) = this.payload_buf.as_slices();
            if slice1.len() >= n {
                buf.put_slice(&slice1[..n]);
            } else {
                buf.put_slice(slice1);
                buf.put_slice(&slice2[..(n - slice1.len())]);
            }
            this.payload_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}

impl<S> AsyncWrite for ObfuscatedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.write_buf.is_empty() {
            let payload_len = buf.len() as u16;
            let mut rng = rand::thread_rng();
            let padding_len = rng.gen_range(16..128) as u16; // Dynamic random padding size
            
            this.write_buf.reserve(4 + buf.len() + padding_len as usize);
            this.write_buf.extend_from_slice(&payload_len.to_be_bytes());
            this.write_buf.extend_from_slice(&padding_len.to_be_bytes());
            this.write_buf.extend_from_slice(buf);
            for _ in 0..padding_len {
                this.write_buf.push(rng.gen::<u8>());
            }
        }

        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
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
    Kcp(KcpStream),
    Obfuscated(ObfuscatedStream<TcpStream>),
    ObfuscatedWs(ObfuscatedStream<WsByteStream<TcpStream>>),
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
            TransportStream::Kcp(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::Obfuscated(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::ObfuscatedWs(s) => Pin::new(s).poll_read(cx, buf),
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
            TransportStream::Kcp(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::Obfuscated(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::ObfuscatedWs(s) => Pin::new(s).poll_write(cx, buf),
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
            TransportStream::Kcp(s) => Pin::new(s).poll_flush(cx),
            TransportStream::Obfuscated(s) => Pin::new(s).poll_flush(cx),
            TransportStream::ObfuscatedWs(s) => Pin::new(s).poll_flush(cx),
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
            TransportStream::Kcp(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::Obfuscated(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::ObfuscatedWs(s) => Pin::new(s).poll_shutdown(cx),
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

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(server_config)
}

use std::sync::OnceLock;
static SERVER_TLS_CONFIG: OnceLock<Arc<rustls::ServerConfig>> = OnceLock::new();

fn get_server_tls_config() -> Result<Arc<rustls::ServerConfig>, Box<dyn Error + Send + Sync>> {
    if let Some(config) = SERVER_TLS_CONFIG.get() {
        return Ok(config.clone());
    }
    let config = Arc::new(generate_self_signed_config()?);
    let _ = SERVER_TLS_CONFIG.set(config.clone());
    Ok(config)
}

fn extract_domain(decoy: &str) -> String {
    let mut host = decoy.trim();
    if host.starts_with("https://") {
        host = &host[8..];
    } else if host.starts_with("http://") {
        host = &host[7..];
    }
    // Strip any path
    if let Some(pos) = host.find('/') {
        host = &host[..pos];
    }
    // Strip any port
    if let Some(pos) = host.find(':') {
        host = &host[..pos];
    }
    host.to_string()
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
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

static CLIENT_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

fn get_client_tls_config() -> Arc<rustls::ClientConfig> {
    CLIENT_TLS_CONFIG.get_or_init(|| {
        Arc::new(create_client_tls_config())
    }).clone()
}

// Handshake verification constants
const PSK_HEADER_PREFIX: &str = "Cheragh-Auth ";

// Helper to construct a standard TLS 1.2 ClientHello binary packet spoofing SNI
fn build_tls_client_hello(decoy: &str, token: &str) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let client_random = hasher.finalize(); // 32 bytes signature

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2
    body.extend_from_slice(&client_random);
    body.push(32); // Session ID length
    body.extend_from_slice(&[0u8; 32]); // Dummy Session ID
    
    // Cipher suites (1 suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    body.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]);
    // Compression
    body.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    let mut extensions = Vec::new();
    let mut sni = Vec::new();
    let name_len = decoy.len() as u16;
    sni.extend_from_slice(&(name_len + 3).to_be_bytes()); // server name list length
    sni.push(0x00); // host_name type
    sni.extend_from_slice(&name_len.to_be_bytes());
    sni.extend_from_slice(decoy.as_bytes());
    
    extensions.extend_from_slice(&[0x00, 0x00]); // SNI type
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);

    let ext_len = extensions.len() as u16;
    body.extend_from_slice(&ext_len.to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01); // Handshake Type: ClientHello
    let body_len = body.len() as u32;
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16); // Content Type: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 Version
    let rec_len = handshake.len() as u16;
    record.extend_from_slice(&rec_len.to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

fn verify_tls_client_hello(data: &[u8], token: &str) -> bool {
    if data.len() < 43 {
        return false;
    }
    // Check TLS Handshake Record Type
    if data[0] != 0x16 || data[1] != 0x03 || data[2] != 0x01 {
        return false;
    }
    if data[5] != 0x01 {
        return false;
    }
    let client_random = &data[11..43];
    
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let expected = hasher.finalize();
    
    client_random == expected.as_slice()
}

/// Client handshake logic to wrap standard TcpStream into selected transport stream
pub async fn client_handshake(
    mut socket: TcpStream,
    protocol: &str,
    token: &str,
    decoy: Option<String>,
) -> Result<TransportStream, Box<dyn Error + Send + Sync>> {
    let decoy_str = extract_domain(&decoy.unwrap_or_else(|| "google.com".to_string()));
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
                 Host: {}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Authorization: {}{}\r\n\r\n",
                decoy_str, PSK_HEADER_PREFIX, token
            );
            socket.write_all(req.as_bytes()).await?;
            socket.flush().await?;
            let mut resp = [0u8; 256];
            let n = socket.read(&mut resp).await?;
            let resp_str = String::from_utf8_lossy(&resp[..n]);
            if !resp_str.contains("101 Switching Protocols") {
                return Err("HTTP upgrade failed".into());
            }
            
            // Wrap client socket in a real WebSocket framing stream!
            let ws_stream = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
            // Wrap in Obfuscated stream to add dynamic padding
            Ok(TransportStream::ObfuscatedWs(ObfuscatedStream::new(WsByteStream::new(ws_stream))))
        }
        "glimmer" | "wsmux" => {
            let ws_url = format!("ws://{}/ws?token={}", decoy_str, token);
            let (ws_stream, _) = tokio_tungstenite::client_async(ws_url, socket).await?;
            Ok(TransportStream::Ws(WsByteStream::new(ws_stream)))
        }
        "nova" | "httpsmux" => {
            let config = get_client_tls_config();
            let connector = TlsConnector::from(config);
            let domain = ServerName::try_from(decoy_str.as_str())?.to_owned();
            let tls_stream = connector.connect(domain, socket).await?;
            
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
            let config = get_client_tls_config();
            let connector = TlsConnector::from(config);
            let domain = ServerName::try_from(decoy_str.as_str())?.to_owned();
            let tls_stream = connector.connect(domain, socket).await?;
            
            let ws_url = format!("wss://{}/wss?token={}", decoy_str, token);
            let (ws_stream, _) = tokio_tungstenite::client_async(ws_url, tls_stream).await?;
            Ok(TransportStream::Wss(WsByteStream::new(ws_stream)))
        }
        "mirage" | "realitymux" => {
            // Write standard TLS 1.2 ClientHello spoofing microsoft.com
            let hello = build_tls_client_hello("microsoft.com", token);
            socket.write_all(&hello).await?;
            socket.flush().await?;
            
            let mut resp = [0u8; 32];
            socket.read_exact(&mut resp).await?;
            if &resp[..12] != b"REALITY_UPGR" {
                return Err("Reality server validation handshake failed".into());
            }
            
            // Apply packet padding obfuscation
            Ok(TransportStream::Obfuscated(ObfuscatedStream::new(socket)))
        }
        _ => {
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
                send_decoy_response(&mut socket, decoy).await?;
                return Err("HTTP upgrade auth failed, decoy served".into());
            }
            let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                        Upgrade: websocket\r\n\
                        Connection: Upgrade\r\n\r\n";
            socket.write_all(resp.as_bytes()).await?;
            socket.flush().await?;
            
            // Wrap in a real WebSocket framing stream!
            let ws_stream = WebSocketStream::from_raw_socket(socket, Role::Server, None).await;
            // Wrap in Obfuscated stream to add dynamic padding
            Ok(TransportStream::ObfuscatedWs(ObfuscatedStream::new(WsByteStream::new(ws_stream))))
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
            let config = get_server_tls_config()?;
            let acceptor = TlsAcceptor::from(config);
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
            let config = get_server_tls_config()?;
            let acceptor = TlsAcceptor::from(config);
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
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await?;
            
            if verify_tls_client_hello(&buf[..n], token) {
                // Successful Reality connection: reply with Reality server ACK sequence
                let mut ack = [0u8; 32];
                ack[..12].copy_from_slice(b"REALITY_UPGR");
                socket.write_all(&ack).await?;
                socket.flush().await?;
                
                // Wrap in Obfuscated stream to add dynamic padding
                Ok(TransportStream::Obfuscated(ObfuscatedStream::new(socket)))
            } else {
                // Active prober: proxy transparently to decoy site port 443
                let decoy_target = decoy.unwrap_or_else(|| "microsoft.com".to_string());
                let decoy_host = if decoy_target.starts_with("http://") {
                    decoy_target.trim_start_matches("http://").to_string()
                } else if decoy_target.starts_with("https://") {
                    decoy_target.trim_start_matches("https://").to_string()
                } else {
                    decoy_target
                };
                
                let decoy_addr = format!("{}:443", decoy_host);
                println!("[SERVER] Active probe / invalid ClientHello detected. Proxying to: {}", decoy_addr);
                
                if let Ok(mut decoy_conn) = TcpStream::connect(&decoy_addr).await {
                    let _ = decoy_conn.write_all(&buf[..n]).await;
                    let _ = tokio::io::copy_bidirectional(&mut socket, &mut decoy_conn).await;
                }
                
                Err("Reality probe proxied successfully".into())
            }
        }
        _ => {
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
