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
    read_pos: usize,
    ping_timer: Pin<Box<tokio::time::Sleep>>,
}

impl<S> WsByteStream<S> {
    pub fn new(ws: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            ws,
            read_buf: Vec::new(),
            read_pos: 0,
            ping_timer: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(30))),
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
            // 1. Check active ping timer for keepalive when connection is idle
            let this = self.as_mut().get_mut();
            if std::future::Future::poll(this.ping_timer.as_mut(), cx).is_ready() {
                let _ = Pin::new(&mut this.ws).start_send(Message::Ping(Vec::new()));
                let _ = Pin::new(&mut this.ws).poll_flush(cx);
                this.ping_timer.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_secs(30));
            }

            let available = self.read_buf.len() - self.read_pos;
            if available > 0 {
                let n = std::cmp::min(buf.remaining(), available);
                buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
                self.read_pos += n;
                if self.read_pos >= self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                // Reset ping timer on active data read
                let this = self.as_mut().get_mut();
                this.ping_timer.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_secs(30));
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.ws).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    // Reset ping timer on active incoming message
                    let this = self.as_mut().get_mut();
                    this.ping_timer.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_secs(30));

                    match msg {
                        Message::Binary(bin) => {
                            self.read_buf = bin;
                            self.read_pos = 0;
                        }
                        Message::Text(txt) => {
                            self.read_buf = txt.into_bytes();
                            self.read_pos = 0;
                        }
                        Message::Ping(data) => {
                            let _ = Pin::new(&mut self.ws).start_send(Message::Pong(data));
                            let _ = Pin::new(&mut self.ws).poll_flush(cx);
                        }
                        Message::Close(_) => {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        _ => {}
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
                // Reset ping timer on active outgoing write
                let this = self.as_mut().get_mut();
                this.ping_timer.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_secs(30));

                // Optimization: Use Bytes::copy_from_slice to avoid a separate heap alloc
                // in hot path, we must accept the one-copy the WS protocol requires.
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

// Stateful parser for Obfuscated Streams (adding random padding to evade DPI).
// Performance-optimized: uses read_pos and write_pos cursors to avoid O(N) drain shifts.
// write_buf capacity is preserved across calls via clear() instead of drain().
// Random padding is generated in bulk with rng.fill() instead of byte-by-byte gen().
pub struct ObfuscatedStream<S> {
    inner: S,
    read_state: ReadState,
    // Raw incoming bytes; read_pos tracks the consumed head without shifting memory.
    read_buf: Vec<u8>,
    read_pos: usize,
    // Decoded payload bytes ready to hand back to the caller.
    payload_buf: VecDeque<u8>,
    // Serialized outgoing frame; write_pos tracks bytes already sent.
    // clear() is used instead of drain() to retain allocated capacity for reuse.
    write_buf: Vec<u8>,
    write_pos: usize,
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
            read_buf: Vec::with_capacity(8192),
            read_pos: 0,
            payload_buf: VecDeque::new(),
            write_buf: Vec::with_capacity(4096),
            write_pos: 0,
        }
    }

    /// Return the slice of read_buf that has not been consumed yet.
    #[inline]
    fn read_unconsumed(&self) -> &[u8] {
        &self.read_buf[self.read_pos..]
    }

    /// Advance the read cursor; compact when we've consumed ≥ 4 KB to prevent
    /// unbounded growth of the raw buffer without paying O(N) cost on every frame.
    #[inline]
    fn read_advance(&mut self, n: usize) {
        self.read_pos += n;
        if self.read_pos >= 4096 {
            self.read_buf.drain(..self.read_pos);
            self.read_pos = 0;
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

        // 1. Yield any pending decoded payload bytes first (fast path).
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

        // 2. Pull raw bytes from the inner stream directly into the tail of
        //    read_buf (no intermediate stack copy).
        loop {
            let before = this.read_buf.len();
            // Reserve room so ReadBuf can fill into the spare capacity.
            this.read_buf.resize(before + 4096, 0);
            let mut temp = ReadBuf::new(&mut this.read_buf[before..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut temp) {
                Poll::Ready(Ok(())) => {
                    let filled = temp.filled().len();
                    // Truncate back to only the bytes actually read.
                    this.read_buf.truncate(before + filled);
                    if filled == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    // Continue pulling; stop only when Pending or we have data to parse.
                }
                Poll::Ready(Err(e)) => {
                    this.read_buf.truncate(before);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    this.read_buf.truncate(before);
                    if this.read_unconsumed().is_empty() {
                        return Poll::Pending;
                    }
                    break;
                }
            }
        }

        // 3. Parse as many complete frames as possible from read_buf using cursor.
        loop {
            let unconsumed = this.read_unconsumed();
            match this.read_state {
                ReadState::Header => {
                    if unconsumed.len() < 4 {
                        break;
                    }
                    let payload_len = u16::from_be_bytes([unconsumed[0], unconsumed[1]]);
                    let padding_len = u16::from_be_bytes([unconsumed[2], unconsumed[3]]);
                    this.read_advance(4);
                    this.read_state = ReadState::Body { payload_len, padding_len };
                }
                ReadState::Body { payload_len, padding_len } => {
                    let total_needed = (payload_len as usize) + (padding_len as usize);
                    let p_len = payload_len as usize;
                    // Use absolute indices to avoid holding a borrow while mutating payload_buf.
                    let start = this.read_pos;
                    let end_payload = start + p_len;
                    let end_total = start + total_needed;
                    if this.read_buf.len() < end_total {
                        break;
                    }
                    
                    // Optimization: If payload_buf is empty and caller's buf has enough remaining space,
                    // copy the payload bytes directly into the output buffer to completely bypass payload_buf!
                    if this.payload_buf.is_empty() && buf.remaining() >= p_len {
                        buf.put_slice(&this.read_buf[start..end_payload]);
                        this.read_pos = end_total;
                        if this.read_pos >= 4096 {
                            this.read_buf.drain(..this.read_pos);
                            this.read_pos = 0;
                        }
                        this.read_state = ReadState::Header;
                        return Poll::Ready(Ok(()));
                    }

                    // Otherwise, extend payload_buf as fallback.
                    this.payload_buf.extend(&this.read_buf[start..end_payload]);
                    this.read_pos = end_total;
                    if this.read_pos >= 4096 {
                        this.read_buf.drain(..this.read_pos);
                        this.read_pos = 0;
                    }
                    this.read_state = ReadState::Header;
                }
            }
        }

        // 4. Yield decoded bytes to the caller.
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

        // Only build a new frame when the previous one has been fully sent.
        if this.write_pos >= this.write_buf.len() {
            let payload_len = buf.len() as u16;
            let mut rng = rand::thread_rng();
            let padding_len: usize = rng.gen_range(16..128);

            // Reuse write_buf's existing allocation: clear preserves capacity.
            this.write_buf.clear();
            this.write_pos = 0;

            let total = 4 + buf.len() + padding_len;
            if this.write_buf.capacity() < total {
                this.write_buf.reserve(total - this.write_buf.capacity());
            }

            this.write_buf.extend_from_slice(&payload_len.to_be_bytes());
            this.write_buf.extend_from_slice(&(padding_len as u16).to_be_bytes());
            this.write_buf.extend_from_slice(buf);

            // Bulk-generate all padding bytes in one RNG call — orders of magnitude
            // faster than byte-by-byte gen::<u8>() in a loop.
            let pad_start = this.write_buf.len();
            this.write_buf.resize(pad_start + padding_len, 0);
            rng.fill(&mut this.write_buf[pad_start..]);
        }

        // Flush as many bytes of the current frame as the inner writer accepts.
        while this.write_pos < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
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
    #[allow(dead_code)]
    Ws(WsByteStream<TcpStream>),
    #[allow(dead_code)]
    Wss(WsByteStream<ClientTlsStream<TcpStream>>),
    #[allow(dead_code)]
    WssServer(WsByteStream<ServerTlsStream<TcpStream>>),
    Udp(udp::UdpVirtualStream),
    Kcp(KcpStream),
    Obfuscated(ObfuscatedStream<TcpStream>),
    ObfuscatedWs(ObfuscatedStream<WsByteStream<TcpStream>>),
    ObfuscatedWss(ObfuscatedStream<WsByteStream<ClientTlsStream<TcpStream>>>),
    ObfuscatedWssServer(ObfuscatedStream<WsByteStream<ServerTlsStream<TcpStream>>>),
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
            TransportStream::ObfuscatedWss(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::ObfuscatedWssServer(s) => Pin::new(s).poll_read(cx, buf),
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
            TransportStream::ObfuscatedWss(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::ObfuscatedWssServer(s) => Pin::new(s).poll_write(cx, buf),
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
            TransportStream::ObfuscatedWss(s) => Pin::new(s).poll_flush(cx),
            TransportStream::ObfuscatedWssServer(s) => Pin::new(s).poll_flush(cx),
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
            TransportStream::ObfuscatedWss(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::ObfuscatedWssServer(s) => Pin::new(s).poll_shutdown(cx),
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
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(server_config)
}

fn load_custom_tls_config(cert_path: &Path, key_path: &Path) -> Result<rustls::ServerConfig, Box<dyn Error + Send + Sync>> {
    use std::fs::File;
    use std::io::BufReader;
    
    let mut cert_file = BufReader::new(File::open(cert_path)?);
    let mut key_file = BufReader::new(File::open(key_path)?);
    
    let cert_bytes = rustls_pemfile::certs(&mut cert_file)?;
    let certs = cert_bytes.into_iter().map(CertificateDer::from).collect::<Vec<_>>();
    
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_file)?;
    if keys.is_empty() {
        let mut key_file2 = BufReader::new(File::open(key_path)?);
        keys = rustls_pemfile::rsa_private_keys(&mut key_file2)?;
    }
    
    if keys.is_empty() {
        return Err("No valid private key found in key.pem".into());
    }
    
    let private_key = PrivateKeyDer::Pkcs8(keys.remove(0).into());
    
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    
    Ok(server_config)
}

fn get_ws_config() -> tungstenite::protocol::WebSocketConfig {
    tungstenite::protocol::WebSocketConfig {
        max_frame_size: Some(256 * 1024),      // 256KB
        max_message_size: Some(1024 * 1024),    // 1MB
        max_write_buffer_size: 512 * 1024,      // 512KB
        ..Default::default()
    }
}

use std::sync::OnceLock;
use std::path::Path;
static SERVER_TLS_CONFIG: OnceLock<Arc<rustls::ServerConfig>> = OnceLock::new();

fn get_server_tls_config() -> Result<Arc<rustls::ServerConfig>, Box<dyn Error + Send + Sync>> {
    if let Some(config) = SERVER_TLS_CONFIG.get() {
        return Ok(config.clone());
    }
    
    let cert_path = Path::new("cert.pem");
    let key_path = Path::new("key.pem");
    
    let config = if cert_path.exists() && key_path.exists() {
        println!("[TLS] Loading custom SSL certificate from cert.pem/key.pem...");
        Arc::new(load_custom_tls_config(cert_path, key_path)?)
    } else {
        Arc::new(generate_self_signed_config()?)
    };
    
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
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

static CLIENT_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

fn get_client_tls_config() -> Arc<rustls::ClientConfig> {
    CLIENT_TLS_CONFIG.get_or_init(|| {
        Arc::new(create_client_tls_config())
    }).clone()
}

// Handshake verification constants

fn is_older(client: &str, server: &str) -> bool {
    let c_parts: Vec<u32> = client.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    let s_parts: Vec<u32> = server.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    for i in 0..std::cmp::max(c_parts.len(), s_parts.len()) {
        let c_val = *c_parts.get(i).unwrap_or(&0);
        let s_val = *s_parts.get(i).unwrap_or(&0);
        if c_val < s_val {
            return true;
        } else if c_val > s_val {
            return false;
        }
    }
    false
}

pub async fn perform_client_upgrade_check<S>(
    stream: &mut S,
    token: &str,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use sha2::{Sha256, Digest};
    use std::time::{SystemTime, UNIX_EPOCH};
    use rand::Rng;

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let hash = format!("{:x}", Sha256::digest(format!("{}{}", token, timestamp).as_bytes()));
    
    // Generate 10 to 150 bytes of random alphanumeric padding to evade size-based DPI fingerprinting
    let padding: String = {
        let mut rng = rand::thread_rng();
        let pad_len = rng.gen_range(10..150);
        (0..pad_len)
            .map(|_| {
                let idx = rng.gen_range(0..62);
                let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                chars[idx] as char
            })
            .collect()
    };

    let auth = format!("Cheragh-Auth-HMAC {} {} v{} {}\n", hash, timestamp, env!("CARGO_PKG_VERSION"), padding);
    stream.write_all(auth.as_bytes()).await?;
    stream.flush().await?;
    
    let mut resp = [0u8; 3];
    stream.read_exact(&mut resp).await?;
    if &resp == b"UPG" {
        let mut remaining = [0u8; 5];
        stream.read_exact(&mut remaining).await?;
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut exe_bytes = vec![0u8; len];
        stream.read_exact(&mut exe_bytes).await?;
        
        if let Ok(exe_path) = std::env::current_exe() {
            let tmp_path = exe_path.with_extension("tmp");
            std::fs::write(&tmp_path, &exe_bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755));
            }
            std::fs::rename(&tmp_path, &exe_path)?;
            println!("[CLIENT] Upgrade downloaded successfully. Restarting process...");
            let args: Vec<String> = std::env::args().collect();
            let _ = std::process::Command::new(&exe_path)
                .args(&args[1..])
                .spawn();
            std::process::exit(0);
        }
    } else if &resp == b"ACK" {
        return Ok(());
    }
    Err("Handshake failed".into())
}

pub async fn perform_server_handshake_check<S>(
    stream: &mut S,
    token: &str,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use sha2::{Sha256, Digest};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > 400 { // Max limit increased to support the random padding
            return Err("Handshake too long".into());
        }
    }
    let auth = String::from_utf8_lossy(&buf);
    if !auth.starts_with("Cheragh-Auth-HMAC ") {
        return Err("Authentication failed: invalid prefix".into());
    }
    
    let parts: Vec<&str> = auth.split_whitespace().collect();
    if parts.len() < 4 {
        return Err("Malformed authentication header".into());
    }

    let client_hash = parts[1];
    let client_time_str = parts[2];
    let client_ver = parts[3].trim_start_matches('v');

    // Parse and verify client timestamp (within 60 seconds)
    let client_time = client_time_str.parse::<u64>().map_err(|_| "Invalid timestamp format")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let diff = (now as i64 - client_time as i64).abs();
    if diff > 60 {
        return Err(format!("Authentication expired. Clock skew: {} seconds", diff).into());
    }

    // Verify expected hash SHA256(token + client_time)
    let expected_hash = format!("{:x}", Sha256::digest(format!("{}{}", token, client_time).as_bytes()));
    if client_hash != expected_hash {
        return Err("Authentication failed: invalid signature".into());
    }
    
    let server_ver = env!("CARGO_PKG_VERSION");
    if is_older(client_ver, server_ver) {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Ok(exe_bytes) = std::fs::read(exe_path) {
                stream.write_all(b"UPG").await?;
                stream.write_all(b"RADE\n").await?;
                stream.write_all(&(exe_bytes.len() as u32).to_be_bytes()).await?;
                stream.write_all(&exe_bytes).await?;
                stream.flush().await?;
                return Err("Client upgrade triggered".into());
            }
        }
    }
    
    stream.write_all(b"ACK").await?;
    stream.flush().await?;
    Ok(())
}

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

    // Append ALPN extension (http/1.1) to look like a standard web browser connection
    extensions.extend_from_slice(&[
        0x00, 0x10, // Extension Type: ALPN
        0x00, 0x0b, // Extension Length: 11
        0x00, 0x09, // Protocol List Length: 9
        0x08, // Protocol Name Length: 8
        b'h', b't', b't', b'p', b'/', b'1', b'.', b'1' // "http/1.1"
    ]);

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
    let _ = crate::common::network::optimize_socket(&socket);
    let decoy_str = extract_domain(&decoy.unwrap_or_else(|| "google.com".to_string()));
    match protocol {
        "beam" | "tcpmux" | "photon" | "quantummux" => {
            perform_client_upgrade_check(&mut socket, token).await?;
            Ok(TransportStream::Tcp(socket))
        }
        "aura" | "httpmux" => {
            use sha2::{Sha256, Digest};
            use std::time::{SystemTime, UNIX_EPOCH};
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let hash = format!("{:x}", Sha256::digest(format!("{}{}", token, timestamp).as_bytes()));
            let req = format!(
                "GET /tunnel HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Cookie: __cf_session_id={}-{}\r\n\r\n",
                 decoy_str, hash, timestamp
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
            use tokio_tungstenite::tungstenite::client::IntoClientRequest;
            let ws_url = format!("ws://{}/ws", decoy_str);
            let mut request = ws_url.into_client_request()?;
            request.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                format!("tunnel, {}", token).parse().unwrap(),
            );
            let (ws_stream, _) = tokio_tungstenite::client_async_with_config(
                request,
                socket,
                Some(get_ws_config()),
            ).await?;
            Ok(TransportStream::ObfuscatedWs(ObfuscatedStream::new(WsByteStream::new(ws_stream))))
        }
        "nova" | "httpsmux" => {
            let config = get_client_tls_config();
            let connector = TlsConnector::from(config);
            let domain = ServerName::try_from(decoy_str.as_str())?.to_owned();
            let tls_stream = connector.connect(domain, socket).await?;
            
            let mut stream = TransportStream::TlsClient(tls_stream);
            perform_client_upgrade_check(&mut stream, token).await?;
            Ok(stream)
        }
        "beacon" | "wssmux" => {
            let config = get_client_tls_config();
            let connector = TlsConnector::from(config);
            let domain = ServerName::try_from(decoy_str.as_str())?.to_owned();
            let tls_stream = connector.connect(domain, socket).await?;
            
            use tokio_tungstenite::tungstenite::client::IntoClientRequest;
            let ws_url = format!("wss://{}/wss", decoy_str);
            let mut request = ws_url.into_client_request()?;
            request.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                format!("tunnel, {}", token).parse().unwrap(),
            );
            let (ws_stream, _) = tokio_tungstenite::client_async_with_config(
                request,
                tls_stream,
                Some(get_ws_config()),
            ).await?;
            Ok(TransportStream::ObfuscatedWss(ObfuscatedStream::new(WsByteStream::new(ws_stream))))
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
            perform_client_upgrade_check(&mut socket, token).await?;
            Ok(TransportStream::Tcp(socket))
        }
    }
}

fn make_ws_auth_callback(
    token: String,
    decoy_str: String,
    token_found: Arc<std::sync::atomic::AtomicBool>,
) -> impl FnOnce(
    &tungstenite::handshake::server::Request,
    tungstenite::handshake::server::Response,
) -> Result<tungstenite::handshake::server::Response, tungstenite::handshake::server::ErrorResponse> {
    move |req, mut resp| {
        // 1. Check query parameter
        if let Some(query) = req.uri().query() {
            if query.contains(&format!("token={}", token)) {
                token_found.store(true, std::sync::atomic::Ordering::Relaxed);
                return Ok(resp);
            }
        }

        // 2. Check Sec-WebSocket-Protocol header
        if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol").and_then(|v| v.to_str().ok()) {
            if proto.contains(&token) {
                token_found.store(true, std::sync::atomic::Ordering::Relaxed);
                resp.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    proto.parse().unwrap(),
                );
                return Ok(resp);
            }
        }

        let redirect_url = if decoy_str.starts_with("http://") || decoy_str.starts_with("https://") {
            decoy_str
        } else {
            format!("https://{}", decoy_str)
        };

        Err(tungstenite::http::Response::builder()
            .status(302)
            .header("Location", redirect_url)
            .header("Connection", "close")
            .body(Some("".to_string()))
            .unwrap())
    }
}

/// Server handshake logic to authenticate client and wrap standard TcpStream
#[allow(clippy::result_large_err)]
pub async fn server_handshake(
    mut socket: TcpStream,
    protocol: &str,
    token: &str,
    decoy: Option<String>,
) -> Result<TransportStream, Box<dyn Error + Send + Sync>> {
    let _ = crate::common::network::optimize_socket(&socket);

    match protocol {
        "beam" | "tcpmux" | "photon" | "quantummux" => {
            perform_server_handshake_check(&mut socket, token).await?;
            Ok(TransportStream::Tcp(socket))
        }
        "aura" | "httpmux" => {
            use tokio::io::AsyncReadExt;
            let mut header_buf = Vec::new();
            let mut temp = [0u8; 1];
            loop {
                socket.read_exact(&mut temp).await?;
                header_buf.push(temp[0]);
                if header_buf.ends_with(b"\r\n\r\n") {
                    break;
                }
                if header_buf.len() > 4096 {
                    return Err("HTTP header limit exceeded".into());
                }
            }
            let req_str = String::from_utf8_lossy(&header_buf);

            // Parse Cookie: __cf_session_id=<hash>-<timestamp>
            let mut authenticated = false;
            let mut client_hash = "";
            let mut client_time_str = "";
            
            for line in req_str.lines() {
                let line_lower = line.to_lowercase();
                if line_lower.starts_with("cookie:") {
                    if let Some(cookie_val) = line.split(':').nth(1) {
                        for cookie in cookie_val.split(';') {
                            let parts: Vec<&str> = cookie.trim().split('=').collect();
                            if parts.len() == 2 && parts[0] == "__cf_session_id" {
                                let val_parts: Vec<&str> = parts[1].split('-').collect();
                                if val_parts.len() == 2 {
                                    client_hash = val_parts[0];
                                    client_time_str = val_parts[1];
                                }
                            }
                        }
                    }
                }
            }

            if !client_hash.is_empty() && !client_time_str.is_empty() {
                if let Ok(client_time) = client_time_str.parse::<u64>() {
                    use std::time::{SystemTime, UNIX_EPOCH};
                    if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                        let diff = (now.as_secs() as i64 - client_time as i64).abs();
                        if diff <= 60 {
                            use sha2::{Sha256, Digest};
                            let expected_hash = format!("{:x}", Sha256::digest(format!("{}{}", token, client_time).as_bytes()));
                            if client_hash == expected_hash {
                                authenticated = true;
                            }
                        }
                    }
                }
            }

            if !authenticated {
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
            use std::sync::atomic::{AtomicBool, Ordering};
            let token_found = Arc::new(AtomicBool::new(false));
            let decoy_str = decoy.clone().unwrap_or_else(|| "google.com".to_string());
            let callback = make_ws_auth_callback(token.to_string(), decoy_str, token_found.clone());
            let ws_stream = tokio_tungstenite::accept_hdr_async_with_config(
                socket,
                callback,
                Some(get_ws_config()),
            ).await?;
            if !token_found.load(Ordering::Relaxed) {
                return Err("WebSocket auth token validation failed".into());
            }
            Ok(TransportStream::ObfuscatedWs(ObfuscatedStream::new(WsByteStream::new(ws_stream))))
        }
        "nova" | "httpsmux" => {
            let config = get_server_tls_config()?;
            let acceptor = TlsAcceptor::from(config);
            let tls_stream = acceptor.accept(socket).await?;
            
            let mut stream = TransportStream::TlsServer(tls_stream);
            if let Err(e) = perform_server_handshake_check(&mut stream, token).await {
                let _ = send_decoy_response(&mut stream, decoy).await;
                return Err(e);
            }
            Ok(stream)
        }
        "beacon" | "wssmux" => {
            let config = get_server_tls_config()?;
            let acceptor = TlsAcceptor::from(config);
            let tls_stream = acceptor.accept(socket).await?;

            use std::sync::atomic::{AtomicBool, Ordering};
            let token_found = Arc::new(AtomicBool::new(false));
            let decoy_str = decoy.clone().unwrap_or_else(|| "google.com".to_string());
            let callback = make_ws_auth_callback(token.to_string(), decoy_str, token_found.clone());
            let ws_stream = tokio_tungstenite::accept_hdr_async_with_config(
                tls_stream,
                callback,
                Some(get_ws_config()),
            ).await?;
            if !token_found.load(Ordering::Relaxed) {
                return Err("WSS auth token validation failed".into());
            }
            Ok(TransportStream::ObfuscatedWssServer(ObfuscatedStream::new(WsByteStream::new(ws_stream))))
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
            perform_server_handshake_check(&mut socket, token).await?;
            Ok(TransportStream::Tcp(socket))
        }
    }
}

async fn fetch_decoy_proxy(decoy_url: &str) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    
    let resp = client.get(decoy_url).send().await?;
    let status = resp.status().as_u16();
    
    let mut headers = Vec::new();
    for (key, val) in resp.headers().iter() {
        if let Ok(val_str) = val.to_str() {
            headers.push((key.to_string(), val_str.to_string()));
        }
    }
    
    let body = resp.bytes().await?.to_vec();
    Ok((status, headers, body))
}

fn clean_decoy_domain(url: &str) -> String {
    let without_proto = if let Some(stripped) = url.strip_prefix("https://") {
        stripped
    } else if let Some(stripped) = url.strip_prefix("http://") {
        stripped
    } else {
        url
    };
    let host = without_proto.split('/').next().unwrap_or(url);
    host.split(':').next().unwrap_or(host).to_string()
}

async fn send_decoy_response<S>(socket: &mut S, decoy: Option<String>) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    
    let mut status = 200;
    let mut headers = vec![
        ("Content-Type".to_string(), "text/html; charset=UTF-8".to_string()),
        ("Connection".to_string(), "close".to_string()),
    ];
    let mut body = b"<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Under Construction</h1></body></html>".to_vec();

    if let Some(ref d) = decoy {
        let domain = clean_decoy_domain(d);
        let local_path = format!("static/decoys/{}.html", domain);
        let path = std::path::Path::new(&local_path);
        
        if path.exists() {
            if let Ok(content) = std::fs::read(path) {
                status = 200;
                headers = vec![
                    ("Content-Type".to_string(), "text/html; charset=UTF-8".to_string()),
                    ("Connection".to_string(), "close".to_string()),
                ];
                body = content;
            }
        } else if d.starts_with("http://") || d.starts_with("https://") {
            // Attempt to reverse proxy the decoy website
            match fetch_decoy_proxy(d).await {
                Ok((s, h, b)) => {
                    status = s;
                    headers = h.into_iter().filter(|(k, _)| {
                        let k_lower = k.to_lowercase();
                        k_lower != "transfer-encoding" && k_lower != "content-encoding" && k_lower != "connection" && k_lower != "server" && k_lower != "date"
                    }).collect();
                    headers.push(("Connection".to_string(), "close".to_string()));
                    body = b;
                }
                Err(e) => {
                    eprintln!("[DECOY] Proxy to {} failed, falling back to redirect: {}", d, e);
                    // Fallback to 302 redirect
                    status = 302;
                    headers = vec![
                        ("Location".to_string(), d.clone()),
                        ("Connection".to_string(), "close".to_string()),
                    ];
                    body = Vec::new();
                }
            }
        } else {
            // Treat as static HTML/text raw decoy content
            headers = vec![
                ("Content-Type".to_string(), "text/html; charset=UTF-8".to_string()),
                ("Connection".to_string(), "close".to_string()),
            ];
            body = d.as_bytes().to_vec();
        }
    }

    // Dynamic HTTP Date Header calculation
    let date_str = {
        let now = std::time::SystemTime::now();
        let dur = now.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap_or_default();
        let secs = dur.as_secs();
        let days = secs / 86400;
        let day_of_week = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(days % 7) as usize];
        
        let mut year = 1970;
        let mut days_left = days;
        loop {
            let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
            let year_days = if is_leap { 366 } else { 365 };
            if days_left < year_days {
                break;
            }
            days_left -= year_days;
            year += 1;
        }
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let month_days = if is_leap {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let mut month_idx = 0;
        while days_left >= month_days[month_idx] {
            days_left -= month_days[month_idx];
            month_idx += 1;
        }
        let mday = days_left + 1;
        let hour = (secs % 86400) / 3600;
        let min = (secs % 3600) / 60;
        let sec = secs % 60;
        format!("{}, {:02} {} {} {:02}:{:02}:{:02} GMT", day_of_week, mday, months[month_idx], year, hour, min, sec)
    };

    headers.push(("Server".to_string(), "nginx/1.22.0 (Ubuntu)".to_string()));
    headers.push(("Date".to_string(), date_str));

    // Active probing packet size randomization padding
    let is_html = headers.iter().any(|(k, v)| k.to_lowercase() == "content-type" && v.to_lowercase().contains("text/html"));
    if is_html && !body.is_empty() {
        let seed = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let pad_len = 50 + (seed % 450) as usize;
        let pad_chars: String = (0..pad_len).map(|i| (((seed + i as u128) % 26) as u8 + b'a') as char).collect();
        let padding_str = format!("\n<!-- {} -->\n", pad_chars);
        body.extend_from_slice(padding_str.as_bytes());
    }
    let status_text = match status {
        200 => "OK",
        302 => "Found",
        404 => "Not Found",
        _ => "OK",
    };
    
    let mut response = format!("HTTP/1.1 {} {}\r\n", status, status_text);
    for (k, v) in &headers {
        response.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !headers.iter().any(|(k, _)| k.to_lowercase() == "content-length") {
        response.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    response.push_str("\r\n");

    let mut raw_bytes = response.into_bytes();
    raw_bytes.extend_from_slice(&body);

    socket.write_all(&raw_bytes).await?;
    socket.flush().await
}

#[cfg(test)]
mod tests;
