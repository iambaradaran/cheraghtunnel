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
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TransportOptions {
    #[serde(default)]
    pub fragment_sni: bool,
    #[serde(default = "default_fragment_size")]
    pub fragment_size: usize,
    #[serde(default)]
    pub randomize_ua: bool,
    #[serde(default)]
    pub enable_padding: bool,
    #[serde(default)]
    pub enable_chaffing: bool,
    #[serde(default)]
    pub enable_ech: bool,
    #[serde(default)]
    pub enable_multipath: bool,
}

fn default_fragment_size() -> usize {
    5
}

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
];

fn get_user_agent(randomize: bool) -> &'static str {
    if randomize {
        let mut rng = rand::thread_rng();
        USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())]
    } else {
        USER_AGENTS[0]
    }
}

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NirvanaReadState {
    ChunkHeader,
    ChunkBody { size: usize },
    ChunkFooter,
}

pub struct NirvanaStream<S> {
    inner: S,
    read_state: NirvanaReadState,
    read_buf: Vec<u8>,
    read_pos: usize,
    payload_buf: VecDeque<u8>,
    write_buf: Vec<u8>,
    write_pos: usize,
    xor_key: [u8; 32],
}

impl<S> NirvanaStream<S> {
    pub fn new(inner: S, token: &str) -> Self {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(token.as_bytes());
        let mut xor_key = [0u8; 32];
        xor_key.copy_from_slice(&hash);
        Self {
            inner,
            read_state: NirvanaReadState::ChunkHeader,
            read_buf: Vec::with_capacity(8192),
            read_pos: 0,
            payload_buf: VecDeque::new(),
            write_buf: Vec::with_capacity(4096),
            write_pos: 0,
            xor_key,
        }
    }

    #[inline]
    fn read_unconsumed(&self) -> &[u8] {
        &self.read_buf[self.read_pos..]
    }

    #[inline]
    fn advance_read(&mut self, n: usize) {
        self.read_pos += n;
        if self.read_pos >= 4096 {
            self.read_buf.drain(0..self.read_pos);
            self.read_pos = 0;
        }
    }
}

impl<S> AsyncRead for NirvanaStream<S>
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

        // 2. Pull raw bytes from the inner stream directly into the tail of read_buf.
        loop {
            let before = this.read_buf.len();
            this.read_buf.resize(before + 4096, 0);
            let mut temp = ReadBuf::new(&mut this.read_buf[before..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut temp) {
                Poll::Ready(Ok(())) => {
                    let filled = temp.filled().len();
                    this.read_buf.truncate(before + filled);
                    if filled == 0 {
                        if this.read_state != NirvanaReadState::ChunkHeader || !this.read_unconsumed().is_empty() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Unexpected EOF in NirvanaStream",
                            )));
                        }
                        return Poll::Ready(Ok(())); // EOF
                    }
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
                NirvanaReadState::ChunkHeader => {
                    if let Some(idx) = unconsumed.windows(2).position(|w| w == b"\r\n") {
                        let hex_str = String::from_utf8_lossy(&unconsumed[..idx]);
                        if let Ok(size) = usize::from_str_radix(hex_str.trim(), 16) {
                            this.read_state = NirvanaReadState::ChunkBody { size };
                            this.advance_read(idx + 2);
                        } else {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Invalid hex chunk size in NirvanaStream",
                            )));
                        }
                    } else {
                        if unconsumed.len() > 16 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Chunk size header too long in NirvanaStream",
                            )));
                        }
                        break;
                    }
                }
                NirvanaReadState::ChunkBody { size } => {
                    let start = this.read_pos;
                    let end_total = start + size;
                    if this.read_buf.len() < end_total {
                        break;
                    }
                    if size < 2 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Nirvana chunk body too short",
                        )));
                    }

                    // XOR decrypt in-place on read_buf (no allocation!)
                    for i in 0..size {
                        this.read_buf[start + i] ^= this.xor_key[i % 32];
                    }

                    let payload_len = u16::from_be_bytes([
                        this.read_buf[start],
                        this.read_buf[start + 1],
                    ]) as usize;

                    if 2 + payload_len > size {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Nirvana payload length out of bounds",
                        )));
                    }

                    let payload_start = start + 2;
                    let payload_end = payload_start + payload_len;

                    // Fast path: skip VecDeque if caller has enough room
                    if payload_len > 0 && this.payload_buf.is_empty() && buf.remaining() >= payload_len {
                        buf.put_slice(&this.read_buf[payload_start..payload_end]);
                        this.advance_read(size);
                        this.read_state = NirvanaReadState::ChunkFooter;
                        return Poll::Ready(Ok(()));
                    }

                    // Fallback to VecDeque
                    this.payload_buf.extend(&this.read_buf[payload_start..payload_end]);
                    this.advance_read(size);
                    this.read_state = NirvanaReadState::ChunkFooter;
                }
                NirvanaReadState::ChunkFooter => {
                    let unconsumed = this.read_unconsumed();
                    if unconsumed.len() >= 2 {
                        if &unconsumed[..2] != b"\r\n" {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Invalid chunk footer in NirvanaStream",
                            )));
                        }
                        this.read_state = NirvanaReadState::ChunkHeader;
                        this.advance_read(2);
                    } else {
                        break;
                    }
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

impl<S> AsyncWrite for NirvanaStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.write_pos >= this.write_buf.len() {
            this.write_buf.clear();
            this.write_pos = 0;

            use rand::Rng;
            let mut rng = rand::thread_rng();
            let padding_len = rng.gen_range(16..128);
            let payload_len = std::cmp::min(buf.len(), 65535);
            let total_body_len = 2 + payload_len + padding_len;

            // Pre-calculate and reserve exact capacity for write_buf to avoid reallocations
            let total_capacity = 10 + total_body_len + 2;
            if this.write_buf.capacity() < total_capacity {
                this.write_buf.reserve(total_capacity - this.write_buf.capacity());
            }

            // Build directly in write_buf — no intermediate Vec allocations!
            let chunk_header = format!("{:x}\r\n", total_body_len);
            this.write_buf.extend_from_slice(chunk_header.as_bytes());
            let xor_offset = this.write_buf.len();
            this.write_buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
            this.write_buf.extend_from_slice(&buf[..payload_len]);
            let pad_start = this.write_buf.len();
            this.write_buf.resize(pad_start + padding_len, 0);
            rng.fill(&mut this.write_buf[pad_start..]);

            // XOR in-place on write_buf
            for i in 0..total_body_len {
                this.write_buf[xor_offset + i] ^= this.xor_key[i % 32];
            }
            this.write_buf.extend_from_slice(b"\r\n");
        }

        let payload_written = std::cmp::min(buf.len(), 65535);

        while this.write_pos < this.write_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..]) {
                Poll::Ready(Ok(n)) => {
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(payload_written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub enum ZeroRttState {
    ReadingHandshake {
        expected: Vec<u8>,
        read_buf: Vec<u8>,
    },
    Ready,
}

pub struct ZeroRttStream<S> {
    inner: S,
    state: ZeroRttState,
    pending_payload: std::collections::VecDeque<u8>,
}

impl<S> ZeroRttStream<S> {
    pub fn new(inner: S, expected_response: Vec<u8>) -> Self {
        Self {
            inner,
            state: ZeroRttState::ReadingHandshake {
                expected: expected_response,
                read_buf: Vec::new(),
            },
            pending_payload: std::collections::VecDeque::new(),
        }
    }
    
    #[allow(dead_code)]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ZeroRttStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // 1. Yield any pending payload bytes first
            if !this.pending_payload.is_empty() {
                let n = std::cmp::min(buf.remaining(), this.pending_payload.len());
                let (slice1, slice2) = this.pending_payload.as_slices();
                if slice1.len() >= n {
                    buf.put_slice(&slice1[..n]);
                } else {
                    buf.put_slice(slice1);
                    buf.put_slice(&slice2[..(n - slice1.len())]);
                }
                this.pending_payload.drain(..n);
                return Poll::Ready(Ok(()));
            }

            // 2. If already Ready, read directly from inner
            if let ZeroRttState::Ready = this.state {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            // 3. Otherwise, we are still ReadingHandshake
            let mut matched = false;
            let mut consumed_len = 0;
            
            if let ZeroRttState::ReadingHandshake { expected, read_buf } = &mut this.state {
                let mut temp_buf = [0u8; 4096];
                let mut temp_read_buf = ReadBuf::new(&mut temp_buf);
                
                match Pin::new(&mut this.inner).poll_read(cx, &mut temp_read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = temp_read_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "ZeroRttStream EOF during handshake",
                            )));
                        }
                        read_buf.extend_from_slice(&temp_buf[..n]);
                        
                        if read_buf.len() >= expected.len() {
                            matched = if expected == b"ACK" {
                                read_buf.starts_with(b"ACK")
                            } else if expected == b"HTTP/1.1 200 OK" {
                                if let Some(idx) = read_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    let header_str = String::from_utf8_lossy(&read_buf[..idx]);
                                    if !header_str.contains("200 OK") {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "Nirvana 200 OK auth failed",
                                        )));
                                    }
                                    true
                                } else {
                                    false
                                }
                            } else if expected == b"ServerHello" {
                                if read_buf.len() >= 6 {
                                    if read_buf[0] != 0x16 || read_buf[1] != 0x03 || read_buf[5] != 0x02 {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "Mirage/Spectre ServerHello verification failed",
                                        )));
                                    }
                                    let rec_len = u16::from_be_bytes([read_buf[3], read_buf[4]]) as usize;
                                    read_buf.len() >= 5 + rec_len
                                } else {
                                    false
                                }
                            } else {
                                read_buf.starts_with(expected)
                            };

                            if matched {
                                consumed_len = if expected == b"ACK" {
                                    3
                                } else if expected == b"HTTP/1.1 200 OK" {
                                    read_buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4
                                } else if expected == b"ServerHello" {
                                    let rec_len = u16::from_be_bytes([read_buf[3], read_buf[4]]) as usize;
                                    5 + rec_len
                                } else {
                                    expected.len()
                                };
                            }
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if matched {
                if let ZeroRttState::ReadingHandshake { read_buf, .. } = &mut this.state {
                    let extra_bytes = &read_buf[consumed_len..];
                    this.pending_payload.extend(extra_bytes);
                }
                this.state = ZeroRttState::Ready;
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ZeroRttStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
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
    Nirvana(NirvanaStream<TcpStream>),
    ZeroRtt(ZeroRttStream<TcpStream>),
    ObfuscatedZeroRtt(ObfuscatedStream<ZeroRttStream<TcpStream>>),
    NirvanaZeroRtt(NirvanaStream<ZeroRttStream<TcpStream>>),
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
            TransportStream::Nirvana(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::ZeroRtt(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::ObfuscatedZeroRtt(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::NirvanaZeroRtt(s) => Pin::new(s).poll_read(cx, buf),
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
            TransportStream::Nirvana(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::ZeroRtt(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::ObfuscatedZeroRtt(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::NirvanaZeroRtt(s) => Pin::new(s).poll_write(cx, buf),
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
            TransportStream::Nirvana(s) => Pin::new(s).poll_flush(cx),
            TransportStream::ZeroRtt(s) => Pin::new(s).poll_flush(cx),
            TransportStream::ObfuscatedZeroRtt(s) => Pin::new(s).poll_flush(cx),
            TransportStream::NirvanaZeroRtt(s) => Pin::new(s).poll_flush(cx),
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
            TransportStream::Nirvana(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::ZeroRtt(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::ObfuscatedZeroRtt(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::NirvanaZeroRtt(s) => Pin::new(s).poll_shutdown(cx),
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

fn timing_safe_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut x = 0;
    for (c1, c2) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        x |= c1 ^ c2;
    }
    x == 0
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

// Helper to construct a standard TLS 1.2 ClientHello binary packet spoofing SNI.
// The ClientRandom field is dynamic, composed of a 4-byte big-endian timestamp
// and a 28-byte hash of the token + timestamp, preventing replay attacks.
fn build_tls_client_hello(decoy: &str, token: &str, opts: &TransportOptions) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    use std::time::{SystemTime, UNIX_EPOCH};
    use rand::Rng;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.update(&timestamp.to_be_bytes());
    let hash = hasher.finalize();
    
    let mut client_random = [0u8; 32];
    client_random[..4].copy_from_slice(&timestamp.to_be_bytes());
    client_random[4..32].copy_from_slice(&hash[..28]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2
    body.extend_from_slice(&client_random);
    body.push(32); // Session ID length
    body.extend_from_slice(&[0u8; 32]); // Dummy Session ID
    
    // Propose 7 modern cipher suites (14 bytes total list length):
    // TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA256 (0x1302), TLS_CHACHA20_POLY1305_SHA256 (0x1303),
    // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b), TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f),
    // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256 (0xc02c), TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA256 (0xc030)
    body.extend_from_slice(&[
        0x00, 0x0e, // Cipher Suites Length: 14 bytes
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
        0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30
    ]);
    
    // Compression methods (1 method: null)
    body.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    let mut extensions = Vec::new();
    
    // 1. Server Name Indication (SNI)
    let mut sni = Vec::new();
    let name_len = decoy.len() as u16;
    sni.extend_from_slice(&(name_len + 3).to_be_bytes()); // server name list length
    sni.push(0x00); // host_name type
    sni.extend_from_slice(&name_len.to_be_bytes());
    sni.extend_from_slice(decoy.as_bytes());
    
    extensions.extend_from_slice(&[0x00, 0x00]); // SNI type
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);

    // 2. ALPN extension (offering http/1.1)
    extensions.extend_from_slice(&[
        0x00, 0x10, // Extension Type: ALPN
        0x00, 0x0b, // Extension Length: 11
        0x00, 0x09, // Protocol List Length: 9
        0x08, // Protocol Name Length: 8
        b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'
    ]);

    // 3. Supported Versions (offering TLS 1.3 & TLS 1.2)
    extensions.extend_from_slice(&[
        0x00, 0x2b, // Extension Type: Supported Versions
        0x00, 0x05, // Extension Length: 5
        0x04,       // Versions List Length: 4
        0x03, 0x04, // TLS 1.3
        0x03, 0x03  // TLS 1.2
    ]);

    // 4. Supported Groups (secp256r1 & x25519)
    extensions.extend_from_slice(&[
        0x00, 0x0a, // Extension Type: Supported Groups
        0x00, 0x06, // Extension Length: 6
        0x04,       // Groups List Length: 4
        0x00, 0x1d, // x25519
        0x00, 0x17  // secp256r1
    ]);

    // 5. Signature Algorithms (ecdsa_sha256, rsa_pss_sha256, rsa_pkcs1_sha256)
    extensions.extend_from_slice(&[
        0x00, 0x0d, // Extension Type: Signature Algorithms
        0x00, 0x08, // Extension Length: 8
        0x06,       // Algorithms List Length: 6
        0x04, 0x03, // ecdsa_secp256r1_sha256
        0x08, 0x04, // rsa_pss_rsae_sha256
        0x04, 0x01  // rsa_pkcs1_sha256
    ]);

    // 6. Key Share (X25519 public key share)
    let mut key_share_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut key_share_bytes);
    let mut key_share = Vec::new();
    key_share.extend_from_slice(&[0x00, 0x24]); // Client key shares length (36 bytes)
    key_share.extend_from_slice(&[0x00, 0x1d]); // Named Group: x25519
    key_share.extend_from_slice(&[0x00, 0x20]); // Key length: 32 bytes
    key_share.extend_from_slice(&key_share_bytes);

    extensions.extend_from_slice(&[0x00, 0x33]); // Extension Type: Key Share
    extensions.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key_share);

    if opts.enable_ech {
        // 7. Encrypted ClientHello (ECH) extension 0xfe0d
        let mut ech_payload = Vec::new();
        ech_payload.extend_from_slice(&[0x00, 0x01]); // Outer ClientHello
        ech_payload.extend_from_slice(&[0x00, 0x20, 0x00, 0x01, 0x00, 0x01]); // CipherSuite: DHKEM(X25519, HKDF-SHA256), AES-128-GCM
        ech_payload.push(0x01); // Config ID
        let mut enc_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut enc_bytes);
        ech_payload.extend_from_slice(&[0x00, 0x20]);
        ech_payload.extend_from_slice(&enc_bytes);
        let mut inner_enc = [0u8; 128];
        rand::thread_rng().fill(&mut inner_enc);
        ech_payload.extend_from_slice(&(inner_enc.len() as u16).to_be_bytes());
        ech_payload.extend_from_slice(&inner_enc);

        extensions.extend_from_slice(&[0xfe, 0x0d]); // Extension Type: ECH (0xfe0d)
        extensions.extend_from_slice(&(ech_payload.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ech_payload);
    }

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

// Verifies the dynamic TLS ClientHello and enforces time-bounded token validation (max 60 seconds clock drift skew).
fn verify_tls_client_hello(data: &[u8], token: &str) -> bool {
    if data.len() < 43 {
        return false;
    }
    // Check TLS Handshake Record Type and Version
    if data[0] != 0x16 || data[1] != 0x03 || data[2] != 0x01 {
        return false;
    }
    if data[5] != 0x01 {
        return false;
    }
    let client_random = &data[11..43];
    
    // Extract timestamp
    let mut ts_bytes = [0u8; 4];
    ts_bytes.copy_from_slice(&client_random[..4]);
    let timestamp = u32::from_be_bytes(ts_bytes);
    
    use std::time::{SystemTime, UNIX_EPOCH};
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
        
    // Enforce 60 seconds time window to block Replay Attacks
    if (current_time as i64 - timestamp as i64).abs() > 60 {
        return false;
    }
    
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.update(&timestamp.to_be_bytes());
    let expected = hasher.finalize();
    
    client_random[4..32] == expected[..28]
}

// Generates a fully valid TLS 1.2 ServerHello record to satisfy stateful DPI engines.
fn build_tls_server_hello() -> Vec<u8> {
    use rand::Rng;
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2
    
    let mut server_random = [0u8; 32];
    rand::thread_rng().fill(&mut server_random);
    body.extend_from_slice(&server_random);
    
    body.push(32); // Session ID length
    body.extend_from_slice(&[0u8; 32]); // Dummy Session ID
    
    // Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc0, 0x2f)
    body.extend_from_slice(&[0xc0, 0x2f]);
    body.push(0x00); // Compression method: null
    
    // Extensions
    let mut extensions = Vec::new();
    
    // 1. ALPN extension (http/1.1)
    extensions.extend_from_slice(&[
        0x00, 0x10, // Extension Type: ALPN
        0x00, 0x0b, // Extension Length: 11
        0x00, 0x09, // Protocol List Length: 9
        0x08, // Protocol Name Length: 8
        b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'
    ]);
    
    // 2. Renegotiation Info
    extensions.extend_from_slice(&[
        0xff, 0x01, // Extension Type: Renegotiation Info
        0x00, 0x01, // Extension Length: 1
        0x00        // Renegotiation verification data length: 0
    ]);

    // 3. EC Point Formats (uncompressed format)
    extensions.extend_from_slice(&[
        0x00, 0x0b, // Extension Type: EC Point Formats
        0x00, 0x02, // Extension Length: 2
        0x01,       // EC point formats length: 1
        0x00        // EC point format: uncompressed
    ]);
    
    let ext_len = extensions.len() as u16;
    body.extend_from_slice(&ext_len.to_be_bytes());
    body.extend_from_slice(&extensions);
    
    let mut handshake = Vec::new();
    handshake.push(0x02); // Handshake Type: ServerHello
    let body_len = body.len() as u32;
    handshake.push(((body_len >> 16) & 0xff) as u8);
    handshake.push(((body_len >> 8) & 0xff) as u8);
    handshake.push((body_len & 0xff) as u8);
    handshake.extend_from_slice(&body);
    
    let mut record = Vec::new();
    record.push(0x16); // Content Type: Handshake
    record.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 Version
    let rec_len = handshake.len() as u16;
    record.extend_from_slice(&rec_len.to_be_bytes());
    record.extend_from_slice(&handshake);
    
    record
}

#[allow(dead_code)]
// Verifies if the incoming packet is a valid TLS ServerHello record.
fn verify_tls_server_hello(data: &[u8]) -> bool {
    if data.len() < 38 {
        return false;
    }
    // Check TLS Handshake Record Type and Version (TLS 1.0 - 1.3 compat)
    if data[0] != 0x16 || data[1] != 0x03 {
        return false;
    }
    // Check Handshake Type: ServerHello (0x02)
    if data[5] != 0x02 {
        return false;
    }
    true
}

/// Client handshake logic to wrap standard TcpStream into selected transport stream
pub async fn client_handshake(
    mut socket: TcpStream,
    protocol: &str,
    token: &str,
    decoy: Option<String>,
    opts: TransportOptions,
) -> Result<TransportStream, Box<dyn Error + Send + Sync>> {
    let _ = crate::common::network::optimize_socket(&socket);
    
    // Resolve multiple decoys (spraying)
    let decoy_list: Vec<&str> = decoy.as_ref()
        .map(|s| s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect())
        .unwrap_or_default();
        
    let selected_decoy = if decoy_list.is_empty() {
        "google.com".to_string()
    } else {
        let mut rng = rand::thread_rng();
        let idx = rng.gen_range(0..decoy_list.len());
        decoy_list[idx].to_string()
    };
    
    let decoy_str = extract_domain(&selected_decoy);
    
    match protocol {
        "beam" | "tcpmux" | "photon" | "quantummux" => {
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
            socket.write_all(auth.as_bytes()).await?;
            socket.flush().await?;
            
            Ok(TransportStream::ZeroRtt(ZeroRttStream::new(socket, b"ACK".to_vec())))
        }
        "nirvana" => {
            use sha2::{Sha256, Digest};
            use std::time::{SystemTime, UNIX_EPOCH};
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let hash = format!("{:x}", Sha256::digest(format!("{}{}", token, timestamp).as_bytes()));
            
            let ua = get_user_agent(opts.randomize_ua);
            let req = format!(
                "POST /api/v1/telemetry HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: {}\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Cookie: __cf_session_id={}-{}\r\n\
                 Connection: keep-alive\r\n\r\n",
                 decoy_str, ua, hash, timestamp
            );
            socket.write_all(req.as_bytes()).await?;
            socket.flush().await?;
            
            let rtt_stream = ZeroRttStream::new(socket, b"HTTP/1.1 200 OK".to_vec());
            Ok(TransportStream::NirvanaZeroRtt(NirvanaStream::new(rtt_stream, token)))
        }
        "aura" | "httpmux" => {
            use sha2::{Sha256, Digest};
            use std::time::{SystemTime, UNIX_EPOCH};
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let hash = format!("{:x}", Sha256::digest(format!("{}{}", token, timestamp).as_bytes()));
            
            let ua = get_user_agent(opts.randomize_ua);
            let req = format!(
                "GET /tunnel HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: {}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Cookie: __cf_session_id={}-{}\r\n\r\n",
                 decoy_str, ua, hash, timestamp
            );
            socket.write_all(req.as_bytes()).await?;
            socket.flush().await?;
            
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
            let resp_str = String::from_utf8_lossy(&header_buf);
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
            use sha2::{Sha256, Digest};
            use std::time::{SystemTime, UNIX_EPOCH};

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let hash = format!("{:x}", Sha256::digest(format!("{}{}", token, timestamp).as_bytes()));
            let ws_url = format!("ws://{}/ws", decoy_str);
            let mut request = ws_url.into_client_request()?;
            request.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                format!("tunnel, {}, {}", hash, timestamp).parse().unwrap(),
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
            use sha2::{Sha256, Digest};
            use std::time::{SystemTime, UNIX_EPOCH};

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let hash = format!("{:x}", Sha256::digest(format!("{}{}", token, timestamp).as_bytes()));
            let ws_url = format!("wss://{}/wss", decoy_str);
            let mut request = ws_url.into_client_request()?;
            request.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                format!("tunnel, {}, {}", hash, timestamp).parse().unwrap(),
            );
            let (ws_stream, _) = tokio_tungstenite::client_async_with_config(
                request,
                tls_stream,
                Some(get_ws_config()),
            ).await?;
            Ok(TransportStream::ObfuscatedWss(ObfuscatedStream::new(WsByteStream::new(ws_stream))))
        }
        "mirage" | "realitymux" | "spectre" => {
            // Write standard TLS ClientHello spoofing the decoy domain
            let hello = build_tls_client_hello(&decoy_str, token, &opts);
            
            if opts.fragment_sni {
                let split = std::cmp::min(opts.fragment_size, hello.len());
                socket.write_all(&hello[..split]).await?;
                socket.flush().await?;
                tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
                if split < hello.len() {
                    socket.write_all(&hello[split..]).await?;
                    socket.flush().await?;
                }
            } else {
                socket.write_all(&hello).await?;
                socket.flush().await?;
            }
            
            let rtt_stream = ZeroRttStream::new(socket, b"ServerHello".to_vec());
            // Apply packet padding obfuscation
            Ok(TransportStream::ObfuscatedZeroRtt(ObfuscatedStream::new(rtt_stream)))
        }
        _ => {
            let auth = format!("Cheragh-Auth-HMAC {} {} v1.0.0\n", token, token);
            socket.write_all(auth.as_bytes()).await?;
            socket.flush().await?;
            Ok(TransportStream::ZeroRtt(ZeroRttStream::new(socket, b"ACK".to_vec())))
        }
    }
}

fn make_ws_auth_callback(
    token: String,
    _decoy_str: String,
    token_found: Arc<std::sync::atomic::AtomicBool>,
) -> impl FnOnce(
    &tungstenite::handshake::server::Request,
    tungstenite::handshake::server::Response,
) -> Result<tungstenite::handshake::server::Response, tungstenite::handshake::server::ErrorResponse> {
    move |req, mut resp| {
        let mut authenticated = false;

        // 1. Check query parameter (sid=<hash>&ts=<timestamp>)
        if let Some(query) = req.uri().query() {
            let mut q_hash = "";
            let mut q_ts = "";
            for part in query.split('&') {
                let kv: Vec<&str> = part.split('=').collect();
                if kv.len() == 2 {
                    if kv[0] == "sid" {
                        q_hash = kv[1];
                    } else if kv[0] == "ts" {
                        q_ts = kv[1];
                    }
                }
            }
            if !q_hash.is_empty() && !q_ts.is_empty() {
                if let Ok(ts_val) = q_ts.parse::<u64>() {
                    use std::time::{SystemTime, UNIX_EPOCH};
                    if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                        if (now.as_secs() as i64 - ts_val as i64).abs() <= 60 {
                            use sha2::{Sha256, Digest};
                            let expected = format!("{:x}", Sha256::digest(format!("{}{}", token, ts_val).as_bytes()));
                            if q_hash == expected {
                                authenticated = true;
                            }
                        }
                    }
                }
            }
        }

        // 2. Check Sec-WebSocket-Protocol header (tunnel, <hash>, <timestamp>)
        if !authenticated {
            if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol").and_then(|v| v.to_str().ok()) {
                let parts: Vec<&str> = proto.split(',').map(|s| s.trim()).collect();
                if parts.len() == 3 && parts[0] == "tunnel" {
                    let client_hash = parts[1];
                    let client_time_str = parts[2];
                    if let Ok(client_time) = client_time_str.parse::<u64>() {
                        use std::time::{SystemTime, UNIX_EPOCH};
                        if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                            if (now.as_secs() as i64 - client_time as i64).abs() <= 60 {
                                use sha2::{Sha256, Digest};
                                let expected = format!("{:x}", Sha256::digest(format!("{}{}", token, client_time).as_bytes()));
                                if client_hash == expected {
                                    authenticated = true;
                                    resp.headers_mut().insert(
                                        "Sec-WebSocket-Protocol",
                                        proto.parse().unwrap(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        if authenticated {
            token_found.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(resp)
        } else {
            let nginx_404_body = "<html>\r\n\
                                  <head><title>404 Not Found</title></head>\r\n\
                                  <body>\r\n\
                                  <center><h1>404 Not Found</h1></center>\r\n\
                                  <hr><center>nginx</center>\r\n\
                                  </body>\r\n\
                                  </html>";
            Err(tungstenite::http::Response::builder()
                .status(404)
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Connection", "close")
                .body(Some(nginx_404_body.to_string()))
                .unwrap())
        }
    }
}

/// Server handshake logic to authenticate client and wrap standard TcpStream
#[allow(clippy::result_large_err)]

pub async fn server_handshake(
    mut socket: TcpStream,
    protocol: &str,
    token: &str,
    decoy: Option<String>,
    _opts: TransportOptions,
) -> Result<TransportStream, Box<dyn Error + Send + Sync>> {
    let _ = crate::common::network::optimize_socket(&socket);

    // Let's inspect the first 5 bytes to determine the protocol dynamically!
    let mut peek_buf = [0u8; 5];
    let n = socket.peek(&mut peek_buf).await.unwrap_or(0);
    
    // Determine the actual protocol format
    let actual_protocol = if ["spectre", "mirage", "nirvana", "beam"].contains(&protocol) {
        if n >= 1 && peek_buf[0] == 0x16 {
            // TLS ClientHello -> Mirage / Spectre
            "spectre"
        } else if n >= 4 && &peek_buf[..4] == b"POST" {
            // HTTP Request -> Nirvana
            "nirvana"
        } else if n >= 4 && &peek_buf[..4] == b"Cher" {
            // Cheragh-Auth-HMAC -> Beam
            "beam"
        } else {
            protocol
        }
    } else {
        protocol
    };

    match actual_protocol {
        "beam" | "tcpmux" | "photon" | "quantummux" => {
            perform_server_handshake_check(&mut socket, token).await?;
            Ok(TransportStream::Tcp(socket))
        }
        "nirvana" => {
            use tokio::io::AsyncReadExt;
            use sha2::{Sha256, Digest};
            use std::time::{SystemTime, UNIX_EPOCH};
            
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
                    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                    let diff = (now as i64 - client_time as i64).abs();
                    if diff <= 60 {
                        let expected_hash = format!("{:x}", Sha256::digest(format!("{}{}", token, client_time).as_bytes()));
                        if timing_safe_eq(client_hash, &expected_hash) {
                            authenticated = true;
                        }
                    }
                }
            }

            if !authenticated {
                let decoy_resp = "HTTP/1.1 404 Not Found\r\n\
                                  Server: Cloudflare\r\n\
                                  Content-Length: 0\r\n\r\n";
                let _ = socket.write_all(decoy_resp.as_bytes()).await;
                return Err("HTTP upgrade auth failed, decoy served".into());
            }

            let resp = "HTTP/1.1 200 OK\r\n\
                        Server: Cloudflare\r\n\
                        Content-Type: application/octet-stream\r\n\
                        Transfer-Encoding: chunked\r\n\
                        Connection: keep-alive\r\n\r\n";
            socket.write_all(resp.as_bytes()).await?;
            socket.flush().await?;

            Ok(TransportStream::Nirvana(NirvanaStream::new(socket, token)))
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
        "mirage" | "realitymux" | "spectre" => {
            use tokio::io::AsyncReadExt;
            let mut header = [0u8; 5];
            socket.read_exact(&mut header).await?;
            
            let mut client_hello = Vec::new();
            client_hello.extend_from_slice(&header);
            
            if header[0] == 0x16 && header[1] == 0x03 {
                let rec_len = u16::from_be_bytes([header[3], header[4]]) as usize;
                if rec_len <= 4096 {
                    let mut body = vec![0u8; rec_len];
                    socket.read_exact(&mut body).await?;
                    client_hello.extend_from_slice(&body);
                }
            } else {
                // Read whatever is immediately available in the socket buffer for the prober
                let mut temp = [0u8; 1024];
                if let Ok(Ok(n)) = tokio::time::timeout(std::time::Duration::from_millis(50), socket.read(&mut temp)).await {
                    client_hello.extend_from_slice(&temp[..n]);
                }
            }

            if verify_tls_client_hello(&client_hello, token) {
                // Successful Reality connection: reply with a standard TLS 1.2 ServerHello
                let hello = build_tls_server_hello();
                socket.write_all(&hello).await?;
                socket.flush().await?;
                
                // Wrap in Obfuscated stream to add dynamic padding
                Ok(TransportStream::Obfuscated(ObfuscatedStream::new(socket)))
            } else {
                // Active prober: proxy transparently to decoy site port 443
                let decoy_target = decoy.unwrap_or_else(|| "microsoft.com".to_string());
                let decoy_list: Vec<&str> = decoy_target.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
                let decoy_host = if decoy_list.is_empty() {
                    "microsoft.com".to_string()
                } else {
                    decoy_list[0].to_string()
                };
                let decoy_host = extract_domain(&decoy_host);
                
                let decoy_addr = format!("{}:443", decoy_host);
                println!("[SERVER] Active probe / invalid ClientHello detected. Proxying to: {}", decoy_addr);
                
                if let Ok(mut decoy_conn) = TcpStream::connect(&decoy_addr).await {
                    let _ = decoy_conn.write_all(&client_hello).await;
                    let _ = tokio::io::copy_bidirectional(&mut socket, &mut decoy_conn).await;
                } else {
                    // Fallback to local-iis to prevent TCP reset/hang signature
                    let _ = send_decoy_response(&mut socket, Some("local-iis".to_string())).await;
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
        
        if d == "local-iis" {
            status = 200;
            headers = vec![
                ("Content-Type".to_string(), "text/html; charset=UTF-8".to_string()),
                ("Connection".to_string(), "close".to_string()),
                ("Server".to_string(), "Microsoft-IIS/10.0".to_string()),
                ("X-Powered-By".to_string(), "ASP.NET".to_string()),
            ];
            body = b"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n\
                     <html xmlns=\"http://www.w3.org/1999/xhtml\">\n\
                     <head>\n\
                     <meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\" />\n\
                     <title>IIS Windows Server</title>\n\
                     <style type=\"text/css\">\n\
                     <!--\n\
                     body {color:#000000;background-color:#FFFFFF;margin:0;font-family:Verdana,Geneva,sans-serif;}\n\
                     #container {width:600px;margin-left:auto;margin-right:auto;padding:100px 0 0 0;}\n\
                     h1 {font-size:2.2em;font-weight:normal;color:#006699;margin:0 0 5px 0;}\n\
                     h2 {font-size:1.2em;font-weight:normal;color:#333333;margin:0 0 20px 0;}\n\
                     a:link, a:visited {color:#007ebb;text-decoration:none;}\n\
                     a:hover {text-decoration:underline;}\n\
                     -->\n\
                     </style>\n\
                     </head>\n\
                     <body>\n\
                     <div id=\"container\">\n\
                     <h1>Welcome</h1>\n\
                     <h2>Internet Information Services (IIS)</h2>\n\
                     <p>This page is served by Microsoft-IIS/10.0 web server. If you are the administrator, configure the site.</p>\n\
                     </div>\n\
                     </body>\n\
                     </html>".to_vec();
        } else if path.exists() {
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

    if !headers.iter().any(|(k, _)| k.to_lowercase() == "server") {
        headers.push(("Server".to_string(), "nginx/1.22.0 (Ubuntu)".to_string()));
    }
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
