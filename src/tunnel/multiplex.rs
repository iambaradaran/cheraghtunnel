use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Mutex};
use std::collections::HashMap;

pub struct TunnelTraffic {
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
}

/// Global thread-safe registry to accumulate traffic byte counts per tunnel ID.
pub static TRAFFIC_REGISTRY: OnceLock<Mutex<HashMap<i64, Arc<TunnelTraffic>>>> = OnceLock::new();

pub fn get_traffic_tracker(tunnel_id: i64) -> Arc<TunnelTraffic> {
    let registry = TRAFFIC_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = registry.lock().unwrap();
    map.entry(tunnel_id)
        .or_insert_with(|| {
            Arc::new(TunnelTraffic {
                rx_bytes: AtomicU64::new(0),
                tx_bytes: AtomicU64::new(0),
            })
        })
        .clone()
}

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

pub struct MonitoredStream<S> {
    inner: S,
    tracker: Arc<TunnelTraffic>,
}

impl<S> MonitoredStream<S> {
    pub fn new(inner: S, tracker: Arc<TunnelTraffic>) -> Self {
        Self { inner, tracker }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MonitoredStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let after = buf.filled().len();
            if after > before {
                self.tracker.rx_bytes.fetch_add((after - before) as u64, Ordering::Relaxed);
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MonitoredStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            self.tracker.tx_bytes.fetch_add(*n as u64, Ordering::Relaxed);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Pipes data bidirectionally between two streams, counting bytes in real-time.
/// Uses tokio::io::copy_bidirectional to guarantee high-performance full-duplex transfer.
pub async fn pipe_streams_monitored<S1, S2>(
    stream1: S1,
    mut stream2: S2,
    tunnel_id: i64,
) where
    S1: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S2: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tracker = get_traffic_tracker(tunnel_id);
    let mut monitored_stream1 = MonitoredStream::new(stream1, tracker);
    
    let _ = tokio::io::copy_bidirectional(&mut monitored_stream1, &mut stream2).await;
}

/// Legacy/Direct pipe without monitoring (used for control connections)
#[allow(dead_code)]
pub async fn pipe_streams<S1, S2>(mut stream1: S1, mut stream2: S2)
where
    S1: AsyncRead + AsyncWrite + Unpin,
    S2: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::io::copy_bidirectional(&mut stream1, &mut stream2).await;
}

/// Helper to connect to local service
pub async fn connect_to_local(target: &str) -> Result<TcpStream, std::io::Error> {
    TcpStream::connect(target).await
}
