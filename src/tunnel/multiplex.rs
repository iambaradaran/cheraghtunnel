use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Mutex};
use std::collections::HashMap;

pub struct TunnelTraffic {
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub quota_limit: AtomicU64,
    pub quota_used: AtomicU64,
    pub speed_limit: std::sync::atomic::AtomicU32, // in KB/s
    pub last_time: Mutex<std::time::Instant>,
    pub bytes_this_sec: std::sync::atomic::AtomicU32,
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
                quota_limit: AtomicU64::new(0),
                quota_used: AtomicU64::new(0),
                speed_limit: std::sync::atomic::AtomicU32::new(0),
                last_time: Mutex::new(std::time::Instant::now()),
                bytes_this_sec: std::sync::atomic::AtomicU32::new(0),
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
        // Enforce quota limit
        let limit = self.tracker.quota_limit.load(Ordering::Relaxed);
        if limit > 0 {
            let used = self.tracker.quota_used.load(Ordering::Relaxed);
            if used >= limit {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Quota limit exceeded",
                )));
            }
        }

        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let after = buf.filled().len();
            if after > before {
                let n = after - before;
                self.tracker.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MonitoredStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        // Enforce quota limit
        let limit = self.tracker.quota_limit.load(Ordering::Relaxed);
        if limit > 0 {
            let used = self.tracker.quota_used.load(Ordering::Relaxed);
            if used >= limit {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Quota limit exceeded",
                )));
            }
        }

        // Enforce speed limit
        let speed_limit = self.tracker.speed_limit.load(Ordering::Relaxed);
        if speed_limit > 0 {
            let now = std::time::Instant::now();
            let mut last = self.tracker.last_time.lock().unwrap();
            let elapsed = now.duration_since(*last).as_secs_f64();
            if elapsed >= 1.0 {
                *last = now;
                self.tracker.bytes_this_sec.store(0, Ordering::Relaxed);
            }
            let current = self.tracker.bytes_this_sec.load(Ordering::Relaxed);
            if current >= (speed_limit as u32 * 1024) {
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    waker.wake();
                });
                return Poll::Pending;
            }
            self.tracker.bytes_this_sec.fetch_add(buf.len() as u32, Ordering::Relaxed);
        }

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
