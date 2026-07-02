use std::io;
use tokio::net::{TcpStream, TcpListener};
use socket2::{SockRef, TcpKeepalive};
use std::time::Duration;

/// Optimizes TCP socket options for high throughput, low latency, and evasion of ISP throttling.
/// Applies keepalive, nodelay, prioritized TOS, optimized buffers, and TCP BBR congestion control on Linux.
pub fn optimize_socket(stream: &TcpStream) -> io::Result<()> {
    let socket = SockRef::from(stream);
    
    // 1. Disable Nagle's algorithm for instant packet delivery (vital for gaming/real-time)
    let _ = socket.set_nodelay(true);
    
    // 2. Configure aggressive keepalives to prevent ISP firewalls from dropping idle sessions
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(20))
        .with_interval(Duration::from_secs(5));
    let _ = socket.set_tcp_keepalive(&keepalive);
    
    // 3. Set optimized TCP buffer sizes (256KB) for high throughput
    let _ = socket.set_recv_buffer_size(256 * 1024);
    let _ = socket.set_send_buffer_size(256 * 1024);
    
    // 4. Set IP Type of Service (TOS) to Low Delay to prioritize packets on routers
    let _ = socket.set_tos(0x10); // IPTOS_LOWDELAY
    
    // 5. Apply TCP BBR congestion control (Linux only, falls back to cubic if BBR is unavailable)
    #[cfg(target_os = "linux")]
    {
        let optval = b"bbr\0";
        unsafe {
            let ret = libc::setsockopt(
                std::os::fd::AsRawFd::as_raw_fd(stream),
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                optval.as_ptr() as *const libc::c_void,
                optval.len() as libc::socklen_t,
            );
            if ret != 0 {
                // Fallback to cubic if BBR is not configured in kernel
                let optval_cubic = b"cubic\0";
                libc::setsockopt(
                    std::os::fd::AsRawFd::as_raw_fd(stream),
                    libc::IPPROTO_TCP,
                    libc::TCP_CONGESTION,
                    optval_cubic.as_ptr() as *const libc::c_void,
                    optval_cubic.len() as libc::socklen_t,
                );
            }
        }
    }
    
    Ok(())
}



/// Creates and binds a TCP listener with SO_REUSEADDR and SO_REUSEPORT enabled before binding
pub fn bind_listener(addr: std::net::SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Socket, Domain, Type, Protocol};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    let _ = socket.set_reuse_port(true);
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener)
}
