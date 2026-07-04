use std::net::UdpSocket;
use tokio::net::UdpSocket as AsyncUdpSocket;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::test]
async fn test_udp_clone() {
    let std_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    std_udp.set_nonblocking(true).unwrap();
    let local_addr = std_udp.local_addr().unwrap();
    println!("Bound to {}", local_addr);
    
    let udp_rx = std_udp.try_clone().unwrap();
    let client_udp_addr = Arc::new(Mutex::new(None::<std::net::SocketAddr>));
    let addr_rx = client_udp_addr.clone();

    // Spawn blocking thread to send
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(addr) = *addr_rx.lock().unwrap() {
            println!("Sending to {}", addr);
            let res = udp_rx.send_to(b"Hello from thread", addr);
            println!("Send result: {:?}", res);
        } else {
            println!("No addr!");
        }
    });

    let async_udp = AsyncUdpSocket::from_std(std_udp).unwrap();
    
    // Spawn another UDP socket to communicate with it
    let client = AsyncUdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"Ping", local_addr).await.unwrap();
    
    let mut buf = [0u8; 1024];
    let (n, addr) = async_udp.recv_from(&mut buf).await.unwrap();
    println!("Async recv: {} bytes from {}", n, addr);
    *client_udp_addr.lock().unwrap() = Some(addr);
    
    // Now the thread should send back
    let (n, addr) = client.recv_from(&mut buf).await.unwrap();
    println!("Client recv: {} bytes from {}", n, addr);
    assert_eq!(&buf[..n], b"Hello from thread");
}
