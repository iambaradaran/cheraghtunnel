use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum as ipv4_header_checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use rand::Rng;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket as AsyncUdpSocket;
use kcp_tokio::{KcpConfig, KcpListener, KcpStream};

const MTU: usize = 1400;

pub fn apply_iptables_drop(port: u16) {
    println!("[FakeTCP] Applying iptables RST drop rule for port {}...", port);
    let _ = Command::new("iptables")
        .args(["-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "--sport", &port.to_string(), "-j", "DROP"])
        .status();
    let _ = Command::new("iptables")
        .args(["-I", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "--sport", &port.to_string(), "-j", "DROP"])
        .status();
}

pub fn remove_iptables_drop(port: u16) {
    let _ = Command::new("iptables")
        .args(["-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "--sport", &port.to_string(), "-j", "DROP"])
        .status();
}

pub struct IptablesGuard {
    port: u16,
}

impl IptablesGuard {
    pub fn new(port: u16) -> Self {
        apply_iptables_drop(port);
        Self { port }
    }
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        remove_iptables_drop(self.port);
    }
}

fn craft_tcp_ip_packet(
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    src_port: u16, dst_port: u16,
    seq: u32, ack: u32, flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut ip_buffer = vec![0u8; 40 + payload.len()];
    {
        let mut tcp = MutableTcpPacket::new(&mut ip_buffer[20..]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        tcp.set_window(65535);
        tcp.set_payload(payload);
        tcp.set_checksum(ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip));
    }
    {
        let mut ip = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((40 + payload.len()) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_checksum(ipv4_header_checksum(&ip.to_immutable()));
    }
    ip_buffer
}

pub struct FakeTcpClient {
    remote_ip: Ipv4Addr,
    remote_port: u16,
    local_ip: Ipv4Addr,
    local_port: u16,
}

impl FakeTcpClient {
    pub fn new(remote_addr: SocketAddrV4) -> Self {
        Self {
            remote_ip: *remote_addr.ip(),
            remote_port: remote_addr.port(),
            local_ip: Ipv4Addr::new(0, 0, 0, 0),
            local_port: 0,
        }
    }

    pub async fn connect(&mut self, config: KcpConfig) -> Result<KcpStream, String> {
        let dummy = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        dummy.connect((self.remote_ip, self.remote_port)).map_err(|e| e.to_string())?;
        self.local_ip = match dummy.local_addr().unwrap().ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => return Err("IPv6 not supported for FakeTCP".into()),
        };
        self.local_port = rand::thread_rng().gen_range(40000..65000) as u16;

        let guard = Arc::new(IptablesGuard::new(self.local_port));

        let (tx, mut rx) = transport_channel(65535, TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)).unwrap();
        
        let client_seq = rand::thread_rng().gen::<u32>();
        
        // --- Start Proxy (No TCP Handshake, just pure spoofing) ---
        let std_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let local_udp = std_udp.local_addr().unwrap();
        std_udp.set_nonblocking(true).unwrap();
        
        let client_udp_addr = Arc::new(Mutex::new(None::<SocketAddr>));
        
        let remote_ip = self.remote_ip;
        let remote_port = self.remote_port;
        let local_ip = self.local_ip;
        let local_port = self.local_port;

        let udp_rx = std_udp.try_clone().unwrap();
        let addr_rx = client_udp_addr.clone();
        let guard_clone = guard.clone();
        
        // Blocking thread for receiving FakeTCP
        std::thread::spawn(move || {
            let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);
            let _g = guard_clone;
            loop {
                if let Ok((ipv4, _)) = iter.next() {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp 
                        && ipv4.get_source() == remote_ip && ipv4.get_destination() == local_ip 
                    {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            if tcp.get_source() == remote_port && tcp.get_destination() == local_port {
                                let payload = tcp.payload();
                                if !payload.is_empty() {
                                    if let Some(addr) = *addr_rx.lock().unwrap() {
                                        let _ = udp_rx.send_to(payload, addr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let async_udp = AsyncUdpSocket::from_std(std_udp).unwrap();
        let tx_mutex = Arc::new(Mutex::new(tx));
        
        // Async task for sending FakeTCP
        tokio::spawn(async move {
            let mut buf = [0u8; MTU];
            let mut seq = client_seq.wrapping_add(1);
            let ack = 1000u32;
            loop {
                if let Ok((n, src_addr)) = async_udp.recv_from(&mut buf).await {
                    *client_udp_addr.lock().unwrap() = Some(src_addr);
                    
                    let pkt = craft_tcp_ip_packet(
                        local_ip, remote_ip, local_port, remote_port,
                        seq, ack, TcpFlags::PSH | TcpFlags::ACK, &buf[..n]
                    );
                    
                    let ip = MutableIpv4Packet::owned(pkt).unwrap();
                    seq = seq.wrapping_add(n as u32);
                    let mut tx_guard = tx_mutex.lock().unwrap();
                    let _ = tx_guard.send_to(ip, std::net::IpAddr::V4(remote_ip));
                }
            }
        });

        Ok(KcpStream::connect(local_udp, config).await.map_err(|e| e.to_string())?)
    }
}

// -----------------------------------------------------------------------------
// SERVER
// -----------------------------------------------------------------------------

pub struct FakeTcpServer {
    local_port: u16,
}

impl FakeTcpServer {
    pub fn new(local_port: u16) -> Self {
        Self { local_port }
    }

    pub async fn bind(&self, config: KcpConfig) -> Result<KcpListener, String> {
        let guard = Arc::new(IptablesGuard::new(self.local_port));
        let kcp_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let kcp_listener = KcpListener::bind(kcp_addr, config).await.map_err(|e| e.to_string())?;
        let kcp_local_udp = *kcp_listener.local_addr();

        let (tx, mut rx) = transport_channel(65535, TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)).unwrap();
        
        let local_port = self.local_port;
        
        let clients = Arc::new(Mutex::new(HashMap::<SocketAddrV4, std::net::UdpSocket>::new()));
        let tx_mutex = Arc::new(Mutex::new(tx));
        let guard_clone = guard.clone();
        
        // Blocking thread for Server FakeTCP RX
        let handle_tx = tx_mutex.clone();
        std::thread::spawn(move || {
            let _g = guard_clone;
            let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);
            loop {
                if let Ok((ipv4, _)) = iter.next() {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            if tcp.get_destination() == local_port {
                                let remote_addr = SocketAddrV4::new(ipv4.get_source(), tcp.get_source());
                                let dst_ip = ipv4.get_destination();

                                let payload = tcp.payload();
                                if !payload.is_empty() {
                                    let mut clients_map = clients.lock().unwrap();
                                    let udp = if let Some(u) = clients_map.get(&remote_addr) {
                                        u.try_clone().unwrap()
                                    } else {
                                        let new_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                                        new_udp.connect(kcp_local_udp).unwrap();
                                        new_udp.set_nonblocking(true).unwrap();
                                        clients_map.insert(remote_addr, new_udp.try_clone().unwrap());
                                        
                                        let async_udp = AsyncUdpSocket::from_std(new_udp.try_clone().unwrap()).unwrap();
                                        let reverse_tx = handle_tx.clone();
                                        
                                        tokio::spawn(async move {
                                            let mut buf = [0u8; MTU];
                                            let mut rseq = 1000u32;
                                            loop {
                                                if let Ok((n, _)) = async_udp.recv_from(&mut buf).await {
                                                    let pkt = craft_tcp_ip_packet(
                                                        dst_ip, *remote_addr.ip(), local_port, remote_addr.port(),
                                                        rseq, 0, TcpFlags::PSH | TcpFlags::ACK, &buf[..n]
                                                    );
                                                    let ip = MutableIpv4Packet::owned(pkt).unwrap();
                                                    rseq = rseq.wrapping_add(n as u32);
                                                    let mut tx_guard = reverse_tx.lock().unwrap();
                                                    let _ = tx_guard.send_to(ip, std::net::IpAddr::V4(*remote_addr.ip()));
                                                }
                                            }
                                        });
                                        new_udp
                                    };
                                    
                                    let _ = udp.send(payload);
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(kcp_listener)
    }
}
