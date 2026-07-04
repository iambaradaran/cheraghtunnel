use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum as ipv4_header_checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use rand::Rng;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::process::Command;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use kcp_tokio::{KcpConfig, KcpListener, KcpStream};

const MTU: usize = 1400;

pub fn apply_iptables_drop(port: u16) {
    println!("[FakeTCP] Applying iptables drop rule for outgoing RST on port {}...", port);
    let _ = Command::new("iptables")
        .args(["-D", "OUTPUT", "-p", "tcp", "--sport", &port.to_string(), "--tcp-flags", "RST", "RST", "-j", "DROP"])
        .status();
    let _ = Command::new("iptables")
        .args(["-I", "OUTPUT", "-p", "tcp", "--sport", &port.to_string(), "--tcp-flags", "RST", "RST", "-j", "DROP"])
        .status();
}

pub fn remove_iptables_drop(port: u16) {
    println!("[FakeTCP] Removing iptables drop rule for outgoing RST on port {}...", port);
    let _ = Command::new("iptables")
        .args(["-D", "OUTPUT", "-p", "tcp", "--sport", &port.to_string(), "--tcp-flags", "RST", "RST", "-j", "DROP"])
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
        let dummy = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
        dummy.connect((self.remote_ip, self.remote_port)).await.map_err(|e| e.to_string())?;
        self.local_ip = match dummy.local_addr().unwrap().ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => return Err("IPv6 not supported for FakeTCP".into()),
        };
        self.local_port = rand::thread_rng().gen_range(40000..65000) as u16;

        let guard = Arc::new(IptablesGuard::new(self.local_port));

        let (mut tx, mut rx) = transport_channel(65535, TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)).unwrap();
        
        let client_seq = rand::thread_rng().gen::<u32>();
        
        // --- 1. TCP Handshake ---
        println!("[FakeTCP Client] Sending SYN to server...");
        let syn_pkt = craft_tcp_ip_packet(
            self.local_ip, self.remote_ip, self.local_port, self.remote_port,
            client_seq, 0, TcpFlags::SYN, &[]
        );
        let ip_syn = MutableIpv4Packet::owned(syn_pkt).unwrap();
        tx.send_to(ip_syn, std::net::IpAddr::V4(self.remote_ip)).map_err(|e| e.to_string())?;

        let mut server_seq = 0;
        let mut handshake_done = false;

        // Wait for SYN-ACK
        {
            let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);
            let start_time = std::time::Instant::now();
            while start_time.elapsed().as_secs() < 5 {
                if let Ok((ipv4, _)) = iter.next() {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp 
                        && ipv4.get_source() == self.remote_ip && ipv4.get_destination() == self.local_ip {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            if tcp.get_source() == self.remote_port && tcp.get_destination() == self.local_port {
                                if (tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK)) == (TcpFlags::SYN | TcpFlags::ACK) {
                                    server_seq = tcp.get_sequence();
                                    println!("[FakeTCP Client] Received SYN-ACK. Sending ACK...");
                                    handshake_done = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        if !handshake_done {
            return Err("FakeTCP Handshake Timeout (No SYN-ACK received)".into());
        }

        let ack_pkt = craft_tcp_ip_packet(
            self.local_ip, self.remote_ip, self.local_port, self.remote_port,
            client_seq.wrapping_add(1), server_seq.wrapping_add(1), TcpFlags::ACK, &[]
        );
        let ip_ack = MutableIpv4Packet::owned(ack_pkt).unwrap();
        tx.send_to(ip_ack, std::net::IpAddr::V4(self.remote_ip)).map_err(|e| e.to_string())?;
        println!("[FakeTCP Client] Handshake complete!");

        // --- 2. Start Proxy ---
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_udp = udp.local_addr().unwrap();
        let client_udp_addr = Arc::new(Mutex::new(None::<SocketAddr>));
        
        let remote_ip = self.remote_ip;
        let remote_port = self.remote_port;
        let local_ip = self.local_ip;
        let local_port = self.local_port;

        let udp_rx = udp.clone();
        let addr_rx = client_udp_addr.clone();
        let guard_clone = guard.clone();
        tokio::spawn(async move {
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
                                    if let Some(addr) = *addr_rx.lock().await {
                                        let _ = udp_rx.send_to(payload, addr).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let udp_tx = udp.clone();
        let tx_mutex = Arc::new(Mutex::new(tx));
        tokio::spawn(async move {
            let mut buf = [0u8; MTU];
            let mut seq = client_seq.wrapping_add(1);
            let ack = server_seq.wrapping_add(1);
            loop {
                if let Ok((n, src_addr)) = udp_tx.recv_from(&mut buf).await {
                    *client_udp_addr.lock().await = Some(src_addr);
                    
                    let pkt = craft_tcp_ip_packet(
                        local_ip, remote_ip, local_port, remote_port,
                        seq, ack, TcpFlags::PSH | TcpFlags::ACK, &buf[..n]
                    );
                    
                    let ip = MutableIpv4Packet::owned(pkt).unwrap();
                    seq = seq.wrapping_add(n as u32);
                    let mut tx_guard = tx_mutex.lock().await;
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

        let (mut tx, mut rx) = transport_channel(65535, TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)).unwrap();
        
        let local_port = self.local_port;
        
        // Mapping from Client Public IP+Port to a UDP socket connected to KCP
        let clients = Arc::new(Mutex::new(HashMap::<SocketAddrV4, Arc<UdpSocket>>::new()));
        
        let tx_mutex = Arc::new(Mutex::new(tx));
        let guard_clone = guard.clone();
        
        tokio::spawn(async move {
            let _g = guard_clone;
            let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);
            loop {
                if let Ok((ipv4, _)) = iter.next() {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            if tcp.get_destination() == local_port {
                                let remote_addr = SocketAddrV4::new(ipv4.get_source(), tcp.get_source());
                                let dst_ip = ipv4.get_destination();
                                let flags = tcp.get_flags();
                                let seq = tcp.get_sequence();
                                
                                // Handle TCP Handshake (SYN)
                                if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) == 0 {
                                    println!("[FakeTCP Server] Received SYN from {}. Sending SYN-ACK...", remote_addr);
                                    let server_seq = rand::thread_rng().gen::<u32>();
                                    let pkt = craft_tcp_ip_packet(
                                        dst_ip, *remote_addr.ip(), local_port, remote_addr.port(),
                                        server_seq, seq.wrapping_add(1), TcpFlags::SYN | TcpFlags::ACK, &[]
                                    );
                                    let ip = MutableIpv4Packet::owned(pkt).unwrap();
                                    let mut tx_guard = tx_mutex.lock().await;
                                    let _ = tx_guard.send_to(ip, std::net::IpAddr::V4(*remote_addr.ip()));
                                    continue;
                                }

                                let payload = tcp.payload();
                                if !payload.is_empty() {
                                    let mut clients_map = clients.lock().await;
                                    let udp = if let Some(u) = clients_map.get(&remote_addr) {
                                        u.clone()
                                    } else {
                                        // New NAT mapping!
                                        let new_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                                        new_udp.connect(kcp_local_udp).await.unwrap();
                                        clients_map.insert(remote_addr, new_udp.clone());
                                        
                                        // Start reverse loop for this client
                                        let reverse_udp = new_udp.clone();
                                        let reverse_tx = tx_mutex.clone();
                                        
                                        tokio::spawn(async move {
                                            let mut buf = [0u8; MTU];
                                            let mut rseq = 1000u32;
                                            loop {
                                                if let Ok(n) = reverse_udp.recv(&mut buf).await {
                                                    let pkt = craft_tcp_ip_packet(
                                                        dst_ip, *remote_addr.ip(), local_port, remote_addr.port(),
                                                        rseq, 0, TcpFlags::PSH | TcpFlags::ACK, &buf[..n]
                                                    );
                                                    let ip = MutableIpv4Packet::owned(pkt).unwrap();
                                                    rseq = rseq.wrapping_add(n as u32);
                                                    let mut tx_guard = reverse_tx.lock().await;
                                                    let _ = tx_guard.send_to(ip, std::net::IpAddr::V4(*remote_addr.ip()));
                                                }
                                            }
                                        });
                                        new_udp
                                    };
                                    
                                    let _ = udp.send(payload).await;
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
