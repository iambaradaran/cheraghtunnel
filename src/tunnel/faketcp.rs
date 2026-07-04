use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::process::Command;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use kcp_tokio::{KcpConfig, KcpListener, KcpStream};

const MTU: usize = 1400;

pub fn apply_iptables_drop(port: u16) {
    println!("[FakeTCP] Applying iptables drop rule for port {}...", port);
    let _ = Command::new("iptables")
        .args(["-I", "INPUT", "-p", "tcp", "--dport", &port.to_string(), "-j", "DROP"])
        .status();
}

pub fn remove_iptables_drop(port: u16) {
    println!("[FakeTCP] Removing iptables drop rule for port {}...", port);
    let _ = Command::new("iptables")
        .args(["-D", "INPUT", "-p", "tcp", "--dport", &port.to_string(), "-j", "DROP"])
        .status();
}

pub struct FakeTcpClient {
    remote_ip: Ipv4Addr,
    remote_port: u16,
    local_ip: Ipv4Addr,
    local_port: u16,
}

impl FakeTcpClient {
    pub fn new(remote_addr: SocketAddrV4, local_addr: SocketAddrV4) -> Self {
        Self {
            remote_ip: *remote_addr.ip(),
            remote_port: remote_addr.port(),
            local_ip: *local_addr.ip(),
            local_port: local_addr.port(),
        }
    }

    pub async fn connect(&self, config: KcpConfig) -> Result<KcpStream, String> {
        apply_iptables_drop(self.local_port);
        let (mut tx, mut rx) = transport_channel(65535, TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)).unwrap();
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_udp = udp.local_addr().unwrap();
        let client_udp_addr = Arc::new(Mutex::new(None::<SocketAddr>));
        let remote_ip = self.remote_ip;
        let remote_port = self.remote_port;
        let local_ip = self.local_ip;
        let local_port = self.local_port;

        let udp_rx = udp.clone();
        let addr_rx = client_udp_addr.clone();
        tokio::spawn(async move {
            let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);
            loop {
                if let Ok((ipv4, _)) = iter.next() {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp && ipv4.get_source() == remote_ip && ipv4.get_destination() == local_ip {
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
            let mut seq = 1000u32;
            loop {
                if let Ok((n, src_addr)) = udp_tx.recv_from(&mut buf).await {
                    *client_udp_addr.lock().await = Some(src_addr);
                    let mut ip_buffer = vec![0u8; 40 + n];
                    {
                        let mut tcp = MutableTcpPacket::new(&mut ip_buffer[20..]).unwrap();
                        tcp.set_source(local_port);
                        tcp.set_destination(remote_port);
                        tcp.set_sequence(seq);
                        tcp.set_acknowledgement(1000);
                        tcp.set_data_offset(5);
                        tcp.set_flags(TcpFlags::PSH | TcpFlags::ACK);
                        tcp.set_window(65535);
                        tcp.set_payload(&buf[..n]);
                        tcp.set_checksum(ipv4_checksum(&tcp.to_immutable(), &local_ip, &remote_ip));
                    }
                    {
                        let mut ip = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
                        ip.set_version(4);
                        ip.set_header_length(5);
                        ip.set_total_length((40 + n) as u16);
                        ip.set_ttl(64);
                        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                        ip.set_source(local_ip);
                        ip.set_destination(remote_ip);
                        ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
                        seq = seq.wrapping_add(n as u32);
                        let mut tx_guard = tx_mutex.lock().await;
                        let _ = tx_guard.send_to(ip, std::net::IpAddr::V4(remote_ip));
                    }
                }
            }
        });

        Ok(KcpStream::connect(local_udp, config).await.map_err(|e| e.to_string())?)
    }
}

pub struct FakeTcpServer {
    local_port: u16,
}

impl FakeTcpServer {
    pub fn new(local_port: u16) -> Self {
        Self {
            local_port,
        }
    }

    pub async fn bind(&self, config: KcpConfig) -> Result<KcpListener, String> {
        apply_iptables_drop(self.local_port);
        let kcp_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let kcp_listener = KcpListener::bind(kcp_addr, config).await.map_err(|e| e.to_string())?;
        let kcp_local_udp = *kcp_listener.local_addr();

        let (mut tx, mut rx) = transport_channel(65535, TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)).unwrap();
        
        let local_port = self.local_port;
        let clients = Arc::new(Mutex::new(HashMap::<SocketAddrV4, Arc<UdpSocket>>::new()));
        
        let tx_mutex = Arc::new(Mutex::new(tx));
        
        let clients_clone = clients.clone();
        let tx_clone = tx_mutex.clone();
        
        tokio::spawn(async move {
            let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);
            loop {
                if let Ok((ipv4, _)) = iter.next() {
                    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            if tcp.get_destination() == local_port {
                                let payload = tcp.payload();
                                if !payload.is_empty() {
                                    let remote_addr = SocketAddrV4::new(ipv4.get_source(), tcp.get_source());
                                    let dst_ip = ipv4.get_destination();
                                    
                                    let mut clients_map = clients_clone.lock().await;
                                    let udp = if let Some(u) = clients_map.get(&remote_addr) {
                                        u.clone()
                                    } else {
                                        // New NAT mapping!
                                        let new_udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                                        new_udp.connect(kcp_local_udp).await.unwrap();
                                        clients_map.insert(remote_addr, new_udp.clone());
                                        
                                        // Start reverse loop for this client
                                        let reverse_udp = new_udp.clone();
                                        let reverse_tx = tx_clone.clone();
                                        tokio::spawn(async move {
                                            let mut buf = [0u8; MTU];
                                            let mut seq = 1000u32;
                                            loop {
                                                if let Ok(n) = reverse_udp.recv(&mut buf).await {
                                                    let mut ip_buffer = vec![0u8; 40 + n];
                                                    {
                                                        let mut t = MutableTcpPacket::new(&mut ip_buffer[20..]).unwrap();
                                                        t.set_source(local_port);
                                                        t.set_destination(remote_addr.port());
                                                        t.set_sequence(seq);
                                                        t.set_acknowledgement(1000);
                                                        t.set_data_offset(5);
                                                        t.set_flags(TcpFlags::PSH | TcpFlags::ACK);
                                                        t.set_window(65535);
                                                        t.set_payload(&buf[..n]);
                                                        t.set_checksum(ipv4_checksum(&t.to_immutable(), &dst_ip, remote_addr.ip()));
                                                    }
                                                    {
                                                        let mut i = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
                                                        i.set_version(4);
                                                        i.set_header_length(5);
                                                        i.set_total_length((40 + n) as u16);
                                                        i.set_ttl(64);
                                                        i.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                                                        i.set_source(dst_ip);
                                                        i.set_destination(*remote_addr.ip());
                                                        i.set_checksum(pnet::packet::ipv4::checksum(&i.to_immutable()));
                                                        seq = seq.wrapping_add(n as u32);
                                                        let mut tx_guard = reverse_tx.lock().await;
                                                        let _ = tx_guard.send_to(i, std::net::IpAddr::V4(*remote_addr.ip()));
                                                    }
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
