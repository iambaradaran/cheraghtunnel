use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use rand::Rng;
use sha2::{Sha256, Digest};

// Packet types for our custom reliable UDP layer
const PKT_SYN: u8 = 1;
const PKT_SYN_ACK: u8 = 2;
const PKT_DATA: u8 = 3;
const PKT_ACK: u8 = 4;
const PKT_FIN: u8 = 5;

async fn send_msg(socket: &UdpSocket, data: &[u8], peer: SocketAddr) -> io::Result<()> {
    match socket.send(data).await {
        Ok(_) => Ok(()),
        Err(_) => socket.send_to(data, peer).await.map(|_| ()),
    }
}

// Attempt to send synchronously to avoid Tokio scheduler task-spawning overhead.
// Falls back to an async tokio::spawn send only if the OS send buffer is full (WouldBlock).
fn try_send_msg(socket: &Arc<UdpSocket>, data: &[u8], peer: SocketAddr) -> io::Result<()> {
    match socket.try_send(data) {
        Ok(_) => Ok(()),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
            let socket_clone = socket.clone();
            let data_vec = data.to_vec();
            tokio::spawn(async move {
                let _ = send_msg(&socket_clone, &data_vec, peer).await;
            });
            Ok(())
        }
        Err(_) => {
            match socket.try_send_to(data, peer) {
                Ok(_) => Ok(()),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let socket_clone = socket.clone();
                    let data_vec = data.to_vec();
                    tokio::spawn(async move {
                        let _ = send_msg(&socket_clone, &data_vec, peer).await;
                    });
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }
}

// Protocol styles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpMode {
    Ray,       // Raw best-effort UDP
    Flash,     // Reliable sliding-window UDP
    Photon,    // Reliable UDP + FEC
    Halo,      // Reliable UDP + WebRTC/STUN framing
    Pulsar,    // High-speed paced reliable UDP
    Lantern,   // Reliable UDP + L3/TUN IP packet framing
    Oracle,    // Reliable UDP + DNS EDNS0 masquerading
    Vortex,    // Reliable UDP + Source Engine Query masquerading
}

#[allow(dead_code)]
struct SentPacket {
    seq: u32,
    data: Vec<u8>,
    sent_time: Instant,
    retries: u32,
}

struct FecEncoder {
    packet_counter: usize,
    buffer: Vec<Vec<u8>>,
}

impl FecEncoder {
    fn new() -> Self {
        Self {
            packet_counter: 0,
            buffer: Vec::new(),
        }
    }

    fn add_packet(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        // Prepend 2-byte big-endian length to avoid data corruption on variable-sized payloads
        let mut pkt_with_len = Vec::with_capacity(2 + data.len());
        pkt_with_len.extend_from_slice(&(data.len() as u16).to_be_bytes());
        pkt_with_len.extend_from_slice(data);

        self.buffer.push(pkt_with_len);
        self.packet_counter += 1;
        if self.packet_counter >= 4 {
            let max_len = self.buffer.iter().map(|v| v.len()).max().unwrap_or(0);
            let mut parity = vec![0u8; max_len];
            for pkt in &self.buffer {
                for (p, &b) in parity.iter_mut().zip(pkt.iter()) {
                    *p ^= b;
                }
            }
            self.buffer.clear();
            self.packet_counter = 0;
            Some(parity)
        } else {
            None
        }
    }
}

struct FecDecoder {
    buffer: HashMap<u32, Vec<u8>>,
}

impl FecDecoder {
    fn new() -> Self {
        Self {
            buffer: HashMap::new(),
        }
    }

    fn add_and_recover(&mut self, seq: u32, data: &[u8]) -> Option<(u32, Vec<u8>)> {
        // For parity packets (seq % 5 == 4), the 2-byte length metadata is already XORed.
        // For data packets, we must format it by prepending the 2-byte payload length.
        let formatted = if seq % 5 == 4 {
            data.to_vec()
        } else {
            let mut buf = Vec::with_capacity(2 + data.len());
            buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
            buf.extend_from_slice(data);
            buf
        };

        self.buffer.insert(seq, formatted);
        let block_start = (seq / 5) * 5;
        let mut present = Vec::new();
        let mut missing = Vec::new();
        for i in 0..5 {
            let s = block_start + i;
            if self.buffer.contains_key(&s) {
                present.push(s);
            } else {
                missing.push(s);
            }
        }

        if missing.len() == 1 {
            let missing_seq = missing[0];
            // Recovering the parity packet itself is useless, we only want to recover data packets
            if missing_seq % 5 == 4 {
                return None;
            }

            let max_len = present.iter().map(|s| self.buffer.get(s).unwrap().len()).max().unwrap_or(0);
            let mut recovered_raw = vec![0u8; max_len];
            for s in &present {
                let pkt = self.buffer.get(s).unwrap();
                for (p, &b) in recovered_raw.iter_mut().zip(pkt.iter()) {
                    *p ^= b;
                }
            }

            if recovered_raw.len() < 2 {
                return None;
            }

            // Extract the original length from the first 2 bytes and truncate padding junk
            let original_len = u16::from_be_bytes([recovered_raw[0], recovered_raw[1]]) as usize;
            if recovered_raw.len() < 2 + original_len {
                return None;
            }
            let recovered_payload = recovered_raw[2..2 + original_len].to_vec();

            // Insert recovered raw packet into buffer for potential future recoveries
            self.buffer.insert(missing_seq, recovered_raw);
            Some((missing_seq, recovered_payload))
        } else {
            None
        }
    }

    fn clean_old(&mut self, current_seq: u32) {
        if current_seq > 50 {
            let limit = current_seq - 50;
            self.buffer.retain(|&k, _| k >= limit);
        }
    }
}

pub struct UdpVirtualStreamInner {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mode: UdpMode,
    
    pub handshake_done: bool,
    
    rx_buf: VecDeque<u8>,
    rx_waker: Option<Waker>,
    next_expected_seq: u32,
    rx_out_of_order: HashMap<u32, Vec<u8>>,
    fec_decoder: FecDecoder,
    token: String,
    is_server: bool,
    
    tx_waker: Option<Waker>,
    next_seq: u32,
    last_acked_seq: u32,
    unacked_packets: std::collections::BTreeMap<u32, SentPacket>,
    fec_encoder: FecEncoder,
    
    is_closed: bool,
    
    last_sent_time: Instant,
    tokens: f64,
    max_tokens: f64,
    pacing_rate: f64,

    // Dynamic RTT/RTO tracking (RFC 6298)
    srtt_ms: f64,
    rttvar_ms: f64,
    rto_ms: u64,
}

pub struct UdpVirtualStream {
    pub inner: Arc<Mutex<UdpVirtualStreamInner>>,
    pub manager_handle: Option<tokio::task::JoinHandle<()>>,
    pub recv_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for UdpVirtualStream {
    fn drop(&mut self) {
        if let Some(h) = self.manager_handle.take() {
            h.abort();
        }
        if let Some(h) = self.recv_handle.take() {
            h.abort();
        }
    }
}

impl UdpVirtualStream {
    pub fn new(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        mode: UdpMode,
        rx: mpsc::Receiver<Vec<u8>>,
        handshake_done: bool,
        is_server: bool,
        token: &str,
    ) -> Self {
        let inner = Arc::new(Mutex::new(UdpVirtualStreamInner {
            socket,
            peer,
            mode,
            handshake_done,
            is_server,
            rx_buf: VecDeque::new(),
            rx_waker: None,
            next_expected_seq: 0,
            rx_out_of_order: HashMap::new(),
            fec_decoder: FecDecoder::new(),
            token: token.to_string(),
            tx_waker: None,
            next_seq: 0,
            last_acked_seq: 0,
            unacked_packets: std::collections::BTreeMap::new(),
            fec_encoder: FecEncoder::new(),
            is_closed: false,
            last_sent_time: Instant::now(),
            tokens: 10000.0,
            max_tokens: 10000.0,
            pacing_rate: {
                if let Ok(val) = std::env::var("PULSAR_MBPS") {
                    if let Ok(mbps) = val.parse::<f64>() {
                        (mbps * 1_000_000.0 / 12_000.0).max(100.0)
                    } else {
                        50000.0 // Default to ~600 Mbps limit
                    }
                } else {
                    50000.0 // Default to ~600 Mbps limit
                }
            },
            srtt_ms: 100.0,
            rttvar_ms: 50.0,
            rto_ms: 200,
        }));

        let inner_clone = inner.clone();
        let manager_handle = tokio::spawn(async move {
            Self::manager_loop(inner_clone, rx).await;
        });

        Self {
            inner,
            manager_handle: Some(manager_handle),
            recv_handle: None,
        }
    }

    async fn manager_loop(inner: Arc<Mutex<UdpVirtualStreamInner>>, mut rx: mpsc::Receiver<Vec<u8>>) {
        let mut interval = tokio::time::interval(Duration::from_millis(15));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let mut lock = inner.lock().await;
                    if lock.is_closed {
                        break;
                    }
                    if lock.mode != UdpMode::Ray {
                        lock.handle_retransmissions().await;
                    }
                }
                pkt_opt = rx.recv() => {
                    match pkt_opt {
                        Some(pkt) => {
                            let mut lock = inner.lock().await;
                            lock.process_packet(&pkt).await;
                        }
                        None => {
                            let mut lock = inner.lock().await;
                            lock.is_closed = true;
                            if let Some(w) = lock.rx_waker.take() {
                                w.wake();
                            }
                            if let Some(w) = lock.tx_waker.take() {
                                w.wake();
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
}

impl UdpVirtualStreamInner {
    /// Derives a 32-byte key from the user token using SHA256.
    fn derive_key(&self) -> [u8; 32] {
        let digest = Sha256::digest(self.token.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        key
    }

    /// Computes the standard internet checksum for IPv4 headers.
    fn calculate_ip_checksum(&self, header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for i in (0..header.len()).step_by(2) {
            let word = u16::from_be_bytes([header[i], header[i + 1]]);
            sum += word as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// XOR-encrypts/decrypts `buf` in-place using a keystream derived from
    /// SHA256(key XOR seq_nonce). The nonce (4 bytes of seq) ensures every
    /// packet has a unique keystream, even if the payload is identical.
    /// Because XOR is symmetric, the same call encrypts and decrypts.
    fn crypt_buffer(&self, buf: &mut [u8], seq_nonce: u32) {
        let key = self.derive_key();

        // Build the 32-byte seed: key XOR (seq_nonce repeated)
        let nonce_bytes = seq_nonce.to_be_bytes();
        let mut seed = key;
        for (i, b) in seed.iter_mut().enumerate() {
            *b ^= nonce_bytes[i % 4];
        }

        // Generate keystream blocks of 32 bytes using SHA256 counter-mode
        let mut keystream = Vec::with_capacity(buf.len() + 32);
        let mut counter: u32 = 0;
        while keystream.len() < buf.len() {
            let mut block_input = seed;
            let counter_bytes = counter.to_be_bytes();
            for (i, b) in block_input[28..32].iter_mut().enumerate() {
                *b ^= counter_bytes[i];
            }
            let block = Sha256::digest(&block_input);
            keystream.extend_from_slice(&block);
            counter += 1;
        }

        // XOR in-place
        for (b, k) in buf.iter_mut().zip(keystream.iter()) {
            *b ^= k;
        }
    }

    fn frame_packet(&self, pkt_type: u8, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let mut raw = Vec::with_capacity(64 + payload.len());
        let mut rng = rand::thread_rng();
        let padding_len = rng.gen_range(16..128); // Dynamic random padding size

        if self.mode == UdpMode::Halo {
            // Halo (WebRTC/STUN Simulation):
            // [Message Type (2)] + [Message Length (2)] + [Magic Cookie (4)] + [Transaction ID (12)]
            
            // Build the unencrypted inner body
            let mut body = Vec::with_capacity(64 + payload.len());
            body.push(pkt_type); // Our custom type hidden inside
            body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            body.extend_from_slice(payload);
            
            // Bulk random padding
            let old_len = body.len();
            body.resize(old_len + padding_len, 0);
            rng.fill(&mut body[old_len..]);
            
            // Encrypt the body using seq as nonce!
            self.crypt_buffer(&mut body, seq);
            
            // Construct the perfect 20-byte STUN Header
            raw.extend_from_slice(&[0x00, 0x01]); // 1. STUN Binding Request
            raw.extend_from_slice(&(body.len() as u16).to_be_bytes()); // 2. Length of encrypted data
            raw.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // 3. Magic Cookie
            
            // 4. Transaction ID (12 bytes): We embed seq, ack, and 4 random bytes
            raw.extend_from_slice(&seq.to_be_bytes());
            raw.extend_from_slice(&ack.to_be_bytes());
            let mut rand_tx = [0u8; 4];
            rng.fill(&mut rand_tx);
            raw.extend_from_slice(&rand_tx);
            
            // 5. Append encrypted body
            raw.extend_from_slice(&body);
            return raw;
        }

        if self.mode == UdpMode::Lantern {
            // Lantern (TUN/IPsec encapsulation simulation):
            // [IPv4 Header (20 bytes)]
            // [UDP Header (8 bytes)]
            // [RUDP Payload (4 + encrypted_payload_len)]
            //   - seq (4 bytes, plaintext nonce)
            //   - encrypted[pkt_type(1) + ack(4) + payload_len(2) + payload + padding]
            
            // Build the unencrypted inner body first
            let mut body = Vec::with_capacity(64 + payload.len());
            body.push(pkt_type);
            body.extend_from_slice(&ack.to_be_bytes());
            body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            body.extend_from_slice(payload);
            
            // Bulk random padding generation
            let old_len = body.len();
            body.resize(old_len + padding_len, 0);
            rng.fill(&mut body[old_len..]);
            
            // Encrypt the body using seq as nonce
            self.crypt_buffer(&mut body, seq);
            
            // Now construct the full encapsulated packet
            let encrypted_payload_len = body.len();
            let total_ip_len = (20 + 8 + 4 + encrypted_payload_len) as u16;
            let total_udp_len = (8 + 4 + encrypted_payload_len) as u16;
            
            // 20-byte IP header
            let mut ip_hdr = vec![0u8; 20];
            ip_hdr[0] = 0x45; // Version 4, IHL 5
            ip_hdr[1] = 0x00; // DSCP / ECN
            ip_hdr[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
            ip_hdr[4..6].copy_from_slice(&[0x12, 0x34]); // Identification
            ip_hdr[6..8].copy_from_slice(&[0x40, 0x00]); // Don't Fragment flag
            ip_hdr[8] = 64; // TTL
            ip_hdr[9] = 17; // Protocol (UDP)
            // Source & Destination IP addresses (simulating internal corporate subnet)
            ip_hdr[12..16].copy_from_slice(&[10, 0, 0, 1]);
            ip_hdr[16..20].copy_from_slice(&[10, 0, 0, 2]);
            
            // Calculate and write the IP checksum
            let ip_chk = self.calculate_ip_checksum(&ip_hdr);
            ip_hdr[10..12].copy_from_slice(&ip_chk.to_be_bytes());
            
            // 8-byte UDP header (mimicking IPsec NAT-T on port 4500)
            let mut udp_hdr = vec![0u8; 8];
            udp_hdr[0..2].copy_from_slice(&[0x11, 0x94]); // Src Port = 4500
            udp_hdr[2..4].copy_from_slice(&[0x11, 0x94]); // Dest Port = 4500
            udp_hdr[4..6].copy_from_slice(&total_udp_len.to_be_bytes());
            // Checksum left as 0x0000 (valid / disabled in IPv4 UDP)
            
            raw.extend_from_slice(&ip_hdr);
            raw.extend_from_slice(&udp_hdr);
            raw.extend_from_slice(&seq.to_be_bytes()); // plaintext seq (nonce)
            raw.extend_from_slice(&body); // encrypted body
            return raw;
        }

        if self.mode == UdpMode::Oracle {
            // Oracle (DNS EDNS0 Simulation):
            // DNS Header (12 bytes) + Question (25 bytes) + OPT pseudo-RR (11 bytes) + Option Header (4 bytes) + [seq (4)] + [encrypted body]
            
            // Build the unencrypted inner body first
            let mut body = Vec::with_capacity(64 + payload.len());
            body.push(pkt_type);
            body.extend_from_slice(&ack.to_be_bytes());
            body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            body.extend_from_slice(payload);
            
            // Random padding
            let old_len = body.len();
            body.resize(old_len + padding_len, 0);
            rng.fill(&mut body[old_len..]);
            
            // Encrypt using seq as nonce
            self.crypt_buffer(&mut body, seq);
            
            // Build DNS Header (12 bytes)
            let tx_id = rng.gen::<u16>();
            raw.extend_from_slice(&tx_id.to_be_bytes());
            
            if !self.is_server {
                raw.extend_from_slice(&[0x01, 0x00]); // Flags: Standard Query
            } else {
                raw.extend_from_slice(&[0x81, 0x80]); // Flags: Standard Query Response
            }
            
            raw.extend_from_slice(&[0x00, 0x01]); // Questions: 1
            raw.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
            raw.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
            raw.extend_from_slice(&[0x00, 0x01]); // Additional RRs: 1 (OPT RR)
            
            // Build Question Section for w.www.microsoft.com (25 bytes)
            raw.extend_from_slice(&[
                0x01, b'w',
                0x03, b'w', b'w', b'w',
                0x09, b'm', b'i', b'c', b'r', b'o', b's', b'o', b'f', b't',
                0x03, b'c', b'o', b'm',
                0x00 // Null terminator
            ]);
            raw.extend_from_slice(&[0x00, 0x10]); // Type: TXT (16)
            raw.extend_from_slice(&[0x00, 0x01]); // Class: IN (1)
            
            // OPT pseudo-RR (11 bytes + option header + option data)
            raw.push(0x00); // Name: Root
            raw.extend_from_slice(&[0x00, 0x29]); // Type: OPT (41)
            raw.extend_from_slice(&[0x10, 0x00]); // UDP Payload Size: 4096 bytes
            raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Extended RCODE / flags
            
            // Data Length = 4 (Option Code + Option Length) + 4 (seq) + encrypted_body_len
            let opt_data_len = (4 + 4 + body.len()) as u16;
            raw.extend_from_slice(&opt_data_len.to_be_bytes());
            
            // Option Code & Option Length (EDNS0 custom option)
            raw.extend_from_slice(&[0xff, 0xfe]); // Custom Option Code
            let opt_val_len = (4 + body.len()) as u16;
            raw.extend_from_slice(&opt_val_len.to_be_bytes());
            
            // OPT data value: seq + encrypted body
            raw.extend_from_slice(&seq.to_be_bytes());
            raw.extend_from_slice(&body);
            
            return raw;
        }

        if self.mode == UdpMode::Vortex {
            // Vortex (Source Engine Game Query Simulation):
            // Header (4 bytes 0xFFFFFFFF) + Type (1 byte 'T' or 'I') + Payload / Metadata + seq (4 bytes) + encrypted_body
            
            // Build the unencrypted inner body
            let mut body = Vec::with_capacity(64 + payload.len());
            body.push(pkt_type);
            body.extend_from_slice(&ack.to_be_bytes());
            body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            body.extend_from_slice(payload);
            
            // Random padding
            let old_len = body.len();
            body.resize(old_len + padding_len, 0);
            rng.fill(&mut body[old_len..]);
            
            // Encrypt using seq as nonce
            self.crypt_buffer(&mut body, seq);
            
            // Prefix 4 bytes: 0xFFFFFFFF
            raw.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
            
            if !self.is_server {
                // Client Request (A2S_INFO Request)
                raw.push(0x54); // 'T'
                raw.extend_from_slice(b"Source Engine Query\0"); // 20 bytes
            } else {
                // Server Response (A2S_INFO Response)
                raw.push(0x49); // 'I'
                raw.push(17); // Protocol version
                raw.extend_from_slice(b"Cheragh Server\0");
                raw.extend_from_slice(b"de_dust2\0");
                raw.extend_from_slice(b"csgo\0");
                raw.extend_from_slice(b"Counter-Strike\0");
                raw.extend_from_slice(&[0x00, 0x01]); // ID: 1
                raw.extend_from_slice(&[0, 20, 0]); // Players: 0, Max: 20, Bots: 0
                raw.push(b'd'); // Dedicated
                raw.push(b'l'); // Linux
                raw.push(0); // Password: No
                raw.push(1); // VAC: Yes
                raw.extend_from_slice(b"1.0.0.0\0");
                raw.push(0x80); // EDF
            }
            
            // Append seq (4 bytes) and encrypted body
            raw.extend_from_slice(&seq.to_be_bytes());
            raw.extend_from_slice(&body);
            return raw;
        }

        // Flash / Photon / Pulsar (Encrypted Reliable UDP):
        // [seq (4, plaintext)] + encrypt_with(seq)[pkt_type(1) + ack(4) + payload_len(2) + payload + padding]
        // The seq is left in plaintext so the receiver can derive the decryption nonce.
        // All remaining bytes are XOR-encrypted making the packet look like random noise.
        raw.extend_from_slice(&seq.to_be_bytes()); // 4 bytes plaintext nonce
        raw.push(pkt_type);
        raw.extend_from_slice(&ack.to_be_bytes());
        raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        raw.extend_from_slice(payload);
        
        // Bulk random padding generation
        let old_len = raw.len();
        raw.resize(old_len + padding_len, 0);
        rng.fill(&mut raw[old_len..]);

        // Encrypt everything after the 4-byte plaintext seq
        self.crypt_buffer(&mut raw[4..], seq);
        raw
    }

    fn deframe_packet(&self, raw: &[u8]) -> Option<(u8, u32, u32, Vec<u8>)> {
        if self.mode == UdpMode::Halo {
            if raw.len() < 20 {
                return None;
            }
            let msg_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
            if raw.len() < 20 + msg_len {
                return None;
            }
            let seq = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
            let ack = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]);
            
            // Decrypt the payload portion
            let mut decrypted = raw[20..20 + msg_len].to_vec();
            self.crypt_buffer(&mut decrypted, seq);
            
            if decrypted.len() < 3 {
                return None;
            }
            let pkt_type = decrypted[0];
            let payload_len = u16::from_be_bytes([decrypted[1], decrypted[2]]) as usize;
            if decrypted.len() < 3 + payload_len {
                return None;
            }
            let payload = decrypted[3..3 + payload_len].to_vec();
            
            return Some((pkt_type, seq, ack, payload));
        }

        if self.mode == UdpMode::Lantern {
            if raw.len() < 39 {
                return None;
            }
            let total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
            if raw.len() < total_len {
                return None;
            }
            let seq = u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]]);
            
            // Decrypt the payload portion
            let mut decrypted = raw[32..].to_vec();
            self.crypt_buffer(&mut decrypted, seq);
            
            if decrypted.len() < 7 {
                return None;
            }
            let pkt_type = decrypted[0];
            let ack = u32::from_be_bytes([decrypted[1], decrypted[2], decrypted[3], decrypted[4]]);
            let payload_len = u16::from_be_bytes([decrypted[5], decrypted[6]]) as usize;
            if decrypted.len() < 7 + payload_len {
                return None;
            }
            let payload = decrypted[7..7 + payload_len].to_vec();
            return Some((pkt_type, seq, ack, payload));
        }

        if self.mode == UdpMode::Oracle {
            if raw.len() < 56 {
                return None;
            }
            let seq = u32::from_be_bytes([raw[52], raw[53], raw[54], raw[55]]);
            
            // Decrypt the payload portion
            let mut decrypted = raw[56..].to_vec();
            self.crypt_buffer(&mut decrypted, seq);
            
            if decrypted.len() < 7 {
                return None;
            }
            let pkt_type = decrypted[0];
            let ack = u32::from_be_bytes([decrypted[1], decrypted[2], decrypted[3], decrypted[4]]);
            let payload_len = u16::from_be_bytes([decrypted[5], decrypted[6]]) as usize;
            if decrypted.len() < 7 + payload_len {
                return None;
            }
            let payload = decrypted[7..7 + payload_len].to_vec();
            return Some((pkt_type, seq, ack, payload));
        }

        if self.mode == UdpMode::Vortex {
            let offset = if self.is_server {
                25
            } else {
                68
            };
            
            if raw.len() < offset + 4 {
                return None;
            }
            let seq = u32::from_be_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
            ]);
            
            // Decrypt the payload portion
            let mut decrypted = raw[offset + 4..].to_vec();
            self.crypt_buffer(&mut decrypted, seq);
            
            if decrypted.len() < 7 {
                return None;
            }
            let pkt_type = decrypted[0];
            let ack = u32::from_be_bytes([decrypted[1], decrypted[2], decrypted[3], decrypted[4]]);
            let payload_len = u16::from_be_bytes([decrypted[5], decrypted[6]]) as usize;
            if decrypted.len() < 7 + payload_len {
                return None;
            }
            let payload = decrypted[7..7 + payload_len].to_vec();
            return Some((pkt_type, seq, ack, payload));
        }

        // Flash / Photon / Pulsar deframing (encrypted)
        // Format: [seq (4, plaintext)] + encrypt_with(seq)[pkt_type(1) + ack(4) + payload_len(2) + payload + padding]
        if raw.len() < 12 {
            return None;
        }
        let seq = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        // Decrypt the rest of the packet in-place
        let mut decrypted = raw[4..].to_vec();
        self.crypt_buffer(&mut decrypted, seq);
        // Now parse from decrypted bytes: [pkt_type(1)] + [ack(4)] + [payload_len(2)] + [payload]
        if decrypted.len() < 7 {
            return None;
        }
        let pkt_type = decrypted[0];
        let ack = u32::from_be_bytes([decrypted[1], decrypted[2], decrypted[3], decrypted[4]]);
        let payload_len = u16::from_be_bytes([decrypted[5], decrypted[6]]) as usize;
        if decrypted.len() < 7 + payload_len {
            return None;
        }
        let payload = decrypted[7..7 + payload_len].to_vec();
        Some((pkt_type, seq, ack, payload))
    }

    async fn send_packet_paced(&mut self, data: &[u8]) -> io::Result<()> {
        if self.mode == UdpMode::Pulsar {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last_sent_time).as_secs_f64();
            self.last_sent_time = now;
            self.tokens = (self.tokens + elapsed * self.pacing_rate).min(self.max_tokens);
            if self.tokens < 1.0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
                self.tokens += 0.001 * self.pacing_rate;
            }
            self.tokens -= 1.0;
        }

        // Apply Micro-jitter (Timing Shaper) to evade DPI statistical signature analysis
        if self.mode == UdpMode::Halo || self.mode == UdpMode::Lantern || self.mode == UdpMode::Oracle || self.mode == UdpMode::Vortex {
            let jitter_ms = {
                let mut rng = rand::thread_rng();
                if rng.gen_bool(0.15) {
                    Some(rng.gen_range(1..4))
                } else {
                    None
                }
            };
            if let Some(ms) = jitter_ms {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
        }

        send_msg(&self.socket, data, self.peer).await
    }

    async fn handle_retransmissions(&mut self) {
        let now = Instant::now();
        let mut to_resend = Vec::new();
        
        for pkt in self.unacked_packets.values_mut() {
            if now.duration_since(pkt.sent_time) > Duration::from_millis(self.rto_ms) {
                pkt.sent_time = now;
                pkt.retries += 1;
                to_resend.push(pkt.data.clone());
                
                // Exponential backoff for subsequent retries to avoid flooding a congested link
                if pkt.retries > 1 {
                    self.rto_ms = (self.rto_ms * 2).min(1000);
                }

                if pkt.retries > 30 {
                    self.is_closed = true;
                    if let Some(w) = self.rx_waker.take() { w.wake(); }
                    if let Some(w) = self.tx_waker.take() { w.wake(); }
                    return;
                }
            }
        }

        for data in to_resend {
            let _ = self.send_packet_paced(&data).await;
        }
    }

    async fn process_packet(&mut self, raw: &[u8]) {
        if self.mode == UdpMode::Ray {
            if !self.handshake_done {
                // First packet for a Ray session must be the 4-byte magic token prefix.
                // Server verifies this before routing any data to rx_buf.
                // Client sets handshake_done=true immediately after sending magic,
                // so server replies flow to rx_buf on client side too.
                let key = self.derive_key();
                if raw.len() >= 4 && raw[..4] == key[..4] {
                    self.handshake_done = true;
                }
                // Do NOT forward the magic handshake packet to rx_buf.
                return;
            }
            self.rx_buf.extend(raw);
            if let Some(w) = self.rx_waker.take() {
                w.wake();
            }
            return;
        }

        let (pkt_type, seq, ack, payload) = match self.deframe_packet(raw) {
            Some(res) => res,
            None => return,
        };

        let now = Instant::now();
        if let Some(pkt) = self.unacked_packets.get(&ack) {
            if pkt.retries == 0 {
                let rtt_sample = now.duration_since(pkt.sent_time).as_secs_f64() * 1000.0;
                self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * (self.srtt_ms - rtt_sample).abs();
                self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * rtt_sample;
                let calculated_rto = (self.srtt_ms + (4.0 * self.rttvar_ms).max(15.0)) as u64;
                self.rto_ms = calculated_rto.clamp(50, 1000);
            }
        }

        while let Some(&seq) = self.unacked_packets.keys().next() {
            if seq <= ack {
                self.unacked_packets.pop_first();
            } else {
                break;
            }
        }
        self.last_acked_seq = self.last_acked_seq.max(ack);
        if let Some(w) = self.tx_waker.take() {
            w.wake();
        }

        match pkt_type {
            PKT_SYN => {
                let resp = self.frame_packet(PKT_SYN_ACK, 0, 0, &[]);
                let _ = send_msg(&self.socket, &resp, self.peer).await;
            }
            PKT_SYN_ACK => {
                self.handshake_done = true;
            }
            PKT_DATA => {
                if seq < self.next_expected_seq {
                    self.send_ack().await;
                    return;
                }

                if seq == self.next_expected_seq {
                    // Feed to fec_decoder first (for Photon mode) to avoid decoder starvation
                    if self.mode == UdpMode::Photon {
                        self.fec_decoder.clean_old(seq);
                        let _ = self.fec_decoder.add_and_recover(seq, &payload);
                    }

                    self.rx_buf.extend(&payload);
                    self.next_expected_seq += 1;
                    if self.mode == UdpMode::Photon {
                        while self.next_expected_seq % 5 == 4 {
                            self.next_expected_seq += 1;
                        }
                    }

                    while let Some(buffered) = self.rx_out_of_order.remove(&self.next_expected_seq) {
                        self.rx_buf.extend(&buffered);
                        self.next_expected_seq += 1;
                        if self.mode == UdpMode::Photon {
                            while self.next_expected_seq % 5 == 4 {
                                self.next_expected_seq += 1;
                            }
                        }
                    }

                    self.send_ack().await;
                    if let Some(w) = self.rx_waker.take() {
                        w.wake();
                    }
                } else if seq < self.next_expected_seq + 64 {
                    if self.mode == UdpMode::Photon {
                        self.fec_decoder.clean_old(seq);
                        if seq % 5 == 4 {
                            // Parity packet: feed to fec_decoder only, do NOT add to rx_out_of_order
                            if let Some((recovered_seq, recovered_data)) = self.fec_decoder.add_and_recover(seq, &payload) {
                                if recovered_seq == self.next_expected_seq {
                                    self.rx_buf.extend(&recovered_data);
                                    self.next_expected_seq += 1;
                                    while self.next_expected_seq % 5 == 4 {
                                        self.next_expected_seq += 1;
                                    }
                                    while let Some(buffered) = self.rx_out_of_order.remove(&self.next_expected_seq) {
                                        self.rx_buf.extend(&buffered);
                                        self.next_expected_seq += 1;
                                        while self.next_expected_seq % 5 == 4 {
                                            self.next_expected_seq += 1;
                                        }
                                    }
                                    if let Some(w) = self.rx_waker.take() {
                                        w.wake();
                                    }
                                } else {
                                    self.rx_out_of_order.insert(recovered_seq, recovered_data);
                                }
                            }
                        } else {
                            // Data packet: insert to rx_out_of_order and feed to fec_decoder
                            self.rx_out_of_order.insert(seq, payload.clone());
                            if let Some((recovered_seq, recovered_data)) = self.fec_decoder.add_and_recover(seq, &payload) {
                                if recovered_seq == self.next_expected_seq {
                                    self.rx_buf.extend(&recovered_data);
                                    self.next_expected_seq += 1;
                                    while self.next_expected_seq % 5 == 4 {
                                        self.next_expected_seq += 1;
                                    }
                                    while let Some(buffered) = self.rx_out_of_order.remove(&self.next_expected_seq) {
                                        self.rx_buf.extend(&buffered);
                                        self.next_expected_seq += 1;
                                        while self.next_expected_seq % 5 == 4 {
                                            self.next_expected_seq += 1;
                                        }
                                    }
                                    if let Some(w) = self.rx_waker.take() {
                                        w.wake();
                                    }
                                } else {
                                    self.rx_out_of_order.insert(recovered_seq, recovered_data);
                                }
                            }
                        }
                    } else {
                        // Non-Photon mode: regular out-of-order data packet
                        self.rx_out_of_order.insert(seq, payload.clone());
                    }
                    self.send_ack().await;
                }
            }
            PKT_ACK => {
                // Parse SACK sequence numbers from payload (4 bytes per seq)
                let mut sacks = Vec::new();
                let mut chunk = payload.as_slice();
                while chunk.len() >= 4 {
                    let s = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    sacks.push(s);
                    chunk = &chunk[4..];
                }

                // Mark SACKed packets as acknowledged (remove from unacked)
                for seq in &sacks {
                    self.unacked_packets.remove(seq);
                }

                // Fast Retransmit:
                // If there are packets in unacked_packets that are older (seq < max_sack)
                // and have not been SACKed, they are likely lost. We immediately retransmit them.
                if let Some(&max_sack) = sacks.iter().max() {
                    let mut to_fast_retransmit = Vec::new();
                    for (&seq, pkt) in &mut self.unacked_packets {
                        if seq < max_sack && !sacks.contains(&seq) {
                            pkt.sent_time = Instant::now() - Duration::from_millis(self.rto_ms + 1); // Force immediate retry
                            pkt.retries += 1;
                            to_fast_retransmit.push(pkt.data.clone());
                        }
                    }
                    for data in to_fast_retransmit {
                        let _ = self.send_packet_paced(&data).await;
                    }
                }
            }
            PKT_FIN => {
                self.is_closed = true;
                if let Some(w) = self.rx_waker.take() {
                    w.wake();
                }
            }
            _ => {}
        }
    }

    async fn send_ack(&mut self) {
        let ack_val = if self.next_expected_seq == 0 {
            0
        } else {
            self.next_expected_seq - 1
        };

        // Populate SACK: up to 8 out-of-order sequence numbers to notify the sender
        let mut sack_payload = Vec::new();
        if !self.rx_out_of_order.is_empty() && self.mode != UdpMode::Ray {
            let mut keys: Vec<u32> = self.rx_out_of_order.keys().copied().collect();
            keys.sort_unstable();
            for &seq in keys.iter().take(8) {
                sack_payload.extend_from_slice(&seq.to_be_bytes());
            }
        }

        let ack_pkt = self.frame_packet(PKT_ACK, 0, ack_val, &sack_payload);
        let _ = send_msg(&self.socket, &ack_pkt, self.peer).await;
    }

    pub async fn send_syn(&mut self) {
        let syn_pkt = self.frame_packet(PKT_SYN, 0, 0, &[]);
        let _ = send_msg(&self.socket, &syn_pkt, self.peer).await;
    }

    #[allow(dead_code)]
    pub async fn send_fin(&mut self) {
        let fin_pkt = self.frame_packet(PKT_FIN, 0, 0, &[]);
        let _ = send_msg(&self.socket, &fin_pkt, self.peer).await;
    }
}

impl AsyncRead for UdpVirtualStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut inner = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if !inner.rx_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), inner.rx_buf.len());
            for _ in 0..n {
                if let Some(b) = inner.rx_buf.pop_front() {
                    buf.put_slice(&[b]);
                }
            }
            return Poll::Ready(Ok(()));
        }

        if inner.is_closed {
            return Poll::Ready(Ok(()));
        }

        inner.rx_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for UdpVirtualStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if inner.is_closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "Stream closed")));
        }

        if inner.mode == UdpMode::Ray {
            let socket = inner.socket.clone();
            let peer = inner.peer;
            let _ = try_send_msg(&socket, buf, peer);
            return Poll::Ready(Ok(buf.len()));
        }

        if inner.next_seq - inner.last_acked_seq > 64 {
            inner.tx_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let seq = inner.next_seq;
        inner.next_seq += 1;

        let ack_val = if inner.next_expected_seq == 0 {
            0
        } else {
            inner.next_expected_seq - 1
        };

        let framed = inner.frame_packet(PKT_DATA, seq, ack_val, buf);
        let socket = inner.socket.clone();
        let peer = inner.peer;
        let framed_clone = framed.clone();

        inner.unacked_packets.insert(seq, SentPacket {
            seq,
            data: framed,
            sent_time: Instant::now(),
            retries: 0,
        });

        if inner.mode == UdpMode::Photon {
            if let Some(parity) = inner.fec_encoder.add_packet(buf) {
                let parity_seq = inner.next_seq;
                inner.next_seq += 1;
                let parity_framed = inner.frame_packet(PKT_DATA, parity_seq, ack_val, &parity);
                let socket_fec = socket.clone();
                let _ = try_send_msg(&socket_fec, &parity_framed, peer);
            }
        }

        if inner.mode == UdpMode::Pulsar {
            let now = Instant::now();
            let elapsed = now.duration_since(inner.last_sent_time).as_secs_f64();
            inner.last_sent_time = now;
            inner.tokens = (inner.tokens + elapsed * inner.pacing_rate).min(inner.max_tokens);

            if inner.tokens < 1.0 {
                // Fallback: if we exceed pacing rate, spawn task to sleep-and-send
                let socket_clone = socket.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    let _ = send_msg(&socket_clone, &framed_clone, peer).await;
                });
            } else {
                inner.tokens -= 1.0;
                let _ = try_send_msg(&socket, &framed_clone, peer);
            }
        } else {
            // Flash / Photon / Halo / Lantern: send synchronously without spawning task
            let _ = try_send_msg(&socket, &framed_clone, peer);
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if inner.is_closed {
            return Poll::Ready(Ok(()));
        }

        inner.is_closed = true;
        let socket = inner.socket.clone();
        let peer = inner.peer;
        let fin_pkt = inner.frame_packet(PKT_FIN, 0, 0, &[]);

        let _ = try_send_msg(&socket, &fin_pkt, peer);

        Poll::Ready(Ok(()))
    }
}

#[allow(dead_code)]
pub struct UdpMultiplexer {
    socket: Arc<UdpSocket>,
    sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
}

impl UdpMultiplexer {
    pub fn new(socket: UdpSocket, mode: UdpMode, new_conn_tx: mpsc::Sender<UdpVirtualStream>, token: String) -> Self {
        let socket = Arc::new(socket);
        let sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
        
        let socket_clone = socket.clone();
        let sessions_clone = sessions.clone();
        let token_clone = token.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket_clone.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        let data = buf[..n].to_vec();
                        let mut map = sessions_clone.lock().await;
                        
                        if let Some(tx) = map.get(&addr) {
                            if tx.send(data).await.is_err() {
                                map.remove(&addr);
                            }
                        } else {
                            // Determine whether this first packet from a new peer should open a session.
                            // For encrypted modes (Flash/Photon/Pulsar), we cannot inspect pkt_type
                            // directly — instead we accept any first packet and let the handshake check
                            // reject illegitimate clients.
                            let is_syn = if mode == UdpMode::Ray {
                                // Ray sessions are opened on any first packet from a new peer.
                                // Authentication is enforced in process_packet: no data reaches
                                // rx_buf until the 4-byte SHA256(token) magic prefix is verified.
                                true
                            } else {
                                match mode {
                                    // Flash / Photon / Pulsar / Lantern / Halo: fully encrypted — accept and let handshake check decide
                                    _ => data.len() >= 12,
                                }
                            };

                            if is_syn {
                                let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
                                map.insert(addr, tx);
                                
                                let virtual_stream = UdpVirtualStream::new(
                                    socket_clone.clone(),
                                    addr,
                                    mode,
                                    rx,
                                    false,
                                    true, // is_server
                                    &token_clone
                                );
                                
                                let _ = map.get(&addr).unwrap().send(data).await;
                                
                                if new_conn_tx.send(virtual_stream).await.is_err() {
                                    map.remove(&addr);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[UDP Multiplexer] Demux error: {}", e);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        });

        Self { socket, sessions }
    }

    #[allow(dead_code)]
    pub async fn create_session(
        &self,
        peer: SocketAddr,
        mode: UdpMode,
        handshake_done: bool,
    ) -> UdpVirtualStream {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        let mut map = self.sessions.lock().await;
        map.insert(peer, tx);
        
        UdpVirtualStream::new(self.socket.clone(), peer, mode, rx, handshake_done, true, "")
    }

    #[allow(dead_code)]
    pub async fn remove_session(&self, peer: &SocketAddr) {
        let mut map = self.sessions.lock().await;
        map.remove(peer);
    }
}
