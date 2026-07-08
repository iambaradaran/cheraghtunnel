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
    Hysteria,  // High-speed paced reliable UDP
    Lantern,   // Reliable UDP + L3/TUN IP packet framing
}

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
                for (i, &b) in pkt.iter().enumerate() {
                    if i < parity.len() {
                        parity[i] ^= b;
                    }
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
                for (i, &b) in pkt.iter().enumerate() {
                    if i < recovered_raw.len() {
                        recovered_raw[i] ^= b;
                    }
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
    
    tx_waker: Option<Waker>,
    next_seq: u32,
    last_acked_seq: u32,
    unacked_packets: VecDeque<SentPacket>,
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
    ) -> Self {
        let inner = Arc::new(Mutex::new(UdpVirtualStreamInner {
            socket,
            peer,
            mode,
            handshake_done,
            rx_buf: VecDeque::new(),
            rx_waker: None,
            next_expected_seq: 0,
            rx_out_of_order: HashMap::new(),
            fec_decoder: FecDecoder::new(),
            tx_waker: None,
            next_seq: 0,
            last_acked_seq: 0,
            unacked_packets: VecDeque::new(),
            fec_encoder: FecEncoder::new(),
            is_closed: false,
            last_sent_time: Instant::now(),
            tokens: 10000.0,
            max_tokens: 10000.0,
            pacing_rate: {
                if let Ok(val) = std::env::var("HYSTERIA_MBPS") {
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
    fn frame_packet(&self, pkt_type: u8, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let mut raw = Vec::with_capacity(64 + payload.len());
        let mut rng = rand::thread_rng();
        let padding_len = rng.gen_range(16..128); // Dynamic random padding size

        if self.mode == UdpMode::Halo {
            // Halo (WebRTC Signature): 
            // [0x00] + [pkt_type] + [payload_len (2)] + [STUN Magic (4)] + [seq (4)] + [ack (4)] + [payload] + [padding]
            raw.extend_from_slice(&[0x00, pkt_type]);
            raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            raw.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
            raw.extend_from_slice(&seq.to_be_bytes());
            raw.extend_from_slice(&ack.to_be_bytes());
            raw.extend_from_slice(payload);
            
            // Bulk random padding generation
            let old_len = raw.len();
            raw.resize(old_len + padding_len, 0);
            rng.fill(&mut raw[old_len..]);
            return raw;
        }

        if self.mode == UdpMode::Lantern {
            // Lantern (TUN Signature): IP header + [pkt_type] + [seq (4)] + [ack (4)] + [payload_len (2)] + [payload] + [padding]
            // Calculate Total IP Packet Length
            let total_len = (20 + 9 + 2 + payload.len() + padding_len) as u16;
            raw.extend_from_slice(&[0x45, 0x00]);
            raw.extend_from_slice(&total_len.to_be_bytes());
            raw.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00]);
            raw.extend_from_slice(&[10, 0, 0, 1]);
            raw.extend_from_slice(&[10, 0, 0, 2]);
            raw.push(pkt_type);
            raw.extend_from_slice(&seq.to_be_bytes());
            raw.extend_from_slice(&ack.to_be_bytes());
            raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            raw.extend_from_slice(payload);
            
            // Bulk random padding generation
            let old_len = raw.len();
            raw.resize(old_len + padding_len, 0);
            rng.fill(&mut raw[old_len..]);
            return raw;
        }

        // Flash / Photon / Hysteria (Obfuscated Reliable UDP):
        // [pkt_type] + [seq (4)] + [ack (4)] + [payload_len (2)] + [payload] + [padding]
        raw.push(pkt_type);
        raw.extend_from_slice(&seq.to_be_bytes());
        raw.extend_from_slice(&ack.to_be_bytes());
        raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        raw.extend_from_slice(payload);
        
        // Bulk random padding generation
        let old_len = raw.len();
        raw.resize(old_len + padding_len, 0);
        rng.fill(&mut raw[old_len..]);
        raw
    }

    fn deframe_packet(&self, raw: &[u8]) -> Option<(u8, u32, u32, Vec<u8>)> {
        if self.mode == UdpMode::Halo {
            if raw.len() < 16 {
                return None;
            }
            let pkt_type = raw[1];
            let payload_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
            let seq = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
            let ack = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]);
            if raw.len() < 16 + payload_len {
                return None;
            }
            let payload = raw[16..16 + payload_len].to_vec();
            return Some((pkt_type, seq, ack, payload));
        }

        if self.mode == UdpMode::Lantern {
            if raw.len() < 31 {
                return None;
            }
            let total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
            if raw.len() < total_len {
                return None;
            }
            let pkt_type = raw[20];
            let seq = u32::from_be_bytes([raw[21], raw[22], raw[23], raw[24]]);
            let ack = u32::from_be_bytes([raw[25], raw[26], raw[27], raw[28]]);
            let payload_len = u16::from_be_bytes([raw[29], raw[30]]) as usize;
            if raw.len() < 31 + payload_len {
                return None;
            }
            let payload = raw[31..31 + payload_len].to_vec();
            return Some((pkt_type, seq, ack, payload));
        }

        // Flash / Photon / Hysteria deframing
        if raw.len() < 11 {
            return None;
        }
        let pkt_type = raw[0];
        let seq = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]);
        let ack = u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]);
        let payload_len = u16::from_be_bytes([raw[9], raw[10]]) as usize;
        if raw.len() < 11 + payload_len {
            return None;
        }
        let payload = raw[11..11 + payload_len].to_vec();
        Some((pkt_type, seq, ack, payload))
    }

    async fn send_packet_paced(&mut self, data: &[u8]) -> io::Result<()> {
        if self.mode == UdpMode::Hysteria {
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
        if self.mode == UdpMode::Halo || self.mode == UdpMode::Lantern {
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
        
        for pkt in &mut self.unacked_packets {
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

        // Smoothed RTT estimation (RFC 6298 with Karn's algorithm)
        let now = Instant::now();
        for pkt in &self.unacked_packets {
            if pkt.seq == ack {
                if pkt.retries == 0 {
                    let rtt_sample = now.duration_since(pkt.sent_time).as_secs_f64() * 1000.0;
                    self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * (self.srtt_ms - rtt_sample).abs();
                    self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * rtt_sample;
                    let calculated_rto = (self.srtt_ms + (4.0 * self.rttvar_ms).max(15.0)) as u64;
                    self.rto_ms = calculated_rto.clamp(50, 1000);
                }
                break;
            }
        }

        while let Some(pkt) = self.unacked_packets.front() {
            if pkt.seq <= ack {
                self.unacked_packets.pop_front();
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
                // Queue clean handled above
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
        let ack_pkt = self.frame_packet(PKT_ACK, 0, ack_val, &[]);
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

        inner.unacked_packets.push_back(SentPacket {
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

        if inner.mode == UdpMode::Hysteria {
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
    pub fn new(socket: UdpSocket, mode: UdpMode, new_conn_tx: mpsc::Sender<UdpVirtualStream>) -> Self {
        let socket = Arc::new(socket);
        let sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
        
        let socket_clone = socket.clone();
        let sessions_clone = sessions.clone();
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
                            let is_syn = if mode == UdpMode::Ray {
                                true
                            } else {
                                let pkt_type = match mode {
                                    UdpMode::Halo => data.get(1).copied(),
                                    UdpMode::Lantern => data.get(20).copied(),
                                    _ => data.first().copied(),
                                };
                                pkt_type.map(|b| b == PKT_SYN).unwrap_or(false)
                            };

                            if is_syn {
                                let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
                                map.insert(addr, tx);
                                
                                let virtual_stream = UdpVirtualStream::new(
                                    socket_clone.clone(),
                                    addr,
                                    mode,
                                    rx,
                                    false
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
        
        UdpVirtualStream::new(self.socket.clone(), peer, mode, rx, handshake_done)
    }

    #[allow(dead_code)]
    pub async fn remove_session(&self, peer: &SocketAddr) {
        let mut map = self.sessions.lock().await;
        map.remove(peer);
    }
}
