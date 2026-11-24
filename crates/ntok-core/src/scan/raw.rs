//! Raw-packet scan techniques via `pnet` (`privileged` feature), mirroring
//! nmap's flag scans: SYN (-sS), ACK (-sA), FIN (-sF), NULL (-sN), Xmas (-sX).
//! Requires Npcap on Windows or root/`CAP_NET_RAW` on Unix.
//!
//! The channel is Layer3 so replies carry their IP header — the TTL feeds the
//! crude OS hint returned alongside the port results.
//!
//! shortcut: replies are classified TCP-only; ICMP unreachable packets are not
//! correlated, so a filtered port reports "no-response" rather than
//! "admin-prohibited". The verdict is the same — upgrade by adding a parallel
//! ICMP channel if the reason string matters.
//! shortcut: IPv4 only; IPv6 targets return filtered. Upgrade by opening a
//! second `TransportProtocol::Ipv6` channel.

use crate::error::{Error, Result};
use crate::model::{PortResult, PortState, Protocol};
use crate::timing::Timing;
use governor::{Quota, RateLimiter};
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::transport::{TransportChannelType, ipv4_packet_iter, transport_channel};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// The flag-scan family — one packet shape, five verdicts.
#[derive(Debug, Clone, Copy)]
pub enum RawTechnique {
    /// nmap -sS: SYN; SYN+ACK → open, RST → closed, silence → filtered.
    Syn,
    /// nmap -sA: ACK; RST → unfiltered, silence → filtered. Maps firewall
    /// rules, not service state.
    Ack,
    /// nmap -sF/-sN/-sX: FIN / no flags / FIN+PSH+URG. RFC 793 says closed
    /// ports RST and open ports drop — so RST → closed, silence →
    /// open|filtered.
    Fin,
    Null,
    Xmas,
}

impl RawTechnique {
    fn flags(self) -> u8 {
        match self {
            Self::Syn => TcpFlags::SYN,
            Self::Ack => TcpFlags::ACK,
            Self::Fin => TcpFlags::FIN,
            Self::Null => 0,
            Self::Xmas => TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
        }
    }

    /// Verdict for a port that answered. `syn_ack`/`rst` are decoded flags.
    fn classify(self, syn_ack: bool, rst: bool) -> Option<PortState> {
        match self {
            Self::Syn if syn_ack => Some(PortState::Open),
            Self::Syn if rst => Some(PortState::Closed),
            Self::Ack if rst => Some(PortState::Unfiltered),
            Self::Fin | Self::Null | Self::Xmas if rst => Some(PortState::Closed),
            _ => None,
        }
    }

    /// Verdict for a port that never answered.
    fn silent(self) -> PortState {
        match self {
            Self::Fin | Self::Null | Self::Xmas => PortState::OpenFiltered,
            _ => PortState::Filtered,
        }
    }
}

/// One decoded reply from the wire.
struct Reply {
    ip: Ipv4Addr,
    port: u16,
    syn_ack: bool,
    rst: bool,
    ttl: u8,
    window: u16,
}

/// Run a flag scan over `hosts` x `ports`. Returns per-port results plus a
/// per-host OS hint derived from reply TTL/window.
pub async fn run(
    hosts: &[IpAddr],
    ports: &[u16],
    timing: &Timing,
    technique: RawTechnique,
) -> Result<(Vec<(IpAddr, PortResult)>, HashMap<IpAddr, String>)> {
    if hosts.iter().any(|h| h.is_ipv6()) {
        return Err(Error::Unsupported("raw scan: IPv6"));
    }
    let (mut ptx, mut prx) = transport_channel(
        64 * 1024,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
    )
    .map_err(Error::Io)?;

    // Ephemeral source port, fixed per run. Replies are keyed by dst==sport.
    let sport = 40_000u16 + (nanos() % 20_000) as u16;

    // Bridge the blocking pnet receiver into tokio. The receiver thread is
    // detached — it ends with the process (pnet's iterator has no timeout).
    let (reply_tx, mut reply_rx) = mpsc::channel::<Reply>(4096);
    std::thread::spawn(move || {
        let mut iter = ipv4_packet_iter(&mut prx);
        loop {
            match iter.next() {
                Ok((ip_pkt, IpAddr::V4(src))) => {
                    let Some(tcp) = TcpPacket::new(ip_pkt.payload()) else {
                        continue;
                    };
                    if tcp.get_destination() != sport {
                        continue;
                    }
                    let flags = tcp.get_flags();
                    let syn_ack = flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0;
                    let rst = flags & TcpFlags::RST != 0;
                    if syn_ack || rst {
                        let _ = reply_tx.blocking_send(Reply {
                            ip: src,
                            port: tcp.get_source(),
                            syn_ack,
                            rst,
                            ttl: ip_pkt.get_ttl(),
                            window: tcp.get_window(),
                        });
                    }
                }
                Ok(_) | Err(_) => continue,
            }
        }
    });

    let limiter = timing
        .probe_delay
        .and_then(|d| Quota::with_period(d).map(RateLimiter::direct));

    let mut pending: HashMap<(Ipv4Addr, u16), ()> = hosts
        .iter()
        .filter_map(|h| match h {
            IpAddr::V4(v) => Some(*v),
            IpAddr::V6(_) => None,
        })
        .flat_map(|h| ports.iter().map(move |p| (h, *p)))
        .map(|k| (k, ()))
        .collect();

    let mut results: Vec<(IpAddr, PortResult)> = Vec::new();
    let mut os_hints: HashMap<IpAddr, String> = HashMap::new();
    let mut seq = nanos() as u32;

    for _round in 0..=timing.retries {
        let keys: Vec<(Ipv4Addr, u16)> = pending.keys().copied().collect();
        for (dst, port) in keys {
            if let Some(l) = &limiter {
                l.until_ready().await;
            }
            send_probe(&mut ptx, dst, port, sport, &mut seq, technique.flags())?;
        }

        // Collect replies for one timeout window.
        let deadline = Instant::now() + timing.timeout;
        while let Ok(Some(reply)) = tokio::time::timeout_at(deadline.into(), reply_rx.recv()).await
        {
            os_hints
                .entry(reply.ip.into())
                .or_insert_with(|| guess_os(reply.ttl, reply.window));
            let key = (reply.ip, reply.port);
            if let Some(state) = technique
                .classify(reply.syn_ack, reply.rst)
                .filter(|_| pending.remove(&key).is_some())
            {
                results.push((
                    reply.ip.into(),
                    PortResult {
                        port: reply.port,
                        protocol: Protocol::Tcp,
                        state,
                        service: None,
                        banner: None,
                        reason: if reply.syn_ack { "syn-ack" } else { "reset" }.into(),
                        rtt_ms: None,
                    },
                ));
            }
            if pending.is_empty() {
                break;
            }
        }
        if pending.is_empty() {
            break;
        }
    }

    for (ip, port) in pending.keys() {
        results.push((
            IpAddr::V4(*ip),
            PortResult {
                port: *port,
                protocol: Protocol::Tcp,
                state: technique.silent(),
                service: None,
                banner: None,
                reason: "no-response".into(),
                rtt_ms: None,
            },
        ));
    }
    Ok((results, os_hints))
}

/// Crude OS family from the reply's TTL and TCP window — nmap-grade
/// fingerprinting needs dozens of probes; this is a one-line hint.
/// Initial TTL is inferred as 64/128/255 by rounding the observed value up.
fn guess_os(ttl: u8, window: u16) -> String {
    let family = match ttl {
        65..=128 => "Windows",
        129..=255 => "network device (Cisco/IOS)",
        _ => {
            if window == 65535 {
                "macOS/*BSD/Solaris"
            } else {
                "Linux/Unix"
            }
        }
    };
    format!("{family} (ttl {ttl}, win {window})")
}

/// Build and send one IPv4+TCP packet with `flags` set.
fn send_probe(
    tx: &mut pnet::transport::TransportSender,
    dst: Ipv4Addr,
    dport: u16,
    sport: u16,
    seq: &mut u32,
    flags: u8,
) -> Result<()> {
    let src = source_addr(dst)?;
    let mut buf = vec![0u8; 40]; // 20-byte IP header + 20-byte TCP header
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[20..])
            .ok_or(Error::Unsupported("raw scan: tcp alloc"))?;
        tcp.set_source(sport);
        tcp.set_destination(dport);
        tcp.set_sequence(*seq);
        tcp.set_flags(flags);
        tcp.set_window(64240);
        tcp.set_data_offset(5);
        tcp.set_checksum(ipv4_checksum(&tcp.to_immutable(), &src, &dst));
    }
    {
        let mut ip =
            MutableIpv4Packet::new(&mut buf).ok_or(Error::Unsupported("raw scan: ip alloc"))?;
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
    }
    let pkt = pnet::packet::ipv4::Ipv4Packet::new(&buf)
        .ok_or(Error::Unsupported("raw scan: packet parse"))?;
    tx.send_to(&pkt, IpAddr::V4(dst)).map_err(Error::Io)?;
    *seq = seq.wrapping_add(1);
    Ok(())
}

/// Learn the local source address the OS would use to reach `dst` by
/// "connecting" a UDP socket (no traffic is sent).
fn source_addr(dst: Ipv4Addr) -> Result<Ipv4Addr> {
    let s = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    s.connect(SocketAddr::from((dst, 80)))?;
    match s.local_addr()?.ip() {
        IpAddr::V4(v) => Ok(v),
        IpAddr::V6(_) => Err(Error::Unsupported("raw scan: IPv6 source")),
    }
}

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}
