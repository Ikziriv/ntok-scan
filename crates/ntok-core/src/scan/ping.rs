//! ICMP echo host discovery via `pnet` (`privileged` feature) — nmap's `-PE`.
//! Merged with TCP-ping results in the engine: a host is up if either
//! answers. Requires Npcap/root like `raw`.
//!
//! shortcut: IPv4 only and echo-request only — no timestamp ( -PP ) or
//! address-mask ( -PM ) probes, no ARP ping on the local segment (nmap's
//! `-PR` default). Upgrade by adding a Layer2 channel for ARP.

use pnet::packet::icmp::echo_request::{IcmpCodes, MutableEchoRequestPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{
    TransportChannelType, TransportProtocol, icmp_packet_iter, transport_channel,
};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Ping every host once, then once more per `retries`, collecting echo
/// replies for `timeout` after each round. Returns the set that answered.
pub async fn sweep(
    hosts: &[IpAddr],
    timeout: Duration,
    retries: u32,
) -> std::io::Result<HashSet<IpAddr>> {
    let (mut tx, mut rx) = transport_channel(
        64 * 1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;

    // Bridge the blocking pnet receiver into tokio (detached thread, same as
    // the raw scanner — ends with the process).
    let (reply_tx, mut reply_rx) = mpsc::channel::<IpAddr>(4096);
    std::thread::spawn(move || {
        let mut iter = icmp_packet_iter(&mut rx);
        loop {
            match iter.next() {
                Ok((pkt, src)) if pkt.get_icmp_type() == IcmpTypes::EchoReply => {
                    let _ = reply_tx.blocking_send(src);
                }
                Ok(_) | Err(_) => continue,
            }
        }
    });

    const IDENT: u16 = 0x6e74; // "nt"
    // ICMPv4 can't reach v6 targets — they still get the TCP-ping path.
    let v4: Vec<std::net::Ipv4Addr> = hosts
        .iter()
        .filter_map(|h| match h {
            IpAddr::V4(v) => Some(*v),
            IpAddr::V6(_) => None,
        })
        .collect();
    let mut pending: HashSet<std::net::Ipv4Addr> = v4.iter().copied().collect();
    let mut up = HashSet::new();
    let mut seq = 0u16;

    for _round in 0..=retries {
        for ip in pending.drain().collect::<Vec<_>>() {
            send_echo(&mut tx, ip, IDENT, seq)?;
            seq = seq.wrapping_add(1);
        }
        let deadline = Instant::now() + timeout;
        while let Ok(Some(src)) = tokio::time::timeout_at(deadline.into(), reply_rx.recv()).await {
            if let IpAddr::V4(v) = src {
                up.insert(v);
            }
        }
        // Anything not yet up goes around again.
        pending = v4.iter().copied().filter(|h| !up.contains(h)).collect();
        if pending.is_empty() {
            break;
        }
    }
    Ok(up.into_iter().map(IpAddr::V4).collect())
}

fn send_echo(
    tx: &mut pnet::transport::TransportSender,
    dst: std::net::Ipv4Addr,
    ident: u16,
    seq: u16,
) -> std::io::Result<()> {
    let mut buf = [0u8; 16];
    let csum = {
        let mut pkt = MutableEchoRequestPacket::new(&mut buf)
            .ok_or_else(|| std::io::Error::other("ping: packet alloc"))?;
        pkt.set_icmp_type(IcmpTypes::EchoRequest);
        pkt.set_icmp_code(IcmpCodes::NoCode);
        pkt.set_identifier(ident);
        pkt.set_sequence_number(seq);
        let view =
            IcmpPacket::new(&buf[..]).ok_or_else(|| std::io::Error::other("ping: packet parse"))?;
        pnet::packet::icmp::checksum(&view)
    };
    // ICMP checksum field is bytes 2..4; checksum was computed over zeroes.
    buf[2..4].copy_from_slice(&csum.to_be_bytes());
    tx.send_to(
        IcmpPacket::new(&buf).ok_or_else(|| std::io::Error::other("ping: packet parse"))?,
        IpAddr::V4(dst),
    )
    .map(|_| ())
}
