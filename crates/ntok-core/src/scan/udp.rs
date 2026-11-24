use crate::model::{PortResult, PortState, Protocol};
use crate::probe;
use crate::scan::PortProber;
use crate::timing::Timing;
use std::borrow::Cow;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use tokio::net::UdpSocket;

/// The `-sU` module: connected-socket UDP probes. Unprivileged.
pub struct UdpScan;

impl PortProber for UdpScan {
    fn probe<'a>(
        &'a self,
        ip: IpAddr,
        port: u16,
        timing: &'a Timing,
        service_probe: bool,
    ) -> Pin<Box<dyn std::future::Future<Output = PortResult> + Send + 'a>> {
        Box::pin(probe_udp(ip, port, timing, service_probe))
    }
}

/// Probe one UDP port using a *connected* UDP socket. Unprivileged.
///
/// A connected socket surfaces ICMP port-unreachable as `ConnectionReset` on
/// `recv` — that is the closed signal. A datagram back means open. Silence
/// after retries is ambiguous (open|filtered), same as nmap.
pub async fn probe_udp(ip: IpAddr, port: u16, timing: &Timing, service_probe: bool) -> PortResult {
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            return result(port, PortState::Filtered, format!("bind: {e}"));
        }
    };
    if let Err(e) = socket.connect(SocketAddr::new(ip, port)).await {
        return result(port, PortState::Filtered, format!("connect: {e}"));
    }

    // Protocol-specific probes (nmap -sV payloads, reduced): a real query
    // gets a real answer from services that ignore empty datagrams.
    let payload: &[u8] = probe_payload(port).unwrap_or(b"");
    let mut banner = None;
    let mut state = PortState::OpenFiltered;
    let mut reason: Cow<'static, str> = "no-response".into();

    for _ in 0..=timing.retries {
        if socket.send(payload).await.is_err() {
            state = PortState::Filtered;
            reason = "send-error".into();
            break;
        }
        let mut buf = [0u8; 512];
        match tokio::time::timeout(timing.timeout, socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                state = PortState::Open;
                reason = "udp-response".into();
                banner = Some(
                    String::from_utf8_lossy(&buf[..n.min(128)])
                        .trim_end()
                        .to_string(),
                );
                break;
            }
            Ok(Ok(_)) => {} // empty datagram: retry
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => {
                state = PortState::Closed;
                reason = "port-unreach".into();
                break;
            }
            Ok(Err(e)) => {
                state = PortState::Filtered;
                reason = format!("error: {e}").into();
                break;
            }
            Err(_) => {} // timeout: retry
        }
    }

    let service = if service_probe && state.is_open() {
        probe::guess_service(port, banner.as_deref())
    } else {
        None
    };

    PortResult {
        port,
        protocol: Protocol::Udp,
        state,
        service,
        banner,
        reason,
        rtt_ms: None,
    }
}

fn result(port: u16, state: PortState, reason: impl Into<Cow<'static, str>>) -> PortResult {
    PortResult {
        port,
        protocol: Protocol::Udp,
        state,
        service: None,
        banner: None,
        reason: reason.into(),
        rtt_ms: None,
    }
}

/// Well-known UDP service probes. A service that would ignore an empty
/// datagram often answers these, turning open|filtered into open.
fn probe_payload(port: u16) -> Option<&'static [u8]> {
    Some(match port {
        53 => DNS_A_QUERY,
        123 => NTP_REQUEST,
        137 => NBSTAT_QUERY,
        161 => SNMP_SYS_DESCR,
        1900 => SSDP_MSEARCH,
        1434 => SQL_BROWSER,
        _ => return None,
    })
}

/// Minimal DNS query for example.com/A.
const DNS_A_QUERY: &[u8] =
    b"\xde\xad\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

/// NTPv3 client request (LI=0, VN=3, mode=3), 48 bytes.
const NTP_REQUEST: &[u8] = &[
    0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// NetBIOS node-status query for the `*` wildcard name (nmap's netbios-ns probe).
const NBSTAT_QUERY: &[u8] =
    b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01";

/// SNMPv1 get-request for sysDescr.0, community "public".
const SNMP_SYS_DESCR: &[u8] = b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00";

/// SSDP M-SEARCH — services answer with a LOCATION header.
const SSDP_MSEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";

/// SQL Server Browser single-byte enumeration request (replies with
/// "ServerName;InstanceName;..." — plain text, lands in the banner).
const SQL_BROWSER: &[u8] = b"\x02";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_table_is_well_formed() {
        assert_eq!(NTP_REQUEST.len(), 48);
        assert!(DNS_A_QUERY.ends_with(b"\x00\x01\x00\x01"));
        assert!(SNMP_SYS_DESCR.starts_with(b"\x30"));
        assert!(SSDP_MSEARCH.starts_with(b"M-SEARCH"));
        assert!(probe_payload(123).is_some());
        assert!(probe_payload(9999).is_none());
    }
}
