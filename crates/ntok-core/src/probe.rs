use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Default service names for ports — the vendored nmap-services table
/// (highest-frequency name per port).
pub fn service_name(port: u16) -> Option<&'static str> {
    crate::svcdb::service_name(port, "tcp")
}

/// Ports where the client must speak first; payload sent before reading.
/// Mirrors nmap-service-probes: a request the service will actually answer.
fn probe_payload(port: u16) -> Option<&'static [u8]> {
    match port {
        80 | 81 | 82 | 3000 | 3001 | 5000 | 5001 | 5601 | 8000 | 8008 | 8080 | 8081 | 8443
        | 8888 | 9000 | 9090 | 3128 => Some(b"HEAD / HTTP/1.0\r\n\r\n"),
        // HTTP APIs that answer GET with identifying JSON.
        9200 | 9300 => Some(b"GET / HTTP/1.0\r\n\r\n"),
        2375 | 2376 => Some(b"GET /version HTTP/1.0\r\n\r\n"),
        8500 => Some(b"GET /v1/status/leader HTTP/1.0\r\n\r\n"),
        6379 => Some(b"PING\r\n"),
        11211 => Some(b"version\r\n"),
        _ => None,
    }
}

/// Read a service banner from an open connection. Sends a protocol-specific
/// probe first where needed (HTTP ports get `HEAD /`, redis gets `PING`).
pub async fn grab_banner(stream: &mut TcpStream, port: u16, timeout: Duration) -> Option<String> {
    if let Some(p) = probe_payload(port) {
        stream.write_all(p).await.ok()?;
    }
    let mut buf = [0u8; 512];
    let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };
    Some(sanitize(&buf[..n]))
}

fn sanitize(b: &[u8]) -> String {
    let s: String = b
        .iter()
        .take(256)
        .map(|&c| {
            if c.is_ascii_graphic() || c == b' ' {
                c as char
            } else {
                '.'
            }
        })
        .collect();
    s.trim_end_matches(['.', ' ']).to_string()
}

/// Service guess: banner match first, port-name fallback.
pub fn guess_service(port: u16, banner: Option<&str>) -> Option<String> {
    if let Some(b) = banner {
        if b.starts_with("SSH-") {
            return Some("ssh".into());
        }
        if b.starts_with("HTTP/") {
            return Some(
                if port == 443 || port == 8443 {
                    "https"
                } else {
                    "http"
                }
                .into(),
            );
        }
        if b.starts_with("+PONG") || b.starts_with("-ERR") {
            return Some("redis".into());
        }
        if b.starts_with("220") {
            return Some(
                if matches!(port, 25 | 465 | 587) {
                    "smtp"
                } else {
                    "ftp"
                }
                .into(),
            );
        }
        if b.starts_with("* OK") {
            return Some("imap".into());
        }
        if b.starts_with("+OK") {
            return Some("pop3".into());
        }
        if b.starts_with("RFB ") {
            return Some("vnc".into());
        }
        if b.starts_with("VERSION ") {
            return Some("memcached".into());
        }
        if b.starts_with("AMQP") {
            return Some("amqp".into());
        }
        // JSON APIs identified by body content rather than a banner line.
        if b.contains("You Know, for Search") || b.contains("\"cluster_name\"") {
            return Some("elasticsearch".into());
        }
        if b.contains("\"ApiVersion\"") || b.contains("\"Docker\"") {
            return Some("docker".into());
        }
        // Long tail: nmap's service-probe match DB (lazily compiled).
        if let Some(name) = crate::svcdb::match_banner(b) {
            return Some(name.into());
        }
    }
    service_name(port).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_guesses() {
        assert_eq!(
            guess_service(22, Some("SSH-2.0-OpenSSH_9")).as_deref(),
            Some("ssh")
        );
        assert_eq!(guess_service(6379, Some("+PONG")).as_deref(), Some("redis"));
        assert_eq!(
            guess_service(8080, Some("HTTP/1.1 200 OK")).as_deref(),
            Some("http")
        );
        assert_eq!(guess_service(3306, None).as_deref(), Some("mysql"));
        assert_eq!(guess_service(65000, None), None);
    }
}
