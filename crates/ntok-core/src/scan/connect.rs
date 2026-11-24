use crate::model::{PortResult, PortState, Protocol};
use crate::probe;
use crate::scan::PortProber;
use crate::timing::Timing;
use std::borrow::Cow;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// The `-sT` module: full TCP connect(). Unprivileged, works everywhere.
pub struct ConnectScan;

impl PortProber for ConnectScan {
    fn probe<'a>(
        &'a self,
        ip: IpAddr,
        port: u16,
        timing: &'a Timing,
        service_probe: bool,
    ) -> Pin<Box<dyn std::future::Future<Output = PortResult> + Send + 'a>> {
        Box::pin(probe_tcp(ip, port, timing, service_probe))
    }
}

/// Probe one TCP port with the connect() technique. Unprivileged.
///
/// Classification: connect success → open; `ConnectionRefused` → closed;
/// timeout or other error → filtered.
pub async fn probe_tcp(ip: IpAddr, port: u16, timing: &Timing, service_probe: bool) -> PortResult {
    let addr = SocketAddr::new(ip, port);
    let mut attempt = 0u32;
    let (state, reason, rtt_ms, mut stream) = loop {
        let r = probe_once(addr, timing.timeout).await;
        // Only "no response" is worth a retry — refused/errored ports won't change.
        if r.0 != PortState::Filtered || attempt >= timing.retries {
            break r;
        }
        attempt += 1;
    };

    let (service, banner) = if state == PortState::Open {
        let banner = if service_probe {
            match stream.as_mut() {
                Some(s) => {
                    probe::grab_banner(s, port, Duration::from_secs(3).min(timing.timeout)).await
                }
                None => None,
            }
        } else {
            None
        };
        (probe::guess_service(port, banner.as_deref()), banner)
    } else {
        (None, None)
    };

    PortResult {
        port,
        protocol: Protocol::Tcp,
        state,
        service,
        banner,
        reason,
        rtt_ms,
    }
}

async fn probe_once(
    addr: SocketAddr,
    timeout: Duration,
) -> (PortState, Cow<'static, str>, Option<f64>, Option<TcpStream>) {
    let t0 = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => (
            PortState::Open,
            Cow::Borrowed("syn-ack"),
            Some(t0.elapsed().as_secs_f64() * 1000.0),
            Some(s),
        ),
        Ok(Err(e)) => {
            let (state, reason) = match e.kind() {
                io::ErrorKind::ConnectionRefused => {
                    (PortState::Closed, Cow::Borrowed("conn-refused"))
                }
                io::ErrorKind::TimedOut => (PortState::Filtered, Cow::Borrowed("no-response")),
                _ => (PortState::Filtered, Cow::Owned(format!("error: {e}"))),
            };
            (state, reason, None, None)
        }
        Err(_) => (
            PortState::Filtered,
            Cow::Borrowed("no-response"),
            None,
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn timing() -> Timing {
        Timing::template(3).unwrap()
    }

    #[tokio::test]
    async fn open_port_reports_open() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let _ = s.write_all(b"SSH-2.0-test\r\n").await;
                });
            }
        });
        let t = Timing::template(3).unwrap();
        let r = probe_tcp("127.0.0.1".parse().unwrap(), port, &t, true).await;
        assert_eq!(r.state, PortState::Open);
        assert_eq!(r.service.as_deref(), Some("ssh"));
        assert!(r.rtt_ms.is_some());
    }

    #[tokio::test]
    async fn closed_port_reports_closed() {
        // Bind then drop to get a port nothing listens on.
        let port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let r = probe_tcp("127.0.0.1".parse().unwrap(), port, &timing().await, false).await;
        assert_eq!(r.state, PortState::Closed);
        assert_eq!(r.reason, "conn-refused");
    }
}
