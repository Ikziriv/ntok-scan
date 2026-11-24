//! Scan technique modules, mirroring nmap's layout: each `-s*` technique is a
//! self-contained module behind [`PortProber`], so new techniques (ACK, FIN,
//! NULL, Xmas — all raw-packet) drop in as a module + one enum variant +
//! one entry in `ScanTechnique::prober`.
//!
//! `connect` (-sT) and `udp` (-sU) run unprivileged. The `privileged` cargo
//! feature (Npcap on Windows / root on Unix) adds `raw` — the flag-scan
//! family -sS/-sA/-sF/-sN/-sX — and `ping` (ICMP echo discovery, -PE).
//! Raw-packet scanners orchestrate their own tx/rx loop instead of
//! implementing `PortProber`, so `prober()` returns `None` for them and the
//! engine calls the module directly.

use crate::model::PortResult;
use crate::timing::Timing;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

pub mod connect;
pub mod udp;

#[cfg(feature = "privileged")]
pub mod ping;
#[cfg(feature = "privileged")]
pub mod raw;

/// A per-(ip, port) probe technique — nmap's unprivileged scan modules.
/// The engine fans `(host, port)` pairs across `probe` calls with shared
/// timing, rate limiting, and cancellation.
pub trait PortProber: Send + Sync {
    fn probe<'a>(
        &'a self,
        ip: IpAddr,
        port: u16,
        timing: &'a Timing,
        service_probe: bool,
    ) -> Pin<Box<dyn Future<Output = PortResult> + Send + 'a>>;
}
