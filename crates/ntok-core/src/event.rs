use crate::model::{PortState, Protocol};
use std::net::IpAddr;

/// Live events emitted by the engine on a broadcast channel. The CLI renders
/// them as progress lines; the web UI re-renders open ports from them.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    Started {
        hosts: usize,
        ports: usize,
        technique: &'static str,
    },
    HostDiscovered {
        ip: IpAddr,
        up: bool,
    },
    PortFound {
        ip: IpAddr,
        port: u16,
        protocol: Protocol,
        state: PortState,
        service: Option<String>,
    },
    /// Informational line — advisor notes, warnings — for the UI log.
    Note {
        text: String,
    },
    Progress {
        done: usize,
        total: usize,
    },
    Finished {
        elapsed_secs: f64,
        open: usize,
        closed: usize,
        filtered: usize,
        unfiltered: usize,
    },
}
