use crate::error::{Error, Result};
use std::time::Duration;

/// Probe pacing and concurrency. Equivalent to nmap's `-T0..-T5` templates.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Maximum probe tasks in flight at once.
    pub concurrency: usize,
    /// Per-probe timeout.
    pub timeout: Duration,
    /// Retries after the first filtered/no-response result.
    pub retries: u32,
    /// Minimum delay between probe starts; `None` = unthrottled.
    pub probe_delay: Option<Duration>,
}

impl Timing {
    pub fn template(level: u8) -> Result<Self> {
        let t = match level {
            // T0/T1 are for IDS evasion: serialized and extremely slow.
            0 => Self {
                concurrency: 1,
                timeout: Duration::from_secs(30),
                retries: 2,
                probe_delay: Some(Duration::from_secs(300)),
            },
            1 => Self {
                concurrency: 1,
                timeout: Duration::from_secs(15),
                retries: 2,
                probe_delay: Some(Duration::from_secs(15)),
            },
            2 => Self {
                concurrency: 4,
                timeout: Duration::from_secs(10),
                retries: 2,
                probe_delay: Some(Duration::from_millis(400)),
            },
            3 => Self {
                concurrency: 256,
                timeout: Duration::from_secs(3),
                retries: 1,
                probe_delay: None,
            },
            4 => Self {
                concurrency: 512,
                timeout: Duration::from_millis(1250),
                retries: 1,
                probe_delay: None,
            },
            5 => Self {
                concurrency: 1024,
                timeout: Duration::from_millis(400),
                retries: 0,
                probe_delay: None,
            },
            _ => return Err(Error::BadTiming(level)),
        };
        Ok(t)
    }
}
