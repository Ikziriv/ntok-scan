//! Core scanning engine for ntok.
//!
//! Frontends (CLI, web) configure a [`engine::ScanConfig`], subscribe to a
//! `tokio::sync::broadcast` channel of [`event::ScanEvent`]s, and call
//! [`engine::run_scan`] to receive a [`model::ScanReport`].

pub mod advisor;
pub mod agent;
pub mod brand;
pub mod diff;
pub mod engine;
pub mod error;
pub mod event;
pub mod import;
pub mod model;
pub mod ports;
pub mod probe;
pub mod report;
pub mod scan;
pub mod svcdb;
pub mod target;
pub mod timing;
pub mod tools;
pub mod web;

pub use advisor::{AiSettings, HttpAdvisor, NullAdvisor, PlanAdvice, PlanRequest, ScanAdvisor};
pub use engine::{ScanConfig, ScanTechnique, run_scan};
pub use error::{Error, Result};
pub use event::ScanEvent;
pub use model::{
    CompanyInfo, DnsRecord, Finding, HostResult, HostState, PortResult, PortState, Protocol,
    RedirectHop, RobotsInfo, ScanReport, ScanSummary, SecurityHeaders, Technology, TlsInfo,
    WebAsset, WebProfile,
};
pub use report::ReportFormat;
pub use timing::Timing;
pub use tools::ToolKind;

/// reqwest's `rustls-tls` pulls `ring` while the workspace pins
/// `aws-lc-rs` — with both compiled in, rustls refuses to guess a
/// `CryptoProvider` and panics on the first `ClientConfig::builder()`.
/// Pin aws-lc-rs as the process default; safe to call repeatedly.
pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
}
