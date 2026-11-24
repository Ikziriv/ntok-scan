use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid target spec: {0}")]
    BadTarget(String),
    #[error("invalid port spec: {0}")]
    BadPorts(String),
    #[error("invalid timing template: T{0} (valid: T0..=T5)")]
    BadTiming(u8),
    #[error("DNS resolution failed for {host}: {source}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("target expansion exceeds limit of {0} hosts")]
    TooManyHosts(usize),
    #[error("scan cancelled")]
    Cancelled,
    #[error("operation not supported in this build: {0}")]
    Unsupported(&'static str),
    #[error("import failed: {0}")]
    Import(String),
    #[error("external tool failed: {0}")]
    Tool(String),
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
