use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("dns error: {0}")]
    Dns(#[from] crate::dns::DnsError),

    #[error("cloudflare error: {0}")]
    Cloudflare(#[from] crate::cloudflare::CloudflareError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}
